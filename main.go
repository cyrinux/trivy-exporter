// trivy-exporter
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	dockerEvents "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/fsnotify/fsnotify"
	otelpyroscope "github.com/grafana/otel-profiling-go"
	"github.com/grafana/pyroscope-go"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Environment variables
var (
	resultsDir        = getEnv("RESULTS_DIR", "/results")
	dockerHost        = getEnv("DOCKER_HOST", "unix:///var/run/docker.sock")
	trivyServerURL    = getEnv("TRIVY_SERVER_URL", "http://localhost:4954")
	ntfyWebhookURL    = getEnv("NTFY_WEBHOOK_URL", "https://ntfy.sh/vulns")
	tempoEndpoint     = getEnv("TEMPO_ENDPOINT", "localhost:4317")
	pyroscopeEndpoint = getEnv("PYROSCOPE_ENDPOINT", "localhost:4040")
	numWorkers        = getEnv("NUM_WORKERS", "1")
	trivyExtraArgs    = getEnv("TRIVY_EXTRA_ARGS", "")
	logLevel          = getEnv("LOG_LEVEL", "info")
	db                *sql.DB
	alertChannel      = make(chan Alert, 100) // Buffer size for pending alerts
	alertsInProgress  sync.Map                // Track CVEs being processed to avoid duplicates
	// Prometheus metrics
	vulnMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability",
			Help: "Detected vulnerabilities from Trivy reports",
		},
		[]string{"image", "image_name", "package", "package_version", "id", "severity", "status", "description"},
	)
	vulnTimestampMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability_timestamp",
			Help: "Timestamp of the last detected vulnerability for each image",
		},
		[]string{"image", "vulnerability_id"},
	)
)

// TrivyVulnerability represents a single vulnerability from the Trivy JSON report
type TrivyVulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion"`
	Severity        string `json:"Severity"`
	Description     string `json:"Description"`
}

// TrivyReport captures the full structure of a Trivy scan report
type TrivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

// imageScanItem holds both the image to scan and the scanners param
type imageScanItem struct {
	Image    string
	Scanners string
}

// Alert represents a vulnerability notification
type Alert struct {
	Image       string
	Package     string
	CVEID       string
	Severity    string
	Description string
}

// init runs before main(), setting up logging and DB
func init() {
	lvl, err := log.ParseLevel(logLevel)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

}

// HealthResponse is the healthcheck structure
type HealthResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	CheckedAt string `json:"checked_at"`
}

func handleHealthCheck(w http.ResponseWriter, _ *http.Request) {
	// Create the health check response struct
	response := HealthResponse{
		Status:    "ok",
		Message:   "Service is healthy",
		CheckedAt: time.Now().Format(time.RFC3339),
	}

	// Set the response content type as JSON
	w.Header().Set("Content-Type", "application/json")

	// Return status code 200 (OK)
	w.WriteHeader(http.StatusOK)

	// Encode the response as JSON and write it to the response body
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Handle encoding error
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

// main starts the program, spawning watchers, listeners, and the HTTP server
func main() {
	ctx := context.Background()

	initDatabase(ctx)
	defer db.Close()

	tp, err := initTracer(ctx)
	if err != nil {
		log.Fatalf("failed to initialize tracer: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			log.Errorf("Error shutting down tracer provider: %v", err)
		}
	}()

	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: "trivy-exporter",
		ServerAddress:   pyroscopeEndpoint,
		Tags: map[string]string{
			"service_git_ref":    "main",
			"service_repository": "https://github.com/cyrinux/trivy-exporter",
		},
	})
	if err != nil {
		log.Fatalf("failed to start pyroscope profiler: %v", err)
	}
	defer func() {
		if err := profiler.Stop(); err != nil {
			log.Errorf("Error shutting down profiler provider: %v", err)
		}
	}()

	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "Main")
	defer span.End()

	n, err := strconv.Atoi(numWorkers)
	// if err != nil || n < 2 {
	// 	n = 2
	// }
	log.Infof("Starting with %d worker(s). Using fsnotify to track JSON files in %s", n, resultsDir)

	// Register Prometheus metrics
	prometheus.MustRegister(vulnMetric, vulnTimestampMetric)

	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if dockerHost != "unix:///var/run/docker.sock" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}

	// Channel of imageScanItem structs for scans
	scanQ := make(chan imageScanItem, n)
	var wg sync.WaitGroup

	// Spawn worker goroutines
	for i := 0; i < n; i++ {
		go worker(ctx, cli, scanQ, &wg)
	}

	// Watch the resultsDir for new JSON files using fsnotify
	go watchResultsDirectory(ctx)

	// Refresh metrics every 30s
	go updateMetrics(ctx)

	// Listen for Docker container "start" events, queueing scans
	go listenDockerEvents(ctx, cli, scanQ, &wg)

	// Start the alert batch processor
	go processAlertBatches(ctx)

	// Provide /metrics for Prometheus
	http.Handle("/metrics", otelhttp.NewHandler(http.HandlerFunc(handleMetrics), "Metrics"))
	// Add the health check endpoint
	http.Handle("/health", otelhttp.NewHandler(http.HandlerFunc(handleHealthCheck), "HealthCheck"))

	log.Infof("Listening on :8080, results stored in %s", resultsDir)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// updateMetrics call updateMetricsFromDatabase in loop
func updateMetrics(ctx context.Context) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "UpdateMetrics")
	defer span.End()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Debounce-related variables
	var debounceMu sync.Mutex
	var lastExecuted time.Time
	debounceInterval := 30 * time.Second

	for {
		select {
		case <-ticker.C:
			debounceMu.Lock()

			// Only proceed if enough time has passed since the last execution
			if time.Since(lastExecuted) >= debounceInterval {
				lastExecuted = time.Now()
				// Perform the action
				go updateMetricsFromDatabase(ctx)
			} else {
				log.Trace("Skipping updateMetrics call due to debounce")
			}

			debounceMu.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

// initDatabase opens or creates the DB and ensures we have required tables
func initDatabase(ctx context.Context) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "InitDatabase")
	defer span.End()

	var err error
	db, err = sql.Open("sqlite3", filepath.Join(resultsDir, "vulns.db"))
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS vulnerabilities (
			vulnerability_id TEXT PRIMARY KEY,
			image TEXT,
			image_name TEXT,
			package TEXT,
			package_version TEXT,
			severity TEXT,
			status TEXT,
			description TEXT,
			timestamp TEXT
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create vulnerabilities table: %v", err)
	}
	_, err = db.ExecContext(ctx, `
	    CREATE TABLE IF NOT EXISTS image_scans (
	        image TEXT PRIMARY KEY,
	        checksum TEXT,
	        status TEXT,
	        timestamp INTEGER
	    )
	`)
	if err != nil {
		log.Fatalf("Failed to create image_scans table: %v", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_vulns_image ON vulnerabilities (image)
	`)
	if err != nil {
		log.Fatalf("Failed to create index on vulns table: %v", err)
	}
	_, err = db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_image_scans_image ON image_scans (image)
	`)
	if err != nil {
		log.Fatalf("Failed to create index on image_scans table: %v", err)
	}
}

// listenDockerEvents monitors Docker events. If container starts, we queue a scan with
// user-specified scanners from the "trivy.scanners" label or default "vuln"
// listenDockerEvents monitors Docker events. If container starts, we queue a scan with
// user-specified scanners from the "trivy.scanners" label or default "vuln"
func listenDockerEvents(ctx context.Context, cli *client.Client, scanQueue chan<- imageScanItem, wg *sync.WaitGroup) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "ListenDockerEvents")
	defer span.End()

	filterArgs := filters.NewArgs()
	filterArgs.Add("event", "start")
	evCh, errCh := cli.Events(ctx, dockerEvents.ListOptions{Filters: filterArgs})
	for {
		select {
		case evt := <-evCh:
			if evt.Type == dockerEvents.ContainerEventType {
				info, e2 := cli.ContainerInspect(ctx, evt.Actor.ID)
				if e2 != nil {
					log.Debugf("Error inspecting container %s: %v", evt.Actor.ID, e2)
					continue
				}
				// Check if label "trivy.scan" is false, skip
				if skip, ok := info.Config.Labels["trivy.scan"]; ok && skip == "false" {
					log.Debugf("Skipping container with trivy.scan=false: %s", info.Config.Image)
					continue
				}
				// If label "trivy.scanners" is set, use that, otherwise default to "vuln"
				scanners := "vuln"
				if custom, ok := info.Config.Labels["trivy.scanners"]; ok && strings.TrimSpace(custom) != "" {
					scanners = custom
					log.Debugf("Using custom scanners '%s' for %s", scanners, info.Config.Image)
				}
				wg.Add(1)

				// Use blocking send instead of select+default
				log.Debugf("Queueing %s for scanning (scanners: %s) - will wait if queue is full", info.Config.Image, scanners)
				scanQueue <- imageScanItem{Image: info.Config.Image, Scanners: scanners}
				log.Debugf("Successfully queued %s for scanning", info.Config.Image)
			}
		case e := <-errCh:
			if e != nil {
				log.Debugf("Docker event error: %v", e)
			}
		}
	}
}

// worker processes queued images, calling Trivy with the specified scanners
func worker(ctx context.Context, cli *client.Client, scanQueue <-chan imageScanItem, wg *sync.WaitGroup) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "Worker")
	defer span.End()

	for item := range scanQueue {
		checksum := getImageDigest(ctx, cli, item.Image)

		// First check if already scanned (or in progress)
		if alreadyScanned(ctx, item.Image, checksum) {
			log.Debugf("Skipping already scanned or in-progress image: %s", item.Image)
			wg.Done()
			continue
		}

		// Mark as in-progress immediately, before starting the scan
		markImageScanInProgress(ctx, item.Image)

		if err := requestTrivyScan(ctx, item.Image, trivyServerURL, item.Scanners); err != nil {
			log.Warnf("Trivy scan error for %s: %v", item.Image, err)
		} else {
			saveImageChecksum(ctx, item.Image, checksum)
		}
		wg.Done()
	}
}

func getImageDigest(ctx context.Context, cli *client.Client, image string) string {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "GetImageDigest")
	defer span.End()

	imgInspect, err := cli.ImageInspect(ctx, image)
	if err != nil {
		log.Warnf("Failed inspecting image %s: %v", image, err)
		return ""
	}

	return imgInspect.ID
}

func alreadyScanned(ctx context.Context, image, checksum string) bool {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "AlreadyScanned")
	defer span.End()

	var dbChecksum, status string
	err := db.QueryRowContext(ctx, "SELECT checksum, status FROM image_scans WHERE image = ?", image).Scan(&dbChecksum, &status)

	// If we find the image in the database and either:
	// 1. It's the same checksum and status is "completed" or
	// 2. Status is "in_progress" (regardless of checksum)
	// then we consider it already scanned or being scanned
	return err == nil && (dbChecksum == checksum && status == "completed" || status == "in_progress")
}

func markImageScanInProgress(ctx context.Context, image string) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "MarkImageScanInProgress")
	defer span.End()

	_, err := db.ExecContext(ctx, `
        INSERT OR REPLACE INTO image_scans (image, status, timestamp)
        VALUES (?, ?, ?)`,
		image, "in_progress", time.Now().Unix(),
	)
	if err != nil {
		log.Warnf("Failed marking scan as in-progress for %s: %v", image, err)
	}
}

func saveImageChecksum(ctx context.Context, image, checksum string) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "SaveImageChecksum")
	defer span.End()

	_, err := db.ExecContext(ctx, `
        INSERT OR REPLACE INTO image_scans (image, checksum, status, timestamp)
        VALUES (?, ?, ?, ?)`,
		image, checksum, "completed", time.Now().Unix(),
	)
	if err != nil {
		log.Warnf("Failed saving checksum for %s: %v", image, err)
	}
}

// watchResultsDirectory uses fsnotify to detect .json file creation or writes in resultsDir
func watchResultsDirectory(ctx context.Context) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "WatchResultsDirectory")
	defer span.End()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Error creating fsnotify watcher: %v", err)
	}
	defer watcher.Close()

	if err := watcher.Add(resultsDir); err != nil {
		log.Fatalf("Error watching %s: %v", resultsDir, err)
	}

	debounceMu := sync.Mutex{}
	debounced := map[string]time.Time{}
	debounceDuration := 500 * time.Millisecond
	timer := time.NewTimer(debounceDuration)
	defer timer.Stop()

	for range timer.C {
		now := time.Now()
		debounceMu.Lock()
		for file, t := range debounced {
			if now.Sub(t) >= debounceDuration {
				go parseTrivyReport(ctx, file)
				delete(debounced, file)
			}
		}
		debounceMu.Unlock()
		timer.Reset(debounceDuration)
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 && filepath.Ext(event.Name) == ".json" {
				debounceMu.Lock()
				debounced[event.Name] = time.Now()
				debounceMu.Unlock()
			}
		case err := <-watcher.Errors:
			if err != nil {
				log.Warnf("Fsnotify error: %v", err)
			}
		}
	}
}

// requestTrivyScan runs Trivy with a specified set of scanners
func requestTrivyScan(ctx context.Context, image, server, scanners string) error {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "RequestTrivyScan")
	defer span.End()

	parts := strings.Split(image, ":")
	baseName := parts[0]
	tag := "latest"
	if len(parts) > 1 {
		tag = parts[1]
	}
	outFile := fmt.Sprintf("%s/%s_%s.json", resultsDir, strings.ReplaceAll(baseName, "/", "_"), tag)
	tmpOutFile := filepath.Join(os.TempDir(), filepath.Base(outFile)+".tmp")

	args := []string{
		"image",
		"--server", server,
		"--scanners", scanners,
		"--format", "json",
		"--output", tmpOutFile,
	}
	if trivyExtraArgs != "" {
		args = append(args, strings.Split(trivyExtraArgs, " ")...)
	}
	args = append(args, image)

	scanContext, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanContext, "trivy", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Trivy scan error for %s: %w", image, err)
	}
	if err := moveFile(ctx, tmpOutFile, outFile); err != nil {
		return fmt.Errorf("Error renaming output file: %w", err)
	}
	return nil
}

// parseTrivyReport reads the JSON file and saves vulnerabilities, then deletes the file
var parseSem = make(chan struct{}, 5)

func parseTrivyReport(ctx context.Context, filePath string) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "ParseTrivyReport")
	defer span.End()

	parseSem <- struct{}{}
	defer func() { <-parseSem }()

	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Debugf("Error reading %s: %v", filePath, err)
		return
	}
	var rep TrivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		log.Debugf("Error unmarshaling JSON: %v", err)
		return
	}
	saveVulnerabilitiesToDatabase(ctx, rep)
	if err := os.Remove(filePath); err != nil {
		log.Debugf("Error removing %s: %v", filePath, err)
	}
}

// updateMetricsFromDatabase reads DB vulnerabilities and updates Prometheus metrics
func updateMetricsFromDatabase(ctx context.Context) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "UpdateMetricsFromDatabase")
	defer span.End()

	log.Trace("Starting updateMetrics")

	vulnMetric.Reset()
	vulnTimestampMetric.Reset()

	rows, err := db.QueryContext(ctx, `
		SELECT 
			image,
			image_name,
			package,
			package_version,
			vulnerability_id,
			severity,
			status,
			description,
			timestamp
		FROM vulnerabilities
	`)
	if err != nil {
		log.Warnf("Error querying DB: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			image, imageName, pkg, pkgVersion, vulnID, sev, status, desc, ts string
		)
		if err := rows.Scan(&image, &imageName, &pkg, &pkgVersion, &vulnID, &sev, &status, &desc, &ts); err != nil {
			continue
		}
		vulnMetric.WithLabelValues(image, imageName, pkg, pkgVersion, vulnID, sev, status, desc).Set(1)
		vulnTimestampMetric.WithLabelValues(image, vulnID).Set(float64(time.Now().Unix()))
	}
}

// handleMetrics is the handler for /metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	log.Debug("Serving /metrics")
	promhttp.Handler().ServeHTTP(w, r)
}

// getEnv reads an environment variable or returns the default
func getEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

// queueAlert adds an alert to the processing queue if it's not already being processed
func queueAlert(ctx context.Context, image, pkg, cveID, severity, description string) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "QueueAlert")
	defer span.End()

	// Check if this CVE is already being processed
	_, exists := alertsInProgress.LoadOrStore(cveID+":"+image, true)
	if exists {
		log.Debugf("Alert for CVE: %s on image: %s already queued, skipping", cveID, image)
		return
	}

	// Queue the alert
	select {
	case alertChannel <- Alert{
		Image:       image,
		Package:     pkg,
		CVEID:       cveID,
		Severity:    severity,
		Description: description,
	}:
		log.Debugf("Queued alert for CVE: %s on image: %s", cveID, image)
	default:
		log.Warnf("Alert queue full, dropping alert for CVE: %s on image: %s", cveID, image)
		alertsInProgress.Delete(cveID + ":" + image)
	}
}

// processAlertBatches continuously processes alerts in batches
func processAlertBatches(ctx context.Context) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "ProcessBatchAlertes")
	defer span.End()

	for {
		// Collect a batch of at most 5 alerts
		var batch []Alert
		batchSize := 0
		batchComplete := false

		// Try to collect up to 5 alerts or until there are no more alerts for 100ms
		for batchSize < 5 && !batchComplete {
			select {
			case alert := <-alertChannel:
				batch = append(batch, alert)
				batchSize++
			case <-time.After(100 * time.Millisecond):
				batchComplete = true
			}
		}

		// If we have any alerts, send them
		if len(batch) > 0 {
			sendAlertBatch(ctx, batch)

			// Clean up the tracking map
			for _, alert := range batch {
				alertsInProgress.Delete(alert.CVEID + ":" + alert.Image)
			}

			// Wait 10 seconds before processing the next batch
			time.Sleep(10 * time.Second)
		} else {
			// If we didn't get any alerts, wait a bit to avoid busy-waiting
			time.Sleep(1 * time.Second)
		}
	}
}

// sendAlertBatch sends a batch of alerts as a single notification
func sendAlertBatch(ctx context.Context, alerts []Alert) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "SendAlertBatch")
	defer span.End()

	if ntfyWebhookURL == "" || len(alerts) == 0 {
		return
	}

	log.Infof("Sending batch of %d alerts", len(alerts))

	// Build the message body with all vulnerabilities
	var msgBuilder strings.Builder
	highestSeverity := "low"
	severityOrder := map[string]int{
		"unknown":  0,
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	for i, alert := range alerts {
		// Track highest severity for title and priority
		alertSev := strings.ToLower(alert.Severity)
		if severityOrder[alertSev] > severityOrder[highestSeverity] {
			highestSeverity = alertSev
		}

		// Add alert details to message
		fmt.Fprintf(&msgBuilder, "Alert %d/%d:\n", i+1, len(alerts))
		fmt.Fprintf(&msgBuilder, "Image: %s\n", alert.Image)
		fmt.Fprintf(&msgBuilder, "Package: %s, CVE ID: %s\n", alert.Package, alert.CVEID)
		fmt.Fprintf(&msgBuilder, "Severity: %s\n", alert.Severity)
		fmt.Fprintf(&msgBuilder, "Description: %s\n\n", alert.Description)
	}

	// Create and send request
	req, err := http.NewRequestWithContext(ctx, "POST", ntfyWebhookURL, strings.NewReader(msgBuilder.String()))
	if err != nil {
		log.Warnf("Error creating batch alert request: %v", err)
		return
	}

	title := fmt.Sprintf("%d New vulnerabilities found (highest: %s)", len(alerts), highestSeverity)
	req.Header.Set("Title", title)

	// Set priority based on highest severity
	priority := "default"
	if highestSeverity == "critical" || highestSeverity == "high" {
		priority = "urgent"
	} else if highestSeverity == "medium" {
		priority = "high"
	}
	req.Header.Set("Priority", priority)
	req.Header.Set("Tags", fmt.Sprintf("warning,security,batch,%s", highestSeverity))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warnf("Error sending batch alert: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Infof("Alert batch sent with status: %s", resp.Status)
}

// sendAlert sends a notification about a vulnerability to ntfy.sh (if configured).
func sendAlert(ctx context.Context, image, pkg, cveID, severity, description string) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "SendAlert")
	defer span.End()

	if ntfyWebhookURL == "" {
		log.Debug("ntfyWebhookURL not set, skipping alert")
		return
	}

	queueAlert(ctx, image, pkg, cveID, severity, description)
}

// saveVulnerabilitiesToDatabase inserts new vulnerabilities into the DB
func saveVulnerabilitiesToDatabase(ctx context.Context, report TrivyReport) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "SaveVulnerabilitiesToDatabase")
	defer span.End()

	imageName := strings.Split(report.ArtifactName, ":")[0]
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			row := db.QueryRowContext(ctx, `SELECT vulnerability_id FROM vulnerabilities WHERE vulnerability_id = ? AND image = ?`, vuln.VulnerabilityID, report.ArtifactName)
			var existingID string
			if err := row.Scan(&existingID); err != nil && err != sql.ErrNoRows {
				continue
			}
			if existingID == "" {
				_, _ = db.Exec(`
                    INSERT INTO vulnerabilities (
                        vulnerability_id, image, image_name, package, package_version,
                        severity, status, description, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
					vuln.VulnerabilityID,
					report.ArtifactName,
					imageName,
					vuln.PkgName,
					vuln.PkgVersion,
					vuln.Severity,
					"NEW",
					vuln.Description,
					time.Now().Format(time.RFC3339),
				)
				// Queue the alert instead of sending immediately
				sendAlert(ctx, report.ArtifactName, vuln.PkgName, vuln.VulnerabilityID, vuln.Severity, vuln.Description)
				log.Debugf("New vulnerability recorded and queued for alert: %s", vuln.VulnerabilityID)
			}
		}
	}
}

func moveFile(ctx context.Context, src, dst string) error {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "MoveFile")
	defer span.End()

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	return os.Remove(src)
}

func initTracer(ctx context.Context) (*sdktrace.TracerProvider, error) {
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(tempoEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	tpr := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("trivy-exporter"),
			semconv.ServiceVersion("1.2.0"),
		)),
	)

	otel.SetTracerProvider(otelpyroscope.NewTracerProvider(tpr))
	return tpr, nil
}

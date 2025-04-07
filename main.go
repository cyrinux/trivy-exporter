// trivy-exporter
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/grafana/pyroscope-go"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	openai "github.com/sashabaranov/go-openai"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	_ "github.com/mattn/go-sqlite3"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func initTracer(ctx context.Context) (*sdktrace.TracerProvider, *pyroscope.Profiler) {
	if disableTracingProfiling {
		tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.NeverSample()))
		otel.SetTracerProvider(tp)
		return tp, nil
	}
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(tempoEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		log.Fatalf("Tracer error: %v", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(appname),
			semconv.ServiceVersionKey.String("1.2.0"),
		)),
	)
	otel.SetTracerProvider(tp)
	profiler, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: appname,
		ServerAddress:   pyroscopeEndpoint,
	})
	if err != nil {
		log.Fatalf("Pyroscope profiler error: %v", err)
	}
	return tp, profiler
}

const appname = "trivy-exporter"
const trivyPrompt = "Provide mitigation steps and fix recommendations for vulnerability %s affecting package %s version %s. Include official references if available."

// Environment variables
var (
	resultsDir              = getEnv("RESULTS_DIR", "/results")
	dockerHost              = getEnv("DOCKER_HOST", "unix:///var/run/docker.sock")
	trivyServerURL          = getEnv("TRIVY_SERVER_URL", "http://localhost:4954")
	ntfyWebhookURL          = getEnv("NTFY_WEBHOOK_URL", "https://ntfy.sh/vulns")
	tempoEndpoint           = getEnv("TEMPO_ENDPOINT", "localhost:4317") // change to http or grpc
	pyroscopeEndpoint       = getEnv("PYROSCOPE_ENDPOINT", "http://localhost:4040")
	numWorkers              = getEnv("NUM_WORKERS", "1")
	trivyExtraArgs          = getEnv("TRIVY_EXTRA_ARGS", "")
	disableTracingProfiling = strings.ToLower(getEnv("DISABLE_TRACING_PROFILING", "false")) == "true"
	logLevel                = getEnv("LOG_LEVEL", "info")
	openAIAPIKey            = getEnv("OPENAI_API_KEY", "")
	openAIModel             = getEnv("OPENAI_MODEL", "gpt-4-turbo")
	scanners                = "vuln"

	db               *sql.DB
	alertChannel     = make(chan Alert, 100) // Buffer size for pending alerts
	alertsInProgress sync.Map                // Track CVEs being processed to avoid duplicates
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
	Image           string `json:"Image"`
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

// HealthResponse is the healthcheck structure
type HealthResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	CheckedAt string `json:"checked_at"`
}

// StatusResponse is the status response structure
type StatusResponse struct {
	CVECount   string `json:"cve_count"`
	NumWorkers string `json:"num_workers"`
	CheckedAt  string `json:"checked_at"`
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

type noOpProfiler struct{}

func (n *noOpProfiler) Stop() error { return nil }

// main starts the program, spawning watchers, listeners, and the HTTP server
func main() {
	rootCtx, cancel := context.WithCancel(context.Background())
	ctx, span := otel.Tracer(appname).Start(rootCtx, "Main")
	defer span.End()
	go waitForShutdown(cancel)
	n, err := strconv.Atoi(numWorkers)
	if err != nil {
		n = 1
	}
	prometheus.MustRegister(vulnMetric, vulnTimestampMetric)
	initDatabase(ctx)
	defer db.Close()
	tp, profiler := initTracer(ctx)
	defer func() {
		if profiler != nil {
			_ = profiler.Stop()
		}
		if tp != nil {
			_ = tp.Shutdown(ctx)
		}
	}()
	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if dockerHost != "unix:///var/run/docker.sock" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatalf("Docker client error: %v", err)
	}
	analysisQ := make(chan TrivyVulnerability, 10)
	go cveAnalysisWorker(ctx, analysisQ)
	scanQ := make(chan imageScanItem, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		go worker(ctx, cli, scanQ, &wg, i, analysisQ)
	}
	go listenDockerEvents(ctx, cli, scanQ, &wg)
	go processAlertBatches(ctx)
	go updateMetrics(ctx)
	http.Handle("/metrics", otelhttp.NewHandler(http.HandlerFunc(handleMetrics), "Metrics"))
	http.Handle("/health", otelhttp.NewHandler(http.HandlerFunc(handleHealthCheck), "HealthCheck"))
	http.Handle("/db/status", otelhttp.NewHandler(http.HandlerFunc(handleStatus), "Status"))
	log.Infof("Listening on :8080, results stored in %s", resultsDir)
	log.Fatal(http.ListenAndServe(":8080", nil))
	wg.Wait()
	close(scanQ)
}

func waitForShutdown(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Info("Interrupt received, shutting down...")
	cancel()
}

// updateMetrics call updateMetricsFromDatabase in loop
func updateMetrics(ctx context.Context) {
	ctx, span := otel.Tracer(appname).Start(ctx, "UpdateMetrics")
	defer span.End()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updateMetricsFromDatabase(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// initDatabase opens or creates the DB and ensures we have required tables
func initDatabase(ctx context.Context) {
	ctx, span := otel.Tracer(appname).Start(ctx, "InitDatabase")
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
	_, err = db.ExecContext(ctx, `
	    CREATE TABLE IF NOT EXISTS cve_analysis (
	        vulnerability_id TEXT PRIMARY KEY,
	        analysis TEXT,
	        analyzed_at TIMESTAMP
	    )
	`)
	if err != nil {
		log.Fatalf("Failed to create cve_analysis table: %v", err)
	}

}

// listenDockerEvents monitors Docker events. If container starts, we queue a scan with
// user-specified scanners from the "trivy.scanners" label or default "vuln"
// listenDockerEvents monitors Docker events. If container starts, we queue a scan with
// user-specified scanners from the "trivy.scanners" label or default "vuln"
func listenDockerEvents(ctx context.Context, cli *client.Client, scanQueue chan<- imageScanItem, wg *sync.WaitGroup) {
	ctx, span := otel.Tracer(appname).Start(ctx, "ListenDockerEvents")
	defer span.End()

	filterArgs := filters.NewArgs()
	filterArgs.Add("event", "start")
	evCh, errCh := cli.Events(ctx, events.ListOptions{Filters: filterArgs})

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping Docker events listener")
			return
		case evt := <-evCh:
			if evt.Type == events.ContainerEventType {
				info, e2 := cli.ContainerInspect(ctx, evt.Actor.ID)
				if e2 != nil {
					log.Debugf("Error inspecting container %s: %v", evt.Actor.ID, e2)
					continue
				}
				if skip, ok := info.Config.Labels["trivy.scan"]; ok && skip == "false" {
					continue
				}
				scannersToUse := scanners
				if custom, ok := info.Config.Labels["trivy.scanners"]; ok && strings.TrimSpace(custom) != "" {
					scannersToUse = custom
				}
				wg.Add(1)
				select {
				case scanQueue <- imageScanItem{Image: info.Config.Image, Scanners: scannersToUse}:
				case <-ctx.Done():
					wg.Done()
					return
				}
			}
		case e := <-errCh:
			if e != nil {
				log.Debugf("Docker event error: %v", e)
			}
		}
	}
}

// worker processes queued images, calling Trivy with the specified scanners
func worker(ctx context.Context, cli *client.Client, scanQueue <-chan imageScanItem, wg *sync.WaitGroup, wid int, analysisQ chan<- TrivyVulnerability) {
	ctx, span := otel.Tracer(appname).Start(ctx, fmt.Sprintf("Worker%v", wid))
	defer span.End()

	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-scanQueue:
			if !ok {
				return
			}
			func() {
				defer wg.Done()

				// Skip if context cancelled mid-loop
				if ctx.Err() != nil {
					return
				}

				checksum := getImageDigest(ctx, cli, item.Image)

				if alreadyScanned(ctx, item.Image, checksum) {
					return
				}

				markImageScanInProgress(ctx, item.Image)

				if err := requestTrivyScan(ctx, item.Image, trivyServerURL, item.Scanners, analysisQ); err != nil {
					log.Warnf("Trivy scan error for %s: %v", item.Image, err)
				} else {
					saveImageChecksum(ctx, item.Image, checksum)
				}
			}()
		}
	}
}

func alreadyScanned(ctx context.Context, image, checksum string) bool {
	var (
		dbChecksum sql.NullString
		status     sql.NullString
	)
	err := db.QueryRowContext(ctx,
		"SELECT checksum, status FROM image_scans WHERE image = ?",
		image,
	).Scan(&dbChecksum, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		log.Warnf("DB error in alreadyScanned for %s: %v", image, err)
		return false
	}

	checksumVal := ""
	if dbChecksum.Valid {
		checksumVal = dbChecksum.String
	}
	statusVal := ""
	if status.Valid {
		statusVal = status.String
	}

	return (checksumVal == checksum && statusVal == "completed") || statusVal == "in_progress"
}

func getImageDigest(ctx context.Context, cli *client.Client, image string) string {
	ctx, span := otel.Tracer(appname).Start(ctx, "GetImageDigest")
	defer span.End()

	imgInspect, err := cli.ImageInspect(ctx, image)
	if err != nil {
		log.Warnf("Failed inspecting image %s: %v", image, err)
		return ""
	}

	return imgInspect.ID
}

func markImageScanInProgress(ctx context.Context, image string) {
	ctx, span := otel.Tracer(appname).Start(ctx, "MarkImageScanInProgress")
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
	ctx, span := otel.Tracer(appname).Start(ctx, "SaveImageChecksum")
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

// requestTrivyScan runs Trivy with a specified set of scanners
func requestTrivyScan(ctx context.Context, image, server, scanners string, analysisQ chan<- TrivyVulnerability) error {
	ctx, span := otel.Tracer(appname).Start(ctx, "RequestTrivyScan")
	defer span.End()

	args := []string{
		"image",
		"--server", server,
		"--scanners", scanners,
		"--format", "json",
	}
	if trivyExtraArgs != "" {
		args = append(args, strings.Split(trivyExtraArgs, " ")...)
	}
	args = append(args, image)

	scanContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(scanContext, "trivy", args...)
	stdout, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Trivy scan error for %s: %w", image, err)
	}

	var report TrivyReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		return fmt.Errorf("Error unmarshaling Trivy output for %s: %w", image, err)
	}

	saveVulnerabilitiesToDatabase(ctx, report, analysisQ)

	return nil
}

// updateMetricsFromDatabase reads DB vulnerabilities and updates Prometheus metrics
func updateMetricsFromDatabase(ctx context.Context) {
	ctx, span := otel.Tracer(appname).Start(ctx, "UpdateMetricsFromDatabase")
	defer span.End()

	vulnMetric.Reset()
	vulnTimestampMetric.Reset()

	rows, err := db.QueryContext(ctx, `
		SELECT 
			image, image_name, package, package_version, vulnerability_id,
			severity, status, description, timestamp
		FROM vulnerabilities
	`)
	if err != nil {
		log.Warnf("DB query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var (
			image, imageName, pkg, pkgVersion, vulnID, sev, status, desc, ts string
		)
		if err := rows.Scan(&image, &imageName, &pkg, &pkgVersion, &vulnID, &sev, &status, &desc, &ts); err != nil {
			log.Warnf("DB row scan error: %v", err)
			continue
		}
		vulnMetric.WithLabelValues(image, imageName, pkg, pkgVersion, vulnID, sev, status, desc).Set(1)

		parsedTime, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			log.Warnf("Timestamp parse error for %s: %v", vulnID, err)
			continue
		}
		vulnTimestampMetric.WithLabelValues(image, vulnID).Set(float64(parsedTime.Unix()))
	}
}

// handleMetrics is the handler for /metrics
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	log.Trace("Serving /metrics")
	promhttp.Handler().ServeHTTP(w, r)
}

// getEnv reads an environment variable or returns the default
func getEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

// sendAlert adds an alert to the processing queue if it's not already being processed
func sendAlert(ctx context.Context, vuln TrivyVulnerability, analysis string) {
	alert := Alert{
		Image:       vuln.Image,
		Package:     vuln.PkgName,
		CVEID:       vuln.VulnerabilityID,
		Severity:    vuln.Severity,
		Description: fmt.Sprintf("%s\n\nAnalysis:\n%s", vuln.Description, analysis),
	}

	select {
	case alertChannel <- alert:
		log.Debugf("Queued enhanced alert for CVE: %s", vuln.VulnerabilityID)
	default:
		log.Warnf("Alert queue full, dropping CVE alert: %s", vuln.VulnerabilityID)
	}
}

// processAlertBatches continuously processes alerts in batches
func processAlertBatches(ctx context.Context) {
	ctx, span := otel.Tracer(appname).Start(ctx, "ProcessBatchAlertes")
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
				log.Tracef("Alert: %v", alert)
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
	ctx, span := otel.Tracer(appname).Start(ctx, "SendAlertBatch")
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

// saveVulnerabilitiesToDatabase inserts new vulnerabilities into the DB
func saveVulnerabilitiesToDatabase(ctx context.Context, report TrivyReport, analysisQ chan<- TrivyVulnerability) {
	imageName := strings.Split(report.ArtifactName, ":")[0]
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			row := db.QueryRowContext(ctx, `
				SELECT vulnerability_id FROM vulnerabilities
				WHERE vulnerability_id = ? AND image = ?`,
				vuln.VulnerabilityID, report.ArtifactName)
			var existingID string
			if err := row.Scan(&existingID); err != nil && err != sql.ErrNoRows {
				continue
			}
			if existingID == "" {
				_, err := db.ExecContext(ctx, `
					INSERT INTO vulnerabilities (
						vulnerability_id, image, image_name, package, package_version,
						severity, status, description, timestamp
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
				if err != nil {
					log.Tracef("Can't write vuln %s to DB: %v", vuln.VulnerabilityID, err)
					continue
				}

				// Queue vulnerability for asynchronous analysis
				vuln.Image = report.ArtifactName
				select {
				case analysisQ <- vuln:
					log.Debugf("Queued CVE %s for analysis", vuln.VulnerabilityID)
				default:
					log.Warnf("Analysis queue full, dropping CVE: %s", vuln.VulnerabilityID)
				}
			}
		}
	}
}

func handleHealthCheck(w http.ResponseWriter, _ *http.Request) {
	response := HealthResponse{
		Status:    "ok",
		Message:   "Service is healthy",
		CheckedAt: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// Handle encoding error
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func handleStatus(w http.ResponseWriter, _ *http.Request) {
	cve_count := "0"
	err := db.QueryRow("SELECT count(*) from vulnerabilities").Scan(&cve_count)
	if err != nil {
		log.Debug("Can't query vuln count from database")
	}

	response := StatusResponse{
		CVECount:   cve_count,
		NumWorkers: numWorkers,
		CheckedAt:  time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func cveAnalysisWorker(ctx context.Context, queue <-chan TrivyVulnerability) {
	if openAIAPIKey == "" {
		log.Info("Skipping CVE analysis worker: OPENAI_API_KEY not set")
		return
	}

	client := openAIClient()

	for vuln := range queue {
		if cachedAnalysis(ctx, vuln.VulnerabilityID) {
			continue
		}
		prompt := fmt.Sprintf(trivyPrompt,
			vuln.VulnerabilityID, vuln.PkgName, vuln.PkgVersion)

		analysis, err := requestAnalysis(ctx, client, prompt)
		if err != nil {
			log.Warnf("OpenAI analysis error (%s): %v", vuln.VulnerabilityID, err)
			continue
		}

		saveAnalysis(ctx, vuln.VulnerabilityID, analysis)
		sendAlert(ctx, vuln, analysis)
	}
}

func openAIClient() *openai.Client {
	return openai.NewClient(openAIAPIKey)
}

func requestAnalysis(ctx context.Context, client *openai.Client, prompt string) (string, error) {
	resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: openAIModel,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		return "", err
	}
	return resp.Choices[0].Message.Content, nil
}

func cachedAnalysis(ctx context.Context, vulnID string) bool {
	var exists bool
	err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT vulnerability_id FROM cve_analysis WHERE vulnerability_id=?)", vulnID).Scan(&exists)
	if err != nil {
		log.Warnf("DB error checking cache for %s: %v", vulnID, err)
		return false
	}
	return exists
}

func saveAnalysis(ctx context.Context, vulnID, analysis string) {
	_, err := db.ExecContext(ctx, `
		INSERT INTO cve_analysis (vulnerability_id, analysis, analyzed_at)
		VALUES (?, ?, ?)`,
		vulnID, analysis, time.Now().UTC())
	if err != nil {
		log.Warnf("DB error saving analysis for %s: %v", vulnID, err)
	}
}

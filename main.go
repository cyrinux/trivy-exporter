package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	dockerEvents "github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

// RESULTS_DIR: Directory where Trivy JSON outputs are stored.
var resultsDir = getEnv("RESULTS_DIR", "/results")

// DOCKER_HOST: Docker socket or address, e.g. unix:///var/run/docker.sock.
var dockerHost = getEnv("DOCKER_HOST", "unix:///var/run/docker.sock")

// TRIVY_SERVER_URL: Endpoint for Trivy server.
var trivyServerURL = getEnv("TRIVY_SERVER_URL", "http://localhost:4954")

// NTFY_WEBHOOK_URL: ntfy.sh webhook for sending vulnerability alerts.
var ntfyWebhookURL = getEnv("NTFY_WEBHOOK_URL", "https://ntfy.sh/vulns")

// NUM_WORKERS: Number of goroutines that perform image scans.
var numWorkers = getEnv("NUM_WORKERS", "2")

// TRIVY_EXTRA_ARGS: Additional arguments passed to Trivy.
var trivyExtraArgs = getEnv("TRIVY_EXTRA_ARGS", "")

// SCAN_INTERVAL_MINUTES: Prevent rescanning an image within this interval.
var scanIntervalStr = getEnv("SCAN_INTERVAL_MINUTES", "15")

// Global SQLite database handle.
var db *sql.DB

// Prometheus metrics for vulnerabilities.
var vulnMetric = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "trivy_vulnerability",
		Help: "Detected vulnerabilities from Trivy reports",
	},
	[]string{"image", "image_name", "package", "package_version", "id", "severity", "status", "description"},
)

// Prometheus metrics tracking timestamps of vulnerabilities.
var vulnTimestampMetric = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "trivy_vulnerability_timestamp",
		Help: "Timestamp of the last detected vulnerability for each image",
	},
	[]string{"image", "vulnerability_id"},
)

// Rescan interval for images to avoid frequent re-scans.
var scanInterval time.Duration

// Timestamp of the last Prometheus metrics update.
var lastMetricsUpdate time.Time

// TrivyVulnerability models a single vulnerability from a Trivy JSON report.
type TrivyVulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion"`
	Severity        string `json:"Severity"`
	Description     string `json:"Description"`
}

// TrivyReport represents the full JSON structure from Trivy.
type TrivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

// init function sets up logging, database, and scan interval.
func init() {
	// Configure log level based on LOG_LEVEL env variable (default "info").
	logLevel := getEnv("LOG_LEVEL", "info")
	lvl, err := log.ParseLevel(logLevel)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	// Initialize the database (creates tables if needed).
	initDatabase()

	// Parse the scan interval (in minutes) for re-scan checks.
	val, err := strconv.Atoi(scanIntervalStr)
	if err != nil || val < 1 {
		val = 30
		log.Warnf("Invalid SCAN_INTERVAL_MINUTES, defaulting to 30 minutes")
	}
	scanInterval = time.Duration(val) * time.Minute
}

// getEnv fetches an environment variable or returns a provided default.
func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

// initDatabase opens the SQLite database and creates necessary tables.
func initDatabase() {
	var err error
	db, err = sql.Open("sqlite3", resultsDir+"/vulns.db")
	if err != nil {
		log.Fatalf("Failed opening DB: %v", err)
	}
	_, err = db.Exec(`
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
		)`)
	if err != nil {
		log.Fatalf("Failed creating vulnerabilities table: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS scans (
			image TEXT PRIMARY KEY,
			last_scan_time INTEGER
		)`)
	if err != nil {
		log.Fatalf("Failed creating scans table: %v", err)
	}
}

// getLastScanTime retrieves the last time we scanned a specific image.
func getLastScanTime(image string) (time.Time, bool) {
	var t int64
	err := db.QueryRow(`SELECT last_scan_time FROM scans WHERE image = ?`, image).Scan(&t)
	if err != nil {
		log.Debugf("No previous scan time found for %s", image)
		return time.Time{}, false
	}
	return time.Unix(t, 0), true
}

// updateLastScanTime sets the current time for a scanned image in the database.
func updateLastScanTime(image string) {
	_, _ = db.Exec(`INSERT OR REPLACE INTO scans (image, last_scan_time) VALUES (?, ?)`,
		image, time.Now().Unix())
}

// requestTrivyScan calls Trivy on the provided image, storing the JSON report to disk.
func requestTrivyScan(image, server string) error {
	log.Debugf("Scanning image: %s", image)
	parts := strings.Split(image, ":")
	baseName := parts[0]
	tag := "latest"
	if len(parts) > 1 {
		tag = parts[1]
	}
	outFile := fmt.Sprintf("%s/%s_%s.json", resultsDir, strings.ReplaceAll(baseName, "/", "_"), tag)

	args := []string{"image", "--server", server, "--scanners", "vuln", "--format", "json", "--output", outFile}
	if trivyExtraArgs != "" {
		args = append(args, strings.Split(trivyExtraArgs, " ")...)
	}
	args = append(args, image)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "trivy", args...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("Trivy scan timeout for %s", image)
		}
		return fmt.Errorf("Error running Trivy scan: %w", err)
	}

	// Update the DB so we know the last scan time for this image.
	updateLastScanTime(image)
	return nil
}

// parseTrivyReport reads a JSON file from Trivy and saves vulnerabilities.
func parseTrivyReport(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Debugf("Error reading file %s: %v", filePath, err)
		return
	}

	var rep TrivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		log.Debugf("Error unmarshaling %s: %v", filePath, err)
		return
	}

	saveVulnerabilitiesToDatabase(rep)
	os.Remove(filePath)
	log.Debugf("Processed and removed %s", filePath)
}

// walkJsonDirectory finds any .json files in the results directory and processes them.
func walkJsonDirectory() {
	files, err := os.ReadDir(resultsDir)
	if err != nil {
		log.Debugf("Error reading directory: %v", err)
		return
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".json" {
			parseTrivyReport(filepath.Join(resultsDir, f.Name()))
		}
	}
}

// saveVulnerabilitiesToDatabase persists new vulnerabilities to the DB and alerts.
func saveVulnerabilitiesToDatabase(report TrivyReport) {
	imageName := strings.Split(report.ArtifactName, ":")[0]
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			row := db.QueryRow(`SELECT vulnerability_id FROM vulnerabilities WHERE vulnerability_id = ?`, vuln.VulnerabilityID)
			var existingID string
			if err := row.Scan(&existingID); err != nil && err != sql.ErrNoRows {
				continue
			}
			if existingID == "" {
				sendAlert(report.ArtifactName, vuln.PkgName, vuln.VulnerabilityID, vuln.Severity, vuln.Description)
				_, _ = db.Exec(`
					INSERT OR IGNORE INTO vulnerabilities (
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
				log.Debugf("New vulnerability recorded: %s", vuln.VulnerabilityID)
			}
		}
	}
}

// sendAlert sends a notification about a vulnerability to ntfy.sh (if configured).
func sendAlert(image, pkg, cveID, severity, description string) {
	if ntfyWebhookURL == "" {
		log.Debug("ntfyWebhookURL not set, skipping alert")
		return
	}

	log.Debugf("Sending alert for CVE: %s on image: %s", cveID, image)
	msg := fmt.Sprintf(`Image: %s
Package: %s, CVE ID: %s
Description: %s`, image, pkg, cveID, description)

	req, err := http.NewRequest("POST", ntfyWebhookURL, strings.NewReader(msg))
	if err != nil {
		log.Debugf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Title", fmt.Sprintf("New %s vulnerability found", severity))
	req.Header.Set("Priority", "urgent")
	req.Header.Set("Tags", fmt.Sprintf("warning,security,%s", strings.ToLower(severity)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Debugf("Error sending alert: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Debugf("Alert sent for CVE: %s with status: %s", cveID, resp.Status)
}

// updateMetricsFromDatabase refreshes all Prometheus metrics from the DB.
func updateMetricsFromDatabase() {
	log.Debug("Updating Prometheus metrics")

	vulnMetric.Reset()
	vulnTimestampMetric.Reset()

	rows, err := db.Query(`
		SELECT image, image_name, package, package_version, 
		       vulnerability_id, severity, status, description, timestamp
		FROM vulnerabilities
	`)
	if err != nil {
		log.Debugf("Error querying DB: %v", err)
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

	lastMetricsUpdate = time.Now()
	log.Debug("Metrics updated successfully")
}

// handleMetrics is the HTTP handler for serving /metrics to Prometheus.
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	log.Debug("Serving /metrics")
	promhttp.Handler().ServeHTTP(w, r)
}

// listenDockerEvents listens to Docker container events to trigger scans upon container startup.
func listenDockerEvents(scanQueue chan<- string, wg *sync.WaitGroup) {
	log.Debug("Starting Docker event listener")

	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if dockerHost != "unix:///var/run/docker.sock" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}

	ctx := context.Background()
	evtCh, errCh := cli.Events(ctx, dockerEvents.ListOptions{})
	for {
		select {
		case evt := <-evtCh:
			if evt.Type == dockerEvents.ContainerEventType && evt.Action == "start" {
				ctr, err := cli.ContainerInspect(ctx, evt.Actor.ID)
				if err == nil {
					if label, ok := ctr.Config.Labels["trivy.scan"]; ok && label == "false" {
						log.Debug("Skipping container with trivy.scan=false label")
						continue
					}
					lastScan, found := getLastScanTime(ctr.Config.Image)
					if found && time.Since(lastScan) < scanInterval {
						log.Debugf("Skipping recent scan for %s (within %v)", ctr.Config.Image, scanInterval)
						continue
					}
					wg.Add(1)
					select {
					case scanQueue <- ctr.Config.Image:
						log.Debugf("Queued image: %s for scanning", ctr.Config.Image)
					case <-time.After(5 * time.Second):
						log.Debugf("Scan queue blocked, skipping %s", ctr.Config.Image)
					}
				} else {
					log.Debugf("Container inspect error: %v", err)
				}
			}
		case e := <-errCh:
			if e != nil {
				log.Debugf("Docker event error: %v", e)
				time.Sleep(5 * time.Second)
			}
		}
	}
}

// worker continuously processes images from the scan queue by calling requestTrivyScan.
func worker(scanQueue <-chan string, wg *sync.WaitGroup) {
	for image := range scanQueue {
		log.Debugf("Worker scanning %s", image)
		if err := requestTrivyScan(image, trivyServerURL); err != nil {
			log.Warnf("Trivy scan error for %s: %v", image, err)
		}
		wg.Done()
	}
}

// main sets up workers, event listeners, and the HTTP server for metrics.
func main() {
	defer db.Close()

	prometheus.MustRegister(vulnMetric, vulnTimestampMetric)

	n, err := strconv.Atoi(numWorkers)
	if err != nil || n < 2 {
		n = 2
	}
	log.Infof("Starting with %d worker(s), scan interval set to %v", n, scanInterval)

	scanQ := make(chan string, n)
	var wg sync.WaitGroup

	// Spin up worker goroutines.
	for i := 0; i < n; i++ {
		go worker(scanQ, &wg)
	}

	// Periodically walk the results directory to parse leftover JSON reports.
	go func() {
		for {
			walkJsonDirectory()
			time.Sleep(30 * time.Second)
		}
	}()

	// Periodically update Prometheus metrics from the DB.
	go func() {
		for {
			updateMetricsFromDatabase()
			time.Sleep(30 * time.Second)
		}
	}()

	// Start listening to Docker events to detect new containers.
	go listenDockerEvents(scanQ, &wg)

	// Provide /metrics endpoint for Prometheus scrapes.
	http.HandleFunc("/metrics", handleMetrics)

	log.Infof("Listening on :8080/metrics, results in %s", resultsDir)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

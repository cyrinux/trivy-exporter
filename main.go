package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	resultsDir     = getEnv("RESULTS_DIR", "/results")
	dockerHost     = getEnv("DOCKER_HOST", "unix:///var/run/docker.sock")
	trivyServerURL = getEnv("TRIVY_SERVER_URL", "http://localhost:4954")
	ntfyWebhookURL = getEnv("NTFY_WEBHOOK_URL", "https://ntfy.sh/vulns")
	numWorkers     = getEnv("NUM_WORKERS", "2")
	trivyExtraArgs = getEnv("TRIVY_EXTRA_ARGS", "") // Allow extra args for Trivy scans

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
	db *sql.DB

	lastMetricsUpdate time.Time // Track the last time metrics were updated
)

type TrivyVulnerability struct {
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion"`
	Severity        string `json:"Severity"`
	Description     string `json:"Description"`
}

type TrivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	Results      []struct {
		Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
	} `json:"Results"`
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func worker(scanQueue <-chan string, wg *sync.WaitGroup) {
	for image := range scanQueue {
		if err := requestTrivyScan(image, trivyServerURL); err != nil {
			log.Printf("Trivy scan error for %s: %v", image, err)
		}
		wg.Done()
	}
}

func sendAlert(image, pkg, cveID, severity, description string) {
	if ntfyWebhookURL == "" {
		log.Println("No ntfy.sh webhook URL provided, skipping alert")
		return
	}

	message := fmt.Sprintf(`
Image: %s
Package: %s, CVE ID: %s
Description: %s`,
		image, pkg, cveID, description,
	)
	req, err := http.NewRequest("POST", ntfyWebhookURL, strings.NewReader(message))
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Title", fmt.Sprintf("New %s vulnerability found", severity))
	req.Header.Set("Priority", "urgent")
	req.Header.Set("Tags", fmt.Sprintf("warning,security,%s", strings.ToLower(severity)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error sending alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("ntfy.sh returned status: %d", resp.StatusCode)
	}
}

func initDatabase() {
	var err error
	db, err = sql.Open("sqlite3", resultsDir+"/vulns.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
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
		log.Fatalf("Failed to create table: %v", err)
	}
}

func requestTrivyScan(image, server string) error {
	// Split the image into its base name and tag
	parts := strings.Split(image, ":")
	baseImageName := parts[0] // e.g., "alpine"
	tag := "latest"
	if len(parts) > 1 {
		tag = parts[1] // Get the tag if available, otherwise use "latest"
	}

	// Construct the filename using both the base image name and the tag to avoid overwriting
	outputFile := fmt.Sprintf("%s/%s_%s.json", resultsDir, strings.ReplaceAll(baseImageName, "/", "_"), tag)
	cmdArgs := []string{"image", "--server", server, "--scanners", "vuln", "--format", "json", "--output", outputFile}

	// Add extra arguments before the image name
	if trivyExtraArgs != "" {
		log.Printf("Adding extra arguments to Trivy scan: %s", trivyExtraArgs)
		cmdArgs = append(cmdArgs, strings.Split(trivyExtraArgs, " ")...)
	}

	// Finally, append the image name (last argument)
	cmdArgs = append(cmdArgs, image)

	log.Printf("Running Trivy scan with command: trivy %s", strings.Join(cmdArgs, " "))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "trivy", cmdArgs...)
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("trivy scan timeout for %s", image)
		}
		return fmt.Errorf("error running Trivy scan: %w", err)
	}
	return nil
}

func saveVulnerabilitiesToDatabase(report TrivyReport) {
	// Extract base image name (without tag) for storing in the DB
	imageName := strings.Split(report.ArtifactName, ":")[0]

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			// Check if the vulnerability already exists in the DB
			row := db.QueryRow(`SELECT 1 FROM vulnerabilities WHERE vulnerability_id = ?`, vuln.VulnerabilityID)
			var exists int
			if err := row.Scan(&exists); err != nil && err != sql.ErrNoRows {
				log.Printf("Error checking vulnerability in DB: %v", err)
				continue
			}

			// If this vulnerability is not in the DB, insert it
			if exists == 0 {
				sendAlert(report.ArtifactName, vuln.PkgName, vuln.VulnerabilityID, vuln.Severity, vuln.Description)
				_, err := db.Exec(`INSERT OR IGNORE INTO vulnerabilities 
                                    (vulnerability_id, image, image_name, package, package_version, 
                                    severity, status, description, timestamp) 
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					vuln.VulnerabilityID, report.ArtifactName, imageName, vuln.PkgName, vuln.PkgVersion,
					vuln.Severity, "NEW", vuln.Description, time.Now().Format(time.RFC3339))
				if err != nil {
					log.Printf("Error inserting vulnerability into DB: %v", err)
				}
			}
		}
	}
}

func parseTrivyReport(filePath string) {
	// Read the Trivy JSON report from the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("Error reading file %s: %v", filePath, err)
		return
	}

	var report TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		log.Printf("Error parsing JSON %s: %v", filePath, err)
		return
	}

	// Save the vulnerabilities to the database
	saveVulnerabilitiesToDatabase(report)

	// Optionally, remove the JSON file after processing it
	os.Remove(filePath)
}

func walkJsonDirectory() {
	files, err := os.ReadDir(resultsDir)
	if err != nil {
		log.Printf("Error reading directory: %v", err)
		return
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			parseTrivyReport(filepath.Join(resultsDir, file.Name()))
		}
	}
}

func updateMetricsFromDatabase() {
	// Reset Prometheus metrics to avoid duplicates or outdated data
	vulnMetric.Reset()
	vulnTimestampMetric.Reset()

	// Query the database for vulnerabilities
	rows, err := db.Query(`SELECT image, image_name, package, package_version, vulnerability_id, severity, status, description, timestamp FROM vulnerabilities`)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		return
	}
	defer rows.Close()

	// Iterate over all rows and set them in the Prometheus metrics
	for rows.Next() {
		var image, imageName, pkg, pkgVersion, vulnID, severity, status, description, timestamp string
		if err := rows.Scan(&image, &imageName, &pkg, &pkgVersion, &vulnID, &severity, &status, &description, &timestamp); err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		// Update the metrics for the vulnerability
		vulnMetric.WithLabelValues(image, imageName, pkg, pkgVersion, vulnID, severity, status, description).Set(1)
		vulnTimestampMetric.WithLabelValues(image, vulnID).Set(float64(time.Now().Unix()))
	}

	// Update the last metrics update timestamp
	lastMetricsUpdate = time.Now()
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	// Serve the Prometheus metrics
	promhttp.Handler().ServeHTTP(w, r)
}

func listenDockerEvents(scanQueue chan<- string, wg *sync.WaitGroup) {
	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if dockerHost != "unix:///var/run/docker.sock" {
		opts = append(opts, client.WithHost(dockerHost))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatalf("Error creating Docker client: %v", err)
	}

	ctx := context.Background()
	eventChan, errChan := cli.Events(ctx, events.ListOptions{})
	for {
		select {
		case event := <-eventChan:
			if event.Type == events.ContainerEventType && event.Action == "start" {
				container, err := cli.ContainerInspect(ctx, event.Actor.ID)
				if err == nil {
					// Check if the container has the label "trivy.scan" with value "false"
					if scanLabel, exists := container.Config.Labels["trivy.scan"]; exists && scanLabel == "false" {
						log.Printf("Skipping container %s as it has the label trivy.scan: false", container.Config.Image)
						continue
					}

					// If the label is not "false" or the label doesn't exist, scan the container
					log.Printf("Detected new container start: %s", container.Config.Image)
					wg.Add(1)
					scanQueue <- container.Config.Image
				}
			}
		case err := <-errChan:
			log.Printf("Docker event error: %v", err)
		}
	}
}

func main() {
	// Initialize the SQLite database
	initDatabase()

	defer db.Close()

	prometheus.MustRegister(vulnMetric)
	prometheus.MustRegister(vulnTimestampMetric)

	numWorkersInt, err := strconv.Atoi(numWorkers)
	if err != nil || numWorkersInt < 2 {
		log.Println("Invalid NUM_WORKERS value or too low, defaulting to 2")
		numWorkersInt = 2
	}

	scanQueue := make(chan string, numWorkersInt)
	var wg sync.WaitGroup

	for i := 0; i < numWorkersInt; i++ {
		go worker(scanQueue, &wg)
	}

	go func() {
		for {
			walkJsonDirectory()
			time.Sleep(30 * time.Second)
		}
	}()

	go func() {
		for {
			updateMetricsFromDatabase()
			time.Sleep(30 * time.Second)
		}
	}()

	go listenDockerEvents(scanQueue, &wg)

	// Setup HTTP server to expose metrics endpoint
	http.HandleFunc("/metrics", handleMetrics)

	// Print the server info and start listening on port 8080
	log.Printf("Server listening on :8080/metrics, storing results in %s, using Docker host %s, Trivy server at %s",
		resultsDir, dockerHost, trivyServerURL)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

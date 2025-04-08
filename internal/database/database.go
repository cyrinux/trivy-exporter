package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	log "github.com/sirupsen/logrus"
)

var DB *sql.DB

type TrivyVulnerability struct {
	Image           string `json:"Image"`
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

type Alert struct {
	Image       string
	Package     string
	CVEID       string
	Severity    string
	Description string
}

type HealthResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	CheckedAt string `json:"checked_at"`
}

type StatusResponse struct {
	CVECount   string `json:"cve_count"`
	NumWorkers string `json:"num_workers"`
	CheckedAt  string `json:"checked_at"`
}

func InitDatabase(ctx context.Context, resultsDir string) {
	var err error
	DB, err = sql.Open("sqlite3", filepath.Join(resultsDir, "vulns.db"))
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	_, err = DB.ExecContext(ctx, `
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
	_, err = DB.ExecContext(ctx, `
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
	_, err = DB.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_vulns_image ON vulnerabilities (image)
	`)
	if err != nil {
		log.Fatalf("Failed to create index on vulns table: %v", err)
	}
	_, err = DB.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_image_scans_image ON image_scans (image)
	`)
	if err != nil {
		log.Fatalf("Failed to create index on image_scans table: %v", err)
	}
	_, err = DB.ExecContext(ctx, `
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

func CloseDB() {
	_ = DB.Close()
}

func SaveVulnerabilitiesToDatabase(ctx context.Context, report TrivyReport, analysisQ chan<- TrivyVulnerability) {
	imageName := firstPart(report.ArtifactName)
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			r := DB.QueryRowContext(ctx, "SELECT vulnerability_id FROM vulnerabilities WHERE vulnerability_id = ? AND image = ?", vuln.VulnerabilityID, report.ArtifactName)
			var existingID string
			if err := r.Scan(&existingID); err != nil && err != sql.ErrNoRows {
				continue
			}
			if existingID == "" {
				_, err := DB.ExecContext(ctx, `
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
					continue
				}
				vuln.Image = report.ArtifactName
				select {
				case analysisQ <- vuln:
				default:
				}
			}
		}
	}
}

func firstPart(artifact string) string {
	return splitFirst(artifact, ":")
}

func splitFirst(s, sep string) string {
	idx := -1
	for i := range s {
		if string(s[i]) == sep {
			idx = i
			break
		}
	}
	if idx == -1 {
		return s
	}
	return s[:idx]
}

func AlreadyScanned(ctx context.Context, image, checksum string) bool {
	var dbChecksum, status sql.NullString
	err := DB.QueryRowContext(ctx, "SELECT checksum, status FROM image_scans WHERE image = ?", image).Scan(&dbChecksum, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return false
		}
		return false
	}
	if dbChecksum.Valid && dbChecksum.String == checksum && status.Valid && status.String == "completed" {
		return true
	}
	if status.Valid && status.String == "in_progress" {
		return true
	}
	return false
}

func MarkImageScanInProgress(ctx context.Context, image string) {
	_, _ = DB.ExecContext(ctx, `
        INSERT OR REPLACE INTO image_scans (image, status, timestamp)
        VALUES (?, ?, ?)`,
		image, "in_progress", time.Now().Unix(),
	)
}

func SaveImageChecksum(ctx context.Context, image, checksum string) {
	_, _ = DB.ExecContext(ctx, `
        INSERT OR REPLACE INTO image_scans (image, checksum, status, timestamp)
        VALUES (?, ?, ?, ?)`,
		image, checksum, "completed", time.Now().Unix(),
	)
}

func GetVulnerabilityCount() string {
	count := "0"
	_ = DB.QueryRow("SELECT count(*) FROM vulnerabilities").Scan(&count)
	return count
}

func JSONUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

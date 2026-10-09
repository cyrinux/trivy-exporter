// Package database wraps the SQLite store used to persist scan state,
// discovered vulnerabilities and cached CVE analyses.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// DB is the shared database handle, initialized by InitDatabase.
var DB *sql.DB

// generation is bumped on every write that changes the vulnerabilities
// table. Consumers (metrics) use it to skip rebuilding when nothing changed.
var generation atomic.Uint64

// Scan status values stored in image_scans.status.
const (
	ScanStatusInProgress = "in_progress"
	ScanStatusCompleted  = "completed"
	ScanStatusFailed     = "failed"
)

// StaleScanAge is how long an in-progress scan is trusted before a rescan
// is allowed. main sets it above the per-scan timeout used by the workers.
var StaleScanAge = 15 * time.Minute

// TrivyVulnerability is a single vulnerability entry from a Trivy report.
type TrivyVulnerability struct {
	Image           string `json:"Image"`
	VulnerabilityID string `json:"VulnerabilityID"`
	PkgName         string `json:"PkgName"`
	PkgVersion      string `json:"PkgVersion"`
	Severity        string `json:"Severity"`
	Status          string `json:"Status"`
	Description     string `json:"Description"`
}

// TrivyResult is one result block (one target) of a Trivy report.
type TrivyResult struct {
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyReport is the subset of Trivy JSON output we consume.
type TrivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	Results      []TrivyResult `json:"Results"`
}

// Alert is a notification about a newly discovered vulnerability.
type Alert struct {
	Image       string
	Package     string
	CVEID       string
	Severity    string
	Description string
}

// HealthResponse is the body of GET /health.
type HealthResponse struct {
	Status    string `json:"status"`
	Message   string `json:"message"`
	CheckedAt string `json:"checked_at"`
}

// StatusResponse is the body of GET /db/status.
type StatusResponse struct {
	CVECount   int64  `json:"cve_count"`
	ImageCount int64  `json:"image_count"`
	NumWorkers int    `json:"num_workers"`
	CheckedAt  string `json:"checked_at"`
}

// VulnerabilityRow is a flattened vulnerabilities table row.
type VulnerabilityRow struct {
	Image          string
	ImageName      string
	Package        string
	PackageVersion string
	ID             string
	Severity       string
	Status         string
	Description    string
	Timestamp      string
}

// Generation returns a counter that changes whenever vulnerabilities are
// added or removed.
func Generation() uint64 { return generation.Load() }

func bumpGeneration() { generation.Add(1) }

// Open opens (or creates) the SQLite database at dsn and applies the schema.
// Use ":memory:" for tests.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite only supports a single writer; serialize access through one
	// connection to avoid SQLITE_BUSY instead of retrying.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// InitDatabase opens the database in resultsDir and stores it in DB.
// It exits the process on failure.
func InitDatabase(ctx context.Context, resultsDir string) {
	db, err := Open(ctx, filepath.Join(resultsDir, "vulns.db"))
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	DB = db
}

// CloseDB closes the shared handle.
func CloseDB() {
	if DB != nil {
		_ = DB.Close()
	}
}

const vulnerabilitiesSchema = `
CREATE TABLE IF NOT EXISTS vulnerabilities (
	vulnerability_id TEXT NOT NULL,
	image            TEXT NOT NULL,
	image_name       TEXT NOT NULL,
	package          TEXT NOT NULL,
	package_version  TEXT NOT NULL,
	severity         TEXT NOT NULL,
	status           TEXT NOT NULL,
	description      TEXT NOT NULL,
	timestamp        TEXT NOT NULL,
	PRIMARY KEY (vulnerability_id, image, package, package_version)
)`

func migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		vulnerabilitiesSchema,
		`CREATE INDEX IF NOT EXISTS idx_vulns_image ON vulnerabilities (image)`,
		`CREATE TABLE IF NOT EXISTS image_scans (
			image     TEXT PRIMARY KEY,
			checksum  TEXT,
			status    TEXT,
			timestamp INTEGER
		)`,
		`CREATE TABLE IF NOT EXISTS cve_analysis (
			vulnerability_id TEXT PRIMARY KEY,
			analysis         TEXT,
			analyzed_at      TIMESTAMP
		)`,
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// Scans interrupted by a crash or shutdown must be retried, not trusted.
	if _, err := db.ExecContext(ctx, `UPDATE image_scans SET status = ? WHERE status = ?`,
		ScanStatusFailed, ScanStatusInProgress); err != nil {
		return fmt.Errorf("reset interrupted scans: %w", err)
	}
	return nil
}

// SaveVulnerabilitiesToDatabase stores every vulnerability of the report
// that is not yet known for that image and pushes the new ones to analysisQ
// (non-blocking). It returns the number of newly inserted rows.
func SaveVulnerabilitiesToDatabase(ctx context.Context, report TrivyReport, analysisQ chan<- TrivyVulnerability) (int, error) {
	imageName := firstPart(report.ArtifactName)
	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO vulnerabilities (
			vulnerability_id, image, image_name, package, package_version,
			severity, status, description, timestamp
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, fmt.Errorf("prepare: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	var inserted []TrivyVulnerability
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			r, err := stmt.ExecContext(ctx,
				vuln.VulnerabilityID, report.ArtifactName, imageName,
				vuln.PkgName, vuln.PkgVersion, vuln.Severity, "NEW",
				vuln.Description, now)
			if err != nil {
				return 0, fmt.Errorf("insert %s: %w", vuln.VulnerabilityID, err)
			}
			if n, _ := r.RowsAffected(); n > 0 {
				v := vuln
				v.Image = report.ArtifactName
				inserted = append(inserted, v)
			}
		}
	}
	pruned, err := pruneMissing(ctx, tx, report)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	if len(inserted) > 0 || pruned > 0 {
		bumpGeneration()
	}
	if pruned > 0 {
		log.Infof("Removed %d fixed vulnerabilities for %s", pruned, report.ArtifactName)
	}
	for _, v := range inserted {
		if analysisQ == nil {
			break
		}
		select {
		case analysisQ <- v:
		default:
			log.Debugf("analysis queue full, skipping %s", v.VulnerabilityID)
		}
	}
	return len(inserted), nil
}

// pruneMissing deletes rows for the report's image that are absent from the
// report, i.e. vulnerabilities fixed since the previous scan. It must run
// inside tx, which owns the single connection, so a TEMP table is safe.
func pruneMissing(ctx context.Context, tx *sql.Tx, report TrivyReport) (int64, error) {
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS seen (id TEXT, pkg TEXT, ver TEXT)`); err != nil {
		return 0, fmt.Errorf("temp table: %w", err)
	}
	defer func() { _, _ = tx.ExecContext(ctx, `DROP TABLE IF EXISTS temp.seen`) }()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO temp.seen VALUES (?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = stmt.Close() }()
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			if _, err := stmt.ExecContext(ctx, v.VulnerabilityID, v.PkgName, v.PkgVersion); err != nil {
				return 0, err
			}
		}
	}
	r, err := tx.ExecContext(ctx, `
		DELETE FROM vulnerabilities WHERE image = ? AND NOT EXISTS (
			SELECT 1 FROM temp.seen s
			WHERE s.id = vulnerabilities.vulnerability_id
			  AND s.pkg = vulnerabilities.package
			  AND s.ver = vulnerabilities.package_version)`, report.ArtifactName)
	if err != nil {
		return 0, fmt.Errorf("prune: %w", err)
	}
	n, _ := r.RowsAffected()
	return n, nil
}

// ListVulnerabilities returns every stored vulnerability row.
func ListVulnerabilities(ctx context.Context) ([]VulnerabilityRow, error) {
	rows, err := DB.QueryContext(ctx, `
		SELECT image, image_name, package, package_version, vulnerability_id,
		       severity, status, description, timestamp
		FROM vulnerabilities`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []VulnerabilityRow
	for rows.Next() {
		var r VulnerabilityRow
		if err := rows.Scan(&r.Image, &r.ImageName, &r.Package, &r.PackageVersion,
			&r.ID, &r.Severity, &r.Status, &r.Description, &r.Timestamp); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func firstPart(artifact string) string {
	if i := strings.Index(artifact, ":"); i >= 0 {
		return artifact[:i]
	}
	return artifact
}

// AlreadyScanned reports whether image with the given checksum has already
// been scanned successfully, or whether a non-stale scan is in progress.
func AlreadyScanned(ctx context.Context, image, checksum string) bool {
	var dbChecksum, status sql.NullString
	var timestamp sql.NullInt64
	err := DB.QueryRowContext(ctx,
		"SELECT checksum, status, timestamp FROM image_scans WHERE image = ?", image).
		Scan(&dbChecksum, &status, &timestamp)
	if err != nil {
		return false
	}
	switch status.String {
	case ScanStatusCompleted:
		return checksum != "" && dbChecksum.Valid && dbChecksum.String == checksum
	case ScanStatusInProgress:
		if timestamp.Valid && time.Since(time.Unix(timestamp.Int64, 0)) > StaleScanAge {
			log.Warnf("Scan for %s is stale, allowing rescan", image)
			return false
		}
		return true
	default:
		return false
	}
}

// MarkImageScanInProgress records that a scan of image has started.
func MarkImageScanInProgress(ctx context.Context, image string) {
	setScanState(ctx, image, "", ScanStatusInProgress)
}

// SaveImageChecksum records a successful scan of image at the given checksum.
func SaveImageChecksum(ctx context.Context, image, checksum string) {
	setScanState(ctx, image, checksum, ScanStatusCompleted)
}

// MarkImageScanFailed records a failed scan so the image is retried later.
func MarkImageScanFailed(ctx context.Context, image string) {
	setScanState(ctx, image, "", ScanStatusFailed)
}

func setScanState(ctx context.Context, image, checksum, status string) {
	if _, err := DB.ExecContext(ctx, `
		INSERT INTO image_scans (image, checksum, status, timestamp) VALUES (?, ?, ?, ?)
		ON CONFLICT(image) DO UPDATE SET checksum=excluded.checksum,
			status=excluded.status, timestamp=excluded.timestamp`,
		image, checksum, status, time.Now().Unix()); err != nil {
		log.Warnf("Failed to update scan state for %s: %v", image, err)
	}
}

// DeleteImage removes an image's vulnerabilities and scan state, e.g. once
// the image is no longer used by any container.
func DeleteImage(ctx context.Context, image string) error {
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, "DELETE FROM vulnerabilities WHERE image = ?", image)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM image_scans WHERE image = ?", image); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		bumpGeneration()
	}
	return nil
}

// GetVulnerabilityCount returns the number of stored vulnerability rows.
func GetVulnerabilityCount(ctx context.Context) int64 {
	var n int64
	_ = DB.QueryRowContext(ctx, "SELECT count(*) FROM vulnerabilities").Scan(&n)
	return n
}

// GetScannedImageCount returns the number of images with a completed scan.
func GetScannedImageCount(ctx context.Context) int64 {
	var n int64
	_ = DB.QueryRowContext(ctx, "SELECT count(*) FROM image_scans WHERE status = ?", ScanStatusCompleted).Scan(&n)
	return n
}

// HasAnalysis reports whether a cached analysis exists for vulnID.
func HasAnalysis(ctx context.Context, vulnID string) bool {
	var exists bool
	err := DB.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM cve_analysis WHERE vulnerability_id = ?)", vulnID).Scan(&exists)
	return err == nil && exists
}

// SaveAnalysis caches the analysis text for vulnID.
func SaveAnalysis(ctx context.Context, vulnID, analysis string) error {
	_, err := DB.ExecContext(ctx,
		"INSERT OR REPLACE INTO cve_analysis (vulnerability_id, analysis, analyzed_at) VALUES (?, ?, ?)",
		vulnID, analysis, time.Now().UTC())
	return err
}

// Package metrics exposes stored vulnerabilities as Prometheus metrics.
package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	// VulnMetric is set to 1 for every known vulnerability.
	VulnMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability",
			Help: "Detected vulnerabilities from Trivy reports",
		},
		[]string{"image", "image_name", "package", "package_version", "id", "severity", "status", "description"},
	)
	// VulnTimestampMetric is the discovery time of each vulnerability.
	VulnTimestampMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability_timestamp",
			Help: "Unix timestamp of the first detection of each vulnerability per image",
		},
		[]string{"image", "vulnerability_id"},
	)
	// ScansTotal counts scan outcomes.
	ScansTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "trivy_exporter_scans_total",
			Help: "Number of image scans by result (completed, failed, skipped)",
		},
		[]string{"result"},
	)
	// ScanDuration tracks how long Trivy scans take.
	ScanDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "trivy_exporter_scan_duration_seconds",
		Help:    "Duration of Trivy image scans",
		Buckets: prometheus.ExponentialBuckets(1, 2, 10),
	})
	// QueueLength is the number of images waiting for a worker.
	QueueLength = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "trivy_exporter_scan_queue_length",
		Help: "Number of images waiting to be scanned",
	})
)

func init() {
	prometheus.MustRegister(VulnMetric, VulnTimestampMetric, ScansTotal, ScanDuration, QueueLength)
}

// HandleMetrics serves the Prometheus registry.
func HandleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

// UpdateMetricsLoop refreshes the vulnerability gauges whenever the
// database changed, polling at the given interval.
func UpdateMetricsLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	var last uint64
	refresh := func() {
		gen := database.Generation()
		if gen == last {
			return
		}
		if err := Refresh(ctx); err != nil {
			log.Warnf("metrics refresh failed: %v", err)
			return
		}
		last = gen
	}
	// Populate once at start so the first scrape is not empty, and force a
	// rebuild even when the generation counter is still zero.
	if err := Refresh(ctx); err != nil {
		log.Warnf("metrics refresh failed: %v", err)
	}
	last = database.Generation()
	for {
		select {
		case <-t.C:
			refresh()
		case <-ctx.Done():
			return
		}
	}
}

// Refresh rebuilds the vulnerability gauges from the database.
func Refresh(ctx context.Context) error {
	rows, err := database.ListVulnerabilities(ctx)
	if err != nil {
		return err
	}
	VulnMetric.Reset()
	VulnTimestampMetric.Reset()
	for _, r := range rows {
		VulnMetric.WithLabelValues(r.Image, r.ImageName, r.Package, r.PackageVersion,
			r.ID, r.Severity, r.Status, r.Description).Set(1)
		if ts, err := time.Parse(time.RFC3339, r.Timestamp); err == nil {
			VulnTimestampMetric.WithLabelValues(r.Image, r.ID).Set(float64(ts.Unix()))
		}
	}
	return nil
}

// JSONEncode writes v as JSON to w.
func JSONEncode(w http.ResponseWriter, v any) error {
	return json.NewEncoder(w).Encode(v)
}

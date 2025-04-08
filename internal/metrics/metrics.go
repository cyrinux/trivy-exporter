package metrics

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
)

var (
	VulnMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability",
			Help: "Detected vulnerabilities from Trivy reports",
		},
		[]string{"image", "image_name", "package", "package_version", "id", "severity", "status", "description"},
	)
	VulnTimestampMetric = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "trivy_vulnerability_timestamp",
			Help: "Timestamp of the last detected vulnerability for each image",
		},
		[]string{"image", "vulnerability_id"},
	)
)

func init() {
	prometheus.MustRegister(VulnMetric, VulnTimestampMetric)
}

func HandleMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func UpdateMetricsLoop(ctx context.Context) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "UpdateMetrics")
	defer span.End()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			updateMetricsFromDatabase(ctx)
		case <-ctx.Done():
			return
		}
	}
}

func updateMetricsFromDatabase(ctx context.Context) {
	VulnMetric.Reset()
	VulnTimestampMetric.Reset()
	rows, err := database.DB.QueryContext(ctx, `
		SELECT 
			image, image_name, package, package_version, vulnerability_id,
			severity, status, description, timestamp
		FROM vulnerabilities
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var image, imageName, pkg, pkgVersion, vulnID, sev, status, desc, ts string
		if err := rows.Scan(&image, &imageName, &pkg, &pkgVersion, &vulnID, &sev, &status, &desc, &ts); err != nil {
			continue
		}
		VulnMetric.WithLabelValues(image, imageName, pkg, pkgVersion, vulnID, sev, status, desc).Set(1)
		pt, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			continue
		}
		VulnTimestampMetric.WithLabelValues(image, vulnID).Set(float64(pt.Unix()))
	}
}

func JSONEncode(w http.ResponseWriter, v interface{}) error {
	return json.NewEncoder(w).Encode(v)
}

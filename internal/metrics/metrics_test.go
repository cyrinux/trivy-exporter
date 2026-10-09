package metrics

import (
	"context"
	"testing"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRefresh(t *testing.T) {
	ctx := context.Background()
	db, err := database.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() { _ = db.Close(); database.DB = nil })

	rep := database.TrivyReport{ArtifactName: "app:1", Results: []database.TrivyResult{{
		Vulnerabilities: []database.TrivyVulnerability{
			{VulnerabilityID: "CVE-1", PkgName: "a", PkgVersion: "1", Severity: "HIGH"},
			{VulnerabilityID: "CVE-2", PkgName: "b", PkgVersion: "2", Severity: "LOW"},
		}}}}
	if _, err := database.SaveVulnerabilitiesToDatabase(ctx, rep, nil); err != nil {
		t.Fatal(err)
	}
	if err := Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(VulnMetric); n != 2 {
		t.Fatalf("VulnMetric series=%d want 2", n)
	}
	if n := testutil.CollectAndCount(VulnTimestampMetric); n != 2 {
		t.Fatalf("VulnTimestampMetric series=%d want 2", n)
	}
	if err := database.DeleteImage(ctx, "app:1"); err != nil {
		t.Fatal(err)
	}
	if err := Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(VulnMetric); n != 0 {
		t.Fatalf("VulnMetric series after delete=%d want 0", n)
	}
}

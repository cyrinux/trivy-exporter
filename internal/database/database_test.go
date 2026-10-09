package database

import (
	"context"
	"testing"
)

func setup(t *testing.T) context.Context {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	DB = db
	t.Cleanup(func() { _ = db.Close(); DB = nil })
	return ctx
}

func report(image string, vulns ...TrivyVulnerability) TrivyReport {
	return TrivyReport{ArtifactName: image, Results: []TrivyResult{{Vulnerabilities: vulns}}}
}

func TestSaveVulnerabilitiesIsIdempotentAndPerImage(t *testing.T) {
	ctx := setup(t)
	v := TrivyVulnerability{VulnerabilityID: "CVE-1", PkgName: "openssl", PkgVersion: "1.0", Severity: "HIGH"}
	q := make(chan TrivyVulnerability, 10)

	gen := Generation()
	n, err := SaveVulnerabilitiesToDatabase(ctx, report("app:1", v), q)
	if err != nil || n != 1 {
		t.Fatalf("first save: n=%d err=%v", n, err)
	}
	if Generation() == gen {
		t.Fatal("generation should change after insert")
	}
	gen = Generation()
	n, err = SaveVulnerabilitiesToDatabase(ctx, report("app:1", v), q)
	if err != nil || n != 0 {
		t.Fatalf("duplicate save: n=%d err=%v", n, err)
	}
	if Generation() != gen {
		t.Fatal("generation should not change when nothing inserted")
	}
	// Same CVE in a different image must be recorded too.
	n, err = SaveVulnerabilitiesToDatabase(ctx, report("other:2", v), q)
	if err != nil || n != 1 {
		t.Fatalf("second image save: n=%d err=%v", n, err)
	}
	if got := GetVulnerabilityCount(ctx); got != 2 {
		t.Fatalf("count=%d want 2", got)
	}
	if len(q) != 2 {
		t.Fatalf("analysis queue len=%d want 2", len(q))
	}
	got := <-q
	if got.Image != "app:1" {
		t.Fatalf("queued image=%q", got.Image)
	}
	rows, err := ListVulnerabilities(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("list: %d rows err=%v", len(rows), err)
	}
	if rows[0].ImageName != "app" || rows[0].Status != "NEW" {
		t.Fatalf("row=%+v", rows[0])
	}
}

func TestScanStateLifecycle(t *testing.T) {
	ctx := setup(t)
	if AlreadyScanned(ctx, "img", "sha256:a") {
		t.Fatal("unknown image reported as scanned")
	}
	MarkImageScanInProgress(ctx, "img")
	if !AlreadyScanned(ctx, "img", "sha256:a") {
		t.Fatal("in-progress scan should block a rescan")
	}
	MarkImageScanFailed(ctx, "img")
	if AlreadyScanned(ctx, "img", "sha256:a") {
		t.Fatal("failed scan must be retried")
	}
	SaveImageChecksum(ctx, "img", "sha256:a")
	if !AlreadyScanned(ctx, "img", "sha256:a") {
		t.Fatal("completed scan with same digest should be skipped")
	}
	if AlreadyScanned(ctx, "img", "sha256:b") {
		t.Fatal("new digest must trigger a rescan")
	}
	if AlreadyScanned(ctx, "img", "") {
		t.Fatal("unknown digest must trigger a rescan")
	}
	if GetScannedImageCount(ctx) != 1 {
		t.Fatal("scanned image count")
	}
}

func TestRescanPrunesFixedVulnerabilities(t *testing.T) {
	ctx := setup(t)
	a := TrivyVulnerability{VulnerabilityID: "CVE-A", PkgName: "p", PkgVersion: "1"}
	b := TrivyVulnerability{VulnerabilityID: "CVE-B", PkgName: "p", PkgVersion: "1"}
	if _, err := SaveVulnerabilitiesToDatabase(ctx, report("app:1", a, b), nil); err != nil {
		t.Fatal(err)
	}
	// Another image keeps CVE-A and must not be affected.
	if _, err := SaveVulnerabilitiesToDatabase(ctx, report("other:1", a), nil); err != nil {
		t.Fatal(err)
	}
	gen := Generation()
	if _, err := SaveVulnerabilitiesToDatabase(ctx, report("app:1", b), nil); err != nil {
		t.Fatal(err)
	}
	if Generation() == gen {
		t.Fatal("prune must bump generation")
	}
	rows, _ := ListVulnerabilities(ctx)
	if len(rows) != 2 {
		t.Fatalf("rows=%+v", rows)
	}
	for _, r := range rows {
		if r.Image == "app:1" && r.ID != "CVE-B" {
			t.Fatalf("CVE-A should have been pruned from app:1: %+v", r)
		}
	}
}

func TestDeleteImage(t *testing.T) {
	ctx := setup(t)
	v := TrivyVulnerability{VulnerabilityID: "CVE-1", PkgName: "p", PkgVersion: "1"}
	if _, err := SaveVulnerabilitiesToDatabase(ctx, report("app:1", v), nil); err != nil {
		t.Fatal(err)
	}
	SaveImageChecksum(ctx, "app:1", "d")
	if err := DeleteImage(ctx, "app:1"); err != nil {
		t.Fatal(err)
	}
	if GetVulnerabilityCount(ctx) != 0 || AlreadyScanned(ctx, "app:1", "d") {
		t.Fatal("image data not removed")
	}
}

func TestAnalysisCache(t *testing.T) {
	ctx := setup(t)
	if HasAnalysis(ctx, "CVE-1") {
		t.Fatal("unexpected cached analysis")
	}
	if err := SaveAnalysis(ctx, "CVE-1", "fix it"); err != nil {
		t.Fatal(err)
	}
	if !HasAnalysis(ctx, "CVE-1") {
		t.Fatal("analysis not cached")
	}
}

func TestOpenResetsInterruptedScans(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := Open(ctx, dir+"/vulns.db")
	if err != nil {
		t.Fatal(err)
	}
	DB = db
	MarkImageScanInProgress(ctx, "img")
	_ = db.Close()
	db, err = Open(ctx, dir+"/vulns.db")
	if err != nil {
		t.Fatal(err)
	}
	DB = db
	t.Cleanup(func() { _ = db.Close(); DB = nil })
	if AlreadyScanned(ctx, "img", "x") {
		t.Fatal("interrupted scan must be retried after restart")
	}
}

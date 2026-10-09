package scanning

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)

type fakeDocker struct {
	containers []container.Summary
	digests    map[string]string
	events     chan events.Message
	errs       chan error
}

func (f *fakeDocker) Events(context.Context, events.ListOptions) (<-chan events.Message, <-chan error) {
	return f.events, f.errs
}

func (f *fakeDocker) ContainerInspect(_ context.Context, id string) (container.InspectResponse, error) {
	for _, c := range f.containers {
		if c.ID == id {
			return container.InspectResponse{Config: &container.Config{Image: c.Image, Labels: c.Labels}}, nil
		}
	}
	return container.InspectResponse{}, os.ErrNotExist
}

func (f *fakeDocker) ContainerList(context.Context, container.ListOptions) ([]container.Summary, error) {
	return f.containers, nil
}

func (f *fakeDocker) ImageInspect(_ context.Context, img string, _ ...client.ImageInspectOption) (image.InspectResponse, error) {
	return image.InspectResponse{ID: f.digests[img]}, nil
}

func TestBuildTrivyArgs(t *testing.T) {
	got := BuildTrivyArgs("nginx:1", "http://srv:4954", "vuln,secret", " --ignore-unfixed  --severity HIGH,CRITICAL ")
	want := []string{"image", "--format", "json", "--quiet", "--server", "http://srv:4954",
		"--scanners", "vuln,secret", "--ignore-unfixed", "--severity", "HIGH,CRITICAL", "nginx:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if got := BuildTrivyArgs("a", "", "", ""); !reflect.DeepEqual(got, []string{"image", "--format", "json", "--quiet", "a"}) {
		t.Fatalf("minimal args: %v", got)
	}
}

func TestParseReport(t *testing.T) {
	r, err := ParseReport([]byte(`{"ArtifactName":"a:1","Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH"}]}]}`))
	if err != nil || r.ArtifactName != "a:1" || len(r.Results[0].Vulnerabilities) != 1 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if _, err := ParseReport([]byte("nope")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestItemForHonorsLabels(t *testing.T) {
	s := &Scanner{Scanners: "vuln"}
	if _, ok := s.itemFor("img", map[string]string{LabelScan: "false"}, false); ok {
		t.Fatal("trivy.scan=false must skip")
	}
	if _, ok := s.itemFor("", nil, false); ok {
		t.Fatal("empty image must skip")
	}
	it, ok := s.itemFor("img", map[string]string{LabelScanners: "vuln,secret"}, true)
	if !ok || it.Scanners != "vuln,secret" || !it.Force {
		t.Fatalf("item=%+v ok=%v", it, ok)
	}
	it, _ = s.itemFor("img", nil, false)
	if it.Scanners != "vuln" {
		t.Fatalf("default scanners: %+v", it)
	}
}

func TestQueueDedupes(t *testing.T) {
	q := NewQueue(10)
	ctx := context.Background()
	q.Push(ctx, ImageScanItem{Image: "a"})
	q.Push(ctx, ImageScanItem{Image: "a"})
	q.Push(ctx, ImageScanItem{Image: "b"})
	if q.Len() != 2 {
		t.Fatalf("len=%d want 2", q.Len())
	}
	// A later forced request for a queued image is merged into it.
	q.Push(ctx, ImageScanItem{Image: "a", Force: true})
	if q.Len() != 2 || !q.release("a") {
		t.Fatal("force flag should be merged into the pending item")
	}
	if q.release("b") {
		t.Fatal("b was never forced")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	full := NewQueue(0)
	if full.Push(cctx, ImageScanItem{Image: "x"}) {
		t.Fatal("push on canceled context should fail")
	}
	if _, pending := full.pending["x"]; pending {
		t.Fatal("pending entry must be released on failed push")
	}
}

// fakeTrivy writes a script that emits a fixed report and returns its path.
func fakeTrivy(t *testing.T, report string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "trivy")
	script := "#!/bin/sh\nfor a; do last=$a; done\nif [ \"$last\" = fail ]; then echo boom >&2; exit 1; fi\ncat <<'JSON'\n" + report + "\nJSON\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWorkerScansRunningContainersAndEvents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := database.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() { _ = db.Close(); database.DB = nil })

	fd := &fakeDocker{
		containers: []container.Summary{
			{ID: "c1", Image: "app:1"},
			{ID: "c2", Image: "skip:1", Labels: map[string]string{LabelScan: "false"}},
		},
		digests: map[string]string{"app:1": "sha256:aaa", "new:2": "sha256:bbb"},
		events:  make(chan events.Message, 1),
		errs:    make(chan error),
	}
	report := `{"ArtifactName":"app:1","Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","PkgVersion":"1","Severity":"HIGH"}]}]}`
	s := &Scanner{Docker: fd, Queue: NewQueue(10), ServerURL: "", Scanners: "vuln", TrivyBin: fakeTrivy(t, report), Timeout: 5 * time.Second}

	var wg sync.WaitGroup
	wg.Add(1)
	go s.Worker(ctx, 0, &wg)
	// Stop the worker before the DB cleanup registered above closes the handle.
	t.Cleanup(func() { cancel(); wg.Wait() })

	status := func(image string) string {
		var st string
		_ = db.QueryRowContext(ctx, "SELECT status FROM image_scans WHERE image = ?", image).Scan(&st)
		return st
	}

	s.ScanRunningContainers(ctx, false)
	waitFor(t, func() bool { return status("app:1") == database.ScanStatusCompleted })
	if !database.AlreadyScanned(ctx, "app:1", "sha256:aaa") {
		t.Fatal("completed scan should be recorded with its digest")
	}
	if database.AlreadyScanned(ctx, "skip:1", "") {
		t.Fatal("labeled container must not be scanned")
	}
	if database.GetVulnerabilityCount(ctx) != 1 {
		t.Fatal("vulnerability not stored")
	}

	// A container start event for a new image triggers a scan.
	fd.containers = append(fd.containers, container.Summary{ID: "c3", Image: "new:2"})
	go s.ListenDockerEvents(ctx)
	fd.events <- events.Message{Type: events.ContainerEventType, Action: "start", Actor: events.Actor{ID: "c3"}}
	waitFor(t, func() bool { return status("new:2") == database.ScanStatusCompleted })

	// A failing scan is recorded as failed so it can be retried.
	s.Queue.Push(ctx, ImageScanItem{Image: "fail"})
	waitFor(t, func() bool { return status("fail") == database.ScanStatusFailed })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

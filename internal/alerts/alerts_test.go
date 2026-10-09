package alerts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
)

func TestHighestSeverityAndPriority(t *testing.T) {
	alerts := []database.Alert{{Severity: "LOW"}, {Severity: "Critical"}, {Severity: "medium"}}
	if got := highestSeverity(alerts); got != "critical" {
		t.Fatalf("highest=%q", got)
	}
	if priorityFor("critical") != "urgent" || priorityFor("medium") != "high" || priorityFor("low") != "default" {
		t.Fatal("priority mapping")
	}
}

func TestSendAlertBatchPostsToNtfy(t *testing.T) {
	type got struct {
		title, prio, tags, body string
	}
	ch := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- got{r.Header.Get("Title"), r.Header.Get("Priority"), r.Header.Get("Tags"), string(b)}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	alerts := []database.Alert{
		{Image: "app:1", Package: "ssl", CVEID: "CVE-1", Severity: "HIGH", Description: "bad"},
		{Image: "app:1", Package: "zlib", CVEID: "CVE-2", Severity: "LOW", Description: "meh"},
	}
	sendAlertBatch(context.Background(), alerts, srv.URL)
	g := <-ch
	if !strings.HasPrefix(g.title, "2 new vulnerabilities") || g.prio != "urgent" || !strings.Contains(g.tags, "high") {
		t.Fatalf("headers: %+v", g)
	}
	if !strings.Contains(g.body, "Alert 1/2") || !strings.Contains(g.body, "CVE-2") {
		t.Fatalf("body: %s", g.body)
	}
}

func TestCollectBatchHonorsSizeAndWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < BatchSize+1; i++ {
		SendAlert(database.TrivyVulnerability{VulnerabilityID: "CVE"}, "")
	}
	b, ok := collectBatch(ctx)
	if !ok || len(b) != BatchSize {
		t.Fatalf("first batch len=%d ok=%v", len(b), ok)
	}
	b, ok = collectBatch(ctx)
	if !ok || len(b) != 1 {
		t.Fatalf("second batch len=%d ok=%v", len(b), ok)
	}
	cancel()
	if _, ok := collectBatch(ctx); ok {
		t.Fatal("canceled context should stop collection")
	}
}

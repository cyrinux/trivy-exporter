package alerts

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
)

var (
	AlertChannel     = make(chan database.Alert, 100)
	AlertsInProgress = make(map[string]bool)
)

func SendAlert(ctx context.Context, vuln database.TrivyVulnerability, analysis string) {
	alert := database.Alert{
		Image:       vuln.Image,
		Package:     vuln.PkgName,
		CVEID:       vuln.VulnerabilityID,
		Severity:    vuln.Severity,
		Description: vuln.Description + "\n\nAnalysis:\n" + analysis,
	}
	select {
	case AlertChannel <- alert:
	default:
	}
}

func ProcessAlertBatches(ctx context.Context, ntfyURL string) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "ProcessBatchAlerts")
	defer span.End()
	for {
		var batch []database.Alert
		size := 0
		done := false
		for size < 5 && !done {
			select {
			case a := <-AlertChannel:
				batch = append(batch, a)
				size++
			case <-time.After(100 * time.Millisecond):
				done = true
			}
		}
		if len(batch) > 0 {
			sendAlertBatch(ctx, batch, ntfyURL)
			for _, a := range batch {
				delete(AlertsInProgress, a.CVEID+":"+a.Image)
			}
			time.Sleep(10 * time.Second)
		} else {
			time.Sleep(1 * time.Second)
		}
	}
}

func sendAlertBatch(ctx context.Context, alerts []database.Alert, ntfyURL string) {
	if ntfyURL == "" || len(alerts) == 0 {
		return
	}
	var sb strings.Builder
	sevOrder := map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	highest := "low"
	for i, a := range alerts {
		cur := strings.ToLower(a.Severity)
		if sevOrder[cur] > sevOrder[highest] {
			highest = cur
		}
		fmt.Fprintf(&sb, "Alert %d/%d:\nImage: %s\nPackage: %s, CVE: %s\nSeverity: %s\nDescription: %s\n\n",
			i+1, len(alerts), a.Image, a.Package, a.CVEID, a.Severity, a.Description)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", ntfyURL, strings.NewReader(sb.String()))
	if err != nil {
		return
	}
	title := fmt.Sprintf("%d New vulnerabilities found (highest: %s)", len(alerts), highest)
	req.Header.Set("Title", title)
	p := "default"
	if highest == "critical" || highest == "high" {
		p = "urgent"
	} else if highest == "medium" {
		p = "high"
	}
	req.Header.Set("Priority", p)
	req.Header.Set("Tags", fmt.Sprintf("warning,security,batch,%s", highest))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	log.Infof("Alert batch sent with status: %s", resp.Status)
}

// Package alerts batches vulnerability notifications and delivers them to
// an ntfy-compatible webhook.
package alerts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	log "github.com/sirupsen/logrus"
)

const (
	// BatchSize is the maximum number of alerts per notification.
	BatchSize = 5
	// BatchWindow is how long to wait for more alerts after the first one.
	BatchWindow = 2 * time.Second
	// MinInterval is the minimum delay between two notifications.
	MinInterval = 10 * time.Second
)

// AlertChannel receives alerts to be batched and sent.
var AlertChannel = make(chan database.Alert, 100)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// SendAlert enqueues an alert; it never blocks and drops when the queue is full.
func SendAlert(vuln database.TrivyVulnerability, analysis string) {
	desc := vuln.Description
	if analysis != "" {
		desc += "\n\nAnalysis:\n" + analysis
	}
	alert := database.Alert{
		Image:       vuln.Image,
		Package:     vuln.PkgName,
		CVEID:       vuln.VulnerabilityID,
		Severity:    vuln.Severity,
		Description: desc,
	}
	select {
	case AlertChannel <- alert:
	default:
		log.Warnf("alert queue full, dropping alert for %s", vuln.VulnerabilityID)
	}
}

// ProcessAlertBatches blocks until ctx is done, grouping alerts into batches
// and posting them to ntfyURL. An empty URL disables delivery.
func ProcessAlertBatches(ctx context.Context, ntfyURL string) {
	if ntfyURL == "" {
		log.Info("NTFY_WEBHOOK_URL not set, alerts disabled")
		// Keep draining so producers never see a full queue.
		for {
			select {
			case <-ctx.Done():
				return
			case <-AlertChannel:
			}
		}
	}
	for {
		batch, ok := collectBatch(ctx)
		if !ok {
			return
		}
		sendAlertBatch(ctx, batch, ntfyURL)
		select {
		case <-ctx.Done():
			return
		case <-time.After(MinInterval):
		}
	}
}

// collectBatch waits for the first alert then gathers up to BatchSize alerts
// within BatchWindow. It returns false when ctx is canceled.
func collectBatch(ctx context.Context) ([]database.Alert, bool) {
	var first database.Alert
	select {
	case <-ctx.Done():
		return nil, false
	case first = <-AlertChannel:
	}
	batch := []database.Alert{first}
	timer := time.NewTimer(BatchWindow)
	defer timer.Stop()
	for len(batch) < BatchSize {
		select {
		case <-ctx.Done():
			return batch, true
		case a := <-AlertChannel:
			batch = append(batch, a)
		case <-timer.C:
			return batch, true
		}
	}
	return batch, true
}

var sevOrder = map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func highestSeverity(alerts []database.Alert) string {
	highest := "unknown"
	for _, a := range alerts {
		cur := strings.ToLower(a.Severity)
		if sevOrder[cur] > sevOrder[highest] {
			highest = cur
		}
	}
	return highest
}

func priorityFor(sev string) string {
	switch sev {
	case "critical", "high":
		return "urgent"
	case "medium":
		return "high"
	default:
		return "default"
	}
}

func formatBatch(alerts []database.Alert) string {
	var sb strings.Builder
	for i, a := range alerts {
		fmt.Fprintf(&sb, "Alert %d/%d:\nImage: %s\nPackage: %s, CVE: %s\nSeverity: %s\nDescription: %s\n\n",
			i+1, len(alerts), a.Image, a.Package, a.CVEID, a.Severity, a.Description)
	}
	return sb.String()
}

func sendAlertBatch(ctx context.Context, alerts []database.Alert, ntfyURL string) {
	if len(alerts) == 0 {
		return
	}
	highest := highestSeverity(alerts)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ntfyURL, strings.NewReader(formatBatch(alerts)))
	if err != nil {
		log.Warnf("alert request error: %v", err)
		return
	}
	req.Header.Set("Title", fmt.Sprintf("%d new vulnerabilities found (highest: %s)", len(alerts), highest))
	req.Header.Set("Priority", priorityFor(highest))
	req.Header.Set("Tags", "warning,security,batch,"+highest)
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Warnf("alert delivery failed: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		log.Warnf("alert delivery returned %s", resp.Status)
		return
	}
	log.Infof("Alert batch of %d sent (%s)", len(alerts), resp.Status)
}

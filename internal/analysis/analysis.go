package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/alerts"
	"github.com/cyrinux/trivy-exporter/internal/database"
	openai "github.com/sashabaranov/go-openai"
)

const trivyPrompt = "Provide mitigation steps and fix recommendations for vulnerability %s affecting package %s version %s. Include official references if available."

func CVEAnalysisWorker(ctx context.Context, queue <-chan database.TrivyVulnerability, apiKey, model string) {
	if apiKey == "" {
		return
	}
	cli := openai.NewClient(apiKey)
	for vuln := range queue {
		if cachedAnalysis(ctx, vuln.VulnerabilityID) {
			continue
		}
		p := fmt.Sprintf(trivyPrompt, vuln.VulnerabilityID, vuln.PkgName, vuln.PkgVersion)
		resp, err := requestAnalysis(ctx, cli, p, model)
		if err != nil {
			continue
		}
		saveAnalysis(ctx, vuln.VulnerabilityID, resp)
		alerts.SendAlert(ctx, vuln, resp)
	}
}

func requestAnalysis(ctx context.Context, c *openai.Client, prompt, model string) (string, error) {
	r, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: prompt},
		},
	})
	if err != nil {
		return "", err
	}
	return r.Choices[0].Message.Content, nil
}

func cachedAnalysis(ctx context.Context, vulnID string) bool {
	var exists bool
	err := database.DB.QueryRowContext(ctx, "SELECT EXISTS(SELECT vulnerability_id FROM cve_analysis WHERE vulnerability_id=?)", vulnID).Scan(&exists)
	if err != nil {
		return false
	}
	return exists
}

func saveAnalysis(ctx context.Context, vulnID, analysis string) {
	_, _ = database.DB.ExecContext(ctx, "INSERT INTO cve_analysis (vulnerability_id, analysis, analyzed_at) VALUES (?, ?, ?)",
		vulnID, analysis, time.Now().UTC())
}

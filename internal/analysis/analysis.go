// Package analysis asks an OpenAI model for mitigation advice on newly
// discovered vulnerabilities and forwards the result as an alert.
package analysis

import (
	"context"
	"errors"
	"fmt"

	"github.com/cyrinux/trivy-exporter/internal/alerts"
	"github.com/cyrinux/trivy-exporter/internal/database"
	openai "github.com/sashabaranov/go-openai"
	log "github.com/sirupsen/logrus"
)

const trivyPrompt = "Provide mitigation steps and fix recommendations for vulnerability %s affecting package %s version %s. Include official references if available."

// CVEAnalysisWorker consumes vulnerabilities from queue. With an API key it
// requests an analysis (cached per CVE) before alerting; without one it
// alerts directly.
func CVEAnalysisWorker(ctx context.Context, queue <-chan database.TrivyVulnerability, apiKey, model string) {
	var cli *openai.Client
	if apiKey != "" {
		cli = openai.NewClient(apiKey)
	} else {
		log.Info("OPENAI_API_KEY not set, CVE analysis disabled")
	}
	for {
		select {
		case <-ctx.Done():
			return
		case vuln, ok := <-queue:
			if !ok {
				return
			}
			handle(ctx, cli, model, vuln)
		}
	}
}

func handle(ctx context.Context, cli *openai.Client, model string, vuln database.TrivyVulnerability) {
	if cli == nil {
		alerts.SendAlert(vuln, "")
		return
	}
	if database.HasAnalysis(ctx, vuln.VulnerabilityID) {
		return
	}
	prompt := fmt.Sprintf(trivyPrompt, vuln.VulnerabilityID, vuln.PkgName, vuln.PkgVersion)
	resp, err := requestAnalysis(ctx, cli, prompt, model)
	if err != nil {
		log.Warnf("analysis of %s failed: %v", vuln.VulnerabilityID, err)
		alerts.SendAlert(vuln, "")
		return
	}
	if err := database.SaveAnalysis(ctx, vuln.VulnerabilityID, resp); err != nil {
		log.Warnf("saving analysis of %s failed: %v", vuln.VulnerabilityID, err)
	}
	alerts.SendAlert(vuln, resp)
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
	if len(r.Choices) == 0 {
		return "", errors.New("empty completion")
	}
	return r.Choices[0].Message.Content, nil
}

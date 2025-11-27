package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/alerts"
	"github.com/cyrinux/trivy-exporter/internal/analysis"
	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/cyrinux/trivy-exporter/internal/metrics"
	"github.com/cyrinux/trivy-exporter/internal/scanning"
	"github.com/cyrinux/trivy-exporter/internal/tracer"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
)

var (
        resultsDir              = scanning.GetEnv("RESULTS_DIR", "/results")
        dockerHost              = scanning.GetEnv("DOCKER_HOST", "unix:///var/run/docker.sock")
        trivyServerURL          = scanning.GetEnv("TRIVY_SERVER_URL", "http://localhost:4954")
        ntfyWebhookURL          = scanning.GetEnv("NTFY_WEBHOOK_URL", "https://ntfy.sh/vulns")
        tempoEndpoint           = scanning.GetEnv("TEMPO_ENDPOINT", "localhost:4317")
        pyroscopeEndpoint       = scanning.GetEnv("PYROSCOPE_ENDPOINT", "http://localhost:4040")
        numWorkers              = scanning.GetEnv("NUM_WORKERS", "1")
        trivyExtraArgs          = scanning.GetEnv("TRIVY_EXTRA_ARGS", "")
        disableTracingProfiling = strings.ToLower(scanning.GetEnv("DISABLE_TRACING_PROFILING", "false")) == "true"
        logLevel                = scanning.GetEnv("LOG_LEVEL", "info")
        openAIAPIKey            = scanning.GetEnv("OPENAI_API_KEY", "")
        openAIModel             = scanning.GetEnv("OPENAI_MODEL", "gpt-4-turbo")
        scanners                = "vuln"
        appname                 = "trivy-exporter"
)
func main() {
	lvl, err := log.ParseLevel(logLevel)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
	rootCtx, cancel := context.WithCancel(context.Background())
	ctx, span := otel.Tracer(appname).Start(rootCtx, "Main")
	defer span.End()
	go waitForShutdown(cancel)
	n, err := strconv.Atoi(numWorkers)
	if err != nil {
		n = 1
	}
	database.InitDatabase(ctx, resultsDir)
	defer database.CloseDB()
	tp, profiler := tracer.InitTracer(ctx, appname, tempoEndpoint, pyroscopeEndpoint, disableTracingProfiling)
	defer func() {
		if profiler != nil {
			_ = profiler.Stop()
		}
		if tp != nil {
			_ = tp.Shutdown(ctx)
		}
	}()
	opts := []client.Opt{client.WithAPIVersionNegotiation()}
	if dockerHost != "unix:///var/run/docker.sock" {
		opts = append(opts, client.WithHost(dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		log.Fatalf("Docker client error: %v", err)
	}
	analysisQ := make(chan database.TrivyVulnerability, 10)
	go analysis.CVEAnalysisWorker(ctx, analysisQ, openAIAPIKey, openAIModel)
	scanQ := make(chan scanning.ImageScanItem, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		go scanning.Worker(ctx, cli, scanQ, &wg, i, analysisQ, trivyServerURL, trivyExtraArgs)
	}
	go scanning.ListenDockerEvents(ctx, cli, scanQ, &wg, scanners)
	go alerts.ProcessAlertBatches(ctx, ntfyWebhookURL)
	go metrics.UpdateMetricsLoop(ctx)
	http.Handle("/metrics", otelhttp.NewHandler(http.HandlerFunc(metrics.HandleMetrics), "Metrics"))
	http.Handle("/health", otelhttp.NewHandler(http.HandlerFunc(handleHealthCheck), "HealthCheck"))
	http.Handle("/db/status", otelhttp.NewHandler(http.HandlerFunc(handleStatus), "Status"))
	log.Infof("Listening on :8080, results in %s", resultsDir)
	log.Fatal(http.ListenAndServe(":8080", nil))
	wg.Wait()
	close(scanQ)
}

func waitForShutdown(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	log.Info("Interrupt received, shutting down...")
	cancel()
}

func handleHealthCheck(w http.ResponseWriter, _ *http.Request) {
	resp := database.HealthResponse{
		Status:    "ok",
		Message:   "Service is healthy",
		CheckedAt: time.Now().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = metrics.JSONEncode(w, resp)
}

func handleStatus(w http.ResponseWriter, _ *http.Request) {

        cveCount := database.GetVulnerabilityCount()

        resp := database.StatusResponse{

                        CVECount:   cveCount,
				NumWorkers: numWorkers,
				CheckedAt:  time.Now().Format(time.RFC3339),
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = metrics.JSONEncode(w, resp)
		}

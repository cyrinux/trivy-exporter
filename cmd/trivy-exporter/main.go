// Command trivy-exporter watches Docker, scans container images with Trivy
// and exposes the findings as Prometheus metrics.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
)

const appname = "trivy-exporter"

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type config struct {
	listenAddr        string
	resultsDir        string
	dockerHost        string
	trivyServerURL    string
	trivyExtraArgs    string
	scanners          string
	numWorkers        int
	scanInterval      time.Duration
	scanTimeout       time.Duration
	metricsRefresh    time.Duration
	ntfyWebhookURL    string
	tempoEndpoint     string
	pyroscopeEndpoint string
	disableTracing    bool
	logLevel          string
	openAIAPIKey      string
	openAIModel       string
}

func loadConfig() config {
	return config{
		listenAddr:        scanning.GetEnv("LISTEN_ADDR", ":8080"),
		resultsDir:        scanning.GetEnv("RESULTS_DIR", "/results"),
		dockerHost:        scanning.GetEnv("DOCKER_HOST", ""),
		trivyServerURL:    scanning.GetEnv("TRIVY_SERVER_URL", ""),
		trivyExtraArgs:    scanning.GetEnv("TRIVY_EXTRA_ARGS", ""),
		scanners:          scanning.GetEnv("TRIVY_SCANNERS", "vuln"),
		numWorkers:        envInt("NUM_WORKERS", 1),
		scanInterval:      time.Duration(envInt("SCAN_INTERVAL_MINUTES", 360)) * time.Minute,
		scanTimeout:       time.Duration(envInt("SCAN_TIMEOUT_MINUTES", 10)) * time.Minute,
		metricsRefresh:    time.Duration(envInt("METRICS_REFRESH_SECONDS", 15)) * time.Second,
		ntfyWebhookURL:    scanning.GetEnv("NTFY_WEBHOOK_URL", ""),
		tempoEndpoint:     scanning.GetEnv("TEMPO_ENDPOINT", "localhost:4317"),
		pyroscopeEndpoint: scanning.GetEnv("PYROSCOPE_ENDPOINT", "http://localhost:4040"),
		disableTracing:    strings.EqualFold(scanning.GetEnv("DISABLE_TRACING_PROFILING", "false"), "true"),
		logLevel:          scanning.GetEnv("LOG_LEVEL", "info"),
		openAIAPIKey:      scanning.GetEnv("OPENAI_API_KEY", ""),
		openAIModel:       scanning.GetEnv("OPENAI_MODEL", "gpt-4o-mini"),
	}
}

func envInt(key string, def int) int {
	v := scanning.GetEnv(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Warnf("Invalid %s=%q, using %d", key, v, def)
		return def
	}
	return n
}

func main() {
	cfg := loadConfig()
	lvl, err := log.ParseLevel(cfg.logLevel)
	if err != nil {
		lvl = log.InfoLevel
	}
	log.SetLevel(lvl)
	log.Infof("Starting %s %s", appname, version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err = run(ctx, cfg)
	stop()
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Info("Stopped")
}

func run(ctx context.Context, cfg config) error {
	// An in-progress scan is distrusted once it could not possibly still be running.
	database.StaleScanAge = cfg.scanTimeout + 5*time.Minute
	database.InitDatabase(ctx, cfg.resultsDir)
	defer database.CloseDB()

	tp, profiler, err := tracer.InitTracer(ctx, appname, version, cfg.tempoEndpoint, cfg.pyroscopeEndpoint, cfg.disableTracing)
	if err != nil {
		return fmt.Errorf("observability setup failed: %w", err)
	}
	defer func() {
		if profiler != nil {
			_ = profiler.Stop()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	}()

	opts := []client.Opt{client.WithAPIVersionNegotiation(), client.FromEnv}
	if cfg.dockerHost != "" {
		opts = append(opts, client.WithHost(cfg.dockerHost))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return fmt.Errorf("docker client error: %w", err)
	}
	defer func() { _ = cli.Close() }()

	workers := max(cfg.numWorkers, 1)
	analysisQ := make(chan database.TrivyVulnerability, 100)
	scanner := &scanning.Scanner{
		Docker:    cli,
		Queue:     scanning.NewQueue(workers * 16),
		AnalysisQ: analysisQ,
		ServerURL: cfg.trivyServerURL,
		ExtraArgs: cfg.trivyExtraArgs,
		Scanners:  cfg.scanners,
		Timeout:   cfg.scanTimeout,
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go scanner.Worker(ctx, i, &wg)
	}
	go analysis.CVEAnalysisWorker(ctx, analysisQ, cfg.openAIAPIKey, cfg.openAIModel)
	go alerts.ProcessAlertBatches(ctx, cfg.ntfyWebhookURL)
	go metrics.UpdateMetricsLoop(ctx, cfg.metricsRefresh)
	go scanner.ListenDockerEvents(ctx)
	go scanner.ScanRunningContainers(ctx, false)
	go scanner.PeriodicRescan(ctx, cfg.scanInterval)

	mux := http.NewServeMux()
	mux.Handle("/metrics", otelhttp.NewHandler(http.HandlerFunc(metrics.HandleMetrics), "Metrics"))
	mux.Handle("/health", otelhttp.NewHandler(http.HandlerFunc(handleHealthCheck), "HealthCheck"))
	mux.Handle("/db/status", otelhttp.NewHandler(statusHandler(workers), "Status"))
	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Infof("Listening on %s, results in %s, %d worker(s), rescan every %s", cfg.listenAddr, cfg.resultsDir, workers, cfg.scanInterval)
		errCh <- srv.ListenAndServe()
	}()

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("Shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("http server: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	wg.Wait()
	return runErr
}

func handleHealthCheck(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, database.HealthResponse{
		Status:    "ok",
		Message:   "Service is healthy",
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

func statusHandler(workers int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, database.StatusResponse{
			CVECount:   database.GetVulnerabilityCount(r.Context()),
			ImageCount: database.GetScannedImageCount(r.Context()),
			NumWorkers: workers,
			CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		})
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := metrics.JSONEncode(w, v); err != nil {
		log.Warnf("JSON encode failed: %v", err)
	}
}

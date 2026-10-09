// Package scanning discovers container images from Docker and runs Trivy
// against them through a pool of workers.
package scanning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/cyrinux/trivy-exporter/internal/metrics"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
)

// Docker labels understood by the exporter.
const (
	LabelScan     = "trivy.scan"
	LabelScanners = "trivy.scanners"
)

// ImageScanItem is a unit of work for a Worker.
type ImageScanItem struct {
	Image    string
	Scanners string
	// Force bypasses the "same digest already scanned" shortcut, used for
	// periodic rescans that should pick up newly published CVEs.
	Force bool
}

// DockerClient is the subset of the Docker API used by this package.
type DockerClient interface {
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error)
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
	ImageInspect(ctx context.Context, imageID string, opts ...client.ImageInspectOption) (image.InspectResponse, error)
}

// Queue is a bounded scan queue that drops duplicate images already waiting.
type Queue struct {
	items chan ImageScanItem
	mu    sync.Mutex
	// pending maps a waiting image to whether a forced scan was requested.
	pending map[string]bool
}

// NewQueue creates a queue holding at most size waiting items.
func NewQueue(size int) *Queue {
	return &Queue{items: make(chan ImageScanItem, size), pending: map[string]bool{}}
}

// Push enqueues item unless the same image is already waiting, in which
// case only the Force flag is merged. It blocks while the queue is full and
// returns false if ctx is canceled.
func (q *Queue) Push(ctx context.Context, item ImageScanItem) bool {
	q.mu.Lock()
	if force, dup := q.pending[item.Image]; dup {
		q.pending[item.Image] = force || item.Force
		q.mu.Unlock()
		log.Debugf("Image %s already queued, skipping", item.Image)
		return true
	}
	q.pending[item.Image] = item.Force
	q.mu.Unlock()
	select {
	case q.items <- item:
		metrics.QueueLength.Set(float64(len(q.items)))
		return true
	case <-ctx.Done():
		q.release(item.Image)
		return false
	}
}

// release removes image from the pending set and returns whether any of
// the merged requests asked for a forced scan.
func (q *Queue) release(image string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	force := q.pending[image]
	delete(q.pending, image)
	return force
}

// Len is the number of waiting items.
func (q *Queue) Len() int { return len(q.items) }

// Scanner runs Trivy scans on queued images.
type Scanner struct {
	Docker    DockerClient
	Queue     *Queue
	AnalysisQ chan<- database.TrivyVulnerability
	ServerURL string
	ExtraArgs string
	Scanners  string
	Timeout   time.Duration
	// TrivyBin is the Trivy executable; defaults to "trivy" from PATH.
	TrivyBin string
}

// ListenDockerEvents enqueues the image of every container that starts.
// It reconnects to the event stream with backoff until ctx is canceled.
func (s *Scanner) ListenDockerEvents(ctx context.Context) {
	backoff := time.Second
	for {
		if err := s.listenOnce(ctx); err != nil && ctx.Err() == nil {
			log.Warnf("Docker event stream error: %v (reconnecting in %s)", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (s *Scanner) listenOnce(ctx context.Context) error {
	f := filters.NewArgs()
	f.Add("type", string(events.ContainerEventType))
	f.Add("event", "start")
	evCh, errCh := s.Docker.Events(ctx, events.ListOptions{Filters: f})
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-evCh:
			if !ok {
				return errors.New("event channel closed")
			}
			info, err := s.Docker.ContainerInspect(ctx, evt.Actor.ID)
			if err != nil {
				log.Debugf("inspect %s: %v", evt.Actor.ID, err)
				continue
			}
			if item, ok := s.itemFor(info.Config.Image, info.Config.Labels, false); ok {
				s.Queue.Push(ctx, item)
			}
		case err, ok := <-errCh:
			if !ok {
				return errors.New("error channel closed")
			}
			return err
		}
	}
}

// itemFor builds a scan item for an image honoring the container labels.
func (s *Scanner) itemFor(image string, labels map[string]string, force bool) (ImageScanItem, bool) {
	if image == "" || strings.EqualFold(strings.TrimSpace(labels[LabelScan]), "false") {
		return ImageScanItem{}, false
	}
	scanners := s.Scanners
	if custom := strings.TrimSpace(labels[LabelScanners]); custom != "" {
		scanners = custom
	}
	return ImageScanItem{Image: image, Scanners: scanners, Force: force}, true
}

// ScanRunningContainers enqueues the images of all running containers.
func (s *Scanner) ScanRunningContainers(ctx context.Context, force bool) {
	list, err := s.Docker.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Warnf("Listing containers failed: %v", err)
		return
	}
	n := 0
	for _, c := range list {
		if item, ok := s.itemFor(c.Image, c.Labels, force); ok {
			if !s.Queue.Push(ctx, item) {
				return
			}
			n++
		}
	}
	log.Infof("Queued %d running container image(s) for scanning (force=%v)", n, force)
}

// PeriodicRescan rescans all running containers every interval; a
// non-positive interval disables it.
func (s *Scanner) PeriodicRescan(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Info("Periodic rescan of running containers")
			s.ScanRunningContainers(ctx, true)
		}
	}
}

// Worker consumes the queue until ctx is canceled.
func (s *Scanner) Worker(ctx context.Context, wid int, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case item := <-s.Queue.items:
			metrics.QueueLength.Set(float64(len(s.Queue.items)))
			item.Force = s.Queue.release(item.Image) || item.Force
			s.process(ctx, wid, item)
		}
	}
}

func (s *Scanner) process(ctx context.Context, wid int, item ImageScanItem) {
	ctx, span := otel.Tracer("trivy-exporter").Start(ctx, "ScanImage")
	defer span.End()
	digest := s.imageDigest(ctx, item.Image)
	if !item.Force && database.AlreadyScanned(ctx, item.Image, digest) {
		log.Debugf("[worker %d] %s already scanned (%s)", wid, item.Image, digest)
		metrics.ScansTotal.WithLabelValues("skipped").Inc()
		return
	}
	log.Infof("[worker %d] Scanning %s (%s)", wid, item.Image, digest)
	database.MarkImageScanInProgress(ctx, item.Image)
	start := time.Now()
	added, err := s.scan(ctx, item)
	metrics.ScanDuration.Observe(time.Since(start).Seconds())
	// The terminal state must be recorded even when ctx was canceled by a
	// shutdown, otherwise the image stays "in progress" across restarts.
	stateCtx := context.WithoutCancel(ctx)
	if err != nil {
		log.Warnf("[worker %d] Scan of %s failed: %v", wid, item.Image, err)
		database.MarkImageScanFailed(stateCtx, item.Image)
		metrics.ScansTotal.WithLabelValues("failed").Inc()
		return
	}
	database.SaveImageChecksum(stateCtx, item.Image, digest)
	metrics.ScansTotal.WithLabelValues("completed").Inc()
	log.Infof("[worker %d] Scan of %s done in %s, %d new vulnerabilities", wid, item.Image, time.Since(start).Round(time.Millisecond), added)
}

func (s *Scanner) imageDigest(ctx context.Context, image string) string {
	insp, err := s.Docker.ImageInspect(ctx, image)
	if err != nil {
		return ""
	}
	return insp.ID
}

// BuildTrivyArgs returns the command line passed to Trivy.
func BuildTrivyArgs(image, server, scanners, extra string) []string {
	args := []string{"image", "--format", "json", "--quiet"}
	if server != "" {
		args = append(args, "--server", server)
	}
	if scanners != "" {
		args = append(args, "--scanners", scanners)
	}
	args = append(args, strings.Fields(extra)...)
	return append(args, image)
}

func (s *Scanner) scan(ctx context.Context, item ImageScanItem) (int, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	bin := s.TrivyBin
	if bin == "" {
		bin = "trivy"
	}
	cmd := exec.CommandContext(scanCtx, bin, BuildTrivyArgs(item.Image, s.ServerURL, item.Scanners, s.ExtraArgs)...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return 0, fmt.Errorf("trivy: %w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return 0, fmt.Errorf("trivy: %w", err)
	}
	report, err := ParseReport(out)
	if err != nil {
		return 0, err
	}
	if report.ArtifactName == "" {
		report.ArtifactName = item.Image
	}
	return database.SaveVulnerabilitiesToDatabase(ctx, report, s.AnalysisQ)
}

// ParseReport decodes Trivy JSON output.
func ParseReport(data []byte) (database.TrivyReport, error) {
	var report database.TrivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return report, fmt.Errorf("decode trivy report: %w", err)
	}
	return report, nil
}

// GetEnv returns the environment variable key or def when unset.
func GetEnv(key, def string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return def
}

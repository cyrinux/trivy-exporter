package scanning

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/cyrinux/trivy-exporter/internal/database"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
)

type ImageScanItem struct {
	Image    string
	Scanners string
}

func ListenDockerEvents(ctx context.Context, cli *client.Client, scanQueue chan<- ImageScanItem, wg *sync.WaitGroup, scanners string) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "ListenDockerEvents")
	defer span.End()
	f := filters.NewArgs()
	f.Add("event", "start")
	evCh, errCh := cli.Events(ctx, events.ListOptions{Filters: f})
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-evCh:
			if evt.Type == events.ContainerEventType {
				info, e2 := cli.ContainerInspect(ctx, evt.Actor.ID)
				if e2 != nil {
					continue
				}
				if skip, ok := info.Config.Labels["trivy.scan"]; ok && skip == "false" {
					continue
				}
				scannersToUse := scanners
				if custom, ok := info.Config.Labels["trivy.scanners"]; ok && strings.TrimSpace(custom) != "" {
					scannersToUse = custom
				}
				wg.Add(1)
				select {
				case scanQueue <- ImageScanItem{Image: info.Config.Image, Scanners: scannersToUse}:
				case <-ctx.Done():
					wg.Done()
					return
				}
			}
		case e := <-errCh:
			if e != nil {
				continue
			}
		}
	}
}

func Worker(ctx context.Context, cli *client.Client, scanQueue <-chan ImageScanItem, wg *sync.WaitGroup, wid int, analysisQ chan<- database.TrivyVulnerability, serverURL, trivyExtraArgs string) {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, fmt.Sprintf("Worker-%d", wid))
	defer span.End()
	for {
		select {
		case <-ctx.Done():
			return
		case item, ok := <-scanQueue:
			if !ok {
				return
			}
			func() {
				defer wg.Done()
				if ctx.Err() != nil {
					return
				}
				digest := getImageDigest(ctx, cli, item.Image)
				if database.AlreadyScanned(ctx, item.Image, digest) {
					return
				}
				database.MarkImageScanInProgress(ctx, item.Image)
				if err := requestTrivyScan(ctx, item.Image, serverURL, item.Scanners, trivyExtraArgs, analysisQ); err != nil {
					log.Warnf("Trivy scan error for %s: %v", item.Image, err)
				} else {
					database.SaveImageChecksum(ctx, item.Image, digest)
				}
			}()
		}
	}
}

func getImageDigest(ctx context.Context, cli *client.Client, image string) string {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "GetImageDigest")
	defer span.End()
	insp, err := cli.ImageInspect(ctx, image)
	if err != nil {
		return ""
	}
	return insp.ID
}

func requestTrivyScan(ctx context.Context, image, server, scanners, extra string, analysisQ chan<- database.TrivyVulnerability) error {
	_, span := otel.Tracer("trivy-exporter").Start(ctx, "RequestTrivyScan")
	defer span.End()
	args := []string{"image", "--server", server, "--scanners", scanners, "--format", "json"}
	if extra != "" {
		args = append(args, strings.Split(extra, " ")...)
	}
	args = append(args, image)
	scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(scanCtx, "trivy", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Trivy scan error for %s: %w", image, err)
	}
	var report database.TrivyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return fmt.Errorf("Error unmarshaling Trivy output for %s: %w", image, err)
	}
	database.SaveVulnerabilitiesToDatabase(ctx, report, analysisQ)
	return nil
}

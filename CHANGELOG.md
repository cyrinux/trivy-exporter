# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-10-09

### Breaking
- The database schema changed and is not migrated: delete the old `vulns.db` (the `trivy-results` volume) before upgrading. Scans and cached analyses are rebuilt automatically.

### Security
- Trivy is now installed from a pinned release (v0.75.0) with SHA-256 verification instead of the floating apt repository, following the 2026 Trivy supply-chain compromises (GHSA-69fq-xp46-6x23 / CVE-2026-33634).
- All GitHub Actions, including `aquasecurity/trivy-action`, are pinned to full commit SHAs.
- Dependencies upgraded (Docker client 28.5, OpenTelemetry 1.47, Prometheus client 1.25, gRPC 1.84); toolchain bumped to Go 1.26.

### Added
- Periodic rescans of running containers (`SCAN_INTERVAL_MINUTES`, default 360, `0` disables) and an initial scan of containers already running at startup.
- Fixed CVEs are pruned from the database and metrics when a rescan no longer reports them.
- Scan metrics: `trivy_exporter_scans_total`, `trivy_exporter_scan_duration_seconds`, `trivy_exporter_scan_queue_length`.
- `LISTEN_ADDR`, `TRIVY_SCANNERS`, `SCAN_TIMEOUT_MINUTES`, `METRICS_REFRESH_SECONDS` settings.
- Multi-arch image (linux/amd64, linux/arm64) and a CI workflow running gofmt, vet, golangci-lint and tests.
- Unit tests for the database, metrics, alerts and scanning packages.

### Changed
- Pure-Go SQLite driver (`modernc.org/sqlite`): static CGO-free binary, WAL journal, single serialised writer.
- Metrics are rebuilt only when the database changed instead of every 5 seconds.
- Vulnerability inserts run in one transaction per report instead of a select-then-insert per CVE.
- Alert batching is event-driven instead of polling every 100 ms.
- Graceful shutdown on SIGINT/SIGTERM: HTTP server drains, workers finish, database closes.
- Docker event listener reconnects with backoff when the stream drops.
- Duplicate images already waiting in the queue are not enqueued twice.
- Alerts are sent even without an OpenAI key.
- Default OpenAI model is `gpt-4o-mini`; tracing/profiling are disabled by default in the Docker image.

### Fixed
- Build failure from an invalid `encoding/jsonV2` import.
- The same CVE found in several images was only stored once (primary key was the CVE id alone).
- A failed scan was recorded as completed, so the image was never retried; scans interrupted by a restart are now marked failed and retried too.
- `wg.Wait()` after `log.Fatal` was unreachable; SIGTERM was not handled.
- Tracer/profiler setup errors no longer abort the process when observability is disabled.

## [1.0.0] - 2025-11-28

### 🎉 Initial Release

#### Added
- **Real-time Docker monitoring**: Listens to Docker events to detect new containers
- **Automatic Trivy scanning**: Automatically scans images of started containers
- **Prometheus metrics**: Exposes detected vulnerabilities via `/metrics`
- **AI CVE analysis**: OpenAI integration to generate mitigation recommendations
- **Alert system**: Batch alert delivery via ntfy.sh with severity-based prioritization
- **SQLite database**: Caches scans and analyses to avoid duplication
- **Multi-worker support**: Parallel scan processing capability
- **Custom Docker labels**: 
  - `trivy.scan=false` to exclude a container
  - `trivy.scanners=vuln,secret` to customize scanners
- **Complete observability**:
  - OpenTelemetry tracing (Tempo)
  - Continuous profiling (Pyroscope)
  - HTTP instrumentation with OTel
- **HTTP endpoints**:
  - `/metrics` - Prometheus metrics
  - `/health` - Health check
  - `/db/status` - Service statistics
- **Flexible configuration**: Environment variables for all settings
- **Docker deployment**:
  - Optimized multi-stage image
  - Built-in health check
  - Cosign signature for published images
- **GitHub Actions CI/CD**:
  - Automatic build and publish to ghcr.io
  - Trivy security scans of images
  - Image signing with Cosign

#### Security
- Recommended use of read-only Docker socket
- No sensitive data in logs
- Support for webhook authentication with ntfy

#### Documentation
- Comprehensive README with examples
- Environment variable documentation
- Architecture diagram
- Docker Compose examples
- Quick start guide

---

## Future Version Format

### [Unreleased]

#### Added
- New features coming soon

#### Changed
- Changes to existing features

#### Deprecated
- Features that will be removed

#### Removed
- Removed features

#### Fixed
- Bug fixes

#### Security
- Security fixes

---

[1.3.0]: https://github.com/cyrinux/trivy-exporter/releases/tag/v1.3.0
[1.0.0]: https://github.com/cyrinux/trivy-exporter/releases/tag/v1.0.0

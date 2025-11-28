# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/cyrinux/trivy-exporter/releases/tag/v1.0.0

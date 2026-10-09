# Trivy Exporter 🔍

<div align="center">

**Intelligent Prometheus exporter for Trivy vulnerabilities with AI analysis**

[![Docker](https://github.com/cyrinux/trivy-exporter/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/cyrinux/trivy-exporter/actions/workflows/docker-publish.yml)
[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## 📖 Description

**Trivy Exporter** is a Go service that automatically monitors your Docker containers, scans their images with [Trivy](https://trivy.dev/), and exposes discovered vulnerabilities as Prometheus metrics. It also integrates automatic CVE analysis via OpenAI and intelligent alert notifications.

### ✨ Key Features

- 🐳 **Real-time Docker monitoring**: Automatically detects new containers
- 🔍 **Automatic Trivy scanning**: Analyzes Docker image vulnerabilities
- 📊 **Prometheus metrics**: Exposes vulnerabilities for monitoring
- 🤖 **AI CVE analysis**: Uses OpenAI to generate mitigation recommendations
- 🔔 **Intelligent alerts**: Batch notifications via ntfy.sh with severity prioritization
- 💾 **SQLite cache**: Avoids redundant scans of the same images, prunes fixed CVEs on rescan
- 🔁 **Periodic rescans**: Running containers are rescanned on a schedule to catch newly published CVEs
- 🔒 **Pinned, checksum-verified Trivy**: The image never installs a floating Trivy version
- 📈 **Complete observability**: OpenTelemetry tracing and Pyroscope profiling
- ⚡ **Multi-workers**: Parallel scan processing

## 🚀 Quick Start

### Prerequisites

- Docker and access to Docker socket (`/var/run/docker.sock`)
- [Trivy CLI](https://trivy.dev/) installed (the provided Docker image ships a pinned, checksum-verified Trivy)
- (Optional) OpenAI API key for CVE analysis
- (Optional) Trivy server in client-server mode

### With Docker

```bash
docker run -d \
  --name trivy-exporter \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v trivy-cache:/root/.cache/trivy \
  -v trivy-results:/results \
  -e OPENAI_API_KEY=sk-your-key-here \
  -e NTFY_WEBHOOK_URL=https://ntfy.sh/your-topic \
  ghcr.io/cyrinux/trivy-exporter:latest
```

### With Docker Compose

```yaml
services:
  trivy-exporter:
    image: ghcr.io/cyrinux/trivy-exporter:latest
    ports:
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - trivy-cache:/root/.cache/trivy
      - trivy-results:/results
    environment:
      - LOG_LEVEL=info
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - NTFY_WEBHOOK_URL=https://ntfy.sh/vulns
      - NUM_WORKERS=2
      - SCAN_INTERVAL_MINUTES=360

volumes:
  trivy-cache:
  trivy-results:
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/cyrinux/trivy-exporter.git
cd trivy-exporter

# Build
go build -o trivy-exporter ./cmd/trivy-exporter

# Run
./trivy-exporter
```

## ⚙️ Configuration

### Environment Variables

| Variable                    | Description                                                              | Default                       | Example                    |
| --------------------------- | ------------------------------------------------------------------------ | ----------------------------- | -------------------------- |
| `LOG_LEVEL`                 | Log level (debug, info, warn, error)                                     | `info`                        | `debug`                    |
| `LISTEN_ADDR`               | HTTP listen address                                                      | `:8080`                       | `127.0.0.1:9100`           |
| `RESULTS_DIR`               | SQLite database storage directory                                        | `/results`                    | `/data/trivy`              |
| `DOCKER_HOST`               | Docker socket to monitor (standard Docker env vars are honoured)        | `unix:///var/run/docker.sock` | `tcp://docker:2375`        |
| `TRIVY_SERVER_URL`          | Trivy server URL (client-server mode); empty uses the local CLI         | _(empty)_                     | `http://trivy:4954`        |
| `TRIVY_SCANNERS`            | Default scanners, overridable per container                              | `vuln`                        | `vuln,secret`              |
| `TRIVY_EXTRA_ARGS`          | Additional arguments for Trivy                                           | `--ignore-unfixed` (image)    | `--severity HIGH,CRITICAL` |
| `NUM_WORKERS`               | Number of parallel scan workers                                          | `1`                           | `4`                        |
| `SCAN_INTERVAL_MINUTES`     | Rescan running containers at this interval; `0` disables                 | `360`                         | `60`                       |
| `SCAN_TIMEOUT_MINUTES`      | Abort a single scan after this long                                      | `10`                          | `30`                       |
| `METRICS_REFRESH_SECONDS`   | How often gauges are rebuilt when the database changed                   | `15`                          | `60`                       |
| `OPENAI_API_KEY`            | OpenAI API key for CVE analysis                                          | _(empty)_                     | `sk-...`                   |
| `OPENAI_MODEL`              | OpenAI model to use                                                      | `gpt-4o-mini`                 | `gpt-4o`                   |
| `NTFY_WEBHOOK_URL`          | ntfy.sh webhook URL for alerts                                           | _(empty)_                     | `https://ntfy.sh/mytopic`  |
| `TEMPO_ENDPOINT`            | Tempo endpoint for OTLP tracing                                          | `localhost:4317`              | `tempo:4317`               |
| `PYROSCOPE_ENDPOINT`        | Pyroscope endpoint for profiling                                         | `http://localhost:4040`       | `http://pyroscope:4040`    |
| `DISABLE_TRACING_PROFILING` | Disable tracing and profiling                                            | `false` (`true` in the image) | `true`                     |

### Custom Docker Labels

You can control scanner behavior via Docker labels on your containers:

```bash
# Exclude a container from scanning
docker run -d --label trivy.scan=false myimage:latest

# Customize scanners used (default: vuln)
docker run -d --label trivy.scanners=vuln,secret myimage:latest
```

## 📊 HTTP Endpoints

| Endpoint         | Description                              |
| ---------------- | ---------------------------------------- |
| `GET /metrics`   | Prometheus metrics                       |
| `GET /health`    | Health check (returns `{"status":"ok"}`) |
| `GET /db/status` | Statistics (CVE count, workers, etc.)    |

### Prometheus Metrics

```promql
# Number of vulnerabilities by image and severity
trivy_vulnerability{image="myapp:v1", severity="HIGH", id="CVE-2024-1234"}

# Timestamp of first detection per vulnerability
trivy_vulnerability_timestamp{image="myapp:v1", vulnerability_id="CVE-2024-1234"}

# Exporter health
trivy_exporter_scans_total{result="completed|failed|skipped"}
trivy_exporter_scan_duration_seconds_bucket
trivy_exporter_scan_queue_length
```

### Example Prometheus Queries

```promql
# Count critical vulnerabilities by image
sum by (image) (trivy_vulnerability{severity="CRITICAL"})

# Vulnerabilities first seen in the last hour
(time() - trivy_vulnerability_timestamp) < 3600

# Scan failures
increase(trivy_exporter_scans_total{result="failed"}[1h]) > 0
```

## 🤖 AI CVE Analysis

When an OpenAI API key is configured, each new vulnerability is automatically analyzed to generate:

- 🔧 **Specific mitigation recommendations**
- 📚 **Official references** to patches
- ⚡ **Priority remediation actions**

Analyses are cached in the SQLite database to avoid redundant API calls.

## 🔔 Alert System

Alerts are sent in batches (max 5 alerts every 10 seconds) to ntfy.sh with:

- **Automatic prioritization** by severity (low → urgent)
- **Intelligent grouping** of similar vulnerabilities
- **Custom tags** for filtering (`security`, `critical`, etc.)
- **AI analysis included** in message body

### Example ntfy Configuration

```bash
# Alerts on a private topic
NTFY_WEBHOOK_URL=https://ntfy.sh/myproject-vulns

# With authentication
NTFY_WEBHOOK_URL=https://user:pass@ntfy.example.com/vulns
```

## 🗄️ Database

The service uses SQLite to store:

1. **Detected vulnerabilities** (`vulnerabilities`)
   - CVE ID, affected package, severity, description
   - Image and discovery timestamp

2. **Scan state** (`image_scans`)
   - Scanned image digests and status (`in_progress`, `completed`, `failed`)
   - Unchanged digests are skipped; failed scans are retried; a rescan removes CVEs that are no longer reported

3. **CVE analyses** (`cve_analysis`)
   - OpenAI analysis results
   - Recommendation cache

The database is stored in `$RESULTS_DIR/vulns.db`. It is a cache: deleting it is safe and is required when upgrading from a version before 1.3.0.

## 📈 Observability

### OpenTelemetry Tracing

The service automatically instruments:

- Trivy scan operations
- HTTP requests
- Docker interactions
- OpenAI analyses

Visualize traces with Grafana Tempo or any OTLP-compatible backend.

### Continuous Profiling (Pyroscope)

Real-time CPU/memory profiling for performance diagnostics.

```yaml
# Example Grafana integration
services:
  trivy-exporter:
    environment:
      - TEMPO_ENDPOINT=tempo:4317
      - PYROSCOPE_ENDPOINT=http://pyroscope:4040
```

## 🏗️ Architecture

```
┌─────────────────┐
│  Docker Engine  │
└────────┬────────┘
         │ Events API
         ▼
┌─────────────────────────┐
│   Trivy Exporter        │
│  ┌──────────────────┐   │
│  │ Event Listener   │   │
│  └─────┬────────────┘   │
│        │                │
│        ▼                │
│  ┌──────────────────┐   │
│  │  Scan Workers    │───┼──→ Trivy CLI/Server
│  │  (Pool)          │   │
│  └─────┬────────────┘   │
│        │                │
│        ▼                │
│  ┌──────────────────┐   │
│  │  SQLite Cache    │   │
│  └─────┬────────────┘   │
│        │                │
│        ▼                │
│  ┌──────────────────┐   │
│  │ OpenAI Analyzer  │───┼──→ OpenAI API
│  └─────┬────────────┘   │
│        │                │
│        ▼                │
│  ┌──────────────────┐   │
│  │ Alert Manager    │───┼──→ ntfy.sh
│  └──────────────────┘   │
│                         │
│  ┌──────────────────┐   │
│  │ Metrics Exporter │───┼──→ Prometheus
│  └──────────────────┘   │
└─────────────────────────┘
```

## 🛡️ Security

- ✅ **Pinned Trivy binary**: the Docker image downloads a fixed Trivy release and verifies its SHA-256 before installing it. Trivy's release channels and GitHub Actions were compromised twice in 2026 ([GHSA-69fq-xp46-6x23](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)); never install a floating version. Bump `TRIVY_VERSION` and the checksums together in the `Dockerfile`.
- ✅ **GitHub Actions pinned to commit SHAs**, including `trivy-action`
- ✅ **Static, CGO-free binary** built with a pure-Go SQLite driver
- ✅ **Read-only Docker socket** recommended
- ✅ **Cosign signatures** for published Docker images
- ✅ **Trivy security scans** in CI/CD
- ✅ **No sensitive data** in logs by default

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. 🍴 Fork the project
2. 🌿 Create a branch (`git checkout -b feature/amazing-feature`)
3. 💾 Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. 📤 Push to the branch (`git push origin feature/amazing-feature`)
5. 🔃 Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Aqua Security](https://www.aquasec.com/) for [Trivy](https://trivy.dev/)
- [OpenAI](https://openai.com/) for the analysis API
- [Binwiederhier](https://ntfy.sh/) for ntfy.sh
- The [Prometheus](https://prometheus.io/) community

## 📬 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/cyrinux/trivy-exporter/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/cyrinux/trivy-exporter/discussions)

---

<div align="center">

Made with ❤️ by the community | [Documentation](https://github.com/cyrinux/trivy-exporter) | [Changelog](CHANGELOG.md)

</div>

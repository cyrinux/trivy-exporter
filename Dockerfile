# syntax=docker/dockerfile:1.7

# ---------- Stage 1: build a static Go binary ----------
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/

# The SQLite driver is pure Go, so the binary is fully static and
# cross-compiles without a C toolchain.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/trivy-exporter ./cmd/trivy-exporter

# ---------- Stage 2: fetch a pinned, checksum-verified Trivy ----------
# Trivy's distribution channels were compromised twice in 2026
# (GHSA-69fq-xp46-6x23 / CVE-2026-33634), so never install a floating
# version. Bump TRIVY_VERSION and the checksums together, taking them from
# https://github.com/aquasecurity/trivy/releases/download/v<ver>/trivy_<ver>_checksums.txt
FROM debian:bookworm-slim AS trivy

ARG TARGETARCH
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) asset="Linux-64bit"; sum="${TRIVY_SHA256_AMD64}" ;; \
      arm64) asset="Linux-ARM64"; sum="${TRIVY_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    tarball="trivy_${TRIVY_VERSION}_${asset}.tar.gz"; \
    curl -fsSL --retry 3 -o "/tmp/${tarball}" \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${tarball}"; \
    echo "${sum}  /tmp/${tarball}" | sha256sum -c -; \
    tar -xzf "/tmp/${tarball}" -C /usr/local/bin trivy; \
    rm -f "/tmp/${tarball}"; \
    /usr/local/bin/trivy --version

# ---------- Stage 3: minimal runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /results /root/.cache/trivy

COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=builder /out/trivy-exporter /usr/local/bin/trivy-exporter

ENV LOG_LEVEL=info \
    LISTEN_ADDR=:8080 \
    RESULTS_DIR=/results \
    TRIVY_CACHE_DIR=/root/.cache/trivy \
    TRIVY_SERVER_URL= \
    TRIVY_EXTRA_ARGS=--ignore-unfixed \
    TRIVY_SCANNERS=vuln \
    NTFY_WEBHOOK_URL= \
    SCAN_INTERVAL_MINUTES=360 \
    SCAN_TIMEOUT_MINUTES=10 \
    METRICS_REFRESH_SECONDS=15 \
    NUM_WORKERS=1 \
    TEMPO_ENDPOINT=localhost:4317 \
    PYROSCOPE_ENDPOINT=http://localhost:4040 \
    DISABLE_TRACING_PROFILING=true \
    OPENAI_API_KEY= \
    OPENAI_MODEL=gpt-4o-mini

VOLUME ["/results", "/root/.cache/trivy"]

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl --fail http://localhost:8080/health || exit 1

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/trivy-exporter"]

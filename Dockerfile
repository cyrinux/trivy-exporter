# Stage 1: Build the Go application
FROM golang:1.24 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .
COPY ./cmd/ .
COPY ./internal/ .
RUN ls --recursive .


# Build the Go app
# RUN go build -ldflags="-s -w" -o trivy-exporter .
RUN go build -ldflags="-w" -o trivy-exporter ./cmd/trivy-exporter

# Stage 2: Run the application
FROM debian:bookworm-slim

# Install Trivy CLI
RUN apt-get update && apt-get install -y wget apt-transport-https gnupg lsb-release curl sqlite3
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add - && \
    echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list && \
    apt-get update && apt-get install -y trivy

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/trivy-exporter .

# Set environment variables
ENV LOG_LEVEL=info
ENV RESULTS_DIR=/results
ENV DOCKER_HOST=unix:///var/run/docker.sock
ENV TRIVY_SERVER_URL=http://localhost:4954
ENV NTFY_WEBHOOK_URL=
ENV TRIVY_EXTRA_ARGS=--ignore-unfixed
ENV SCAN_INTERVAL_MINUTES=15
ENV NUM_WORKERS=1
ENV TEMPO_ENDPOINT=localhost:4317
ENV PYROSCOPE_ENDPOINT=http://localhost:4040
ENV DISABLE_TRACING_PROFILING=false
ENV OPENAI_API_KEY=
ENV OPENAI_MODEL=gpt-4-turbo


# Health check configuration
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl --fail http://localhost:8080/health || exit 1

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./trivy-exporter"]

# Security Policy

## Supported Versions

We actively support the following versions with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Trivy Exporter seriously. If you have discovered a security vulnerability, please report it responsibly.

### How to Report

**Please DO NOT open a public issue for security vulnerabilities.**

Instead, please report security vulnerabilities by:

1. **Email**: Send details to the maintainer (check repository owner's profile for contact)
2. **GitHub Security Advisories**: Use the [Security Advisory](https://github.com/cyrinux/trivy-exporter/security/advisories) feature

### What to Include

Please include the following information in your report:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Fix Timeline**: Varies based on severity and complexity

### Severity Classification

We use the following severity levels:

- **Critical**: Remote code execution, privilege escalation
- **High**: Data exposure, authentication bypass
- **Medium**: Information disclosure, denial of service
- **Low**: Minor security issues

## Security Best Practices

When deploying Trivy Exporter:

### 1. Docker Socket Access

- ✅ **DO**: Mount Docker socket as read-only
  ```yaml
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
  ```

- ❌ **DON'T**: Give write access to Docker socket unless absolutely necessary

### 2. Environment Variables

- ✅ **DO**: Use Docker secrets or environment files for sensitive data
  ```bash
  docker run -e OPENAI_API_KEY_FILE=/run/secrets/openai_key ...
  ```

- ❌ **DON'T**: Hardcode secrets in docker-compose.yml or Dockerfiles

### 3. Network Exposure

- ✅ **DO**: Use reverse proxy with authentication for public exposure
- ✅ **DO**: Restrict access to metrics endpoint in production
  ```yaml
  # Example with Traefik
  labels:
    - "traefik.http.routers.trivy.middlewares=auth"
  ```

- ❌ **DON'T**: Expose port 8080 directly to the internet without protection

### 4. Image Verification

- ✅ **DO**: Verify image signatures with Cosign
  ```bash
  cosign verify ghcr.io/cyrinux/trivy-exporter:latest
  ```

- ✅ **DO**: Use specific version tags instead of `latest`
  ```yaml
  image: ghcr.io/cyrinux/trivy-exporter:v1.0.0
  ```

### 5. Resource Limits

- ✅ **DO**: Set resource limits to prevent DoS
  ```yaml
  deploy:
    resources:
      limits:
        cpus: '2'
        memory: 1G
  ```

### 6. Logging

- ✅ **DO**: Monitor logs for suspicious activity
- ✅ **DO**: Use log aggregation with alerting
- ❌ **DON'T**: Log sensitive information (API keys, tokens, etc.)

### 7. Updates

- ✅ **DO**: Keep Trivy Exporter and Trivy CLI up to date
- ✅ **DO**: Monitor security advisories
- ✅ **DO**: Subscribe to release notifications

### 8. Database Security

- ✅ **DO**: Store SQLite database on encrypted volumes in production
- ✅ **DO**: Backup database regularly
- ❌ **DON'T**: Expose the database file publicly

### 9. API Keys

- ✅ **DO**: Use API keys with minimal required permissions
- ✅ **DO**: Rotate API keys regularly
- ✅ **DO**: Use separate API keys per environment
- ❌ **DON'T**: Commit API keys to version control

### 10. Webhook URLs

- ✅ **DO**: Use authenticated webhook endpoints
- ✅ **DO**: Use HTTPS for webhook URLs
- ❌ **DON'T**: Use public topic names with sensitive information

## Security Features

Trivy Exporter includes the following security features:

1. **No credential storage**: API keys are used from environment only
2. **Read-only operations**: Default Docker socket access is read-only
3. **SQLite isolation**: Database stored in isolated volume
4. **HTTPS support**: Can be deployed behind HTTPS reverse proxy
5. **Signed images**: Docker images are signed with Cosign
6. **Vulnerability scanning**: Images are scanned with Trivy in CI/CD
7. **Minimal base image**: Uses Debian slim for smaller attack surface
8. **No privileged mode**: Runs as non-root user in container

## Compliance

Trivy Exporter helps with compliance by:

- Detecting vulnerable dependencies (OWASP Top 10)
- Providing audit trail of scanned images
- Generating compliance reports via Prometheus metrics
- Supporting security scanning automation

## Security Audits

We welcome security audits of this project. If you're conducting a security audit:

1. Please notify us before starting
2. Provide a detailed report of findings
3. Allow reasonable time for fixes before public disclosure

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers who help improve the security of this project (with their permission).

---

**Last Updated**: November 28, 2025

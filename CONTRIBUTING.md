# Contributing Guide 🤝

Thank you for your interest in contributing to Trivy Exporter! This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Contribute](#how-to-contribute)
- [Development Process](#development-process)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Bug Reporting](#bug-reporting)
- [Feature Suggestions](#feature-suggestions)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be courteous and professional in all your interactions.

## How to Contribute

There are several ways to contribute:

1. 🐛 **Report bugs**
2. 💡 **Suggest new features**
3. 📝 **Improve documentation**
4. 🔧 **Submit fixes or new features**
5. ⭐ **Share the project**

## Development Process

### Prerequisites

- Go 1.23.6 or higher
- Docker and Docker Compose
- Git
- Make (optional but recommended)

### Setting Up Development Environment

```bash
# 1. Fork the project on GitHub

# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/trivy-exporter.git
cd trivy-exporter

# 3. Add upstream repository
git remote add upstream https://github.com/cyrinux/trivy-exporter.git

# 4. Install dependencies
go mod download

# 5. Create a branch for your work
git checkout -b feature/my-new-feature
```

### Local Build and Test

```bash
# Build the project
go build -o trivy-exporter ./cmd/trivy-exporter

# Run tests
go test -v ./...

# Run with race detector
go test -race ./...

# Check formatting
go fmt ./...

# Linter (if golangci-lint is installed)
golangci-lint run

# Build Docker image
docker build -t trivy-exporter:dev .
```

## Code Standards

### Go Style

- Follow [official Go conventions](https://golang.org/doc/effective_go.html)
- Use `gofmt` to format your code
- Use descriptive names for variables and functions
- Comment exported (public) functions
- Keep functions short and focused

### Commit Structure

Use clear and descriptive commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) convention:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Commit types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes only
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding or fixing tests
- `chore`: Maintenance, dependencies, etc.

Examples:
```
feat(scanning): add support for custom Trivy scanners

fix(alerts): correct severity mapping for ntfy priority

docs(readme): update configuration examples

refactor(database): optimize vulnerability queries
```

### Code Review Checklist

Before submitting your PR, verify:

- [ ] Code compiles without errors
- [ ] Tests pass (`go test ./...`)
- [ ] Code is formatted (`go fmt ./...`)
- [ ] New features have tests
- [ ] Documentation is updated if necessary
- [ ] Commit messages follow the convention
- [ ] No secrets or credentials in the code
- [ ] Logs are appropriate (no sensitive data)

## Pull Request Process

1. **Sync with upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push your branch**
   ```bash
   git push origin feature/my-new-feature
   ```

3. **Create a Pull Request on GitHub**
   - Use a descriptive title
   - Fill out the PR template
   - Reference related issues (if applicable)
   - Add screenshots if relevant

4. **Review and modifications**
   - Respond to review comments
   - Make requested changes
   - Push changes (they'll be added to the PR)

5. **Merge**
   - Once approved, your PR will be merged
   - You can delete your branch

### Pull Request Template

```markdown
## Description
[Description of your changes]

## Type of Change
- [ ] Bug fix (non-breaking change)
- [ ] New feature (non-breaking change)
- [ ] Breaking change
- [ ] Documentation

## Tests Performed
[Describe the tests you performed]

## Checklist
- [ ] My code follows the project standards
- [ ] I've commented complex parts
- [ ] I've updated the documentation
- [ ] My changes don't generate warnings
- [ ] I've added tests
- [ ] All tests pass
```

## Bug Reporting

### Before Reporting a Bug

1. Verify you're using the latest version
2. Search existing issues
3. Test with default configuration

### Bug Issue Template

```markdown
**Bug Description**
[Clear and concise description]

**How to Reproduce**
1. Go to '...'
2. Click on '....'
3. Scroll to '....'
4. Observe error

**Expected Behavior**
[What should happen]

**Screenshots**
[If applicable]

**Environment**
- OS: [e.g. Ubuntu 22.04]
- Docker Version: [e.g. 24.0.5]
- Trivy Exporter Version: [e.g. 1.0.0]
- Trivy Version: [e.g. 0.48.0]

**Logs**
```
[Paste relevant logs here]
```

**Configuration**
```yaml
[Your docker-compose.yml or docker run command]
```

**Additional Context**
[Any other relevant information]
```

## Feature Suggestions

We welcome improvement suggestions!

### Feature Request Template

```markdown
**The Problem**
[Describe the problem you're experiencing]

**Proposed Solution**
[Describe the solution you'd like to see]

**Alternatives Considered**
[Describe alternatives you've considered]

**Additional Context**
[Any other relevant information]

**Are you willing to contribute this feature?**
- [ ] Yes
- [ ] No
- [ ] With help
```

## Areas Where We Need Help

Here are some areas where contributions are particularly welcome:

- 📝 **Documentation**: Improving README, adding examples
- 🧪 **Tests**: Adding unit and integration tests
- 🌐 **Integrations**: Support for new alert systems, metrics backends
- 🔧 **Features**: New features in the roadmap
- 🐛 **Bugs**: Fixing existing bugs
- 🎨 **UX/UI**: Improving Grafana dashboards

## Questions?

Feel free to:
- Open a [GitHub Discussion](https://github.com/cyrinux/trivy-exporter/discussions)
- Ask questions in issues

## Acknowledgments

Thank you to all contributors who help improve this project! 🙏

---

*This contributing guide may evolve. Feel free to suggest improvements!*

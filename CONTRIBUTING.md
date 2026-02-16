# Contributing to Auth Operator

Thank you for your interest in contributing to the Auth Operator! This document provides guidelines and contribution requirements.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Contribution Requirements

### 1. Coding Standards

- **Go**: Use standard Go formatting (gofmt/goimports) and follow Go idioms
- Use standard library constants (e.g., `http.MethodGet` instead of string literals)
- See [.golangci.yml](.golangci.yml) for Go linting rules

### 2. Testing Policy (Required)

All new features and significant changes **must include automated tests**:

- Add `*_test.go` files colocated with source code
- Cover success cases, error cases, and edge cases
- Aim for >70% code coverage for new code
- Run `make test` before opening PRs

If testing is impractical, document why in the PR description.

### 3. Documentation Updates (Required)

Documentation must be updated for every user-facing change:

- **API changes**: Update docs in `docs/api-reference/`
- **CRD changes**: Run `make docs` to regenerate API reference
- **Configuration**: Update relevant documentation
- **Helm charts**: Update chart README and inline values comments

### 4. Quality Standards

- Maintain or improve test coverage (monitored via CI)
- Run linters locally: `make lint`
- Fix all linter errors before submitting

### 5. Security and Privacy

- Never commit secrets, credentials, or PII
- Report security issues privately per [SECURITY.md](.github/SECURITY.md)
- Consider security implications in PR descriptions

## Workflow

### 1. Find or Create an Issue

- Check existing issues to avoid duplicates
- For features, describe the use case, alternatives, and security impact
- Link your PR to the issue when ready

### 2. Develop Your Changes

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes following the architecture in README.md
# For CRD changes, regenerate code:
make generate manifests
```

### 3. Test Locally

```bash
# Run tests and linting
make test
make lint

# Run E2E tests (requires kind cluster)
make test-e2e
```

### 4. Update Documentation

- Update relevant docs in `docs/`
- Run `make docs` if CRD changes were made
- Update Helm chart docs if applicable

### 5. Open a Pull Request

- Provide a clear description and link related issues
- Note test coverage and any limitations
- Describe security implications if relevant

## Code Review Requirements

All changes require pull request review before merge:

- ✅ At least one approving review
- ✅ All CI checks passing (tests, linting, security scans)
- ✅ Up-to-date with base branch
- ✅ No direct pushes to main branch
- ✅ Stale approvals dismissed on new commits

Any exceptions must be documented in the PR with justification.

## Development Setup

### Prerequisites

- Go 1.25 or later
- Docker (for building images)
- kubectl (for interacting with Kubernetes clusters)
- kind (for local development with Kubernetes)
- Helm 3.17+ (for Helm chart development)
- make (for build automation)

### Install Dependencies

```bash
# Download Go dependencies
go mod download

# Install development tools
make controller-gen
make golangci-lint
```

### Running Locally

```bash
# Run tests
make test

# Build the binary
make build

# Run the controller locally (requires kubeconfig)
make run-ctrl

# Run the webhook locally
make run-wh
```

### Using Kind for Development

```bash
# Build and deploy to kind cluster
make deploy OVERLAY=dev

# Run e2e tests
make test-e2e
```

## Commit Messages

Follow conventional commit format:

```
type(scope): short description

Longer description if needed.

Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`

## AI-Assisted Development

This project provides AI coding guidance via [`.github/copilot-instructions.md`](.github/copilot-instructions.md). These instructions are loaded automatically by GitHub Copilot and compatible AI assistants.

Key conventions documented there include:

- **Import alias patterns** (e.g., `authorizationv1alpha1` for API types)
- **Error wrapping** with `fmt.Errorf("context: %w", err)`
- **Testing patterns**: envtest, Ginkgo/Gomega, table-driven tests
- **REUSE compliance**: SPDX headers required in all new files
- **Helm chart conventions**: naming, CRD sync, RBAC generation

When using AI tools, ensure generated code follows these conventions. Review the instructions file before your first contribution.

## Questions or Help

Open an issue or discussion with context. See [SECURITY.md](.github/SECURITY.md) for reporting security vulnerabilities.

Thank you for contributing! 🎉

# Auth Operator — Agent Instructions

This document provides conventions for AI coding agents working on this repository.
For full project context, see [`.github/copilot-instructions.md`](.github/copilot-instructions.md).

## Quick Start

```bash
make manifests generate  # After editing *_types.go or kubebuilder markers
make fmt vet lint        # Format, vet, lint
make test                # Unit + integration tests (envtest)
make helm                # Sync CRDs to Helm chart
```

## Directory Layout

```
api/authorization/v1alpha1/    CRD types & webhooks (kubebuilder v4 multi-group)
internal/controller/           Reconcilers (RoleDefinition, BindDefinition)
internal/webhook/              Admission webhook handlers, cert rotation
pkg/                           Shared libraries (conditions, SSA, metrics, discovery)
config/                        Kustomize overlays (CRDs, RBAC, webhook are auto-generated)
chart/auth-operator/           Helm chart
test/e2e/                      Ginkgo E2E tests
```

## Critical Rules

1. **Never edit auto-generated files** — `config/crd/bases/`, `config/rbac/role.yaml`, `zz_generated.deepcopy.go`, `chart/auth-operator/crds/`.
2. **Never remove** `// +kubebuilder:scaffold:*` comments.
3. **After editing `*_types.go`**: Run `make manifests generate docs helm`.
4. **Import alias convention**: Use descriptive package aliases:
   - `authorizationv1alpha1` for `api/authorization/v1alpha1`
   - `ctrl` for `sigs.k8s.io/controller-runtime`
   - `rbacv1` for `k8s.io/api/rbac/v1`
5. **Error wrapping**: Always use `fmt.Errorf("context: %w", err)` — never `fmt.Errorf("context: %v", err)`.
6. **Standard library constants**: Use `http.MethodGet` not `"GET"`, `rbacv1.GroupName` not `"rbac.authorization.k8s.io"`.
7. **REUSE compliance**: All new files must have SPDX headers or be covered by a glob in `REUSE.toml`.
8. **Test patterns**: Use Ginkgo/Gomega for controller tests, standard `testing` for unit tests. Target >70% coverage.
9. **Condition management**: Use `pkg/conditions.SetCondition()` — never set conditions manually on status.
10. **Server-Side Apply**: Use `pkg/ssa` helpers for RBAC resources — never use `Update()` for managed objects.

## Testing

```bash
make test                    # Unit + envtest integration
make test-e2e-full           # Full E2E (requires kind + Docker)
make test-e2e-helm-full      # Helm installation E2E
```

E2E test labels: `helm`, `complex`, `ha`, `leader-election`, `integration`, `golden`, `dev`

## CI Checks

All PRs must pass: golangci-lint, go vet, go mod tidy check, unit tests (envtest), Docker build, Helm lint, govulncheck, Trivy scan, REUSE compliance.

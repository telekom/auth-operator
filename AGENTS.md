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

## Reusable Prompts (16 total)

Prompts are in [`.github/prompts/`](.github/prompts/) and can be invoked by name:

| Prompt | Category | Purpose |
|--------|----------|---------|
| **Task Prompts** | | |
| `review-pr` | General | PR checklist (code quality, testing, security, docs) |
| `add-crd-field` | Task | Step-by-step guide for adding a new CRD field |
| `helm-chart-changes` | Task | Helm chart modification checklist |
| `github-pr-management` | Workflow | GitHub PR workflows: review threads, rebasing, squashing, CI checks |
| **Code Quality Reviewers** | | |
| `review-go-style` | Lint | golangci-lint v2 compliance: `importas`, `errorlint`, `godot`, `revive`, `goconst`, strict lint |
| `review-concurrency` | Safety | SSA ownership, condition management, cache staleness, webhook timeout, retry-on-conflict |
| `review-k8s-patterns` | Ops | Error handling, idempotency, conditions via `pkg/conditions`, structured logging |
| `review-performance` | Perf | Reconciler efficiency, namespace enumeration, SSA no-op detection, metrics cardinality |
| `review-integration-wiring` | Wiring | Dead code, unwired fields, SSA apply completeness, RBAC marker→Helm propagation |
| **API & Security Reviewers** | | |
| `review-api-crd` | API | CRD schema, backwards compat, webhook validation, SSA apply configuration completeness |
| `review-security` | Security | RBAC least privilege, privilege escalation prevention, SSA field ownership, DoS protection |
| **Documentation & Testing Reviewers** | | |
| `review-docs-consistency` | Docs | Documentation ↔ code alignment: field names, conditions, Helm values, API reference |
| `review-ci-testing` | Testing | Test coverage, Ginkgo/Gomega patterns, assertion quality, CI workflow alignment |
| `review-edge-cases` | Testing | Zero/nil/empty values, namespace lifecycle, SSA conflicts, webhook timing, fuzz properties |
| `review-qa-regression` | QA | RBAC generation regression, condition regression, SSA ownership changes, rollback safety |
| **User Experience Reviewers** | | |
| `review-end-user` | UX | End-user experience: platform engineer, cluster admin, security auditor |

### Running a Multi-Persona Review

Invoke each review prompt in sequence against a code change and collect findings.
The 13 reviewer personas cover every issue class found by automated reviewers
(Copilot, etc.) and more:

**Code quality** (4 personas):
- **Go style** catches import alias violations, `%v` error wrapping, `godot` comment periods, `revive` naming
- **Concurrency** catches SSA ownership conflicts, condition management bypasses, stale cache reads
- **K8s patterns** catches missing context timeouts, non-idempotent reconcilers, condition mis-management
- **Performance** catches unbounded namespace enumeration, SSA no-op waste, high-cardinality metrics

**Correctness** (4 personas):
- **Integration wiring** catches new code that is defined but never called, SSA apply gaps, RBAC drift
- **API & CRD** catches missing validation markers, backwards-compatibility breaks, SSA completeness
- **Edge cases** catches namespace lifecycle races, SSA conflicts, zero-value bugs, webhook timing
- **QA regression** catches RBAC generation regressions, condition reason changes, rollback hazards

**Security & documentation** (3 personas):
- **Security** catches privilege escalation via RBAC generation, webhook bypass, DoS vectors
- **Docs consistency** catches field name mismatches, stale condition references, Helm doc drift
- **CI & testing** catches coverage gaps, Ginkgo/testify mixing, missing enum cases, golden staleness

**User-facing** (2 personas):
- **End-user** catches platform engineer confusion, admin upgrade friction, auditor visibility gaps
- **Helm chart changes** catches values drift, CRD sync issues, RBAC template mismatches

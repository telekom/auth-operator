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
11. **Context-aware logging only**: In production controller/webhook code, derive loggers from context via `log.FromContext(ctx)` (or pass `ctx` and derive inside helpers). Do not pass raw logger instances across helper boundaries.
12. **Tracing attributes**: For reconciler spans, include controller/resource/namespace attributes. For impersonated apply flows, add user attribute to the active span.
13. **Sample set semantics**:
   - `config/samples/`: structurally valid baseline samples for normal reconciliation paths.
   - `config/samples/broken/`: structurally valid runtime-failure samples that MUST apply and then stall/partially reconcile.
   - Webhook/schema-invalid examples stay outside the broken kustomization apply set.
14. **SSA no-op regression safety**: When changing binding reconciliation, test both RoleBinding and ClusterRoleBinding against a real API server for unchanged skips, drift correction, foreign field ownership, removed-field pruning, and deterministic order-insensitive subject handling. Assert actual apply requests, not only resource versions (a no-op apply can still invoke admission). Verify that generated ServiceAccounts, Roles, and ClusterRoles keep their existing reconciliation behavior and that intentionally unconditional restricted-resource applies remain unconditional.
15. **YAGNI and standard tools**: Implement only behavior demonstrated by a regression test; avoid speculative abstractions or broad rewrites. Use Go standard-library helpers and existing Kubernetes/client-go APIs for normalization and managed-field inspection. Run existing `make fmt vet lint`, `make test`, and the relevant isolated kind E2E suite; do not add custom linters or duplicate shared helpers.
16. **Reuse upstream libraries before writing helpers**: Follow the decision order and candidates below. Custom code is the last resort; repeated cross-repository glue belongs in `telekom/t-caas-go-library`, not duplicated here.

## Reuse upstream libraries before writing helpers

Before adding a helper or dependency, check in this order: **Go standard
library → Kubernetes, controller-runtime, client-go, and apimachinery → Flux
`fluxcd/pkg` → other well-known maintained libraries →
`telekom/t-caas-go-library` → custom code**. Prefer direct upstream APIs when
they fit. This table is a shortlist for this operator, not a dependency
mandate; check Go/Kubernetes compatibility and preserve this project's
behavior when migrating.

| Concern | Prefer |
|---|---|
| Conditions | `github.com/fluxcd/pkg/runtime/conditions`, `github.com/fluxcd/pkg/apis/meta`; `k8s.io/apimachinery/pkg/api/meta` for condition slices |
| Readiness of arbitrary resources | `sigs.k8s.io/cli-utils/pkg/kstatus/status` |
| Object status/condition patching | `github.com/fluxcd/pkg/runtime/patch` |
| Conflict retries and optimistic locking | `k8s.io/client-go/util/retry`, `sigs.k8s.io/controller-runtime/pkg/client` (`MergeFromWithOptimisticLock`) |
| Server-Side Apply / drift | `github.com/fluxcd/pkg/ssa`, `github.com/fluxcd/pkg/ssa/normalize`; typed apply: `sigs.k8s.io/controller-runtime/pkg/client`, `k8s.io/client-go/applyconfigurations` |
| Envtest and CRD readiness | `sigs.k8s.io/controller-runtime/pkg/envtest` |
| Envtest assertions | `sigs.k8s.io/controller-runtime/pkg/envtest/komega`, `github.com/onsi/gomega` |
| E2E waits and manifest decoding | `sigs.k8s.io/e2e-framework/klient/wait`, `sigs.k8s.io/e2e-framework/klient/decoder` |
| Predicates, mapping, indexes | `sigs.k8s.io/controller-runtime/pkg/predicate`, `sigs.k8s.io/controller-runtime/pkg/handler`, `sigs.k8s.io/controller-runtime/pkg/client` (`FieldIndexer`) |
| Owners and finalizers | `sigs.k8s.io/controller-runtime/pkg/controller/controllerutil`, `k8s.io/apimachinery/pkg/apis/meta/v1` |
| Leader election and workqueues | `k8s.io/client-go/tools/leaderelection`, `k8s.io/client-go/tools/leaderelection/resourcelock`, `k8s.io/client-go/util/workqueue` |
| Manager probes, cache sync, shutdown | `sigs.k8s.io/controller-runtime/pkg/manager`, `sigs.k8s.io/controller-runtime/pkg/healthz`, `k8s.io/client-go/tools/cache` |
| Tracing | `go.opentelemetry.io/otel/sdk/trace`, `go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc` |
| Metrics and events | `github.com/prometheus/client_golang/prometheus`, `github.com/fluxcd/pkg/runtime/metrics`, `github.com/fluxcd/pkg/runtime/events` |
| Webhook certificates | `github.com/open-policy-agent/cert-controller/pkg/rotator`, `sigs.k8s.io/controller-runtime/pkg/certwatcher` |
| Discovery and namespace resolution | `k8s.io/client-go/discovery`, `sigs.k8s.io/controller-runtime/pkg/cache`; library candidates `pkg/discovery/tracker`, `pkg/namespaceselector` |
| Remote client lifecycle and repeated patch glue | `sigs.k8s.io/controller-runtime/pkg/cluster`; library candidates `pkg/remoteclient`, `pkg/patch` |

See [`telekom/t-caas-go-library`'s upstream-library
guide](https://github.com/telekom/t-caas-go-library/blob/main/docs/upstream-libraries.md)
for package details and migration caveats. The library repository is currently
private and is planned to become public; this guidance summarizes relevant
choices locally so it remains useful before that happens. Its merged packages
potentially relevant here include `pkg/patch`, `pkg/remoteclient`,
`pkg/namespaceselector`, and `pkg/discovery/tracker`. The generic SSA helpers
are under discussion in [library PR #5](https://github.com/telekom/t-caas-go-library/pull/5),
which is still open; do not treat that package as merged or available yet.

Auth Operator's open [PR #580](https://github.com/telekom/auth-operator/pull/580)
proposes generic skip-if-unchanged SSA helpers in `pkg/ssa`; this code is not
yet part of `main`. Compare its proposed typed/cache-based skip behavior with
Flux `pkg/ssa`'s server-evaluated drift detection before choosing. Do not grow
another general-purpose SSA framework while PR #580 and library PR #5 remain
under review.

Existing migration candidates (documentation only; do not change them as part of
this rule): `pkg/conditions/` can use Flux conditions, apimachinery condition
helpers, and kstatus while retaining coordinated Ready-condition policy;
`pkg/ssa/patchhelper.go` can be compared with Flux SSA; generic helpers
proposed by PR #580 and library PR #5 are not merged; controller/webhook
envtest suites should keep using native envtest with pinned absolute assets;
and `test/utils/utils.go` wait, decoder, and apply helpers can use e2e-framework
and Kubernetes APIs while retaining intentional `ForceOwnership`. The tracing
package already uses OpenTelemetry directly, and the webhook certificate
rotator already uses `cert-controller`; neither is a migration candidate.
Verify current call sites and semantics before proposing any migration.

Only add convenience wrappers when the same glue demonstrably repeats across
multiple repositories. Contribute that shared glue to `telekom/t-caas-go-library`
instead of duplicating it here. Keep consumer-specific policy local; if no
suitable upstream exists, state the missing capability or semantic mismatch
before implementing custom code.

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
The 12 reviewer personas (out of 16 total prompts; the remaining 4 are
task and workflow guides: `review-pr`, `add-crd-field`, `helm-chart-changes`,
`github-pr-management`) cover every issue class found by automated reviewers
(Copilot, etc.) and more.

Grouped below by the *class of bug* each persona catches (the table
above groups by domain):

**Code quality** (4 personas):
- **Go style** catches import alias violations (`authorizationv1alpha1` enforcement), `%v` error wrapping, `godot` comment periods, `revive` naming
- **Concurrency** catches SSA ownership conflicts, condition management bypasses, stale cache reads
- **K8s patterns** catches missing context timeouts, non-idempotent reconcilers, condition mis-management
- **Performance** catches unbounded namespace enumeration, SSA no-op waste, high-cardinality metrics

**Correctness** (4 personas):
- **Integration wiring** catches new code that is defined but never called, SSA apply gaps, RBAC drift, **PR description ↔ implementation alignment**
- **API & CRD** catches missing validation markers, backwards-compatibility breaks (incl. **validation tightening** as breaking), SSA completeness
- **Edge cases** catches namespace lifecycle races, SSA conflicts, zero-value bugs, webhook timing, **SSA field ownership edge cases** (ForceOwnership wars, GC interactions)
- **QA regression** catches RBAC generation regressions, condition reason changes, rollback hazards, **verification discipline** (search codebase before flagging)

**Security & documentation** (3 personas):
- **Security** catches privilege escalation via RBAC generation, webhook bypass, DoS vectors, **error response sanitization** (no internal details in admission responses)
- **Docs consistency** catches field name mismatches, stale condition references, Helm doc drift
- **CI & testing** catches coverage gaps, Ginkgo/testify mixing, missing enum cases, golden staleness, **verification discipline** (search tests before flagging)

**User-facing** (1 persona):
- **End-user** catches platform engineer confusion, admin upgrade friction, auditor visibility gaps

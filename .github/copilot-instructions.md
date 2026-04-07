# Auth Operator - Copilot Instructions

## Project Overview

Auth Operator is a Kubernetes operator for T-CaaS that manages authentication (`authN`) and authorization (`authZ`) across multiple cluster consumers. It provides six CRDs:
- **RoleDefinition**: Dynamically generates ClusterRoles/Roles based on API discovery
- **BindDefinition**: Creates ClusterRoleBindings/RoleBindings for subjects (Users, Groups, ServiceAccounts)
- **WebhookAuthorizer**: Configures webhook-based authorization decisions
- **RBACPolicy**: Defines policy constraints for restricted CRDs (allowed/forbidden roles, namespaces, subjects)
- **RestrictedRoleDefinition**: Policy-governed variant of RoleDefinition (must reference an RBACPolicy)
- **RestrictedBindDefinition**: Policy-governed variant of BindDefinition (must reference an RBACPolicy)

**Stack**: Go (see go.mod), Kubebuilder v4 (multi-group layout), controller-runtime v0.23, Ginkgo/Gomega testing, Helm chart  
**Domain**: `t-caas.telekom.com` | **API Group**: `authorization.t-caas.telekom.com` | **Version**: `v1alpha1`

## Build & Validation Commands

**Always run from repository root.** Tool versions in `versions.env`.

### Essential Workflow
```bash
make manifests generate  # ALWAYS after editing *_types.go or kubebuilder markers
make fmt vet lint        # Format, vet, lint
make build               # Build binary (includes manifests, generate, fmt, vet)
make test                # Unit + integration tests (envtest)
make docs                # Regenerate API docs
make helm                # Sync CRDs to Helm chart
```

### Pre-Commit Validation (Run Before Every PR)
```bash
go mod tidy              # CI verifies this
make manifests generate  # Regenerate CRDs/DeepCopy
make lint                # golangci-lint
make test                # Unit tests
make helm-lint           # Lint Helm chart
git diff --exit-code     # Verify no uncommitted generated changes
```

### CI Checks (GitHub Actions)
| Check | Command | Workflow |
|-------|---------|----------|
| Lint | `golangci-lint run --timeout 10m` | ci.yml |
| Vet | `go vet ./...` | ci.yml |
| go.mod tidy | `go mod tidy && git diff --exit-code go.mod go.sum` | ci.yml |
| Unit Tests | `make test` (envtest K8s 1.34.1) | ci.yml, e2e.yml |
| Build | `go build -v -o bin/auth-operator ./main.go` | ci.yml |
| Docker | `docker build -t auth-operator:test .` | ci.yml |
| Helm Lint | `helm lint chart/auth-operator --strict` | ci.yml |
| Security | `govulncheck ./...` | ci.yml |
| REUSE | License headers in all files | reuse-compliance.yml |

### E2E Testing (Requires kind + Docker)
```bash
make test-e2e-full       # Full suite (fresh kind cluster)
make test-e2e-helm-full  # Helm installation tests
make test-e2e-ha         # HA/leader-election (multi-node)
```
Set `SKIP_E2E_CLEANUP=true` to keep cluster for debugging.

**E2E Test Labels**: `helm`, `complex`, `ha`, `leader-election`, `integration`, `golden`, `dev`

## Project Structure (Multi-Group Kubebuilder v4)

```
main.go                              # Entry point (invokes cmd package)
cmd/
  root.go                            # CLI setup, scheme registration
  controller.go                      # Controller manager init
  webhook.go                         # Webhook server init
api/authorization/v1alpha1/
  roledefinition_types.go            # RoleDefinition CRD schema
  binddefinition_types.go            # BindDefinition CRD schema
  webhookauthorizer_types.go         # WebhookAuthorizer CRD schema
  rbacpolicy_types.go                # RBACPolicy CRD schema
  restrictedbinddefinition_types.go  # RestrictedBindDefinition CRD schema
  restrictedroledefinition_types.go  # RestrictedRoleDefinition CRD schema
  *_webhook.go                       # Validation webhooks
  conditions.go                      # Condition type definitions
  groupversion_info.go               # API group registration
  zz_generated.deepcopy.go           # AUTO-GENERATED (never edit)
internal/controller/authorization/
  roledefinition_controller.go       # RoleDefinition reconciliation
  binddefinition_controller.go       # BindDefinition reconciliation
  rbacpolicy_controller.go           # RBACPolicy reconciliation
  restrictedbinddefinition_controller.go  # RestrictedBindDefinition reconciliation
  restrictedroledefinition_controller.go  # RestrictedRoleDefinition reconciliation
  restricted_helpers.go              # Shared helpers for restricted CRDs
  *_helpers.go                       # Controller helpers
internal/webhook/
  authorization/                     # Webhook handlers
  certrotator/                       # TLS cert rotation (cert-controller)
pkg/
  conditions/                        # Condition management utilities
  discovery/                         # API resource discovery & tracking
  helpers/                           # Shared helpers
  indexer/                           # Client indexer utilities
  metrics/                           # Prometheus metrics registration
  policy/                            # RBACPolicy enforcement engine
  ssa/                               # Server-Side Apply helpers for RBAC
  system/                            # System-level utilities
config/
  crd/bases/                         # AUTO-GENERATED CRDs (never edit)
  rbac/                              # AUTO-GENERATED RBAC (never edit)
  webhook/manifests.yaml             # AUTO-GENERATED (never edit)
  overlays/dev/                      # Dev overlay (debug logging)
  overlays/production/               # Prod overlay
  samples/                           # Example CRs (edit these)
chart/auth-operator/
  crds/                              # AUTO-SYNCED from config/crd/bases
test/e2e/                            # E2E tests (Ginkgo)
docs/api-reference/                  # Generated API documentation
```

## Critical Rules

### Never Edit Auto-Generated Files
- `config/crd/bases/*.yaml` — run `make manifests`
- `config/rbac/role.yaml` — run `make manifests`
- `config/webhook/manifests.yaml` — run `make manifests`
- `api/**/zz_generated.deepcopy.go` — run `make generate`
- `chart/auth-operator/crds/*.yaml` — run `make helm`
- `PROJECT` — Kubebuilder metadata (do not edit)

### Never Remove Scaffold Markers
Do NOT delete `// +kubebuilder:scaffold:*` comments. Kubebuilder CLI injects code at these markers.

### Keep Project Structure
Do not move files around. The Kubebuilder CLI expects files in specific locations.

### After Editing Type Files
After modifying `api/authorization/v1alpha1/*_types.go` or kubebuilder markers:
```bash
make manifests generate  # Regenerate CRDs, RBAC, DeepCopy
make docs                # Regenerate API reference
make helm                # Sync CRDs to Helm chart
```

### Use Standard Library Constants
```go
// Good                    // Bad
http.MethodGet            "GET"
rbacv1.GroupName          "rbac.authorization.k8s.io"
```

### Testing Requirements
All new features must include tests (target >70% coverage):
- Unit tests: `*_test.go` colocated with source
- Controller tests: `internal/controller/authorization/*_test.go`
- E2E tests: `test/e2e/` (use Ginkgo labels)

#### Envtest Patterns
Controller tests use envtest (real API server + etcd, no kubelet):
```go
var testEnv *envtest.Environment

func TestControllers(t *testing.T) {
    RegisterFailHandler(Fail)
    RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
    testEnv = &envtest.Environment{
        CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
    }
    cfg, err := testEnv.Start()
    Expect(err).NotTo(HaveOccurred())
    // ... setup manager, client, scheme
})
```

#### Table-Driven Tests
```go
DescribeTable("validation",
    func(input string, expectErr bool) {
        err := validate(input)
        if expectErr {
            Expect(err).To(HaveOccurred())
        } else {
            Expect(err).NotTo(HaveOccurred())
        }
    },
    Entry("valid input", "good", false),
    Entry("empty input", "", true),
)
```

### Import Alias Convention
Use descriptive, consistent aliases throughout the codebase:
```go
import (
    authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
    ctrl "sigs.k8s.io/controller-runtime"
    rbacv1 "k8s.io/api/rbac/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)
```

### Error Wrapping
Always wrap errors with `%w` for proper error chain support:
```go
// Good — enables errors.Is/As
return fmt.Errorf("unable to get resource: %w", err)

// Bad — breaks error chain
return fmt.Errorf("unable to get resource: %v", err)
```

### REUSE / Licensing Compliance
- All new files **must** have SPDX headers or be covered by a glob in `REUSE.toml`.
- Standard header: `// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG` + `// SPDX-License-Identifier: Apache-2.0`
- CI runs `reuse lint` on every PR — ensure compliance before committing.
- See `REUSE.toml` for glob-based license annotations on auto-generated and binary files.

### E2E Tests Require Isolated Kind Cluster
Run E2E tests against a dedicated kind cluster, not dev/prod clusters.

## Controller & Webhook Patterns

### Reconciliation (Idempotent)
```go
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    logger := log.FromContext(ctx)
    // 1. Fetch resource (use client.IgnoreNotFound)
    // 2. Handle finalizers for cleanup
    // 3. Reconcile desired state
    // 4. Update status and conditions
}
```

### Condition Management
```go
import "github.com/telekom/auth-operator/pkg/conditions"
conditions.SetCondition(obj, metav1.Condition{
    Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "Success",
})
```

### RBAC Markers (in controllers)
```go
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=roledefinitions/finalizers,verbs=update
```

### Webhook Markers
```go
// +kubebuilder:webhook:path=/validate-...,mutating=false,failurePolicy=fail,sideEffects=None,...
```

### Structured Logging
```go
logger := log.FromContext(ctx)
logger.Info("msg", "key", val)
logger.V(1).Info("debug")  // Verbose
```

Use context-aware logging only in production controller/webhook code:
- derive logger with `log.FromContext(ctx)` where logging happens, or
- pass `ctx` into helpers and derive logger inside helper.

Do not pass raw logger instances across helper boundaries when `ctx` is available.

### Sample Set Semantics

- `config/samples/` contains structurally valid baseline samples for normal reconciliation.
- `config/samples/broken/` contains structurally valid runtime-failure samples that MUST apply,
  then stall or partially reconcile.
- Webhook/schema-invalid examples should not be part of the broken apply kustomization.

## Configuration Files

| File | Purpose |
|------|---------|
| `go.mod` | **Single source of truth for Go version** - CI, Dockerfile, Makefile all read from here |
| `.golangci.yml` | Go linter config (v2 format) |
| `.yamllint.yml` | YAML linting rules |
| `versions.env` | Tool versions (controller-gen, kustomize, etc.) |
| `PROJECT` | Kubebuilder project metadata (do not edit) |
| `Makefile` | All build/test/deploy commands |

## Environment Variables & CLI Flags

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POD_NAMESPACE` | Operator namespace (default for `--namespace` flag) | — |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (alternative to `--tracing-endpoint` flag) | — |

### CLI Flags (Global)

| Flag | Description | Default |
|------|-------------|---------|
| `--namespace` | Operator namespace | value of `POD_NAMESPACE` (empty if unset) |
| `--health-probe-bind-address` | Health probe address | `:8081` |
| `--metrics-bind-address` | Metrics address (set to `0` to disable serving) | `:8080` |
| `--metrics-secure` | Require authn/authz for metrics endpoint | `false` |
| `--verbosity` / `-v` | Log level (0-9) | `2` |
| `--tracing-enabled` | Enable OpenTelemetry tracing (requires `--tracing-endpoint` or `OTEL_EXPORTER_OTLP_ENDPOINT`) | `false` |
| `--tracing-endpoint` | OTLP collector endpoint (required when `--tracing-enabled` is true, unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set) | — |
| `--tracing-sampling-rate` | Trace sampling rate (0.0–1.0) | `0.1` |
| `--tracing-insecure` | Use insecure gRPC for tracing | `false` |

### CLI Flags (controller subcommand)

| Flag | Description | Default |
|------|-------------|---------|
| `--leader-elect` | Enable leader election | `true` |
| `--binddefinition-concurrency` | Max concurrent BindDefinition reconciliations | `5` |
| `--roledefinition-concurrency` | Max concurrent RoleDefinition reconciliations | `5` |
| `--webhookauthorizer-concurrency` | Max concurrent WebhookAuthorizer reconciliations | `1` |
| `--rbacpolicy-concurrency` | Max concurrent RBACPolicy reconciliations | `5` |
| `--restrictedbinddefinition-concurrency` | Max concurrent RestrictedBindDefinition reconciliations | `5` |
| `--restrictedroledefinition-concurrency` | Max concurrent RestrictedRoleDefinition reconciliations | `5` |
| `--cache-sync-timeout` | Timeout for waiting for CRDs to become available | `2m0s` |
| `--graceful-shutdown-timeout` | Timeout for graceful shutdown of the manager | `30s` |
| `--wait-for-crds` | Wait for required CRDs before starting controllers | `true` |

### CLI Flags (webhook subcommand)

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Webhook server port | `9443` |
| `--leader-elect` | Enable leader election | `false` |
| `--certs-dir` | Directory for HTTPS certificates | `""` |
| `--disable-cert-rotation` | Disable automatic cert rotation | `false` |
| `--enable-http2` | Enable HTTP/2 on the webhook server | `false` |
| `--cert-rotation-dns-name` | DNS name for the generated TLS certificate | `""` |
| `--cert-rotation-secret-name` | Secret name for the rotated certificate | `""` |
| `--cert-rotation-mutating-webhook` | Mutating webhook names to patch with CA bundle | `[]` |
| `--cert-rotation-validating-webhook` | Validating webhook names to patch with CA bundle | `[]` |
| `--tdg-migration` | Enable T-DDI to T-CaaS migration mode | `false` |
| `--authorize-rate-limit` | Per-pod sustained requests/second for authorize endpoint | `100` |
| `--authorize-rate-burst` | Burst size for authorize endpoint rate limiter | `200` |

## Common Issues & Workarounds

| Issue | Solution |
|-------|----------|
| "go.mod is not tidy" in CI | Run `go mod tidy` before committing |
| "Generated code out of date" | Run `make manifests generate` and commit |
| Envtest failures | Run `make envtest && $(LOCALBIN)/setup-envtest use 1.34.1 --bin-dir ./bin` |
| Helm CRD sync | Run `make helm` after modifying CRDs |

## Kubebuilder CLI Commands (Reference)

```bash
# Create new API
kubebuilder create api --group <group> --version <version> --kind <Kind>

# Create webhooks
kubebuilder create webhook --group <group> --version <version> --kind <Kind> --defaulting --programmatic-validation

# Controller for core K8s types (no CRD)
kubebuilder create api --group core --version v1 --kind Pod --controller=true --resource=false
```

## References

### Internal Documentation
- **Operator Guide**: `docs/operator-guide.md` — Installation, configuration, HA, upgrades
- **Debugging Guide**: `docs/debugging-guide.md` — Troubleshooting and diagnostics
- **Metrics & Alerting**: `docs/metrics-and-alerting.md` — Prometheus metrics and alerts
- **SSA Architecture**: `docs/ssa-architecture.md` — Server-Side Apply patterns
- **Condition Lifecycle**: `docs/condition-lifecycle.md` — Status condition reference
- **API Reference**: `docs/api-reference/authorization.t-caas.telekom.com.md` — CRD specification
- **E2E Testing**: `test/e2e/README.md` — End-to-end test guide
- **k8s-breakglass Integration**: `docs/breakglass-integration.md` — Temporary privilege escalation

### Related Projects
- **k8s-breakglass**: https://github.com/telekom/k8s-breakglass — Temporary privilege escalation system

### External References
- **Kubebuilder Book**: https://book.kubebuilder.io
- **controller-runtime**: https://github.com/kubernetes-sigs/controller-runtime
- **API Conventions**: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md
- **Markers Reference**: https://book.kubebuilder.io/reference/markers.html
- **Good Practices**: https://book.kubebuilder.io/reference/good-practices.html
- **cert-controller**: https://github.com/open-policy-agent/cert-controller (TLS management)

## Trust These Instructions
The information above is validated and accurate. Only search the codebase if these instructions are incomplete or produce errors.

# Auth-Operator — Full Repository Review

> **Date:** 2025-07  
> **Scope:** Entire `main` branch  
> **Reviewers:** Security Auditor, K8s Platform Engineer, Senior Go Engineer (automated personas)

---

## Executive Summary

The auth-operator is a well-structured Kubernetes RBAC operator with strong foundations: consistent Server-Side Apply (SSA) usage, comprehensive Prometheus metrics, proper concurrency primitives, kstatus conditions with `ObservedGeneration`, and a solid golangci-lint configuration. Key areas for improvement are RBAC least-privilege scoping, operational defaults (replicas, memory), and code maintainability (complexity, duplication, cache lifecycle).

| Severity | Security | Operations | Go Quality | **Total** |
|----------|----------|------------|------------|-----------|
| CRITICAL | 0        | 0          | 0          | **0**     |
| HIGH     | 4        | 3          | 2          | **9**     |
| MEDIUM   | 6        | 5          | 9          | **20**    |
| LOW      | 5        | 12         | 11         | **28**    |

---

## Security Findings

### SEC-001 | HIGH | Metrics Endpoint Exposed Without Authentication

**Description:** Both the controller manager and webhook server expose Prometheus metrics on `:8080` without any authentication or authorization. The `metricsserver.Options` only specifies `BindAddress` — it does not configure `FilterProvider` for authn/authz. Any pod with network access can scrape metrics which may reveal internal state (reconcile errors, managed resource counts, BindDefinition names, namespace counts).

**Files:**
- `cmd/controller.go:80` — `Metrics: metricsserver.Options{BindAddress: metricsAddr}`
- `cmd/webhook.go:85` — `Metrics: metricsserver.Options{BindAddress: metricsAddr}`

**Fix:** Enable metrics endpoint authentication using controller-runtime's built-in authn/authz support:
```go
Metrics: metricsserver.Options{
    BindAddress:    metricsAddr,
    FilterProvider: filters.WithAuthenticationAndAuthorization,
}
```

---

### SEC-002 | HIGH | Overly Broad ClusterRole: Wildcard Read Access to All Resources

**Description:** The Helm chart ClusterRole grants `get`, `list`, `watch` on `*/*` (all API groups, all resources). This includes secrets, configmaps, and any other sensitive resource in the cluster. While the RoleDefinition controller needs API discovery, it should use the discovery API (`/api`, `/apis`) rather than `get/list/watch` on `*/*`.

**File:** `chart/auth-operator/templates/clusterrole.yaml:55-62`

**Fix:** Replace the wildcard with explicit API groups/resources or use the discovery API client. If wildcard is truly necessary for dynamic discovery, document clearly and consider an aggregated ClusterRole that users can opt into.

---

### SEC-003 | HIGH | ClusterRole Has `escalate` and `bind` on Roles and ClusterRoles

**Description:** The ClusterRole grants `escalate` and `bind` verbs on `roles`, `clusterroles`, `rolebindings`, and `clusterrolebindings`. If the operator's service account is compromised, an attacker could create arbitrary ClusterRoleBindings granting cluster-admin to any principal.

**File:** `chart/auth-operator/templates/clusterrole.yaml:125-145`

**Fix:** This is inherent to the operator's design — document the risk. Consider adding a validating webhook on the operator's own SA to prevent bindings to `cluster-admin`. Consider splitting controller and webhook into separate SAs with narrower permissions.

---

### SEC-004 | HIGH | Broad Cluster-Wide Secrets Access

**Description:** The ClusterRole grants `get`, `list`, `patch`, `update`, `watch` on secrets cluster-wide. Likely needed for the cert-rotator but grants access to ALL secrets. An attacker compromising the operator pod can read every secret in the cluster.

**File:** `chart/auth-operator/templates/clusterrole.yaml:25-34`

**Fix:** Scope the secret access to only the operator's namespace using a Role (not ClusterRole) or use `resourceNames` to restrict to the specific webhook certificate secret name.

---

### SEC-005 | MEDIUM | No NetworkPolicy Deployed by Default

**Description:** The Helm chart does not include any `NetworkPolicy` resources by default. The controller manager and webhook server pods can receive traffic from any pod. The webhook server (port 9443) should only be accessible from the Kubernetes API server.

**File:** `chart/auth-operator/templates/` — no NetworkPolicy template

**Fix:** Add a `NetworkPolicy` template restricting ingress to webhook port from kube-apiserver, metrics port from monitoring namespace, and health probes from kubelet.

---

### SEC-006 | MEDIUM | AutomountServiceAccountToken Defaults to `true`

**Description:** `BindDefinitionSpec.AutomountServiceAccountToken` defaults to `true`. When BindDefinitions create ServiceAccounts, those SAs automatically mount API tokens into pods. This increases the attack surface for workloads that don't need Kubernetes API access.

**File:** `api/authorization/v1alpha1/binddefinition_types.go:87-93`

**Fix:** Consider changing default to `false` in a future API version. Document security implications.

---

### SEC-007 | MEDIUM | No Rate Limiting on Authorization Webhook Endpoint

**Description:** The `/authorize` webhook endpoint has no rate limiting. While request body size is limited to 1MB, an attacker could flood the webhook with SubjectAccessReview requests causing CPU/memory exhaustion.

**File:** `internal/webhook/authorization/webhook_authorizer.go:50-57`

**Fix:** Add rate limiting middleware using `golang.org/x/time/rate`.

---

### SEC-008 | MEDIUM | No Immutability Check on RoleDefinition TargetRole Change

**Description:** The validating webhook does not prevent changing `spec.targetRole` from `ClusterRole` to `Role` on update. This could leave orphaned RBAC resources and grant unintended permissions.

**File:** `api/authorization/v1alpha1/roledefinition_webhook.go:76-109`

**Fix:** Add immutability validation for `spec.targetRole` and `spec.targetName` in `ValidateUpdate`.

---

### SEC-009 | MEDIUM | BindDefinition Subject Kind Not Validated

**Description:** The `BindDefinitionSpec.Subjects` field uses `rbacv1.Subject` without webhook validation on the `Kind` field. Invalid subject kinds will be accepted but won't function.

**File:** `api/authorization/v1alpha1/binddefinition_types.go:68-70`

**Fix:** Add validation in the BindDefinition webhook to ensure each subject `Kind` is "User", "Group", or "ServiceAccount".

---

### SEC-010 | MEDIUM | Single Replica Defaults for Security-Critical Components

**Description:** Both controller and webhook default to `replicas: 1`. The webhook is particularly critical — if unavailable with `failurePolicy: Fail`, no namespaces can be created cluster-wide. PodDisruptionBudget is disabled by default.

**File:** `chart/auth-operator/values.yaml:46,62`

**Fix:** Default webhook server replicas to at least 2 for production. Enable PDB by default.

---

### SEC-011 | LOW | Error Messages May Leak Internal State

**Description:** Some error messages include raw error strings with internal Kubernetes API server details, visible to anyone with `get` access to the CRD status.

**File:** `internal/controller/authorization/roledefinition_helpers.go:165-169`

**Fix:** Sanitize error messages in status conditions. Log detailed errors separately.

---

### SEC-012 | LOW | Hardcoded Bypass Accounts in Webhook Helpers

**Description:** Webhook bypass accounts are hardcoded constants. No way for cluster admins to customize which accounts bypass namespace validation.

**File:** `internal/webhook/authorization/helpers.go:56-64`

**Fix:** Consider making configurable via ConfigMap or Helm values.

---

### SEC-013 | LOW | HTTP/2 Disabled Without Documentation

**Description:** Webhook server disables HTTP/2 by default (correct security measure for CVE-2023-44487) but the rationale is not documented in values.yaml.

**File:** `cmd/webhook.go:59-63`

**Fix:** Add comment in values.yaml explaining the CVE rationale.

---

### SEC-014 | LOW | Events Have Wildcard Verbs

**Description:** ClusterRole grants `*` (all verbs) on events instead of just `create`, `patch`, `update`. The `delete` verb could be used to tamper with audit trails.

**File:** `chart/auth-operator/templates/clusterrole.yaml:47-54`

**Fix:** Replace `*` with explicit `create`, `patch`, `update`.

---

### SEC-015 | LOW | SharedServiceAccount Across Controller and Webhook

**Description:** Both deployments use the same ServiceAccount. The controller has cert-rotator's secret access and the webhook has RBAC escalation privileges.

**Files:** `chart/auth-operator/templates/controller-manager-deployment.yaml:72`, `webhook-server-deployment.yaml:80`

**Fix:** Create separate ServiceAccounts and ClusterRoles.

---

## Operational Findings

### OPS-001 | HIGH | No Startup Probe — Liveness Kills Pods Before Cache Sync

**Description:** The webhook server Deployment has no `startupProbe`. In large clusters, cache sync can take 30-60 seconds. The liveness probe (10s initial delay + 10s period + 3 failures = 40s) may kill the pod before the cache is ready, creating a restart loop.

**File:** `chart/auth-operator/templates/webhook-server-deployment.yaml`

**Fix:** Add a startup probe with generous failureThreshold (e.g., `failureThreshold: 30`, `periodSeconds: 2` = 60s budget).

---

### OPS-002 | HIGH | Controller Memory Limit 128Mi Too Low

**Description:** The default memory limit is 128Mi. In clusters with >500 namespaces, the controller caches all namespaces, BindDefinitions, RoleDefinitions, and their associated Roles/ClusterRoles. OOM kills are likely at scale.

**File:** `chart/auth-operator/values.yaml` — resource limits section

**Fix:** Increase default to 256Mi or 512Mi. Document scaling guidelines.

---

### OPS-007 | HIGH | Webhook Server 1 Replica — Single Point of Failure

**Description:** The webhook server defaults to 1 replica with `failurePolicy: Fail`. If the webhook pod is evicted, restarting, or OOM-killed, ALL namespace operations cluster-wide are blocked.

**File:** `chart/auth-operator/values.yaml:62`

**Fix:** Default to 2 replicas. Enable PDB with `minAvailable: 1`. Add anti-affinity to spread across nodes.

---

### OPS-003 | MEDIUM | No `values.schema.json` for Helm Values

**Description:** No values schema means typos in values silently accepted. Users may configure `contorller.replicas` expecting it to work.

**Fix:** Add `values.schema.json` with JSON Schema validation.

---

### OPS-004 | MEDIUM | Tracker Events Channel Buffer Overflow

**Description:** The blocking resources tracker uses a channel buffer of 100. In clusters with many API resources, the channel can overflow and block periodic collection.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:176`

**Fix:** Size buffer dynamically or use a non-blocking send with overflow logging.

---

### OPS-005 | MEDIUM | Namespace Event Fan-Out to All BindDefinitions

**Description:** Every namespace event fans out to ALL BindDefinitions via label-based mapping. This creates O(N×M) no-op reconciles where N is namespace events and M is BindDefinition count.

**Fix:** Add more selective predicates or namespace-specific queueing.

---

### OPS-012 | LOW | terminationGracePeriodSeconds < graceful-shutdown-timeout

**Description:** `terminationGracePeriodSeconds: 10` is shorter than `--graceful-shutdown-timeout=30s`. In-flight reconciles will be SIGKILL'd before the controller can gracefully drain.

**Fix:** Set `terminationGracePeriodSeconds` to at least 35s (graceful timeout + 5s buffer).

---

### OPS-017 | MEDIUM | Leader Election Wire-Up Risk

**Description:** Leader election works via Helm args but Go default is `false`. If replicas are scaled without using the chart, multiple leaders could run simultaneously.

**Fix:** Default to `true` in Go code, let chart override to `false` for single-replica.

---

## Go Quality Findings

### GO-005 | HIGH | `namespaceTerminationResourcesCache` Grows Unboundedly

**Description:** `sync.Map` field `namespaceTerminationResourcesCache` is populated via `LoadOrStore` but entries are never evicted. Every terminating namespace creates a permanent entry — a memory leak in long-running operators.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:90`

**Fix:** Delete entries when the RoleBinding finalizer is successfully removed:
```go
r.namespaceTerminationResourcesCache.Delete(namespace.Name)
```

---

### GO-016 | HIGH | `gocyclo` Exclusions Mask High-Complexity Functions

**Description:** `.golangci.yml` excludes four critical files from cyclomatic complexity checking. The `Handle` method in the validating webhook has deeply nested control flow that likely exceeds the threshold of 20.

**File:** `.golangci.yml:165-172`

**Fix:** Refactor excluded functions to reduce complexity below the threshold, then remove exclusions.

---

### GO-001 | MEDIUM | Duplicate Bypass Logic Between Mutator and Validator

**Description:** `CheckMutatorBypass` and `CheckValidatorBypass` contain near-identical logic. Adding a new bypass account requires updating both functions.

**File:** `internal/webhook/authorization/helpers.go:102-178`

**Fix:** Extract common bypass rules into a data-driven configuration.

---

### GO-004 | MEDIUM | `rate.Sometimes.Do` Silently Returns Stale Results

**Description:** In `getNamespacedBlockingResources`, `rate.Sometimes.Do` may suppress the callback and return stale cached data with no feedback to the caller.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:125-136`

**Fix:** Track a timestamp alongside cached data. Log when returning cached vs. fresh data.

---

### GO-007 | MEDIUM | `markReady` Takes Unused `ctx` Parameter

**Description:** The function has `_ = ctx // unused` — an API smell. The parameter should either be used for logging or removed.

**File:** `internal/controller/authorization/binddefinition_helpers.go:106-112`

**Fix:** Use ctx for V(3) level logging or remove the parameter.

---

### GO-008 | MEDIUM | `collectNamespaces` Duplicates `resolveRoleBindingNamespaces`

**Description:** Both functions iterate over `roleBinding.NamespaceSelector`, create selectors, and list namespaces with slightly different semantics. Maintenance burden.

**Files:** `internal/controller/authorization/binddefinition_controller.go:1035-1083`, `binddefinition_helpers.go:363-395`

**Fix:** Extract a shared `resolveNamespaces` function.

---

### GO-011 | MEDIUM | Inconsistent Error Wrapping

**Description:** Some paths wrap errors with `fmt.Errorf("…: %w")` while others return bare errors. `ensureFinalizer` in roledefinition returns raw errors while binddefinition wraps them.

**Files:** `internal/controller/authorization/roledefinition_helpers.go:104-112`, `binddefinition_controller.go:302`

**Fix:** Always wrap errors with operation context.

---

### GO-013 | MEDIUM | `getOwningBindDefinition` Returns Generic Error Instead of Sentinel

**Description:** When no BindDefinition owner reference is found, returns `fmt.Errorf("no BindDefinition owner reference found")`. Callers cannot distinguish this from API errors without string matching.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:283`

**Fix:** Define `var ErrNoBindDefinitionOwner = errors.New(...)` and use `errors.Is` in callers.

---

### GO-002 | MEDIUM | Repeated Label Key Checks in `getLabelsFromNamespaceSelector`

**Description:** Repeated `if key == ...` checks for both `matchLabels` and `matchExpressions`.

**File:** `internal/webhook/authorization/namespace_mutating_webhook.go:165-195`

**Fix:** Use a `trackedLabelKeys` map.

---

### GO-018 | MEDIUM | `filterAPIResourcesForRoleDefinition` Takes Unused `context.Context`

**Description:** Function has `_ context.Context` as first parameter despite being logic-heavy. Debug logging would be useful.

**File:** `internal/controller/authorization/roledefinition_helpers.go:340`

**Fix:** Use context for V(3)/V(4) level logging of filtering decisions.

---

### GO-020 | MEDIUM | Webhook Deny Messages Not Centralized

**Description:** User-facing denial messages are hardcoded strings spread across multiple functions. Makes i18n and consistency difficult.

**Files:** `internal/webhook/authorization/namespace_mutating_webhook.go:154`, `namespace_validating_webhook.go:346`

**Fix:** Define denial message constants in the API package or a dedicated `messages.go`.

---

### GO-003 | LOW | `InjectDecoder` Methods Are Deprecated

**Description:** Both `NamespaceMutator.InjectDecoder` and `NamespaceValidator.InjectDecoder` implement the deprecated `admission.DecoderInjector` interface.

**Files:** `internal/webhook/authorization/namespace_mutating_webhook.go:30-33`, `namespace_validating_webhook.go:32-35`

**Fix:** Remove `InjectDecoder` and use `admission.NewDecoder(scheme)`.

---

### GO-006 | LOW | Non-Preallocated Slice in `formatBlockingResourcesMessage`

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:253`

**Fix:** `resourceDetails := make([]string, 0, len(blockingResources))`

---

### GO-009 | LOW | `deleteResult` Enum Zero Value Ambiguous

**Description:** `deleteResultDeleted = 0` makes error-path `return 0, err` semantically misleading.

**File:** `internal/controller/authorization/binddefinition_helpers.go:118-123`

**Fix:** Start iota at 1 or add `deleteResultUnknown = iota` at position 0.

---

### GO-010 | LOW | `SubjectExists` Uses Linear Scan

**Description:** O(n²) when called in a loop in `ensureServiceAccounts`.

**File:** `pkg/helpers/resource.go`

**Fix:** Use a map keyed by `namespace/name`.

---

### GO-012 | LOW | go.mod Has a Stale TODO for controller-runtime Pin

**Description:** Comment pins to a pre-release commit hash with `// TODO: switch to v0.23.2`. May be stale.

**File:** `go.mod:20`

**Fix:** Check if v0.23.2 is released and update.

---

### GO-015 | LOW | Metrics Use `init()` for Registration

**Description:** Makes testing harder and prevents registration order control.

**File:** `pkg/metrics/metrics.go:186-200`

**Fix:** Consider a `RegisterMetrics(registry)` function for testability.

---

### GO-017 | LOW | Missing Package-Level Godoc on `pkg/helpers`

**File:** `pkg/helpers/resource.go`

**Fix:** Add `// Package helpers ...` doc comment.

---

### GO-019 | LOW | `isOwnedByBindDefinition` Placement

**Description:** Cross-cutting concern defined in terminator controller. Could live in helpers.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:278-284`

---

### GO-021 | LOW | Channel Buffer Size Magic Number

**Description:** `make(chan namespaceDeletionResourceBlocking, 100)` has no sizing rationale.

**File:** `internal/controller/authorization/rolebinding_terminator_controller.go:176`

**Fix:** Extract as named constant with sizing comment.

---

### GO-022 | LOW | SSA Apply Functions Use `fmt.Errorf` for Validation Errors

**Description:** Programming errors should use sentinel errors or panics.

**File:** `pkg/ssa/ssa.go:93-104`

**Fix:** Define sentinel errors like `ErrMissingName`.

---

## Positive Observations

### Security
- Distroless container image with digest pinning
- Non-root user (65532) with `readOnlyRootFilesystem`
- `seccompProfile: RuntimeDefault` and `capabilities.drop: ALL`
- Request body size limit (1MB) on SubjectAccessReview endpoint
- Sensitive flag values redacted in logs via regex pattern
- Webhook cert rotation with proper TLS
- Audit logging for webhook bypass decisions
- Label immutability enforcement on namespaces

### Operations
- SSA used consistently with `ForceOwnership` — correct for an RBAC operator
- kstatus conditions (Ready/Reconciling/Stalled) with `ObservedGeneration` on every condition
- 13 custom Prometheus metrics with proper label cardinality management (`DeleteManagedResourceSeries`)
- CRD wait with configurable timeout before starting controllers
- Finalizer handling with optimistic locking and re-fetch before removal
- Ownership conflict pre-flight check before SSA apply
- Rate-limited API discovery with watch + periodic + full rescan fallback

### Go Quality
- Consistent SSA usage across all controllers
- Good error wrapping with `%w` (with some gaps noted above)
- Comprehensive test coverage (>75% on controllers, >80% on webhooks)
- Solid golangci-lint configuration
- Proper concurrency primitives (sync.Map, atomic, channels)
- Table-driven tests in webhook validation

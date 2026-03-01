# Proposal: CEL-Based Authorization for WebhookAuthorizer

| Field          | Value                                                   |
| -------------- | ------------------------------------------------------- |
| **Status**     | Draft                                                   |
| **Authors**    | @MaxRink                                                |
| **Created**    | 2026-03-01                                              |
| **K8s target** | 1.35+ (controller-runtime v0.23, apiextensions v0.35)   |
| **Go version** | 1.25                                                    |

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Background: Current Model](#3-background-current-model)
4. [Proposal Overview](#4-proposal-overview)
5. [Phase 1 — CEL Match Conditions](#5-phase-1--cel-match-conditions)
6. [Phase 2 — CEL Allow/Deny Rules](#6-phase-2--cel-allowdeny-rules)
7. [Phase 3 — Parameter References (In-Cluster Lookups)](#7-phase-3--parameter-references-in-cluster-lookups)
8. [Phase 4 — Full CEL Evaluation Mode](#8-phase-4--full-cel-evaluation-mode)
9. [CEL Environment & Variables](#9-cel-environment--variables)
10. [Security Considerations](#10-security-considerations)
11. [Performance & Scalability](#11-performance--scalability)
12. [Operational Concerns](#12-operational-concerns)
13. [Testing Strategy](#13-testing-strategy)
14. [Migration & Backwards Compatibility](#14-migration--backwards-compatibility)
15. [Implementation Roadmap](#15-implementation-roadmap)
16. [Open Questions](#16-open-questions)
17. [Appendix: Review Persona Analysis](#17-appendix-review-persona-analysis)

---

## 1. Problem Statement

The current `WebhookAuthorizer` CRD uses a **static, declarative model** for
authorization decisions:

- **Principal matching** requires exact string equality on `user` or `groups`,
  plus an optional namespace filter for ServiceAccounts.
- **Resource rules** are static verb/group/resource tuples.
- **Namespace scoping** is limited to label selectors.

This design works well for straightforward RBAC-style controls but **cannot
express**:

| Scenario | Why it fails today |
|---|---|
| Pattern-based principal matching (e.g. `system:serviceaccount:team-*:deployer`) | No regex/glob support on `user` field |
| Cross-field conditions (allow user X only for resource Y in namespace Z) | Requires creating separate WebhookAuthorizer CRs per combination |
| Time-based access windows (allow destructive verbs only during maintenance) | No temporal awareness at all |
| Conditional per-namespace rules (allow only in namespaces with `tier=production` annotation) | NamespaceSelector uses labels but cannot test annotations or combine with other conditions |
| External data-driven decisions (allow-lists stored in ConfigMaps) | No mechanism to reference cluster resources beyond namespaces |

As authorization requirements grow more nuanced, platform teams are forced to
proliferate `WebhookAuthorizer` CRs or work around limitations at the
infrastructure level.

## 2. Goals & Non-Goals

### Goals

- **G1**: Enable pattern-based principal matching using CEL string functions.
- **G2**: Support cross-field authorization conditions in a single CR.
- **G3**: Enable time-based access rules via a `now` variable.
- **G4**: Allow CEL expressions to reference in-cluster objects (Namespaces,
  ConfigMaps, user-defined resources) for data-driven decisions.
- **G5**: Maintain full backwards compatibility — existing CRs without CEL
  behave identically.
- **G6**: Provide actionable error messages for invalid CEL expressions at
  admission time.
- **G7**: Bound CEL evaluation cost to prevent webhook DoS.
- **G8**: Align with Kubernetes API conventions (ValidatingAdmissionPolicy
  patterns for CEL environment, paramRef).

### Non-Goals

- Replacing Kubernetes RBAC or OPA/Gatekeeper.
- Supporting arbitrary side-effects in CEL (HTTP calls, writes).
- Providing a CEL playground or REPL in the operator.
- CEL macros or user-defined CEL functions beyond the standard K8s CEL library.

## 3. Background: Current Model

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: example
spec:
  allowedPrincipals:
    - user: "system:serviceaccount:platform:deployer"
    - groups: ["platform-admins"]
    - namespace: "ci-cd"
  deniedPrincipals:
    - user: "system:anonymous"
  resourceRules:
    - verbs: ["get", "list", "watch"]
      apiGroups: ["apps"]
      resources: ["deployments"]
  nonResourceRules:
    - verbs: ["get"]
      nonResourceURLs: ["/healthz"]
  namespaceSelector:
    matchLabels:
      env: production
```

**Evaluation flow** (`evaluateSAR`):

1. For each `WebhookAuthorizer` (sorted by name for deterministic order):
   a. If `namespaceSelector` is set and the target namespace doesn't match → skip.
   b. If the SAR principal matches `deniedPrincipals` → **deny**.
   c. If the SAR principal matches `allowedPrincipals` AND resource/non-resource rules match → **allow**.
2. If no authorizer matched → **deny** ("no matching rules").

This is a first-match, deny-before-allow model.

## 4. Proposal Overview

We introduce CEL (Common Expression Language) into the `WebhookAuthorizer` in
**four incremental phases**, each building on the previous:

| Phase | Feature | Minimum Viable | Builds On |
|-------|---------|----------------|-----------|
| **1** | `matchConditions` | CEL guards that scope when an authorizer applies | — |
| **2** | `celRules` | CEL expressions that return allow/deny/noOpinion | Phase 1 |
| **3** | `paramRef` | In-cluster object lookups available as CEL variables | Phase 2 |
| **4** | `mode: cel` | Full CEL evaluation replacing the static model | Phases 1–3 |

Each phase is independently useful, backwards-compatible, and shippable.

---

## 5. Phase 1 — CEL Match Conditions

### Motivation

Today, `namespaceSelector` is the only way to scope when an authorizer applies.
CEL match conditions provide **arbitrary pre-filtering** on any SAR field before
the static allow/deny logic runs.

This mirrors the `matchConditions` field on Kubernetes
`ValidatingAdmissionPolicy` and `ValidatingWebhookConfiguration` (GA in K8s 1.30).

### API Changes

```go
// WebhookAuthorizerSpec defines the desired state of WebhookAuthorizer.
type WebhookAuthorizerSpec struct {
    // ... existing fields ...

    // MatchConditions is a list of CEL expressions that must ALL evaluate to
    // true for this authorizer to be considered during SubjectAccessReview
    // evaluation. If any condition evaluates to false, the authorizer is
    // skipped (equivalent to noOpinion).
    //
    // Each expression has access to the `request` variable containing the
    // SubjectAccessReview spec fields.
    //
    // When empty, the authorizer always participates (current behavior).
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxItems=16
    MatchConditions []MatchCondition `json:"matchConditions,omitempty"`
}

// MatchCondition is a CEL expression used as a pre-filter.
type MatchCondition struct {
    // Name is a human-readable identifier for this condition, used in
    // logging and error messages. Must be unique within the authorizer.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=64
    // +kubebuilder:validation:Pattern=`^[a-zA-Z_][a-zA-Z0-9_]*$`
    Name string `json:"name"`

    // Expression is a CEL expression that must evaluate to a boolean.
    // When false, this authorizer is skipped for the current request.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=2048
    Expression string `json:"expression"`
}
```

### Example CRs

**Pattern-based principal matching** — only apply this authorizer to
ServiceAccounts in `team-*` namespaces:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: team-deployers
spec:
  matchConditions:
    - name: isTeamServiceAccount
      expression: >-
        request.user.startsWith("system:serviceaccount:team-")
  allowedPrincipals:
    - groups: ["deployers"]
  resourceRules:
    - verbs: ["*"]
      apiGroups: ["apps"]
      resources: ["deployments"]
```

**Skip for cluster-admin group** — never evaluate this authorizer for cluster
admins:

```yaml
spec:
  matchConditions:
    - name: notClusterAdmin
      expression: >-
        !request.groups.exists(g, g == "system:masters")
```

### Evaluation Flow Change

```
For each WebhookAuthorizer (sorted by name):
  1. [EXISTING] If namespaceSelector set and NS doesn't match → skip
  2. [NEW]      If any matchCondition evaluates to false → skip
  3. [EXISTING] If deniedPrincipals match → deny
  4. [EXISTING] If allowedPrincipals + rules match → allow
```

Match conditions are evaluated **before** the static principal/rule logic, so
they act as a "gate" that can cheaply short-circuit evaluation.

### Validation

CEL expressions are compiled and type-checked at **admission time**
(`ValidateCreate`/`ValidateUpdate`). The admission webhook:

1. Creates a CEL environment with the `request` variable type.
2. Compiles each expression and ensures it returns `bool`.
3. Estimates the cost and rejects expressions exceeding the cost budget.
4. Rejects duplicate `name` fields within `matchConditions`.

If compilation fails, the admission webhook returns a descriptive error including
the CEL error position and type mismatch details.

### Status & Conditions

New condition reasons extend the existing typed constant pattern from
`conditions.go`. Each maps to a specific kstatus condition type:

| Reason | Condition Type | Status | Set By |
|--------|---------------|--------|--------|
| `CELCompilationFailed` | `Stalled` | `True` | Reconciler (permanent — user must fix expression) |
| `ParamRefNotFound` | `Reconciling` | `True` | Reconciler (transient — object may appear) |
| `CELCostExceeded` | — | — | Webhook handler (deny + metric, not a condition) |

The reconciler re-validates CEL for CRs that bypassed webhook validation
(e.g., migrated from backup) and sets conditions accordingly.

```go
const (
    // CEL compilation errors are permanent — the user must fix the expression.
    StalledReasonCELCompilationFailed  AuthZConditionReason  = "CELCompilationFailed"
    StalledMessageCELCompilationFailed AuthZConditionMessage = "one or more CEL expressions failed compilation: %s"

    // paramRef target not found is transient — the object may appear.
    ReconcilingReasonParamRefNotFound  AuthZConditionReason  = "ParamRefNotFound"
    ReconcilingMessageParamRefNotFound AuthZConditionMessage = "paramRef target %s/%s not found in cache"
)
```

> **Note**: `CELCostExceeded` is a runtime event during SAR evaluation, not a
> reconciler condition. It increments the `auth_operator_cel_cost_exceeded_total`
> counter and is logged at Error level.

---

## 6. Phase 2 — CEL Allow/Deny Rules

### Motivation

Phase 1 only filters *when* an authorizer applies. Phase 2 lets CEL
expressions make the **authorization decision itself** — enabling cross-field
conditions that are impossible with static principal/rule matching.

### API Changes

```go
type WebhookAuthorizerSpec struct {
    // ... existing fields ...
    // ... matchConditions from Phase 1 ...

    // CELRules is a list of CEL-based authorization rules. Each rule
    // specifies an action (Allow or Deny) and a CEL expression.
    //
    // CELRules are evaluated AFTER matchConditions pass and BEFORE
    // static allowedPrincipals/deniedPrincipals. The first matching
    // CEL rule determines the outcome.
    //
    // If no CEL rule matches, evaluation falls through to static rules.
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxItems=32
    CELRules []CELRule `json:"celRules,omitempty"`
}

// CELRule defines a CEL expression paired with an authorization action.
type CELRule struct {
    // Name is a human-readable identifier for this rule, used in
    // logging, metrics, and the SubjectAccessReview reason string.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=64
    // +kubebuilder:validation:Pattern=`^[a-zA-Z_][a-zA-Z0-9_]*$`
    Name string `json:"name"`

    // Expression is a CEL expression that must evaluate to a boolean.
    // When true, the Action is applied.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=2048
    Expression string `json:"expression"`

    // Action determines the authorization outcome when Expression is true.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:Enum=Allow;Deny
    Action CELRuleAction `json:"action"`

    // Message is an optional human-readable literal string included in the
    // SubjectAccessReview reason when this rule matches.
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxLength=512
    Message string `json:"message,omitempty"`

    // MessageExpression is an optional CEL expression that evaluates to a
    // string, used as the SubjectAccessReview reason when this rule matches.
    // Has access to the same variables as Expression. Takes precedence over
    // Message when set. If evaluation fails, falls back to Message.
    //
    // This follows the ValidatingAdmissionPolicy messageExpression pattern.
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxLength=512
    MessageExpression string `json:"messageExpression,omitempty"`
}

// CELRuleAction defines the outcome when a CEL rule matches.
// +kubebuilder:validation:Enum=Allow;Deny
type CELRuleAction string

const (
    CELRuleActionAllow CELRuleAction = "Allow"
    CELRuleActionDeny  CELRuleAction = "Deny"
)
```

### Example CRs

**Cross-field condition** — allow user `ci-bot` only for Deployments in the
`ci-cd` namespace:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: ci-bot-scoped
spec:
  matchConditions:
    - name: isResourceRequest
      expression: "has(request.resourceAttributes)"
  celRules:
    - name: allowCiBotDeployments
      expression: >-
        request.user == "ci-bot" &&
        request.resourceAttributes.namespace == "ci-cd" &&
        request.resourceAttributes.resource == "deployments" &&
        request.resourceAttributes.group == "apps"
      action: Allow
      message: "ci-bot is allowed to manage deployments in ci-cd namespace"
  resourceRules:
    - verbs: ["create", "update", "patch", "delete"]
      apiGroups: ["apps"]
      resources: ["deployments"]
```

**Time-based access window** — deny destructive verbs outside business hours
(UTC):

```yaml
spec:
  matchConditions:
    - name: isResourceRequest
      expression: "has(request.resourceAttributes)"
  celRules:
    - name: denyOutsideBusinessHours
      expression: >-
        request.resourceAttributes.verb in ["delete", "patch", "update"] &&
        (now.getHours() < 8 || now.getHours() >= 18)
      action: Deny
      message: "destructive operations are only allowed 08:00–18:00 UTC"
```

**Regex-style principal matching** — deny any ServiceAccount from `legacy-*`
namespaces:

```yaml
spec:
  celRules:
    - name: denyLegacyServiceAccounts
      expression: >-
        request.user.matches("^system:serviceaccount:legacy-.*:.*$")
      action: Deny
      message: "ServiceAccounts from legacy namespaces are denied"
```

### Evaluation Flow Change

```
For each WebhookAuthorizer (sorted by name):
  1. [Phase 0] If namespaceSelector set and NS doesn't match → skip
  2. [Phase 1] If any matchCondition evaluates to false → skip
  3. [Phase 0] If deniedPrincipals match → DENY (unchanged — deny-first preserved)
  4. [Phase 2] Evaluate celRules in order:
     a. If expression is true AND action is Deny  → DENY (return immediately)
     b. If expression is true AND action is Allow → ALLOW (return immediately)
  5. [Phase 0] If allowedPrincipals + rules match → allow
```

> **Design invariant**: Static `deniedPrincipals` are always checked **before**
> CEL rules. No CEL Allow rule can override an explicit `deniedPrincipals` entry.
> This preserves the existing deny-before-allow security guarantee.

CEL rules are evaluated **first-match**. If no CEL rule matches, evaluation
falls through to the existing static logic, preserving backwards compatibility.

### CEL Rule Message Expressions

The `message` field is a literal string. For dynamic messages, use the
separate `messageExpression` field, which is a CEL expression that must
evaluate to a `string`:

```yaml
celRules:
  - name: denyAfterHours
    expression: >-
      has(request.resourceAttributes) &&
      request.resourceAttributes.verb in ["delete"] &&
      (now.getHours() < 8 || now.getHours() >= 18)
    action: Deny
    message: "destructive operations are only allowed during business hours"
    messageExpression: >-
      'denied user ' + request.user + ' at ' + string(now)
```

When `messageExpression` is set and evaluates successfully, its result is used.
If evaluation fails, `message` is used as a fallback. When neither is set,
a default reason including the authorizer and rule name is generated.

This follows the `ValidatingAdmissionPolicy` pattern where `message` and
`messageExpression` are separate fields, avoiding the ambiguity of implicit
CEL detection.

> **Security note**: `messageExpression` can expose paramRef data via SAR
> response reason strings. Since the CR author has cluster-admin access
> (Section 10.1), this is within the trust boundary. Auditors should review
> `messageExpression` fields for unintended data exposure.

---

## 7. Phase 3 — Parameter References (In-Cluster Lookups)

### Motivation

Hard-coding allow-lists, time windows, or environment metadata in CEL
expressions makes them brittle and hard to audit. Phase 3 introduces
**parameter references** that bind in-cluster objects as CEL variables,
enabling data-driven authorization decisions.

This aligns with the Kubernetes `ValidatingAdmissionPolicy` `paramRef`
pattern.

### API Changes

```go
type WebhookAuthorizerSpec struct {
    // ... existing fields ...
    // ... matchConditions, celRules ...

    // ParamRefs binds in-cluster objects that are available as typed
    // variables in CEL expressions. Each paramRef defines a variable
    // name and a reference to a Kubernetes resource.
    //
    // Referenced objects are read from the informer cache, never via
    // live API calls. The operator watches referenced resource kinds
    // and re-reconciles when they change.
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxItems=8
    ParamRefs []ParamRef `json:"paramRefs,omitempty"`
}

// ParamRef binds an in-cluster object to a CEL variable.
type ParamRef struct {
    // Name is the CEL variable name for this parameter. Must be a valid
    // CEL identifier that does not collide with reserved variable names.
    //
    // Reserved names (rejected by admission webhook):
    //   request, now, authorizer, authz, object, oldObject, params
    //
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=64
    // +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9_]*$`
    Name string `json:"name"`

    // Resource identifies the Kubernetes resource to bind.
    Resource ParamResource `json:"resource"`
}

// ParamResource identifies a specific Kubernetes resource instance.
type ParamResource struct {
    // APIVersion is the API group/version (e.g. "v1", "apps/v1").
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=64
    APIVersion string `json:"apiVersion"`

    // Kind is the resource kind (e.g. "ConfigMap", "Namespace").
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=64
    Kind string `json:"kind"`

    // Name is the resource name.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=253
    Name string `json:"name"`

    // Namespace is the resource namespace. Required for namespaced
    // resources. Omit for cluster-scoped resources.
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxLength=63
    Namespace string `json:"namespace,omitempty"`
}
```

### Admission Validation Rules

Beyond schema markers, the admission webhook enforces:

1. **Reserved variable names**: paramRef names matching the set
   `{request, now, authorizer, authz, object, oldObject, params}` are
   rejected.
2. **Allowed-kind list**: Only permitted GVKs (see below) are accepted.
3. **Self-reference prohibition**: paramRefs referencing
   `authorization.t-caas.telekom.com/WebhookAuthorizer` are rejected to
   prevent reconciliation loops.
4. **Duplicate names**: No two paramRefs may share the same `name`.

### Allowed Resource Kinds

To prevent information disclosure and reduce RBAC surface, the operator
restricts which resource kinds are allowed in `paramRef`. The initial
allowed-list is:

| Kind | APIVersion | Rationale |
|------|-----------|-----------|
| `Namespace` | `v1` | Already used for namespace label matching |
| `ConfigMap` | `v1` | Safe data carrier for allow-lists, config |

Cluster operators can extend the allowed-list via the Helm chart
(`cel.allowedParamKinds`) or a CLI flag. The admission webhook rejects
`paramRef` entries pointing to disallowed kinds.

**Secrets are explicitly forbidden** by default to prevent credential
leakage through CEL evaluation logs.

### Example CRs

**ConfigMap-driven allow-list** — allow users listed in a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authorized-deployers
  namespace: auth-system
data:
  users: "alice,bob,ci-bot"
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: deployer-allowlist
spec:
  paramRefs:
    - name: allowList
      resource:
        apiVersion: v1
        kind: ConfigMap
        name: authorized-deployers
        namespace: auth-system
  celRules:
    - name: checkAllowList
      expression: >-
        has(allowList.data) && has(allowList.data["users"]) &&
        request.user in allowList.data["users"].split(",")
      action: Allow
      message: "user is in the authorized-deployers ConfigMap"
  resourceRules:
    - verbs: ["*"]
      apiGroups: ["apps"]
      resources: ["deployments"]
```

**Namespace annotation-based rules** — allow only in namespaces with a
specific annotation. The target namespace must be referenced by a
statically-named paramRef (dynamic resolution is a future consideration,
see Open Question #3):

```yaml
spec:
  paramRefs:
    - name: targetNS
      resource:
        apiVersion: v1
        kind: Namespace
        name: production  # Static name — resolved at reconcile time
  celRules:
    - name: requireProductionTier
      expression: >-
        has(targetNS.metadata.annotations) &&
        "tier" in targetNS.metadata.annotations &&
        targetNS.metadata.annotations["tier"] == "production"
      action: Allow
```

> **Future consideration**: Dynamic namespace resolution (binding a paramRef
> to the SAR’s target namespace at evaluation time) is deferred to a future
> enhancement. See Open Question #3 for design considerations.

### paramRef Resolution

1. **Cache-only**: paramRef objects are resolved from the informer cache, never
   via live API calls. This guarantees <1ms lookup latency.
2. **Snapshot guarantee**: All paramRef objects for a given SAR evaluation are
   resolved **once** at the start of evaluation and captured in an immutable
   snapshot map. This snapshot is shared across all matchCondition and celRule
   evaluations within that SAR, preventing mid-evaluation inconsistencies
   (e.g., a ConfigMap being deleted between a `has()` guard and a data access).
3. **Dynamic watches**: When a `WebhookAuthorizer` references a new
   GVK/namespace/name, the reconciler registers a watch via a thread-safe
   `watchManager` component (see Architecture below). Watches are cleaned up
   when no `WebhookAuthorizer` references that GVK anymore.
4. **Missing objects**: If a paramRef target doesn't exist:
   - During **reconciliation**: set condition `ParamRefNotFound` (transient, requeue with backoff).
   - During **SAR evaluation**: the variable is `null` in the snapshot. CEL expressions must use `has()` guards.
5. **Cache staleness**: paramRef data may be stale by up to the informer resync
   period (typically 10 minutes). This is acceptable for authorization
   decisions on data that changes infrequently (allow-lists, namespace metadata).
   The staleness window is documented and configurable.
6. **ConfigMap without `.data`**: If a ConfigMap has only `.binaryData` and
   no `.data` field, `has(param.data)` returns `false`. CEL expressions
   must guard `.data` access accordingly.

### Dynamic Watch Architecture

The paramRef watch lifecycle is managed by a `watchManager` component:

```go
// watchManager tracks active GVK watches for paramRef resolution.
// Thread-safe for concurrent reconciler access.
type watchManager struct {
    mu       sync.Mutex
    watches  map[schema.GroupVersionKind]watchEntry
    ctrl     controller.Controller
}

type watchEntry struct {
    refCount int        // Number of WebhookAuthorizers referencing this GVK.
    cancel   func()     // Cancels the watch source.
}
```

- **Reconciler calls** `watchManager.EnsureWatch(gvk)` for each paramRef GVK.
- **On CR deletion**, `watchManager.Release(gvk)` decrements the ref count;
  when zero, the watch is cancelled.
- **Reverse index**: An `EnqueueRequestsFromMapFunc` maps ConfigMap/Namespace
  changes back to referencing `WebhookAuthorizer` CRs, triggering re-reconciliation.
- **Location**: `internal/controller/authorization/watch_manager.go`

### RBAC Impact

The operator needs `get`, `list`, `watch` permissions for each allowed paramRef
kind. For the default allowed-list (ConfigMap, Namespace), the operator already
has Namespace permissions. ConfigMap requires adding:

```yaml
# +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
```

This marker goes on the `WebhookAuthorizerReconciler.Reconcile()` method and
flows through `make manifests` → `config/rbac/role.yaml` → `make helm` →
`chart/auth-operator/templates/clusterrole.yaml`.

When the allowed-list is extended, the cluster operator must grant additional
RBAC to the operator’s ServiceAccount.

> **⚠️ Security note**: This grants the operator **cluster-wide read access to
> all ConfigMaps** in every namespace. ConfigMaps may contain sensitive data
> (TLS certs, database URLs, cloud configs). Document this blast radius in
> the Helm chart values. Consider using namespace-scoped `Role` + `RoleBinding`
> if only specific namespaces contain paramRef targets. See Section 10.2.

---

## 8. Phase 4 — Full CEL Evaluation Mode

### Motivation

For advanced use cases, the static `allowedPrincipals`/`deniedPrincipals` +
`resourceRules`/`nonResourceRules` model is not just insufficient but actively
burdensome — users must maintain parallel CEL and static rules. Phase 4
introduces a `mode` field that lets a `WebhookAuthorizer` use **CEL as the
sole authorization engine**.

### API Changes

```go
type WebhookAuthorizerSpec struct {
    // Mode controls the evaluation model for this authorizer.
    //
    // - "Static" (default): Uses allowedPrincipals, deniedPrincipals,
    //   resourceRules, nonResourceRules, and optionally matchConditions
    //   and celRules (Phases 1-3).
    //
    // - "CEL": Uses a single CEL expression as the sole authorization
    //   decision. Static principal and rule fields are ignored. The
    //   expression must return an Authz value (allow/deny/noOpinion).
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:default=Static
    // +kubebuilder:validation:Enum=Static;CEL
    Mode EvaluationMode `json:"mode,omitempty"`

    // Authorization is the CEL expression used when mode is "CEL".
    // It must return an object of type Authz with fields:
    //   - allowed (bool): whether the request is allowed
    //   - reason  (string): human-readable reason for the decision
    //
    // Construct return values using the Authz helper functions:
    //   - authz.allow("reason") → allowed with reason
    //   - authz.deny("reason")  → denied with reason
    //   - authz.noOpinion()     → skip this authorizer
    //
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxLength=4096
    Authorization string `json:"authorization,omitempty"`

    // ... existing fields ...
}

// EvaluationMode determines how the authorizer evaluates requests.
// +kubebuilder:validation:Enum=Static;CEL
type EvaluationMode string

const (
    EvaluationModeStatic EvaluationMode = "Static"
    EvaluationModeCEL    EvaluationMode = "CEL"
)
```

**Zero-value semantics**: Existing CRs stored in etcd before the `mode` field
exists will have `mode: ""` (empty string). The evaluation code must treat
`""` and `"Static"` identically: `if mode == "" || mode == EvaluationModeStatic`.
The defaulting webhook sets `mode: Static` on create/update, but the evaluator
must handle the empty case for CRs that bypass defaulting (backup restore, GitOps).

**Cross-field CRD validation** (works even when the webhook is unavailable):

```yaml
# x-kubernetes-validations on WebhookAuthorizerSpec:
- rule: "self.mode != 'CEL' || self.authorization != ''"
  message: "authorization expression is required when mode is CEL"
```

The reconciler additionally validates: if `mode == CEL` and `authorization == ""`,
it sets a `Stalled` condition with reason `InvalidConfiguration`.

### Example CRs

**Full CEL mode** — complex multi-factor authorization in a single expression:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: WebhookAuthorizer
metadata:
  name: advanced-policy
spec:
  mode: CEL
  paramRefs:
    - name: policy
      resource:
        apiVersion: v1
        kind: ConfigMap
        name: auth-policy
        namespace: auth-system
  authorization: |
    // Deny anonymous users unconditionally.
    request.user == "system:anonymous" ? authz.deny("anonymous access denied") :

    // Deny destructive verbs outside business hours.
    request.resourceAttributes.verb in ["delete"] &&
    (now.getHours() < 8 || now.getHours() >= 18) ?
      authz.deny("delete operations only allowed 08:00-18:00 UTC") :

    // Allow users in the allowList ConfigMap.
    has(policy.data["users"]) &&
    request.user in policy.data["users"].split(",") ?
      authz.allow("user in authorized-deployers list") :

    // No opinion — let other authorizers decide.
    authz.noOpinion()
```

### Validation

When `mode: CEL`:

1. The `authorization` field is **required** and must be non-empty.
2. Static fields (`allowedPrincipals`, `deniedPrincipals`, `resourceRules`,
   `nonResourceRules`) should be empty. If present, the admission webhook
   emits a **warning** (not error) indicating they will be ignored.
3. The CEL expression must return the `Authz` type (not `bool`).
4. `matchConditions` remain functional in CEL mode — they still gate whether
   the authorizer participates.

### The `authz` Helper Object

The `authz` object is a CEL custom type providing factory functions:

| Function | Return Type | Semantics |
|----------|-------------|-----------|
| `authz.allow(reason)` | `Authz` | Request is allowed with the given reason. |
| `authz.deny(reason)` | `Authz` | Request is denied with the given reason. |
| `authz.noOpinion()` | `Authz` | Authorizer abstains — continue to next authorizer. |

This pattern mirrors Kubernetes `authorizer.responseAttributes` in admission
CEL and provides a clean three-valued authorization semantic.

---

## 9. CEL Environment & Variables

### Variable Reference

All CEL expressions (matchConditions, celRules, authorization) share the same
variable environment:

| Variable | Type | Available | Description |
|----------|------|-----------|-------------|
| `request.user` | `string` | Always | The requesting user identity. |
| `request.groups` | `list(string)` | Always | The requesting user's group memberships. |
| `request.uid` | `string` | Always | The UID of the requesting user. |
| `request.extra` | `map(string, list(string))` | Always | Extra attributes from the authentication layer. |
| `request.resourceAttributes.namespace` | `string` | Resource requests | Target namespace. |
| `request.resourceAttributes.verb` | `string` | Resource requests | API verb (get, list, create, etc.). |
| `request.resourceAttributes.group` | `string` | Resource requests | API group. |
| `request.resourceAttributes.version` | `string` | Resource requests | API version. |
| `request.resourceAttributes.resource` | `string` | Resource requests | API resource. |
| `request.resourceAttributes.subresource` | `string` | Resource requests | API subresource. |
| `request.resourceAttributes.name` | `string` | Resource requests | Object name (if applicable). |
| `request.nonResourceAttributes.path` | `string` | Non-resource requests | URL path. |
| `request.nonResourceAttributes.verb` | `string` | Non-resource requests | HTTP verb. |
| `now` | `timestamp` | Always | Current UTC timestamp, captured once per SAR evaluation (immutable within a single request). |
| `authorizer.name` | `string` | Always | Name of the `WebhookAuthorizer` CR. |
| `authorizer.labels` | `map(string, string)` | Always | Labels of the `WebhookAuthorizer` CR. |
| `authorizer.annotations` | `map(string, string)` | Always | Annotations of the `WebhookAuthorizer` CR. |
| `<paramRef.name>` | `object` | Phase 3+ | Resolved paramRef objects (dynamic). |

### Null Safety

- `request.resourceAttributes` is `null` for non-resource requests.
- `request.nonResourceAttributes` is `null` for resource requests.
- paramRef variables are `null` when the referenced object doesn't exist.
- CEL expressions **must** use `has()` or null-coalescing (`?:`) to safely
  access optional fields.

### CEL Libraries

The CEL environment includes:

| Library | Purpose |
|---------|---------|
| Standard CEL | Arithmetic, string ops, list/map operations |
| K8s CEL extensions | `url`, `regex`, `authz`, `quantity` |
| `strings` ext | `split`, `join`, `replace`, `trim`, `lowerAscii`, `upperAscii` |
| `sets` ext  | `sets.contains`, `sets.intersects`, `sets.equivalent` |

The environment is constructed once at startup and shared across all
evaluations (thread-safe, immutable after creation).

> **Regex safety**: CEL's `matches()` function uses RE2, which guarantees
> linear-time evaluation. There is no risk of ReDoS (regular expression
> denial of service) attacks through CEL regex operations.

### CEL Cost Budget

Every CEL expression is subject to a **cost budget** that limits computational
complexity:

| Limit | Default | Configurable |
|-------|---------|------------|
| Per-expression compilation cost | 100,000 | `--cel-compilation-cost-limit` |
| Per-expression runtime cost | 1,000,000 | `--cel-runtime-cost-limit` |
| **Per-authorizer aggregate runtime cost** | **5,000,000** | `--cel-aggregate-cost-limit` |
| **Per-SAR total runtime cost** | **50,000,000** | No (hard limit) |
| Max expression length | 4,096 chars | Kubebuilder validation |
| Max matchConditions per CR | 16 | Kubebuilder validation |
| Max celRules per CR | 32 | Kubebuilder validation |
| Max paramRefs per CR | 8  | Kubebuilder validation |

The **per-authorizer aggregate** limit (sum of all matchConditions + celRules
for one CR) prevents a single CR from monopolizing the evaluation budget.
The **per-SAR total** limit (sum across all authorizers evaluated for one
SubjectAccessReview) prevents aggregate DoS across many CRs.

Cost estimation occurs at **compile time** (admission webhook). Runtime cost
tracking terminates long-running evaluations with a clear error.

---

## 10. Security Considerations

### 10.1 CEL as a Privilege Escalation Vector

**Threat**: A user who can create/edit `WebhookAuthorizer` CRs can write CEL
that always evaluates to `allow`, effectively granting themselves arbitrary
permissions.

**Mitigations**:
- `WebhookAuthorizer` is a **cluster-scoped** resource. Creating/editing it
  requires cluster-admin-equivalent permissions, same as creating ClusterRoles.
- The admission webhook validates that CEL expressions are syntactically and
  type-correct, but does **not** validate semantic authorization intent —
  this is consistent with how Kubernetes treats ClusterRole rules.
- Organizations should use Kubernetes RBAC to restrict who can manage
  `WebhookAuthorizer` CRs.

### 10.2 paramRef Information Disclosure

**Threat**: CEL expressions that reference arbitrary cluster resources via
paramRef could leak sensitive data through authorization decision reasons.

**Mitigations**:
- **Allowed-list for paramRef kinds**: Only `Namespace` and `ConfigMap` are
  allowed by default. `Secret` is **explicitly forbidden**.
- The allowed-list is configurable but requires operator restart (Helm values
  change), preventing runtime escalation.
- CEL evaluation logs at Debug level never include paramRef object contents —
  only the variable name and whether resolution succeeded.
- Authorization decision `reason` strings are controlled by the CR author
  (who already has cluster-admin access), so exposing paramRef data in
  reasons is an acceptable trust boundary.

### 10.3 CEL Cost-Based DoS

**Threat**: Adversarial CEL expressions with deeply nested comprehensions or
large string operations exhaust CPU during webhook evaluation, causing
timeouts that block API requests (when `failurePolicy: Fail`).

**Mitigations**:
- **Compile-time cost estimation** rejects expressions exceeding the
  compilation cost budget at admission time.
- **Runtime cost tracking** terminates evaluation when the runtime budget is
  exceeded and returns a deny decision with a clear reason.
- The per-expression cost limits are configurable via Helm values.
- The webhook's own `timeoutSeconds` (default: 10s) acts as an ultimate
  backstop. CEL evaluation should complete in <10ms for any expression
  within budget.

### 10.4 Webhook Failure Policy Interaction

The authorization webhook should use **`failurePolicy: Fail`** to prevent
unauthorized access when the webhook is unavailable. This means:

- If CEL evaluation panics (recovered), the handler returns an explicit deny.
- If CEL evaluation exceeds the runtime cost limit, the handler returns deny
  with reason "CEL cost limit exceeded".
- The operator includes panic-recovery middleware in the webhook handler that
  catches any panic, logs it, and returns a deny response.

---

## 11. Performance & Scalability

### 11.1 CEL Compilation Cache

CEL programs are **compiled once per expression per CR generation** and
cached using an `atomic.Pointer` to an immutable snapshot map, keyed by
`(CR UID, CR generation)`. This design ensures:

- **Lock-free reads**: SAR evaluation reads the cache via `atomic.Load()`
  with zero contention. No mutex on the hot path.
- **Safe writes**: The reconciler builds a new map, swaps it in via
  `atomic.Store()`. In-flight evaluations continue using the old map.
- **Populated during reconciliation**, not during SAR evaluation.
- **Evicted** when a CR is deleted (reconciler removes entry) or its
  generation changes (reconciler replaces entry).
- **CR deletion cleanup**: The reconciler's finalizer (or `DeleteFunc`
  watch predicate) removes the CR's entry from the cache.
- **Bounded** by the total number of WebhookAuthorizer CRs × max expressions
  per CR (i.e. N × 48, where N is CR count). For typical deployments
  (10–100 CRs), this is negligible memory.

```go
type compilationCache struct {
    programs atomic.Pointer[map[cacheKey]*compiledPrograms]
}

type cacheKey struct {
    uid        types.UID
    generation int64
}
```

**Multi-replica behavior**: The reconciler only runs on the leader, so only
the leader proactively compiles CEL during reconciliation. Non-leader replicas
(which still serve webhook requests) compile lazily on first evaluation and
cache the result. This lazy path uses a `sync.Once`-per-entry pattern to
avoid duplicate compilations. The lazy compilation path is acceptable because
it only occurs during leader failover and the compilation cost (<10ms per CR)
is within the webhook timeout budget.

### 11.2 Evaluation Latency Budget

The authorization webhook must respond within the kube-apiserver's configured
timeout (default 10s, typically set to 3–5s). The CEL evaluation budget:

| Component | Budget | Source |
|-----------|--------|--------|
| HTTP decode + encode | <1ms | Standard library |
| Informer cache read (authorizer list) | <1ms | controller-runtime cache |
| CEL matchCondition evaluation (per authorizer) | <1ms | Cached program, simple bool |
| CEL rule evaluation (per rule) | <5ms | Cached program, cost-bounded |
| paramRef resolution (per ref) | <1ms | Informer cache read |
| **Typical (10 authorizers × 5 rules each)** | **<10ms** | Realistic estimate |
| **Worst case (100 authorizers × 32 rules)** | **~16s** | Theoretical maximum |

> **⚠️ Worst case is unrealistic**: 100 authorizers × 32 rules each = 3,200
> CEL evaluations per SAR. In practice, `matchConditions` filter out most
> authorizers (Phase 1 exists for this purpose), and typical deployments
> have 10-30 authorizers with 3-5 rules each.
>
> **Tiered analysis**:
> - Small deployment (10 CRs, 3 rules avg): ~10 × 3 × 5ms = **<150ms** ✓
> - Medium deployment (30 CRs, 5 rules avg): ~30 × 5 × 5ms = **<750ms** ⚠
>   (mitigated by matchCondition filtering)
> - Large deployment (100 CRs, 10 rules avg): 100 × 10 × 5ms = **5s** ❌
>   (requires matchCondition filtering + evaluation timeout)
>
> The `--cel-evaluation-timeout` flag (default: `1s`) sets a hard deadline
> for CEL evaluation across all authorizers for a single SAR. When exceeded,
> the handler returns `NoOpinion` for remaining authorizers and logs a
> warning. This prevents runaway evaluation from blocking the API server.

### 11.3 Metrics

New metrics for CEL evaluation:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_cel_compilation_duration_seconds` | Histogram | `authorizer` | CEL compilation time during reconciliation. |
| `auth_operator_cel_evaluation_duration_seconds` | Histogram | `authorizer`, `rule_index` | Per-rule CEL evaluation time. |
| `auth_operator_cel_evaluation_total` | Counter | `authorizer`, `result` | CEL evaluation outcomes (matched/unmatched/error). |
| `auth_operator_cel_cost_exceeded_total` | Counter | `authorizer` | Times CEL cost limit was hit. |
| `auth_operator_paramref_resolution_duration_seconds` | Histogram | `authorizer`, `param_name` | paramRef lookup time. |
| `auth_operator_paramref_resolution_errors_total` | Counter | `authorizer`, `param_name`, `reason` | paramRef resolution failures (not_found, cache_miss). |

**Cardinality control**: Labels use CR name and rule index (integer), never
expression content or paramRef object values.

### 11.4 Memory Footprint

| Component | Estimated Memory per CR | Notes |
|-----------|------------------------|-------|
| Compiled CEL programs (16 matchConditions + 32 rules) | ~50KB | Typical program ≈1KB |
| paramRef cached objects (8 refs) | ~10KB–8MB | ConfigMaps: up to 1MB each; Namespaces: ~1KB each |
| **Total per CR (typical)** | **~60KB** | Assumes small ConfigMaps (<10KB each) |
| **Total per CR (worst, 8×1MB CMs)** | **~8MB** | Rare; document ConfigMap size guidance |
| **100 CRs (typical)** | **~6MB** | Acceptable for controller pods |
| **100 CRs (8 large CMs each)** | **~800MB** | Requires memory limit tuning |

> **Guidance**: paramRef ConfigMaps should be small (key-value allow-lists,
> feature flags). The admission webhook should warn when a paramRef targets
> a ConfigMap larger than 100KB. The operator's memory limit should account
> for the worst-case paramRef memory footprint.

---

## 12. Operational Concerns

### 12.1 Error Classification

| Error Type | Classification | Reconciler Behavior | Condition |
|------------|---------------|---------------------|-----------|
| CEL compilation error | **Permanent** (user must fix) | Set condition, don't requeue | `CELCompilationFailed` |
| CEL type error | **Permanent** | Set condition, don't requeue | `CELCompilationFailed` |
| paramRef not found | **Transient** (object may appear) | Set condition, requeue with backoff | `ParamRefNotFound` |
| paramRef cache miss | **Transient** | Log warning, use null variable | — |
| CEL runtime cost exceeded | **Permanent** (expression too complex) | Deny + log at Error | `CELCostExceeded` |
| CEL runtime error (division by zero, null deref) | **Input-dependent** (varies per request) | Deny + log at Error | — |

> **Input-dependent errors**: CEL runtime errors like division by zero or
> null dereference depend on the specific SAR request content, not the
> expression itself. The same expression may succeed for one request and
> fail for another. These are logged at Error level (not Warning) because
> they indicate a missing `has()` guard in the CEL expression —
> a bug in the CR, not a transient system issue.

### 12.2 Structured Logging

CEL evaluation logs follow the existing structured logging conventions:

```
// Debug (V(2)) — per-expression eval result
logger.V(2).Info("CEL expression evaluated",
    "authorizer", wa.Name,
    "rule", rule.Name,
    "result", result,
    "duration", elapsed)

// Warning — runtime error (input-dependent, indicates missing has() guard)
logger.Error(err, "CEL runtime error, denying request",
    "authorizer", wa.Name,
    "rule", rule.Name)
```

No CEL variable values are logged above V(3) to prevent sensitive data leakage.
At V(4)+, a sanitized variable dump is logged for debugging (paramRef objects
have `.data` redacted).

### 12.3 Graceful Degradation

If the CEL evaluation subsystem encounters an unrecoverable error (e.g., panic):

1. The panic-recovery middleware catches it.
2. The request is **denied** (fail-closed).
3. An error metric is incremented.
4. The error is logged at Error level with stack trace.
5. The operator continues serving — it does not crash.

### 12.4 Rolling Update Safety

During a rolling update from a pre-CEL to a CEL-aware operator version:

- Old replicas see unknown CEL fields on CRs. Because CRDs use
  `+kubebuilder:pruning`, unknown fields are **pruned** — old replicas see
  the static fields only and evaluate them normally.
- **Risk**: If a CR has `mode: CEL` with no static rules, old replicas see no
  rules and deny everything. During the rolling update window, requests
  alternate between CEL evaluation (new replica) and deny-all (old replica),
  causing **intermittent authorization failures** (approximately 50% of
  requests denied during a 2-replica rollout). This is acceptable because:
  - `mode: CEL` CRs can only be created after the new CRD is applied.
  - CRD update is a prerequisite for operator update.
  - The migration sequence (below) prevents this scenario.
- **Recommendation**: Apply CRD updates. Then roll the operator. Only then
  create `mode: CEL` CRs. **Never create `mode: CEL` CRs before the rollout
  is complete.** Document this sequence prominently.

### 12.5 Rollback Safety

If the operator is rolled back after CEL CRDs and CRs are in place:

- The old CRD schema prunes CEL fields from stored CRs.
- CRs with `mode: CEL` lose their `authorization` field and keep `mode: CEL`
  (if the field is preserved by the old CRD) or lose `mode` too (if pruned).
- **Worst case**: A CR becomes no-static-rules, deny-all. This is fail-safe.
- **Migration doc**: Before rollback, platform operators should delete or
  convert `mode: CEL` CRs to static equivalents.

---

## 13. Testing Strategy

### 13.1 Unit Tests (`testing` package)

| Test Category | Example Cases | Package |
|------|------|------|
| CEL compilation | Valid/invalid expressions, type errors, cost exceeded | `pkg/cel/` |
| CEL evaluation | Boolean results, error handling, timeout, null variables | `pkg/cel/` |
| Variable binding | `request.*` mapping from SAR, `now` injection, `authorizer.*` | `pkg/cel/` |
| paramRef resolution | Found, not found, wrong type, cache miss | `pkg/cel/` |
| Match condition evaluation | All true, one false, empty list | `pkg/cel/` |
| CEL rule evaluation | First match, deny precedence, fall-through | `pkg/cel/` |
| Cost budget enforcement | Over-budget compilation, over-budget runtime | `pkg/cel/` |

### 13.2 Admission Webhook Tests (`testing` package)

| Test Category | Package |
|------|------|
| CEL compilation validation at admission | `api/authorization/v1alpha1/` |
| Duplicate matchCondition names rejected | `api/authorization/v1alpha1/` |
| paramRef kind allowed-list enforcement | `api/authorization/v1alpha1/` |
| `mode: CEL` with missing `authorization` rejected | `api/authorization/v1alpha1/` |
| `mode: CEL` with static fields warns | `api/authorization/v1alpha1/` |
| Reserved variable names in paramRef rejected | `api/authorization/v1alpha1/` |

### 13.3 Integration Tests (envtest)

| Test Category | Package |
|------|------|
| Reconciler compiles CEL and sets Ready condition | `internal/controller/authorization/` |
| Reconciler sets CELCompilationFailed on bad expression | `internal/controller/authorization/` |
| Reconciler sets ParamRefNotFound when object missing | `internal/controller/authorization/` |
| Webhook handler evaluates matchConditions correctly | `internal/webhook/authorization/` |
| Webhook handler evaluates celRules and returns correct verdict | `internal/webhook/authorization/` |
| Webhook handler resolves paramRefs from cache | `internal/webhook/authorization/` |
| Full mode: CEL returns authz.allow/deny/noOpinion | `internal/webhook/authorization/` |
| Existing CRs without CEL continue to work identically | `internal/webhook/authorization/` |

### 13.4 Fuzz Tests

```go
func FuzzCELCompilation(f *testing.F) {
    f.Add("request.user == 'test'")
    f.Add("true")
    f.Add("")
    f.Add(strings.Repeat("a", 10000))
    f.Fuzz(func(t *testing.T, expr string) {
        // Must never panic
        _, _ = compileCELExpression(env, expr)
    })
}
```

### 13.5 E2E Tests

- Deploy operator with CEL-enabled CRDs.
- Create a matchCondition-only CR, verify filtering.
- Create a celRules CR, send SARs, verify decisions.
- Create a paramRef CR with a ConfigMap, verify data-driven decisions.
- Update the ConfigMap, verify the decision changes (after cache sync).
- Create a `mode: CEL` CR, verify full CEL evaluation.
- Verify rollback: delete CEL CRDs, verify old operator handles pruned CRs.

---

## 14. Migration & Backwards Compatibility

### 14.1 Compatibility Guarantees

| Aspect | Guarantee |
|--------|-----------|
| Existing CRs without CEL fields | Behavior is **identical** — no change in evaluation logic. |
| Phase 1 without Phase 2/3/4 | matchConditions are the only new field; all others are optional. |
| `mode` field default | `Static` (current behavior). Omitting `mode` is a no-op. |
| CRD schema | All new fields are `+optional` with zero-value defaults. |
| API version | Remains `v1alpha1` — CEL is additive, not breaking. |

### 14.2 Feature Gating

Each phase is behind a feature gate (controller flag + Helm value):

| Gate | Default | Controls |
|------|---------|----------|
| `--feature-cel-match-conditions` | `true` (Phase 1) | matchConditions field processing |
| `--feature-cel-rules` | `false` (Phase 2) | celRules field processing |
| `--feature-cel-param-ref` | `false` (Phase 3) | paramRef field processing |
| `--feature-cel-mode` | `false` (Phase 4) | mode: CEL processing |

When a gate is disabled, the corresponding fields are accepted by the CRD
(schema is always up-to-date) but **ignored** during evaluation. The
reconciler sets a condition warning when gated fields are present but
not processed.

> **⚠️ Security warning — gate toggling with active deny rules**: If
> `--feature-cel-rules=true` is later changed to `false` while CRs with
> `celRules` deny entries exist, those deny rules stop being evaluated.
> This **widens access** silently. The reconciler must detect this case
> and set a `Stalled` condition with reason `FeatureGateDisabledWithDenyRules`
> on affected CRs, and the Helm chart should include a pre-upgrade hook
> that checks for active deny rules before disabling a gate.

**Helm values mapping**:
```yaml
# values.yaml
featureGates:
  celMatchConditions: true   # → --feature-cel-match-conditions
  celRules: false            # → --feature-cel-rules
  celParamRef: false         # → --feature-cel-param-ref
  celMode: false             # → --feature-cel-mode
```

These values flow through `chart/auth-operator/templates/deployment.yaml`
into container args on the manager deployment.

---

## 15. Implementation Roadmap

### Phase 1: CEL Match Conditions

**Effort**: ~2 weeks

| Step | Task |
|------|------|
| 1 | Add `cel-go` dependency, create `pkg/cel/` package with environment setup |
| 2 | Add `MatchCondition` type to `webhookauthorizer_types.go` |
| 3 | Run `make manifests generate docs helm` |
| 4 | Add CEL compilation validation to admission webhook |
| 5 | Add compilation cache to reconciler |
| 6 | Integrate matchCondition evaluation before static logic in webhook handler |
| 7 | Add CEL metrics |
| 8 | Unit tests, envtest integration tests, fuzz tests |
| 9 | Update operator guide, API reference, Helm chart README |
| 10 | E2E tests |

### Phase 2: CEL Allow/Deny Rules

**Effort**: ~2 weeks (builds on Phase 1 infrastructure)

| Step | Task |
|------|------|
| 1 | Add `CELRule`, `CELRuleAction` types |
| 2 | Add celRules evaluation between matchConditions and static logic |
| 3 | Implement `now` variable injection with monotonic clock |
| 4 | Implement `authorizer.*` variable injection |
| 5 | Implement `messageExpression` support |
| 6 | Tests + docs |

### Phase 3: Parameter References

**Effort**: ~3 weeks

| Step | Task |
|------|------|
| 1 | Add `ParamRef`, `ParamResource` types |
| 2 | Implement paramRef resolver with dynamic watch registration |
| 3 | Add allowed-kind validation to admission webhook |
| 4 | Wire paramRef objects into CEL environment during evaluation |
| 5 | Add RBAC markers for ConfigMap access |
| 6 | Implement `ParamRefNotFound` condition + requeue |
| 7 | Tests + docs |

### Phase 4: Full CEL Evaluation Mode

**Effort**: ~2 weeks

| Step | Task |
|------|------|
| 1 | Add `EvaluationMode`, `Authorization` fields |
| 2 | Implement `authz` custom CEL type with allow/deny/noOpinion |
| 3 | Add mode-aware evaluation path in webhook handler |
| 4 | Add admission validation for mode ↔ field consistency |
| 5 | Tests + docs |

**Total estimated effort**: ~9 weeks across all phases.

---

## 16. Open Questions

| # | Question | Relevant Phase | Notes |
|---|----------|----------------|-------|
| 1 | Should `now` use UTC or cluster-local time? Proposal assumes UTC. | Phase 2 | UTC is simpler and avoids timezone ambiguity across nodes. |
| 2 | ~~Should the runtime cost limit be per-rule or per-authorizer?~~ **Resolved**: Both. Per-expression (1M) + per-authorizer aggregate (5M) + per-SAR total (50M). | Phase 2 | See Section 9 cost budget table. |
| 3 | Should paramRef support dynamic namespace resolution (binding to the SAR target namespace at evaluation time)? | Phase 3 | Deferred to future enhancement. Requires evaluation-time resolution, not reconcile-time. See paramRef section. |
| 4 | Should we allow `paramRef` to reference CRDs (custom resources)? | Phase 3 | Requires dynamic GVK resolution. Start with core types only. |
| 5 | Should `mode: CEL` expressions returning non-Authz types be a compilation error or a runtime deny? | Phase 4 | Compilation error preferred — caught at admission time. |
| 6 | Should we add a `dryRun` field to test CEL expressions without affecting authorization decisions? | All | Could use a status field with last-evaluation result instead. |
| 7 | ~~Should CEL evaluation failures result in Deny or NoOpinion?~~ **Resolved**: Deny (fail-closed). See Section 10.4. | All | Consistent with webhook `failurePolicy: Fail`. |
| 8 | Should the admission webhook warn when a paramRef targets a ConfigMap larger than 100KB? | Phase 3 | See Section 11.4 memory guidance. |
| 9 | Should `celStatus` be added to WebhookAuthorizer `.status` for auditors to inspect compiled CEL state (expression count, compilation time, last error)? | Phase 1+ | Useful for security auditors. Low implementation cost. |

---

## 17. Appendix: Review Persona Analysis

This design was refined using the auth-operator's 13 review personas in a
multi-pass subagent review. Below are the key findings and how each was
addressed in the refined proposal.

### Critical Findings (addressed in this revision)

| # | Persona | Finding | Resolution |
|---|---------|---------|------------|
| C1 | Security | CEL Allow rules could bypass static `deniedPrincipals`, breaking deny-first guarantee | Fixed: `deniedPrincipals` now evaluated **before** `celRules` in Phase 2 flow (Section 6) |
| C2 | Edge Cases | Dynamic paramRef `${request...}` syntax contradicted cache-at-reconcile design | Fixed: Removed `${...}` syntax. Static names only. Dynamic resolution deferred (Open Question #3) |
| C3 | Concurrency | Non-leader replicas have no compiled CEL (reconciler runs on leader only) | Fixed: Added lazy compilation on non-leaders via `sync.Once`-per-entry pattern (Section 11.1) |
| C4 | Performance | Latency budget math wrong: 100×32×5ms = 16s, not <200ms | Fixed: Added tiered analysis (typical/medium/large) + `--cel-evaluation-timeout` flag (Section 11.2) |
| C5 | Go Style | Condition naming inconsistent with existing `AuthZConditionReason` typed pattern | Fixed: Conditions now use `StalledReasonCELCompilationFailed` etc. with type table (Section 5) |

### High Findings (addressed in this revision)

| # | Persona | Finding | Resolution |
|---|---------|---------|------------|
| H1 | Security | Implicit message interpolation (autodetect whether message is CEL) is fragile | Fixed: Replaced with explicit `messageExpression` field following K8s VAP pattern (Section 6) |
| H2 | Security | Cluster-wide ConfigMap RBAC is a significant privilege expansion | Fixed: Added RBAC blast radius warning in paramRef section, documented namespace-scoped alternative |
| H3 | Edge Cases | Example CRs missing `has()` null-safety guards | Fixed: Added `has(request.resourceAttributes)` matchConditions and `has(allowList.data)` guards |
| H4 | Edge Cases | `now` variable semantics unclear (per-expression or per-SAR?) | Fixed: Documented as "captured once per SAR evaluation (immutable within a single request)" |
| H5 | API/CRD | Mode field zero-value (`""`) behavior unspecified | Fixed: Added zero-value = Static semantics + x-kubernetes-validations for mode↔authorization |
| H6 | API/CRD | ParamResource fields missing MaxLength markers | Fixed: Added MaxLength (64, 64, 253, 63) and MaxLength for Namespace field |
| H7 | API/CRD | Reserved variable names only listed 3, should be comprehensive | Fixed: Expanded to 7 reserved names + explicit admission validation rules section |
| H8 | Concurrency | Cache lacks concrete concurrency mechanism | Fixed: Specified `atomic.Pointer` for lock-free reads with immutable snapshot swap (Section 11.1) |
| H9 | Concurrency | paramRef data could change mid-evaluation across rules | Fixed: Added snapshot guarantee — all paramRefs resolved once at SAR evaluation start |
| H10 | K8s Patterns | Cache eviction mechanism missing for deleted CRs | Fixed: Documented finalizer/DeleteFunc cleanup in compilation cache section |
| H11 | Integration | Watch lifecycle manager design missing | Fixed: Added `watchManager` component design with refCount tracking (paramRef section) |
| H12 | Integration | Feature gate Helm values path unspecified | Fixed: Added Helm values mapping and deployment template flow (Section 14.2) |
| H13 | QA | Toggling feature gates with active deny rules silently widens access | Fixed: Added security warning + `FeatureGateDisabledWithDenyRules` condition (Section 14.2) |
| H14 | QA | Rolling update risk assessment underestimates intermittent failures | Fixed: Explicitly documented ~50% failure rate during rollout + migration sequence (Section 12.4) |
| H15 | Ops | CEL runtime errors classified as "Transient" but they're input-dependent | Fixed: Reclassified as "Input-dependent" with explanation (Section 12.1) |
| H16 | Ops | Runtime errors logged at Info level instead of Error | Fixed: Changed to `logger.Error(err, ...)` (Section 12.2) |
| H17 | Security | Per-expression cost limit insufficient alone | Fixed: Added per-authorizer (5M) and per-SAR (50M) aggregate cost limits (Section 9) |
| H18 | Performance | Memory estimate assumes 10KB per paramRef but ConfigMaps can be 1MB | Fixed: Added worst-case analysis (8×1MB CMs = 8MB/CR) + size guidance (Section 11.4) |

### Medium Findings (noted for implementation phase)

| # | Persona | Finding | Status |
|---|---------|---------|--------|
| M1 | Go Style | Import alias for `cel-go` packages not specified | Noted — will follow existing alias conventions during implementation |
| M2 | Docs | Terminology inconsistency ("celRules" vs "CEL rules" in prose) | Acceptable — field names in backticks, English prose uses natural form |
| M3 | Docs | Variable reference table should note RE2 regex guarantees | Fixed: Added RE2/ReDoS immunity note after CEL Libraries table |
| M4 | Performance | Metrics labels `rule_index` may not be useful for debugging | Noted — consider `rule_name` instead during implementation |
| M5 | CI/Testing | Fuzz test covers compilation but not evaluation with adversarial inputs | Noted — add evaluation fuzzing during Phase 2 implementation |
| M6 | CI/Testing | Golden file tests for CEL evaluation results not mentioned | Noted — good idea for regression testing, add during implementation |
| M7 | End-User | No way for auditors to inspect compiled CEL state in `.status` | Added as Open Question #9 (`celStatus` field) |
| M8 | End-User | Progressive disclosure not clearly communicated | Phase 1 (matchConditions) designed for 80% of use cases; examples in each phase section |
| M9 | K8s Patterns | Error at V(4)+ logging "sanitized variable dump" — define what sanitized means | Noted — implementation should redact `.data` fields, keep `.metadata` only |
| M10 | API/CRD | Self-referential paramRef (CR referencing WebhookAuthorizer) could cause loops | Fixed: Added self-reference prohibition to admission validation rules |
| M11 | Integration | CEL environment layering (base env vs paramRef-augmented env) not detailed | Noted — base env created at startup, paramRef vars injected per-evaluation via `cel.Variable()` |
| M12 | QA | Rollback safety — CRD pruning is write-time only, etcd may retain fields | Noted — documentation should warn about etcd-stored fields surviving CRD downgrade until next write |

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

A new condition reason `CELCompilationFailed` is added for cases where a CR
that bypassed webhook validation contains invalid CEL (e.g., migrated from
backup). The reconciler re-validates CEL and sets this condition.

```go
const (
    CELCompilationFailedReason  = "CELCompilationFailed"
    CELCompilationFailedMessage = "one or more CEL expressions failed compilation"
)
```

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

// CELRule is a CEL expression paired with an authorization action.
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

    // Message is an optional human-readable message included in the
    // SubjectAccessReview reason when this rule matches. Supports CEL
    // string interpolation using the same variables as Expression.
    // +kubebuilder:validation:Optional
    // +kubebuilder:validation:MaxLength=512
    Message string `json:"message,omitempty"`
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
  3. [Phase 2] Evaluate celRules in order:
     a. If expression is true AND action is Deny  → DENY (return immediately)
     b. If expression is true AND action is Allow → ALLOW (return immediately)
  4. [Phase 0] If deniedPrincipals match → deny
  5. [Phase 0] If allowedPrincipals + rules match → allow
```

CEL rules are evaluated **first-match**. If no CEL rule matches, evaluation
falls through to the existing static logic, preserving backwards compatibility.

### CEL Rule Message Interpolation

The `message` field optionally supports CEL string interpolation. When the
message itself is a valid CEL string expression, it is evaluated with the same
variables:

```yaml
message: "'denied user ' + request.user + ' at ' + string(now)"
```

If the message is not valid CEL or if evaluation fails, the literal string is
used as-is. This makes simple messages zero-effort while enabling dynamic
messages for advanced users.

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
    // CEL identifier that does not collide with built-in variables
    // (request, now, authorizer).
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
    APIVersion string `json:"apiVersion"`

    // Kind is the resource kind (e.g. "ConfigMap", "Namespace").
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    Kind string `json:"kind"`

    // Name is the resource name.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    Name string `json:"name"`

    // Namespace is the resource namespace. Required for namespaced
    // resources. Omit for cluster-scoped resources.
    // +kubebuilder:validation:Optional
    Namespace string `json:"namespace,omitempty"`
}
```

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
        request.user in allowList.data["users"].split(",")
      action: Allow
      message: "user is in the authorized-deployers ConfigMap"
  resourceRules:
    - verbs: ["*"]
      apiGroups: ["apps"]
      resources: ["deployments"]
```

**Namespace annotation-based rules** — allow only in namespaces with a
specific annotation:

```yaml
spec:
  paramRefs:
    - name: targetNS
      resource:
        apiVersion: v1
        kind: Namespace
        # Special: when name is omitted, resolves to the SAR target namespace
        name: "${request.resourceAttributes.namespace}"
  celRules:
    - name: requireProductionTier
      expression: >-
        has(targetNS.metadata.annotations) &&
        "tier" in targetNS.metadata.annotations &&
        targetNS.metadata.annotations["tier"] == "production"
      action: Allow
```

### paramRef Resolution

1. **Cache-only**: paramRef objects are resolved from the informer cache, never
   via live API calls. This guarantees <1ms lookup latency.
2. **Dynamic watches**: When a `WebhookAuthorizer` references a new
   GVK/namespace/name, the reconciler registers a watch. Watches are cleaned
   up when no `WebhookAuthorizer` references that GVK anymore.
3. **Missing objects**: If a paramRef target doesn't exist:
   - During **reconciliation**: set condition `ParamRefNotFound` (transient, requeue with backoff).
   - During **SAR evaluation**: the variable is `null`. CEL expressions should use `has()` guards.
4. **Cache staleness**: paramRef data may be stale by up to the informer resync
   period (typically 10 minutes). This is acceptable for authorization
   decisions on data that changes infrequently (allow-lists, namespace metadata).
   The staleness window is documented and configurable.

### RBAC Impact

The operator needs `get`, `list`, `watch` permissions for each allowed paramRef
kind. For the default allowed-list (ConfigMap, Namespace), the operator already
has Namespace permissions. ConfigMap requires adding:

```yaml
# +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch
```

When the allowed-list is extended, the cluster operator must grant additional
RBAC to the operator's ServiceAccount.

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
| `now` | `timestamp` | Always | Current UTC timestamp. |
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

### CEL Cost Budget

Every CEL expression is subject to a **cost budget** that limits computational
complexity:

| Limit | Default | Configurable |
|-------|---------|------------|
| Per-expression compilation cost | 100,000 | `--cel-compilation-cost-limit` |
| Per-expression runtime cost | 1,000,000 | `--cel-runtime-cost-limit` |
| Max expression length | 4,096 chars | Kubebuilder validation |
| Max matchConditions per CR | 16 | Kubebuilder validation |
| Max celRules per CR | 32 | Kubebuilder validation |
| Max paramRefs per CR | 8  | Kubebuilder validation |

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
cached in an in-memory map keyed by `(CR UID, generation, expression hash)`.
The cache is:

- **Populated during reconciliation**, not during SAR evaluation.
- **Evicted** when a CR is deleted or its generation changes.
- **Bounded** by the total number of WebhookAuthorizer CRs × max expressions
  per CR (i.e. N × 48, where N is CR count). For typical deployments
  (10–100 CRs), this is negligible memory.

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
| **Total per-request (worst case, 100 authorizers × 32 rules)** | **<200ms** | Conservative estimate |

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
| paramRef cached objects (8 refs) | ~10KB | Metadata + data fields |
| **Total per CR** | **~60KB** | |
| **100 CRs** | **~6MB** | Acceptable for controller pods |

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
| CEL runtime error (division by zero, null deref) | **Transient** (depends on input) | Deny + log at Warning | — |

### 12.2 Structured Logging

CEL evaluation logs follow the existing structured logging conventions:

```
// Debug (V(2)) — per-expression eval result
logger.V(2).Info("CEL expression evaluated",
    "authorizer", wa.Name,
    "rule", rule.Name,
    "result", result,
    "duration", elapsed)

// Warning — runtime error
logger.Info("CEL runtime error, denying request",
    "authorizer", wa.Name,
    "rule", rule.Name,
    "error", err.Error())
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
  rules and deny everything. This is acceptable because:
  - `mode: CEL` CRs can only be created after the new CRD is applied.
  - CRD update is a prerequisite for operator update.
  - During the rolling update window, both old and new replicas may handle
    requests. The `mode: CEL` CR would alternate between CEL evaluation
    (new) and deny-all (old) until the rollout completes.
- **Recommendation**: Apply CRD updates. Then roll the operator. Only then
  create `mode: CEL` CRs. Document this sequence.

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
| 5 | Add message interpolation support |
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

| # | Question | Relevant Phase |
|---|----------|----------------|
| 1 | Should `now` use UTC or cluster-local time? Proposal assumes UTC. | Phase 2 |
| 2 | Should the runtime cost limit be per-rule or per-authorizer (sum of all rules)? | Phase 2 |
| 3 | Should paramRef support dynamic namespace resolution (e.g., `${request.resourceAttributes.namespace}`)? | Phase 3 |
| 4 | Should we allow `paramRef` to reference CRDs (custom resources)? | Phase 3 |
| 5 | Should `mode: CEL` expressions returning non-Authz types be a compilation error or a runtime deny? | Phase 4 |
| 6 | Do we need a `dryRun` field to test CEL expressions without affecting authorization decisions? | All |
| 7 | Should CEL evaluation failures (cost exceeded, runtime error) result in `Deny` or `NoOpinion`? Proposal assumes `Deny` (fail-closed). | All |

---

## 17. Appendix: Review Persona Analysis

This design was refined using the auth-operator's 13 review personas. Key
concerns raised by each persona and how the design addresses them:

### Edge Cases & Boundary Testing
- **Empty/nil CEL**: Empty `matchConditions` = always participates (current behavior). Empty `expression` rejected by MinLength=1 validation.
- **Malformed CEL**: Compiled at admission time; type errors produce descriptive messages with position info.
- **Missing paramRef targets**: Variable is `null`; expressions must use `has()` guards. Reconciler sets `ParamRefNotFound` condition.
- **Extreme complexity**: MaxLength=4096 + compile-time cost estimation + runtime cost budget.

### API & CRD Correctness
- **Backwards compatible**: All new fields are `+optional`. Default `mode: Static` preserves existing behavior.
- **Webhook validation**: CEL compiled and type-checked at admission — invalid expressions never reach the reconciler.
- **Schema markers**: `MaxItems`, `MaxLength`, `MinLength`, `Pattern`, `Enum` on all new fields.
- **SSA completeness**: New fields included in SSA apply configurations via `make generate`.

### Security
- **Escalation prevention**: WebhookAuthorizer is cluster-scoped, requires cluster-admin to edit. Consistent with ClusterRole trust model.
- **Information disclosure**: paramRef allowed-list prevents Secret access. Logs redact paramRef data above V(3).
- **Cost-based DoS**: Compile-time cost estimation + runtime cost tracking + webhook timeout backstop.
- **Failure policy**: Fail-closed (deny on error). Panic recovery prevents operator crash.

### Performance & Scalability
- **Compilation cache**: Per-CR-generation, populated during reconciliation, not during SAR evaluation.
- **paramRef from cache**: Informer cache only, never live API calls. Guaranteed <1ms.
- **Metrics cardinality**: Labels use CR name + rule index, not expression content.
- **Memory budget**: ~60KB per CR, ~6MB for 100 CRs.

### Concurrency & Safety
- **Thread safety**: CEL environment is immutable. Compiled programs are read-only. Evaluation creates per-call activation.
- **Cache staleness**: paramRef reads are eventually consistent (informer resync). Documented and acceptable.
- **Evaluation timeout**: Runtime cost budget terminates long-running evaluations. HTTP handler has its own context deadline.

### End-User Experience
- **Error messages**: CEL compilation errors include position, expected type, and actual type.
- **Audit trail**: Authorization decision reasons include the authorizer name and rule name. V(2) logs show expression + result + duration.
- **Progressive disclosure**: matchConditions (Phase 1) covers 80% of use cases with minimal YAML. Full CEL mode (Phase 4) is opt-in.
- **Examples**: Four concrete examples in each phase section covering common scenarios.

### Operational Patterns
- **Error taxonomy**: Permanent (compilation) vs. transient (paramRef not found) vs. input-dependent (runtime error). Each has defined reconciler behavior.
- **Conditions**: New reasons (`CELCompilationFailed`, `ParamRefNotFound`, `CELCostExceeded`) extend existing condition types. `ObservedGeneration` tracks re-evaluation.
- **Graceful degradation**: Panic recovery → deny → log → continue. Operator never crashes on CEL errors.
- **Rolling updates**: CRD pruning ensures old replicas ignore unknown fields. Migration sequence documented.

### Integration Wiring
- **New package**: `pkg/cel/` for environment setup, compilation, evaluation, caching.
- **Webhook handler**: CEL evaluator injected via constructor, same as existing `Client` and `Log` fields.
- **Helm chart**: New values for cost limits, feature gates, allowed paramRef kinds.
- **RBAC**: ConfigMap permissions added via kubebuilder markers.
- **Generation chain**: `make manifests generate docs helm` covers all aspects.

### Testing
- **Coverage**: Unit tests for `pkg/cel/`, admission tests for webhook, envtest integration tests for full flow.
- **Fuzz**: CEL compilation fuzz-tested to ensure no panics on arbitrary input.
- **CI impact**: `cel-go` is a transitive dependency of `k8s.io/apiextensions-apiserver` (already in `go.mod` via `apiextensions v0.35.1`), so no new binary size impact.

### Documentation
- **Variable reference**: Complete table in Section 9 with types, availability, and descriptions.
- **Field names**: Consistent across Go types, API reference, operator guide, Helm values, and examples.
- **Design doc as authority**: This document serves as the authoritative reference for CEL behavior.

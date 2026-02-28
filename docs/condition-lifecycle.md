<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Condition Lifecycle

This document describes every condition type used by auth-operator CRDs,
when each condition is set, and what state transitions to expect.

---

## kstatus Standard Conditions

The operator follows [kstatus](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md)
conventions. Three top-level conditions drive tooling compatibility (e.g., `kubectl wait`,
Argo CD health checks):

### Ready

Indicates whether the resource's actual state matches its desired state.

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `Reconciled` | All managed resources are up-to-date |
| `False` | `Reconciling` | Reconciliation is in progress |
| `False` | `Failed` | An error prevented reconciliation |

**Lifecycle**: Set to `False` at the start of every reconciliation
(`MarkReconciling`). Promoted to `True` at the end if all steps succeed
(`MarkReady`). Remains `False` if any step fails (`MarkStalled` or
`MarkNotReady`).

### Reconciling

Abnormal-true condition — **present and True** when the controller is actively
working; **absent** when idle.

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `Progressing` | Controller is reconciling the resource |
| *(deleted)* | — | Reconciliation complete or stalled |

**Lifecycle**: Set via `MarkReconciling()` at the start of reconciliation.
Deleted when `MarkReady()` or `MarkStalled()` is called.

### Stalled

Abnormal-true condition — **present and True** when the controller has
encountered a persistent error; **absent** when healthy.

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `Error` | A reconciliation error occurred |
| `True` | `MissingDependency` | A required dependency is missing |
| *(deleted)* | — | Reconciliation succeeded or progressing |

**Lifecycle**: Set via `MarkStalled()` on unrecoverable errors. Deleted when
`MarkReady()` or `MarkReconciling()` is called.

### State Machine

```
    ┌─────────────────────────────────────┐
    │         Reconcile triggered          │
    └───────────────┬─────────────────────┘
                    ▼
         ┌──────────────────┐
         │   Reconciling    │  Ready=False, Reconciling=True
         └────────┬─────────┘
                  │
           ┌──────┴──────┐
           ▼             ▼
    ┌────────────┐ ┌───────────┐
    │   Ready    │ │  Stalled  │  Ready=False, Stalled=True
    │ Ready=True │ │           │
    └────────────┘ └───────────┘
```

`MarkReady`, `MarkReconciling`, and `MarkStalled` are **mutually exclusive** —
each one clears the other abnormal-true conditions.

---

## Domain-Specific Conditions

These conditions report progress through individual reconciliation steps.
They use the standard `True`/`False` status pattern.

### Finalizer

Set when the operator adds its finalizer to a CRD resource.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `OrphanPrevention` | Set finalizer to prevent orphaned resources |

**Applies to**: RoleDefinition, BindDefinition

### Deleted

Set when the operator detects a deletion timestamp and begins cleanup.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `TriggeredDelete` | Reconciling deletion request |

**Applies to**: RoleDefinition, BindDefinition

### Created

Set when the operator applies managed resources for a new CRD object.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `TriggeredCreate` | Reconciling creation request |

**Applies to**: RoleDefinition, BindDefinition

### Updated

Set when the operator detects a spec change (generation bump) and re-applies.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `TriggeredUpdate` | Reconciling update request |

**Applies to**: RoleDefinition, BindDefinition

### OwnerRef

Set when owner references are established on child resources.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `ResourceOwnership` | Set owner reference to child resource |

**Applies to**: BindDefinition (ServiceAccount ownership)

---

## RoleDefinition-Specific Conditions

### APIGroupDiscovered

Set after the operator fetches the cluster's API group list.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Discovery` | Fetching all available API groups |

### ResourceDiscovered

Set after the operator fetches API resources for each group.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Discovery` | Fetching all available API resources |

### APIGroupFiltered

Set after applying the denylist filter to API groups.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Filtering` | Filtering API groups via denylist |

### ResourceFiltered

Set after applying the denylist filter to individual resources.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Filtering` | Filtering API resources via denylist |

### Reconciliation Sequence (RoleDefinition)

```
Finalizer → APIGroupDiscovered → ResourceDiscovered →
APIGroupFiltered → ResourceFiltered → Created/Updated → Ready
```

---

## BindDefinition-Specific Conditions

### RoleRefsValid

Reports whether all referenced ClusterRoles and Roles exist in the cluster.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `RoleRefValidation` | All referenced roles exist |
| `False` | `RoleRefNotFound` | One or more referenced roles do not exist |

**Behavior**: When `False`, the operator still creates bindings but marks the
resource as not fully healthy. This allows partial progress while surfacing
the missing dependency.

### Reconciliation Sequence (BindDefinition)

```
Finalizer → RoleRefsValid → OwnerRef (if SAs) →
Created/Updated → Ready
```

---

## BindDefinition — Namespace Termination Conditions

These conditions are set on **RoleBinding** resources managed by the
RoleBinding Terminator controller, not on the BindDefinition itself.

### AuthOperatorNamespaceTerminationBlocked

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `AuthOperatorPreventedTermination` | Auth-operator blocked role bindings termination due to remaining resources |
| `False` | `AuthOperatorResourcesCleanedUp` | All role bindings created by auth-operator have been cleaned up |

**Purpose**: Prevents namespace deletion from removing RoleBindings before
the operator has cleaned up dependent resources.

---

## WebhookAuthorizer-Specific Conditions

The WebhookAuthorizer controller (see issue #49) uses these conditions to
report the health and validity of each WebhookAuthorizer resource.

### Ready

Overall readiness of the WebhookAuthorizer.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `AuthorizerReady` | All rules are valid and the authorizer is actively processing requests |
| `False` | `InvalidRules` | One or more resource/non-resource rules are malformed: *\<detail\>* |
| `False` | `InvalidNamespaceSelector` | The namespace selector cannot be parsed: *\<detail\>* |
| `False` | `NoPrincipals` | Neither allowedPrincipals nor deniedPrincipals are defined |

### RulesValid

Validation status of resource and non-resource rules.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `AllRulesValid` | All resourceRules and nonResourceRules are syntactically valid |
| `False` | `InvalidResourceRule` | A resourceRule contains invalid API groups, resources, or verbs: *\<detail\>* |
| `False` | `InvalidNonResourceRule` | A nonResourceRule contains invalid paths or verbs: *\<detail\>* |

### NamespaceSelectorValid

Status of the namespace selector.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `SelectorValid` | Namespace selector is parseable and matches namespaces |
| `True` | `SelectorEmpty` | No namespace selector defined (matches all namespaces) |
| `False` | `SelectorInvalid` | Namespace selector cannot be parsed: *\<detail\>* |

### PrincipalConfigured

Status of principal configuration.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `PrincipalsConfigured` | AllowedPrincipals and/or DeniedPrincipals are defined |
| `False` | `NoPrincipalsConfigured` | No principals defined — authorizer will never match |
| `Unknown` | `PrincipalOverlap` | A principal appears in both allowed and denied lists: *\<detail\>* |

### Reconciliation Sequence (WebhookAuthorizer)

```
NamespaceSelectorValid → RulesValid → PrincipalConfigured → Ready
```

---

## Condition Utilities

The `pkg/conditions` package provides helpers for managing conditions:

| Function | Effect |
|----------|--------|
| `MarkReady(obj, gen, reason, msg)` | `Ready=True`, deletes `Reconciling` and `Stalled` |
| `MarkNotReady(obj, gen, reason, msg)` | `Ready=False` |
| `MarkReconciling(obj, gen, reason, msg)` | `Reconciling=True`, `Ready=False`, deletes `Stalled` |
| `MarkStalled(obj, gen, reason, msg)` | `Stalled=True`, `Ready=False`, deletes `Reconciling` |
| `Set(obj, condition)` | Sets an individual condition (preserves `LastTransitionTime` if status unchanged) |
| `Delete(obj, type)` | Removes a condition by type |
| `Get(obj, type)` | Retrieves a condition by type |
| `IsReady(obj)` / `IsStalled(obj)` / `IsReconciling(obj)` | Boolean checks |

### ObservedGeneration

Every condition carries `ObservedGeneration` matching the resource's
`metadata.generation` at the time the condition was evaluated. This allows
clients to detect stale conditions after a spec change.

Status objects also carry a top-level `ObservedGeneration` field for kstatus
compatibility.

---

## Observing Conditions

```bash
# Check if a RoleDefinition is ready
kubectl get roledefinition <name> -o jsonpath='{.status.conditions}'

# Wait for ready state
kubectl wait roledefinition <name> --for=condition=Ready --timeout=30s

# Check for stalled resources
kubectl get roledefinitions -o json | \
  jq '.items[] | select(.status.conditions[]? | select(.type=="Stalled" and .status=="True")) | .metadata.name'
```

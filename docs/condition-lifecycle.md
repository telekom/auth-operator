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
| `Unknown` | `RoleRefValidationSkipped` | Role reference validation skipped (missing-role-policy=ignore) |

**Behavior**: When `False` and the `missing-role-policy` annotation is `warn`
(the default), the operator still creates bindings but marks the resource as
not fully healthy. This allows partial progress while surfacing the missing
dependency. When the policy is set to `error`, reconciliation is blocked and
no bindings are created until the missing roles are resolved. When the policy
is set to `ignore`, validation is skipped entirely and the condition is set
to `Unknown`.

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

The WebhookAuthorizer controller reports reconciliation progress with the
standard `Reconciling`, `Ready`, and `Stalled` conditions. It also updates
`status.observedGeneration` and `status.authorizerConfigured`.

The admission webhook rejects malformed rules and principal-free specs before
they are reconciled. Runtime status is therefore focused on whether the
controller accepted the spec and whether namespace selector validation
succeeded.

The API package still exports legacy WebhookAuthorizer condition constants such
as `RulesValid`, `NamespaceSelectorValid`, and `PrincipalConfigured` for
compatibility. The current controller does not set those conditions.

### Reconciling

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Progressing` | Controller is reconciling the resource |

Set before validation and cleared when the resource becomes `Ready` or
`Stalled`.

### Ready

Overall readiness of the WebhookAuthorizer.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Reconciled` | Resource is fully reconciled |
| `False` | `Progressing` | Controller is reconciling the resource |
| `False` | `Error` | Error during reconciliation: check operator logs for details |

When `Ready=True`, the controller also sets
`status.authorizerConfigured=true`.

### Stalled

Permanent reconciliation failure. The current controller uses this when the
namespace selector cannot be parsed.

| Status | Reason | Message |
|--------|--------|---------|
| `True` | `Error` | Error during reconciliation: check operator logs for details |

When `Stalled=True`, the controller sets `status.authorizerConfigured=false`
and waits for a spec change before reconciling again.

### authorizerConfigured

`status.authorizerConfigured` is a compact readiness flag for scripts and
JSONPath checks:

| Value | Meaning |
|-------|---------|
| `true` | The controller reconciled the WebhookAuthorizer and marked it `Ready=True` |
| `false` or unset | Reconciliation has not completed or the resource is stalled |

### Reconciliation Sequence

```
Reconciling -> Ready
Reconciling -> Stalled
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

---

## Operational Guidance

### Status and Admission Signals

| Signal | Meaning | Recommended Action |
|--------|---------|-------------------|
| `Ready=False` | Resource not fully reconciled | Check `Stalled` and `Reconciling` conditions for details |
| `RoleRefsValid=False` | Referenced roles missing | Create the missing ClusterRole/Role, or remove the reference from the BindDefinition |
| `Stalled=True` | WebhookAuthorizer namespace selector failed validation during reconciliation | Fix the label selector expression in the spec |
| Admission rejection | Invalid WebhookAuthorizer rules or missing principals | Fix the rejected field from the API error and apply the resource again |

### What to Do When a Condition Is True (Abnormal-True)

| Condition | When True | Recommended Action |
|-----------|----------|-------------------|
| `Stalled` | Persistent error | Read the condition's `message` field for error details; fix the root cause and the operator will retry |
| `Reconciling` | Active reconciliation | Normal — wait for completion; if stuck for >5 minutes, check controller logs |

### Monitoring Conditions via Metrics

The operator exposes a `auth_operator_reconcile_total` counter with a `result`
label. Possible values are `success`, `error`, `requeue`, `skipped`, `finalized`,
and `degraded`. A rising `error` count correlates with `Stalled=True` conditions:

```bash
curl -s http://localhost:8080/metrics | grep auth_operator_reconcile_total
```

### Condition Staleness Check

If `status.observedGeneration` is **less than** `metadata.generation`,
the status is stale — the resource has been modified since the last
reconciliation. Wait for the controller to re-evaluate:

```bash
kubectl get roledefinition <name> -o json | \
  jq '{generation: .metadata.generation, observedGeneration: .status.observedGeneration}'
```

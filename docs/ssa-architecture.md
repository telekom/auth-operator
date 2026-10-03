<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Server-Side Apply Architecture

This document describes how the auth-operator uses Kubernetes
[Server-Side Apply (SSA)](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
for resource management, status updates, and conflict resolution.

---

## Overview

The auth-operator manages RBAC resources (ClusterRoles, Roles, ClusterRoleBindings,
RoleBindings, ServiceAccounts) entirely through SSA. This replaces traditional
Create/Update workflows with a declarative, field-ownership-aware model.

Three distinct write patterns are used, each chosen for a specific purpose:

| Operation | API Method | Field Owner | Conflict Strategy |
|-----------|-----------|-------------|-------------------|
| Resource management | `client.Apply()` | `auth-operator` | `ForceOwnership` |
| Status updates | `SubResource("status").Apply()` | `auth-operator` | `ForceOwnership` |
| Finalizer add/remove | `client.Patch()` (MergePatch) | N/A (strategic merge) | Optimistic lock |

---

## Resource Management (SSA with ForceOwnership)

All RBAC resources are applied using typed `ApplyConfiguration` objects
from `client-go` and the `client.Apply()` method.

### How It Works

1. Build an `ApplyConfiguration` (e.g., `rbacv1ac.ClusterRole("name")`)
2. Populate only the fields the operator manages
3. Call `client.Apply()` with `client.FieldOwner("auth-operator")` and
   `client.ForceOwnership`

```go
// pkg/ssa/ssa.go — simplified example
ac := rbacv1ac.ClusterRole(name).WithLabels(labels)
for _, rule := range rules {
    ac.WithRules(PolicyRuleFrom(&rule))
}
return c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
```

### Managed Resources

| Resource | Builder | Applier |
|----------|---------|---------|
| ClusterRole | `ClusterRoleWithLabelsAndRules()` | `ApplyClusterRole()` |
| Role | `RoleWithLabelsAndRules()` | `ApplyRole()` |
| ClusterRoleBinding | `ClusterRoleBindingWithSubjectsAndRoleRef()` | `ApplyClusterRoleBinding()` |
| RoleBinding | `RoleBindingWithSubjectsAndRoleRef()` | `ApplyRoleBinding()` |
| ServiceAccount | `ServiceAccountWith()` | `ApplyServiceAccount()` |

All builders and appliers live in `pkg/ssa/ssa.go`.

### Why ForceOwnership

`ForceOwnership` means the operator always wins field conflicts. This is safe
because:

- The operator is the **sole intended manager** of these generated RBAC
  resources
- Resources are derived from CRD specs — external edits would be overwritten
  on the next reconciliation anyway
- Without `ForceOwnership`, a manual `kubectl apply` on a managed resource
  would cause the operator to fail with a conflict error until the conflict
  is manually resolved

### What SSA Provides Over Create/Update

- **Partial updates**: Only fields included in the ApplyConfiguration are
  claimed and set; other fields are left untouched
- **No read-modify-write race**: No need to `Get` before writing; the API
  server merges declaratively
- **Automatic cleanup**: Fields the operator previously owned but no longer
  includes are automatically released
- **Drift detection**: The API server tracks exactly which fields each manager
  owns; `kubectl` and the operator never interfere with each other's fields

---

## Status Updates (SSA on SubResource)

Status is updated using `SubResource("status").Apply()` with typed
ApplyConfigurations generated for each CRD.

### How It Works

1. Convert the in-memory status object to an `*ApplyConfiguration` using
   `StatusFrom()` converters
2. Verify the parent object exists (status subresource requires it)
3. Apply using `SubResource("status").Apply()` with `ForceOwnership`

```go
// api/authorization/v1alpha1/applyconfiguration/ssa/ssa.go — simplified
applyConfig := ac.RoleDefinition(rd.Name, rd.Namespace).
    WithStatus(RoleDefinitionStatusFrom(&rd.Status))

return c.SubResource("status").Apply(ctx, applyConfig,
    client.FieldOwner(FieldOwner), client.ForceOwnership)
```

### Error Wrapping

Each status applier (`ApplyRoleDefinitionStatus`, `ApplyBindDefinitionStatus`,
`ApplyWebhookAuthorizerStatus`) calls `SubResource("status").Apply()` directly
and wraps any error with a descriptive message including the object name. If the
parent object no longer exists, the API server returns `NotFound`, which the
caller can handle — no pre-flight `Get` is needed, avoiding TOCTOU races.

### Status ApplyConfiguration Types

Generated ApplyConfiguration types live in:

```
api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1/
```

Each CRD has `*StatusApplyConfiguration` types mirroring the status struct,
with `With*()` builder methods for SSA compatibility.

---

## Skip-if-Unchanged Apply (Generic `Applier`)

Sending an SSA apply for every managed object on every reconcile produces
thousands of no-op PATCH requests in large clusters. `pkg/ssa` therefore reads
the live object (normally from the informer cache) and only applies when it
must. The decision is implemented once by the generic `ssa.Applier` and
`ssa.StatusApplier` types; the exported `PatchApply*` functions
(`PatchApplyClusterRole`, `PatchApplyRoleBinding`, `PatchApplyServiceAccount`,
`PatchApply<CRD>Status`, ...) are thin wrappers over predefined descriptors.

`pkg/ssa` imports only the Go standard library, apimachinery, client-go and
controller-runtime, so other operators (for example
[k8s-breakglass](https://github.com/telekom/k8s-breakglass)) can reuse it.

### Apply Decision

For a descriptor `Applier[T, AC]`, `PatchApply(ctx, c, ac, alwaysApply, opts...)`:

1. Validates the name (and namespace when `Namespaced`) and requires a
   `client.FieldOwner` in `opts`.
2. Gets the live object; if it is missing, applies and returns `created`.
3. Optionally prunes stale labels selected by `ShouldPruneLabel` with a
   JSON merge patch (used for labels a previous field manager owned).
4. Skips (`skipped`, no API call) only when all of the following hold:
   - `Matches(existing, ac)` reports that every desired value is present,
   - `alwaysApply` is false,
   - `ac` carries no `uid`/`resourceVersion` precondition,
   - the `Ownership` policy allows it: the field manager's owned fields
     (`Extract(existing, manager)`) must equal the desired fields for forced
     applies, and must be a subset of them for unforced applies (otherwise
     SSA still needs to prune a field). `OwnershipExactWhenForced` skips
     unforced applies on value equality alone. Dry-run applies that check
     ownership are never skipped.
5. Otherwise applies (through `PrepareApply` when set) and returns `patched`.

| Descriptor | Ownership | Hooks |
|------------|-----------|-------|
| ClusterRole | `OwnershipExactWhenForced` | RBAC field normalization, optional label pruning |
| Role | `OwnershipExactWhenForced` | RBAC field normalization |
| ClusterRoleBinding / RoleBinding | `OwnershipExactOrSubset` | RBAC field normalization, subject/ownerRef canonicalization before apply |
| ServiceAccount | `OwnershipExactOrSubset` | create conflicts require a requeue |

### Defining a Descriptor in Another Operator

```go
import (
    corev1 "k8s.io/api/core/v1"
    corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
    "github.com/telekom/auth-operator/pkg/ssa"
)

var configMapApplier = ssa.Applier[*corev1.ConfigMap, *corev1ac.ConfigMapApplyConfiguration]{
    Kind:       "ConfigMap",
    Namespaced: true,
    New:        func() *corev1.ConfigMap { return &corev1.ConfigMap{} },
    Matches: func(existing *corev1.ConfigMap, desired *corev1ac.ConfigMapApplyConfiguration) bool {
        return maps.Equal(existing.Data, desired.Data)
    },
    Extract: corev1ac.ExtractConfigMap,
    // Ownership defaults to OwnershipExactOrSubset.
}

result, err := configMapApplier.PatchApply(ctx, c, desiredAC, false,
    client.FieldOwner("my-operator"), client.ForceOwnership)
```

`Matches` must compare only the fields the descriptor declares; `Extract` is
the client-go or applyconfiguration-gen `Extract<Kind>` function. Build a fresh
apply configuration for every call: `client.Apply` writes the server response
(including `resourceVersion` and `uid`) back into it, which `PatchApply` would
then treat as a precondition.

Status subresources use `ssa.StatusApplier[T, AC]` with `New`, `Equal`,
`ApplyConfiguration` and `FieldOwner` (and an optional `BeforeApply` hook).
It skips the apply when `Equal(cached, desired)` holds and otherwise applies
the status with `ForceOwnership`. `ssa.ManagedBy(obj, manager, operation)`
reports whether a field manager has a `managedFields` entry for an operation.

A runnable example lives in `pkg/ssa/example_test.go`.

---

## Finalizer Management (MergePatch with Optimistic Lock)

Finalizers are **not** managed via SSA. Instead, they use `client.Patch()` with
a strategic MergePatch and optimistic locking.

### How It Works

```go
old := bindDefinition.DeepCopy()
controllerutil.AddFinalizer(bindDefinition, BindDefinitionFinalizer)
err := r.client.Patch(ctx, bindDefinition,
    client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{}))
```

### Why Not SSA for Finalizers

Finalizers live in `metadata.finalizers`, which is shared between multiple
actors (the operator, other controllers, the garbage collector). Using SSA
with `ForceOwnership` on finalizers would **remove** finalizers set by other
managers, since SSA treats the entire list as a managed field set.

MergePatch with optimistic locking is the standard Kubernetes pattern for
finalizers because it:

- **Appends/removes** individual finalizer entries without claiming ownership
  of the entire list
- **Detects concurrent modifications** via `resourceVersion` (optimistic lock)
  and retries automatically via controller-runtime's queue
- Allows multiple controllers to each manage their own finalizer entry

### Finalizer Locations

| Controller | Finalizer | File |
|-----------|-----------|------|
| RoleDefinition | `roledefinition.authorization.t-caas.telekom.com/finalizer` | `roledefinition_helpers.go` (2 sites) |
| BindDefinition | `binddefinition.authorization.t-caas.telekom.com/finalizer` | `binddefinition_controller.go` (2 sites) |
| RoleBinding Terminator | `rolebinding.authorization.t-caas.telekom.com/finalizer` | `rolebinding_terminator_controller.go` (3 sites) |

---

## Field Ownership Summary

The operator uses a single field owner identity: `"auth-operator"`.

```go
const FieldOwner = "auth-operator" // pkg/ssa/ssa.go
```

### What the Operator Owns

| Field Path | Resource | Owned? |
|-----------|----------|--------|
| `metadata.labels` | All managed RBAC | Yes (operator-set labels only) |
| `metadata.ownerReferences` | ServiceAccounts | Yes |
| `rules` | ClusterRole, Role | Yes |
| `subjects` | ClusterRoleBinding, RoleBinding | Yes |
| `roleRef` | ClusterRoleBinding, RoleBinding | Yes |
| `automountServiceAccountToken` | ServiceAccount | Yes |
| `status.*` | CRD objects | Yes (via status subresource) |
| `metadata.finalizers` | CRD objects, RoleBindings | **No** (MergePatch) |

### Inspecting Field Ownership

Use `kubectl` to see which fields each manager owns:

```bash
kubectl get clusterrole <name> -o json | \
  jq '.metadata.managedFields[] | select(.manager == "auth-operator")'
```

---

## Error Handling

Every error in the reconciliation loop is reflected in the resource's status
conditions. The operator never silently drops errors.

| Error Type | Condition Set | Pattern |
|-----------|--------------|---------|
| API call failure | `Stalled=True`, `Ready=False` | `MarkStalled()` |
| Missing dependency (role ref) | `RoleRefsValid=False` | `MarkNotReady()` |
| Finalizer patch conflict | Requeue (automatic) | Controller-runtime retry |
| Status apply on deleted object | Graceful handling | Apply returns NotFound, wrapped with context |

---

## Further Reading

- [Kubernetes SSA Documentation](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
- [KEP-3325: SSA for Status](https://github.com/kubernetes/enhancements/issues/3325)
- [kstatus Conventions](https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md)

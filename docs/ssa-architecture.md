<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Server-Side Apply Architecture

This document describes how the auth-operator uses Kubernetes
[Server-Side Apply (SSA)](https://kubernetes.io/docs/reference/using-api/server-side-apply/)
for resource management, status updates, and conflict resolution.

---

## Migration characterization coverage

The `ssa-migration` Ginkgo label selects real-apiserver characterization tests
in `pkg/ssa/migration_envtest_test.go` and
`internal/controller/authorization/ssa_migration_envtest_test.go`. Run from the
repository root with an **absolute** `KUBEBUILDER_ASSETS` path:

```bash
go test ./pkg/ssa ./internal/controller/authorization \
  -run 'TestSSA|TestControllers' -ginkgo.label-filter=ssa-migration -count=1
```

Together with the existing SSA/controller suites and the Kyverno binding-update
storm guard in `test/e2e/creator_tracking_kyverno_e2e_test.go`, these tests pin
apply-call counts, field-manager ownership, drift repair, label preservation and
pruning, status no-ops and empty-list cleanup, and optimistic-lock finalizer and
ServiceAccount metadata patches under actual concurrent API-server writes.
Controller status-helper entry points also run against the real status
subresource, including restricted policy-violation callbacks, degraded binding
conditions, stalled conditions, nonfatal status applies and deletion failures.
Restricted RBAC and ServiceAccount paths intentionally **always apply** to
re-evaluate authorization; ordinary BindDefinition and RoleDefinition paths
can skip unchanged values. ServiceAccount applies are unforced: a competing
manager's different token setting remains a conflict, not a forced repair.
Restricted ClusterRole reconciliation deliberately normalizes all labels,
unlike ordinary roles/bindings which preserve unrelated foreign labels.

The tests characterize the remaining helper gaps, not desired safety
guarantees: ServiceAccount no-op skipping bypasses UID/resourceVersion
preconditions, and ServiceAccount wrappers have no dry-run option. Ordinary
Role/ClusterRole wrappers still skip unchanged **unforced** dry-runs when label
pruning is not involved; changed or forced dry-runs reach the server.
ClusterRole label pruning now forwards dry-run options to its preliminary merge
patch, so dry-run requests do not persist the label deletion. No controller
currently supplies a pruning dry-run.

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

## Library-backed skip-if-unchanged apply

Sending an SSA apply for every managed object on every reconcile produces
thousands of no-op PATCH requests in large clusters. `pkg/ssa` therefore reads
the live object (normally from the informer cache) and only applies when it
must. The shared gate is provided by
[`github.com/telekom/t-caas-go-library/pkg/ssa`](https://github.com/telekom/t-caas-go-library/tree/v0.1.0/pkg/ssa)
at **v0.1.0**, not by a second generic engine in auth-operator.
The exported `PatchApply*` functions
(`PatchApplyClusterRole`, `PatchApplyRoleBinding`, `PatchApplyServiceAccount`,
`PatchApply<CRD>Status`, ...) retain their signatures and result constants.

RBAC comparators, subject/owner-reference canonicalization, field owners,
label cleanup and CR-specific status builders remain local. See the library's
[upstream-first guide](https://github.com/telekom/t-caas-go-library/blob/main/docs/upstream-libraries.md)
for alternatives and limits.

### Apply Decision

The library's `Applier[T, AC]` validates the identity and field manager, reads
the object, and skips only when values match and ownership permits it. Forced
applies require exact owned-field equality; unforced applies require the owned
fields to be a subset of the desired fields, so omitted owned fields are pruned.
Dry-runs and UID/resourceVersion preconditions normally reach the API server.
`alwaysApply` bypasses the gate at restricted authorization boundaries.

AO retains the phase-1 characterized policies, with one explicit safety fix
for ClusterRole label-pruning dry-runs:

- Ordinary Role/ClusterRole unforced equal requests skip, including dry-runs
  when label pruning is not involved.
- Ordinary ServiceAccount no-op checks ignore UID/resourceVersion preconditions.
  A comparison clone omits them, but actual writes send the original configuration
  and therefore still enforce them. Always variants do not use this adapter.
- ClusterRole label pruning remains an AO merge patch, but forwards dry-run
  options and never converts a persistent apply conflict into apparent
  convergence based only on matching values.
- Missing-ServiceAccount create conflicts still require fresh ownership
  classification on the next reconcile.

Build fresh configurations for each reconcile: native `client.Apply` can write
server response metadata into them. Cached gates cannot observe admission-policy
or permission changes; the restricted callers always apply.

Status subresources use library `StatusApplier[T, AC]` with `New`, `Equal`,
`ApplyConfiguration` and `FieldOwner` (and an optional `BeforeApply` hook).
It skips the apply when `Equal(cached, desired)` holds and otherwise applies
the status with `ForceOwnership`. AO retains the empty-list status merge patches;
the Namespace terminator calls library `ApplyStatus` unconditionally when its
condition exists.

---

## Finalizer Management (MergePatch with Optimistic Lock)

Finalizers are **not** managed via SSA. All ten add/remove sites use
library `pkg/patch.EnsureFinalizer` / `RemoveFinalizer`, which delegate to
native JSON merge patches with optimistic locking.

### How It Works

```go
_, err := librarypatch.EnsureFinalizer(ctx, r.client,
    bindDefinition, authorizationv1alpha1.BindDefinitionFinalizer)
```

Conflicts retain each controller's existing error/requeue behavior. The library
restores in-memory finalizers after failed writes and omits already-satisfied
finalizer patches; server-side mutation and foreign-finalizer preservation stay
unchanged. Existing reader selection, retry backoff and consumer mutations
remain explicit for `pkg/patch.Object` (ServiceAccount
metadata) and `pkg/patch.Status` (generated-ServiceAccount status cleanup).
Status cleanup now also treats a parent deleted between its read and patch
as successful, as it already did for a missing parent at read time; an adoption
envtest exercises that real-server race.
Single-shot external-SA tracking and empty RBAC/status array patches keep their
native merge-patch APIs and existing semantics.

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
| RoleBinding Terminator | `rolebinding.authorization.t-caas.telekom.com/finalizer` | `rolebinding_terminator_controller.go` (2 sites) |
| RestrictedRoleDefinition | `restrictedroledefinition.authorization.t-caas.telekom.com/finalizer` | `restrictedroledefinition_controller.go` (2 sites) |
| RestrictedBindDefinition | `restrictedbinddefinition.authorization.t-caas.telekom.com/finalizer` | `restrictedbinddefinition_controller.go` (2 sites) |

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

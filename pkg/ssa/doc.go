// Package ssa provides Server-Side Apply helpers for constructing and applying
// RBAC and core resource ApplyConfiguration objects (ClusterRoles, Roles,
// RoleBindings, ServiceAccounts, etc.) with per-BindDefinition field ownership.
//
// The generic Applier and StatusApplier types implement skip-if-unchanged
// SSA for any object type: they read the live object, compare desired values
// and the field manager's ownership, and only send an apply when needed.
// The package depends only on the standard library, apimachinery, client-go
// and controller-runtime, so other operators can define their own
// descriptors; see docs/ssa-architecture.md and ExampleApplier.
package ssa

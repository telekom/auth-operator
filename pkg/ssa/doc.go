// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package ssa provides Server-Side Apply helpers for constructing and applying
// RBAC and core resource ApplyConfiguration objects (ClusterRoles, Roles,
// RoleBindings, ServiceAccounts, etc.) with per-BindDefinition field ownership.
//
// Cache and managed-field comparison gates come from
// github.com/telekom/t-caas-go-library/pkg/ssa. RBAC schema normalization,
// label cleanup and characterized auth-operator compatibility policies stay
// here; see docs/ssa-architecture.md.
package ssa

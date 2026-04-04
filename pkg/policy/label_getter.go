// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import "context"

// LabelGetter resolves labels for Kubernetes objects by name.
// It is used by the policy evaluator to evaluate label-selector-based
// constraints (e.g. AllowedRoleRefSelector, AllowedNamespaceSelector).
// Pass nil to skip all selector-based checks.
type LabelGetter interface {
	// GetNamespaceLabels returns labels for a namespace.
	// The bool return indicates whether the namespace was found.
	GetNamespaceLabels(ctx context.Context, name string) (map[string]string, bool)

	// GetClusterRoleLabels returns labels for a ClusterRole.
	// The bool return indicates whether the ClusterRole was found.
	GetClusterRoleLabels(ctx context.Context, name string) (map[string]string, bool)

	// GetRoleLabels returns labels for a namespaced Role.
	// The bool return indicates whether the Role was found.
	GetRoleLabels(ctx context.Context, namespace, name string) (map[string]string, bool)
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// EvaluateBindDefinition checks a RestrictedBindDefinition against its
// governing RBACPolicy and returns all violations. An empty slice
// indicates full compliance.
func EvaluateBindDefinition(policy *authorizationv1alpha1.RBACPolicy, rbd *authorizationv1alpha1.RestrictedBindDefinition) []Violation {
	var violations []Violation

	if policy.Spec.BindingLimits != nil {
		violations = append(violations, evaluateBindingLimits(policy.Spec.BindingLimits, rbd)...)
	}

	if policy.Spec.SubjectLimits != nil {
		violations = append(violations, evaluateSubjectLimits(policy.Spec.SubjectLimits, rbd.Spec.Subjects)...)
	}

	return violations
}

// evaluateBindingLimits checks binding-related constraints.
func evaluateBindingLimits(limits *authorizationv1alpha1.BindingLimits, rbd *authorizationv1alpha1.RestrictedBindDefinition) []Violation {
	var violations []Violation

	// Check ClusterRoleBinding permission.
	if !limits.AllowClusterRoleBindings && len(rbd.Spec.ClusterRoleBindings.ClusterRoleRefs) > 0 {
		violations = append(violations, Violation{
			Field:   "spec.clusterRoleBindings",
			Message: "ClusterRoleBindings are not allowed by policy",
		})
	}

	// Check CRB role ref limits.
	if limits.AllowClusterRoleBindings && limits.ClusterRoleBindingLimits != nil {
		for i, ref := range rbd.Spec.ClusterRoleBindings.ClusterRoleRefs {
			violations = append(violations, checkRoleRef(
				limits.ClusterRoleBindingLimits,
				ref,
				fmt.Sprintf("spec.clusterRoleBindings.clusterRoleRefs[%d]", i),
			)...)
		}
	}

	// Check RoleBinding role ref limits.
	if limits.RoleBindingLimits != nil {
		for i, nb := range rbd.Spec.RoleBindings {
			for j, ref := range nb.ClusterRoleRefs {
				violations = append(violations, checkRoleRef(
					limits.RoleBindingLimits,
					ref,
					fmt.Sprintf("spec.roleBindings[%d].clusterRoleRefs[%d]", i, j),
				)...)
			}
			for j, ref := range nb.RoleRefs {
				violations = append(violations, checkRoleRef(
					limits.RoleBindingLimits,
					ref,
					fmt.Sprintf("spec.roleBindings[%d].roleRefs[%d]", i, j),
				)...)
			}
		}
	}

	// Check target namespace limits.
	if limits.TargetNamespaceLimits != nil {
		violations = append(violations, evaluateNamespaceLimits(limits.TargetNamespaceLimits, rbd)...)
	}

	return violations
}

// checkRoleRef validates a single role reference against role ref limits.
func checkRoleRef(limits *authorizationv1alpha1.RoleRefLimits, ref, fieldPath string) []Violation {
	var violations []Violation

	// Forbidden takes precedence.
	if len(limits.ForbiddenRoleRefs) > 0 && matchesAnyWildcard(limits.ForbiddenRoleRefs, ref) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("role ref %q is forbidden by policy", ref),
		})
	}

	// Check allowed list (default-deny: empty list = nothing allowed).
	if len(limits.AllowedRoleRefs) > 0 && !matchesAnyWildcard(limits.AllowedRoleRefs, ref) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("role ref %q is not in the allowed list", ref),
		})
	}

	return violations
}

// evaluateNamespaceLimits checks namespace targeting constraints.
func evaluateNamespaceLimits(limits *authorizationv1alpha1.NamespaceLimits, rbd *authorizationv1alpha1.RestrictedBindDefinition) []Violation {
	var violations []Violation

	for i, nb := range rbd.Spec.RoleBindings {
		if nb.Namespace != "" {
			violations = append(violations, checkNamespace(limits, nb.Namespace, fmt.Sprintf("spec.roleBindings[%d].namespace", i))...)
		}
	}

	// Check MaxTargetNamespaces.
	if limits.MaxTargetNamespaces != nil {
		count := countTargetNamespaces(rbd)
		if count > int(*limits.MaxTargetNamespaces) {
			violations = append(violations, Violation{
				Field:   "spec.roleBindings",
				Message: fmt.Sprintf("exceeds maximum target namespaces: %d > %d", count, *limits.MaxTargetNamespaces),
			})
		}
	}

	return violations
}

// checkNamespace validates a single namespace against namespace limits.
func checkNamespace(limits *authorizationv1alpha1.NamespaceLimits, namespace, fieldPath string) []Violation {
	var violations []Violation

	if containsString(limits.ForbiddenNamespaces, namespace) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("namespace %q is forbidden by policy", namespace),
		})
	}

	if hasAnyPrefix(limits.ForbiddenNamespacePrefixes, namespace) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("namespace %q matches a forbidden prefix", namespace),
		})
	}

	return violations
}

// countTargetNamespaces counts the number of distinct explicit namespaces
// targeted by a RestrictedBindDefinition. Namespace selectors are not counted
// because their resolution depends on the cluster state.
func countTargetNamespaces(rbd *authorizationv1alpha1.RestrictedBindDefinition) int {
	seen := make(map[string]struct{})
	for _, nb := range rbd.Spec.RoleBindings {
		if nb.Namespace != "" {
			seen[nb.Namespace] = struct{}{}
		}
	}
	return len(seen)
}

// evaluateSubjectLimits checks subject-related constraints.
func evaluateSubjectLimits(limits *authorizationv1alpha1.SubjectLimits, subjects []rbacv1.Subject) []Violation {
	var violations []Violation

	for i, s := range subjects {
		fieldPath := fmt.Sprintf("spec.subjects[%d]", i)

		// Check forbidden kinds (takes precedence).
		if containsString(limits.ForbiddenKinds, s.Kind) {
			violations = append(violations, Violation{
				Field:   fieldPath + ".kind",
				Message: fmt.Sprintf("subject kind %q is forbidden by policy", s.Kind),
			})
			continue
		}

		// Check allowed kinds (default-deny).
		if len(limits.AllowedKinds) > 0 && !containsString(limits.AllowedKinds, s.Kind) {
			violations = append(violations, Violation{
				Field:   fieldPath + ".kind",
				Message: fmt.Sprintf("subject kind %q is not allowed by policy", s.Kind),
			})
			continue
		}

		// Check kind-specific name limits.
		switch s.Kind {
		case rbacv1.UserKind:
			if limits.UserLimits != nil {
				violations = append(violations, checkNameMatchLimits(limits.UserLimits, s.Name, fieldPath+".name")...)
			}
		case rbacv1.GroupKind:
			if limits.GroupLimits != nil {
				violations = append(violations, checkNameMatchLimits(limits.GroupLimits, s.Name, fieldPath+".name")...)
			}
		case rbacv1.ServiceAccountKind:
			if limits.ServiceAccountLimits != nil {
				violations = append(violations, checkServiceAccountLimits(limits.ServiceAccountLimits, s, fieldPath)...)
			}
		}
	}

	return violations
}

// checkNameMatchLimits validates a name against NameMatchLimits.
func checkNameMatchLimits(limits *authorizationv1alpha1.NameMatchLimits, name, fieldPath string) []Violation {
	var violations []Violation

	// Forbidden checks (take precedence).
	if containsString(limits.ForbiddenNames, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q is forbidden by policy", name),
		})
	}

	if hasAnyPrefix(limits.ForbiddenPrefixes, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q matches a forbidden prefix", name),
		})
	}

	if hasAnySuffix(limits.ForbiddenSuffixes, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q matches a forbidden suffix", name),
		})
	}

	// Allowed checks (must match at least one if specified).
	if len(limits.AllowedNames) > 0 && !containsString(limits.AllowedNames, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q is not in the allowed list", name),
		})
	}

	if len(limits.AllowedPrefixes) > 0 && !hasAnyPrefix(limits.AllowedPrefixes, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q does not match any allowed prefix", name),
		})
	}

	if len(limits.AllowedSuffixes) > 0 && !hasAnySuffix(limits.AllowedSuffixes, name) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("name %q does not match any allowed suffix", name),
		})
	}

	return violations
}

// checkServiceAccountLimits validates a ServiceAccount subject.
func checkServiceAccountLimits(limits *authorizationv1alpha1.ServiceAccountLimits, subject rbacv1.Subject, fieldPath string) []Violation {
	var violations []Violation

	// Check forbidden namespaces.
	if containsString(limits.ForbiddenNamespaces, subject.Namespace) {
		violations = append(violations, Violation{
			Field:   fieldPath + ".namespace",
			Message: fmt.Sprintf("ServiceAccount namespace %q is forbidden by policy", subject.Namespace),
		})
	}

	if hasAnyPrefix(limits.ForbiddenNamespacePrefixes, subject.Namespace) {
		violations = append(violations, Violation{
			Field:   fieldPath + ".namespace",
			Message: fmt.Sprintf("ServiceAccount namespace %q matches a forbidden prefix", subject.Namespace),
		})
	}

	return violations
}

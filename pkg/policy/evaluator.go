// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// EvaluateBindDefinition checks a RestrictedBindDefinition against its
// governing RBACPolicy and returns all violations. An empty slice
// indicates full compliance.
// The optional labelGetter enables label-selector-based checks;
// pass nil to skip selector evaluation.
func EvaluateBindDefinition(
	ctx context.Context,
	policy *authorizationv1alpha1.RBACPolicy,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	labelGetter LabelGetter,
) []Violation {
	var violations []Violation

	if policy.Spec.BindingLimits != nil {
		violations = append(violations, evaluateBindingLimits(ctx, policy.Spec.BindingLimits, rbd, labelGetter)...)
	}

	if policy.Spec.SubjectLimits != nil {
		violations = append(violations, evaluateSubjectLimits(ctx, policy.Spec.SubjectLimits, rbd.Spec.Subjects, labelGetter)...)
	}

	return violations
}

// evaluateBindingLimits checks binding-related constraints.
func evaluateBindingLimits(ctx context.Context, limits *authorizationv1alpha1.BindingLimits, rbd *authorizationv1alpha1.RestrictedBindDefinition, lg LabelGetter) []Violation {
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
			var roleLabels map[string]string
			if lg != nil {
				roleLabels, _ = lg.GetClusterRoleLabels(ctx, ref)
			}
			violations = append(violations, checkRoleRef(
				limits.ClusterRoleBindingLimits,
				ref,
				fmt.Sprintf("spec.clusterRoleBindings.clusterRoleRefs[%d]", i),
				roleLabels,
				lg != nil,
			)...)
		}
	}

	// Check RoleBinding role ref limits.
	if limits.RoleBindingLimits != nil {
		for i, nb := range rbd.Spec.RoleBindings {
			for j, ref := range nb.ClusterRoleRefs {
				var roleLabels map[string]string
				if lg != nil {
					roleLabels, _ = lg.GetClusterRoleLabels(ctx, ref)
				}
				violations = append(violations, checkRoleRef(
					limits.RoleBindingLimits,
					ref,
					fmt.Sprintf("spec.roleBindings[%d].clusterRoleRefs[%d]", i, j),
					roleLabels,
					lg != nil,
				)...)
			}
			for j, ref := range nb.RoleRefs {
				var roleLabels map[string]string
				if lg != nil {
					roleLabels, _ = lg.GetRoleLabels(ctx, nb.Namespace, ref)
				}
				violations = append(violations, checkRoleRef(
					limits.RoleBindingLimits,
					ref,
					fmt.Sprintf("spec.roleBindings[%d].roleRefs[%d]", i, j),
					roleLabels,
					lg != nil,
				)...)
			}
		}
	}

	// Check target namespace limits.
	if limits.TargetNamespaceLimits != nil {
		violations = append(violations, evaluateNamespaceLimits(ctx, limits.TargetNamespaceLimits, rbd, lg)...)
	}

	return violations
}

// checkRoleRef validates a single role reference against role ref limits.
// roleLabels are the resolved labels of the referenced role (nil if not found
// or no resolver). selectorEnabled indicates whether a LabelGetter was
// available (to distinguish "no resolver" from "role not found").
func checkRoleRef(limits *authorizationv1alpha1.RoleRefLimits, ref, fieldPath string, roleLabels map[string]string, selectorEnabled bool) []Violation {
	var violations []Violation

	// Forbidden checks: any match triggers rejection (independent).
	if len(limits.ForbiddenRoleRefs) > 0 && matchesAnyWildcard(limits.ForbiddenRoleRefs, ref) {
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("role ref %q is forbidden by policy", ref),
		})
	}

	if selectorEnabled && roleLabels != nil && limits.ForbiddenRoleRefSelector != nil {
		if matchesSelector(limits.ForbiddenRoleRefSelector, roleLabels) {
			violations = append(violations, Violation{
				Field:   fieldPath,
				Message: fmt.Sprintf("role ref %q matches the forbidden role ref label selector", ref),
			})
		}
	}

	// Allowed checks: name OR selector (combined with OR semantics).
	// A ref is allowed if it matches AllowedRoleRefs OR AllowedRoleRefSelector.
	hasNameConfig := len(limits.AllowedRoleRefs) > 0
	hasSelectorConfig := selectorEnabled && limits.AllowedRoleRefSelector != nil

	if hasNameConfig || hasSelectorConfig {
		nameAllowed := hasNameConfig && matchesAnyWildcard(limits.AllowedRoleRefs, ref)
		selectorAllowed := hasSelectorConfig && roleLabels != nil && matchesSelector(limits.AllowedRoleRefSelector, roleLabels)

		if !nameAllowed && !selectorAllowed {
			violations = append(violations, Violation{
				Field:   fieldPath,
				Message: fmt.Sprintf("role ref %q is not allowed by policy (name or label selector)", ref),
			})
		}
	} else {
		// No allowed configuration at all — default-deny.
		violations = append(violations, Violation{
			Field:   fieldPath,
			Message: fmt.Sprintf("role ref %q is not in the allowed list", ref),
		})
	}

	return violations
}

// evaluateNamespaceLimits checks namespace targeting constraints.
func evaluateNamespaceLimits(ctx context.Context, limits *authorizationv1alpha1.NamespaceLimits, rbd *authorizationv1alpha1.RestrictedBindDefinition, lg LabelGetter) []Violation {
	var violations []Violation

	for i, nb := range rbd.Spec.RoleBindings {
		if nb.Namespace != "" {
			violations = append(violations, checkNamespace(ctx, limits, nb.Namespace, fmt.Sprintf("spec.roleBindings[%d].namespace", i), lg)...)
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
func checkNamespace(ctx context.Context, limits *authorizationv1alpha1.NamespaceLimits, namespace, fieldPath string, lg LabelGetter) []Violation {
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

	// Check AllowedNamespaceSelector.
	if limits.AllowedNamespaceSelector != nil && lg != nil {
		nsLabels, found := lg.GetNamespaceLabels(ctx, namespace)
		if !found || !matchesSelector(limits.AllowedNamespaceSelector, nsLabels) {
			violations = append(violations, Violation{
				Field:   fieldPath,
				Message: fmt.Sprintf("namespace %q does not match the allowed namespace label selector", namespace),
			})
		}
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
func evaluateSubjectLimits(ctx context.Context, limits *authorizationv1alpha1.SubjectLimits, subjects []rbacv1.Subject, lg LabelGetter) []Violation {
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

		// Check allowed kinds (default-deny: empty list = nothing allowed).
		if !containsString(limits.AllowedKinds, s.Kind) {
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
				violations = append(violations, checkServiceAccountLimits(ctx, limits.ServiceAccountLimits, s, fieldPath, lg)...)
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
// AllowAutoCreate, AllowedCreationNamespaceSelector, and DisableAdoption
// are behavioral flags enforced by the controller at reconciliation time,
// not spec-level constraints checked here.
func checkServiceAccountLimits(ctx context.Context, limits *authorizationv1alpha1.ServiceAccountLimits, subject rbacv1.Subject, fieldPath string, lg LabelGetter) []Violation {
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

	// Check AllowedNamespaceSelector.
	if limits.AllowedNamespaceSelector != nil && lg != nil && subject.Namespace != "" {
		nsLabels, found := lg.GetNamespaceLabels(ctx, subject.Namespace)
		if !found || !matchesSelector(limits.AllowedNamespaceSelector, nsLabels) {
			violations = append(violations, Violation{
				Field:   fieldPath + ".namespace",
				Message: fmt.Sprintf("ServiceAccount namespace %q does not match the allowed namespace label selector", subject.Namespace),
			})
		}
	}

	// Check SA creation namespace constraints (OR semantics: static list OR selector).
	if limits.Creation != nil && subject.Namespace != "" {
		hasStaticCheck := len(limits.Creation.AllowedCreationNamespaces) > 0
		hasSelectorCheck := limits.Creation.AllowedCreationNamespaceSelector != nil && lg != nil

		if hasStaticCheck || hasSelectorCheck {
			staticAllowed := hasStaticCheck && containsString(limits.Creation.AllowedCreationNamespaces, subject.Namespace)
			selectorAllowed := false
			if hasSelectorCheck {
				nsLabels, found := lg.GetNamespaceLabels(ctx, subject.Namespace)
				if found {
					selectorAllowed = matchesSelector(limits.Creation.AllowedCreationNamespaceSelector, nsLabels)
				}
			}
			if !staticAllowed && !selectorAllowed {
				violations = append(violations, Violation{
					Field:   fieldPath + ".namespace",
					Message: fmt.Sprintf("ServiceAccount namespace %q is not in the allowed creation namespaces", subject.Namespace),
				})
			}
		}
	}

	return violations
}

// matchesSelector checks if the given labels match a label selector.
// Returns false if the selector is invalid or labels are nil.
func matchesSelector(selector *metav1.LabelSelector, objLabels map[string]string) bool {
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}
	return sel.Matches(labels.Set(objLabels))
}

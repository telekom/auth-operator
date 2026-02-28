// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FieldOwner is the field manager name for the auth-operator.
const FieldOwner = "auth-operator"

// maxFieldManagerLength is the Kubernetes API server limit for fieldManager.
const maxFieldManagerLength = 128

// FieldOwnerForBD returns a per-BindDefinition field owner for SSA.
// This allows multiple BDs to independently manage ownerReferences on shared SAs.
// Each BD's ownerRef is tracked separately so one BD's apply doesn't remove another's.
// If the resulting field owner would exceed 128 characters (K8s limit), the BD name
// is truncated and suffixed with a short hash to ensure uniqueness.
func FieldOwnerForBD(bdName string) string {
	prefix := FieldOwner + "/"
	fullOwner := prefix + bdName

	if len(fullOwner) <= maxFieldManagerLength {
		return fullOwner
	}

	// Hash the full name for uniqueness
	hash := sha256.Sum256([]byte(bdName))
	hashSuffix := hex.EncodeToString(hash[:4]) // 8 hex chars

	// Truncate bdName to fit: prefix + truncated + "-" + hash <= 128
	maxNameLen := maxFieldManagerLength - len(prefix) - 1 - len(hashSuffix)
	truncatedName := bdName[:maxNameLen]

	return prefix + truncatedName + "-" + hashSuffix
}

// OwnerReference creates an OwnerReference ApplyConfiguration for use with SSA.
func OwnerReference(
	apiVersion, kind, name string,
	uid types.UID,
	controller, blockOwnerDeletion bool,
) *metav1ac.OwnerReferenceApplyConfiguration {
	return metav1ac.OwnerReference().
		WithAPIVersion(apiVersion).
		WithKind(kind).
		WithName(name).
		WithUID(uid).
		WithController(controller).
		WithBlockOwnerDeletion(blockOwnerDeletion)
}

// ServiceAccountWith creates a ServiceAccount ApplyConfiguration with labels
// and automountServiceAccountToken. Attach owner references via the returned AC.
func ServiceAccountWith(
	name, namespace string,
	labels map[string]string,
	automountToken bool,
) *corev1ac.ServiceAccountApplyConfiguration {
	ac := corev1ac.ServiceAccount(name, namespace).
		WithAutomountServiceAccountToken(automountToken)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	return ac
}

// ApplyServiceAccount applies a ServiceAccount using Server-Side Apply.
func ApplyServiceAccount(
	ctx context.Context,
	c client.Client,
	ac *corev1ac.ServiceAccountApplyConfiguration,
) error {
	return ApplyServiceAccountWithFieldOwner(ctx, c, ac, FieldOwner)
}

// ApplyServiceAccountWithFieldOwner applies a ServiceAccount using SSA with a custom field owner.
// Use FieldOwnerForBD(bdName) for shared SAs to ensure each BD's ownerRef is tracked independently.
func ApplyServiceAccountWithFieldOwner(
	ctx context.Context,
	c client.Client,
	ac *corev1ac.ServiceAccountApplyConfiguration,
	fieldOwner string,
) error {
	if ac == nil || ac.Name == nil {
		return fmt.Errorf("serviceAccount ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return fmt.Errorf("serviceAccount ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil || *ac.Namespace == "" {
		return fmt.Errorf("serviceAccount ApplyConfiguration must have a namespace")
	}

	return c.Apply(ctx, ac, client.FieldOwner(fieldOwner), client.ForceOwnership)
}

// ClusterRoleWithLabelsAndRules creates a ClusterRole ApplyConfiguration with the specified
// labels and rules. This is the starting point for building a ClusterRole for SSA.
func ClusterRoleWithLabelsAndRules(
	name string,
	labels map[string]string,
	rules []rbacv1.PolicyRule,
) *rbacv1ac.ClusterRoleApplyConfiguration {
	ac := rbacv1ac.ClusterRole(name)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	for _, rule := range rules {
		ruleAC := PolicyRuleFrom(&rule)
		ac.WithRules(ruleAC)
	}

	return ac
}

// ClusterRoleWithAggregation creates a ClusterRole ApplyConfiguration with an aggregation rule
// and optional labels. Aggregated ClusterRoles have empty rules (managed by the aggregation controller).
func ClusterRoleWithAggregation(
	name string,
	labels map[string]string,
	aggregationRule *rbacv1.AggregationRule,
) *rbacv1ac.ClusterRoleApplyConfiguration {
	ac := rbacv1ac.ClusterRole(name)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	// Explicitly set rules to empty so SSA removes any previously-applied rules
	// when transitioning from rule-based to aggregation-based reconciliation.
	ac.WithRules()

	if aggregationRule != nil {
		aggAC := rbacv1ac.AggregationRule()
		for i := range aggregationRule.ClusterRoleSelectors {
			sel := &aggregationRule.ClusterRoleSelectors[i]
			selAC := LabelSelectorFrom(sel)
			aggAC.WithClusterRoleSelectors(selAC)
		}
		ac.WithAggregationRule(aggAC)
	}

	return ac
}

// LabelSelectorFrom converts a metav1.LabelSelector to its ApplyConfiguration.
func LabelSelectorFrom(sel *metav1.LabelSelector) *metav1ac.LabelSelectorApplyConfiguration {
	if sel == nil {
		return nil
	}
	selAC := metav1ac.LabelSelector()
	if len(sel.MatchLabels) > 0 {
		selAC.WithMatchLabels(sel.MatchLabels)
	}
	for i := range sel.MatchExpressions {
		expr := &sel.MatchExpressions[i]
		exprAC := metav1ac.LabelSelectorRequirement().
			WithKey(expr.Key).
			WithOperator(expr.Operator).
			WithValues(expr.Values...)
		selAC.WithMatchExpressions(exprAC)
	}
	return selAC
}

// RoleWithLabelsAndRules creates a Role ApplyConfiguration with the specified
// labels and rules. This is the starting point for building a Role for SSA.
func RoleWithLabelsAndRules(
	name, namespace string,
	labels map[string]string,
	rules []rbacv1.PolicyRule,
) *rbacv1ac.RoleApplyConfiguration {
	ac := rbacv1ac.Role(name, namespace)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	for _, rule := range rules {
		ruleAC := PolicyRuleFrom(&rule)
		ac.WithRules(ruleAC)
	}

	return ac
}

// PolicyRuleFrom converts a PolicyRule to its ApplyConfiguration.
func PolicyRuleFrom(rule *rbacv1.PolicyRule) *rbacv1ac.PolicyRuleApplyConfiguration {
	if rule == nil {
		return nil
	}

	ac := rbacv1ac.PolicyRule()

	if len(rule.Verbs) > 0 {
		ac.WithVerbs(rule.Verbs...)
	}
	if len(rule.APIGroups) > 0 {
		ac.WithAPIGroups(rule.APIGroups...)
	}
	if len(rule.Resources) > 0 {
		ac.WithResources(rule.Resources...)
	}
	if len(rule.ResourceNames) > 0 {
		ac.WithResourceNames(rule.ResourceNames...)
	}
	if len(rule.NonResourceURLs) > 0 {
		ac.WithNonResourceURLs(rule.NonResourceURLs...)
	}

	return ac
}

// ApplyClusterRole applies a ClusterRole using Server-Side Apply.
func ApplyClusterRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleApplyConfiguration,
) error {
	if ac == nil || ac.Name == nil {
		return fmt.Errorf("clusterRole ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return fmt.Errorf("clusterRole ApplyConfiguration name must not be empty")
	}

	return c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// ApplyRole applies a Role using Server-Side Apply.
func ApplyRole(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleApplyConfiguration,
) error {
	if ac == nil || ac.Name == nil {
		return fmt.Errorf("role ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return fmt.Errorf("role ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil {
		return fmt.Errorf("role ApplyConfiguration must have a namespace")
	}
	if *ac.Namespace == "" {
		return fmt.Errorf("role ApplyConfiguration namespace must not be empty")
	}

	return c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// ClusterRoleBindingWithSubjectsAndRoleRef creates a ClusterRoleBinding ApplyConfiguration.
func ClusterRoleBindingWithSubjectsAndRoleRef(
	name string,
	labels map[string]string,
	subjects []rbacv1.Subject,
	roleRef rbacv1.RoleRef,
) *rbacv1ac.ClusterRoleBindingApplyConfiguration {
	ac := rbacv1ac.ClusterRoleBinding(name)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	for _, subject := range subjects {
		subjectAC := SubjectFrom(&subject)
		ac.WithSubjects(subjectAC)
	}

	roleRefAC := RoleRefFrom(&roleRef)
	ac.WithRoleRef(roleRefAC)

	return ac
}

// RoleBindingWithSubjectsAndRoleRef creates a RoleBinding ApplyConfiguration.
func RoleBindingWithSubjectsAndRoleRef(
	name, namespace string,
	labels map[string]string,
	subjects []rbacv1.Subject,
	roleRef rbacv1.RoleRef,
) *rbacv1ac.RoleBindingApplyConfiguration {
	ac := rbacv1ac.RoleBinding(name, namespace)

	if len(labels) > 0 {
		ac.WithLabels(labels)
	}

	for _, subject := range subjects {
		subjectAC := SubjectFrom(&subject)
		ac.WithSubjects(subjectAC)
	}

	roleRefAC := RoleRefFrom(&roleRef)
	ac.WithRoleRef(roleRefAC)

	return ac
}

// SubjectFrom converts a Subject to its ApplyConfiguration.
func SubjectFrom(subject *rbacv1.Subject) *rbacv1ac.SubjectApplyConfiguration {
	if subject == nil {
		return nil
	}

	ac := rbacv1ac.Subject().
		WithKind(subject.Kind).
		WithName(subject.Name)

	if subject.APIGroup != "" {
		ac.WithAPIGroup(subject.APIGroup)
	}
	if subject.Namespace != "" {
		ac.WithNamespace(subject.Namespace)
	}

	return ac
}

// RoleRefFrom converts a RoleRef to its ApplyConfiguration.
func RoleRefFrom(roleRef *rbacv1.RoleRef) *rbacv1ac.RoleRefApplyConfiguration {
	if roleRef == nil {
		return nil
	}

	return rbacv1ac.RoleRef().
		WithAPIGroup(roleRef.APIGroup).
		WithKind(roleRef.Kind).
		WithName(roleRef.Name)
}

// ApplyClusterRoleBinding applies a ClusterRoleBinding using Server-Side Apply.
func ApplyClusterRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.ClusterRoleBindingApplyConfiguration,
) error {
	if ac == nil || ac.Name == nil {
		return fmt.Errorf("clusterRoleBinding ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return fmt.Errorf("clusterRoleBinding ApplyConfiguration name must not be empty")
	}

	return c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// ApplyRoleBinding applies a RoleBinding using Server-Side Apply.
func ApplyRoleBinding(
	ctx context.Context,
	c client.Client,
	ac *rbacv1ac.RoleBindingApplyConfiguration,
) error {
	if ac == nil || ac.Name == nil {
		return fmt.Errorf("roleBinding ApplyConfiguration must have a name")
	}
	if *ac.Name == "" {
		return fmt.Errorf("roleBinding ApplyConfiguration name must not be empty")
	}
	if ac.Namespace == nil {
		return fmt.Errorf("roleBinding ApplyConfiguration must have a namespace")
	}
	if *ac.Namespace == "" {
		return fmt.Errorf("roleBinding ApplyConfiguration namespace must not be empty")
	}

	return c.Apply(ctx, ac, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

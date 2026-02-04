// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

// Package ssa provides Server-Side Apply (SSA) helpers for RBAC resources.
// It wraps the client-go ApplyConfiguration types to provide a convenient
// API for applying ClusterRoles, Roles, and other RBAC resources.
package ssa

import (
	"context"
	"encoding/json"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
)

// FieldOwner is the field manager name for the auth-operator.
const FieldOwner = "auth-operator"

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

	clusterRole := &rbacv1.ClusterRole{}
	clusterRole.Name = *ac.Name

	patch, err := createPatch(ac)
	if err != nil {
		return fmt.Errorf("create patch for ClusterRole %s: %w", *ac.Name, err)
	}

	return c.Patch(ctx, clusterRole, patch, client.FieldOwner(FieldOwner), client.ForceOwnership)
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

	role := &rbacv1.Role{}
	role.Name = *ac.Name
	role.Namespace = *ac.Namespace

	patch, err := createPatch(ac)
	if err != nil {
		return fmt.Errorf("create patch for Role %s/%s: %w", *ac.Namespace, *ac.Name, err)
	}

	return c.Patch(ctx, role, patch, client.FieldOwner(FieldOwner), client.ForceOwnership)
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

	crb := &rbacv1.ClusterRoleBinding{}
	crb.Name = *ac.Name

	patch, err := createPatch(ac)
	if err != nil {
		return fmt.Errorf("create patch for ClusterRoleBinding %s: %w", *ac.Name, err)
	}

	return c.Patch(ctx, crb, patch, client.FieldOwner(FieldOwner), client.ForceOwnership)
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

	rb := &rbacv1.RoleBinding{}
	rb.Name = *ac.Name
	rb.Namespace = *ac.Namespace

	patch, err := createPatch(ac)
	if err != nil {
		return fmt.Errorf("create patch for RoleBinding %s/%s: %w", *ac.Namespace, *ac.Name, err)
	}

	return c.Patch(ctx, rb, patch, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// applyPatch is a custom patch type for Server-Side Apply that marshals an ApplyConfiguration to JSON.
// This properly applies the ApplyConfiguration fields instead of applying an empty object.
type applyPatch struct {
	data []byte
}

// Type implements client.Patch.
func (p applyPatch) Type() types.PatchType {
	return types.ApplyPatchType
}

// Data implements client.Patch.
func (p applyPatch) Data(_ client.Object) ([]byte, error) {
	return p.data, nil
}

// createPatch creates an Apply patch from an ApplyConfiguration by marshaling it to JSON.
// Uses runtime.ApplyConfiguration interface for type safety at compile time.
func createPatch(ac runtime.ApplyConfiguration) (client.Patch, error) {
	data, err := json.Marshal(ac)
	if err != nil {
		return nil, fmt.Errorf("marshal ApplyConfiguration: %w", err)
	}
	return applyPatch{data: data}, nil
}

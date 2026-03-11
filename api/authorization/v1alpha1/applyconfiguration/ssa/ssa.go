// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package ssa provides Server-Side Apply (SSA) helpers for working with the
// generated ApplyConfiguration types. These helpers create typed ApplyConfigurations
// from existing objects and apply them via the native SubResource("status").Apply() API.
package ssa

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	ac "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1"
)

// FieldOwner is the field manager name for the auth-operator controller.
const FieldOwner = "auth-operator"

// applyStatus applies a typed ApplyConfiguration to the status subresource
// using the native controller-runtime SubResource("status").Apply() API.
// This uses Server-Side Apply without any unstructured conversion or workarounds.
func applyStatus(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) error {
	if applyConfig == nil {
		return fmt.Errorf("applyConfig must not be nil")
	}

	return c.SubResource("status").Apply(ctx, applyConfig, client.FieldOwner(FieldOwner), client.ForceOwnership)
}

// ApplyRoleDefinitionStatus applies a status update to a RoleDefinition using native SSA.
// It delegates to PatchApplyRoleDefinitionStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyRoleDefinitionStatus(ctx context.Context, c client.Client, rd *authorizationv1alpha1.RoleDefinition) error {
	_, err := PatchApplyRoleDefinitionStatus(ctx, c, rd)
	return err
}

// ApplyBindDefinitionStatus applies a status update to a BindDefinition using native SSA.
// It delegates to PatchApplyBindDefinitionStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyBindDefinitionStatus(ctx context.Context, c client.Client, bd *authorizationv1alpha1.BindDefinition) error {
	_, err := PatchApplyBindDefinitionStatus(ctx, c, bd)
	return err
}

// ApplyWebhookAuthorizerStatus applies a status update to a WebhookAuthorizer using native SSA.
// It delegates to PatchApplyWebhookAuthorizerStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyWebhookAuthorizerStatus(ctx context.Context, c client.Client, wa *authorizationv1alpha1.WebhookAuthorizer) error {
	_, err := PatchApplyWebhookAuthorizerStatus(ctx, c, wa)
	return err
}

// RoleDefinitionStatusFrom converts a RoleDefinitionStatus to its ApplyConfiguration.
func RoleDefinitionStatusFrom(status *authorizationv1alpha1.RoleDefinitionStatus) *ac.RoleDefinitionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.RoleDefinitionStatus()

	// Set ObservedGeneration (required for kstatus)
	result.WithObservedGeneration(status.ObservedGeneration)

	// Set RoleReconciled
	result.WithRoleReconciled(status.RoleReconciled)

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// BindDefinitionStatusFrom converts a BindDefinitionStatus to its ApplyConfiguration.
func BindDefinitionStatusFrom(status *authorizationv1alpha1.BindDefinitionStatus) *ac.BindDefinitionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.BindDefinitionStatus()

	// Set ObservedGeneration (required for kstatus)
	result.WithObservedGeneration(status.ObservedGeneration)

	// Set BindReconciled
	result.WithBindReconciled(status.BindReconciled)

	// Set GeneratedServiceAccounts
	for _, sa := range status.GeneratedServiceAccounts {
		result.WithGeneratedServiceAccounts(sa)
	}

	// Set MissingRoleRefs — always initialise the slice (even when empty) so
	// that SSA retains field ownership and can clear a previously populated list.
	result.MissingRoleRefs = make([]string, 0, len(status.MissingRoleRefs))
	for _, ref := range status.MissingRoleRefs {
		result.WithMissingRoleRefs(ref)
	}

	// Set ExternalServiceAccounts
	for _, sa := range status.ExternalServiceAccounts {
		result.WithExternalServiceAccounts(sa)
	}

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// WebhookAuthorizerStatusFrom converts a WebhookAuthorizerStatus to its ApplyConfiguration.
func WebhookAuthorizerStatusFrom(status *authorizationv1alpha1.WebhookAuthorizerStatus) *ac.WebhookAuthorizerStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.WebhookAuthorizerStatus()

	// Set ObservedGeneration (required for kstatus)
	result.WithObservedGeneration(status.ObservedGeneration)

	// Set AuthorizerConfigured
	result.WithAuthorizerConfigured(status.AuthorizerConfigured)

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// ApplyRBACPolicyStatus applies a status update to an RBACPolicy using native SSA.
// It delegates to PatchApplyRBACPolicyStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyRBACPolicyStatus(ctx context.Context, c client.Client, rp *authorizationv1alpha1.RBACPolicy) error {
	_, err := PatchApplyRBACPolicyStatus(ctx, c, rp)
	return err
}

// ApplyRestrictedBindDefinitionStatus applies a status update to a RestrictedBindDefinition using native SSA.
// It delegates to PatchApplyRestrictedBindDefinitionStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyRestrictedBindDefinitionStatus(ctx context.Context, c client.Client, rbd *authorizationv1alpha1.RestrictedBindDefinition) error {
	_, err := PatchApplyRestrictedBindDefinitionStatus(ctx, c, rbd)
	return err
}

// ApplyRestrictedRoleDefinitionStatus applies a status update to a RestrictedRoleDefinition using native SSA.
// It delegates to PatchApplyRestrictedRoleDefinitionStatus which compares against the cache first
// and skips the API call when the status is already up-to-date.
func ApplyRestrictedRoleDefinitionStatus(ctx context.Context, c client.Client, rrd *authorizationv1alpha1.RestrictedRoleDefinition) error {
	_, err := PatchApplyRestrictedRoleDefinitionStatus(ctx, c, rrd)
	return err
}

// RBACPolicyStatusFrom converts an RBACPolicyStatus to its ApplyConfiguration.
func RBACPolicyStatusFrom(status *authorizationv1alpha1.RBACPolicyStatus) *ac.RBACPolicyStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.RBACPolicyStatus()
	result.WithObservedGeneration(status.ObservedGeneration)
	result.WithBoundResourceCount(status.BoundResourceCount)

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// RestrictedBindDefinitionStatusFrom converts a RestrictedBindDefinitionStatus to its ApplyConfiguration.
func RestrictedBindDefinitionStatusFrom(status *authorizationv1alpha1.RestrictedBindDefinitionStatus) *ac.RestrictedBindDefinitionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.RestrictedBindDefinitionStatus()
	result.WithObservedGeneration(status.ObservedGeneration)
	result.WithBindReconciled(status.BindReconciled)

	for _, sa := range status.GeneratedServiceAccounts {
		result.WithGeneratedServiceAccounts(sa)
	}

	result.MissingRoleRefs = make([]string, 0, len(status.MissingRoleRefs))
	for _, ref := range status.MissingRoleRefs {
		result.WithMissingRoleRefs(ref)
	}

	for _, sa := range status.ExternalServiceAccounts {
		result.WithExternalServiceAccounts(sa)
	}

	result.PolicyViolations = make([]string, 0, len(status.PolicyViolations))
	for _, v := range status.PolicyViolations {
		result.WithPolicyViolations(v)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// RestrictedRoleDefinitionStatusFrom converts a RestrictedRoleDefinitionStatus to its ApplyConfiguration.
func RestrictedRoleDefinitionStatusFrom(status *authorizationv1alpha1.RestrictedRoleDefinitionStatus) *ac.RestrictedRoleDefinitionStatusApplyConfiguration {
	if status == nil {
		return nil
	}

	result := ac.RestrictedRoleDefinitionStatus()
	result.WithObservedGeneration(status.ObservedGeneration)
	result.WithRoleReconciled(status.RoleReconciled)

	result.PolicyViolations = make([]string, 0, len(status.PolicyViolations))
	for _, v := range status.PolicyViolations {
		result.WithPolicyViolations(v)
	}

	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// ConditionFrom converts a metav1.Condition to its ApplyConfiguration.
func ConditionFrom(c *metav1.Condition) *metav1ac.ConditionApplyConfiguration {
	if c == nil {
		return nil
	}

	return metav1ac.Condition().
		WithType(c.Type).
		WithStatus(c.Status).
		WithObservedGeneration(c.ObservedGeneration).
		WithLastTransitionTime(c.LastTransitionTime).
		WithReason(c.Reason).
		WithMessage(c.Message)
}

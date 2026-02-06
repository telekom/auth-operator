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
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
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
// The target object must already exist; applying status to a non-existent object is an error
// (real API servers return NotFound for status subresource patches on missing objects).
func ApplyRoleDefinitionStatus(ctx context.Context, c client.Client, rd *authv1alpha1.RoleDefinition) error {
	if rd == nil {
		return fmt.Errorf("roleDefinition must not be nil")
	}
	if rd.Name == "" {
		return fmt.Errorf("roleDefinition must have a name")
	}

	// Verify the object exists — status subresource apply requires an existing parent object.
	if err := c.Get(ctx, types.NamespacedName{Name: rd.Name, Namespace: rd.Namespace}, &authv1alpha1.RoleDefinition{}); err != nil {
		return fmt.Errorf("get RoleDefinition %s before status apply: %w", rd.Name, err)
	}

	applyConfig := ac.RoleDefinition(rd.Name, rd.Namespace).
		WithStatus(RoleDefinitionStatusFrom(&rd.Status))

	return applyStatus(ctx, c, applyConfig)
}

// ApplyBindDefinitionStatus applies a status update to a BindDefinition using native SSA.
// The target object must already exist; applying status to a non-existent object is an error.
func ApplyBindDefinitionStatus(ctx context.Context, c client.Client, bd *authv1alpha1.BindDefinition) error {
	if bd == nil {
		return fmt.Errorf("bindDefinition must not be nil")
	}
	if bd.Name == "" {
		return fmt.Errorf("bindDefinition must have a name")
	}

	// Verify the object exists — status subresource apply requires an existing parent object.
	if err := c.Get(ctx, types.NamespacedName{Name: bd.Name, Namespace: bd.Namespace}, &authv1alpha1.BindDefinition{}); err != nil {
		return fmt.Errorf("get BindDefinition %s before status apply: %w", bd.Name, err)
	}

	applyConfig := ac.BindDefinition(bd.Name, bd.Namespace).
		WithStatus(BindDefinitionStatusFrom(&bd.Status))

	return applyStatus(ctx, c, applyConfig)
}

// ApplyWebhookAuthorizerStatus applies a status update to a WebhookAuthorizer using native SSA.
// The target object must already exist; applying status to a non-existent object is an error.
func ApplyWebhookAuthorizerStatus(ctx context.Context, c client.Client, wa *authv1alpha1.WebhookAuthorizer) error {
	if wa == nil {
		return fmt.Errorf("webhookAuthorizer must not be nil")
	}
	if wa.Name == "" {
		return fmt.Errorf("webhookAuthorizer must have a name")
	}

	// Verify the object exists — status subresource apply requires an existing parent object.
	if err := c.Get(ctx, types.NamespacedName{Name: wa.Name, Namespace: wa.Namespace}, &authv1alpha1.WebhookAuthorizer{}); err != nil {
		return fmt.Errorf("get WebhookAuthorizer %s before status apply: %w", wa.Name, err)
	}

	applyConfig := ac.WebhookAuthorizer(wa.Name, wa.Namespace).
		WithStatus(WebhookAuthorizerStatusFrom(&wa.Status))

	return applyStatus(ctx, c, applyConfig)
}

// RoleDefinitionStatusFrom converts a RoleDefinitionStatus to its ApplyConfiguration.
func RoleDefinitionStatusFrom(status *authv1alpha1.RoleDefinitionStatus) *ac.RoleDefinitionStatusApplyConfiguration {
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
func BindDefinitionStatusFrom(status *authv1alpha1.BindDefinitionStatus) *ac.BindDefinitionStatusApplyConfiguration {
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

	// Set conditions
	for i := range status.Conditions {
		result.WithConditions(ConditionFrom(&status.Conditions[i]))
	}

	return result
}

// WebhookAuthorizerStatusFrom converts a WebhookAuthorizerStatus to its ApplyConfiguration.
func WebhookAuthorizerStatusFrom(status *authv1alpha1.WebhookAuthorizerStatus) *ac.WebhookAuthorizerStatusApplyConfiguration {
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

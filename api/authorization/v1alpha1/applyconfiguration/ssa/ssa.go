// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package ssa provides Server-Side Apply (SSA) helpers for working with the
// generated ApplyConfiguration types. These helpers create typed ApplyConfigurations
// from existing objects for use with client.Status().Patch().
package ssa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	ac "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1"
)

// FieldOwner is the field manager name for the auth-operator controller.
const FieldOwner = "auth-operator"

// managedFieldsNilRequiredSubstring is the error message substring used by the fake client
// when it requires managed fields to be nil. This is centralized for maintainability.
const managedFieldsNilRequiredSubstring = "metadata.managedFields must be nil"

// isManagedFieldsNilRequiredErr checks if the error is the fake client's managed fields validation error.
// This is used to detect when the fake client requires managed fields to be nil for SSA patches.
// It first attempts a structured check via StatusError causes, then falls back to string matching.
func isManagedFieldsNilRequiredErr(err error) bool {
	if err == nil {
		return false
	}

	// Try structured check first: inspect StatusError details/causes
	var statusErr *apierrors.StatusError
	if errors.As(err, &statusErr) {
		if statusErr.ErrStatus.Details != nil {
			for _, cause := range statusErr.ErrStatus.Details.Causes {
				if cause.Field == "metadata.managedFields" {
					return true
				}
			}
		}
	}

	// Fall back to string matching for fake client errors that may not be structured
	return strings.Contains(err.Error(), managedFieldsNilRequiredSubstring)
}

// applyStatusViaUnstructured applies a typed ApplyConfiguration by first converting it to
// unstructured and then using the SubResource status patch. This works with both real API
// servers and fake clients in tests.
//
// Following cluster-api patterns: https://github.com/kubernetes-sigs/cluster-api/blob/main/util/patch/patch.go
func applyStatusViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) error {
	if applyConfig == nil {
		return fmt.Errorf("applyConfig must not be nil")
	}

	// Marshal to JSON and unmarshal to unstructured - this is the same approach
	// used by the fake client internally
	data, err := json.Marshal(applyConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal apply configuration: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		return fmt.Errorf("failed to unmarshal apply configuration: %w", err)
	}

	// Clear managed fields - the fake client requires this to be nil for SSA patches
	u.SetManagedFields(nil)
	// Also clear from the raw object map in case it's set there
	if metaMap, ok := u.Object["metadata"].(map[string]interface{}); ok {
		delete(metaMap, "managedFields")
	}

	// Fetch the current resource version from the server - the fake client requires this
	// for status patch operations to work correctly.
	// Following cluster-api pattern: status updates should fail if the object doesn't exist.
	current := &unstructured.Unstructured{}
	current.SetGroupVersionKind(u.GetObjectKind().GroupVersionKind())
	if getErr := c.Get(ctx, client.ObjectKey{Name: u.GetName(), Namespace: u.GetNamespace()}, current); getErr != nil {
		// Return error if object doesn't exist - status updates require existing objects
		return fmt.Errorf("failed to get object for status update: %w", getErr)
	}
	if u.GetResourceVersion() == "" {
		u.SetResourceVersion(current.GetResourceVersion())
	}

	// Use SubResource("status").Patch with client.Apply which works with the fake client
	//nolint:staticcheck // SA1019: client.Apply patch type works reliably with fake client
	err = c.SubResource("status").Patch(ctx, u, client.Apply, client.FieldOwner(FieldOwner), client.ForceOwnership)

	// Fallback: if the fake client still rejects managed fields, use MergeFrom patch
	// Following cluster-api pattern from util/patch/patch.go:patchStatus
	if isManagedFieldsNilRequiredErr(err) {
		original := current.DeepCopy()
		current.Object["status"] = u.Object["status"]
		if metaMap, ok := current.Object["metadata"].(map[string]interface{}); ok {
			delete(metaMap, "managedFields")
		}
		return c.SubResource("status").Patch(ctx, current, client.MergeFrom(original))
	}

	return err
}

// ApplyRoleDefinitionStatus applies a status update to a RoleDefinition using native SSA.
// This function builds an apply configuration from the current status and patches it.
func ApplyRoleDefinitionStatus(ctx context.Context, c client.Client, rd *authv1alpha1.RoleDefinition) error {
	if rd == nil {
		return fmt.Errorf("roleDefinition must not be nil")
	}
	if rd.Name == "" {
		return fmt.Errorf("roleDefinition must have a name")
	}

	applyConfig := ac.RoleDefinition(rd.Name, rd.Namespace).
		WithStatus(RoleDefinitionStatusFrom(&rd.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyBindDefinitionStatus applies a status update to a BindDefinition using native SSA.
// This function builds an apply configuration from the current status and patches it.
func ApplyBindDefinitionStatus(ctx context.Context, c client.Client, bd *authv1alpha1.BindDefinition) error {
	if bd == nil {
		return fmt.Errorf("bindDefinition must not be nil")
	}
	if bd.Name == "" {
		return fmt.Errorf("bindDefinition must have a name")
	}

	applyConfig := ac.BindDefinition(bd.Name, bd.Namespace).
		WithStatus(BindDefinitionStatusFrom(&bd.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// ApplyWebhookAuthorizerStatus applies a status update to a WebhookAuthorizer using native SSA.
// This function builds an apply configuration from the current status and patches it.
func ApplyWebhookAuthorizerStatus(ctx context.Context, c client.Client, wa *authv1alpha1.WebhookAuthorizer) error {
	if wa == nil {
		return fmt.Errorf("webhookAuthorizer must not be nil")
	}
	if wa.Name == "" {
		return fmt.Errorf("webhookAuthorizer must have a name")
	}

	applyConfig := ac.WebhookAuthorizer(wa.Name, wa.Namespace).
		WithStatus(WebhookAuthorizerStatusFrom(&wa.Status))

	return applyStatusViaUnstructured(ctx, c, applyConfig)
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

// ApplyViaUnstructured exports the internal applyStatusViaUnstructured helper for use by
// reconcilers that build custom apply configurations.
func ApplyViaUnstructured(ctx context.Context, c client.Client, applyConfig runtime.ApplyConfiguration) error {
	return applyStatusViaUnstructured(ctx, c, applyConfig)
}

// GeneratedServiceAccountFrom creates an rbacv1.Subject from the given parameters.
// Helper for building BindDefinitionStatus.GeneratedServiceAccounts.
func GeneratedServiceAccountFrom(name, namespace string) rbacv1.Subject {
	return rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      name,
		Namespace: namespace,
	}
}

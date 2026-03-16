/*
Copyright © 2026 Deutsche Telekom AG.
*/
package indexer

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
)

const (
	// RoleDefinitionTargetNameField is the field index for RoleDefinition.Spec.TargetName.
	RoleDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// BindDefinitionTargetNameField is the field index for BindDefinition.Spec.TargetName.
	BindDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// WebhookAuthorizerHasNamespaceSelectorField indexes WebhookAuthorizer
	// resources by whether they define a non-empty namespace selector.
	// This allows the webhook handler to efficiently filter authorizers that
	// need namespace matching versus those that apply globally.
	WebhookAuthorizerHasNamespaceSelectorField = ".spec.hasNamespaceSelector"

	// RestrictedBindDefinitionPolicyRefField indexes RestrictedBindDefinition
	// by the referenced RBACPolicy name for efficient reverse lookups.
	RestrictedBindDefinitionPolicyRefField = ".spec.policyRef.name"

	// RestrictedRoleDefinitionPolicyRefField indexes RestrictedRoleDefinition
	// by the referenced RBACPolicy name for efficient reverse lookups.
	RestrictedRoleDefinitionPolicyRefField = ".spec.policyRef.name"

	// RestrictedBindDefinitionTargetNameField indexes RestrictedBindDefinition
	// by TargetName for duplicate detection in webhook validation.
	RestrictedBindDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// RestrictedRoleDefinitionTargetNameField indexes RestrictedRoleDefinition
	// by TargetName for duplicate detection in webhook validation.
	RestrictedRoleDefinitionTargetNameField = authorizationv1alpha1.TargetNameField
)

// SetupIndexes registers field indexes on the manager's cache for efficient lookups.
// This should be called before starting the manager.
func SetupIndexes(ctx context.Context, mgr manager.Manager) error {
	// Index RoleDefinition by Spec.TargetName for duplicate detection in webhook validation
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RoleDefinition{},
		RoleDefinitionTargetNameField,
		func(obj client.Object) []string {
			rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
			if !ok || rd.Spec.TargetName == "" {
				return nil
			}
			return []string{rd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for RoleDefinition.Spec.TargetName: %w", err)
	}

	// Index BindDefinition by Spec.TargetName for duplicate detection in webhook validation
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.BindDefinition{},
		BindDefinitionTargetNameField,
		func(obj client.Object) []string {
			bd, ok := obj.(*authorizationv1alpha1.BindDefinition)
			if !ok || bd.Spec.TargetName == "" {
				return nil
			}
			return []string{bd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for BindDefinition.Spec.TargetName: %w", err)
	}

	// Index WebhookAuthorizer by whether a namespace selector is set.
	// This enables the webhook handler to efficiently query only those
	// authorizers that require namespace matching, avoiding full scans
	// on every SubjectAccessReview evaluation.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.WebhookAuthorizer{},
		WebhookAuthorizerHasNamespaceSelectorField,
		WebhookAuthorizerHasNamespaceSelectorFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for WebhookAuthorizer.Spec.HasNamespaceSelector: %w", err)
	}

	// Index RestrictedBindDefinition by PolicyRef.Name for reverse lookups from RBACPolicy.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionPolicyRefField,
		RestrictedBindDefinitionPolicyRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.PolicyRef.Name: %w", err)
	}

	// Index RestrictedBindDefinition by TargetName for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionTargetNameField,
		func(obj client.Object) []string {
			rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
			if !ok || rbd.Spec.TargetName == "" {
				return nil
			}
			return []string{rbd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.TargetName: %w", err)
	}

	// Index RestrictedRoleDefinition by PolicyRef.Name for reverse lookups from RBACPolicy.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionPolicyRefField,
		RestrictedRoleDefinitionPolicyRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.PolicyRef.Name: %w", err)
	}

	// Index RestrictedRoleDefinition by TargetName for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionTargetNameField,
		func(obj client.Object) []string {
			rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
			if !ok || rrd.Spec.TargetName == "" {
				return nil
			}
			return []string{rrd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.TargetName: %w", err)
	}

	return nil
}

// WebhookAuthorizerHasNamespaceSelectorFunc extracts the index value for
// the hasNamespaceSelector field. Exported for testing and fake client setup.
func WebhookAuthorizerHasNamespaceSelectorFunc(obj client.Object) []string {
	wa, ok := obj.(*authorizationv1alpha1.WebhookAuthorizer)
	if !ok {
		return nil
	}
	if helpers.IsLabelSelectorEmpty(&wa.Spec.NamespaceSelector) {
		return []string{"false"}
	}
	return []string{"true"}
}

// RestrictedBindDefinitionPolicyRefFunc extracts the RBACPolicy name from a
// RestrictedBindDefinition for field indexing. Exported for testing and fake client setup.
func RestrictedBindDefinitionPolicyRefFunc(obj client.Object) []string {
	rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
	if !ok || rbd.Spec.PolicyRef.Name == "" {
		return nil
	}
	return []string{rbd.Spec.PolicyRef.Name}
}

// RestrictedRoleDefinitionPolicyRefFunc extracts the RBACPolicy name from a
// RestrictedRoleDefinition for field indexing. Exported for testing and fake client setup.
func RestrictedRoleDefinitionPolicyRefFunc(obj client.Object) []string {
	rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
	if !ok || rrd.Spec.PolicyRef.Name == "" {
		return nil
	}
	return []string{rrd.Spec.PolicyRef.Name}
}

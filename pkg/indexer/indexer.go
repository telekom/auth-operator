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
	RoleDefinitionTargetNameField = ".spec.targetName"

	// BindDefinitionTargetNameField is the field index for BindDefinition.Spec.TargetName.
	BindDefinitionTargetNameField = ".spec.targetName"

	// WebhookAuthorizerHasNamespaceSelectorField indexes WebhookAuthorizer
	// resources by whether they define a non-empty namespace selector.
	// This allows the webhook handler to efficiently filter authorizers that
	// need namespace matching versus those that apply globally.
	WebhookAuthorizerHasNamespaceSelectorField = ".spec.hasNamespaceSelector"
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

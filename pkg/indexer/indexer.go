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
)

const (
	// RoleDefinitionTargetNameField is the field index for RoleDefinition.Spec.TargetName.
	RoleDefinitionTargetNameField = ".spec.targetName"

	// BindDefinitionTargetNameField is the field index for BindDefinition.Spec.TargetName.
	BindDefinitionTargetNameField = ".spec.targetName"
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

	return nil
}

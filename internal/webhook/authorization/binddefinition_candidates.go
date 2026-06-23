// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func freshBindDefinitionsWithRoleBindings(ctx context.Context, cachedReader, liveReader client.Reader) ([]authorizationv1alpha1.BindDefinition, error) {
	if liveReader == nil {
		liveReader = cachedReader
	}

	candidates, err := cachedBindDefinitionsWithRoleBindings(ctx, cachedReader)
	if err != nil {
		return nil, err
	}

	fresh := make([]authorizationv1alpha1.BindDefinition, 0, len(candidates))
	for i := range candidates {
		current := &authorizationv1alpha1.BindDefinition{}
		if err := liveReader.Get(ctx, client.ObjectKey{Name: candidates[i].Name}, current); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		if len(current.Spec.RoleBindings) == 0 {
			continue
		}
		fresh = append(fresh, *current)
	}
	return fresh, nil
}

func cachedBindDefinitionsWithRoleBindings(ctx context.Context, reader client.Reader) ([]authorizationv1alpha1.BindDefinition, error) {
	indexed := &authorizationv1alpha1.BindDefinitionList{}
	if err := reader.List(ctx, indexed, client.MatchingFields{
		indexer.BindDefinitionHasRoleBindingsField: indexer.BindDefinitionHasRoleBindingsTrue,
	}); err != nil {
		if !isFieldIndexError(err) {
			return nil, err
		}
		return listAllCachedBindDefinitionsWithRoleBindings(ctx, reader)
	}
	return indexed.Items, nil
}

func listAllCachedBindDefinitionsWithRoleBindings(ctx context.Context, reader client.Reader) ([]authorizationv1alpha1.BindDefinition, error) {
	all := &authorizationv1alpha1.BindDefinitionList{}
	if err := reader.List(ctx, all); err != nil {
		return nil, err
	}
	filtered := all.Items[:0]
	for _, bindDefinition := range all.Items {
		if len(bindDefinition.Spec.RoleBindings) > 0 {
			filtered = append(filtered, bindDefinition)
		}
	}
	return filtered, nil
}

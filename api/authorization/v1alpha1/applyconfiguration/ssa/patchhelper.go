// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"fmt"
	"slices"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	ac "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

// PatchApplyRoleDefinitionStatus compares the desired RoleDefinition status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyRoleDefinitionStatus(ctx context.Context, c client.Client, rd *authv1alpha1.RoleDefinition) (pkgssa.PatchApplyResult, error) {
	if rd == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("roleDefinition must not be nil")
	}
	if rd.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("roleDefinition must have a name")
	}

	logger := log.FromContext(ctx)

	// Read the cached copy to compare.
	var cached authv1alpha1.RoleDefinition
	if err := c.Get(ctx, types.NamespacedName{Name: rd.Name, Namespace: rd.Namespace}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			// Object gone — fall through to Apply which will return a clear
			// error from the API server.
			logger.V(2).Info("RoleDefinition not in cache, applying status unconditionally", "name", rd.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached RoleDefinition %s: %w", rd.Name, err)
		}
	} else if roleDefinitionStatusEqual(&cached.Status, &rd.Status) {
		logger.V(2).Info("RoleDefinition status unchanged, skipping apply", "name", rd.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.RoleDefinition(rd.Name, rd.Namespace).
		WithStatus(RoleDefinitionStatusFrom(&rd.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply RoleDefinition %s status: %w", rd.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// PatchApplyBindDefinitionStatus compares the desired BindDefinition status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyBindDefinitionStatus(ctx context.Context, c client.Client, bd *authv1alpha1.BindDefinition) (pkgssa.PatchApplyResult, error) {
	if bd == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("bindDefinition must not be nil")
	}
	if bd.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("bindDefinition must have a name")
	}

	logger := log.FromContext(ctx)

	var cached authv1alpha1.BindDefinition
	if err := c.Get(ctx, types.NamespacedName{Name: bd.Name, Namespace: bd.Namespace}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("BindDefinition not in cache, applying status unconditionally", "name", bd.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached BindDefinition %s: %w", bd.Name, err)
		}
	} else if bindDefinitionStatusEqual(&cached.Status, &bd.Status) {
		logger.V(2).Info("BindDefinition status unchanged, skipping apply", "name", bd.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.BindDefinition(bd.Name, bd.Namespace).
		WithStatus(BindDefinitionStatusFrom(&bd.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply BindDefinition %s status: %w", bd.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// PatchApplyWebhookAuthorizerStatus compares the desired WebhookAuthorizer status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyWebhookAuthorizerStatus(ctx context.Context, c client.Client, wa *authv1alpha1.WebhookAuthorizer) (pkgssa.PatchApplyResult, error) {
	if wa == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("webhookAuthorizer must not be nil")
	}
	if wa.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("webhookAuthorizer must have a name")
	}

	logger := log.FromContext(ctx)

	var cached authv1alpha1.WebhookAuthorizer
	if err := c.Get(ctx, types.NamespacedName{Name: wa.Name, Namespace: wa.Namespace}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("WebhookAuthorizer not in cache, applying status unconditionally", "name", wa.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached WebhookAuthorizer %s: %w", wa.Name, err)
		}
	} else if webhookAuthorizerStatusEqual(&cached.Status, &wa.Status) {
		logger.V(2).Info("WebhookAuthorizer status unchanged, skipping apply", "name", wa.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.WebhookAuthorizer(wa.Name, wa.Namespace).
		WithStatus(WebhookAuthorizerStatusFrom(&wa.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply WebhookAuthorizer %s status: %w", wa.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// roleDefinitionStatusEqual compares two RoleDefinitionStatus values for equality.
func roleDefinitionStatusEqual(a, b *authv1alpha1.RoleDefinitionStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.RoleReconciled != b.RoleReconciled {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// bindDefinitionStatusEqual compares two BindDefinitionStatus values for equality.
func bindDefinitionStatusEqual(a, b *authv1alpha1.BindDefinitionStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.BindReconciled != b.BindReconciled {
		return false
	}
	if !subjectsEqual(a.GeneratedServiceAccounts, b.GeneratedServiceAccounts) {
		return false
	}
	if !slices.Equal(a.MissingRoleRefs, b.MissingRoleRefs) {
		return false
	}
	if !slices.Equal(a.ExternalServiceAccounts, b.ExternalServiceAccounts) {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// webhookAuthorizerStatusEqual compares two WebhookAuthorizerStatus values for equality.
func webhookAuthorizerStatusEqual(a, b *authv1alpha1.WebhookAuthorizerStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.AuthorizerConfigured != b.AuthorizerConfigured {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// conditionsEqual compares two condition slices.
// Condition comparison ignores LastTransitionTime when all other fields match,
// because LastTransitionTime is set by the conditions helper based on whether
// the condition is new or changed.
func conditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type ||
			a[i].Status != b[i].Status ||
			a[i].Reason != b[i].Reason ||
			a[i].Message != b[i].Message ||
			a[i].ObservedGeneration != b[i].ObservedGeneration {
			return false
		}
	}
	return true
}

// subjectsEqual compares two Subject slices for equality.
func subjectsEqual(a, b []rbacv1.Subject) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PatchApplyRBACPolicyStatus compares the desired RBACPolicy status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRBACPolicyStatus(ctx context.Context, c client.Client, rp *authv1alpha1.RBACPolicy) (pkgssa.PatchApplyResult, error) {
	if rp == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("rbacPolicy must not be nil")
	}
	if rp.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("rbacPolicy must have a name")
	}

	logger := log.FromContext(ctx)

	var cached authv1alpha1.RBACPolicy
	if err := c.Get(ctx, types.NamespacedName{Name: rp.Name}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RBACPolicy not in cache, applying status unconditionally", "name", rp.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached RBACPolicy %s: %w", rp.Name, err)
		}
	} else if rbacPolicyStatusEqual(&cached.Status, &rp.Status) {
		logger.V(2).Info("RBACPolicy status unchanged, skipping apply", "name", rp.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.RBACPolicy(rp.Name, rp.Namespace).
		WithStatus(RBACPolicyStatusFrom(&rp.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply RBACPolicy %s status: %w", rp.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// PatchApplyRestrictedBindDefinitionStatus compares the desired RestrictedBindDefinition status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRestrictedBindDefinitionStatus(ctx context.Context, c client.Client, rbd *authv1alpha1.RestrictedBindDefinition) (pkgssa.PatchApplyResult, error) {
	if rbd == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("restrictedBindDefinition must not be nil")
	}
	if rbd.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("restrictedBindDefinition must have a name")
	}

	logger := log.FromContext(ctx)

	var cached authv1alpha1.RestrictedBindDefinition
	if err := c.Get(ctx, types.NamespacedName{Name: rbd.Name}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RestrictedBindDefinition not in cache, applying status unconditionally", "name", rbd.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached RestrictedBindDefinition %s: %w", rbd.Name, err)
		}
	} else if restrictedBindDefinitionStatusEqual(&cached.Status, &rbd.Status) {
		logger.V(2).Info("RestrictedBindDefinition status unchanged, skipping apply", "name", rbd.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.RestrictedBindDefinition(rbd.Name, rbd.Namespace).
		WithStatus(RestrictedBindDefinitionStatusFrom(&rbd.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply RestrictedBindDefinition %s status: %w", rbd.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// PatchApplyRestrictedRoleDefinitionStatus compares the desired RestrictedRoleDefinition status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRestrictedRoleDefinitionStatus(ctx context.Context, c client.Client, rrd *authv1alpha1.RestrictedRoleDefinition) (pkgssa.PatchApplyResult, error) {
	if rrd == nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("restrictedRoleDefinition must not be nil")
	}
	if rrd.Name == "" {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("restrictedRoleDefinition must have a name")
	}

	logger := log.FromContext(ctx)

	var cached authv1alpha1.RestrictedRoleDefinition
	if err := c.Get(ctx, types.NamespacedName{Name: rrd.Name}, &cached); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(2).Info("RestrictedRoleDefinition not in cache, applying status unconditionally", "name", rrd.Name)
		} else {
			return pkgssa.PatchApplyResultPatched, fmt.Errorf("get cached RestrictedRoleDefinition %s: %w", rrd.Name, err)
		}
	} else if restrictedRoleDefinitionStatusEqual(&cached.Status, &rrd.Status) {
		logger.V(2).Info("RestrictedRoleDefinition status unchanged, skipping apply", "name", rrd.Name)
		return pkgssa.PatchApplyResultSkipped, nil
	}

	applyConfig := ac.RestrictedRoleDefinition(rrd.Name, rrd.Namespace).
		WithStatus(RestrictedRoleDefinitionStatusFrom(&rrd.Status))

	if err := applyStatus(ctx, c, applyConfig); err != nil {
		return pkgssa.PatchApplyResultPatched, fmt.Errorf("apply RestrictedRoleDefinition %s status: %w", rrd.Name, err)
	}
	return pkgssa.PatchApplyResultPatched, nil
}

// rbacPolicyStatusEqual compares two RBACPolicyStatus values for equality.
func rbacPolicyStatusEqual(a, b *authv1alpha1.RBACPolicyStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.BoundResourceCount != b.BoundResourceCount {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// restrictedBindDefinitionStatusEqual compares two RestrictedBindDefinitionStatus values for equality.
func restrictedBindDefinitionStatusEqual(a, b *authv1alpha1.RestrictedBindDefinitionStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.BindReconciled != b.BindReconciled {
		return false
	}
	if !subjectsEqual(a.GeneratedServiceAccounts, b.GeneratedServiceAccounts) {
		return false
	}
	if !slices.Equal(a.MissingRoleRefs, b.MissingRoleRefs) {
		return false
	}
	if !slices.Equal(a.ExternalServiceAccounts, b.ExternalServiceAccounts) {
		return false
	}
	if !slices.Equal(a.PolicyViolations, b.PolicyViolations) {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// restrictedRoleDefinitionStatusEqual compares two RestrictedRoleDefinitionStatus values for equality.
func restrictedRoleDefinitionStatusEqual(a, b *authv1alpha1.RestrictedRoleDefinitionStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.RoleReconciled != b.RoleReconciled {
		return false
	}
	if !slices.Equal(a.PolicyViolations, b.PolicyViolations) {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

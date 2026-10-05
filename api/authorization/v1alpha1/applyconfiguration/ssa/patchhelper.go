// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	libraryssa "github.com/telekom/t-caas-go-library/pkg/ssa"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	ac "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

var (
	roleDefinitionStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.RoleDefinition, *ac.RoleDefinitionApplyConfiguration]{
		Kind:       "RoleDefinition",
		FieldOwner: FieldOwner,
		New:        func() *authorizationv1alpha1.RoleDefinition { return &authorizationv1alpha1.RoleDefinition{} },
		Equal: func(cached, desired *authorizationv1alpha1.RoleDefinition) bool {
			return roleDefinitionStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(rd *authorizationv1alpha1.RoleDefinition) *ac.RoleDefinitionApplyConfiguration {
			return ac.RoleDefinition(rd.Name).WithStatus(RoleDefinitionStatusFrom(&rd.Status))
		},
	}
	bindDefinitionStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.BindDefinition, *ac.BindDefinitionApplyConfiguration]{
		Kind:       "BindDefinition",
		FieldOwner: FieldOwner,
		New:        func() *authorizationv1alpha1.BindDefinition { return &authorizationv1alpha1.BindDefinition{} },
		Equal: func(cached, desired *authorizationv1alpha1.BindDefinition) bool {
			return bindDefinitionStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(bd *authorizationv1alpha1.BindDefinition) *ac.BindDefinitionApplyConfiguration {
			return ac.BindDefinition(bd.Name).WithStatus(BindDefinitionStatusFrom(&bd.Status))
		},
	}
	webhookAuthorizerStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.WebhookAuthorizer, *ac.WebhookAuthorizerApplyConfiguration]{
		Kind:       "WebhookAuthorizer",
		FieldOwner: FieldOwner,
		New:        func() *authorizationv1alpha1.WebhookAuthorizer { return &authorizationv1alpha1.WebhookAuthorizer{} },
		Equal: func(cached, desired *authorizationv1alpha1.WebhookAuthorizer) bool {
			return webhookAuthorizerStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(wa *authorizationv1alpha1.WebhookAuthorizer) *ac.WebhookAuthorizerApplyConfiguration {
			return ac.WebhookAuthorizer(wa.Name).WithStatus(WebhookAuthorizerStatusFrom(&wa.Status))
		},
	}
	rbacPolicyStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.RBACPolicy, *ac.RBACPolicyApplyConfiguration]{
		Kind:       "RBACPolicy",
		FieldOwner: FieldOwner,
		New:        func() *authorizationv1alpha1.RBACPolicy { return &authorizationv1alpha1.RBACPolicy{} },
		Equal: func(cached, desired *authorizationv1alpha1.RBACPolicy) bool {
			return rbacPolicyStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(rp *authorizationv1alpha1.RBACPolicy) *ac.RBACPolicyApplyConfiguration {
			return ac.RBACPolicy(rp.Name).WithStatus(RBACPolicyStatusFrom(&rp.Status))
		},
	}
	restrictedBindDefinitionStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.RestrictedBindDefinition, *ac.RestrictedBindDefinitionApplyConfiguration]{
		Kind:       "RestrictedBindDefinition",
		FieldOwner: FieldOwner,
		New: func() *authorizationv1alpha1.RestrictedBindDefinition {
			return &authorizationv1alpha1.RestrictedBindDefinition{}
		},
		Equal: func(cached, desired *authorizationv1alpha1.RestrictedBindDefinition) bool {
			return restrictedBindDefinitionStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(rbd *authorizationv1alpha1.RestrictedBindDefinition) *ac.RestrictedBindDefinitionApplyConfiguration {
			return ac.RestrictedBindDefinition(rbd.Name).WithStatus(RestrictedBindDefinitionStatusFrom(&rbd.Status))
		},
	}
	restrictedRoleDefinitionStatusApplier = libraryssa.StatusApplier[*authorizationv1alpha1.RestrictedRoleDefinition, *ac.RestrictedRoleDefinitionApplyConfiguration]{
		Kind:       "RestrictedRoleDefinition",
		FieldOwner: FieldOwner,
		New: func() *authorizationv1alpha1.RestrictedRoleDefinition {
			return &authorizationv1alpha1.RestrictedRoleDefinition{}
		},
		Equal: func(cached, desired *authorizationv1alpha1.RestrictedRoleDefinition) bool {
			return restrictedRoleDefinitionStatusEqual(&cached.Status, &desired.Status)
		},
		ApplyConfiguration: func(rrd *authorizationv1alpha1.RestrictedRoleDefinition) *ac.RestrictedRoleDefinitionApplyConfiguration {
			return ac.RestrictedRoleDefinition(rrd.Name).WithStatus(RestrictedRoleDefinitionStatusFrom(&rrd.Status))
		},
		BeforeApply: clearRestrictedRoleDefinitionEmptyStatusSlices,
	}
)

// PatchApplyRoleDefinitionStatus compares the desired RoleDefinition status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyRoleDefinitionStatus(ctx context.Context, c client.Client, rd *authorizationv1alpha1.RoleDefinition) (pkgssa.PatchApplyResult, error) {
	return roleDefinitionStatusApplier.PatchApply(ctx, c, rd)
}

// PatchApplyBindDefinitionStatus compares the desired BindDefinition status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyBindDefinitionStatus(ctx context.Context, c client.Client, bd *authorizationv1alpha1.BindDefinition) (pkgssa.PatchApplyResult, error) {
	return bindDefinitionStatusApplier.PatchApply(ctx, c, bd)
}

// PatchApplyWebhookAuthorizerStatus compares the desired WebhookAuthorizer status
// against the cached version and skips the API call when nothing changed.
// Returns PatchApplyResultSkipped when the status is already up-to-date.
func PatchApplyWebhookAuthorizerStatus(ctx context.Context, c client.Client, wa *authorizationv1alpha1.WebhookAuthorizer) (pkgssa.PatchApplyResult, error) {
	return webhookAuthorizerStatusApplier.PatchApply(ctx, c, wa)
}

// PatchApplyRBACPolicyStatus compares the desired RBACPolicy status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRBACPolicyStatus(ctx context.Context, c client.Client, rp *authorizationv1alpha1.RBACPolicy) (pkgssa.PatchApplyResult, error) {
	return rbacPolicyStatusApplier.PatchApply(ctx, c, rp)
}

// PatchApplyRestrictedBindDefinitionStatus compares the desired RestrictedBindDefinition status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRestrictedBindDefinitionStatus(ctx context.Context, c client.Client, rbd *authorizationv1alpha1.RestrictedBindDefinition) (pkgssa.PatchApplyResult, error) {
	return restrictedBindDefinitionStatusApplier.PatchApply(ctx, c, rbd)
}

// PatchApplyRestrictedRoleDefinitionStatus compares the desired RestrictedRoleDefinition status
// against the cached version and skips the API call when nothing changed.
func PatchApplyRestrictedRoleDefinitionStatus(ctx context.Context, c client.Client, rrd *authorizationv1alpha1.RestrictedRoleDefinition) (pkgssa.PatchApplyResult, error) {
	return restrictedRoleDefinitionStatusApplier.PatchApply(ctx, c, rrd)
}

// roleDefinitionStatusEqual compares two RoleDefinitionStatus values for equality.
func roleDefinitionStatusEqual(a, b *authorizationv1alpha1.RoleDefinitionStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.RoleReconciled != b.RoleReconciled {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// bindDefinitionStatusEqual compares two BindDefinitionStatus values for equality.
func bindDefinitionStatusEqual(a, b *authorizationv1alpha1.BindDefinitionStatus) bool {
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
	if !slices.Equal(a.SkippedServiceAccounts, b.SkippedServiceAccounts) {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// webhookAuthorizerStatusEqual compares two WebhookAuthorizerStatus values for equality.
func webhookAuthorizerStatusEqual(a, b *authorizationv1alpha1.WebhookAuthorizerStatus) bool {
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

func clearRestrictedRoleDefinitionEmptyStatusSlices(
	ctx context.Context,
	c client.Client,
	cached *authorizationv1alpha1.RestrictedRoleDefinition,
	desired *authorizationv1alpha1.RestrictedRoleDefinition,
) error {
	statusPatch := map[string]any{}
	addClear := func(field string, desiredLen, cachedLen int) {
		if desiredLen == 0 && cachedLen > 0 {
			statusPatch[field] = []any{}
		}
	}
	addClear("policyViolations", len(desired.Status.PolicyViolations), len(cached.Status.PolicyViolations))
	addClear("conditions", len(desired.Status.Conditions), len(cached.Status.Conditions))
	if len(statusPatch) == 0 {
		return nil
	}

	patch, err := json.Marshal(map[string]any{"status": statusPatch})
	if err != nil {
		return fmt.Errorf("marshal RestrictedRoleDefinition status clear patch: %w", err)
	}
	target := &authorizationv1alpha1.RestrictedRoleDefinition{}
	target.Name = desired.Name
	target.Namespace = desired.Namespace
	if err := c.Status().Patch(ctx, target, client.RawPatch(types.MergePatchType, patch)); err != nil {
		return fmt.Errorf("clear RestrictedRoleDefinition %s empty status slices: %w", desired.Name, err)
	}
	return nil
}

// rbacPolicyStatusEqual compares two RBACPolicyStatus values for equality.
func rbacPolicyStatusEqual(a, b *authorizationv1alpha1.RBACPolicyStatus) bool {
	if a.ObservedGeneration != b.ObservedGeneration {
		return false
	}
	if a.BoundResourceCount != b.BoundResourceCount {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// restrictedBindDefinitionStatusEqual compares two RestrictedBindDefinitionStatus values for equality.
func restrictedBindDefinitionStatusEqual(a, b *authorizationv1alpha1.RestrictedBindDefinitionStatus) bool {
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
	if !slices.Equal(a.SkippedServiceAccounts, b.SkippedServiceAccounts) {
		return false
	}
	if !slices.Equal(a.PolicyViolations, b.PolicyViolations) {
		return false
	}
	return conditionsEqual(a.Conditions, b.Conditions)
}

// restrictedRoleDefinitionStatusEqual compares two RestrictedRoleDefinitionStatus values for equality.
func restrictedRoleDefinitionStatusEqual(a, b *authorizationv1alpha1.RestrictedRoleDefinitionStatus) bool {
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

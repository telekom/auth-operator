// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RestrictedRoleDefinitionValidator implements admission.Validator for RestrictedRoleDefinition.
// +kubebuilder:object:generate=false
type RestrictedRoleDefinitionValidator struct {
	Client client.Client
}

var _ admission.Validator[*RestrictedRoleDefinition] = &RestrictedRoleDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RestrictedRoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RestrictedRoleDefinitionValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-restrictedroledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions,verbs=create;update,versions=v1alpha1,name=restrictedroledefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateCreate(ctx context.Context, obj *RestrictedRoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, webhookValidationTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := v.validateRestrictedRoleDefinitionSpec(ctx, obj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists.
	return nil, v.validatePolicyRefExists(ctx, obj)
}

// ValidateUpdate implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RestrictedRoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, webhookValidationTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	// Enforce immutability of targetRole, targetName, and policyRef.
	var allErrs field.ErrorList
	if oldObj.Spec.TargetRole != newObj.Spec.TargetRole {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetRole"), "field is immutable after creation"))
	}
	if oldObj.Spec.TargetName != newObj.Spec.TargetName {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetName"), "field is immutable after creation"))
	}
	if oldObj.Spec.PolicyRef.Name != newObj.Spec.PolicyRef.Name {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "policyRef", "name"), "field is immutable after creation"))
	}
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
			newObj.Name, allErrs)
	}

	if err := v.validateRestrictedRoleDefinitionSpec(ctx, newObj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists.
	return nil, v.validatePolicyRefExists(ctx, newObj)
}

// ValidateDelete implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateDelete(_ context.Context, _ *RestrictedRoleDefinition) (admission.Warnings, error) {
	return nil, nil
}

// validateRestrictedRoleDefinitionSpec validates the spec for duplicate targetName.
func (v *RestrictedRoleDefinitionValidator) validateRestrictedRoleDefinitionSpec(ctx context.Context, obj *RestrictedRoleDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")

	// Check duplicate targetName (scoped to same targetRole). The field index constrains
	// results to matching items; the context timeout provides the hard latency bound.
	rrdList := &RestrictedRoleDefinitionList{}
	if err := v.Client.List(ctx, rrdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(fmt.Errorf("unable to list RestrictedRoleDefinitions: %w", err))
	}

	for _, existing := range rrdList.Items {
		if existing.Spec.TargetRole == obj.Spec.TargetRole && existing.Name != obj.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existing.Name)
			return apierrors.NewBadRequest(
				fmt.Sprintf("targetName %s already exists in RestrictedRoleDefinition %s", obj.Spec.TargetName, existing.Name))
		}
	}

	// Check for cross-type targetName collision with RoleDefinitions. The field index
	// constrains results; the context timeout provides the hard latency bound.
	rdList := &RoleDefinitionList{}
	if err := v.Client.List(ctx, rdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(fmt.Errorf("unable to list RoleDefinitions: %w", err))
	}
	for _, existing := range rdList.Items {
		if existing.Spec.TargetRole == obj.Spec.TargetRole {
			return apierrors.NewBadRequest(
				fmt.Sprintf("targetName %s already exists in RoleDefinition %s", obj.Spec.TargetName, existing.Name))
		}
	}

	// Validate restrictedAPIs versions follow the expected format.
	return validateRestrictedRoleDefinitionAPIsVersions(obj)
}

// validateRestrictedRoleDefinitionAPIsVersions ensures every version entry
// starts with 'v' and is at most 20 characters.
func validateRestrictedRoleDefinitionAPIsVersions(obj *RestrictedRoleDefinition) error {
	for i, group := range obj.Spec.RestrictedAPIs {
		for j, gv := range group.Versions {
			if !strings.HasPrefix(gv.Version, "v") || len(gv.Version) > 20 {
				return apierrors.NewInvalid(
					schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
					obj.Name,
					field.ErrorList{field.Invalid(
						field.NewPath("spec", "restrictedApis").Index(i).Child("versions").Index(j).Child("version"),
						gv.Version, "must start with 'v' and be at most 20 characters")})
			}
		}
	}
	return nil
}

// validatePolicyRefExists verifies that the referenced RBACPolicy exists.
// Full policy compliance evaluation is performed by the controller during reconciliation.
func (v *RestrictedRoleDefinitionValidator) validatePolicyRefExists(ctx context.Context, obj *RestrictedRoleDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")

	rbacPolicy := &RBACPolicy{}
	if err := v.Client.Get(ctx, client.ObjectKey{Name: obj.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return apierrors.NewBadRequest(
				fmt.Sprintf("referenced RBACPolicy %q does not exist", obj.Spec.PolicyRef.Name))
		}
		logger.Error(err, "failed to get RBACPolicy", "policyRef", obj.Spec.PolicyRef.Name)
		return apierrors.NewInternalError(fmt.Errorf("unable to get RBACPolicy: %w", err))
	}

	return nil
}

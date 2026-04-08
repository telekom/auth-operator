// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
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
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := v.validateRestrictedRoleDefinitionSpec(ctx, obj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists.
	if err := v.validatePolicyRefExists(ctx, obj); err != nil {
		return nil, err
	}

	// Enforce requester-based default policy assignment, if configured.
	if err := validateDefaultPolicyForRequester(
		ctx,
		v.Client,
		schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
		obj.Name,
		obj.Spec.PolicyRef.Name,
	); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RestrictedRoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	// Enforce immutability of targetRole, targetName, targetNamespace, and policyRef.
	var allErrs field.ErrorList
	if oldObj.Spec.TargetRole != newObj.Spec.TargetRole {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetRole"), "field is immutable after creation"))
	}
	if oldObj.Spec.TargetName != newObj.Spec.TargetName {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetName"), "field is immutable after creation"))
	}
	if oldObj.Spec.TargetNamespace != newObj.Spec.TargetNamespace {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetNamespace"), "field is immutable after creation"))
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
	if err := v.validatePolicyRefExists(ctx, newObj); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateDelete(_ context.Context, _ *RestrictedRoleDefinition) (admission.Warnings, error) {
	return nil, nil
}

// validateRestrictedRoleDefinitionSpec validates the spec for duplicate targetName.
func (v *RestrictedRoleDefinitionValidator) validateRestrictedRoleDefinitionSpec(ctx context.Context, obj *RestrictedRoleDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")

	// Check duplicate targetName. Collisions are scoped by targetRole and,
	// for Role targets, targetNamespace. The field index constrains
	// results to matching items; the context timeout provides the hard latency bound.
	rrdList := &RestrictedRoleDefinitionList{}
	if err := v.Client.List(ctx, rrdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(2)); err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "targetName", obj.Spec.TargetName)
		return listErrorToAdmission("RestrictedRoleDefinitions", err)
	}

	for _, existing := range rrdList.Items {
		if existing.Name != obj.Name &&
			roleTargetCollision(obj.Spec.TargetRole, obj.Spec.TargetNamespace, existing.Spec.TargetRole, existing.Spec.TargetNamespace) {
			logger.Info("validation failed: duplicate targetName",
				"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existing.Name)
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
				obj.Name,
				field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
					fmt.Sprintf("%s (already used by RestrictedRoleDefinition %q)", obj.Spec.TargetName, existing.Name))})
		}
	}

	// Check for cross-type targetName collision with RoleDefinitions (only need first match).
	// The field index constrains results; the context timeout provides the hard latency bound.
	rdList := &RoleDefinitionList{}
	if err := v.Client.List(ctx, rdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(1)); err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", obj.Spec.TargetName)
		return listErrorToAdmission("RoleDefinitions", err)
	}
	for _, existing := range rdList.Items {
		if roleTargetCollision(obj.Spec.TargetRole, obj.Spec.TargetNamespace, existing.Spec.TargetRole, existing.Spec.TargetNamespace) {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
				obj.Name,
				field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
					fmt.Sprintf("%s (already used by RoleDefinition %q)", obj.Spec.TargetName, existing.Name))})
		}
	}

	// Reject duplicate API group names in RestrictedAPIs — only the first entry
	// would take effect and subsequent entries would be silently ignored.
	if err := validateNoDuplicateRestrictedRRDAPIs(obj); err != nil {
		return err
	}

	// Validate restrictedAPIs versions follow the expected format.
	return validateRestrictedRoleDefinitionAPIsVersions(obj)
}

// validateNoDuplicateRestrictedRRDAPIs rejects duplicate API group names in RestrictedAPIs.
// Duplicate entries are ambiguous because only the first match is used during
// filtering — subsequent entries for the same group name are silently ignored.
func validateNoDuplicateRestrictedRRDAPIs(obj *RestrictedRoleDefinition) error {
	seen := make(map[string]int, len(obj.Spec.RestrictedAPIs))
	for i, group := range obj.Spec.RestrictedAPIs {
		if prev, ok := seen[group.Name]; ok {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
				obj.Name,
				field.ErrorList{field.Duplicate(
					field.NewPath("spec", "restrictedApis").Index(i).Child("name"),
					fmt.Sprintf("%q is already used at restrictedApis[%d]", group.Name, prev),
				)},
			)
		}
		seen[group.Name] = i
	}
	return nil
}

// validateRestrictedRoleDefinitionAPIsVersions ensures every version entry
// starts with 'v' and is at most maxVersionLength characters.
func validateRestrictedRoleDefinitionAPIsVersions(obj *RestrictedRoleDefinition) error {
	for i, group := range obj.Spec.RestrictedAPIs {
		for j, gv := range group.Versions {
			if !strings.HasPrefix(gv.Version, "v") || len(gv.Version) > maxVersionLength {
				return apierrors.NewInvalid(
					schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
					obj.Name,
					field.ErrorList{field.Invalid(
						field.NewPath("spec", "restrictedApis").Index(i).Child("versions").Index(j).Child("version"),
						gv.Version, fmt.Sprintf("must start with 'v' and be at most %d characters", maxVersionLength))})
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
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"},
				obj.Name,
				field.ErrorList{field.NotFound(
					field.NewPath("spec", "policyRef", "name"),
					obj.Spec.PolicyRef.Name,
				)},
			)
		}
		logger.Error(err, "failed to get RBACPolicy", "policyRef", obj.Spec.PolicyRef.Name)
		return apierrors.NewInternalError(errors.New("unable to validate policy reference"))
	}

	return nil
}

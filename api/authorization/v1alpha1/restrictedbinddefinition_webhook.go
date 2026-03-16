// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RestrictedBindDefinitionValidator implements admission.Validator for RestrictedBindDefinition.
// +kubebuilder:object:generate=false
type RestrictedBindDefinitionValidator struct {
	Client client.Client
}

var _ admission.Validator[*RestrictedBindDefinition] = &RestrictedBindDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RestrictedBindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RestrictedBindDefinitionValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-restrictedbinddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions,verbs=create;update,versions=v1alpha1,name=restrictedbinddefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateCreate(ctx context.Context, obj *RestrictedBindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := v.validateRestrictedBindDefinitionSpec(ctx, obj); err != nil {
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
		schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedBindDefinition"},
		obj.Name,
		obj.Spec.PolicyRef.Name,
	); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RestrictedBindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	// Enforce immutability of targetName and policyRef.
	var allErrs field.ErrorList
	if oldObj.Spec.TargetName != newObj.Spec.TargetName {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetName"), "field is immutable after creation"))
	}
	if oldObj.Spec.PolicyRef.Name != newObj.Spec.PolicyRef.Name {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "policyRef", "name"), "field is immutable after creation"))
	}
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedBindDefinition"},
			newObj.Name, allErrs)
	}

	if err := v.validateRestrictedBindDefinitionSpec(ctx, newObj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists.
	if err := v.validatePolicyRefExists(ctx, newObj); err != nil {
		return nil, err
	}

	// Enforce requester-based default policy assignment, if configured.
	if err := validateDefaultPolicyForRequester(
		ctx,
		v.Client,
		schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedBindDefinition"},
		newObj.Name,
		newObj.Spec.PolicyRef.Name,
	); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateDelete(_ context.Context, _ *RestrictedBindDefinition) (admission.Warnings, error) {
	return nil, nil
}

// validateRestrictedBindDefinitionSpec validates the spec for duplicate targetName
// and valid namespace selectors.
func (v *RestrictedBindDefinitionValidator) validateRestrictedBindDefinitionSpec(ctx context.Context, obj *RestrictedBindDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")

	// Check duplicate targetName. The field index constrains results to matching
	// items; the context timeout provides the hard latency bound.
	rbdList := &RestrictedBindDefinitionList{}
	if err := v.Client.List(ctx, rbdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(2)); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(fmt.Errorf("unable to list RestrictedBindDefinitions: %w", err))
	}

	for _, existing := range rbdList.Items {
		if existing.Name != obj.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existing.Name)
			return apierrors.NewBadRequest(
				fmt.Sprintf("targetName %s is already in use by RestrictedBindDefinition %q", obj.Spec.TargetName, existing.Name))
		}
	}

	// Check for cross-type targetName collision with BindDefinitions (only need first match).
	bdList := &BindDefinitionList{}
	if err := v.Client.List(ctx, bdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(1)); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(fmt.Errorf("unable to list BindDefinitions: %w", err))
	}
	for _, existing := range bdList.Items {
		return apierrors.NewBadRequest(
			fmt.Sprintf("targetName %s is already in use by BindDefinition %q", obj.Spec.TargetName, existing.Name))
	}

	// Validate subject Kinds are one of the RBAC-supported types.
	for i, subject := range obj.Spec.Subjects {
		switch subject.Kind {
		case rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind:
			// valid
		default:
			fldErr := field.NotSupported(field.NewPath("spec", "subjects").Index(i).Child("kind"), subject.Kind, supportedSubjectKinds)
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedBindDefinition"},
				obj.Name, field.ErrorList{fldErr})
		}
	}

	// Validate namespace selectors in roleBindings.
	for i, nb := range obj.Spec.RoleBindings {
		for j, sel := range nb.NamespaceSelector {
			if _, err := metav1.LabelSelectorAsSelector(&sel); err != nil {
				return apierrors.NewInvalid(
					schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedBindDefinition"},
					obj.Name,
					field.ErrorList{field.Invalid(
						field.NewPath("spec", "roleBindings").Index(i).Child("namespaceSelector").Index(j),
						sel, err.Error())})
			}
		}
	}

	return nil
}

// validatePolicyRefExists verifies that the referenced RBACPolicy exists.
// Full policy compliance evaluation is performed by the controller during reconciliation.
func (v *RestrictedBindDefinitionValidator) validatePolicyRefExists(ctx context.Context, obj *RestrictedBindDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")

	rbacPolicy := &RBACPolicy{}
	if err := v.Client.Get(ctx, client.ObjectKey{Name: obj.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return apierrors.NewBadRequest(
				fmt.Sprintf("referenced RBACPolicy %q does not exist", obj.Spec.PolicyRef.Name))
		}
		logger.Error(err, "failed to get RBACPolicy", "policyRef", obj.Spec.PolicyRef.Name)
		return apierrors.NewInternalError(fmt.Errorf("unable to get RBACPolicy %q: %w", obj.Spec.PolicyRef.Name, err))
	}

	return nil
}

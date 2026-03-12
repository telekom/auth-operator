// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// PolicyRefField is the field index path for lookups by policy reference name.
// This must match the index registered in pkg/indexer.
const PolicyRefField = ".spec.policyRef.name"

// RBACPolicyValidator implements admission.Validator for RBACPolicy.
// +kubebuilder:object:generate=false
type RBACPolicyValidator struct {
	Client client.Client
}

var _ admission.Validator[*RBACPolicy] = &RBACPolicyValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RBACPolicy) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RBACPolicyValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-rbacpolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=rbacpolicies,verbs=create;update;delete,versions=v1alpha1,name=rbacpolicy.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for RBACPolicy.
func (v *RBACPolicyValidator) ValidateCreate(ctx context.Context, obj *RBACPolicy) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("rbacpolicy-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := validateRBACPolicySpec(obj); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator for RBACPolicy.
func (v *RBACPolicyValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RBACPolicy) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("rbacpolicy-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	if err := validateRBACPolicySpec(newObj); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateDelete checks if any RestrictedBindDefinitions or RestrictedRoleDefinitions
// still reference this policy. If so, deletion is blocked.
func (v *RBACPolicyValidator) ValidateDelete(ctx context.Context, obj *RBACPolicy) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("rbacpolicy-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)

	// Check for bound RestrictedBindDefinitions.
	rbdList := &RestrictedBindDefinitionList{}
	if err := v.Client.List(ctx, rbdList, client.MatchingFields{
		PolicyRefField: obj.Name,
	}); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions")
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list RestrictedBindDefinitions: %w", err))
	}

	// Check for bound RestrictedRoleDefinitions.
	rrdList := &RestrictedRoleDefinitionList{}
	if err := v.Client.List(ctx, rrdList, client.MatchingFields{
		PolicyRefField: obj.Name,
	}); err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions")
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list RestrictedRoleDefinitions: %w", err))
	}

	total := len(rbdList.Items) + len(rrdList.Items)
	if total > 0 {
		return nil, apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "rbacpolicies"},
			obj.Name,
			fmt.Errorf("cannot delete: %d resource(s) still reference this policy", total),
		)
	}

	return nil, nil
}

// validateRBACPolicySpec validates the semantic correctness of the RBACPolicy spec
// beyond what CEL/kubebuilder markers can express.
func validateRBACPolicySpec(obj *RBACPolicy) error {
	var allErrs field.ErrorList

	// Validate appliesTo label selector.
	if obj.Spec.AppliesTo.NamespaceSelector != nil {
		if _, err := metav1.LabelSelectorAsSelector(obj.Spec.AppliesTo.NamespaceSelector); err != nil {
			allErrs = append(allErrs, field.Invalid(
				field.NewPath("spec", "appliesTo", "namespaceSelector"),
				obj.Spec.AppliesTo.NamespaceSelector, err.Error()))
		}
	}

	// Validate label selectors in binding limits.
	if bl := obj.Spec.BindingLimits; bl != nil {
		allErrs = append(allErrs, validateRoleRefLimitsSelectors(bl.ClusterRoleBindingLimits,
			field.NewPath("spec", "bindingLimits", "clusterRoleBindingLimits"))...)
		allErrs = append(allErrs, validateRoleRefLimitsSelectors(bl.RoleBindingLimits,
			field.NewPath("spec", "bindingLimits", "roleBindingLimits"))...)

		if bl.TargetNamespaceLimits != nil && bl.TargetNamespaceLimits.AllowedNamespaceSelector != nil {
			if _, err := metav1.LabelSelectorAsSelector(bl.TargetNamespaceLimits.AllowedNamespaceSelector); err != nil {
				allErrs = append(allErrs, field.Invalid(
					field.NewPath("spec", "bindingLimits", "targetNamespaceLimits", "allowedNamespaceSelector"),
					bl.TargetNamespaceLimits.AllowedNamespaceSelector, err.Error()))
			}
		}
		if bl.TargetNamespaceLimits != nil {
			for i, v := range bl.TargetNamespaceLimits.ForbiddenNamespacePrefixes {
				if v == "" {
					allErrs = append(allErrs, field.Invalid(
						field.NewPath("spec", "bindingLimits", "targetNamespaceLimits", "forbiddenNamespacePrefixes").Index(i),
						v, "must not be empty"))
				}
			}
		}
	}

	// Validate label selectors in subject limits.
	if sl := obj.Spec.SubjectLimits; sl != nil {
		allErrs = append(allErrs, validateNameMatchLimits(sl.UserLimits,
			field.NewPath("spec", "subjectLimits", "userLimits"))...)
		allErrs = append(allErrs, validateNameMatchLimits(sl.GroupLimits,
			field.NewPath("spec", "subjectLimits", "groupLimits"))...)
		if sl.ServiceAccountLimits != nil {
			if sl.ServiceAccountLimits.AllowedNamespaceSelector != nil {
				if _, err := metav1.LabelSelectorAsSelector(sl.ServiceAccountLimits.AllowedNamespaceSelector); err != nil {
					allErrs = append(allErrs, field.Invalid(
						field.NewPath("spec", "subjectLimits", "serviceAccountLimits", "allowedNamespaceSelector"),
						sl.ServiceAccountLimits.AllowedNamespaceSelector, err.Error()))
				}
			}
			for i, v := range sl.ServiceAccountLimits.ForbiddenNamespacePrefixes {
				if v == "" {
					allErrs = append(allErrs, field.Invalid(
						field.NewPath("spec", "subjectLimits", "serviceAccountLimits", "forbiddenNamespacePrefixes").Index(i),
						v, "must not be empty"))
				}
			}
			if sl.ServiceAccountLimits.Creation != nil && sl.ServiceAccountLimits.Creation.AllowedCreationNamespaceSelector != nil {
				if _, err := metav1.LabelSelectorAsSelector(sl.ServiceAccountLimits.Creation.AllowedCreationNamespaceSelector); err != nil {
					allErrs = append(allErrs, field.Invalid(
						field.NewPath("spec", "subjectLimits", "serviceAccountLimits", "creation", "allowedCreationNamespaceSelector"),
						sl.ServiceAccountLimits.Creation.AllowedCreationNamespaceSelector, err.Error()))
				}
			}
		}

		allErrs = append(allErrs, validateSubjectKinds(sl.AllowedKinds,
			field.NewPath("spec", "subjectLimits", "allowedKinds"))...)
		allErrs = append(allErrs, validateSubjectKinds(sl.ForbiddenKinds,
			field.NewPath("spec", "subjectLimits", "forbiddenKinds"))...)
	}

	if len(allErrs) > 0 {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RBACPolicy"},
			obj.Name, allErrs)
	}

	return nil
}

// validateRoleRefLimitsSelectors validates label selectors within RoleRefLimits.
func validateRoleRefLimitsSelectors(limits *RoleRefLimits, fldPath *field.Path) field.ErrorList {
	if limits == nil {
		return nil
	}

	var allErrs field.ErrorList
	if limits.AllowedRoleRefSelector != nil {
		if _, err := metav1.LabelSelectorAsSelector(limits.AllowedRoleRefSelector); err != nil {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("allowedRoleRefSelector"),
				limits.AllowedRoleRefSelector, err.Error()))
		}
	}
	if limits.ForbiddenRoleRefSelector != nil {
		if _, err := metav1.LabelSelectorAsSelector(limits.ForbiddenRoleRefSelector); err != nil {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("forbiddenRoleRefSelector"),
				limits.ForbiddenRoleRefSelector, err.Error()))
		}
	}
	return allErrs
}

// validateNameMatchLimits validates that prefix and suffix arrays in NameMatchLimits
// do not contain empty strings (which would match everything).
func validateNameMatchLimits(limits *NameMatchLimits, fldPath *field.Path) field.ErrorList {
	if limits == nil {
		return nil
	}
	var allErrs field.ErrorList
	for i, v := range limits.ForbiddenPrefixes {
		if v == "" {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("forbiddenPrefixes").Index(i), v, "must not be empty"))
		}
	}
	for i, v := range limits.ForbiddenSuffixes {
		if v == "" {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("forbiddenSuffixes").Index(i), v, "must not be empty"))
		}
	}
	for i, v := range limits.AllowedPrefixes {
		if v == "" {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("allowedPrefixes").Index(i), v, "must not be empty"))
		}
	}
	for i, v := range limits.AllowedSuffixes {
		if v == "" {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("allowedSuffixes").Index(i), v, "must not be empty"))
		}
	}
	return allErrs
}

// validSubjectKinds lists the valid RBAC subject kinds.
var validSubjectKinds = []string{"User", "Group", "ServiceAccount"}

// validateSubjectKinds validates that all entries in a subject kind list are valid.
func validateSubjectKinds(kinds []string, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList
	for i, kind := range kinds {
		valid := false
		for _, vk := range validSubjectKinds {
			if kind == vk {
				valid = true
				break
			}
		}
		if !valid {
			allErrs = append(allErrs, field.NotSupported(
				fldPath.Index(i), kind, validSubjectKinds))
		}
	}
	return allErrs
}

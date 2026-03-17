// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
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

const (
	// PolicyRefField is the field index path for lookups by policy reference name.
	// This must match the index registered in pkg/indexer.
	PolicyRefField = ".spec.policyRef.name"

	// HasDefaultAssignmentField indexes RBACPolicy by whether defaultAssignment is set.
	// Used by admission-time default-policy enforcement to avoid full-policy scans.
	HasDefaultAssignmentField = ".spec.hasDefaultAssignment"
)

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
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("rbacpolicy-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)

	// Check for bound RestrictedBindDefinitions. Only need to check existence,
	// not count — Limit(1) avoids loading all referencing resources.
	rbdList := &RestrictedBindDefinitionList{}
	if err := v.Client.List(ctx, rbdList, client.MatchingFields{
		PolicyRefField: obj.Name,
	}, client.Limit(1)); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions")
		return nil, apierrors.NewInternalError(errors.New("unable to list RestrictedBindDefinitions"))
	}
	if len(rbdList.Items) > 0 {
		return nil, apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "rbacpolicies"},
			obj.Name,
			fmt.Errorf("cannot delete: RestrictedBindDefinition(s) still reference this policy"),
		)
	}

	// Check for bound RestrictedRoleDefinitions. Only need to check existence,
	// not count — Limit(1) avoids loading all referencing resources.
	rrdList := &RestrictedRoleDefinitionList{}
	if err := v.Client.List(ctx, rrdList, client.MatchingFields{
		PolicyRefField: obj.Name,
	}, client.Limit(1)); err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions")
		return nil, apierrors.NewInternalError(errors.New("unable to list RestrictedRoleDefinitions"))
	}
	if len(rrdList.Items) > 0 {
		return nil, apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "rbacpolicies"},
			obj.Name,
			fmt.Errorf("cannot delete: RestrictedRoleDefinition(s) still reference this policy"),
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

	allErrs = append(allErrs, validateDefaultAssignment(obj.Spec.DefaultAssignment,
		field.NewPath("spec", "defaultAssignment"))...)
	allErrs = append(allErrs, validateImpersonationConfig(obj.Spec.Impersonation,
		field.NewPath("spec", "impersonation"))...)

	if len(allErrs) > 0 {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RBACPolicy"},
			obj.Name, allErrs)
	}

	return nil
}

// validateDefaultAssignment validates the optional default policy assignment block.
func validateDefaultAssignment(da *DefaultPolicyAssignment, fldPath *field.Path) field.ErrorList {
	if da == nil {
		return nil
	}

	var allErrs field.ErrorList
	if len(da.Groups) == 0 && len(da.ServiceAccounts) == 0 {
		allErrs = append(allErrs, field.Invalid(fldPath, da,
			"must define at least one group or serviceAccount"))
	}

	for i, g := range da.Groups {
		if g == "" {
			allErrs = append(allErrs, field.Invalid(
				fldPath.Child("groups").Index(i), g, "must not be empty"))
		}
	}

	for i, sa := range da.ServiceAccounts {
		if sa.Name == "" {
			allErrs = append(allErrs, field.Required(
				fldPath.Child("serviceAccounts").Index(i).Child("name"), "name is required"))
		}
		if sa.Namespace == "" {
			allErrs = append(allErrs, field.Required(
				fldPath.Child("serviceAccounts").Index(i).Child("namespace"),
				"namespace is required for default policy serviceAccount matching"))
		}
	}

	return allErrs
}

// validateImpersonationConfig validates optional impersonation settings.
func validateImpersonationConfig(ic *ImpersonationConfig, fldPath *field.Path) field.ErrorList {
	if ic == nil {
		return nil
	}

	var allErrs field.ErrorList
	if !ic.Enabled {
		return allErrs
	}

	if ic.ServiceAccountRef == nil {
		allErrs = append(allErrs, field.Required(
			fldPath.Child("serviceAccountRef"),
			"serviceAccountRef is required when impersonation.enabled is true",
		))
		return allErrs
	}

	if ic.ServiceAccountRef.Name == "" {
		allErrs = append(allErrs, field.Required(
			fldPath.Child("serviceAccountRef", "name"),
			"name is required when impersonation is enabled",
		))
	}
	if ic.ServiceAccountRef.Namespace == "" {
		allErrs = append(allErrs, field.Required(
			fldPath.Child("serviceAccountRef", "namespace"),
			"namespace is required when impersonation is enabled",
		))
	}

	return allErrs
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
var validSubjectKinds = []string{rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind}

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

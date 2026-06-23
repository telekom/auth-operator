// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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
	// Reader is a non-cached API reader used for requester default-policy
	// enforcement. Admission-time policy assignment is a security boundary, so
	// it must not fail open when the informer cache lags behind the API server.
	Reader client.Reader
}

var _ admission.Validator[*RestrictedRoleDefinition] = &RestrictedRoleDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RestrictedRoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RestrictedRoleDefinitionValidator{
			Client: mgr.GetClient(),
			Reader: mgr.GetAPIReader(),
		}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-restrictedroledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions,verbs=create;update;delete,versions=v1alpha1,name=restrictedroledefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

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
		v.defaultPolicyReader(),
		schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
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

	if reflect.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}

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
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
			newObj.Name, allErrs)
	}

	if newObj.Spec.TargetRole == DefinitionClusterRole {
		if err := validateNoRestrictedAggregationLabels(newObj); err != nil {
			return nil, err
		}
	}

	if equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) {
		return nil, nil
	}

	if err := v.validateRestrictedRoleDefinitionSpec(ctx, newObj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists.
	if err := v.validatePolicyRefExists(ctx, newObj); err != nil {
		return nil, err
	}

	// Enforce requester-based default policy assignment for mutable spec updates
	// too. The policyRef is immutable, but restricted rules can change under the
	// selected policy.
	if err := validateDefaultPolicyForRequester(
		ctx,
		v.defaultPolicyReader(),
		schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
		newObj.Name,
		newObj.Spec.PolicyRef.Name,
	); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements admission.Validator for RestrictedRoleDefinition.
func (v *RestrictedRoleDefinitionValidator) ValidateDelete(ctx context.Context, obj *RestrictedRoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)

	// Deletes remove granted access and must remain available for cleanup even
	// when the requester is not assigned to the object's default policy.
	return nil, nil
}

func (v *RestrictedRoleDefinitionValidator) defaultPolicyReader() client.Reader {
	if v.Reader != nil {
		return v.Reader
	}
	return v.Client
}

// validateRestrictedRoleDefinitionSpec validates the spec for duplicate targetName.
func (v *RestrictedRoleDefinitionValidator) validateRestrictedRoleDefinitionSpec(ctx context.Context, obj *RestrictedRoleDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedroledefinition-webhook")

	// Check duplicate targetName. Collisions are scoped by targetRole and,
	// for Role targets, targetNamespace.
	existingRRD, err := v.findRestrictedRoleDefinitionTargetNameConflict(ctx, obj)
	if err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "targetName", obj.Spec.TargetName)
		return listErrorToAdmission("RestrictedRoleDefinitions", err)
	}
	if existingRRD != nil {
		logger.Info("validation failed: duplicate targetName",
			"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existingRRD.Name)
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
			obj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RestrictedRoleDefinition %q)", obj.Spec.TargetName, existingRRD.Name))})
	}

	// Check for cross-type targetName collision with RoleDefinitions.
	existingRD, err := v.findRoleDefinitionTargetNameConflict(ctx, obj)
	if err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", obj.Spec.TargetName)
		return listErrorToAdmission("RoleDefinitions", err)
	}
	if existingRD != nil {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
			obj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RoleDefinition %q)", obj.Spec.TargetName, existingRD.Name))})
	}

	if obj.Spec.TargetRole == DefinitionClusterRole {
		if err := validateNoRestrictedAggregationLabels(obj); err != nil {
			return err
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

//nolint:nilnil // A nil object with nil error means no conflicting targetName was found.
func (v *RestrictedRoleDefinitionValidator) findRestrictedRoleDefinitionTargetNameConflict(
	ctx context.Context,
	obj *RestrictedRoleDefinition,
) (*RestrictedRoleDefinition, error) {
	reader := v.defaultPolicyReader()
	continueToken := ""
	for {
		rrdList := &RestrictedRoleDefinitionList{}
		nextContinueToken, err := listAdmissionPage(ctx, reader, rrdList, continueToken)
		if err != nil {
			return nil, err
		}
		for i := range rrdList.Items {
			existing := &rrdList.Items[i]
			if existing.Spec.TargetName == obj.Spec.TargetName &&
				existing.Name != obj.Name &&
				roleTargetCollision(obj.Spec.TargetRole, obj.Spec.TargetNamespace, existing.Spec.TargetRole, existing.Spec.TargetNamespace) {
				return existing, nil
			}
		}
		if nextContinueToken == "" {
			return nil, nil
		}
		continueToken = nextContinueToken
	}
}

//nolint:nilnil // A nil object with nil error means no conflicting targetName was found.
func (v *RestrictedRoleDefinitionValidator) findRoleDefinitionTargetNameConflict(
	ctx context.Context,
	obj *RestrictedRoleDefinition,
) (*RoleDefinition, error) {
	reader := v.defaultPolicyReader()
	continueToken := ""
	for {
		rdList := &RoleDefinitionList{}
		nextContinueToken, err := listAdmissionPage(ctx, reader, rdList, continueToken)
		if err != nil {
			return nil, err
		}
		for i := range rdList.Items {
			existing := &rdList.Items[i]
			if existing.Spec.TargetName == obj.Spec.TargetName &&
				roleTargetCollision(obj.Spec.TargetRole, obj.Spec.TargetNamespace, existing.Spec.TargetRole, existing.Spec.TargetNamespace) {
				return existing, nil
			}
		}
		if nextContinueToken == "" {
			return nil, nil
		}
		continueToken = nextContinueToken
	}
}

// validateNoDuplicateRestrictedRRDAPIs rejects duplicate API group names in RestrictedAPIs.
// Duplicate entries are ambiguous because only the first match is used during
// filtering — subsequent entries for the same group name are silently ignored.
func validateNoDuplicateRestrictedRRDAPIs(obj *RestrictedRoleDefinition) error {
	seen := make(map[string]int, len(obj.Spec.RestrictedAPIs))
	for i, group := range obj.Spec.RestrictedAPIs {
		if prev, ok := seen[group.Name]; ok {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
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

func validateNoRestrictedAggregationLabels(obj *RestrictedRoleDefinition) error {
	for key := range obj.Labels {
		if strings.HasPrefix(key, rbacv1.GroupName+"/aggregate-to-") {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
				obj.Name,
				field.ErrorList{field.Forbidden(
					field.NewPath("metadata", "labels").Key(key),
					"Kubernetes ClusterRole aggregation labels are not allowed on RestrictedRoleDefinition metadata",
				)},
			)
		}
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
					schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
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
	if err := v.defaultPolicyReader().Get(ctx, client.ObjectKey{Name: obj.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
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

	if rbacPolicy.GetDeletionTimestamp() != nil {
		return invalidDeletingPolicyRef(
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedRoleDefinitionKind},
			obj.Name,
			obj.Spec.PolicyRef.Name,
		)
	}

	return nil
}

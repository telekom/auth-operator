package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TargetNameField is the field index for efficient lookups by Spec.TargetName.
// This index must be registered with the manager before use.
const TargetNameField = ".spec.targetName"

// RoleDefinitionValidator implements admission.Validator for RoleDefinition.
// It holds a client reference for listing existing resources during validation.
// +kubebuilder:object:generate=false
type RoleDefinitionValidator struct {
	Client client.Client
}

var _ admission.Validator[*RoleDefinition] = &RoleDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RoleDefinitionValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-roledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=create;update,versions=v1alpha1,name=roledefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateRestrictedAPIsVersions ensures every version entry starts with 'v'
// and is at most 20 characters. This was previously a CEL XValidation rule but
// the nested iteration over upstream metav1.APIGroup exceeded the CEL cost budget.
func validateRestrictedAPIsVersions(obj *RoleDefinition) error {
	for i, group := range obj.Spec.RestrictedAPIs {
		for j, gv := range group.Versions {
			if !strings.HasPrefix(gv.Version, "v") || len(gv.Version) > 20 {
				return fmt.Errorf("restrictedApis[%d].versions[%d].version %q: must start with 'v' and be at most 20 characters", i, j, gv.Version)
			}
		}
	}
	return nil
}

// ValidateCreate implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateCreate(ctx context.Context, obj *RoleDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	// breakglassAllowed is only meaningful for ClusterRoles — Roles are
	// namespace-scoped and not eligible for breakglass escalation.
	if obj.Spec.BreakglassAllowed && obj.Spec.TargetRole == DefinitionNamespacedRole {
		return nil, apierrors.NewBadRequest("breakglassAllowed may only be set when targetRole is 'ClusterRole'")
	}

	// Validate version format in RestrictedAPIs
	if err := validateRestrictedAPIsVersions(obj); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	// Validate TargetNamespace is required when TargetRole is Role
	if obj.Spec.TargetRole == DefinitionNamespacedRole && obj.Spec.TargetNamespace == "" {
		return nil, apierrors.NewBadRequest("targetNamespace is required when targetRole is 'Role'")
	}

	// Validate TargetNamespace must not be set when TargetRole is ClusterRole
	if obj.Spec.TargetRole == DefinitionClusterRole && obj.Spec.TargetNamespace != "" {
		return nil, apierrors.NewBadRequest("targetNamespace must not be set when targetRole is 'ClusterRole'")
	}

	// Use field index for efficient lookup by TargetName
	roleDefinitionList := &RoleDefinitionList{}
	if err := v.Client.List(ctx, roleDefinitionList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", obj.Spec.TargetName)
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list RoleDefinitions: %w", err))
	}

	for _, roleDefinition := range roleDefinitionList.Items {
		if roleDefinition.Spec.TargetRole == obj.Spec.TargetRole && roleDefinition.Name != obj.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", roleDefinition.Name)
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in RoleDefinition %s", obj.Spec.TargetName, roleDefinition.Name))
		}
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RoleDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	if oldObj.Generation == newObj.Generation {
		return nil, nil
	}

	// breakglassAllowed is only meaningful for ClusterRoles.
	if newObj.Spec.BreakglassAllowed && newObj.Spec.TargetRole == DefinitionNamespacedRole {
		return nil, apierrors.NewBadRequest("breakglassAllowed may only be set when targetRole is 'ClusterRole'")
	}

	// Validate version format in RestrictedAPIs
	if err := validateRestrictedAPIsVersions(newObj); err != nil {
		return nil, apierrors.NewBadRequest(err.Error())
	}

	// Validate TargetNamespace is required when TargetRole is Role
	if newObj.Spec.TargetRole == DefinitionNamespacedRole && newObj.Spec.TargetNamespace == "" {
		return nil, apierrors.NewBadRequest("targetNamespace is required when targetRole is 'Role'")
	}

	// Validate TargetNamespace must not be set when TargetRole is ClusterRole
	if newObj.Spec.TargetRole == DefinitionClusterRole && newObj.Spec.TargetNamespace != "" {
		return nil, apierrors.NewBadRequest("targetNamespace must not be set when targetRole is 'ClusterRole'")
	}

	// Use field index for efficient lookup by TargetName
	roleDefinitionList := &RoleDefinitionList{}
	if err := v.Client.List(ctx, roleDefinitionList, client.MatchingFields{
		TargetNameField: newObj.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", newObj.Spec.TargetName)
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list RoleDefinitions: %w", err))
	}

	for _, roleDefinition := range roleDefinitionList.Items {
		if roleDefinition.Spec.TargetRole == newObj.Spec.TargetRole && roleDefinition.Name != newObj.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", newObj.Name, "targetName", newObj.Spec.TargetName, "conflictsWith", roleDefinition.Name)
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in RoleDefinition %s", newObj.Spec.TargetName, roleDefinition.Name))
		}
	}

	return nil, nil
}

// ValidateDelete implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateDelete(ctx context.Context, obj *RoleDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)
	return nil, nil
}

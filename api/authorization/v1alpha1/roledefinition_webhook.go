package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// TargetNameField is the field index for efficient lookups by Spec.TargetName.
// This index must be registered with the manager before use.
const TargetNameField = ".spec.targetName"

// rdWebhookClient is a cached client from the manager.
// List operations use the informer cache with field indexes for efficient lookups.
var rdWebhookClient client.Client

// RoleDefinitionValidator implements admission.Validator for RoleDefinition.
type RoleDefinitionValidator struct{}

var _ admission.Validator[*RoleDefinition] = &RoleDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *RoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	rdWebhookClient = mgr.GetClient() // needed to initialize the client somewhere
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RoleDefinitionValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-roledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=create;update,versions=v1alpha1,name=webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateCreate(ctx context.Context, obj *RoleDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	// Validate that TargetNamespace is set when TargetRole is Role
	if obj.Spec.TargetRole == "Role" && obj.Spec.TargetNamespace == "" {
		logger.Info("validation failed: targetNamespace is required when targetRole is Role", "name", obj.Name)
		return nil, apierrors.NewBadRequest("targetNamespace is required when targetRole is Role")
	}

	// Validate that TargetNamespace is not set when TargetRole is ClusterRole
	if obj.Spec.TargetRole == "ClusterRole" && obj.Spec.TargetNamespace != "" {
		logger.Info("validation failed: targetNamespace must not be set when targetRole is ClusterRole",
			"name", obj.Name, "targetNamespace", obj.Spec.TargetNamespace)
		return nil, apierrors.NewBadRequest("targetNamespace must not be set when targetRole is ClusterRole")
	}

	// Use field index for efficient lookup by TargetName
	roleDefinitionList := &RoleDefinitionList{}
	if err := rdWebhookClient.List(ctx, roleDefinitionList, client.MatchingFields{
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

	// Validate that TargetNamespace is set when TargetRole is Role
	if newObj.Spec.TargetRole == "Role" && newObj.Spec.TargetNamespace == "" {
		logger.Info("validation failed: targetNamespace is required when targetRole is Role", "name", newObj.Name)
		return nil, apierrors.NewBadRequest("targetNamespace is required when targetRole is Role")
	}

	// Validate that TargetNamespace is not set when TargetRole is ClusterRole
	if newObj.Spec.TargetRole == "ClusterRole" && newObj.Spec.TargetNamespace != "" {
		logger.Info("validation failed: targetNamespace must not be set when targetRole is ClusterRole",
			"name", newObj.Name, "targetNamespace", newObj.Spec.TargetNamespace)
		return nil, apierrors.NewBadRequest("targetNamespace must not be set when targetRole is ClusterRole")
	}

	// Use field index for efficient lookup by TargetName
	roleDefinitionList := &RoleDefinitionList{}
	if err := rdWebhookClient.List(ctx, roleDefinitionList, client.MatchingFields{
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

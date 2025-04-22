package v1alpha1

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var roledefinitionlog = logf.Log.WithName("roledefinition-resource")
var rdWebhookClient client.Client

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *RoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	rdWebhookClient = mgr.GetClient() // needed to initialize the client somewhere
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-roledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=create;update,versions=v1alpha1,name=webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

//var _ webhook.Validator = &RoleDefinition{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *RoleDefinition) ValidateCreate() (admission.Warnings, error) {
	roledefinitionlog.Info("validate create", "name", r.Name)
	ctx := context.Background()

	roleDefinitionList := &RoleDefinitionList{}
	if err := rdWebhookClient.List(ctx, roleDefinitionList); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list RoleDefinitions: %v", err))
	}

	for _, roleDefinition := range roleDefinitionList.Items {
		if roleDefinition.Spec.TargetRole == r.Spec.TargetRole && roleDefinition.Spec.TargetName == r.Spec.TargetName && roleDefinition.Name != r.Name {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in RoleDefinition %s", r.Spec.TargetName, roleDefinition.Name))
		}
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *RoleDefinition) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	roledefinitionlog.Info("validate update", "name", r.Name)
	ctx := context.Background()

	oldRoleDefinition, ok := old.(*RoleDefinition)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected a RoleDefinition but got a %T", old))
	}
	if oldRoleDefinition.Generation == r.Generation {
		return nil, nil
	}

	roleDefinitionList := &RoleDefinitionList{}
	if err := rdWebhookClient.List(ctx, roleDefinitionList); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list RoleDefinitions: %v", err))
	}

	for _, roleDefinition := range roleDefinitionList.Items {
		if roleDefinition.Spec.TargetRole == r.Spec.TargetRole && roleDefinition.Spec.TargetName == r.Spec.TargetName && roleDefinition.Name != r.Name {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in RoleDefinition %s", r.Spec.TargetName, roleDefinition.Name))
		}
	}

	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *RoleDefinition) ValidateDelete() (admission.Warnings, error) {
	roledefinitionlog.Info("validate delete", "name", r.Name)
	return nil, nil
}

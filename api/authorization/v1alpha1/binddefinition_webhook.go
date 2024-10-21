package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var binddefinitionlog = logf.Log.WithName("binddefinition-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *BindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/mutate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=true,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=webhook.authn-authz.t-caas.telekom.de,admissionReviewVersions=v1
var _ webhook.Defaulter = &BindDefinition{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *BindDefinition) Default() {
	binddefinitionlog.Info("default", "name", r.Name)

	// TODO(user): fill in your defaulting logic.
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=webhook.authn-authz.t-caas.telekom.de,admissionReviewVersions=v1
var _ webhook.Validator = &BindDefinition{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateCreate() (admission.Warnings, error) {
	binddefinitionlog.Info("validate create", "name", r.Name)

	// TODO(user): fill in your validation logic upon object creation.
	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	binddefinitionlog.Info("validate update", "name", r.Name)

	// TODO(user): fill in your validation logic upon object update.
	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateDelete() (admission.Warnings, error) {
	binddefinitionlog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

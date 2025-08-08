package v1alpha1

import (
	"context"
	"fmt"
	"reflect"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// log is for logging in this package.
var binddefinitionlog = logf.Log.WithName("binddefinition-resource")
var bdWebhookClient client.Client

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *BindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	bdWebhookClient = mgr.GetClient() // needed to initialize the client somewhere
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

//var _ webhook.Validator = &BindDefinition{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateCreate() (admission.Warnings, error) {
	binddefinitionlog.Info("validate create", "name", r.Name)
	ctx := context.Background()

	bindDefinitionList := &BindDefinitionList{}
	if err := bdWebhookClient.List(ctx, bindDefinitionList); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list BindDefinitions: %v", err))
	}

	for _, bindDefinition := range bindDefinitionList.Items {
		// Check if there is already a BindDefinition with same TargetName
		if bindDefinition.Spec.TargetName == r.Spec.TargetName && bindDefinition.Name != r.Name {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in BindDefinition %s", r.Spec.TargetName, bindDefinition.Name))
		}
	}
	for _, RoleBinding := range r.Spec.RoleBindings {
		// Handle multiple NamespaceSelectors
		if len(RoleBinding.NamespaceSelector) > 0 {
			namespaceSet := make(map[string]corev1.Namespace)

			for _, nsSelector := range RoleBinding.NamespaceSelector {
				if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
					selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
					if err != nil {
						return nil, apierrors.NewBadRequest(fmt.Sprintf("Invalid namespaceSelector: %v", err))
					}
					namespaceList := &corev1.NamespaceList{}
					listOptions := &client.ListOptions{
						LabelSelector: selector,
					}
					if err := bdWebhookClient.List(ctx, namespaceList, listOptions); err != nil {
						return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list namespaces: %v", err))
					}
					for _, ns := range namespaceList.Items {
						namespaceSet[ns.Name] = ns
					}
				}
			}

			for _, ns := range namespaceSet {
				for _, roleRef := range RoleBinding.RoleRefs {
					role := &rbacv1.Role{}
					key := client.ObjectKey{
						Namespace: ns.Name,
						Name:      roleRef,
					}
					if err := bdWebhookClient.Get(ctx, key, role); err != nil {
						if apierrors.IsNotFound(err) {
							return nil, apierrors.NewBadRequest(fmt.Sprintf("Role '%s' not found in namespace '%s'", roleRef, ns.Name))
						} else {
							return nil, apierrors.NewInternalError(fmt.Errorf("Error fetching Role '%s' in namespace '%s': %v", roleRef, ns.Name, err))
						}
					}
				}
			}
		}
	}

	return nil, nil
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	binddefinitionlog.Info("validate create", "name", r.Name)
	ctx := context.Background()

	oldBindDefinition, ok := old.(*BindDefinition)
	if !ok {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("expected a BindDefinition but got a %T", old))
	}
	if oldBindDefinition.Generation == r.Generation {
		return nil, nil
	}

	bindDefinitionList := &BindDefinitionList{}
	if err := bdWebhookClient.List(ctx, bindDefinitionList); err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list BindDefinitions: %v", err))
	}

	for _, bindDefinition := range bindDefinitionList.Items {
		// Check if there is already a BindDefinition with same TargetName
		if bindDefinition.Spec.TargetName == r.Spec.TargetName && bindDefinition.Name != r.Name {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in BindDefinition %s", r.Spec.TargetName, bindDefinition.Name))
		}
	}
	for _, RoleBinding := range r.Spec.RoleBindings {

		// Handle multiple NamespaceSelectors
		if len(RoleBinding.NamespaceSelector) > 0 {
			namespaceSet := make(map[string]corev1.Namespace)

			for _, nsSelector := range RoleBinding.NamespaceSelector {
				if !reflect.DeepEqual(nsSelector, metav1.LabelSelector{}) {
					selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
					if err != nil {
						return nil, apierrors.NewBadRequest(fmt.Sprintf("Invalid namespaceSelector: %v", err))
					}
					namespaceList := &corev1.NamespaceList{}
					listOptions := &client.ListOptions{
						LabelSelector: selector,
					}
					if err := bdWebhookClient.List(ctx, namespaceList, listOptions); err != nil {
						return nil, apierrors.NewInternalError(fmt.Errorf("Unable to list namespaces: %v", err))
					}
					for _, ns := range namespaceList.Items {
						namespaceSet[ns.Name] = ns
					}
				}
			}

			for _, ns := range namespaceSet {
				for _, roleRef := range RoleBinding.RoleRefs {
					role := &rbacv1.Role{}
					key := client.ObjectKey{
						Namespace: ns.Name,
						Name:      roleRef,
					}
					if err := bdWebhookClient.Get(ctx, key, role); err != nil {
						if apierrors.IsNotFound(err) {
							return nil, apierrors.NewBadRequest(fmt.Sprintf("Role '%s' not found in namespace '%s'", roleRef, ns.Name))
						} else {
							return nil, apierrors.NewInternalError(fmt.Errorf("Error fetching Role '%s' in namespace '%s': %v", roleRef, ns.Name, err))
						}
					}
				}
			}
		}
	}

	return nil, nil
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *BindDefinition) ValidateDelete() (admission.Warnings, error) {
	binddefinitionlog.Info("validate delete", "name", r.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

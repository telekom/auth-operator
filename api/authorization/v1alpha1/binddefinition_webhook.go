package v1alpha1

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// BindDefinitionValidator implements admission.Validator for BindDefinition.
// It holds a client reference for listing existing resources during validation.
// +kubebuilder:object:generate=false
type BindDefinitionValidator struct {
	Client client.Client
}

var _ admission.Validator[*BindDefinition] = &BindDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *BindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&BindDefinitionValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=binddefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateBindDefinitionSpec validates the BindDefinition spec for duplicate targetName.
// Role existence is checked but only returns warnings (not errors) to allow applying
// BindDefinitions before the referenced roles exist. The controller will handle
// missing roles during reconciliation and set appropriate error conditions.
func (v *BindDefinitionValidator) validateBindDefinitionSpec(ctx context.Context, r *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	var warnings admission.Warnings

	// Use field index for efficient lookup by TargetName
	bindDefinitionList := &BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitionList, client.MatchingFields{
		TargetNameField: r.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "targetName", r.Spec.TargetName)
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list BindDefinitions: %w", err))
	}

	for _, bindDefinition := range bindDefinitionList.Items {
		// The field index already filters by TargetName, so we only need to check
		// that this isn't the same BindDefinition being validated (by name)
		if bindDefinition.Name != r.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", r.Name, "targetName", r.Spec.TargetName, "conflictsWith", bindDefinition.Name)
			return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in BindDefinition %s", r.Spec.TargetName, bindDefinition.Name))
		}
	}

	// Validate ClusterRoleRefs in cluster-scoped bindings - warn if not found
	for _, clusterRoleRef := range r.Spec.ClusterRoleBindings.ClusterRoleRefs {
		clusterRole := &rbacv1.ClusterRole{}
		if err := v.Client.Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Info("warning: clusterrole not found (will be checked during reconciliation)",
					"name", r.Name, "clusterRoleName", clusterRoleRef)
				warnings = append(warnings, fmt.Sprintf("ClusterRole '%s' not found - binding will fail during reconciliation until the role exists", clusterRoleRef))
			} else {
				logger.Error(err, "failed to fetch clusterrole", "clusterRoleName", clusterRoleRef)
				return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching clusterrole '%s': %w", clusterRoleRef, err))
			}
		}
	}

	for _, roleBinding := range r.Spec.RoleBindings {
		// Validate ClusterRoleRefs in namespaced bindings - warn if not found
		for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
			clusterRole := &rbacv1.ClusterRole{}
			if err := v.Client.Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
				if apierrors.IsNotFound(err) {
					logger.Info("warning: clusterrole not found (will be checked during reconciliation)",
						"name", r.Name, "clusterRoleName", clusterRoleRef)
					warnings = append(warnings, fmt.Sprintf("ClusterRole '%s' not found - binding will fail during reconciliation until the role exists", clusterRoleRef))
				} else {
					logger.Error(err, "failed to fetch clusterrole", "clusterRoleName", clusterRoleRef)
					return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching clusterrole '%s': %w", clusterRoleRef, err))
				}
			}
		}

		// Handle multiple NamespaceSelectors
		if len(roleBinding.NamespaceSelector) > 0 {
			namespaceSet := make(map[string]corev1.Namespace)

			for _, nsSelector := range roleBinding.NamespaceSelector {
				if isLabelSelectorEmpty(&nsSelector) {
					continue
				}

				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					logger.Info("validation failed: invalid namespaceSelector",
						"name", r.Name, "error", err.Error())
					return warnings, apierrors.NewBadRequest(fmt.Sprintf("invalid namespaceSelector: %v", err))
				}
				namespaceList := &corev1.NamespaceList{}
				listOptions := &client.ListOptions{
					LabelSelector: selector,
				}
				if err := v.Client.List(ctx, namespaceList, listOptions); err != nil {
					logger.Error(err, "failed to list namespaces", "selector", selector.String())
					return warnings, apierrors.NewInternalError(fmt.Errorf("unable to list namespaces: %w", err))
				}
				for _, ns := range namespaceList.Items {
					namespaceSet[ns.Name] = ns
				}
			}

			for _, ns := range namespaceSet {
				for _, roleRef := range roleBinding.RoleRefs {
					role := &rbacv1.Role{}
					key := client.ObjectKey{
						Namespace: ns.Name,
						Name:      roleRef,
					}
					if err := v.Client.Get(ctx, key, role); err != nil {
						if apierrors.IsNotFound(err) {
							logger.Info("warning: role not found (will be checked during reconciliation)",
								"name", r.Name, "roleName", roleRef, "namespace", ns.Name)
							warnings = append(warnings, fmt.Sprintf("Role '%s' not found in namespace '%s' - binding will fail during reconciliation until the role exists", roleRef, ns.Name))
						} else {
							logger.Error(err, "failed to fetch role", "roleName", roleRef, "namespace", ns.Name)
							return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching role '%s' in namespace '%s': %w", roleRef, ns.Name, err))
						}
					}
				}
			}
		}
	}

	return warnings, nil
}

// ValidateCreate implements admission.Validator for BindDefinition.
func (v *BindDefinitionValidator) ValidateCreate(ctx context.Context, obj *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)
	return v.validateBindDefinitionSpec(ctx, obj)
}

// ValidateUpdate implements admission.Validator for BindDefinition.
func (v *BindDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	if oldObj.Generation == newObj.Generation {
		return nil, nil
	}

	return v.validateBindDefinitionSpec(ctx, newObj)
}

// ValidateDelete implements admission.Validator for BindDefinition.
func (v *BindDefinitionValidator) ValidateDelete(ctx context.Context, obj *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)
	return nil, nil
}

// isLabelSelectorEmpty checks if a LabelSelector has no matching criteria.
// More efficient than using reflect.DeepEqual.
func isLabelSelectorEmpty(selector *metav1.LabelSelector) bool {
	return selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}

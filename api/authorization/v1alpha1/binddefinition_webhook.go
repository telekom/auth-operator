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

// bdWebhookClient is a cached client from the manager.
// List operations use the informer cache with field indexes for efficient lookups.
var bdWebhookClient client.Client

// BindDefinitionValidator implements admission.Validator for BindDefinition.
type BindDefinitionValidator struct{}

var _ admission.Validator[*BindDefinition] = &BindDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (r *BindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	bdWebhookClient = mgr.GetClient() // needed to initialize the client somewhere
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&BindDefinitionValidator{}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateBindDefinitionSpec validates the BindDefinition spec for duplicate targetName.
// Role existence is checked but only returns warnings (not errors) to allow applying
// BindDefinitions before the referenced roles exist. The controller will handle
// missing roles during reconciliation and set appropriate error conditions.
func validateBindDefinitionSpec(ctx context.Context, r *BindDefinition) (admission.Warnings, error) {
	var warnings admission.Warnings

	// Validate unique targetName
	if err := validateUniqueTargetName(ctx, r); err != nil {
		return nil, err
	}

	// Validate ClusterRoleRefs in cluster-scoped bindings
	clusterRoleWarnings, err := validateClusterRoleRefs(ctx, r.Name, r.Spec.ClusterRoleBindings.ClusterRoleRefs)
	if err != nil {
		return clusterRoleWarnings, err
	}
	warnings = append(warnings, clusterRoleWarnings...)

	// Validate RoleBindings
	roleBindingWarnings, err := validateRoleBindings(ctx, r.Name, r.Spec.RoleBindings)
	if err != nil {
		return warnings, err
	}
	warnings = append(warnings, roleBindingWarnings...)

	return warnings, nil
}

// validateUniqueTargetName checks that no other BindDefinition uses the same targetName.
func validateUniqueTargetName(ctx context.Context, r *BindDefinition) error {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")

	// Use field index for efficient lookup by TargetName
	bindDefinitionList := &BindDefinitionList{}
	if err := bdWebhookClient.List(ctx, bindDefinitionList, client.MatchingFields{
		TargetNameField: r.Spec.TargetName,
	}); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "targetName", r.Spec.TargetName)
		return apierrors.NewInternalError(fmt.Errorf("unable to list BindDefinitions: %w", err))
	}

	for _, bindDefinition := range bindDefinitionList.Items {
		// The field index already filters by TargetName, so we only need to check
		// that this isn't the same BindDefinition being validated (by name)
		if bindDefinition.Name != r.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", r.Name, "targetName", r.Spec.TargetName, "conflictsWith", bindDefinition.Name)
			return apierrors.NewBadRequest(fmt.Sprintf("targetName %s already exists in BindDefinition %s", r.Spec.TargetName, bindDefinition.Name))
		}
	}

	return nil
}

// validateClusterRoleRefs checks that referenced ClusterRoles exist, returning warnings for missing ones.
func validateClusterRoleRefs(ctx context.Context, bdName string, clusterRoleRefs []string) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	var warnings admission.Warnings

	for _, clusterRoleRef := range clusterRoleRefs {
		clusterRole := &rbacv1.ClusterRole{}
		if err := bdWebhookClient.Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
			if apierrors.IsNotFound(err) {
				logger.Info("warning: clusterrole not found (will be checked during reconciliation)",
					"name", bdName, "clusterRoleName", clusterRoleRef)
				warnings = append(warnings, fmt.Sprintf("ClusterRole '%s' not found - binding will fail during reconciliation until the role exists", clusterRoleRef))
			} else {
				logger.Error(err, "failed to fetch clusterrole", "clusterRoleName", clusterRoleRef)
				return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching clusterrole '%s': %w", clusterRoleRef, err))
			}
		}
	}

	return warnings, nil
}

// validateRoleBindings validates all RoleBinding entries including their ClusterRoleRefs and RoleRefs.
func validateRoleBindings(ctx context.Context, bdName string, roleBindings []NamespaceBinding) (admission.Warnings, error) {
	var warnings admission.Warnings

	for _, roleBinding := range roleBindings {
		// Validate ClusterRoleRefs in namespaced bindings
		clusterRoleWarnings, err := validateClusterRoleRefs(ctx, bdName, roleBinding.ClusterRoleRefs)
		if err != nil {
			return warnings, err
		}
		warnings = append(warnings, clusterRoleWarnings...)

		// Validate RoleRefs against selected namespaces
		roleWarnings, err := validateNamespacedRoleRefs(ctx, bdName, roleBinding)
		if err != nil {
			return warnings, err
		}
		warnings = append(warnings, roleWarnings...)
	}

	return warnings, nil
}

// validateNamespacedRoleRefs checks that Roles exist in namespaces matching the selector.
func validateNamespacedRoleRefs(ctx context.Context, bdName string, roleBinding NamespaceBinding) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	var warnings admission.Warnings

	if len(roleBinding.NamespaceSelector) == 0 {
		return nil, nil
	}

	// Collect namespaces matching the selectors
	namespaceSet, err := collectMatchingNamespaces(ctx, roleBinding.NamespaceSelector)
	if err != nil {
		return nil, err
	}

	// Validate each RoleRef in each matching namespace
	for _, ns := range namespaceSet {
		for _, roleRef := range roleBinding.RoleRefs {
			role := &rbacv1.Role{}
			key := client.ObjectKey{
				Namespace: ns.Name,
				Name:      roleRef,
			}
			if err := bdWebhookClient.Get(ctx, key, role); err != nil {
				if apierrors.IsNotFound(err) {
					logger.Info("warning: role not found (will be checked during reconciliation)",
						"name", bdName, "roleName", roleRef, "namespace", ns.Name)
					warnings = append(warnings, fmt.Sprintf("Role '%s' not found in namespace '%s' - binding will fail during reconciliation until the role exists", roleRef, ns.Name))
				} else {
					logger.Error(err, "failed to fetch role", "roleName", roleRef, "namespace", ns.Name)
					return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching role '%s' in namespace '%s': %w", roleRef, ns.Name, err))
				}
			}
		}
	}

	return warnings, nil
}

// collectMatchingNamespaces returns namespaces matching any of the given label selectors.
func collectMatchingNamespaces(ctx context.Context, selectors []metav1.LabelSelector) (map[string]corev1.Namespace, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	namespaceSet := make(map[string]corev1.Namespace)

	for _, nsSelector := range selectors {
		if isLabelSelectorEmpty(&nsSelector) {
			continue
		}

		selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
		if err != nil {
			logger.Info("validation failed: invalid namespaceSelector", "error", err.Error())
			return nil, apierrors.NewBadRequest(fmt.Sprintf("invalid namespaceSelector: %v", err))
		}

		namespaceList := &corev1.NamespaceList{}
		listOptions := &client.ListOptions{
			LabelSelector: selector,
		}
		if err := bdWebhookClient.List(ctx, namespaceList, listOptions); err != nil {
			logger.Error(err, "failed to list namespaces", "selector", selector.String())
			return nil, apierrors.NewInternalError(fmt.Errorf("unable to list namespaces: %w", err))
		}

		for _, ns := range namespaceList.Items {
			namespaceSet[ns.Name] = ns
		}
	}

	return namespaceSet, nil
}

// ValidateCreate implements admission.Validator for BindDefinition.
func (v *BindDefinitionValidator) ValidateCreate(ctx context.Context, obj *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)
	return validateBindDefinitionSpec(ctx, obj)
}

// ValidateUpdate implements admission.Validator for BindDefinition.
func (v *BindDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *BindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	if oldObj.Generation == newObj.Generation {
		return nil, nil
	}

	return validateBindDefinitionSpec(ctx, newObj)
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

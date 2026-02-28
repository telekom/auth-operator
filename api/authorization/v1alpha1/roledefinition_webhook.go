package v1alpha1

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

	if err := validateRoleDefinitionSpec(obj); err != nil {
		return nil, err
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

	if err := validateRoleDefinitionSpec(newObj); err != nil {
		return nil, err
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

// validateRoleDefinitionSpec validates the RoleDefinition spec fields.
func validateRoleDefinitionSpec(obj *RoleDefinition) error {
	// Validate version format in RestrictedAPIs
	if err := validateRestrictedAPIsVersions(obj); err != nil {
		return apierrors.NewBadRequest(err.Error())
	}

	// Validate TargetNamespace is required when TargetRole is Role
	if obj.Spec.TargetRole == DefinitionNamespacedRole && obj.Spec.TargetNamespace == "" {
		return apierrors.NewBadRequest("targetNamespace is required when targetRole is 'Role'")
	}

	// Validate TargetNamespace must not be set when TargetRole is ClusterRole
	if obj.Spec.TargetRole == DefinitionClusterRole && obj.Spec.TargetNamespace != "" {
		return apierrors.NewBadRequest("targetNamespace must not be set when targetRole is 'ClusterRole'")
	}

	// Aggregation fields are only valid for ClusterRole targets
	if obj.Spec.TargetRole != DefinitionClusterRole {
		if len(obj.Spec.AggregationLabels) > 0 {
			return apierrors.NewBadRequest("aggregationLabels can only be used when targetRole is 'ClusterRole'")
		}
		if obj.Spec.AggregateFrom != nil {
			return apierrors.NewBadRequest("aggregateFrom can only be used when targetRole is 'ClusterRole'")
		}
	}

	// Reject aggregation labels that target built-in ClusterRoles to prevent
	// privilege escalation via ClusterRole aggregation.
	// Only applies to ClusterRole targets since aggregation is a ClusterRole-only concept.
	if obj.Spec.TargetRole == DefinitionClusterRole {
		if err := rejectForbiddenAggregationLabels(obj); err != nil {
			return err
		}
	}

	// AggregateFrom is mutually exclusive with discovery-based fields
	if obj.Spec.AggregateFrom != nil {
		if err := validateAggregateFrom(obj); err != nil {
			return err
		}
	}

	return nil
}

// forbiddenAggregationTargets lists built-in ClusterRoles that must never be
// recipients of aggregation — granting into cluster-admin is a privilege escalation.
// admin/edit/view are intentionally allowed as they are the standard Kubernetes
// aggregation targets (see issue #51 Use Case 1).
var forbiddenAggregationTargets = []string{"cluster-admin"}

// rejectForbiddenAggregationLabels checks both spec.aggregationLabels and
// metadata.labels for aggregation keys targeting built-in ClusterRoles.
func rejectForbiddenAggregationLabels(obj *RoleDefinition) error {
	for key := range obj.Spec.AggregationLabels {
		for _, target := range forbiddenAggregationTargets {
			if key == rbacv1.GroupName+"/aggregate-to-"+target {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
					obj.Name,
					field.Forbidden(
						field.NewPath("spec", "aggregationLabels").Key(key),
						fmt.Sprintf("must not aggregate into built-in ClusterRole %q", target),
					),
				)
			}
		}
	}
	for key := range obj.Labels {
		for _, target := range forbiddenAggregationTargets {
			if key == rbacv1.GroupName+"/aggregate-to-"+target {
				return apierrors.NewForbidden(
					schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
					obj.Name,
					field.Forbidden(
						field.NewPath("metadata", "labels").Key(key),
						fmt.Sprintf("must not aggregate into built-in ClusterRole %q — label propagates to generated ClusterRole", target),
					),
				)
			}
		}
	}
	return nil
}

// validateAggregateFrom validates the AggregateFrom field constraints.
func validateAggregateFrom(obj *RoleDefinition) error {
	if len(obj.Spec.RestrictedAPIs) > 0 || len(obj.Spec.RestrictedResources) > 0 || len(obj.Spec.RestrictedVerbs) > 0 {
		return apierrors.NewBadRequest(
			"aggregateFrom is mutually exclusive with restrictedApis, restrictedResources, and restrictedVerbs",
		)
	}
	if len(obj.Spec.AggregateFrom.ClusterRoleSelectors) == 0 {
		return apierrors.NewBadRequest("aggregateFrom must have at least one clusterRoleSelector")
	}
	// Reject selectors with no criteria — an empty selector matches all ClusterRoles
	// and would grant unbounded privilege aggregation.
	for i, selector := range obj.Spec.AggregateFrom.ClusterRoleSelectors {
		if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
			return apierrors.NewForbidden(
				schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
				obj.Name,
				field.Forbidden(
					field.NewPath("spec", "aggregateFrom", "clusterRoleSelectors").Index(i),
					"empty selector would match all ClusterRoles; specify matchLabels or matchExpressions",
				),
			)
		}
	}
	return nil
}

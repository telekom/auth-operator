// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilvalidation "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RoleDefinitionValidator implements admission.Validator for RoleDefinition.
// It uses Reader for admission-critical live reads and falls back to Client in
// unit tests that construct the validator directly.
// +kubebuilder:object:generate=false
type RoleDefinitionValidator struct {
	Client client.Client
	Reader client.Reader
}

var _ admission.Validator[*RoleDefinition] = &RoleDefinitionValidator{}

func (v *RoleDefinitionValidator) reader() client.Reader {
	if v.Reader != nil {
		return v.Reader
	}
	return v.Client
}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RoleDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RoleDefinitionValidator{Client: mgr.GetClient(), Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-roledefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=roledefinitions,verbs=create;update,versions=v1alpha1,name=roledefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateRestrictedAPIsVersions ensures every version entry starts with 'v'
// and is at most maxVersionLength characters. This was previously a CEL XValidation rule but
// the nested iteration over the RestrictedAPIGroup type exceeded the CEL cost budget.
func validateRestrictedAPIsVersions(obj *RoleDefinition) error {
	for i, group := range obj.Spec.RestrictedAPIs {
		for j, gv := range group.Versions {
			if !strings.HasPrefix(gv.Version, "v") || len(gv.Version) > maxVersionLength {
				return fmt.Errorf("restrictedApis[%d].versions[%d].version %q: must start with 'v' and be at most %d characters", i, j, gv.Version, maxVersionLength)
			}
		}
	}
	return nil
}

// listErrorToAdmission converts a List API error to an appropriate admission error.
// Transient errors (timeout, server timeout, service unavailable, context deadline/cancel)
// are wrapped with a message that signals the caller should retry; all other errors return
// a generic internal error suitable for a permanent admission denial.
func listErrorToAdmission(resource string, err error) error {
	if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return apierrors.NewInternalError(fmt.Errorf("transient error listing %s; please retry", resource))
	}
	return apierrors.NewInternalError(fmt.Errorf("unable to list %s", resource))
}

// validateNoDuplicateRestrictedAPIs rejects duplicate API group names in RestrictedAPIs.
// Duplicate entries are ambiguous because only the first match is used during
// filtering — subsequent entries for the same group name are silently ignored.
func validateNoDuplicateRestrictedAPIs(obj *RoleDefinition) error {
	seen := make(map[string]int, len(obj.Spec.RestrictedAPIs))
	for i, group := range obj.Spec.RestrictedAPIs {
		if prev, ok := seen[group.Name]; ok {
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
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

// ValidateCreate implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateCreate(ctx context.Context, obj *RoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := validateRoleDefinitionSpec(obj); err != nil {
		return nil, err
	}

	existingRD, err := v.findRoleDefinitionTargetConflict(ctx, obj)
	if err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", obj.Spec.TargetName)
		return nil, listErrorToAdmission("RoleDefinitions", err)
	}
	if existingRD != nil {
		logger.Info("validation failed: duplicate targetName",
			"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existingRD.Name)
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
			obj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RoleDefinition %q)", obj.Spec.TargetName, existingRD.Name))})
	}

	// Check for cross-type targetName collision with RestrictedRoleDefinitions.
	existingRRD, err := v.findRestrictedRoleDefinitionTargetConflict(ctx, obj)
	if err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "targetName", obj.Spec.TargetName)
		return nil, listErrorToAdmission("RestrictedRoleDefinitions", err)
	}
	if existingRRD != nil {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
			obj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RestrictedRoleDefinition %q)", obj.Spec.TargetName, existingRRD.Name))})
	}

	return nil, nil
}

// ValidateUpdate implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RoleDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	// Immutability: targetRole, targetName, and targetNamespace cannot be changed
	// after creation. Changing these would orphan the generated
	// ClusterRole/Role and its bindings.
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
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
			newObj.Name, allErrs)
	}

	// Always check forbidden aggregation labels, even on metadata-only
	// updates (which don't bump generation), to prevent adding a forbidden
	// label via kubectl label or similar tools.
	if newObj.Spec.TargetRole == DefinitionClusterRole {
		if err := rejectForbiddenAggregationLabels(newObj); err != nil {
			return nil, err
		}
	}

	// Always run spec validation on update because Kubernetes increments
	// generation after admission webhooks run, so old.Generation and
	// new.Generation are always equal during the webhook call.
	if err := validateRoleDefinitionSpec(newObj); err != nil {
		return nil, err
	}

	existingRD, err := v.findRoleDefinitionTargetConflict(ctx, newObj)
	if err != nil {
		logger.Error(err, "failed to list RoleDefinitions", "targetName", newObj.Spec.TargetName)
		return nil, listErrorToAdmission("RoleDefinitions", err)
	}
	if existingRD != nil {
		logger.Info("validation failed: duplicate targetName",
			"name", newObj.Name, "targetName", newObj.Spec.TargetName, "conflictsWith", existingRD.Name)
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
			newObj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RoleDefinition %q)", newObj.Spec.TargetName, existingRD.Name))})
	}

	// Keep cross-type targetName collision checks aligned with ValidateCreate.
	existingRRD, err := v.findRestrictedRoleDefinitionTargetConflict(ctx, newObj)
	if err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "targetName", newObj.Spec.TargetName)
		return nil, listErrorToAdmission("RestrictedRoleDefinitions", err)
	}
	if existingRRD != nil {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
			newObj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by RestrictedRoleDefinition %q)", newObj.Spec.TargetName, existingRRD.Name))})
	}

	return nil, nil
}

//nolint:nilnil // A nil object with nil error means no conflicting targetName was found.
func (v *RoleDefinitionValidator) findRoleDefinitionTargetConflict(
	ctx context.Context,
	obj *RoleDefinition,
) (*RoleDefinition, error) {
	reader := v.reader()
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
func (v *RoleDefinitionValidator) findRestrictedRoleDefinitionTargetConflict(
	ctx context.Context,
	obj *RoleDefinition,
) (*RestrictedRoleDefinition, error) {
	reader := v.reader()
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

// ValidateDelete implements admission.Validator for RoleDefinition.
func (v *RoleDefinitionValidator) ValidateDelete(ctx context.Context, obj *RoleDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("roledefinition-webhook")
	logger.V(1).Info("validating delete", "name", obj.Name)
	return nil, nil
}

// validateRoleDefinitionSpec validates the RoleDefinition spec fields.
func validateRoleDefinitionSpec(obj *RoleDefinition) error {
	if err := validateRoleTargetFields(
		schema.GroupKind{Group: GroupVersion.Group, Kind: "RoleDefinition"},
		obj.Name,
		obj.Spec.TargetRole,
		obj.Spec.TargetName,
		obj.Spec.TargetNamespace,
	); err != nil {
		return err
	}

	// breakglassAllowed is only meaningful for ClusterRoles — Roles are
	// namespace-scoped and not eligible for breakglass escalation.
	if obj.Spec.BreakglassAllowed && obj.Spec.TargetRole == DefinitionNamespacedRole {
		return apierrors.NewBadRequest("breakglassAllowed may only be set when targetRole is 'ClusterRole'")
	}

	// Validate version format in RestrictedAPIs.
	if err := validateRestrictedAPIsVersions(obj); err != nil {
		return apierrors.NewBadRequest(err.Error())
	}

	// Reject duplicate API group names in RestrictedAPIs — only the first entry
	// would take effect and subsequent entries would be silently ignored.
	if err := validateNoDuplicateRestrictedAPIs(obj); err != nil {
		return err
	}

	// Metadata labels propagate to the generated Role or ClusterRole. Reject
	// Kubernetes RBAC aggregation labels for every targetRole so reconciliation
	// does not silently drop admitted input.
	if err := rejectForbiddenMetadataAggregationLabels(obj); err != nil {
		return err
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
	if obj.Spec.TargetRole == DefinitionClusterRole {
		if err := rejectForbiddenAggregationLabels(obj); err != nil {
			return err
		}
	}

	// AggregateFrom is mutually exclusive with discovery-based fields
	if obj.Spec.AggregateFrom != nil {
		if err := ValidateRoleDefinitionAggregateFrom(obj); err != nil {
			return err
		}
	}

	return nil
}

func validateRoleTargetFields(
	kind schema.GroupKind,
	name string,
	targetRole string,
	targetName string,
	targetNamespace string,
) error {
	var allErrs field.ErrorList
	if targetRole == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "targetRole"), "targetRole is required"))
	} else if targetRole != DefinitionClusterRole && targetRole != DefinitionNamespacedRole {
		allErrs = append(allErrs, field.NotSupported(field.NewPath("spec", "targetRole"), targetRole, []string{DefinitionClusterRole, DefinitionNamespacedRole}))
	} else if targetRole == DefinitionNamespacedRole && targetNamespace == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "targetNamespace"), "targetNamespace is required when targetRole is 'Role'"))
	} else if targetRole == DefinitionClusterRole && targetNamespace != "" {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetNamespace"), "targetNamespace must be empty when targetRole is 'ClusterRole'"))
	}
	if targetName == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "targetName"), "targetName is required"))
	}
	if targetNamespace != "" && targetRole != DefinitionClusterRole {
		for _, msg := range utilvalidation.IsDNS1123Label(targetNamespace) {
			allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "targetNamespace"), targetNamespace, msg))
		}
	}
	if len(allErrs) > 0 {
		return apierrors.NewInvalid(kind, name, allErrs)
	}
	return nil
}

const (
	kubernetesRBACAggregationLabelPrefix = rbacv1.GroupName + "/aggregate-to-"
	aggregateFromFragmentLabelKey        = "t-caas.telekom.com/rbac-fragment"
	aggregateFromFragmentLabelValue      = "true"
	aggregateFromScopeLabelKey           = "t-caas.telekom.com/aggregate-scope"
)

// rejectForbiddenAggregationLabels checks spec.aggregationLabels for Kubernetes
// RBAC aggregation keys. RoleDefinition must not feed generated rules into
// built-in or externally managed aggregating roles.
func rejectForbiddenAggregationLabels(obj *RoleDefinition) error {
	for key := range obj.Spec.AggregationLabels {
		if strings.HasPrefix(key, kubernetesRBACAggregationLabelPrefix) {
			return apierrors.NewForbidden(
				schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
				obj.Name,
				field.Forbidden(
					field.NewPath("spec", "aggregationLabels").Key(key),
					"must not use Kubernetes RBAC aggregation labels",
				),
			)
		}
	}
	return nil
}

func rejectForbiddenMetadataAggregationLabels(obj *RoleDefinition) error {
	for key := range obj.Labels {
		if strings.HasPrefix(key, kubernetesRBACAggregationLabelPrefix) {
			return apierrors.NewForbidden(
				schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
				obj.Name,
				field.Forbidden(
					field.NewPath("metadata", "labels").Key(key),
					"must not use Kubernetes RBAC aggregation labels because metadata labels propagate to the generated RBAC object",
				),
			)
		}
	}
	return nil
}

// ValidateRoleDefinitionAggregateFrom validates the AggregateFrom field constraints.
func ValidateRoleDefinitionAggregateFrom(obj *RoleDefinition) error {
	if obj.Spec.TargetRole != DefinitionClusterRole {
		return apierrors.NewBadRequest("aggregateFrom can only be used when targetRole is 'ClusterRole'")
	}
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
					"empty selector would match all ClusterRoles; specify matchLabels",
				),
			)
		}
		if err := validateAggregateFromSelector(obj, i, selector); err != nil {
			return err
		}
	}
	return nil
}

func validateAggregateFromSelector(obj *RoleDefinition, index int, selector metav1.LabelSelector) error {
	selectorPath := field.NewPath("spec", "aggregateFrom", "clusterRoleSelectors").Index(index)
	if len(selector.MatchExpressions) > 0 {
		return apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
			obj.Name,
			field.Forbidden(
				selectorPath.Child("matchExpressions"),
				"matchExpressions are not allowed for aggregateFrom; use explicit matchLabels",
			),
		)
	}
	if selector.MatchLabels[aggregateFromFragmentLabelKey] != aggregateFromFragmentLabelValue {
		return apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
			obj.Name,
			field.Forbidden(
				selectorPath.Child("matchLabels").Key(aggregateFromFragmentLabelKey),
				fmt.Sprintf("must be %q", aggregateFromFragmentLabelValue),
			),
		)
	}
	if selector.MatchLabels[aggregateFromScopeLabelKey] == "" {
		return apierrors.NewForbidden(
			schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
			obj.Name,
			field.Forbidden(
				selectorPath.Child("matchLabels").Key(aggregateFromScopeLabelKey),
				"must select an explicit aggregate scope",
			),
		)
	}
	for key := range selector.MatchLabels {
		if key != aggregateFromFragmentLabelKey && key != aggregateFromScopeLabelKey {
			return apierrors.NewForbidden(
				schema.GroupResource{Group: GroupVersion.Group, Resource: "roledefinitions"},
				obj.Name,
				field.Forbidden(
					selectorPath.Child("matchLabels").Key(key),
					fmt.Sprintf("aggregateFrom selectors may only use %q and %q", aggregateFromFragmentLabelKey, aggregateFromScopeLabelKey),
				),
			)
		}
	}
	return nil
}

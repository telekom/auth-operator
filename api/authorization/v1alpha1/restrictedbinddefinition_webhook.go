// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/telekom/auth-operator/pkg/helpers"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// RestrictedBindDefinitionValidator implements admission.Validator for RestrictedBindDefinition.
// +kubebuilder:object:generate=false
type RestrictedBindDefinitionValidator struct {
	Client client.Client
	// Reader is a non-cached API reader used for requester default-policy
	// enforcement. Admission-time policy assignment is a security boundary, so
	// it must not fail open when the informer cache lags behind the API server.
	Reader client.Reader
}

var _ admission.Validator[*RestrictedBindDefinition] = &RestrictedBindDefinitionValidator{}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *RestrictedBindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&RestrictedBindDefinitionValidator{
			Client: mgr.GetClient(),
			Reader: mgr.GetAPIReader(),
		}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-restrictedbinddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions,verbs=create;update,versions=v1alpha1,name=restrictedbinddefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// ValidateCreate implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateCreate(ctx context.Context, obj *RestrictedBindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")
	logger.V(1).Info("validating create", "name", obj.Name)

	if err := v.validateRestrictedBindDefinitionSpec(ctx, obj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists and collect any admission warnings.
	warnings, err := v.validatePolicyRefExists(ctx, obj)
	if err != nil {
		return nil, err
	}

	// Enforce requester-based default policy assignment, if configured.
	if err := validateDefaultPolicyForRequester(
		ctx,
		v.defaultPolicyReader(),
		schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
		obj.Name,
		obj.Spec.PolicyRef.Name,
	); err != nil {
		return nil, err
	}

	return warnings, nil
}

// ValidateUpdate implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj *RestrictedBindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")
	logger.V(1).Info("validating update", "name", newObj.Name)

	// Enforce immutability of targetName and policyRef.
	var allErrs field.ErrorList
	if oldObj.Spec.TargetName != newObj.Spec.TargetName {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "targetName"), "field is immutable after creation"))
	}
	if oldObj.Spec.PolicyRef.Name != newObj.Spec.PolicyRef.Name {
		allErrs = append(allErrs, field.Forbidden(field.NewPath("spec", "policyRef", "name"), "field is immutable after creation"))
	}
	if len(allErrs) > 0 {
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
			newObj.Name, allErrs)
	}

	if err := v.validateRestrictedBindDefinitionSpec(ctx, newObj); err != nil {
		return nil, err
	}

	// Verify that the referenced RBACPolicy exists and collect any admission warnings.
	warnings, err := v.validatePolicyRefExists(ctx, newObj)
	if err != nil {
		return nil, err
	}

	return warnings, nil
}

// ValidateDelete implements admission.Validator for RestrictedBindDefinition.
func (v *RestrictedBindDefinitionValidator) ValidateDelete(_ context.Context, _ *RestrictedBindDefinition) (admission.Warnings, error) {
	return nil, nil
}

func (v *RestrictedBindDefinitionValidator) defaultPolicyReader() client.Reader {
	if v.Reader != nil {
		return v.Reader
	}
	return v.Client
}

// validateRestrictedBindDefinitionSpec validates the spec for duplicate targetName
// and valid namespace selectors.
func (v *RestrictedBindDefinitionValidator) validateRestrictedBindDefinitionSpec(ctx context.Context, obj *RestrictedBindDefinition) error {
	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")

	// Check duplicate targetName. The field index constrains results to matching
	// items; the context timeout provides the hard latency bound.
	rbdList := &RestrictedBindDefinitionList{}
	if err := v.Client.List(ctx, rbdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(2)); err != nil {
		if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) {
			logger.Error(err, "transient error listing RestrictedBindDefinitions", "targetName", obj.Spec.TargetName)
			return apierrors.NewInternalError(errors.New("transient error listing RestrictedBindDefinitions"))
		}
		logger.Error(err, "failed to list RestrictedBindDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(errors.New("unable to list RestrictedBindDefinitions"))
	}

	for _, existing := range rbdList.Items {
		if existing.Name != obj.Name {
			logger.Info("validation failed: duplicate targetName",
				"name", obj.Name, "targetName", obj.Spec.TargetName, "conflictsWith", existing.Name)
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
				obj.Name,
				field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
					fmt.Sprintf("%s (already used by RestrictedBindDefinition %q)", obj.Spec.TargetName, existing.Name))})
		}
	}

	// Check for cross-type targetName collision with BindDefinitions (only need first match).
	bdList := &BindDefinitionList{}
	if err := v.Client.List(ctx, bdList, client.MatchingFields{
		TargetNameField: obj.Spec.TargetName,
	}, client.Limit(1)); err != nil {
		if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) {
			logger.Error(err, "transient error listing BindDefinitions", "targetName", obj.Spec.TargetName)
			return apierrors.NewInternalError(errors.New("transient error listing BindDefinitions"))
		}
		logger.Error(err, "failed to list BindDefinitions", "targetName", obj.Spec.TargetName)
		return apierrors.NewInternalError(errors.New("unable to list BindDefinitions"))
	}
	for _, existing := range bdList.Items {
		return apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
			obj.Name,
			field.ErrorList{field.Duplicate(field.NewPath("spec", "targetName"),
				fmt.Sprintf("%s (already used by BindDefinition %q)", obj.Spec.TargetName, existing.Name))})
	}

	// Validate subject Kinds are one of the RBAC-supported types.
	for i, subject := range obj.Spec.Subjects {
		switch subject.Kind {
		case rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind:
			// valid
		default:
			fldErr := field.NotSupported(field.NewPath("spec", "subjects").Index(i).Child("kind"), subject.Kind, supportedSubjectKinds)
			return apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
				obj.Name, field.ErrorList{fldErr})
		}
	}

	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind}
	if err := validateNamespaceBindings(kind, obj.Name, obj.Spec.RoleBindings); err != nil {
		return err
	}
	return v.validateRoleBindingNameCollisions(ctx, kind, obj)
}

type roleBindingNameClaim struct {
	roleKind string
	roleRef  string
	path     *field.Path
}

func (v *RestrictedBindDefinitionValidator) validateRoleBindingNameCollisions(
	ctx context.Context,
	kind schema.GroupKind,
	obj *RestrictedBindDefinition,
) error {
	claims := make(map[string]roleBindingNameClaim)
	for i, binding := range obj.Spec.RoleBindings {
		namespaces, err := v.resolveRoleBindingNamespacesForValidation(ctx, binding)
		if err != nil {
			return err
		}
		for _, namespace := range namespaces {
			for j, roleRef := range binding.ClusterRoleRefs {
				path := field.NewPath("spec", "roleBindings").Index(i).Child("clusterRoleRefs").Index(j)
				if err := recordRoleBindingNameClaim(kind, obj.Name, obj.Spec.TargetName, claims, namespace, "ClusterRole", roleRef, path); err != nil {
					return err
				}
			}
			for j, roleRef := range binding.RoleRefs {
				path := field.NewPath("spec", "roleBindings").Index(i).Child("roleRefs").Index(j)
				if err := recordRoleBindingNameClaim(kind, obj.Name, obj.Spec.TargetName, claims, namespace, "Role", roleRef, path); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (v *RestrictedBindDefinitionValidator) resolveRoleBindingNamespacesForValidation(
	ctx context.Context,
	binding NamespaceBinding,
) ([]string, error) {
	if binding.Namespace != "" {
		return []string{binding.Namespace}, nil
	}

	namespaceSet := make(map[string]struct{})
	for _, namespaceSelector := range binding.NamespaceSelector {
		selector, err := metav1.LabelSelectorAsSelector(&namespaceSelector)
		if err != nil {
			return nil, apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
				"",
				field.ErrorList{field.Invalid(field.NewPath("spec", "roleBindings").Child("namespaceSelector"), namespaceSelector, err.Error())})
		}
		namespaceList := &corev1.NamespaceList{}
		if err := v.Client.List(ctx, namespaceList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, apierrors.NewInternalError(errors.New("unable to list namespaces for RoleBinding name collision validation"))
		}
		for _, namespace := range namespaceList.Items {
			if namespace.Status.Phase == corev1.NamespaceTerminating {
				continue
			}
			namespaceSet[namespace.Name] = struct{}{}
		}
	}

	namespaces := make([]string, 0, len(namespaceSet))
	for namespace := range namespaceSet {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

func recordRoleBindingNameClaim(
	kind schema.GroupKind,
	objectName, targetName string,
	claims map[string]roleBindingNameClaim,
	namespace, roleKind, roleRef string,
	path *field.Path,
) error {
	bindingName := helpers.BuildBindingName(targetName, roleRef)
	key := namespace + "/" + bindingName
	if existing, ok := claims[key]; ok {
		if existing.roleKind == roleKind && existing.roleRef == roleRef {
			return nil
		}
		return apierrors.NewInvalid(
			kind,
			objectName,
			field.ErrorList{field.Duplicate(
				path,
				fmt.Sprintf("%s %q collides with %s %q at %s/%s",
					roleKind, roleRef, existing.roleKind, existing.roleRef, namespace, bindingName))})
	}
	claims[key] = roleBindingNameClaim{roleKind: roleKind, roleRef: roleRef, path: path}
	return nil
}

// validatePolicyRefExists verifies that the referenced RBACPolicy exists and returns
// admission warnings for constraints that cannot be evaluated at admission time.
// Full policy compliance evaluation is performed by the controller during reconciliation.
func (v *RestrictedBindDefinitionValidator) validatePolicyRefExists(ctx context.Context, obj *RestrictedBindDefinition) (admission.Warnings, error) {
	logger := log.FromContext(ctx).WithName("restrictedbinddefinition-webhook")

	rbacPolicy := &RBACPolicy{}
	if err := v.Client.Get(ctx, client.ObjectKey{Name: obj.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: RestrictedBindDefinitionKind},
				obj.Name,
				field.ErrorList{field.NotFound(
					field.NewPath("spec", "policyRef", "name"),
					obj.Spec.PolicyRef.Name,
				)},
			)
		}
		if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || apierrors.IsServiceUnavailable(err) {
			logger.Error(err, "transient error fetching RBACPolicy", "policyRef", obj.Spec.PolicyRef.Name)
			return nil, apierrors.NewInternalError(errors.New("transient error validating policy reference"))
		}
		logger.Error(err, "failed to get RBACPolicy", "policyRef", obj.Spec.PolicyRef.Name)
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to validate policy reference: %w", err))
	}

	// AllowedNamespaceSelector constraints cannot be evaluated at admission time because
	// no LabelGetter is available in the webhook. The constraint will be enforced during
	// reconciliation by the controller. Emit an admission warning so the requester is aware.
	var selectorWarningIssued bool
	if bl := rbacPolicy.Spec.BindingLimits; bl != nil {
		if tnl := bl.TargetNamespaceLimits; tnl != nil && tnl.AllowedNamespaceSelector != nil {
			selectorWarningIssued = true
		}
	}
	if !selectorWarningIssued {
		if sl := rbacPolicy.Spec.SubjectLimits; sl != nil {
			if sal := sl.ServiceAccountLimits; sal != nil && sal.AllowedNamespaceSelector != nil {
				selectorWarningIssued = true
			}
		}
	}

	var warnings admission.Warnings
	if selectorWarningIssued {
		warnings = append(warnings, "AllowedNamespaceSelector constraints will be enforced at reconciliation time, not at admission")
	}
	return warnings, nil
}

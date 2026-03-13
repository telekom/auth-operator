package v1alpha1

import (
	"context"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

// supportedSubjectKinds lists the RBAC-supported subject types for BindDefinition subjects.
var supportedSubjectKinds = []string{rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind}

var _ admission.Validator[*BindDefinition] = &BindDefinitionValidator{}

// checkRoleExists checks whether a Role exists in the given namespace, using
// roleCache to avoid redundant lookups. It returns an error on API failures;
// on NotFound the missing ref is appended to *missingRoles and nil is returned.
func (v *BindDefinitionValidator) checkRoleExists(
	ctx context.Context,
	namespace, roleRef, bdName string,
	policy MissingRolePolicy,
	roleCache map[string]bool,
	missingRoles *[]string,
) error {
	logger := log.FromContext(ctx)
	roleKey := namespace + "/" + roleRef
	if exists, checked := roleCache[roleKey]; checked {
		if !exists {
			ref := fmt.Sprintf("Role/%s/%s", namespace, roleRef)
			if !slices.Contains(*missingRoles, ref) {
				*missingRoles = append(*missingRoles, ref)
			}
		}
		return nil
	}
	role := &rbacv1.Role{}
	key := client.ObjectKey{Namespace: namespace, Name: roleRef}
	if err := v.Client.Get(ctx, key, role); err != nil {
		if apierrors.IsNotFound(err) {
			roleCache[roleKey] = false
			logger.Info("role not found",
				"name", bdName, "roleName", roleRef, "namespace", namespace, "policy", string(policy))
			ref := fmt.Sprintf("Role/%s/%s", namespace, roleRef)
			if !slices.Contains(*missingRoles, ref) {
				*missingRoles = append(*missingRoles, ref)
			}
			return nil
		}
		logger.Error(err, "failed to fetch role", "roleName", roleRef, "namespace", namespace)
		return fmt.Errorf("error fetching role '%s' in namespace '%s': %w", roleRef, namespace, err)
	}
	roleCache[roleKey] = true
	return nil
}

// SetupWebhookWithManager will setup the manager to manage the webhooks.
func (r *BindDefinition) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr, r).
		WithValidator(&BindDefinitionValidator{Client: mgr.GetClient()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=binddefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateBindDefinitionSpec validates the BindDefinition spec for duplicate targetName.
// Role existence is checked. With the default "warn" policy, missing roles only return
// warnings. With the "error" policy, missing roles cause admission rejection. With
// "ignore", role checks are skipped entirely. The controller will also handle missing
// roles during reconciliation and set appropriate conditions.
func (v *BindDefinitionValidator) validateBindDefinitionSpec(ctx context.Context, r *BindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, webhookValidationTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	var warnings admission.Warnings

	// Use field index for efficient lookup by TargetName (cap at 100 to bound webhook latency).
	bindDefinitionList := &BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitionList, client.MatchingFields{
		TargetNameField: r.Spec.TargetName,
	}, client.Limit(100)); err != nil {
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

	// Check for cross-type targetName collision with RestrictedBindDefinitions (only need first match).
	rbdList := &RestrictedBindDefinitionList{}
	if err := v.Client.List(ctx, rbdList, client.MatchingFields{
		TargetNameField: r.Spec.TargetName,
	}, client.Limit(1)); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions", "targetName", r.Spec.TargetName)
		return nil, apierrors.NewInternalError(fmt.Errorf("unable to list RestrictedBindDefinitions: %w", err))
	}
	if len(rbdList.Items) > 0 {
		return nil, apierrors.NewBadRequest(
			fmt.Sprintf("targetName %s already exists in RestrictedBindDefinition %s", r.Spec.TargetName, rbdList.Items[0].Name))
	}

	// Validate subject Kinds are one of the RBAC-supported types.
	for i, subject := range r.Spec.Subjects {
		switch subject.Kind {
		case rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind:
			// valid
		default:
			fldErr := field.NotSupported(field.NewPath("spec", "subjects").Index(i).Child("kind"), subject.Kind, supportedSubjectKinds)
			return warnings, apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: "BindDefinition"},
				r.Name, field.ErrorList{fldErr})
		}
	}

	// Determine the missing-role policy from annotation.
	policy := r.GetMissingRolePolicy()

	// Always validate namespace selector syntax, regardless of missing-role policy.
	// Invalid selectors are a configuration error and must not be silently ignored.
	for _, roleBinding := range r.Spec.RoleBindings {
		for _, nsSelector := range roleBinding.NamespaceSelector {
			if isLabelSelectorEmpty(&nsSelector) {
				continue
			}
			if _, err := metav1.LabelSelectorAsSelector(&nsSelector); err != nil {
				logger.Info("validation failed: invalid namespaceSelector",
					"name", r.Name, "error", err.Error())
				return warnings, apierrors.NewBadRequest(fmt.Sprintf("invalid namespaceSelector: %v", err))
			}
		}
	}

	if policy == MissingRolePolicyIgnore {
		return warnings, nil
	}
	blockOnMissing := policy == MissingRolePolicyError
	var missingRoles []string

	// Cache existence results to avoid redundant informer-cache lookups
	// when the same role is referenced in multiple roleBinding entries.
	clusterRoleExists := make(map[string]bool) // name → exists
	roleExists := make(map[string]bool)        // "namespace/name" → exists

	// Validate ClusterRoleRefs in cluster-scoped bindings
	for _, clusterRoleRef := range r.Spec.ClusterRoleBindings.ClusterRoleRefs {
		if exists, checked := clusterRoleExists[clusterRoleRef]; checked {
			if !exists {
				ref := fmt.Sprintf("ClusterRole/%s", clusterRoleRef)
				if !slices.Contains(missingRoles, ref) {
					missingRoles = append(missingRoles, ref)
				}
			}
			continue
		}
		clusterRole := &rbacv1.ClusterRole{}
		if err := v.Client.Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
			if apierrors.IsNotFound(err) {
				clusterRoleExists[clusterRoleRef] = false
				logger.Info("clusterrole not found",
					"name", r.Name, "clusterRoleName", clusterRoleRef, "policy", string(policy))
				ref := fmt.Sprintf("ClusterRole/%s", clusterRoleRef)
				if !slices.Contains(missingRoles, ref) {
					missingRoles = append(missingRoles, ref)
				}
			} else {
				logger.Error(err, "failed to fetch clusterrole", "clusterRoleName", clusterRoleRef)
				return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching clusterrole '%s': %w", clusterRoleRef, err))
			}
		} else {
			clusterRoleExists[clusterRoleRef] = true
		}
	}

	for _, roleBinding := range r.Spec.RoleBindings {
		// Validate ClusterRoleRefs in namespaced bindings
		for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
			if exists, checked := clusterRoleExists[clusterRoleRef]; checked {
				if !exists {
					ref := fmt.Sprintf("ClusterRole/%s", clusterRoleRef)
					if !slices.Contains(missingRoles, ref) {
						missingRoles = append(missingRoles, ref)
					}
				}
				continue
			}
			clusterRole := &rbacv1.ClusterRole{}
			if err := v.Client.Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
				if apierrors.IsNotFound(err) {
					clusterRoleExists[clusterRoleRef] = false
					logger.Info("clusterrole not found",
						"name", r.Name, "clusterRoleName", clusterRoleRef, "policy", string(policy))
					ref := fmt.Sprintf("ClusterRole/%s", clusterRoleRef)
					if !slices.Contains(missingRoles, ref) {
						missingRoles = append(missingRoles, ref)
					}
				} else {
					logger.Error(err, "failed to fetch clusterrole", "clusterRoleName", clusterRoleRef)
					return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching clusterrole '%s': %w", clusterRoleRef, err))
				}
			} else {
				clusterRoleExists[clusterRoleRef] = true
			}
		}

		// Handle multiple NamespaceSelectors
		if len(roleBinding.NamespaceSelector) > 0 {
			namespaceSet := make(map[string]corev1.Namespace)

			for _, nsSelector := range roleBinding.NamespaceSelector {
				// An empty label selector ({}) matches all namespaces in Kubernetes.
				// Convert it to a proper selector so we can list and validate the
				// resulting namespace set, rather than silently skipping it.
				selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
				if err != nil {
					// Unreachable: syntax was pre-validated, but guard defensively.
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

			// Sort namespace names for deterministic warning/error output.
			nsNames := make([]string, 0, len(namespaceSet))
			for name := range namespaceSet {
				nsNames = append(nsNames, name)
			}
			sort.Strings(nsNames)

			for _, nsName := range nsNames {
				ns := namespaceSet[nsName]
				// Skip terminating namespaces — roles may already be deleted.
				if ns.Status.Phase == corev1.NamespaceTerminating {
					continue
				}
				for _, roleRef := range roleBinding.RoleRefs {
					if err := v.checkRoleExists(ctx, ns.Name, roleRef, r.Name, policy, roleExists, &missingRoles); err != nil {
						return warnings, apierrors.NewInternalError(err)
					}
				}
			}
		} else if roleBinding.Namespace != "" {
			// Validate RoleRefs in the explicitly specified namespace.
			// First verify the namespace exists and is not terminating.
			ns := &corev1.Namespace{}
			if err := v.Client.Get(ctx, client.ObjectKey{Name: roleBinding.Namespace}, ns); err != nil {
				if apierrors.IsNotFound(err) {
					logger.Info("namespace not found, skipping role checks",
						"name", r.Name, "namespace", roleBinding.Namespace)
					warnings = append(warnings, fmt.Sprintf("namespace %q does not exist yet — role references will be validated once it is created", roleBinding.Namespace))
					continue
				}
				logger.Error(err, "failed to get namespace", "namespace", roleBinding.Namespace)
				return warnings, apierrors.NewInternalError(fmt.Errorf("error fetching namespace %q: %w", roleBinding.Namespace, err))
			}
			if ns.Status.Phase == corev1.NamespaceTerminating {
				continue
			}
			for _, roleRef := range roleBinding.RoleRefs {
				if err := v.checkRoleExists(ctx, roleBinding.Namespace, roleRef, r.Name, policy, roleExists, &missingRoles); err != nil {
					return warnings, apierrors.NewInternalError(err)
				}
			}
		}
	}

	if len(missingRoles) > 0 {
		// Sort for deterministic admission output across runs.
		slices.Sort(missingRoles)

		if blockOnMissing {
			return warnings, apierrors.NewBadRequest(
				fmt.Sprintf("missing-role-policy is 'error': referenced roles do not exist: %v", missingRoles))
		}
		for _, ref := range missingRoles {
			warnings = append(warnings, fmt.Sprintf("%s not found - binding will be created but ineffective until the role exists", ref))
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

	// Immutability: targetName cannot be changed after creation.
	// Changing it would orphan the generated bindings and service accounts.
	if oldObj.Spec.TargetName != newObj.Spec.TargetName {
		allErrs := field.ErrorList{
			field.Forbidden(field.NewPath("spec", "targetName"), "field is immutable after creation"),
		}
		return nil, apierrors.NewInvalid(
			schema.GroupKind{Group: GroupVersion.Group, Kind: "BindDefinition"},
			newObj.Name, allErrs)
	}

	// Skip expensive spec validation (namespace listing, role lookups) when
	// neither the spec nor the missing-role-policy annotation changed.
	if equality.Semantic.DeepEqual(oldObj.Spec, newObj.Spec) &&
		oldObj.GetMissingRolePolicy() == newObj.GetMissingRolePolicy() {
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

package v1alpha1

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

// BindDefinitionValidator implements admission.Validator for BindDefinition.
// It uses Reader for admission-critical live reads and falls back to Client in
// unit tests that construct the validator directly.
// +kubebuilder:object:generate=false
type BindDefinitionValidator struct {
	Client client.Client
	Reader client.Reader
}

// supportedSubjectKinds lists the RBAC-supported subject types for BindDefinition subjects.
var supportedSubjectKinds = []string{rbacv1.UserKind, rbacv1.GroupKind, rbacv1.ServiceAccountKind}

var _ admission.Validator[*BindDefinition] = &BindDefinitionValidator{}

func (v *BindDefinitionValidator) reader() client.Reader {
	if v.Reader != nil {
		return v.Reader
	}
	return v.Client
}

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
	if err := v.reader().Get(ctx, key, role); err != nil {
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
		WithValidator(&BindDefinitionValidator{Client: mgr.GetClient(), Reader: mgr.GetAPIReader()}).
		Complete()
}

// +kubebuilder:webhook:path=/validate-authorization-t-caas-telekom-com-v1alpha1-binddefinition,mutating=false,failurePolicy=fail,sideEffects=None,groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=create;update,versions=v1alpha1,name=binddefinition.validating.webhook.auth.t-caas.telekom.de,admissionReviewVersions=v1

// validateBindDefinitionSpec validates the BindDefinition spec for duplicate targetName.
// Role existence is checked. With the default "warn" policy, missing roles only return
// warnings. With the "error" policy, missing roles cause admission rejection. With
// "ignore", role checks are skipped entirely. The controller will also handle missing
// roles during reconciliation and set appropriate conditions.
func (v *BindDefinitionValidator) validateBindDefinitionSpec(ctx context.Context, r *BindDefinition) (admission.Warnings, error) {
	ctx, cancel := context.WithTimeout(ctx, WebhookCacheTimeout)
	defer cancel()

	logger := log.FromContext(ctx).WithName("binddefinition-webhook")
	var warnings admission.Warnings

	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind}
	if err := validateBindDefinitionRequiredFields(kind, r); err != nil {
		return warnings, err
	}
	if err := validateBindDefinitionSubjects(kind, r.Name, r.Spec.Subjects); err != nil {
		return warnings, err
	}

	existingBD, err := v.findBindDefinitionTargetNameConflict(ctx, r)
	if err != nil {
		logger.Error(err, "failed to list BindDefinitions", "targetName", r.Spec.TargetName)
		return nil, apierrors.NewInternalError(errors.New("unable to list BindDefinitions"))
	}
	if existingBD != nil {
		logger.Info("validation failed: duplicate targetName",
			"name", r.Name, "targetName", r.Spec.TargetName, "conflictsWith", existingBD.Name)
		return nil, apierrors.NewBadRequest(fmt.Sprintf("targetName %s is already in use by BindDefinition %q", r.Spec.TargetName, existingBD.Name))
	}

	// Check for cross-type targetName collision with RestrictedBindDefinitions (only need first match).
	existingRBD, err := v.findRestrictedBindDefinitionTargetNameConflict(ctx, r)
	if err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions", "targetName", r.Spec.TargetName)
		return nil, apierrors.NewInternalError(errors.New("unable to list RestrictedBindDefinitions"))
	}
	if existingRBD != nil {
		return nil, apierrors.NewBadRequest(
			fmt.Sprintf("targetName %s is already in use by RestrictedBindDefinition %q", r.Spec.TargetName, existingRBD.Name))
	}

	// Determine the missing-role policy from annotation.
	policy := r.GetMissingRolePolicy()

	if err := validateNamespaceBindings(kind, r.Name, r.Spec.RoleBindings); err != nil {
		logger.Info("validation failed: invalid roleBindings", "name", r.Name, "error", err.Error())
		return warnings, err
	}
	if err := v.validateRoleBindingNameCollisions(ctx, kind, r); err != nil {
		return warnings, err
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
		if err := v.reader().Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
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
				return warnings, apierrors.NewInternalError(errors.New("unable to fetch ClusterRole"))
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
			if err := v.reader().Get(ctx, client.ObjectKey{Name: clusterRoleRef}, clusterRole); err != nil {
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
					return warnings, apierrors.NewInternalError(errors.New("unable to fetch ClusterRole"))
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
				continueToken := ""
				for {
					namespaceList := &corev1.NamespaceList{}
					nextContinueToken, err := listAdmissionPage(
						ctx,
						v.reader(),
						namespaceList,
						continueToken,
						client.MatchingLabelsSelector{Selector: selector},
					)
					if err != nil {
						logger.Error(err, "failed to list namespaces", "selector", selector.String())
						return warnings, apierrors.NewInternalError(errors.New("unable to list namespaces"))
					}
					for _, ns := range namespaceList.Items {
						namespaceSet[ns.Name] = ns
					}
					if nextContinueToken == "" {
						break
					}
					continueToken = nextContinueToken
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
						logger.Error(err, "failed to validate role reference",
							"name", r.Name, "namespace", ns.Name, "roleName", roleRef)
						return warnings, apierrors.NewInternalError(errors.New("unable to validate role reference"))
					}
				}
			}
		} else if roleBinding.Namespace != "" {
			// Validate RoleRefs in the explicitly specified namespace.
			// First verify the namespace exists and is not terminating.
			ns := &corev1.Namespace{}
			if err := v.reader().Get(ctx, client.ObjectKey{Name: roleBinding.Namespace}, ns); err != nil {
				if apierrors.IsNotFound(err) {
					logger.Info("namespace not found, skipping role checks",
						"name", r.Name, "namespace", roleBinding.Namespace)
					warnings = append(warnings, fmt.Sprintf("namespace %q does not exist yet — role references will be validated once it is created", roleBinding.Namespace))
					continue
				}
				logger.Error(err, "failed to get namespace", "namespace", roleBinding.Namespace)
				return warnings, apierrors.NewInternalError(errors.New("unable to get namespace"))
			}
			if ns.Status.Phase == corev1.NamespaceTerminating {
				continue
			}
			for _, roleRef := range roleBinding.RoleRefs {
				if err := v.checkRoleExists(ctx, roleBinding.Namespace, roleRef, r.Name, policy, roleExists, &missingRoles); err != nil {
					logger.Error(err, "failed to validate role reference",
						"name", r.Name, "namespace", roleBinding.Namespace, "roleName", roleRef)
					return warnings, apierrors.NewInternalError(errors.New("unable to validate role reference"))
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

func (v *BindDefinitionValidator) validateRoleBindingNameCollisions(
	ctx context.Context,
	kind schema.GroupKind,
	obj *BindDefinition,
) error {
	return validateRoleBindingNameCollisionClaims(ctx, kind, obj.Name, obj.Spec.TargetName, nil, obj.Spec.RoleBindings, v.resolveRoleBindingNamespacesForValidation)
}

func (v *BindDefinitionValidator) resolveRoleBindingNamespacesForValidation(
	ctx context.Context,
	binding NamespaceBinding,
	bindingIndex int,
	objectName string,
) ([]string, error) {
	if binding.Namespace != "" {
		return []string{binding.Namespace}, nil
	}

	namespaceSet := make(map[string]struct{})
	for selectorIndex, namespaceSelector := range binding.NamespaceSelector {
		selector, err := metav1.LabelSelectorAsSelector(&namespaceSelector)
		if err != nil {
			return nil, apierrors.NewInvalid(
				schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind},
				objectName,
				field.ErrorList{field.Invalid(
					field.NewPath("spec", "roleBindings").Index(bindingIndex).Child("namespaceSelector").Index(selectorIndex),
					namespaceSelector,
					err.Error())})
		}

		continueToken := ""
		for {
			namespaceList := &corev1.NamespaceList{}
			nextContinueToken, err := listAdmissionPage(
				ctx,
				v.reader(),
				namespaceList,
				continueToken,
				client.MatchingLabelsSelector{Selector: selector},
			)
			if err != nil {
				return nil, apierrors.NewInternalError(errors.New("unable to list namespaces for RoleBinding name collision validation"))
			}
			for i := range namespaceList.Items {
				namespace := &namespaceList.Items[i]
				if namespace.Status.Phase == corev1.NamespaceTerminating {
					continue
				}
				namespaceSet[namespace.Name] = struct{}{}
			}
			if nextContinueToken == "" {
				break
			}
			continueToken = nextContinueToken
		}
	}

	namespaces := make([]string, 0, len(namespaceSet))
	for namespace := range namespaceSet {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	return namespaces, nil
}

//nolint:nilnil // A nil object with nil error means no conflicting targetName was found.
func (v *BindDefinitionValidator) findBindDefinitionTargetNameConflict(
	ctx context.Context,
	obj *BindDefinition,
) (*BindDefinition, error) {
	reader := v.reader()
	continueToken := ""
	for {
		bdList := &BindDefinitionList{}
		nextContinueToken, err := listAdmissionPage(ctx, reader, bdList, continueToken)
		if err != nil {
			return nil, err
		}
		for i := range bdList.Items {
			existing := &bdList.Items[i]
			if existing.Spec.TargetName == obj.Spec.TargetName && existing.Name != obj.Name {
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
func (v *BindDefinitionValidator) findRestrictedBindDefinitionTargetNameConflict(
	ctx context.Context,
	obj *BindDefinition,
) (*RestrictedBindDefinition, error) {
	reader := v.reader()
	continueToken := ""
	for {
		rbdList := &RestrictedBindDefinitionList{}
		nextContinueToken, err := listAdmissionPage(ctx, reader, rbdList, continueToken)
		if err != nil {
			return nil, err
		}
		for i := range rbdList.Items {
			existing := &rbdList.Items[i]
			if existing.Spec.TargetName == obj.Spec.TargetName {
				return existing, nil
			}
		}
		if nextContinueToken == "" {
			return nil, nil
		}
		continueToken = nextContinueToken
	}
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

func validateNamespaceBindings(kind schema.GroupKind, name string, bindings []NamespaceBinding) error {
	for i, binding := range bindings {
		if (len(binding.ClusterRoleRefs) > 0 || len(binding.RoleRefs) > 0) &&
			binding.Namespace == "" &&
			len(binding.NamespaceSelector) == 0 {
			return apierrors.NewInvalid(
				kind,
				name,
				field.ErrorList{field.Required(
					field.NewPath("spec", "roleBindings").Index(i).Child("namespace"),
					"roleBindings entries with role refs must specify namespace or namespaceSelector")})
		}
		for j, roleRef := range binding.RoleRefs {
			if slices.Contains(binding.ClusterRoleRefs, roleRef) {
				return apierrors.NewInvalid(
					kind,
					name,
					field.ErrorList{field.Duplicate(
						field.NewPath("spec", "roleBindings").Index(i).Child("roleRefs").Index(j),
						roleRef)})
			}
		}
		for j, selector := range binding.NamespaceSelector {
			if isLabelSelectorEmpty(&selector) {
				continue
			}
			if _, err := metav1.LabelSelectorAsSelector(&selector); err != nil {
				return apierrors.NewInvalid(
					kind,
					name,
					field.ErrorList{field.Invalid(
						field.NewPath("spec", "roleBindings").Index(i).Child("namespaceSelector").Index(j),
						selector,
						err.Error())})
			}
			for key := range selector.MatchLabels {
				if key != LabelKeyOwner && key != LabelKeyTenant && key != LabelKeyThirdParty && key != corev1.LabelMetadataName {
					return apierrors.NewInvalid(
						kind,
						name,
						field.ErrorList{field.Invalid(
							field.NewPath("spec", "roleBindings").Index(i).Child("namespaceSelector").Index(j).Child("matchLabels").Key(key),
							key,
							"namespace admission selectors may only use tracked ownership labels ("+LabelKeyOwner+", "+LabelKeyTenant+", "+LabelKeyThirdParty+") or "+corev1.LabelMetadataName)})
				}
			}
			for _, expr := range selector.MatchExpressions {
				if expr.Key != LabelKeyOwner && expr.Key != LabelKeyTenant && expr.Key != LabelKeyThirdParty && expr.Key != corev1.LabelMetadataName {
					return apierrors.NewInvalid(
						kind,
						name,
						field.ErrorList{field.Invalid(
							field.NewPath("spec", "roleBindings").Index(i).Child("namespaceSelector").Index(j).Child("matchExpressions").Key(expr.Key),
							expr.Key,
							"namespace admission selectors may only use tracked ownership labels ("+LabelKeyOwner+", "+LabelKeyTenant+", "+LabelKeyThirdParty+") or "+corev1.LabelMetadataName)})
				}
			}
		}
	}
	return nil
}

func validateBindDefinitionRequiredFields(kind schema.GroupKind, obj *BindDefinition) error {
	var allErrs field.ErrorList
	if obj.Spec.TargetName == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "targetName"), "targetName is required"))
	}
	if len(obj.Spec.Subjects) == 0 {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "subjects"), "at least one subject must be specified"))
	}
	hasReferencedRole := len(obj.Spec.ClusterRoleBindings.ClusterRoleRefs) > 0
	for _, binding := range obj.Spec.RoleBindings {
		if len(binding.ClusterRoleRefs) > 0 || len(binding.RoleRefs) > 0 {
			hasReferencedRole = true
			break
		}
	}
	if !hasReferencedRole {
		allErrs = append(allErrs, field.Required(field.NewPath("spec"), "at least one binding with a referenced role must be specified"))
	}
	if len(allErrs) > 0 {
		return apierrors.NewInvalid(kind, obj.Name, allErrs)
	}
	return nil
}

func validateBindDefinitionSubjects(kind schema.GroupKind, name string, subjects []rbacv1.Subject) error {
	var allErrs field.ErrorList
	for i, subject := range subjects {
		subjectPath := field.NewPath("spec", "subjects").Index(i)
		if subject.Name == "" {
			allErrs = append(allErrs, field.Required(subjectPath.Child("name"), "subject name is required"))
		}
		switch subject.Kind {
		case rbacv1.UserKind, rbacv1.GroupKind:
			if subject.APIGroup != rbacv1.GroupName {
				allErrs = append(allErrs, field.Invalid(subjectPath.Child("apiGroup"), subject.APIGroup, "User and Group subjects must use rbac.authorization.k8s.io"))
			}
			if subject.Namespace != "" {
				allErrs = append(allErrs, field.Forbidden(subjectPath.Child("namespace"), "User and Group subjects must not set namespace"))
			}
		case rbacv1.ServiceAccountKind:
			if subject.APIGroup != "" {
				allErrs = append(allErrs, field.Forbidden(subjectPath.Child("apiGroup"), "ServiceAccount subjects must not set apiGroup"))
			}
			if subject.Namespace == "" {
				allErrs = append(allErrs, field.Required(subjectPath.Child("namespace"), "ServiceAccount subjects must specify a namespace"))
			} else {
				for _, msg := range utilvalidation.IsDNS1123Label(subject.Namespace) {
					allErrs = append(allErrs, field.Invalid(subjectPath.Child("namespace"), subject.Namespace, msg))
				}
			}
		default:
			allErrs = append(allErrs, field.NotSupported(subjectPath.Child("kind"), subject.Kind, supportedSubjectKinds))
		}
	}
	if len(allErrs) > 0 {
		return apierrors.NewInvalid(kind, name, allErrs)
	}
	return nil
}

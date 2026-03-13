package webhooks

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/metrics"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch

// legacyOwnerLabel is the label key from the legacy schiff.telekom.de CRDs
// used for namespace ownership before the t-caas migration.
const legacyOwnerLabel = "schiff.telekom.de/owner"

// NamespaceValidator is a validating webhook that validates namespace operations based on BindDefinitions.
type NamespaceValidator struct {
	Client       client.Client
	Decoder      admission.Decoder
	TDGMigration bool
}

// Handle validates namespace operations based on BindDefinition configurations.
func (v *NamespaceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-validator")

	// Only handle namespace CREATE, UPDATE, DELETE operations
	if req.Kind.Kind != "Namespace" {
		logger.V(4).Info("webhook request for non-Namespace resource - ignoring",
			"kind", req.Kind.Kind)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	logger.V(2).Info("namespace validator webhook triggered",
		"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)

	// Check for bypass conditions
	bypassResult := CheckBypass(req.UserInfo.Username, req.UserInfo.Groups, req.Operation, req.Name, v.TDGMigration)
	if bypassResult.ShouldBypass {
		logger.Info("AUDIT: webhook bypass granted",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
			"bypassReason", bypassResult.Reason, "webhook", "validator")

		// For Create and Delete operations, bypass users skip all validation.
		if req.Operation != admissionv1.Update {
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
			return admission.Allowed("")
		}
	}

	ns, oldNs, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		return *errResp
	}

	if req.Operation == admissionv1.Update {
		logger.V(2).Info("validating namespace update", "namespace", req.Name)

		if !bypassResult.SkipUpdateLabelChecks {
			if resp := v.validateLabelImmutability(logger, req, &ns, &oldNs, bypassResult); resp != nil {
				return *resp
			}

			if resp := v.crossValidateLegacyLabels(logger, req, &ns, &oldNs); resp != nil {
				return *resp
			}

			logger.V(3).Info("namespace labels validated", "namespace", req.Name)
		} else {
			logger.V(1).Info("AUDIT: privileged bypass skipped update label checks",
				"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
				"bypassReason", bypassResult.Reason)
		}
	}

	// Bypass users can skip the BindDefinition authorization check once
	// any required update-label checks have been processed.
	if bypassResult.ShouldBypass {
		logger.V(2).Info("bypass granted - allowing namespace operation",
			"namespace", req.Name,
			"operation", req.Operation,
			"bypassReason", bypassResult.Reason,
			"skipUpdateLabelChecks", bypassResult.SkipUpdateLabelChecks)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	return v.authorizeViaBindDefinitions(ctx, logger, req, &ns)
}

// decodeNamespaces decodes the namespace objects from the admission request based on
// the operation type. Returns the decoded namespaces and an error response if decoding fails.
func (v *NamespaceValidator) decodeNamespaces(logger logr.Logger, req admission.Request) (ns, oldNs corev1.Namespace, errResp *admission.Response) {
	var err error
	var oldErr error

	switch req.Operation {
	case admissionv1.Create:
		err = v.Decoder.Decode(req, &ns)
	case admissionv1.Update:
		err = v.Decoder.Decode(req, &ns)
		oldErr = v.Decoder.DecodeRaw(req.OldObject, &oldNs)
	case admissionv1.Delete:
		switch {
		case len(req.OldObject.Raw) > 0:
			err = v.Decoder.DecodeRaw(req.OldObject, &ns)
		case len(req.Object.Raw) > 0:
			err = v.Decoder.DecodeRaw(req.Object, &ns)
		default:
			err = fmt.Errorf("missing namespace object for delete operation")
		}
	default:
		logger.V(3).Info("unknown operation type - allowing", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		resp := admission.Allowed("")
		return ns, oldNs, &resp
	}

	if err != nil {
		logger.Error(err, "failed to decode namespace object", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		resp := admission.Errored(http.StatusBadRequest, err)
		return ns, oldNs, &resp
	}
	if oldErr != nil {
		logger.Error(oldErr, "failed to decode old namespace object", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		resp := admission.Errored(http.StatusBadRequest, oldErr)
		return ns, oldNs, &resp
	}

	return ns, oldNs, nil
}

// validateLabelImmutability checks that controlled labels are not modified or removed
// during namespace updates. Initial adoption (adding a label for the first time) is allowed.
// Returns a denial response if a violation is found, or nil if validation passes.
func (v *NamespaceValidator) validateLabelImmutability(logger logr.Logger, req admission.Request, ns, oldNs *corev1.Namespace, bypassResult BypassCheckResult) *admission.Response {
	// Ensure Labels maps are not nil to prevent nil pointer dereference
	if ns.Labels == nil {
		ns.Labels = map[string]string{}
	}
	if oldNs.Labels == nil {
		oldNs.Labels = map[string]string{}
	}

	// Define the label keys of interest
	labelKeys := []string{
		authzv1alpha1.LabelKeyOwner,
		authzv1alpha1.LabelKeyTenant,
		authzv1alpha1.LabelKeyThirdParty,
	}
	if v.TDGMigration {
		labelKeys = append(labelKeys, legacyOwnerLabel)
	}

	ownerReclassification := v.detectOwnerReclassification(logger, req, ns, oldNs, bypassResult)

	// Compare labels between old and new namespaces.
	// Initial adoption is allowed, but modifying or removing existing labels is denied.
	for _, key := range labelKeys {
		oldValue, oldExists := oldNs.Labels[key]
		newValue, newExists := ns.Labels[key]

		// Allow initial label adoption: label didn't exist before, now being added.
		if !oldExists && newExists {
			logger.V(2).Info("label adoption allowed",
				"namespace", req.Name, "label", key, "newValue", newValue)
			continue
		}

		// During tenant↔thirdparty reclassification, allow changes to owner/tenant/thirdparty labels.
		if ownerReclassification && (key == authzv1alpha1.LabelKeyOwner ||
			key == authzv1alpha1.LabelKeyTenant ||
			key == authzv1alpha1.LabelKeyThirdParty) {
			logger.V(2).Info("label change allowed during reclassification",
				"namespace", req.Name, "label", key, "oldValue", oldValue, "newValue", newValue)
			continue
		}

		// Allow removal of the legacy schiff.telekom.de/owner label by bypass users
		// once the new t-caas.telekom.com/owner label is established.
		if bypassResult.ShouldBypass &&
			key == legacyOwnerLabel && oldExists && !newExists {
			_, newOwnerExists := ns.Labels[authzv1alpha1.LabelKeyOwner]
			if newOwnerExists {
				logger.V(1).Info("AUDIT: legacy label removal allowed (new owner label exists)",
					"namespace", req.Name, "removedLabel", key, "removedValue", oldValue)
				continue
			}
		}

		// Deny modification of existing label value or removal of existing label
		if oldExists && (!newExists || oldValue != newValue) {
			logger.V(2).Info("label modification denied",
				"namespace", req.Name, "label", key, "oldValue", oldValue, "newValue", newValue)
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
			resp := admission.Denied(fmt.Sprintf(DenialLabelModificationFmt, key))
			return &resp
		}
	}

	return nil
}

// detectOwnerReclassification returns true if a tenant↔thirdparty reclassification is
// happening during TDG migration by a bypass user. Platform is never reclassifiable.
func (v *NamespaceValidator) detectOwnerReclassification(logger logr.Logger, req admission.Request, ns, oldNs *corev1.Namespace, bypassResult BypassCheckResult) bool {
	if !v.TDGMigration || !bypassResult.ShouldBypass {
		return false
	}
	oldOwner := oldNs.Labels[authzv1alpha1.LabelKeyOwner]
	newOwner := ns.Labels[authzv1alpha1.LabelKeyOwner]
	if oldOwner == newOwner {
		return false
	}
	// Only tenant↔thirdparty is allowed; platform is always immutable.
	// Both old and new must be non-empty to prevent label removal from being treated as reclassification.
	if oldOwner == authzv1alpha1.OwnerPlatform || newOwner == authzv1alpha1.OwnerPlatform ||
		oldOwner == "" || newOwner == "" {
		return false
	}
	logger.V(1).Info("AUDIT: tenant/thirdparty reclassification allowed",
		"namespace", req.Name, "oldOwner", oldOwner, "newOwner", newOwner)
	return true
}

// crossValidateLegacyLabels validates that legacy schiff.telekom.de/owner to t-caas owner
// mapping is consistent during label adoption when TDG migration is enabled.
// Returns a denial response if inconsistent, or nil if validation passes.
func (v *NamespaceValidator) crossValidateLegacyLabels(logger logr.Logger, req admission.Request, ns, oldNs *corev1.Namespace) *admission.Response {
	if !v.TDGMigration {
		return nil
	}

	legacyOwner := oldNs.Labels[legacyOwnerLabel]
	newOwner, newOwnerExists := ns.Labels[authzv1alpha1.LabelKeyOwner]
	_, oldOwnerExists := oldNs.Labels[authzv1alpha1.LabelKeyOwner]

	// Only validate during initial adoption of the new owner label
	if legacyOwner == "" || !newOwnerExists || oldOwnerExists {
		return nil
	}

	isLegacyPlatform := legacyOwner == "platform" || legacyOwner == "schiff"
	isNewPlatform := newOwner == authzv1alpha1.OwnerPlatform

	if isLegacyPlatform && !isNewPlatform {
		logger.V(2).Info("adoption denied: legacy platform namespace cannot become non-platform",
			"namespace", req.Name, "legacyOwner", legacyOwner, "newOwner", newOwner)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
		resp := admission.Denied(fmt.Sprintf(DenialLegacyPlatformToNonPlatformFmt, legacyOwnerLabel, legacyOwner, newOwner))
		return &resp
	}
	if !isLegacyPlatform && isNewPlatform {
		logger.V(2).Info("adoption denied: legacy non-platform namespace cannot become platform",
			"namespace", req.Name, "legacyOwner", legacyOwner, "newOwner", newOwner)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
		resp := admission.Denied(fmt.Sprintf(DenialLegacyNonPlatformToPlatformFmt, legacyOwnerLabel, legacyOwner))
		return &resp
	}

	return nil
}

// authorizeViaBindDefinitions checks if the requesting user is authorized by any
// BindDefinition to perform the operation on the namespace.
func (v *NamespaceValidator) authorizeViaBindDefinitions(ctx context.Context, logger logr.Logger, req admission.Request, ns *corev1.Namespace) admission.Response {
	userGroups := req.UserInfo.Groups
	saInfo := ParseServiceAccount(req.UserInfo.Username)
	logger.V(3).Info("parsed user info", "namespace", req.Name,
		"username", req.UserInfo.Username, "isServiceAccount", saInfo.IsServiceAccount,
		"groupCount", len(userGroups))

	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	listCtx, cancel := context.WithTimeout(ctx, authzv1alpha1.WebhookCacheTimeout)
	defer cancel()
	if err := v.Client.List(listCtx, bindDefinitions); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "namespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusInternalServerError, err)
	}

	logger.V(2).Info("checking authorization against BindDefinitions",
		"namespace", req.Name, "bindDefinitionCount", len(bindDefinitions.Items))

	isAllowed := false
	for bdIdx, bindDef := range bindDefinitions.Items {
		if IsRestrictedBindDefinition(bindDef.Name) {
			logger.V(4).Info("skipping restricted BindDefinition", "bindDefinitionName", bindDef.Name)
			continue
		}
		logger.V(3).Info("checking BindDefinition", "namespace", req.Name,
			"bindDefinitionName", bindDef.Name, "bdIndex", bdIdx, "subjectCount", len(bindDef.Spec.Subjects))

		if !MatchesSubjects(userGroups, saInfo, bindDef.Spec.Subjects) {
			logger.V(4).Info("user not found in BindDefinition subjects",
				"namespace", req.Name, "bindDefinitionName", bindDef.Name)
			continue
		}

		logger.V(3).Info("user matched in BindDefinition", "namespace", req.Name, "bindDefinition", bindDef.Name)

		for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
			namespaceMatchFound := false
			for nsIdx, namespaceSelector := range roleBinding.NamespaceSelector {
				matches, err := namespaceMatchesSelector(ns, &namespaceSelector)
				if err != nil {
					logger.Error(err, "failed to match namespace selector",
						"namespace", req.Name, "bindDefinition", bindDef.Name)
					metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
					return admission.Errored(http.StatusInternalServerError, err)
				}
				if matches {
					namespaceMatchFound = true
					logger.V(3).Info("namespace matched selector", "namespace", req.Name,
						"bindDefinition", bindDef.Name, "roleBindingIndex", rbIdx, "selectorIndex", nsIdx)
					break
				}
			}
			if namespaceMatchFound {
				isAllowed = true
				logger.V(2).Info("user authorized for namespace operation", "namespace", req.Name,
					"bindDefinition", bindDef.Name, "username", req.UserInfo.Username)
				break
			}
		}
		if isAllowed {
			break
		}
	}

	if isAllowed {
		logger.V(1).Info("namespace operation allowed",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	// Allow orphan cleanup only when the namespace has a non-empty owner label
	// and does not match any BindDefinition selector. This keeps delete
	// authorization conservative for namespaces that are still targeted.
	if req.Operation == admissionv1.Delete {
		ownerValue, hasOwner := ns.Labels[authzv1alpha1.LabelKeyOwner]
		if hasOwner && ownerValue != "" && !namespaceMatchedByAnyBindDefinition(logger, ns, bindDefinitions.Items) {
			logger.V(1).Info("namespace delete allowed - owner label is unclaimed by any BindDefinition",
				"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
			return admission.Allowed("")
		}
	}

	// Last resort: if the user is a ServiceAccount performing CREATE/UPDATE, check if
	// its source namespace has the same tracked ownership labels as the target namespace (issue #202).
	// This is restricted to CREATE/UPDATE — DELETE is intentionally excluded.
	if saInfo.IsServiceAccount &&
		(req.Operation == admissionv1.Create || req.Operation == admissionv1.Update) {
		saCtx, saCancel := context.WithTimeout(ctx, authzv1alpha1.WebhookCacheTimeout)
		defer saCancel()
		inheritedLabels, saErr := GetSANamespaceTrackedLabels(saCtx, v.Client, saInfo)
		if saErr != nil {
			logger.Error(saErr, "failed to lookup SA namespace labels", "saNamespace", saInfo.Namespace, "targetNamespace", req.Name)
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
			return admission.Errored(http.StatusInternalServerError, saErr)
		}
		if len(inheritedLabels) > 0 {
			// Symmetric comparison: all inherited labels must match AND the target
			// must not have extra tracked ownership labels beyond what the SA namespace has.
			labelsMatch := true
			for k, val := range inheritedLabels {
				actual, ok := ns.Labels[k]
				if !ok || actual != val {
					labelsMatch = false
					break
				}
			}
			if labelsMatch {
				// Check for extra tracked keys on the target that the SA namespace doesn't have.
				if extraKey := FindExtraTrackedKey(ns.Labels, inheritedLabels); extraKey != "" {
					labelsMatch = false
				}
			}
			if labelsMatch {
				logger.V(1).Info("SA namespace label inheritance - authorized via matching SA source namespace labels",
					"namespace", req.Name, "saNamespace", saInfo.Namespace, "username", req.UserInfo.Username)
				metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
				return admission.Allowed("")
			}
		}
	}

	denialMsg := fmt.Sprintf(DenialNotNamespaceOwnerFmt, req.UserInfo.Username, ns.Name)
	logger.V(1).Info("namespace operation denied", "namespace", req.Name,
		"operation", req.Operation, "username", req.UserInfo.Username, "reason", denialMsg)
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
	return admission.Denied(denialMsg)
}

func namespaceMatchesSelector(ns *corev1.Namespace, selector *metav1.LabelSelector) (bool, error) {
	// Convert the LabelSelector into a labels.Selector
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, err
	}

	// Check if the namespace's labels match the selector
	return labelSelector.Matches(labels.Set(ns.Labels)), nil
}

func namespaceMatchedByAnyBindDefinition(logger logr.Logger, ns *corev1.Namespace, bindDefs []authzv1alpha1.BindDefinition) bool {
	for _, bindDef := range bindDefs {
		if IsRestrictedBindDefinition(bindDef.Name) {
			continue
		}

		for _, roleBinding := range bindDef.Spec.RoleBindings {
			for _, namespaceSelector := range roleBinding.NamespaceSelector {
				matches, err := namespaceMatchesSelector(ns, &namespaceSelector)
				if err != nil {
					// Fail closed: if selector evaluation fails, treat namespace as matched
					// to avoid accidentally allowing deletion.
					logger.Error(err, "failed to evaluate namespace selector while checking namespace delete; treating namespace as matched",
						"namespace", ns.Name, "bindDefinition", bindDef.Name)
					return true
				}

				if matches {
					return true
				}
			}
		}
	}

	return false
}

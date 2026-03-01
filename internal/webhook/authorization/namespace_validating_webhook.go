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

// InjectDecoder injects the decoder into the NamespaceValidator.
func (v *NamespaceValidator) InjectDecoder(d admission.Decoder) error {
	v.Decoder = d
	return nil
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
	bypassResult := CheckValidatorBypass(req.UserInfo.Username, req.Operation, req.Name, v.TDGMigration)
	if bypassResult.ShouldBypass {
		logger.Info("AUDIT: webhook bypass granted",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
			"bypassReason", bypassResult.Reason, "webhook", "validator")

		// Even bypass users must go through label immutability checks on updates.
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

		if resp := v.validateLabelImmutability(logger, req, &ns, &oldNs, bypassResult); resp != nil {
			return *resp
		}

		if resp := v.crossValidateLegacyLabels(logger, req, &ns, &oldNs); resp != nil {
			return *resp
		}

		logger.V(3).Info("namespace labels validated", "namespace", req.Name)
	}

	// Bypass users that passed the label immutability check above can skip
	// the BindDefinition authorization check.
	if bypassResult.ShouldBypass {
		logger.V(2).Info("bypass user passed label immutability check - allowing",
			"namespace", req.Name, "bypassReason", bypassResult.Reason)
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
		err = v.Decoder.DecodeRaw(req.OldObject, &ns)
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
			resp := admission.Denied(fmt.Sprintf("Modification of label '%s' is not allowed", key))
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
		resp := admission.Denied(fmt.Sprintf("Legacy platform namespace (%s=%s) cannot be adopted as '%s'", legacyOwnerLabel, legacyOwner, newOwner))
		return &resp
	}
	if !isLegacyPlatform && isNewPlatform {
		logger.V(2).Info("adoption denied: legacy non-platform namespace cannot become platform",
			"namespace", req.Name, "legacyOwner", legacyOwner, "newOwner", newOwner)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
		resp := admission.Denied(fmt.Sprintf("Legacy non-platform namespace (%s=%s) cannot be adopted as 'platform'", legacyOwnerLabel, legacyOwner))
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
	if err := v.Client.List(ctx, bindDefinitions); err != nil {
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

	denialMsg := fmt.Sprintf("User %s is not the owner of namespace %s", req.UserInfo.Username, ns.Name)
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

package webhooks

import (
	"context"
	"fmt"
	"net/http"

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
		// Log bypass at Info level for security auditing
		logger.Info("AUDIT: webhook bypass granted",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
			"bypassReason", bypassResult.Reason, "webhook", "validator")

		// Even bypass users must go through label immutability checks on updates.
		// This prevents ownership type switches (e.g. platform -> tenant) even by
		// trusted migration accounts. Only initial label adoption and non-label
		// changes are allowed through the bypass.
		//
		// For Create and Delete operations, bypass users skip all validation
		// including the BindDefinition authorization check. This is intentional:
		// bypass users (e.g. helm-controller) are trusted to create namespaces
		// with appropriate labels as part of GitOps-driven cluster management.
		if req.Operation != admissionv1.Update {
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
			return admission.Allowed("")
		}
	}

	var ns corev1.Namespace
	var oldNs corev1.Namespace
	var err error
	var oldErr error

	switch req.Operation {
	case admissionv1.Create:
		// For create operations, decode the object
		err = v.Decoder.Decode(req, &ns)
	case admissionv1.Update:
		// For update operations, decode both object and old object
		err = v.Decoder.Decode(req, &ns)
		oldErr = v.Decoder.DecodeRaw(req.OldObject, &oldNs)
	case admissionv1.Delete:
		// For update and delete operations, decode the old object
		err = v.Decoder.DecodeRaw(req.OldObject, &ns)
	default:
		logger.V(3).Info("unknown operation type - allowing", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	if err != nil {
		logger.Error(err, "failed to decode namespace object", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusBadRequest, err)
	}
	if oldErr != nil {
		logger.Error(oldErr, "failed to decode old namespace object", "namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusBadRequest, oldErr)
	}

	if req.Operation == admissionv1.Update {
		logger.V(2).Info("validating namespace update", "namespace", req.Name)

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

		// If TDGMigration is enabled, add the additional label key
		if v.TDGMigration {
			labelKeys = append(labelKeys, "schiff.telekom.de/owner")
		}
		// Determine if a tenant↔thirdparty reclassification is happening.
		// In the legacy system (TDG), there was no thirdparty concept — everything
		// non-platform was "tenant". During TDG migration, bypass users are allowed
		// to reclassify between tenant and thirdparty, including changing the
		// associated tenant/thirdparty name labels.
		ownerReclassification := false
		if v.TDGMigration && bypassResult.ShouldBypass {
			oldOwner := oldNs.Labels[authzv1alpha1.LabelKeyOwner]
			newOwner := ns.Labels[authzv1alpha1.LabelKeyOwner]
			if oldOwner != newOwner {
				// Only tenant↔thirdparty is allowed; platform is always immutable.
				// Both old and new must be non-empty to prevent label removal from
				// being treated as a reclassification.
				if oldOwner != authzv1alpha1.OwnerPlatform && newOwner != authzv1alpha1.OwnerPlatform &&
					oldOwner != "" && newOwner != "" {
					ownerReclassification = true
					logger.V(1).Info("AUDIT: tenant/thirdparty reclassification allowed",
						"namespace", req.Name, "oldOwner", oldOwner, "newOwner", newOwner)
				}
			}
		}

		// Compare the labels between old and new namespaces.
		// Initial adoption (adding a label that didn't exist before) is allowed,
		// but modifying an existing label's value or removing an existing label is denied.
		// This enables namespaces to be adopted into the auth-operator contract
		// by setting t-caas labels for the first time.
		//
		// Exception: during TDG migration, bypass users may reclassify between
		// tenant and thirdparty (including the associated name labels), since
		// the thirdparty concept did not exist before.
		for _, key := range labelKeys {
			oldValue, oldExists := oldNs.Labels[key]
			newValue, newExists := ns.Labels[key]

			// Allow initial label adoption: label didn't exist before, now being added.
			// This applies to ALL users (bypass and non-bypass). Non-bypass users are
			// still subject to the BindDefinition authorization check (below) which
			// verifies the user has permission for the namespace with the new labels.
			if !oldExists && newExists {
				logger.V(2).Info("label adoption allowed",
					"namespace", req.Name, "label", key, "newValue", newValue)
				continue
			}

			// During tenant↔thirdparty reclassification, allow changes to the
			// owner, tenant, and thirdparty labels (but NOT schiff.telekom.de/owner)
			if ownerReclassification && (key == authzv1alpha1.LabelKeyOwner ||
				key == authzv1alpha1.LabelKeyTenant ||
				key == authzv1alpha1.LabelKeyThirdParty) {
				logger.V(2).Info("label change allowed during reclassification",
					"namespace", req.Name, "label", key, "oldValue", oldValue, "newValue", newValue)
				continue
			}

			// Allow removal of the legacy schiff.telekom.de/owner label by bypass users
			// once the new t-caas.telekom.com/owner label is established.
			// This supports the final migration step: cleaning up legacy labels.
			// Note: the v.TDGMigration guard is implicit — schiff.telekom.de/owner is
			// only in labelKeys when TDGMigration is enabled (see above).
			if bypassResult.ShouldBypass &&
				key == "schiff.telekom.de/owner" && oldExists && !newExists {
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
				return admission.Denied(fmt.Sprintf("Modification of label '%s' is not allowed", key))
			}
		}

		// Cross-validate legacy label consistency during adoption.
		// If TDGMigration is enabled and the legacy schiff.telekom.de/owner label exists,
		// ensure the new t-caas owner label is consistent:
		// - Legacy "platform" or "schiff" must map to new "platform"
		// - Legacy anything else must NOT map to new "platform" (can be tenant or thirdparty)
		//
		// This check runs for ALL users (bypass and non-bypass) during initial adoption.
		// This is intentional: regardless of who performs the adoption, the legacy→new
		// owner mapping must be consistent to prevent misclassification.
		if v.TDGMigration {
			legacyOwner := oldNs.Labels["schiff.telekom.de/owner"]
			newOwner, newOwnerExists := ns.Labels[authzv1alpha1.LabelKeyOwner]
			_, oldOwnerExists := oldNs.Labels[authzv1alpha1.LabelKeyOwner]

			if legacyOwner != "" && newOwnerExists && !oldOwnerExists {
				isLegacyPlatform := legacyOwner == "platform" || legacyOwner == "schiff"
				isNewPlatform := newOwner == authzv1alpha1.OwnerPlatform

				if isLegacyPlatform && !isNewPlatform {
					logger.V(2).Info("adoption denied: legacy platform namespace cannot become non-platform",
						"namespace", req.Name, "legacyOwner", legacyOwner, "newOwner", newOwner)
					metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
					return admission.Denied(fmt.Sprintf("Legacy platform namespace (schiff.telekom.de/owner=%s) cannot be adopted as '%s'", legacyOwner, newOwner))
				}
				if !isLegacyPlatform && isNewPlatform {
					logger.V(2).Info("adoption denied: legacy non-platform namespace cannot become platform",
						"namespace", req.Name, "legacyOwner", legacyOwner, "newOwner", newOwner)
					metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
					return admission.Denied(fmt.Sprintf("Legacy non-platform namespace (schiff.telekom.de/owner=%s) cannot be adopted as 'platform'", legacyOwner))
				}
			}
		}

		logger.V(3).Info("namespace labels validated",
			"namespace", req.Name)
	}

	// Bypass users that passed the label immutability check above can skip
	// the BindDefinition authorization check.
	if bypassResult.ShouldBypass {
		logger.V(2).Info("bypass user passed label immutability check - allowing",
			"namespace", req.Name, "bypassReason", bypassResult.Reason)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	// Extract user information and parse service account
	userGroups := req.UserInfo.Groups
	saInfo := ParseServiceAccount(req.UserInfo.Username)
	if saInfo.IsServiceAccount {
		logger.V(3).Info("user is a ServiceAccount",
			"namespace", req.Name, "saNamespace", saInfo.Namespace, "saName", saInfo.Name)
	} else {
		logger.V(3).Info("user is not a ServiceAccount",
			"namespace", req.Name, "username", req.UserInfo.Username, "groupCount", len(userGroups))
	}

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitions); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "namespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusInternalServerError, err)
	}

	logger.V(2).Info("checking authorization against BindDefinitions",
		"namespace", req.Name, "bindDefinitionCount", len(bindDefinitions.Items))

	// Check if any BindDefinition allows the user to perform the operation
	isAllowed := false

	for bdIdx, bindDef := range bindDefinitions.Items {
		// Skip restricted BindDefinitions
		if IsRestrictedBindDefinition(bindDef.Name) {
			logger.V(4).Info("skipping restricted BindDefinition",
				"bindDefinitionName", bindDef.Name)
			continue
		}
		logger.V(3).Info("checking BindDefinition",
			"namespace", req.Name, "bindDefinitionName", bindDef.Name,
			"bdIndex", bdIdx, "subjectCount", len(bindDef.Spec.Subjects))

		// Check if the user matches any subjects in the BindDefinition
		if !MatchesSubjects(userGroups, saInfo, bindDef.Spec.Subjects) {
			logger.V(4).Info("user not found in BindDefinition subjects",
				"namespace", req.Name, "bindDefinitionName", bindDef.Name)
			continue
		}

		logger.V(3).Info("user matched in BindDefinition",
			"namespace", req.Name, "bindDefinition", bindDef.Name)

		for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
			// Get the NamespaceSelectors from the BindDefinition
			namespaceSelectors := roleBinding.NamespaceSelector
			namespaceMatchFound := false
			for nsIdx, namespaceSelector := range namespaceSelectors {
				matches, err := namespaceMatchesSelector(&ns, &namespaceSelector)
				if err != nil {
					logger.Error(err, "failed to match namespace selector",
						"namespace", req.Name, "bindDefinition", bindDef.Name)
					metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultErrored).Inc()
					return admission.Errored(http.StatusInternalServerError, err)
				}
				if matches {
					namespaceMatchFound = true
					logger.V(3).Info("namespace matched selector",
						"namespace", req.Name, "bindDefinition", bindDef.Name,
						"roleBindingIndex", rbIdx, "selectorIndex", nsIdx)
					break
				}
			}
			if namespaceMatchFound {
				isAllowed = true
				logger.V(2).Info("user authorized for namespace operation",
					"namespace", req.Name, "bindDefinition", bindDef.Name,
					"username", req.UserInfo.Username)
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
	logger.V(1).Info("namespace operation denied",
		"namespace", req.Name, "operation", req.Operation,
		"username", req.UserInfo.Username, "reason", denialMsg)
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

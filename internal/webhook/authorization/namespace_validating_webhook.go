package webhooks

import (
	"context"
	"fmt"
	"net/http"

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
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

type NamespaceValidator struct {
	Client       client.Client
	Decoder      admission.Decoder
	TDGMigration bool
}

func (v *NamespaceValidator) InjectDecoder(d admission.Decoder) error {
	v.Decoder = d
	return nil
}

func (v *NamespaceValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-validator")

	// Only handle namespace CREATE, UPDATE, DELETE operations
	if req.Kind.Kind != "Namespace" {
		logger.V(4).Info("webhook request for non-Namespace resource - ignoring",
			"kind", req.Kind.Kind)
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
		return admission.Allowed("")
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
		return admission.Allowed("")
	}

	if err != nil {
		logger.Error(err, "failed to decode namespace object", "namespace", req.Name, "operation", req.Operation)
		return admission.Errored(http.StatusBadRequest, err)
	}
	if oldErr != nil {
		logger.Error(oldErr, "failed to decode old namespace object", "namespace", req.Name, "operation", req.Operation)
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
			"t-caas.telekom.com/owner",
			"t-caas.telekom.com/tenant",
			"t-caas.telekom.com/thirdparty",
		}

		// If TDGMigration is enabled, add the additional label key
		if v.TDGMigration {
			labelKeys = append(labelKeys, "schiff.telekom.de/owner")
		}
		// Compare the labels between old and new namespaces
		for _, key := range labelKeys {
			oldValue, oldExists := oldNs.Labels[key]
			newValue, newExists := ns.Labels[key]
			if oldExists != newExists || oldValue != newValue {
				logger.V(2).Info("label modification denied",
					"namespace", req.Name, "label", key, "oldValue", oldValue, "newValue", newValue)
				return admission.Denied(fmt.Sprintf("Modification of label '%s' is not allowed", key))
			}
		}
		logger.V(3).Info("namespace labels validated - no changes detected",
			"namespace", req.Name)
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
		return admission.Allowed("")
	}

	denialMsg := fmt.Sprintf("User %s is not the owner of namespace %s", req.UserInfo.Username, ns.Name)
	logger.V(1).Info("namespace operation denied",
		"namespace", req.Name, "operation", req.Operation,
		"username", req.UserInfo.Username, "reason", denialMsg)
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

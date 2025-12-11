package webhooks

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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

var nsValidatorLog = logf.Log.WithName("namespace-validator")

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
	// Only handle namespace CREATE, UPDATE, DELETE operations
	if req.Kind.Kind != "Namespace" {
		nsValidatorLog.V(4).Info("DEBUG: Webhook request for non-Namespace resource - ignoring", "kind", req.Kind.Kind)
		return admission.Allowed("")
	}

	nsValidatorLog.V(2).Info("DEBUG: Namespace validator webhook triggered", "namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)

	// Allow the default kubernetes-admin to CRUD namespaces (necessary for CAPI/Flux)
	if req.UserInfo.Username == "kubernetes-admin" {
		nsValidatorLog.V(3).Info("DEBUG: Allowing kubernetes-admin request", "namespace", req.Name, "operation", req.Operation)
		return admission.Allowed("")
	}
	// If tdgMigration is enabled, allow the helm and kustomize controller to update namespaces
	if v.TDGMigration {
		switch req.UserInfo.Username {
		case "system:serviceaccount:flux-system:helm-controller":
			nsValidatorLog.V(3).Info("DEBUG: Allowing helm-controller", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:flux-system:kustomize-controller":
			nsValidatorLog.V(3).Info("DEBUG: Allowing kustomize-controller", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:schiff-tenant:m2m-sa":
			nsValidatorLog.V(3).Info("DEBUG: Allowing schiff-tenant m2m-sa", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:schiff-system:m2m-sa":
			nsValidatorLog.V(3).Info("DEBUG: Allowing schiff-system m2m-sa", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:capi-operator-system:capi-operator-manager":
			nsValidatorLog.V(3).Info("DEBUG: Allowing capi-operator-manager", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:trident-system:trident-operator":
			if req.Operation == admissionv1.Update && req.Name == "trident-system" {
				nsValidatorLog.V(3).Info("DEBUG: Allowing trident-operator for trident-system namespace", "namespace", req.Name)
				return admission.Allowed("")
			}
		}
	}
	// ToDo: Trident patches its own namespace and that cant be disabled.
	// https://github.com/NetApp/trident/blob/6b4cdf074578ade04ca0f1a5c59bb72c019391da/operator/controllers/orchestrator/installer/installer.go#L938
	if req.UserInfo.Username == "system:serviceaccount:t-caas-storage:trident-operator" && req.Operation == admissionv1.Update && req.Name == "t-caas-storage" {
		nsValidatorLog.V(3).Info("DEBUG: Allowing trident-operator for t-caas-storage namespace", "namespace", req.Name)
		return admission.Allowed("")
	}
	if req.UserInfo.Username == "system:serviceaccount:capi-operator-system:capi-operator-manager" && req.Operation == admissionv1.Update {
		nsValidatorLog.V(3).Info("DEBUG: Allowing capi-operator-manager for update", "namespace", req.Name)
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
		nsValidatorLog.V(3).Info("DEBUG: Unknown operation type - allowing", "namespace", req.Name, "operation", req.Operation)
		return admission.Allowed("")
	}

	if err != nil || oldErr != nil {
		nsValidatorLog.Error(err, "ERROR: Failed to decode namespace object", "namespace", req.Name, "operation", req.Operation)
		return admission.Errored(http.StatusBadRequest, err)
	}

	if req.Operation == admissionv1.Update {
		nsValidatorLog.V(2).Info("DEBUG: Validating namespace update", "namespace", req.Name)

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
				nsValidatorLog.V(2).Info("DEBUG: Label modification denied", "namespace", req.Name, "label", key, "oldValue", oldValue, "newValue", newValue)
				return admission.Denied(fmt.Sprintf("Modification of label '%s' is not allowed", key))
			}
		}
		nsValidatorLog.V(3).Info("DEBUG: Namespace labels validated - no changes detected", "namespace", req.Name)
	}

	// Extract user information
	userGroups := req.UserInfo.Groups

	// Check if the user is a ServiceAccount
	var saNamespace, saName string
	isServiceAccount := false
	usernameParts := strings.Split(req.UserInfo.Username, ":")
	if len(usernameParts) == 4 && usernameParts[0] == "system" && usernameParts[1] == "serviceaccount" {
		isServiceAccount = true
		saNamespace = usernameParts[2]
		saName = usernameParts[3]
		nsValidatorLog.V(3).Info("DEBUG: User is a ServiceAccount", "namespace", req.Name, "saNamespace", saNamespace, "saName", saName)
	} else {
		nsValidatorLog.V(3).Info("DEBUG: User is not a ServiceAccount", "namespace", req.Name, "username", req.UserInfo.Username, "groupCount", len(userGroups))
	}

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := v.Client.List(ctx, bindDefinitions); err != nil {
		nsValidatorLog.Error(err, "ERROR: Failed to list BindDefinitions", "namespace", req.Name)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	nsValidatorLog.V(2).Info("DEBUG: Checking authorization against BindDefinitions", "namespace", req.Name, "bindDefinitionCount", len(bindDefinitions.Items))

	// Check if any BindDefinition allows the user to perform the operation
	isAllowed := false

	for bdIdx, bindDef := range bindDefinitions.Items {
		// Skip BindDefinitions whose name ends with "-namespaced-reader-restricted"
		if strings.HasSuffix(bindDef.Name, "-namespaced-reader-restricted") {
			nsValidatorLog.V(4).Info("DEBUG: Skipping restricted BindDefinition", "bindDefinitionName", bindDef.Name)
			continue
		}
		nsValidatorLog.V(3).Info("DEBUG: Checking BindDefinition", "namespace", req.Name, "bindDefinitionName", bindDef.Name, "bdIndex", bdIdx, "subjectCount", len(bindDef.Spec.Subjects))

		userMatchFound := false
		// Check if the user matches any subjects in the BindDefinition
		for sidx, subject := range bindDef.Spec.Subjects {
			if subject.Kind == "Group" {
				for _, userGroup := range userGroups {
					if subject.Name == userGroup {
						userMatchFound = true
						nsValidatorLog.V(3).Info("DEBUG: User matched via group", "namespace", req.Name, "bindDefinition", bindDef.Name, "group", userGroup, "subjectIndex", sidx)
						break
					}
				}
			} else if subject.Kind == "ServiceAccount" && isServiceAccount {
				if subject.Namespace == saNamespace && subject.Name == saName {
					userMatchFound = true
					nsValidatorLog.V(3).Info("DEBUG: User matched via ServiceAccount", "namespace", req.Name, "bindDefinition", bindDef.Name, "sa", fmt.Sprintf("%s/%s", saNamespace, saName), "subjectIndex", sidx)
					break
				}
			}
			if userMatchFound {
				break
			}
		}
		if !userMatchFound {
			nsValidatorLog.V(4).Info("DEBUG: User not found in BindDefinition subjects", "namespace", req.Name, "bindDefinitionName", bindDef.Name)
			continue
		}

		for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
			// Get the NamespaceSelectors from the BindDefinition
			namespaceSelectors := roleBinding.NamespaceSelector
			namespaceMatchFound := false
			for nsIdx, namespaceSelector := range namespaceSelectors {
				matches, err := namespaceMatchesSelector(&ns, &namespaceSelector)
				if err != nil {
					nsValidatorLog.Error(err, "ERROR: Failed to match namespace selector", "namespace", req.Name, "bindDefinition", bindDef.Name)
					return admission.Errored(http.StatusInternalServerError, err)
				}
				if matches {
					namespaceMatchFound = true
					nsValidatorLog.V(3).Info("DEBUG: Namespace matched selector", "namespace", req.Name, "bindDefinition", bindDef.Name, "roleBindingIndex", rbIdx, "selectorIndex", nsIdx)
					break
				}
			}
			if namespaceMatchFound {
				isAllowed = true
				nsValidatorLog.V(2).Info("DEBUG: User authorized for namespace operation", "namespace", req.Name, "bindDefinition", bindDef.Name, "username", req.UserInfo.Username)
				break
			}
		}
		if isAllowed {
			break
		}
	}

	if isAllowed {
		nsValidatorLog.V(1).Info("DEBUG: Namespace operation allowed", "namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)
		return admission.Allowed("")
	}

	denialMsg := fmt.Sprintf("User %s is not the owner of namespace %s", req.UserInfo.Username, ns.Name)
	nsValidatorLog.V(1).Info("DEBUG: Namespace operation denied", "namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username, "reason", denialMsg)
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

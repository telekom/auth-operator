package webhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"strings" // Import strings package for parsing username

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch

var nsMutatorLog = logf.Log.WithName("namespace-mutator")

// Service account constants for namespace mutation webhook
const (
	capiOperatorManagerSA = "system:serviceaccount:capi-operator-system:capi-operator-manager"
)

type NamespaceMutator struct {
	Client       client.Client
	Decoder      admission.Decoder
	TDGMigration bool
}

// InjectDecoder injects the decoder into the NamespaceMutator
func (m *NamespaceMutator) InjectDecoder(d admission.Decoder) error {
	m.Decoder = d
	return nil
}

// Handle mutates the Namespace by adding a label based on user groups or ServiceAccount
func (m *NamespaceMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Handle both CREATE and UPDATE operations
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		nsMutatorLog.V(4).Info("DEBUG: Operation not CREATE/UPDATE - allowing", "namespace", req.Name, "operation", req.Operation)
		return admission.Allowed("Operation is neither CREATE nor UPDATE")
	}

	nsMutatorLog.V(2).Info("DEBUG: Namespace mutator webhook triggered", "namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)

	// Allow the default kubernetes-admin to CRUD namespaces without mutation (necessary for CAPI/Flux)
	if req.UserInfo.Username == "kubernetes-admin" {
		nsMutatorLog.V(3).Info("DEBUG: Allowing kubernetes-admin without mutation", "namespace", req.Name)
		return admission.Allowed("")
	}
	// ToDo: Trident patches its own namespace and that cant be disabled.
	// https://github.com/NetApp/trident/blob/6b4cdf074578ade04ca0f1a5c59bb72c019391da/operator/controllers/orchestrator/installer/installer.go#L938
	if req.UserInfo.Username == "system:serviceaccount:t-caas-storage:trident-operator" && req.Operation == admissionv1.Update && req.Name == "t-caas-storage" {
		nsMutatorLog.V(3).Info("DEBUG: Allowing trident-operator without mutation", "namespace", req.Name)
		return admission.Allowed("")
	}
	if req.UserInfo.Username == capiOperatorManagerSA && req.Operation == admissionv1.Update {
		nsMutatorLog.V(3).Info("DEBUG: Allowing capi-operator-manager without mutation", "namespace", req.Name)
		return admission.Allowed("")
	}
	// If tdgMigration is enabled, allow the helm and kustomize controller to update namespaces
	if m.TDGMigration {
		switch req.UserInfo.Username {
		case "system:serviceaccount:flux-system:helm-controller":
			nsMutatorLog.V(3).Info("DEBUG: Allowing helm-controller without mutation", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:flux-system:kustomize-controller":
			nsMutatorLog.V(3).Info("DEBUG: Allowing kustomize-controller without mutation", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:schiff-tenant:m2m-sa":
			nsMutatorLog.V(3).Info("DEBUG: Allowing schiff-tenant m2m-sa without mutation", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:schiff-system:m2m-sa":
			nsMutatorLog.V(3).Info("DEBUG: Allowing schiff-system m2m-sa without mutation", "namespace", req.Name)
			return admission.Allowed("")
		case capiOperatorManagerSA:
			nsMutatorLog.V(3).Info("DEBUG: Allowing capi-operator-manager without mutation (tdgMigration)", "namespace", req.Name)
			return admission.Allowed("")
		case "system:serviceaccount:trident-system:trident-operator":
			if req.Operation == admissionv1.Update && req.Name == "trident-system" {
				nsMutatorLog.V(3).Info("DEBUG: Allowing trident-operator without mutation (tdgMigration)", "namespace", req.Name)
				return admission.Allowed("")
			}
		}
	}
	ns := &corev1.Namespace{}
	var err = m.Decoder.Decode(req, ns)
	if err != nil {
		nsMutatorLog.Error(err, "ERROR: Failed to decode namespace", "namespace", req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Get the user's groups from the request
	userGroups := req.UserInfo.Groups

	// Check if the user is a ServiceAccount
	var saNamespace, saName string
	isServiceAccount := false
	usernameParts := strings.Split(req.UserInfo.Username, ":")
	if len(usernameParts) == 4 && usernameParts[0] == "system" && usernameParts[1] == "serviceaccount" {
		isServiceAccount = true
		saNamespace = usernameParts[2]
		saName = usernameParts[3]
		nsMutatorLog.V(3).Info("DEBUG: User is ServiceAccount", "namespace", req.Name, "saNamespace", saNamespace, "saName", saName)
	} else {
		nsMutatorLog.V(3).Info("DEBUG: User is not ServiceAccount", "namespace", req.Name, "username", req.UserInfo.Username, "groupCount", len(userGroups))
	}

	// Fetch all BindDefinition CRDs - this has to be faster
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := m.Client.List(ctx, bindDefinitions); err != nil {
		nsMutatorLog.Error(err, "ERROR: Failed to list BindDefinitions", "namespace", req.Name)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	nsMutatorLog.V(2).Info("DEBUG: Checking BindDefinitions for label mutations", "namespace", req.Name, "bindDefinitionCount", len(bindDefinitions.Items))

	// Prepare a map to hold labels to be added
	labelsToAdd := map[string]string{}

	// Iterate over each BindDefinition
	for bdIdx, bindDef := range bindDefinitions.Items {
		// Skip BindDefinitions whose name ends with "-namespaced-reader-restricted"
		if strings.HasSuffix(bindDef.Name, "-namespaced-reader-restricted") {
			nsMutatorLog.V(4).Info("DEBUG: Skipping restricted BindDefinition", "bindDefinitionName", bindDef.Name)
			continue
		}

		nsMutatorLog.V(3).Info("DEBUG: Checking BindDefinition for user match", "namespace", req.Name, "bindDefinitionName", bindDef.Name, "bdIndex", bdIdx)

		// Collect subjects from BindDefinition
		subjects := bindDef.Spec.Subjects

		// Check if the user's group is in the subjects or if the user is a matching ServiceAccount
		userMatchFound := false
		for sidx, subject := range subjects {
			if subject.Kind == "Group" {
				for _, userGroup := range userGroups {
					if subject.Name == userGroup {
						userMatchFound = true
						nsMutatorLog.V(3).Info("DEBUG: User matched group in BindDefinition", "namespace", req.Name, "bindDefinition", bindDef.Name, "group", userGroup, "subjectIndex", sidx)
						break
					}
				}
			} else if subject.Kind == "ServiceAccount" && isServiceAccount {
				if subject.Namespace == saNamespace && subject.Name == saName {
					userMatchFound = true
					nsMutatorLog.V(3).Info("DEBUG: User matched ServiceAccount in BindDefinition", "namespace", req.Name, "bindDefinition", bindDef.Name, "sa", saNamespace+"/"+saName, "subjectIndex", sidx)
					break
				}
			}
			if userMatchFound {
				break
			}
		}

		if userMatchFound {
			nsMutatorLog.V(3).Info("DEBUG: User matched - extracting labels from RoleBindings", "namespace", req.Name, "bindDefinition", bindDef.Name)

			for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
				// Extract labels from namespaceSelector in RoleBindings
				if len(roleBinding.NamespaceSelector) > 0 {
					nsMutatorLog.V(3).Info("DEBUG: Processing RoleBinding namespace selectors", "namespace", req.Name, "roleBindingIndex", rbIdx, "selectorCount", len(roleBinding.NamespaceSelector))

					for nsIdx, nsSelector := range roleBinding.NamespaceSelector {
						labels := getLabelsFromNamespaceSelector(nsSelector)
						nsMutatorLog.V(3).Info("DEBUG: Extracted labels from selector", "namespace", req.Name, "rbIndex", rbIdx, "selectorIndex", nsIdx, "labelCount", len(labels))

						for k, v := range labels {
							labelsToAdd[k] = v
						}
					}
				}
			}
		} else {
			nsMutatorLog.V(4).Info("DEBUG: User not matched in BindDefinition", "namespace", req.Name, "bindDefinitionName", bindDef.Name)
		}
	}

	// If there are labels to add, mutate the namespace
	if len(labelsToAdd) > 0 {
		nsMutatorLog.V(2).Info("DEBUG: Mutating namespace with labels", "namespace", req.Name, "labelCount", len(labelsToAdd))

		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		for k, v := range labelsToAdd {
			if _, exists := ns.Labels[k]; !exists {
				nsMutatorLog.V(2).Info("DEBUG: Adding label to namespace", "namespace", req.Name, "label", k, "value", v)
				ns.Labels[k] = v
			} else {
				nsMutatorLog.V(3).Info("DEBUG: Label already exists - skipping", "namespace", req.Name, "label", k)
			}
		}

		// Marshal the mutated namespace object
		marshalledNS, err := json.Marshal(ns)
		if err != nil {
			nsMutatorLog.Error(err, "ERROR: Failed to marshal mutated namespace", "namespace", req.Name)
			return admission.Errored(http.StatusInternalServerError, err)
		}
		nsMutatorLog.V(1).Info("DEBUG: Namespace mutation successful", "namespace", req.Name, "labelCount", len(labelsToAdd))
		return admission.PatchResponseFromRaw(req.Object.Raw, marshalledNS)
	}

	// If no labels to add, deny the request with a warning
	denialMsg := "The user does not have any OIDC attributes assigned to this cluster and the user is not a Kubernetes admin. Namespace creation is not allowed."
	nsMutatorLog.V(1).Info("DEBUG: Namespace mutation denied - no labels matched", "namespace", req.Name, "username", req.UserInfo.Username)
	return admission.Denied(denialMsg)
}

// Extract labels from NamespaceSelector
func getLabelsFromNamespaceSelector(selector metav1.LabelSelector) map[string]string {
	labels := map[string]string{}
	// Process matchLabels
	for key, value := range selector.MatchLabels {
		if key == "t-caas.telekom.com/owner" {
			labels[key] = value
		}
		if key == "t-caas.telekom.com/tenant" {
			labels[key] = value
		}
		if key == "t-caas.telekom.com/thirdparty" {
			labels[key] = value
		}
	}
	// Process matchExpressions
	for _, expr := range selector.MatchExpressions {
		if expr.Key == "t-caas.telekom.com/owner" && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
		if expr.Key == "t-caas.telekom.com/tenant" && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
		if expr.Key == "t-caas.telekom.com/thirdparty" && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
	}
	return labels
}

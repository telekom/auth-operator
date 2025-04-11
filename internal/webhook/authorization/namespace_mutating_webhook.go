package webhooks

import (
	"context"
	"encoding/json"
	"net/http"
	"strings" // Import strings package for parsing username

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var nsMutatorLog = logf.Log.WithName("namespace-mutator")

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch
type NamespaceMutator struct {
	Client  client.Client
	Decoder admission.Decoder
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
		return admission.Allowed("Operation is neither CREATE nor UPDATE")
	}

	// Allow the default kubernetes-admin to CRUD namespaces without mutation (necessary for CAPI/Flux)
	if req.UserInfo.Username == "kubernetes-admin" {
		nsMutatorLog.Info("Accepted request", "Username", req.UserInfo.Username)
		return admission.Allowed("")
	}
	// ToDo: Trident patches its own namespace and that cant be disabled.
	// https://github.com/NetApp/trident/blob/6b4cdf074578ade04ca0f1a5c59bb72c019391da/operator/controllers/orchestrator/installer/installer.go#L938
	if req.UserInfo.Username == "system:serviceaccount:t-caas-storage:trident-operator" && req.Operation == admissionv1.Update && req.Name == "t-caas-storage" {
		nsValidatorLog.Info("Accepted request", "Username", req.UserInfo.Username)
		return admission.Allowed("")
	}
	ns := &corev1.Namespace{}
	var err error

	// Label key-value validation is done in the Validating Webhook, there we don't
	// care about req.OldObject - i.e. there is no difference in decoding between
	// CREATE and UPDATE verbs. This stems from advisory on Mutating Webhook authoring
	// https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#use-caution-when-authoring-and-installing-mutating-webhooks
	err = m.Decoder.Decode(req, ns)
	if err != nil {
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
	}

	// Fetch all BindDefinition CRDs - this has to be faster
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := m.Client.List(ctx, bindDefinitions); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Prepare a map to hold labels to be added
	labelsToAdd := map[string]string{}

	// Iterate over each BindDefinition
	for _, bindDef := range bindDefinitions.Items {
		// Skip BindDefinitions whose name ends with "-namespaced-reader-restricted"
		if strings.HasSuffix(bindDef.Name, "-namespaced-reader-restricted") {
			continue
		}

		// Collect subjects from BindDefinition
		subjects := bindDef.Spec.Subjects

		// Check if the user's group is in the subjects or if the user is a matching ServiceAccount
		userMatchFound := false
		for _, subject := range subjects {
			if subject.Kind == "Group" {
				for _, userGroup := range userGroups {
					if subject.Name == userGroup {
						userMatchFound = true
						break
					}
				}
			} else if subject.Kind == "ServiceAccount" && isServiceAccount {
				if subject.Namespace == saNamespace && subject.Name == saName {
					userMatchFound = true
					break
				}
			}
			if userMatchFound {
				break
			}
		}

		if userMatchFound {
			// Extract labels from namespaceSelector in RoleBindings
			if len(bindDef.Spec.RoleBindings.NamespaceSelector) > 0 {
				for _, nsSelector := range bindDef.Spec.RoleBindings.NamespaceSelector {
					labels := getLabelsFromNamespaceSelector(nsSelector)
					for k, v := range labels {
						labelsToAdd[k] = v
					}
				}
			}
		}
	}

	// If there are labels to add, mutate the namespace
	if len(labelsToAdd) > 0 {
		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		for k, v := range labelsToAdd {
			if _, exists := ns.Labels[k]; !exists {
				nsMutatorLog.Info("OIDC group attribute match found - adding labels", "Namespace", ns.Name, "Label key", k, "Label value", v)
				ns.Labels[k] = v
			}
		}

		// Marshal the mutated namespace object
		marshalledNS, err := json.Marshal(ns)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		return admission.PatchResponseFromRaw(req.Object.Raw, marshalledNS)
	}

	// If no labels to add, deny the request with a warning
	return admission.Denied("The user does not have any OIDC attributes assigned to this cluster and the user is not a Kubernetes admin. Namespace creation is not allowed.")
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

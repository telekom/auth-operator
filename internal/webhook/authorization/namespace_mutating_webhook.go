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
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

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

	ns := &corev1.Namespace{}
	err := m.Decoder.Decode(req, ns)
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

	// Fetch all BindDefinition CRDs
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
			ns.Labels[k] = v
		}

		// Marshal the mutated namespace object
		marshalledNS, err := json.Marshal(ns)
		if err != nil {
			return admission.Errored(http.StatusInternalServerError, err)
		}
		return admission.PatchResponseFromRaw(req.Object.Raw, marshalledNS)
	}

	// If no labels to add, allow the request without changes
	return admission.Allowed("No labels to add")
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

package webhooks

import (
	"context"
	"encoding/json"
	"net/http"

	authorizationv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
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

// InjectDecoder injects the decoder into the NamespaceDefaulter
func (m *NamespaceMutator) InjectDecoder(d admission.Decoder) error {
	m.Decoder = d
	return nil
}

// Handle mutates the Namespace by adding a label based on user groups
func (m *NamespaceMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	// Only handle CREATE operations
	if req.Operation != admissionv1.Create {
		return admission.Allowed("Operation is not CREATE")
	}

	ns := &corev1.Namespace{}
	err := m.Decoder.Decode(req, ns)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Get the user's groups from the request
	userGroups := req.UserInfo.Groups

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authorizationv1alpha1.BindDefinitionList{}
	if err := m.Client.List(ctx, bindDefinitions); err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Prepare a map to hold labels to be added
	labelsToAdd := map[string]string{}

	// Iterate over each BindDefinition
	for _, bindDef := range bindDefinitions.Items {
		// Check if the BindDefinition has RoleBindings with NamespaceSelector
		if bindDef.Spec.RoleBindings.NamespaceSelector.MatchLabels != nil || len(bindDef.Spec.RoleBindings.NamespaceSelector.MatchExpressions) > 0 {
			// Iterate over the subjects in the BindDefinition
			for _, subject := range bindDef.Spec.Subjects {
				if subject.Kind == "Group" {
					// Check if the subject group is in the user's groups
					for _, userGroup := range userGroups {
						if subject.Name == userGroup {
							// Extract labels from the NamespaceSelector
							labels := getLabelsFromNamespaceSelector(bindDef.Spec.RoleBindings.NamespaceSelector)
							// Merge labels
							for k, v := range labels {
								labelsToAdd[k] = v
							}
						}
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

func getLabelsFromNamespaceSelector(selector metav1.LabelSelector) map[string]string {
	labels := map[string]string{}
	// Process matchLabels
	for key, value := range selector.MatchLabels {
		labels[key] = value
	}
	// Process matchExpressions
	for _, expr := range selector.MatchExpressions {
		if expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) > 0 {
			// For simplicity, use the first value
			labels[expr.Key] = expr.Values[0]
		}
	}
	return labels
}

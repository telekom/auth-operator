package webhooks

import (
	"context"
	"encoding/json"
	"net/http"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch

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
	logger := logf.FromContext(ctx).WithName("namespace-mutator")

	// Handle both CREATE and UPDATE operations
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		logger.V(4).Info("operation not CREATE/UPDATE - allowing",
			"namespace", req.Name, "operation", req.Operation)
		return admission.Allowed("Operation is neither CREATE nor UPDATE")
	}

	logger.V(2).Info("namespace mutator webhook triggered",
		"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)

	// Check for bypass conditions
	bypassResult := CheckMutatorBypass(req.UserInfo.Username, req.Operation, req.Name, m.TDGMigration)
	if bypassResult.ShouldBypass {
		// Log bypass at Info level for security auditing
		logger.Info("AUDIT: webhook bypass granted",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
			"bypassReason", bypassResult.Reason, "webhook", "mutator")
		return admission.Allowed("")
	}

	ns := &corev1.Namespace{}
	var err = m.Decoder.Decode(req, ns)
	if err != nil {
		logger.Error(err, "failed to decode namespace", "namespace", req.Name)
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Get the user's groups and parse service account info
	userGroups := req.UserInfo.Groups
	saInfo := ParseServiceAccount(req.UserInfo.Username)
	if saInfo.IsServiceAccount {
		logger.V(3).Info("user is ServiceAccount",
			"namespace", req.Name, "saNamespace", saInfo.Namespace, "saName", saInfo.Name)
	} else {
		logger.V(3).Info("user is not ServiceAccount",
			"namespace", req.Name, "username", req.UserInfo.Username, "groupCount", len(userGroups))
	}

	// Fetch all BindDefinition CRDs
	bindDefinitions := &authzv1alpha1.BindDefinitionList{}
	if err := m.Client.List(ctx, bindDefinitions); err != nil {
		logger.Error(err, "failed to list BindDefinitions", "namespace", req.Name)
		return admission.Errored(http.StatusInternalServerError, err)
	}

	logger.V(2).Info("checking BindDefinitions for label mutations",
		"namespace", req.Name, "bindDefinitionCount", len(bindDefinitions.Items))

	// Prepare a map to hold labels to be added
	labelsToAdd := map[string]string{}

	// Iterate over each BindDefinition
	for bdIdx, bindDef := range bindDefinitions.Items {
		// Skip BindDefinitions whose name ends with "-namespaced-reader-restricted"
		if IsRestrictedBindDefinition(bindDef.Name) {
			logger.V(4).Info("skipping restricted BindDefinition", "bindDefinitionName", bindDef.Name)
			continue
		}

		logger.V(3).Info("checking BindDefinition for user match",
			"namespace", req.Name, "bindDefinitionName", bindDef.Name, "bdIndex", bdIdx)

		// Check if the user's group or service account matches subjects
		if MatchesSubjects(userGroups, saInfo, bindDef.Spec.Subjects) {
			logger.V(3).Info("user matched - extracting labels from RoleBindings",
				"namespace", req.Name, "bindDefinition", bindDef.Name)

			for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
				// Extract labels from namespaceSelector in RoleBindings
				if len(roleBinding.NamespaceSelector) > 0 {
					logger.V(3).Info("processing RoleBinding namespace selectors",
						"namespace", req.Name, "roleBindingIndex", rbIdx,
						"selectorCount", len(roleBinding.NamespaceSelector))

					for nsIdx, nsSelector := range roleBinding.NamespaceSelector {
						labels := getLabelsFromNamespaceSelector(nsSelector)
						logger.V(3).Info("extracted labels from selector",
							"namespace", req.Name, "rbIndex", rbIdx,
							"selectorIndex", nsIdx, "labelCount", len(labels))

						for k, v := range labels {
							labelsToAdd[k] = v
						}
					}
				}
			}
		} else {
			logger.V(4).Info("user not matched in BindDefinition",
				"namespace", req.Name, "bindDefinitionName", bindDef.Name)
		}
	}

	// If there are labels to add, mutate the namespace
	if len(labelsToAdd) > 0 {
		logger.V(2).Info("mutating namespace with labels",
			"namespace", req.Name, "labelCount", len(labelsToAdd))

		if ns.Labels == nil {
			ns.Labels = map[string]string{}
		}
		for k, v := range labelsToAdd {
			if _, exists := ns.Labels[k]; !exists {
				logger.V(2).Info("adding label to namespace",
					"namespace", req.Name, "label", k, "value", v)
				ns.Labels[k] = v
			} else {
				logger.V(3).Info("label already exists - skipping",
					"namespace", req.Name, "label", k)
			}
		}

		// Marshal the mutated namespace object
		marshalledNS, err := json.Marshal(ns)
		if err != nil {
			logger.Error(err, "failed to marshal mutated namespace", "namespace", req.Name)
			return admission.Errored(http.StatusInternalServerError, err)
		}
		logger.V(1).Info("namespace mutation successful", "namespace", req.Name, "labelCount", len(labelsToAdd))
		return admission.PatchResponseFromRaw(req.Object.Raw, marshalledNS)
	}

	// If no labels to add, deny the request with a warning
	denialMsg := "The user does not have any OIDC attributes assigned to this cluster and the user is not a Kubernetes admin. Namespace creation is not allowed."
	logger.V(1).Info("namespace mutation denied - no labels matched", "namespace", req.Name, "username", req.UserInfo.Username)
	return admission.Denied(denialMsg)
}

// Extract labels from NamespaceSelector
func getLabelsFromNamespaceSelector(selector metav1.LabelSelector) map[string]string {
	labels := map[string]string{}
	// Process matchLabels
	for key, value := range selector.MatchLabels {
		if key == authzv1alpha1.LabelKeyOwner {
			labels[key] = value
		}
		if key == authzv1alpha1.LabelKeyTenant {
			labels[key] = value
		}
		if key == authzv1alpha1.LabelKeyThirdParty {
			labels[key] = value
		}
	}
	// Process matchExpressions
	for _, expr := range selector.MatchExpressions {
		if expr.Key == authzv1alpha1.LabelKeyOwner && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
		if expr.Key == authzv1alpha1.LabelKeyTenant && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
		if expr.Key == authzv1alpha1.LabelKeyThirdParty && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
	}
	return labels
}

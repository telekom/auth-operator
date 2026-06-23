package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/metrics"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=binddefinitions/status,verbs=get;update;patch

// NamespaceMutator is a mutating webhook that adds labels to namespaces based on user groups or ServiceAccount.
type NamespaceMutator struct {
	Client       client.Client
	Reader       client.Reader
	Decoder      admission.Decoder
	TDGMigration bool
}

// Handle mutates the Namespace by adding a label based on user groups or ServiceAccount.
func (m *NamespaceMutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-mutator")

	// Handle both CREATE and UPDATE operations
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		logger.V(4).Info("operation not CREATE/UPDATE - allowing",
			"namespace", req.Name, "operation", req.Operation)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("Operation is neither CREATE nor UPDATE")
	}

	logger.V(2).Info("namespace mutator webhook triggered",
		"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)

	// Check for bypass conditions
	bypassResult := CheckBypass(req.UserInfo.Username, req.UserInfo.Groups, req.Operation, req.Name, m.TDGMigration)
	if bypassResult.ShouldBypass {
		// Log bypass at Info level for security auditing
		logger.Info("AUDIT: webhook bypass granted",
			"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username,
			"bypassReason", bypassResult.Reason, "webhook", "mutator")
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
		return admission.Allowed("")
	}

	ns := &corev1.Namespace{}
	var err = m.Decoder.Decode(req, ns)
	if err != nil {
		logger.Error(err, "failed to decode namespace", "namespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusBadRequest, errors.New("unable to decode namespace request"))
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

	// Collect labels from matching BindDefinitions
	labelsToAdd, listErr := m.collectBindDefinitionLabels(ctx, req.Name, req.UserInfo.Username, userGroups, saInfo)
	if listErr != nil {
		logger.Error(listErr, "failed to collect BindDefinition labels", "namespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusInternalServerError, ErrNamespaceWebhookInternal)
	}

	var response admission.Response
	var handled bool
	labelsToAdd, response, handled = m.inheritServiceAccountNamespaceLabels(ctx, req, ns, labelsToAdd, saInfo)
	if handled {
		return response
	}

	// If there are labels to add, mutate the namespace
	if len(labelsToAdd) > 0 {
		candidateLabels := maps.Clone(ns.Labels)
		if candidateLabels == nil {
			candidateLabels = make(map[string]string, len(labelsToAdd))
		}
		for key, value := range labelsToAdd {
			candidateLabels[key] = value
		}
		if !ValidTrackedOwnershipLabels(candidateLabels) {
			logger.V(1).Info("namespace mutation denied - invalid tracked ownership labels",
				"namespace", req.Name, "operation", req.Operation, "username", req.UserInfo.Username)
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultDenied).Inc()
			return admission.Denied(fmt.Sprintf(DenialInvalidTrackedLabelsFmt, ns.Name))
		}
		return m.applyLabelPatch(ctx, req, ns, labelsToAdd)
	}

	// If no labels to add, deny the request with a warning
	logger.V(1).Info("namespace mutation denied - no labels matched", "namespace", req.Name, "username", req.UserInfo.Username)
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultDenied).Inc()
	return admission.Denied(DenialNoOIDCAttributes)
}

func (m *NamespaceMutator) inheritServiceAccountNamespaceLabels(
	ctx context.Context,
	req admission.Request,
	ns *corev1.Namespace,
	labelsToAdd map[string]string,
	saInfo ServiceAccountInfo,
) (map[string]string, admission.Response, bool) {
	if len(labelsToAdd) > 0 || !saInfo.IsServiceAccount {
		return labelsToAdd, admission.Response{}, false
	}

	logger := logf.FromContext(ctx).WithName("namespace-mutator")
	saCtx, saCancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer saCancel()
	inherited, err := GetSANamespaceTrackedLabels(saCtx, m.admissionReader(), saInfo)
	if err != nil {
		logger.Error(err, "failed to lookup SA namespace labels",
			"saNamespace", saInfo.Namespace, "targetNamespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return labelsToAdd, admission.Errored(http.StatusInternalServerError, ErrNamespaceWebhookInternal), true
	}
	if len(inherited) == 0 {
		return labelsToAdd, admission.Response{}, false
	}
	if response, denied := denyConflictingInheritedLabels(ctx, req, ns, inherited, saInfo); denied {
		return labelsToAdd, response, true
	}

	logger.V(1).Info("SA namespace label inheritance - inheriting labels from SA source namespace",
		"namespace", req.Name, "saNamespace", saInfo.Namespace, "labelCount", len(inherited))
	return inherited, admission.Response{}, false
}

func denyConflictingInheritedLabels(
	ctx context.Context,
	req admission.Request,
	ns *corev1.Namespace,
	inherited map[string]string,
	saInfo ServiceAccountInfo,
) (admission.Response, bool) {
	if ns.Labels == nil {
		return admission.Response{}, false
	}

	logger := logf.FromContext(ctx).WithName("namespace-mutator")
	for k, inheritedVal := range inherited {
		if existingVal, exists := ns.Labels[k]; exists && existingVal != inheritedVal {
			logger.V(1).Info("SA namespace label inheritance denied - label conflict on target namespace",
				"namespace", req.Name, "label", k, "existingValue", existingVal, "inheritedValue", inheritedVal)
			metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultDenied).Inc()
			return admission.Denied(fmt.Sprintf(DenialLabelConflictFmt, req.Name, k, existingVal, inheritedVal, saInfo.Namespace)), true
		}
	}
	if extraKey := FindExtraTrackedKey(ns.Labels, inherited); extraKey != "" {
		logger.V(1).Info("SA namespace label inheritance denied - target has extra tracked key",
			"namespace", req.Name, "extraKey", extraKey, "saNamespace", saInfo.Namespace)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultDenied).Inc()
		return admission.Denied(fmt.Sprintf(DenialExtraTrackedKeyFmt, req.Name, extraKey, saInfo.Namespace)), true
	}
	return admission.Response{}, false
}

// collectBindDefinitionLabels iterates over all BindDefinitions and collects labels to add
// from those whose subjects match the requesting user.
func (m *NamespaceMutator) collectBindDefinitionLabels(ctx context.Context, nsName, username string, userGroups []string, saInfo ServiceAccountInfo) (map[string]string, error) {
	logger := logf.FromContext(ctx).WithName("namespace-mutator")

	listCtx, cancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer cancel()
	bindDefinitions, err := freshBindDefinitionsWithRoleBindings(listCtx, m.Client, m.admissionReader())
	if err != nil {
		logger.Error(err, "failed to list BindDefinitions", "namespace", nsName)
		return nil, err
	}

	logger.V(2).Info("checking BindDefinitions for label mutations",
		"namespace", nsName, "bindDefinitionCount", len(bindDefinitions))

	labelsToAdd := map[string]string{}

	for bdIdx, bindDef := range bindDefinitions {
		if IsRestrictedBindDefinition(bindDef.Name) {
			logger.V(4).Info("skipping restricted BindDefinition", "bindDefinitionName", bindDef.Name)
			continue
		}

		logger.V(3).Info("checking BindDefinition for user match",
			"namespace", nsName, "bindDefinitionName", bindDef.Name, "bdIndex", bdIdx)

		if MatchesSubjects(username, userGroups, saInfo, bindDef.Spec.Subjects) {
			logger.V(3).Info("user matched - extracting labels from RoleBindings",
				"namespace", nsName, "bindDefinition", bindDef.Name)

			for rbIdx, roleBinding := range bindDef.Spec.RoleBindings {
				if roleBinding.Namespace != "" {
					logger.V(4).Info("skipping namespace selectors because explicit namespace is set",
						"namespace", nsName, "roleBindingIndex", rbIdx,
						"explicitNamespace", roleBinding.Namespace)
					continue
				}
				if len(roleBinding.NamespaceSelector) > 0 {
					logger.V(3).Info("processing RoleBinding namespace selectors",
						"namespace", nsName, "roleBindingIndex", rbIdx,
						"selectorCount", len(roleBinding.NamespaceSelector))

					for nsIdx, nsSelector := range roleBinding.NamespaceSelector {
						labels := getCompleteTrackedLabelsFromNamespaceSelector(nsSelector)
						logger.V(3).Info("extracted labels from selector",
							"namespace", nsName, "rbIndex", rbIdx,
							"selectorIndex", nsIdx, "labelCount", len(labels))

						for k, v := range labels {
							labelsToAdd[k] = v
						}
					}
				}
			}
		} else {
			logger.V(4).Info("user not matched in BindDefinition",
				"namespace", nsName, "bindDefinitionName", bindDef.Name)
		}
	}

	return labelsToAdd, nil
}

func (m *NamespaceMutator) admissionReader() client.Reader {
	if m.Reader != nil {
		return m.Reader
	}
	return m.Client
}

// applyLabelPatch adds the given labels to the namespace and returns a patch response.
func (m *NamespaceMutator) applyLabelPatch(ctx context.Context, req admission.Request, ns *corev1.Namespace, labelsToAdd map[string]string) admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-mutator")

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

	marshalledNS, err := json.Marshal(ns)
	if err != nil {
		logger.Error(err, "failed to marshal mutated namespace", "namespace", req.Name)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultErrored).Inc()
		return admission.Errored(http.StatusInternalServerError, err)
	}
	logger.V(1).Info("namespace mutation successful", "namespace", req.Name, "labelCount", len(labelsToAdd))
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceMutator, string(req.Operation), metrics.WebhookResultAllowed).Inc()
	return admission.PatchResponseFromRaw(req.Object.Raw, marshalledNS)
}

// trackedLabelKeys defines the set of label keys that are extracted from NamespaceSelectors.
// Derived from the package-level trackedOwnershipKeys.
var trackedLabelKeys = func() map[string]bool {
	m := make(map[string]bool, len(trackedOwnershipKeys))
	for _, k := range trackedOwnershipKeys {
		m[k] = true
	}
	return m
}()

// Extract labels from NamespaceSelector.
func getLabelsFromNamespaceSelector(selector metav1.LabelSelector) map[string]string {
	labels := map[string]string{}
	// Process matchLabels.
	for key, value := range selector.MatchLabels {
		if trackedLabelKeys[key] {
			labels[key] = value
		}
	}
	// Process matchExpressions.
	for _, expr := range selector.MatchExpressions {
		if trackedLabelKeys[expr.Key] && expr.Operator == metav1.LabelSelectorOpIn && len(expr.Values) == 1 {
			labels[expr.Key] = expr.Values[0]
		}
	}
	return labels
}

func getCompleteTrackedLabelsFromNamespaceSelector(selector metav1.LabelSelector) map[string]string {
	labels := getLabelsFromNamespaceSelector(selector)
	if len(labels) == 0 {
		return map[string]string{}
	}

	labels = maps.Clone(labels)
	if tenant, ok := labels[authorizationv1alpha1.LabelKeyTenant]; ok && tenant != "" {
		if owner, hasOwner := labels[authorizationv1alpha1.LabelKeyOwner]; hasOwner && owner != authorizationv1alpha1.OwnerTenant {
			return map[string]string{}
		}
		labels[authorizationv1alpha1.LabelKeyOwner] = authorizationv1alpha1.OwnerTenant
	}
	if thirdParty, ok := labels[authorizationv1alpha1.LabelKeyThirdParty]; ok && thirdParty != "" {
		if owner, hasOwner := labels[authorizationv1alpha1.LabelKeyOwner]; hasOwner && owner != authorizationv1alpha1.OwnerThirdParty {
			return map[string]string{}
		}
		labels[authorizationv1alpha1.LabelKeyOwner] = authorizationv1alpha1.OwnerThirdParty
	}
	if !ValidTrackedOwnershipLabels(labels) {
		return map[string]string{}
	}
	return labels
}

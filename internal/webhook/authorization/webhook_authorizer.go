package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=webhookauthorizers,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=webhookauthorizers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch

// Constants for user identity parsing.
const (
	systemPrefix       = "system"
	serviceAccountKind = "serviceaccount"
)

// maxRequestBodySize is the maximum allowed request body size (1MB).
// This prevents denial-of-service attacks via oversized request bodies.
const maxRequestBodySize = 1 << 20 // 1MB

// Decision values used in structured audit log entries.
const (
	decisionAllowed   = "allowed"
	decisionDenied    = "denied"
	decisionNoOpinion = "no-opinion"
)

// evaluationResult captures the full outcome of a SubjectAccessReview evaluation.
type evaluationResult struct {
	allowed        bool
	reason         string
	decision       string
	authorizerName string
	matchedRule    int    // -1 when no rule matched
	matchedField   string // "deniedPrincipal", "resourceRule", "nonResourceRule", or ""
	evaluatedCount int
}

// Authorizer implements an HTTP handler for SubjectAccessReview requests.
// The Client field should be the cached client returned by manager.GetClient()
// so that List and Get calls are served from the informer cache rather than
// hitting the API server on every SubjectAccessReview evaluation.
type Authorizer struct {
	Client client.Client
	Log    logr.Logger
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	defer func() { _ = r.Body.Close() }()

	// Limit request body size to prevent OOM from oversized payloads
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		wa.Log.Error(err, "failed to decode SubjectAccessReview request",
			"latency", time.Since(start).String())
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	wa.logReceivedSAR(&sar)

	// Use field-indexed queries to efficiently categorize authorizers.
	// Global authorizers (no namespace selector) always apply.
	// Scoped authorizers (with namespace selector) only apply when the SAR
	// targets a specific namespace, avoiding unnecessary namespace lookups.
	var globalAuth authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &globalAuth, client.MatchingFields{
		indexer.WebhookAuthorizerHasNamespaceSelectorField: "false",
	}); err != nil {
		wa.Log.Error(err, "failed to list global WebhookAuthorizers",
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	items := globalAuth.Items

	// Only query namespace-scoped authorizers when the SAR has a namespace target.
	if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Namespace != "" {
		var scopedAuth authzv1alpha1.WebhookAuthorizerList
		if err := wa.Client.List(ctx, &scopedAuth, client.MatchingFields{
			indexer.WebhookAuthorizerHasNamespaceSelectorField: "true",
		}); err != nil {
			wa.Log.Error(err, "failed to list scoped WebhookAuthorizers",
				"user", sar.Spec.User,
				"latency", time.Since(start).String())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		items = append(items, scopedAuth.Items...)
	}

	// Sort authorizers by name for deterministic evaluation order.
	slices.SortFunc(items, func(a, b authzv1alpha1.WebhookAuthorizer) int {
		return strings.Compare(a.Name, b.Name)
	})

	webhookAuthorizers := authzv1alpha1.WebhookAuthorizerList{Items: items}
	result := wa.evaluateSAR(ctx, &sar, &webhookAuthorizers)

	wa.logDecision(&sar, &result, time.Since(start))

	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: result.allowed,
			Reason:  result.reason,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode SubjectAccessReview response",
			"latency", time.Since(start).String())
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
	}
}

// maxLoggedGroups is the maximum number of group names emitted in audit log
// lines. Keeping this bounded prevents log explosion for subjects that belong
// to many groups.
const maxLoggedGroups = 10

// cappedGroups returns at most maxLoggedGroups elements from groups, appending a
// truncation marker if the list was shortened. This prevents audit logs from
// growing unbounded when subjects belong to many groups.
func cappedGroups(groups []string) []string {
	if len(groups) <= maxLoggedGroups {
		return groups
	}
	out := make([]string, maxLoggedGroups+1)
	copy(out, groups[:maxLoggedGroups])
	out[maxLoggedGroups] = fmt.Sprintf("...and %d more", len(groups)-maxLoggedGroups)
	return out
}

// logReceivedSAR logs the incoming SubjectAccessReview at V(2) for detailed tracing.
func (wa *Authorizer) logReceivedSAR(sar *authzv1.SubjectAccessReview) {
	switch {
	case sar.Spec.ResourceAttributes != nil:
		wa.Log.V(2).Info("received SubjectAccessReview",
			"namespace", sar.Spec.ResourceAttributes.Namespace,
			"user", sar.Spec.User,
			"groups", cappedGroups(sar.Spec.Groups),
			"verb", sar.Spec.ResourceAttributes.Verb,
			"apiGroup", sar.Spec.ResourceAttributes.Group,
			"resource", sar.Spec.ResourceAttributes.Resource)
	case sar.Spec.NonResourceAttributes != nil:
		wa.Log.V(2).Info("received SubjectAccessReview",
			"user", sar.Spec.User,
			"groups", cappedGroups(sar.Spec.Groups),
			"verb", sar.Spec.NonResourceAttributes.Verb,
			"path", sar.Spec.NonResourceAttributes.Path)
	default:
		wa.Log.V(2).Info("received SubjectAccessReview",
			"user", sar.Spec.User,
			"groups", cappedGroups(sar.Spec.Groups),
			"detail", "no resource or non-resource attributes")
	}
}

// logDecision emits a structured audit log entry for the evaluation result.
// Deny decisions are logged at V(0), allow and no-opinion at V(1).
func (wa *Authorizer) logDecision(sar *authzv1.SubjectAccessReview, res *evaluationResult, latency time.Duration) {
	fields := []any{
		"decision", res.decision,
		"allowed", res.allowed,
		"reason", res.reason,
		"user", sar.Spec.User,
		"groups", cappedGroups(sar.Spec.Groups),
		"authorizer", res.authorizerName,
		"evaluatedCount", res.evaluatedCount,
		"latency", latency.String(),
	}

	if sar.Spec.ResourceAttributes != nil {
		fields = append(fields,
			"verb", sar.Spec.ResourceAttributes.Verb,
			"apiGroup", sar.Spec.ResourceAttributes.Group,
			"resource", sar.Spec.ResourceAttributes.Resource,
			"namespace", sar.Spec.ResourceAttributes.Namespace,
		)
	} else if sar.Spec.NonResourceAttributes != nil {
		fields = append(fields,
			"verb", sar.Spec.NonResourceAttributes.Verb,
			"path", sar.Spec.NonResourceAttributes.Path,
		)
	}

	if res.matchedField != "" {
		fields = append(fields, "matchedField", res.matchedField)
	}
	if res.matchedRule >= 0 {
		fields = append(fields, "matchedRule", res.matchedRule)
	}

	switch res.decision {
	case decisionDenied:
		wa.Log.Info("authorization decision", fields...)
	default:
		// noOpinion and allow are verbose — only visible at V(1).
		wa.Log.V(1).Info("authorization decision", fields...)
	}
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, waList *authzv1alpha1.WebhookAuthorizerList) evaluationResult {
	totalCount := len(waList.Items)

	for i, webhookAuthorizer := range waList.Items {
		evaluated := i + 1
		wa.Log.V(2).Info("evaluating WebhookAuthorizer",
			"authorizer", webhookAuthorizer.Name,
			"index", i,
			"user", sar.Spec.User)

		if sar.Spec.ResourceAttributes != nil &&
			!helpers.IsLabelSelectorEmpty(&webhookAuthorizer.Spec.NamespaceSelector) &&
			sar.Spec.ResourceAttributes.Namespace != "" {
			if !wa.namespaceMatches(ctx, sar.Spec.ResourceAttributes.Namespace, &webhookAuthorizer.Spec.NamespaceSelector) {
				wa.Log.V(2).Info("namespace selector did not match, skipping",
					"authorizer", webhookAuthorizer.Name,
					"namespace", sar.Spec.ResourceAttributes.Namespace)
				continue
			}
		}

		// Check DeniedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			return evaluationResult{
				allowed:        false,
				reason:         fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name),
				decision:       decisionDenied,
				authorizerName: webhookAuthorizer.Name,
				matchedRule:    -1,
				matchedField:   "deniedPrincipal",
				evaluatedCount: evaluated,
			}
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			if sar.Spec.ResourceAttributes != nil {
				if ruleIdx := wa.resourceRuleIndex(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes); ruleIdx >= 0 {
					return evaluationResult{
						allowed:        true,
						reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
						decision:       decisionAllowed,
						authorizerName: webhookAuthorizer.Name,
						matchedRule:    ruleIdx,
						matchedField:   "resourceRule",
						evaluatedCount: evaluated,
					}
				}
			}
			if sar.Spec.NonResourceAttributes != nil {
				if ruleIdx := wa.nonResourceRuleIndex(webhookAuthorizer.Spec.NonResourceRules, sar.Spec.NonResourceAttributes); ruleIdx >= 0 {
					return evaluationResult{
						allowed:        true,
						reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
						decision:       decisionAllowed,
						authorizerName: webhookAuthorizer.Name,
						matchedRule:    ruleIdx,
						matchedField:   "nonResourceRule",
						evaluatedCount: evaluated,
					}
				}
			}
		}
	}

	return evaluationResult{
		allowed:        false,
		reason:         "Access denied: no matching rules",
		decision:       decisionNoOpinion,
		authorizerName: "",
		matchedRule:    -1,
		evaluatedCount: totalCount,
	}
}

// namespaceMatches checks if the namespace matches the selector.
func (wa *Authorizer) namespaceMatches(ctx context.Context, namespace string, selector *metav1.LabelSelector) bool {
	if namespace == "" {
		return false
	}
	var ns corev1.Namespace
	err := wa.Client.Get(ctx, types.NamespacedName{Name: namespace}, &ns)
	if err != nil {
		wa.Log.Error(err, "Failed to get namespace", "namespace", namespace)
		return false
	}
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		wa.Log.Error(err, "Invalid label selector")
		return false
	}
	return labelSelector.Matches(labels.Set(ns.Labels))
}

// principalMatches checks if the user or groups match the principals.
func (wa *Authorizer) principalMatches(user string, groups []string, principals []authzv1alpha1.Principal) bool {
	for _, principal := range principals {
		if principal.User != "" && principal.User == user {
			return true
		}
		if len(principal.Groups) > 0 && intersects(groups, principal.Groups) {
			return true
		}
		if principal.Namespace != "" && isServiceAccountInNamespace(user, principal.User, principal.Namespace) {
			return true
		}
	}
	return false
}

// intersects checks if two slices have any common elements.
func intersects(slice1, slice2 []string) bool {
	for _, s := range slice1 {
		if slices.Contains(slice2, s) {
			return true
		}
	}
	return false
}

// resourceRuleIndex returns the index of the first matching resource rule, or -1.
func (wa *Authorizer) resourceRuleIndex(rules []authzv1.ResourceRule, attr *authzv1.ResourceAttributes) int {
	for i, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.APIGroups, attr.Group) &&
			matchesRule(rule.Resources, attr.Resource) {
			return i
		}
	}
	return -1
}

// nonResourceRuleIndex returns the index of the first matching non-resource rule, or -1.
func (wa *Authorizer) nonResourceRuleIndex(rules []authzv1.NonResourceRule, attr *authzv1.NonResourceAttributes) int {
	for i, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.NonResourceURLs, attr.Path) {
			return i
		}
	}
	return -1
}

// matchesRule checks if a value matches any pattern in the list.
func matchesRule(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

// isServiceAccountInNamespace checks if the user is a service account in the specified namespace.
func isServiceAccountInNamespace(user, saUser, namespace string) bool {
	// Format: system:serviceaccount:<namespace>:<serviceaccount>
	parts := strings.Split(user, ":")
	return len(parts) == 4 && parts[0] == systemPrefix && parts[1] == serviceAccountKind && parts[2] == namespace && parts[3] == saUser
}

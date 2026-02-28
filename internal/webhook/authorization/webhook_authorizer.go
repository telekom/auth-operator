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
	"github.com/telekom/auth-operator/pkg/metrics"
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

// Authorizer implements an HTTP handler for SubjectAccessReview requests.
// The Client field should be the cached client returned by manager.GetClient()
// so that List and Get calls are served from the informer cache rather than
// hitting the API server on every SubjectAccessReview evaluation.
type Authorizer struct {
	Client client.Client
	Log    logr.Logger
}

// evaluationResult captures the outcome of a SubjectAccessReview evaluation.
type evaluationResult struct {
	// allowed is true when the request should be permitted.
	allowed bool
	// reason is a human-readable explanation of the decision.
	reason string
	// authorizerName is the name of the WebhookAuthorizer that matched, or
	// metrics.AuthorizerNameNone if no authorizer matched.
	authorizerName string
	// deniedByPrincipal is true when the denial was caused by a
	// DeniedPrincipals match rather than the default "no matching rules".
	deniedByPrincipal bool
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Use request context for proper cancellation and deadline propagation
	ctx := r.Context()
	start := time.Now()

	// Limit request body size to prevent OOM from oversized payloads
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Ensure request body is closed to prevent resource leaks
	defer func() { _ = r.Body.Close() }()

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		wa.Log.Error(err, "failed to decode SubjectAccessReview request")
		metrics.AuthorizerRequestsTotal.WithLabelValues(metrics.AuthorizerDecisionError, metrics.AuthorizerNameNone).Inc()
		metrics.AuthorizerRequestDuration.WithLabelValues(metrics.AuthorizerDecisionError).Observe(time.Since(start).Seconds())
		http.Error(w, "failed to decode request body", http.StatusBadRequest)
		return
	}

	switch {
	case sar.Spec.ResourceAttributes != nil:
		wa.Log.Info("received SubjectAccessReview",
			"namespace", sar.Spec.ResourceAttributes.Namespace,
			"user", sar.Spec.User,
			"groups", sar.Spec.Groups,
			"verb", sar.Spec.ResourceAttributes.Verb,
			"apiGroup", sar.Spec.ResourceAttributes.Group,
			"resource", sar.Spec.ResourceAttributes.Resource)
	case sar.Spec.NonResourceAttributes != nil:
		wa.Log.Info("received SubjectAccessReview",
			"user", sar.Spec.User,
			"groups", sar.Spec.Groups,
			"verb", sar.Spec.NonResourceAttributes.Verb,
			"path", sar.Spec.NonResourceAttributes.Path)
	default:
		wa.Log.Info("received SubjectAccessReview",
			"user", sar.Spec.User,
			"groups", sar.Spec.Groups,
			"detail", "no resource or non-resource attributes")
	}

	// Fetch all WebhookAuthorizers in a single unindexed List call.
	//
	// An earlier implementation split this into two indexed queries (global +
	// namespace-scoped) using MatchingFields on the hasNamespaceSelector
	// field index. The metrics branch intentionally consolidated to a single
	// list so that AuthorizerActiveRules reflects the true total count
	// without double-fetching or race conditions between the two queries.
	//
	// Performance note: this is an in-memory informer-cache list, so the
	// cost is O(n) over cached objects — not an API-server round trip per
	// query. For deployments with very large numbers of WebhookAuthorizer
	// CRs (hundreds+), consider restoring the indexed split and summing
	// the counts, or adding a dedicated cache-level metric.
	var webhookAuthorizers authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &webhookAuthorizers); err != nil {
		wa.Log.Error(err, "failed to list WebhookAuthorizers")
		metrics.AuthorizerRequestsTotal.WithLabelValues(metrics.AuthorizerDecisionError, metrics.AuthorizerNameNone).Inc()
		metrics.AuthorizerRequestDuration.WithLabelValues(metrics.AuthorizerDecisionError).Observe(time.Since(start).Seconds())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	metrics.AuthorizerActiveRules.Set(float64(len(webhookAuthorizers.Items)))

	// Sort authorizers by name for deterministic evaluation order.
	// evaluateSAR returns on the first match, so ordering matters.
	slices.SortFunc(webhookAuthorizers.Items, func(a, b authzv1alpha1.WebhookAuthorizer) int {
		return strings.Compare(a.Name, b.Name)
	})

	result := wa.evaluateSAR(ctx, &sar, &webhookAuthorizers)

	// Record metrics based on the evaluation result.
	decision := metrics.AuthorizerDecisionDenied
	if result.allowed {
		decision = metrics.AuthorizerDecisionAllowed
	}
	metrics.AuthorizerRequestsTotal.WithLabelValues(decision, result.authorizerName).Inc()
	metrics.AuthorizerRequestDuration.WithLabelValues(decision).Observe(time.Since(start).Seconds())

	if result.deniedByPrincipal {
		metrics.AuthorizerDeniedPrincipalHitsTotal.WithLabelValues(result.authorizerName).Inc()
	}

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

	wa.Log.V(1).Info("SubjectAccessReview decision", "allowed", result.allowed, "reason", result.reason)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode SubjectAccessReview response")
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
	}
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, waList *authzv1alpha1.WebhookAuthorizerList) evaluationResult {
	for _, webhookAuthorizer := range waList.Items {
		// Skip namespace-scoped authorizers when the SAR has no namespace context:
		// non-resource SARs and cluster-scoped resource SARs don't belong to any namespace.
		if !helpers.IsLabelSelectorEmpty(&webhookAuthorizer.Spec.NamespaceSelector) {
			if sar.Spec.ResourceAttributes == nil {
				// Non-resource SAR — namespace-scoped authorizer does not apply.
				continue
			}
			if sar.Spec.ResourceAttributes.Namespace == "" {
				// Cluster-scoped resource — namespace-scoped authorizer does not apply.
				continue
			}
			if !wa.namespaceMatches(ctx, sar.Spec.ResourceAttributes.Namespace, &webhookAuthorizer.Spec.NamespaceSelector) {
				continue
			}
		}

		// Check DeniedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			return evaluationResult{
				allowed:           false,
				reason:            fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name),
				authorizerName:    webhookAuthorizer.Name,
				deniedByPrincipal: true,
			}
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			// Check ResourceRules.
			if sar.Spec.ResourceAttributes != nil && wa.resourceRulesMatch(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes) {
				return evaluationResult{
					allowed:        true,
					reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
					authorizerName: webhookAuthorizer.Name,
				}
			}
			// Check NonResourceRules.
			if sar.Spec.NonResourceAttributes != nil && wa.nonResourceRulesMatch(webhookAuthorizer.Spec.NonResourceRules, sar.Spec.NonResourceAttributes) {
				return evaluationResult{
					allowed:        true,
					reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
					authorizerName: webhookAuthorizer.Name,
				}
			}
		}
	}
	return evaluationResult{
		allowed:        false,
		reason:         "Access denied: no matching rules",
		authorizerName: metrics.AuthorizerNameNone,
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

// resourceRulesMatch checks if the resource attributes match any of the resource rules.
func (wa *Authorizer) resourceRulesMatch(rules []authzv1.ResourceRule, attr *authzv1.ResourceAttributes) bool {
	for _, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.APIGroups, attr.Group) &&
			matchesRule(rule.Resources, attr.Resource) {
			return true
		}
	}
	return false
}

// nonResourceRulesMatch checks if the non-resource attributes match any of the non-resource rules.
func (wa *Authorizer) nonResourceRulesMatch(rules []authzv1.NonResourceRule, attr *authzv1.NonResourceAttributes) bool {
	for _, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.NonResourceURLs, attr.Path) {
			return true
		}
	}
	return false
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

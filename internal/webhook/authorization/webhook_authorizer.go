package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

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
	"github.com/telekom/auth-operator/pkg/tracing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
	Tracer trace.Tracer
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Use request context for proper cancellation and deadline propagation
	ctx := r.Context()

	// Start a tracing span for the full SAR evaluation
	if wa.Tracer != nil {
		var span trace.Span
		ctx, span = wa.Tracer.Start(ctx, "webhook.SubjectAccessReview")
		defer span.End()
	}

	// Limit request body size to prevent OOM from oversized payloads
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Ensure request body is closed to prevent resource leaks
	defer func() { _ = r.Body.Close() }()

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		wa.Log.Error(err, "failed to decode SubjectAccessReview request")
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid request body")
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Add SAR attributes to the span
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(tracing.AttrUser.String(sar.Spec.User))
		if sar.Spec.ResourceAttributes != nil {
			span.SetAttributes(
				tracing.AttrVerb.String(sar.Spec.ResourceAttributes.Verb),
				tracing.AttrAPIGroup.String(sar.Spec.ResourceAttributes.Group),
				tracing.AttrResourceType.String(sar.Spec.ResourceAttributes.Resource),
				tracing.AttrNamespace.String(sar.Spec.ResourceAttributes.Namespace),
			)
		}
		if sar.Spec.NonResourceAttributes != nil {
			span.SetAttributes(
				tracing.AttrVerb.String(sar.Spec.NonResourceAttributes.Verb),
				tracing.AttrPath.String(sar.Spec.NonResourceAttributes.Path),
			)
		}
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

	// Pre-fetch all authorizers in case the field index is unavailable,
	// so global and scoped queries share a single fallback API call.
	var fallbackCache []authzv1alpha1.WebhookAuthorizer

	globalItems, err := wa.listGlobalAuthorizers(ctx, &fallbackCache)
	if err != nil {
		wa.Log.Error(err, "failed to list global WebhookAuthorizers")
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to list global WebhookAuthorizers")
		}
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
		return
	}

	items := globalItems

	// Only query namespace-scoped authorizers when the SAR has a namespace target.
	if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Namespace != "" {
		scopedItems, err := wa.listScopedAuthorizers(ctx, &fallbackCache)
		if err != nil {
			wa.Log.Error(err, "failed to list scoped WebhookAuthorizers")
			if span := trace.SpanFromContext(ctx); span.IsRecording() {
				span.RecordError(err)
				span.SetStatus(codes.Error, "failed to list scoped WebhookAuthorizers")
			}
			http.Error(w, "internal evaluation error", http.StatusInternalServerError)
			return
		}
		items = append(items, scopedItems...)
	}

	// Sort authorizers by name for deterministic evaluation order.
	// This ensures deny-before-allow semantics are stable regardless of
	// whether the client is backed by a cache (random map iteration) or
	// the API server (alphabetical order).
	slices.SortFunc(items, func(a, b authzv1alpha1.WebhookAuthorizer) int {
		return strings.Compare(a.Name, b.Name)
	})

	verdict, reason := wa.evaluateSAR(ctx, &sar, items)

	// Record decision in the span
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		decision := "denied"
		if verdict {
			decision = "allowed"
		}
		ruleCount := 0
		for _, a := range items {
			ruleCount += len(a.Spec.ResourceRules) + len(a.Spec.NonResourceRules)
		}
		span.SetAttributes(
			tracing.AttrDecision.String(decision),
			tracing.AttrReason.String(reason),
			tracing.AttrRuleCount.Int(ruleCount),
		)
	}

	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: verdict,
			Reason:  reason,
		},
	}

	wa.Log.V(1).Info("SubjectAccessReview decision", "allowed", verdict, "reason", reason)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode SubjectAccessReview response")
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to encode response")
		}
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
	}
}

func (wa *Authorizer) listGlobalAuthorizers(ctx context.Context, cachedAll *[]authzv1alpha1.WebhookAuthorizer) ([]authzv1alpha1.WebhookAuthorizer, error) {
	var globalAuth authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &globalAuth, client.MatchingFields{
		indexer.WebhookAuthorizerHasNamespaceSelectorField: "false",
	}); err == nil {
		return globalAuth.Items, nil
	} else if !isFieldIndexError(err) {
		// Propagate real errors (RBAC, network, etc.) instead of silently
		// falling back to an unindexed full list which would mask bugs.
		return nil, fmt.Errorf("indexed list of global WebhookAuthorizers: %w", err)
	}

	// Field index not registered — fall back to filtering a full list.
	wa.Log.V(1).Info("field index unavailable, falling back to unindexed list for global authorizers")
	if cachedAll == nil || *cachedAll == nil {
		all, err := wa.listAllAuthorizers(ctx)
		if err != nil {
			return nil, err
		}
		if cachedAll != nil {
			*cachedAll = all
		}
		globalItems := make([]authzv1alpha1.WebhookAuthorizer, 0, len(all))
		for _, candidate := range all {
			if helpers.IsLabelSelectorEmpty(&candidate.Spec.NamespaceSelector) {
				globalItems = append(globalItems, candidate)
			}
		}
		return globalItems, nil
	}

	globalItems := make([]authzv1alpha1.WebhookAuthorizer, 0, len(*cachedAll))
	for _, candidate := range *cachedAll {
		if helpers.IsLabelSelectorEmpty(&candidate.Spec.NamespaceSelector) {
			globalItems = append(globalItems, candidate)
		}
	}

	return globalItems, nil
}

func (wa *Authorizer) listScopedAuthorizers(ctx context.Context, cachedAll *[]authzv1alpha1.WebhookAuthorizer) ([]authzv1alpha1.WebhookAuthorizer, error) {
	var scopedAuth authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &scopedAuth, client.MatchingFields{
		indexer.WebhookAuthorizerHasNamespaceSelectorField: "true",
	}); err == nil {
		return scopedAuth.Items, nil
	} else if !isFieldIndexError(err) {
		// Propagate real errors (RBAC, network, etc.) instead of silently
		// falling back to an unindexed full list which would mask bugs.
		return nil, fmt.Errorf("indexed list of scoped WebhookAuthorizers: %w", err)
	}

	// Field index not registered — fall back to filtering a full list.
	wa.Log.V(1).Info("field index unavailable, falling back to unindexed list for scoped authorizers")
	if cachedAll == nil || *cachedAll == nil {
		all, err := wa.listAllAuthorizers(ctx)
		if err != nil {
			return nil, err
		}
		if cachedAll != nil {
			*cachedAll = all
		}
		scopedItems := make([]authzv1alpha1.WebhookAuthorizer, 0, len(all))
		for _, candidate := range all {
			if !helpers.IsLabelSelectorEmpty(&candidate.Spec.NamespaceSelector) {
				scopedItems = append(scopedItems, candidate)
			}
		}
		return scopedItems, nil
	}

	scopedItems := make([]authzv1alpha1.WebhookAuthorizer, 0, len(*cachedAll))
	for _, candidate := range *cachedAll {
		if !helpers.IsLabelSelectorEmpty(&candidate.Spec.NamespaceSelector) {
			scopedItems = append(scopedItems, candidate)
		}
	}

	return scopedItems, nil
}

func (wa *Authorizer) listAllAuthorizers(ctx context.Context) ([]authzv1alpha1.WebhookAuthorizer, error) {
	var allAuth authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &allAuth); err != nil {
		return nil, fmt.Errorf("list WebhookAuthorizers: %w", err)
	}
	return allAuth.Items, nil
}

// isFieldIndexError returns true when err indicates that a controller-runtime
// field index has not been registered. These errors are expected when the
// webhook process starts before the informer cache has the index configured
// (e.g. in the standalone webhook binary), and justify falling back to an
// unindexed full list. All other errors (RBAC, network, API server
// unavailable) are NOT index errors and must be propagated.
func isFieldIndexError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") && strings.Contains(msg, "index")
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, authorizers []authzv1alpha1.WebhookAuthorizer) (allowed bool, reason string) {
	for _, webhookAuthorizer := range authorizers {
		if sar.Spec.ResourceAttributes != nil && !helpers.IsLabelSelectorEmpty(&webhookAuthorizer.Spec.NamespaceSelector) && sar.Spec.ResourceAttributes.Namespace != "" {
			if !wa.namespaceMatches(ctx, sar.Spec.ResourceAttributes.Namespace, &webhookAuthorizer.Spec.NamespaceSelector) {
				continue
			}
		}

		// Check DeniedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			return false, fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name)
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			// Check ResourceRules.
			if sar.Spec.ResourceAttributes != nil && wa.resourceRulesMatch(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes) {
				return true, fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name)
			}
			// Check NonResourceRules.
			if sar.Spec.NonResourceAttributes != nil && wa.nonResourceRulesMatch(webhookAuthorizer.Spec.NonResourceRules, sar.Spec.NonResourceAttributes) {
				return true, fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name)
			}
		}
	}
	return false, "Access denied: no matching rules"
}

// namespaceMatches checks if the namespace matches the selector.
func (wa *Authorizer) namespaceMatches(ctx context.Context, namespace string, selector *metav1.LabelSelector) bool {
	if wa.Tracer != nil {
		var span trace.Span
		ctx, span = wa.Tracer.Start(ctx, "webhook.NamespaceMatch",
			trace.WithAttributes(tracing.AttrNamespace.String(namespace)))
		defer span.End()
	}

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

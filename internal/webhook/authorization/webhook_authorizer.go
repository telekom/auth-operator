package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
	pkgmetrics "github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/tracing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
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

// Decision values used in structured audit log entries are defined in
// pkg/metrics (AuthorizerDecisionAllowed, AuthorizerDecisionDenied,
// AuthorizerDecisionNoOpinion) to keep audit logs and Prometheus labels
// consistent.

// evaluationResult captures the full outcome of a SubjectAccessReview evaluation.
type evaluationResult struct {
	allowed        bool
	reason         string
	decision       string
	authorizerName string
	matchedRule    int    // -1 when no rule matched
	matchedField   string // "deniedPrincipal", "resourceRule", "nonResourceRule", or ""
	evaluatedCount int    // authorizers that actively participated in evaluation
	skippedCount   int    // authorizers skipped due to namespace selector mismatch
}

// Authorizer implements an HTTP handler for SubjectAccessReview requests.
// The Client field should be the cached client returned by manager.GetClient()
// so that List and Get calls are served from the informer cache rather than
// hitting the API server on every SubjectAccessReview evaluation.
type Authorizer struct {
	Client  client.Client
	Log     logr.Logger
	Tracer  trace.Tracer
	Limiter *rate.Limiter

	// indexFallbackWarned ensures the "field index unavailable" warning is
	// logged only once instead of on every request.
	indexFallbackWarned sync.Once
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Rate-limit incoming requests to prevent overloading the authorizer.
	// When the limiter is configured and the token bucket is exhausted,
	// return HTTP 429 with a denied SubjectAccessReview response.
	if wa.Limiter != nil && !wa.Limiter.Allow() {
		pkgmetrics.AuthorizerRateLimitedTotal.Inc()
		wa.Log.V(1).Info("rate limit exceeded, rejecting request",
			"latency", time.Since(start).String())
		wa.writeRateLimitResponse(w)
		return
	}

	// Extract trace context and start a tracing span only when tracing is
	// enabled (non-nil Tracer). When disabled, this avoids header parsing and
	// noop span creation on every request — true zero overhead.
	if wa.Tracer != nil {
		ctx = otel.GetTextMapPropagator().Extract(ctx, propagation.HeaderCarrier(r.Header))
		var span trace.Span
		ctx, span = wa.Tracer.Start(ctx, "webhook.SubjectAccessReview")
		defer span.End()
	}

	// Limit request body size to prevent OOM from oversized payloads.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Ensure request body is closed to prevent resource leaks.
	defer func() { _ = r.Body.Close() }()

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		wa.Log.Error(err, "failed to decode SubjectAccessReview request",
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid request body")
		}
		wa.recordErrorMetrics(start)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	wa.annotateSARSpan(ctx, &sar)
	wa.logReceivedSAR(&sar)

	// Prepare a shared fallback cache in case the field index is unavailable,
	// so global and scoped queries share a single fallback API call.
	var fallbackCache []authzv1alpha1.WebhookAuthorizer

	globalItems, err := wa.listGlobalAuthorizers(ctx, &fallbackCache)
	if err != nil {
		wa.Log.Error(err, "failed to list global WebhookAuthorizers",
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to list global WebhookAuthorizers")
		}
		wa.recordErrorMetrics(start)
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
		return
	}

	items := globalItems

	// Always query scoped authorizers so the active-rules gauge reflects the
	// full set regardless of request type. Scoped authorizers are only used
	// for evaluation when the SAR targets a specific namespace.
	scopedItems, err := wa.listScopedAuthorizers(ctx, &fallbackCache)
	if err != nil {
		wa.Log.Error(err, "failed to list scoped WebhookAuthorizers",
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to list scoped WebhookAuthorizers")
		}
		wa.recordErrorMetrics(start)
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
		return
	}
	if sar.Spec.ResourceAttributes != nil && sar.Spec.ResourceAttributes.Namespace != "" {
		items = append(items, scopedItems...)
	}

	// Sort authorizers by name for deterministic first-match evaluation order
	// regardless of whether the client is backed by a cache (random map
	// iteration) or the API server (alphabetical order).
	slices.SortFunc(items, func(a, b authzv1alpha1.WebhookAuthorizer) int {
		return strings.Compare(a.Name, b.Name)
	})

	result := wa.evaluateSAR(ctx, &sar, items)

	// Count total rules across ALL WebhookAuthorizer resources (global + scoped)
	// for the gauge. This is request-independent: even if a namespace-scoped
	// authorizer was not evaluated for this SAR, it still contributes to the
	// total rule count.
	allRules := countTotalRules(globalItems) + countTotalRules(scopedItems)

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

	// Buffer the response before writing so that metrics and audit logs
	// are not recorded when serialization fails. Note: metrics are recorded
	// after successful marshal but before w.Write — a late write failure
	// (e.g. client disconnect) will still have metrics emitted.
	respBytes, err := json.Marshal(response)
	if err != nil {
		wa.Log.Error(err, "failed to encode SubjectAccessReview response",
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to encode response")
		}
		wa.recordErrorMetrics(start)
		http.Error(w, "internal evaluation error", http.StatusInternalServerError)
		return
	}

	// Record audit log and metrics only after successful serialization.
	latency := time.Since(start)
	wa.logDecision(&sar, &result, latency)
	wa.recordMetrics(&result, latency, allRules)

	// Record decision in the span.
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			tracing.AttrDecision.String(result.decision),
			tracing.AttrReason.String(result.reason),
			tracing.AttrRuleCount.Int(allRules),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		wa.Log.Error(err, "failed to write SubjectAccessReview response",
			"latency", time.Since(start).String())
	}
}

// annotateSARSpan adds SAR attributes to the active tracing span.
func (wa *Authorizer) annotateSARSpan(ctx context.Context, sar *authzv1.SubjectAccessReview) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
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
		"skippedCount", res.skippedCount,
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
	case pkgmetrics.AuthorizerDecisionDenied:
		wa.Log.Info("authorization decision", fields...)
	default:
		// noOpinion and allow are verbose — only visible at V(1).
		wa.Log.V(1).Info("authorization decision", fields...)
	}
}

// countTotalRules returns the total number of resource and non-resource rules
// across the provided authorizers. The caller is responsible for passing the
// complete set of authorizers to get a request-independent count suitable for
// the AuthorizerActiveRules gauge.
func countTotalRules(authorizers []authzv1alpha1.WebhookAuthorizer) int {
	total := 0
	for i := range authorizers {
		total += len(authorizers[i].Spec.ResourceRules) + len(authorizers[i].Spec.NonResourceRules)
	}
	return total
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
	wa.indexFallbackWarned.Do(func() {
		wa.Log.Info("field index unavailable for WebhookAuthorizers, falling back to unindexed list")
	})
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
	// Warning is logged once via indexFallbackWarned in listGlobalAuthorizers.
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
//
// NOTE: controller-runtime returns an untyped fmt.Errorf for missing field
// indexes (see cache/internal/informers_map.go), so there is no sentinel
// error or typed error to use with errors.Is/errors.As. String matching is
// the only reliable detection method available.
func isFieldIndexError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") && strings.Contains(msg, "index")
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, items []authzv1alpha1.WebhookAuthorizer) evaluationResult {
	evaluated := 0
	skipped := 0

	for i, webhookAuthorizer := range items {
		// Skip namespace-scoped authorizers for non-resource or cluster-scoped SARs
		// that have no namespace target. This is a defensive guard — the list query
		// already excludes scoped authorizers for these cases, but this ensures
		// correct behavior regardless of how items were assembled.
		if !helpers.IsLabelSelectorEmpty(&webhookAuthorizer.Spec.NamespaceSelector) {
			resourceNS := ""
			if sar.Spec.ResourceAttributes != nil {
				resourceNS = sar.Spec.ResourceAttributes.Namespace
			}
			if resourceNS == "" {
				wa.Log.V(2).Info("skipping namespace-scoped authorizer for non-namespaced SAR",
					"authorizer", webhookAuthorizer.Name)
				skipped++
				continue
			}
			if !wa.namespaceMatches(ctx, resourceNS, &webhookAuthorizer.Spec.NamespaceSelector) {
				wa.Log.V(2).Info("namespace selector did not match, skipping",
					"authorizer", webhookAuthorizer.Name,
					"namespace", resourceNS)
				skipped++
				continue
			}
		}

		evaluated++

		wa.Log.V(2).Info("evaluating WebhookAuthorizer",
			"authorizer", webhookAuthorizer.Name,
			"index", i,
			"user", sar.Spec.User)

		// Check DeniedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			return evaluationResult{
				allowed:        false,
				reason:         fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name),
				decision:       pkgmetrics.AuthorizerDecisionDenied,
				authorizerName: webhookAuthorizer.Name,
				matchedRule:    -1,
				matchedField:   "deniedPrincipal",
				evaluatedCount: evaluated,
				skippedCount:   skipped,
			}
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			if sar.Spec.ResourceAttributes != nil {
				if ruleIdx := wa.resourceRuleIndex(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes); ruleIdx >= 0 {
					return evaluationResult{
						allowed:        true,
						reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
						decision:       pkgmetrics.AuthorizerDecisionAllowed,
						authorizerName: webhookAuthorizer.Name,
						matchedRule:    ruleIdx,
						matchedField:   "resourceRule",
						evaluatedCount: evaluated,
						skippedCount:   skipped,
					}
				}
			}
			if sar.Spec.NonResourceAttributes != nil {
				if ruleIdx := wa.nonResourceRuleIndex(webhookAuthorizer.Spec.NonResourceRules, sar.Spec.NonResourceAttributes); ruleIdx >= 0 {
					return evaluationResult{
						allowed:        true,
						reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
						decision:       pkgmetrics.AuthorizerDecisionAllowed,
						authorizerName: webhookAuthorizer.Name,
						matchedRule:    ruleIdx,
						matchedField:   "nonResourceRule",
						evaluatedCount: evaluated,
						skippedCount:   skipped,
					}
				}
			}
		}
	}

	return evaluationResult{
		allowed:        false,
		reason:         "Access denied: no matching rules",
		decision:       pkgmetrics.AuthorizerDecisionNoOpinion,
		authorizerName: pkgmetrics.AuthorizerNameNone,
		matchedRule:    -1,
		evaluatedCount: evaluated,
		skippedCount:   skipped,
	}
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

// recordMetrics records Prometheus counters, histogram, and gauge for a
// completed SAR evaluation. This is called alongside audit logging to ensure
// Prometheus metrics stay in sync with the structured audit trail.
func (wa *Authorizer) recordMetrics(result *evaluationResult, latency time.Duration, activeRuleCount int) {
	pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(result.decision, result.authorizerName).Inc()
	pkgmetrics.AuthorizerRequestDuration.WithLabelValues(result.decision).Observe(latency.Seconds())
	pkgmetrics.AuthorizerActiveRules.Set(float64(activeRuleCount))

	if result.matchedField == "deniedPrincipal" {
		pkgmetrics.AuthorizerDeniedPrincipalHitsTotal.WithLabelValues(result.authorizerName).Inc()
	}
}

// writeRateLimitResponse writes a SubjectAccessReview response that denies the
// request due to rate limiting and sets the HTTP status to 429 Too Many Requests.
func (wa *Authorizer) writeRateLimitResponse(w http.ResponseWriter) {
	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  "rate limit exceeded",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "1")
	w.WriteHeader(http.StatusTooManyRequests)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode rate-limit response")
	}
}

// recordErrorMetrics records Prometheus request counter and duration histogram
// with decision=error for early-return error paths (decode failures, list
// failures) so error rates and latency remain visible in dashboards.
func (wa *Authorizer) recordErrorMetrics(start time.Time) {
	duration := time.Since(start).Seconds()
	pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(pkgmetrics.AuthorizerDecisionError, pkgmetrics.AuthorizerNameNone).Inc()
	pkgmetrics.AuthorizerRequestDuration.WithLabelValues(pkgmetrics.AuthorizerDecisionError).Observe(duration)
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

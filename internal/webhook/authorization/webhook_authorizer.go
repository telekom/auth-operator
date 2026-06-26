package webhooks

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
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

const (
	maxSubjectLimiters         = 4096
	minSubjectLimiterIdleTTL   = 5 * time.Minute
	subjectLimiterCleanupEvery = time.Minute
)

// maxRequestBodySize is the maximum allowed request body size (1MB).
// This prevents denial-of-service attacks via oversized request bodies.
const maxRequestBodySize = 1 << 20 // 1MB

// Validation rejection reasons returned by validateSAR.
const (
	reasonEmptyIdentity           = "empty user identity and no groups"
	reasonMissingAttrs            = "missing resource and non-resource attributes"
	reasonMultipleAttrs           = "resource and non-resource attributes are mutually exclusive"
	reasonInternalEvaluationError = "internal evaluation error"
	reasonUnauthorized            = "unauthorized"
)

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
// The Client field should be a live reader, typically manager.GetAPIReader(),
// because authorization decisions must not allow requests from stale informer
// state after rules or namespace labels change.
type Authorizer struct {
	Client client.Reader
	Log    logr.Logger
	Tracer trace.Tracer
	// BearerToken is optional. When set, /authorize requests must include
	// Authorization: Bearer <token> before the request body is trusted.
	BearerToken string
	// Limiter is used as a per-subject limiter template. Each SAR subject gets
	// an independent token bucket with this limit and burst, preventing one
	// identity from consuming another identity's authorization budget.
	Limiter *rate.Limiter

	subjectLimitersMu       sync.Mutex
	subjectLimiters         map[string]*subjectLimiterEntry
	subjectLimiterCleanupAt time.Time
}

type subjectLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Limit request body size to prevent OOM from oversized payloads.
	// Applied before any other processing so that early-return paths
	// (rate limiting, decode errors) also benefit from the size cap.
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	// Ensure request body is closed to prevent resource leaks.
	defer func() {
		if err := r.Body.Close(); err != nil {
			wa.Log.Error(err, "failed to close request body")
		}
	}()

	if !wa.authenticateRequest(w, r) {
		wa.recordRejectedMetrics(start)
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

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		wa.Log.Error(err, "failed to decode SubjectAccessReview request",
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "invalid request body")
		}
		wa.recordErrorMetrics(start)
		wa.writeDeniedResponse(w, "invalid request body")
		return
	}

	if reason := validateSAR(&sar); reason != "" {
		wa.Log.V(1).Info("rejecting malformed SubjectAccessReview",
			"reason", reason,
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		wa.recordRejectedMetrics(start)
		wa.writeDeniedResponse(w, reason)
		return
	}

	wa.annotateSARSpan(ctx, &sar)
	if wa.Limiter != nil && !wa.allowSubjectRequest(&sar) {
		pkgmetrics.AuthorizerRateLimitedTotal.Inc()
		wa.recordRejectedMetrics(start)
		wa.Log.V(1).Info("rate limit exceeded, rejecting request",
			"user", sar.Spec.User,
			"groups", cappedGroups(sar.Spec.Groups),
			"latency", time.Since(start).String())
		wa.writeRateLimitResponse(w)
		return
	}
	wa.logReceivedSAR(&sar)

	evalCtx, evalCancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer evalCancel()

	allItems, err := wa.listAllAuthorizers(evalCtx)
	if err != nil {
		wa.Log.Error(err, "failed to list WebhookAuthorizers",
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to list WebhookAuthorizers")
		}
		wa.recordErrorMetrics(start)
		wa.writeDeniedResponse(w, reasonInternalEvaluationError)
		return
	}
	globalItems, scopedItems := splitAuthorizers(allItems)
	allRules := countTotalRules(globalItems) + countTotalRules(scopedItems)

	items := append([]authorizationv1alpha1.WebhookAuthorizer(nil), globalItems...)

	// Always keep scoped authorizers loaded so the active-rules gauge reflects the
	// full set regardless of request type. Scoped authorizers are only used for
	// namespaced evaluation when the SAR targets a specific namespace; for
	// resource SARs without a namespace, they may only fail closed through a
	// matching deniedPrincipal/resourceRule.
	if sar.Spec.ResourceAttributes != nil {
		items = append(items, scopedItems...)
	}

	// Sort authorizers by name for deterministic first-match evaluation order
	// regardless of whether the client is backed by a cache (random map
	// iteration) or the API server (alphabetical order).
	slices.SortFunc(items, func(a, b authorizationv1alpha1.WebhookAuthorizer) int {
		return strings.Compare(a.Name, b.Name)
	})

	result, err := wa.evaluateSAR(evalCtx, &sar, items)
	if err != nil {
		wa.Log.Error(err, "failed to evaluate SubjectAccessReview",
			"user", sar.Spec.User,
			"latency", time.Since(start).String())
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.RecordError(err)
			span.SetStatus(codes.Error, "failed to evaluate SubjectAccessReview")
		}
		wa.recordErrorMetrics(start)
		wa.writeDeniedResponse(w, reasonInternalEvaluationError)
		return
	}

	publicReason := publicAuthorizerReason(result)

	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: result.allowed,
			// Set Denied=true for explicit deny decisions. Per K8s SAR semantics,
			// Allowed=false without Denied=true means "no opinion" — subsequent
			// authorizers can still allow the request. Only explicit deny (not
			// no-opinion) sets Denied=true.
			Denied: result.decision == pkgmetrics.AuthorizerDecisionDenied,
			Reason: publicReason,
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
			tracing.AttrReason.String(publicReason),
			tracing.AttrRuleCount.Int(allRules),
		)
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(respBytes); err != nil {
		wa.Log.Error(err, "failed to write SubjectAccessReview response",
			"latency", time.Since(start).String())
	}
}

func publicAuthorizerReason(result evaluationResult) string {
	switch result.decision {
	case pkgmetrics.AuthorizerDecisionAllowed:
		return "Access granted by WebhookAuthorizer"
	case pkgmetrics.AuthorizerDecisionDenied:
		return "Access denied by WebhookAuthorizer"
	default:
		return result.reason
	}
}

func (wa *Authorizer) allowSubjectRequest(sar *authzv1.SubjectAccessReview) bool {
	limiter := wa.subjectLimiter(rateLimitSubjectKey(sar))
	return limiter.Allow()
}

func (wa *Authorizer) subjectLimiter(subjectKey string) *rate.Limiter {
	wa.subjectLimitersMu.Lock()
	defer wa.subjectLimitersMu.Unlock()

	if wa.subjectLimiters == nil {
		wa.subjectLimiters = make(map[string]*subjectLimiterEntry)
	}
	now := time.Now()
	if now.After(wa.subjectLimiterCleanupAt) {
		wa.pruneSubjectLimitersLocked(now)
		wa.subjectLimiterCleanupAt = now.Add(subjectLimiterCleanupEvery)
	}
	if entry, exists := wa.subjectLimiters[subjectKey]; exists {
		entry.lastSeen = now
		return entry.limiter
	}
	if len(wa.subjectLimiters) >= maxSubjectLimiters {
		wa.evictOldestSubjectLimiterLocked()
	}
	limiter := rate.NewLimiter(wa.Limiter.Limit(), wa.Limiter.Burst())
	wa.subjectLimiters[subjectKey] = &subjectLimiterEntry{limiter: limiter, lastSeen: now}
	return limiter
}

func (wa *Authorizer) pruneSubjectLimitersLocked(now time.Time) {
	idleTTL := subjectLimiterIdleTTL(wa.Limiter)
	for key, entry := range wa.subjectLimiters {
		if now.Sub(entry.lastSeen) > idleTTL {
			delete(wa.subjectLimiters, key)
		}
	}
}

func subjectLimiterIdleTTL(limiter *rate.Limiter) time.Duration {
	if limiter == nil || limiter.Limit() <= 0 || limiter.Burst() <= 0 {
		return minSubjectLimiterIdleTTL
	}
	refill := time.Duration(float64(time.Second) * float64(limiter.Burst()) / float64(limiter.Limit()))
	if refill < minSubjectLimiterIdleTTL {
		return minSubjectLimiterIdleTTL
	}
	return refill
}

func (wa *Authorizer) evictOldestSubjectLimiterLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, entry := range wa.subjectLimiters {
		if oldestKey == "" || entry.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(wa.subjectLimiters, oldestKey)
	}
}

func rateLimitSubjectKey(sar *authzv1.SubjectAccessReview) string {
	groups := append([]string(nil), sar.Spec.Groups...)
	slices.Sort(groups)
	groups = slices.Compact(groups)
	return sar.Spec.User + "\x00" + strings.Join(groups, "\x00")
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
func countTotalRules(authorizers []authorizationv1alpha1.WebhookAuthorizer) int {
	total := 0
	for i := range authorizers {
		total += len(authorizers[i].Spec.ResourceRules) + len(authorizers[i].Spec.NonResourceRules)
	}
	return total
}

func splitAuthorizers(
	all []authorizationv1alpha1.WebhookAuthorizer,
) (globalItems, scopedItems []authorizationv1alpha1.WebhookAuthorizer) {
	globalItems = make([]authorizationv1alpha1.WebhookAuthorizer, 0, len(all))
	scopedItems = make([]authorizationv1alpha1.WebhookAuthorizer, 0, len(all))
	for _, candidate := range all {
		if helpers.IsLabelSelectorEmpty(&candidate.Spec.NamespaceSelector) {
			globalItems = append(globalItems, candidate)
		} else {
			scopedItems = append(scopedItems, candidate)
		}
	}

	return globalItems, scopedItems
}

func (wa *Authorizer) listAllAuthorizers(ctx context.Context) ([]authorizationv1alpha1.WebhookAuthorizer, error) {
	listCtx, cancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer cancel()
	var allAuth authorizationv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(listCtx, &allAuth); err != nil {
		return nil, fmt.Errorf("list WebhookAuthorizers: %w", err)
	}
	return allAuth.Items, nil
}

type namespaceLabelCacheEntry struct {
	labels labels.Set
	err    error
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, items []authorizationv1alpha1.WebhookAuthorizer) (evaluationResult, error) {
	evaluated := 0
	skipped := 0

	// nsLabelCache is a per-request cache keyed by namespace name. It records
	// both successful label fetches and Get errors so repeated scoped
	// authorizers do not repeat the same lookup, while errors still propagate
	// to the fail-closed HTTP path.
	var nsLabelCache map[string]namespaceLabelCacheEntry

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
				if sar.Spec.ResourceAttributes != nil &&
					wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
					if ruleIdx := wa.resourceRuleIndex(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes); ruleIdx >= 0 {
						evaluated++
						return evaluationResult{
							allowed:        false,
							reason:         fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name),
							decision:       pkgmetrics.AuthorizerDecisionDenied,
							authorizerName: webhookAuthorizer.Name,
							matchedRule:    ruleIdx,
							matchedField:   "deniedPrincipal",
							evaluatedCount: evaluated,
							skippedCount:   skipped,
						}, nil
					}
				}
				wa.Log.V(2).Info("skipping namespace-scoped authorizer for non-namespaced SAR",
					"authorizer", webhookAuthorizer.Name)
				skipped++
				continue
			}
			if nsLabelCache == nil {
				nsLabelCache = make(map[string]namespaceLabelCacheEntry)
			}
			matches, err := wa.namespaceMatches(ctx, resourceNS, &webhookAuthorizer.Spec.NamespaceSelector, nsLabelCache)
			if err != nil {
				return evaluationResult{
					allowed:        false,
					reason:         "internal evaluation error",
					decision:       pkgmetrics.AuthorizerDecisionNoOpinion,
					authorizerName: pkgmetrics.AuthorizerNameNone,
					matchedRule:    -1,
					evaluatedCount: evaluated,
					skippedCount:   skipped,
				}, fmt.Errorf("WebhookAuthorizer %q namespace selector: %w", webhookAuthorizer.Name, err)
			}
			if !matches {
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

		// Check DeniedPrincipals. Denies are scoped by the same resource and
		// non-resource rules as allows; otherwise a deny-list entry in a
		// namespaced authorizer would block unrelated requests in that namespace.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			if ruleIdx := wa.matchRequestRule(webhookAuthorizer.Spec.ResourceRules, webhookAuthorizer.Spec.NonResourceRules, sar); ruleIdx >= 0 {
				return evaluationResult{
					allowed:        false,
					reason:         fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name),
					decision:       pkgmetrics.AuthorizerDecisionDenied,
					authorizerName: webhookAuthorizer.Name,
					matchedRule:    ruleIdx,
					matchedField:   "deniedPrincipal",
					evaluatedCount: evaluated,
					skippedCount:   skipped,
				}, nil
			}
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			if ruleIdx, matchedField := wa.matchRequestRuleWithField(webhookAuthorizer.Spec.ResourceRules, webhookAuthorizer.Spec.NonResourceRules, sar); ruleIdx >= 0 {
				return evaluationResult{
					allowed:        true,
					reason:         fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name),
					decision:       pkgmetrics.AuthorizerDecisionAllowed,
					authorizerName: webhookAuthorizer.Name,
					matchedRule:    ruleIdx,
					matchedField:   matchedField,
					evaluatedCount: evaluated,
					skippedCount:   skipped,
				}, nil
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
	}, nil
}

// namespaceMatches checks if the namespace matches the selector.
// nsCache is a per-request map that avoids redundant Get calls when multiple
// scoped authorizers target the same namespace within one SAR evaluation.
// Cached Get errors are returned to callers so selector evaluation fails
// closed instead of silently skipping scoped authorizers.
func (wa *Authorizer) namespaceMatches(ctx context.Context, namespace string, selector *metav1.LabelSelector, nsCache map[string]namespaceLabelCacheEntry) (bool, error) {
	if wa.Tracer != nil {
		var span trace.Span
		ctx, span = wa.Tracer.Start(ctx, "webhook.NamespaceMatch",
			trace.WithAttributes(tracing.AttrNamespace.String(namespace)))
		defer span.End()
	}

	if namespace == "" {
		return false, nil
	}

	if cached, ok := nsCache[namespace]; ok {
		if cached.err != nil {
			return false, cached.err
		}
		labelSelector, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return false, fmt.Errorf("parse namespace selector for namespace %q: %w", namespace, err)
		}
		return labelSelector.Matches(cached.labels), nil
	}

	var ns corev1.Namespace
	getCtx, cancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer cancel()
	if err := wa.Client.Get(getCtx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		wrappedErr := fmt.Errorf("get namespace %q: %w", namespace, err)
		nsCache[namespace] = namespaceLabelCacheEntry{err: wrappedErr}
		return false, wrappedErr
	}
	nsLabels := labels.Set(ns.Labels)
	nsCache[namespace] = namespaceLabelCacheEntry{labels: nsLabels}

	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false, fmt.Errorf("parse namespace selector for namespace %q: %w", namespace, err)
	}
	return labelSelector.Matches(nsLabels), nil
}

// principalMatches checks if the user or groups match the principals.
func (wa *Authorizer) principalMatches(user string, groups []string, principals []authorizationv1alpha1.Principal) bool {
	for _, principal := range principals {
		if principal.Namespace != "" {
			if principal.User != "" && len(principal.Groups) == 0 && isServiceAccountInNamespace(user, principal.User, principal.Namespace) {
				return true
			}
			continue
		}
		if principal.User != "" && principal.User == user {
			return true
		}
		if len(principal.Groups) > 0 && intersects(groups, principal.Groups) {
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

func (wa *Authorizer) matchRequestRule(
	resourceRules []authzv1.ResourceRule,
	nonResourceRules []authzv1.NonResourceRule,
	sar *authzv1.SubjectAccessReview,
) int {
	ruleIdx, _ := wa.matchRequestRuleWithField(resourceRules, nonResourceRules, sar)
	return ruleIdx
}

func (wa *Authorizer) matchRequestRuleWithField(
	resourceRules []authzv1.ResourceRule,
	nonResourceRules []authzv1.NonResourceRule,
	sar *authzv1.SubjectAccessReview,
) (ruleIndex int, matchedField string) {
	if sar.Spec.ResourceAttributes != nil {
		if ruleIdx := wa.resourceRuleIndex(resourceRules, sar.Spec.ResourceAttributes); ruleIdx >= 0 {
			return ruleIdx, "resourceRule"
		}
	}
	if sar.Spec.NonResourceAttributes != nil {
		if ruleIdx := wa.nonResourceRuleIndex(nonResourceRules, sar.Spec.NonResourceAttributes); ruleIdx >= 0 {
			return ruleIdx, "nonResourceRule"
		}
	}
	return -1, ""
}

// resourceRuleIndex returns the index of the first matching resource rule, or -1.
//
// Subresource matching: when attr.Subresource is non-empty the composed string
// "resource/subresource" is matched against rule.Resources. A rule that lists
// only "pods" does NOT match a request for "pods/log" (subresource), so callers
// cannot inadvertently over-permit access to subresources.
//
// ResourceNames matching: when rule.ResourceNames is non-empty the request's
// attr.Name must appear in that list. An empty ResourceNames means "all names".
func (wa *Authorizer) resourceRuleIndex(rules []authzv1.ResourceRule, attr *authzv1.ResourceAttributes) int {
	// Compose the resource identifier including the subresource, if any.
	// K8s rule convention: subresources appear as "resource/subresource" in Rules.
	resourceKey := attr.Resource
	if attr.Subresource != "" {
		resourceKey = attr.Resource + "/" + attr.Subresource
	}
	for i, rule := range rules {
		if !matchesExactOrAll(rule.Verbs, attr.Verb) {
			continue
		}
		if !matchesExactOrAll(rule.APIGroups, attr.Group) {
			continue
		}
		if !matchesResourceRule(rule.Resources, resourceKey, attr.Subresource) {
			continue
		}
		// ResourceNames: non-empty list restricts which resource names are allowed.
		if len(rule.ResourceNames) > 0 && !matchesExactOrAll(rule.ResourceNames, attr.Name) {
			continue
		}
		return i
	}
	return -1
}

// nonResourceRuleIndex returns the index of the first matching non-resource rule, or -1.
func (wa *Authorizer) nonResourceRuleIndex(rules []authzv1.NonResourceRule, attr *authzv1.NonResourceAttributes) int {
	for i, rule := range rules {
		if matchesExactOrAll(rule.Verbs, attr.Verb) &&
			matchesNonResourceURLRule(rule.NonResourceURLs, attr.Path) {
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
// request due to rate limiting. Uses HTTP 200 with Allowed=false and Denied=true
// as required by the Kubernetes authorization webhook protocol:
//   - Non-200 is treated as a webhook failure, not a valid denial.
//   - Allowed=false without Denied=true means "no opinion"; setting Denied=true
//     ensures the request is actively rejected rather than passed to other authorizers.
func (wa *Authorizer) writeRateLimitResponse(w http.ResponseWriter) {
	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: false,
			Denied:  true,
			Reason:  "rate limit exceeded",
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode rate-limit response")
	}
}

// validateSAR checks that the SubjectAccessReview contains the fields a
// legitimate Kubernetes API server always populates: a non-empty user identity
// or at least one group, and at least one of ResourceAttributes or
// NonResourceAttributes. Returns an empty string when valid, or a
// human-readable reason when invalid.
func validateSAR(sar *authzv1.SubjectAccessReview) string {
	if sar.Spec.User == "" && len(sar.Spec.Groups) == 0 {
		return reasonEmptyIdentity
	}
	if sar.Spec.ResourceAttributes == nil && sar.Spec.NonResourceAttributes == nil {
		return reasonMissingAttrs
	}
	if sar.Spec.ResourceAttributes != nil && sar.Spec.NonResourceAttributes != nil {
		return reasonMultipleAttrs
	}
	return ""
}

// writeDeniedResponse sends a valid SubjectAccessReview with Denied=true so
// internal evaluation failures fail closed instead of becoming webhook
// transport failures that may be treated as no-opinion by the API server.
func (wa *Authorizer) writeDeniedResponse(w http.ResponseWriter, reason string) {
	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: false,
			Denied:  true,
			Reason:  reason,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		wa.Log.Error(err, "failed to encode denied response")
	}
}

func (wa *Authorizer) authenticateRequest(w http.ResponseWriter, r *http.Request) bool {
	if wa.BearerToken == "" {
		return true
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" || !constantTimeTokenEqual(token, wa.BearerToken) {
		wa.Log.V(1).Info("rejecting unauthorized SubjectAccessReview request")
		wa.writeDeniedResponse(w, reasonUnauthorized)
		return false
	}
	return true
}

func constantTimeTokenEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}

// recordErrorMetrics records Prometheus request counter and duration histogram
// with decision=error for early-return error paths (decode failures, list
// failures) so error rates and latency remain visible in dashboards.
func (wa *Authorizer) recordErrorMetrics(start time.Time) {
	duration := time.Since(start).Seconds()
	pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(pkgmetrics.AuthorizerDecisionError, pkgmetrics.AuthorizerNameNone).Inc()
	pkgmetrics.AuthorizerRequestDuration.WithLabelValues(pkgmetrics.AuthorizerDecisionError).Observe(duration)
}

// recordRejectedMetrics records Prometheus request counter and duration
// histogram with decision=denied for early rejection paths.
func (wa *Authorizer) recordRejectedMetrics(start time.Time) {
	duration := time.Since(start).Seconds()
	pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(pkgmetrics.AuthorizerDecisionDenied, pkgmetrics.AuthorizerNameNone).Inc()
	pkgmetrics.AuthorizerRequestDuration.WithLabelValues(pkgmetrics.AuthorizerDecisionDenied).Observe(duration)
}

// matchesExactOrAll matches Kubernetes ResourceRule fields where only exact
// values or the full "*" wildcard are supported.
func matchesExactOrAll(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

func matchesResourceRule(patterns []string, resourceKey, subresource string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == resourceKey {
			return true
		}
		if subresource != "" && pattern == "*/"+subresource {
			return true
		}
	}
	return false
}

func matchesNonResourceURLRule(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == path {
			return true
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

// isServiceAccountInNamespace checks if the user is a service account in the specified namespace.
func isServiceAccountInNamespace(user, principalUser, namespace string) bool {
	userNamespace, userName, ok := parseServiceAccountUsername(user)
	if !ok || userNamespace != namespace {
		return false
	}
	principalNamespace, principalName, principalIsQualified := parseServiceAccountUsername(principalUser)
	if principalIsQualified {
		return principalNamespace == namespace && principalName == userName
	}
	return principalUser == userName
}

func parseServiceAccountUsername(user string) (namespace, name string, ok bool) {
	// Format: system:serviceaccount:<namespace>:<serviceaccount>
	parts := strings.Split(user, ":")
	if len(parts) != 4 || parts[0] != systemPrefix || parts[1] != serviceAccountKind {
		return "", "", false
	}
	return parts[2], parts[3], true
}

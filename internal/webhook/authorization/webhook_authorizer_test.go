package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
	pkgmetrics "github.com/telekom/auth-operator/pkg/metrics"
)

// capturingLogger returns a logr.Logger that appends every log line to buf.
// verbosity controls which V-levels are visible (0 = Info only, 2 = all).
func capturingLogger(buf *strings.Builder, verbosity int) logr.Logger {
	return funcr.New(func(prefix, args string) {
		buf.WriteString(prefix)
		buf.WriteString(args)
		buf.WriteString("\n")
	}, funcr.Options{Verbosity: verbosity})
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := authzv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("failed to add authzv1alpha1 to scheme: %v", err)
	}
	return s
}

// newIndexedClient builds a fake client with the WebhookAuthorizer
// hasNamespaceSelector field index registered, matching the real manager setup.
func newIndexedClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(
			&authzv1alpha1.WebhookAuthorizer{},
			indexer.WebhookAuthorizerHasNamespaceSelectorField,
			indexer.WebhookAuthorizerHasNamespaceSelectorFunc,
		)
	if len(objs) > 0 {
		builder = builder.WithObjects(objs...)
	}
	return builder.Build()
}

func marshalSAR(t *testing.T, sar authzv1.SubjectAccessReview) []byte {
	t.Helper()
	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}
	return body
}

func TestAuditLog_DenyDecisionAtV0(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{{User: "baduser"}},
		},
	}
	cl := newIndexedClient(scheme, &wa)
	handler := &Authorizer{Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "baduser",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}

	body := marshalSAR(t, sar)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	output := buf.String()
	// Deny decisions must be logged at V(0) and contain key fields.
	if !strings.Contains(output, "authorization decision") {
		t.Error("expected 'authorization decision' log entry")
	}
	if !strings.Contains(output, `"decision"="denied"`) {
		t.Errorf("expected decision=denied in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"authorizer"="deny-wa"`) {
		t.Errorf("expected authorizer=deny-wa in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"user"="baduser"`) {
		t.Errorf("expected user=baduser in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"matchedField"="deniedPrincipal"`) {
		t.Errorf("expected matchedField=deniedPrincipal in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"latency"`) {
		t.Errorf("expected latency field in log output, got:\n%s", output)
	}
}

func TestAuditLog_AllowDecisionAtV1(t *testing.T) {
	// With verbosity=0 the allow decision should NOT appear.
	var buf0 strings.Builder
	logger0 := capturingLogger(&buf0, 0)
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "admin"}},
			ResourceRules:     []authzv1.ResourceRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		},
	}
	cl := newIndexedClient(scheme, &wa)

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "admin",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)

	handler0 := &Authorizer{Client: cl, Log: logger0}
	req0 := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec0 := httptest.NewRecorder()
	handler0.ServeHTTP(rec0, req0)

	if rec0.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec0.Code)
	}

	if strings.Contains(buf0.String(), "authorization decision") {
		t.Errorf("at V(0) allow decisions should not be logged, got:\n%s", buf0.String())
	}

	// With verbosity=1 the allow decision SHOULD appear.
	var buf1 strings.Builder
	logger1 := capturingLogger(&buf1, 1)
	handler1 := &Authorizer{Client: cl, Log: logger1}
	body = marshalSAR(t, sar)
	req1 := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler1.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec1.Code)
	}

	output := buf1.String()
	if !strings.Contains(output, "authorization decision") {
		t.Errorf("expected 'authorization decision' in V(1) log, got:\n%s", output)
	}
	if !strings.Contains(output, `"decision"="allowed"`) {
		t.Errorf("expected decision=allowed in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"authorizer"="allow-wa"`) {
		t.Errorf("expected authorizer=allow-wa in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"matchedRule"=0`) {
		t.Errorf("expected matchedRule=0 in log output, got:\n%s", output)
	}
}

func TestAuditLog_NoOpinionDecisionAtV1(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	// no-opinion is routine (no authorizer matched) and logged at V(1) to
	// reduce noise at V(0).
	var buf0 strings.Builder
	logger0 := capturingLogger(&buf0, 0)
	handler0 := &Authorizer{Client: cl, Log: logger0}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "unknown",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler0.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	if strings.Contains(buf0.String(), `"decision"="no-opinion"`) {
		t.Errorf("no-opinion should NOT appear at V(0), got:\n%s", buf0.String())
	}

	// At V(1) no-opinion should appear.
	var buf1 strings.Builder
	logger1 := capturingLogger(&buf1, 1)
	handler1 := &Authorizer{Client: cl, Log: logger1}
	body = marshalSAR(t, sar)
	req = httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handler1.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	output := buf1.String()
	if !strings.Contains(output, `"decision"="no-opinion"`) {
		t.Errorf("expected decision=no-opinion in log, got:\n%s", output)
	}
	if !strings.Contains(output, `"evaluatedCount"=0`) {
		t.Errorf("expected evaluatedCount=0 in log, got:\n%s", output)
	}
}

func TestAuditLog_V2TraceLogs(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 2)
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "trace-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "tracer"}},
			ResourceRules:     []authzv1.ResourceRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		},
	}
	cl := newIndexedClient(scheme, &wa)
	handler := &Authorizer{Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "tracer",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Namespace: "default"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	output := buf.String()
	if !strings.Contains(output, "received SubjectAccessReview") {
		t.Errorf("expected V(2) received-SAR trace log, got:\n%s", output)
	}
	if !strings.Contains(output, "evaluating WebhookAuthorizer") {
		t.Errorf("expected V(2) evaluating-authorizer trace log, got:\n%s", output)
	}
}

func TestAuditLog_DecodeError(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	cl := newIndexedClient(scheme)
	handler := &Authorizer{Client: cl, Log: logger}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}

	output := buf.String()
	if !strings.Contains(output, "failed to decode") {
		t.Errorf("expected decode error log, got:\n%s", output)
	}
	if !strings.Contains(output, "latency") {
		t.Errorf("expected latency in error log, got:\n%s", output)
	}
}

func TestAuditLog_NonResourceAttributes(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 1)
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "nonres-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "admin"}},
			NonResourceRules:  []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}},
		},
	}
	cl := newIndexedClient(scheme, &wa)
	handler := &Authorizer{Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:                  "admin",
			NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/healthz"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	output := buf.String()
	if !strings.Contains(output, `"decision"="allowed"`) {
		t.Errorf("expected allowed decision for non-resource, got:\n%s", output)
	}
	if !strings.Contains(output, `"path"="/healthz"`) {
		t.Errorf("expected path in log output, got:\n%s", output)
	}
	if !strings.Contains(output, `"matchedField"="nonResourceRule"`) {
		t.Errorf("expected matchedField=nonResourceRule, got:\n%s", output)
	}
}

func TestEvaluateSAR_ResultFields(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "eval-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			DeniedPrincipals:  []authzv1alpha1.Principal{{User: "bob"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"secrets"}},
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	waList := &authzv1alpha1.WebhookAuthorizerList{Items: []authzv1alpha1.WebhookAuthorizer{wa}}

	t.Run("allowed returns correct rule index", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "alice",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if !res.allowed {
			t.Fatal("expected allowed")
		}
		if res.matchedRule != 1 {
			t.Errorf("expected matchedRule=1, got %d", res.matchedRule)
		}
		if res.decision != pkgmetrics.AuthorizerDecisionAllowed {
			t.Errorf("expected decision=allowed, got %s", res.decision)
		}
	})

	t.Run("denied sets matchedField and authorizerName", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "bob",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if res.allowed {
			t.Fatal("expected denied")
		}
		if res.matchedField != "deniedPrincipal" {
			t.Errorf("expected matchedField=deniedPrincipal, got %s", res.matchedField)
		}
		if res.authorizerName != "eval-wa" {
			t.Errorf("expected authorizerName=eval-wa, got %s", res.authorizerName)
		}
		if res.decision != pkgmetrics.AuthorizerDecisionDenied {
			t.Errorf("expected decision=denied, got %s", res.decision)
		}
	})

	t.Run("no-opinion when no authorizer matches", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "charlie",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if res.allowed {
			t.Fatal("expected denied")
		}
		if res.decision != pkgmetrics.AuthorizerDecisionNoOpinion {
			t.Errorf("expected decision=no-opinion, got %s", res.decision)
		}
		if res.evaluatedCount != 1 {
			t.Errorf("expected evaluatedCount=1, got %d", res.evaluatedCount)
		}
		if res.matchedRule != -1 {
			t.Errorf("expected matchedRule=-1, got %d", res.matchedRule)
		}
	})
}

func TestServeHTTP_OversizedBody(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	cl := newIndexedClient(scheme)
	handler := &Authorizer{Client: cl, Log: logger}

	// Create a body larger than 1MB
	oversizedBody := make([]byte, 1<<20+1)
	for i := range oversizedBody {
		oversizedBody[i] = 'A'
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(oversizedBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic error message, got %q", body)
	}
}

func TestServeHTTP_InvalidJSON(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	cl := newIndexedClient(scheme)
	handler := &Authorizer{Client: cl, Log: logger}

	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("{invalid json"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}

	body := rec.Body.String()
	// Verify the error message does NOT leak internal details
	if strings.Contains(body, "json") || strings.Contains(body, "invalid character") {
		t.Errorf("error response leaks internal details: %q", body)
	}
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic error message, got %q", body)
	}
}

// TestAuditLog_StructuredFieldsComprehensive verifies that the structured audit log
// output contains ALL expected fields for each decision type.
// If the log format changes (e.g., a field is renamed or removed), this test catches
// the breakage before it reaches log parsers and SIEM integrations.
func TestAuditLog_StructuredFieldsComprehensive(t *testing.T) {
	scheme := newScheme(t)

	// Set up a deny authorizer so we get a deny decision at V(0).
	deny := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "audit-format-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{{User: "audit-user"}},
		},
	}
	cl := newIndexedClient(scheme, &deny)

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   "audit-user",
			Groups: []string{"group-a", "group-b"},
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      "delete",
				Group:     "apps",
				Resource:  "deployments",
				Namespace: "production",
			},
		},
	}

	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	handler := &Authorizer{Client: cl, Log: logger}

	body := marshalSAR(t, sar)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	output := buf.String()

	// Mandatory structured fields that log parsers depend on.
	// These field names MUST NOT change without updating SIEM/log pipeline configurations.
	requiredFields := []struct {
		key   string
		value string
	}{
		{"decision", "denied"},
		{"user", "audit-user"},
		{"groups", ""}, // present with array value
		{"authorizer", "audit-format-wa"},
		{"evaluatedCount", ""},
		{"latency", ""},
		{"verb", "delete"},
		{"apiGroup", "apps"},
		{"resource", "deployments"},
		{"namespace", "production"},
	}

	for _, f := range requiredFields {
		fieldKey := `"` + f.key + `"`
		if !strings.Contains(output, fieldKey) {
			t.Errorf("structured audit log missing required field %q\nFull output:\n%s", f.key, output)
		}
		if f.value != "" {
			fieldKV := `"` + f.key + `"="` + f.value + `"`
			if !strings.Contains(output, fieldKV) {
				t.Errorf("structured audit log field %q expected value %q not found\nFull output:\n%s", f.key, f.value, output)
			}
		}
	}

	// Verify the log message key is stable.
	if !strings.Contains(output, "authorization decision") {
		t.Errorf("missing stable log message 'authorization decision'\nFull output:\n%s", output)
	}

	// Verify the response body still contains a valid SubjectAccessReview.
	var respSAR authzv1.SubjectAccessReview
	if err := json.Unmarshal(rec.Body.Bytes(), &respSAR); err != nil {
		t.Fatalf("response body is not valid SubjectAccessReview JSON: %v", err)
	}
	if respSAR.Status.Allowed {
		t.Errorf("expected allowed=false (denied) in response, got %+v", respSAR.Status)
	}
	if respSAR.Status.Reason == "" {
		t.Errorf("expected non-empty denial reason in response, got %+v", respSAR.Status)
	}
}

// TestMetrics_RecordedAfterServeHTTP verifies that Prometheus metrics are
// correctly emitted after ServeHTTP processes a SubjectAccessReview. This
// guards against regressions where refactoring might break metric recording.
func TestMetrics_RecordedAfterServeHTTP(t *testing.T) {
	scheme := newScheme(t)
	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals:  []authzv1alpha1.Principal{{User: "blocked"}},
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "admin"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	cl := newIndexedClient(scheme, &wa)

	// Reset counters, histogram and gauge so prior tests don't pollute assertions.
	pkgmetrics.AuthorizerRequestsTotal.Reset()
	pkgmetrics.AuthorizerDeniedPrincipalHitsTotal.Reset()
	pkgmetrics.AuthorizerRequestDuration.Reset()
	pkgmetrics.AuthorizerActiveRules.Set(0)

	// --- Deny decision ---
	handler := &Authorizer{Client: cl, Log: logr.Discard()}
	denySAR := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "blocked",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, denySAR)
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("deny: expected 200, got %d", rec.Code)
	}

	// Verify denied counter incremented.
	deniedCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionDenied, "metrics-wa"))
	if deniedCount != 1 {
		t.Errorf("expected AuthorizerRequestsTotal{denied,metrics-wa}=1, got %v", deniedCount)
	}

	// Verify denied principal hits counter incremented.
	deniedPrincipalCount := testutil.ToFloat64(pkgmetrics.AuthorizerDeniedPrincipalHitsTotal.WithLabelValues("metrics-wa"))
	if deniedPrincipalCount != 1 {
		t.Errorf("expected AuthorizerDeniedPrincipalHitsTotal{metrics-wa}=1, got %v", deniedPrincipalCount)
	}

	// Verify duration histogram was observed (at least 1 sample across all buckets).
	if testutil.CollectAndCount(pkgmetrics.AuthorizerRequestDuration) == 0 {
		t.Error("expected AuthorizerRequestDuration to have observations")
	}

	// --- Allow decision ---
	allowSAR := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "admin",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
		},
	}
	body = marshalSAR(t, allowSAR)
	req = httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("allow: expected 200, got %d", rec.Code)
	}

	allowedCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionAllowed, "metrics-wa"))
	if allowedCount != 1 {
		t.Errorf("expected AuthorizerRequestsTotal{allowed,metrics-wa}=1, got %v", allowedCount)
	}

	// --- Active rules gauge ---
	// The authorizer has 2 ResourceRules, so the gauge should reflect that.
	activeRules := testutil.ToFloat64(pkgmetrics.AuthorizerActiveRules)
	if activeRules != 2 {
		t.Errorf("expected AuthorizerActiveRules=2, got %v", activeRules)
	}

	// --- No-opinion decision (no authorizer matched) ---
	pkgmetrics.AuthorizerRequestsTotal.Reset()
	noMatchSAR := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "unknown-user",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "other", Resource: "secrets"},
		},
	}
	body = marshalSAR(t, noMatchSAR)
	req = httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("no-opinion: expected 200, got %d", rec.Code)
	}

	noOpinionCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionNoOpinion, pkgmetrics.AuthorizerNameNone))
	if noOpinionCount != 1 {
		t.Errorf("expected AuthorizerRequestsTotal{no-opinion,none}=1, got %v", noOpinionCount)
	}

	// --- Error decision (decode failure) ---
	pkgmetrics.AuthorizerRequestsTotal.Reset()
	req = httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	errorCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionError, pkgmetrics.AuthorizerNameNone))
	if errorCount != 1 {
		t.Errorf("expected AuthorizerRequestsTotal{error,none}=1, got %v", errorCount)
	}
}

func TestCappedGroups(t *testing.T) {
	tests := []struct {
		name   string
		groups []string
		want   int
	}{
		{"nil", nil, 0},
		{"empty", []string{}, 0},
		{"under-limit", []string{"a", "b"}, 2},
		{"at-limit", make([]string, maxLoggedGroups), maxLoggedGroups},
		{"over-limit", make([]string, maxLoggedGroups+5), maxLoggedGroups + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cappedGroups(tt.groups)
			if len(got) != tt.want {
				t.Errorf("cappedGroups(%d groups) returned %d elements, want %d", len(tt.groups), len(got), tt.want)
			}
			if tt.want > maxLoggedGroups {
				last := got[len(got)-1]
				if !strings.Contains(last, "more") {
					t.Errorf("expected trailing '...and N more' element, got %q", last)
				}
			}
		})
	}
}

func TestCountTotalRules(t *testing.T) {
	tests := []struct {
		name        string
		authorizers []authzv1alpha1.WebhookAuthorizer
		want        int
	}{
		{"nil", nil, 0},
		{"empty", []authzv1alpha1.WebhookAuthorizer{}, 0},
		{"single with rules", []authzv1alpha1.WebhookAuthorizer{
			{Spec: authzv1alpha1.WebhookAuthorizerSpec{
				ResourceRules:    []authzv1.ResourceRule{{Verbs: []string{"get"}}},
				NonResourceRules: []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}},
			}},
		}, 2},
		{"multiple", []authzv1alpha1.WebhookAuthorizer{
			{Spec: authzv1alpha1.WebhookAuthorizerSpec{
				ResourceRules: []authzv1.ResourceRule{{Verbs: []string{"get"}}, {Verbs: []string{"list"}}},
			}},
			{Spec: authzv1alpha1.WebhookAuthorizerSpec{
				NonResourceRules: []authzv1.NonResourceRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}},
			}},
		}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countTotalRules(tt.authorizers)
			if got != tt.want {
				t.Errorf("countTotalRules() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestServeHTTP_RateLimiting(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 2)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	// Limiter with burst=1: first request allowed, second rejected.
	handler := &Authorizer{
		Client:  cl,
		Log:     logger,
		Limiter: rate.NewLimiter(rate.Limit(0), 1), // 0 rps, burst 1
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   "test-user",
			Groups: []string{"test-group"},
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body := marshalSAR(t, sar)

	// Ensure the counter series exists so we can measure the delta.
	pkgmetrics.AuthorizerRateLimitedTotal.Add(0)
	initialCount := testutil.ToFloat64(pkgmetrics.AuthorizerRateLimitedTotal)

	// First request should succeed (uses the burst token).
	req1 := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected first request to succeed with status %d, got %d", http.StatusOK, rec1.Code)
	}

	// Second request should be rate limited (no tokens left, 0 rps).
	// Per the Kubernetes authorization webhook protocol, the response is HTTP 200
	// with Allowed=false (non-200 would be treated as a webhook failure).
	req2 := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Errorf("expected rate-limited response to use status %d (K8s webhook protocol), got %d", http.StatusOK, rec2.Code)
	}

	// Verify the response is a valid denied SubjectAccessReview.
	var response authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec2.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode rate-limited response: %v", err)
	}
	if response.Status.Allowed {
		t.Error("rate-limited response should have Allowed=false")
	}
	if response.Status.Reason != "rate limit exceeded" {
		t.Errorf("expected reason %q, got %q", "rate limit exceeded", response.Status.Reason)
	}

	// Verify the rate-limited metric incremented.
	afterCount := testutil.ToFloat64(pkgmetrics.AuthorizerRateLimitedTotal)
	if afterCount-initialCount < 1 {
		t.Errorf("AuthorizerRateLimitedTotal did not increment: before=%v, after=%v", initialCount, afterCount)
	}
}

func TestServeHTTP_NoRateLimiter(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	// No Limiter set — rate limiting should be disabled.
	handler := &Authorizer{
		Client: cl,
		Log:    logger,
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   "test-user",
			Groups: []string{"test-group"},
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body := marshalSAR(t, sar)

	// Multiple requests should all succeed when limiter is nil.
	for i := range 5 {
		req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status %d, got %d", i, http.StatusOK, rec.Code)
		}
	}
}

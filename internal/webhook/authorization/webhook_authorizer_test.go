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
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
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

func newScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = authzv1alpha1.AddToScheme(s)
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
	scheme := newScheme()

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
	scheme := newScheme()

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
	scheme := newScheme()
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
	scheme := newScheme()

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
	scheme := newScheme()

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
	scheme := newScheme()

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
	scheme := newScheme()
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
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if !res.allowed {
			t.Fatal("expected allowed")
		}
		if res.matchedRule != 1 {
			t.Errorf("expected matchedRule=1, got %d", res.matchedRule)
		}
		if res.decision != decisionAllowed {
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
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if res.allowed {
			t.Fatal("expected denied")
		}
		if res.matchedField != "deniedPrincipal" {
			t.Errorf("expected matchedField=deniedPrincipal, got %s", res.matchedField)
		}
		if res.authorizerName != "eval-wa" {
			t.Errorf("expected authorizerName=eval-wa, got %s", res.authorizerName)
		}
		if res.decision != decisionDenied {
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
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if res.allowed {
			t.Fatal("expected denied")
		}
		if res.decision != decisionNoOpinion {
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
	scheme := newScheme()

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
	scheme := newScheme()

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
	scheme := newScheme()

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

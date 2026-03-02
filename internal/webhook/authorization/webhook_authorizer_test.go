package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	dto "github.com/prometheus/client_model/go"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/metrics"
)

// resetAuthorizerMetrics zeroes out all authorizer-related counters so that
// individual test cases do not interfere with each other.
func resetAuthorizerMetrics() {
	metrics.AuthorizerRequestsTotal.Reset()
	metrics.AuthorizerRequestDuration.Reset()
	metrics.AuthorizerActiveRules.Set(0)
	metrics.AuthorizerDeniedPrincipalHitsTotal.Reset()
}

// counterValue returns the current value of a counter with the given labels.
func counterValue(cv *dto.Metric) float64 {
	if cv.Counter != nil {
		return cv.Counter.GetValue()
	}
	return 0
}

func TestServeHTTPMetrics_Allowed(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-authorizer"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{
				{User: "admin"},
			},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wa).
		Build()

	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "admin",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "",
				Resource:  "pods",
			},
		},
	}

	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Status.Allowed {
		t.Fatalf("expected allowed=true, got false; reason=%s", resp.Status.Reason)
	}

	// Verify metrics were recorded.
	m := &dto.Metric{}
	if err := metrics.AuthorizerRequestsTotal.WithLabelValues(
		metrics.AuthorizerDecisionAllowed, "test-authorizer",
	).Write(m); err != nil {
		t.Fatalf("failed to read metric: %v", err)
	}
	if counterValue(m) != 1 {
		t.Errorf("expected authorizer_requests_total{allowed,test-authorizer}=1, got %v", counterValue(m))
	}
}

func TestServeHTTPMetrics_DeniedByPrincipal(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-authorizer"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{
				{User: "baduser"},
			},
		},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wa).
		Build()

	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "baduser",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Fatal("expected denied, got allowed")
	}

	// Verify denied counter.
	m := &dto.Metric{}
	if err := metrics.AuthorizerRequestsTotal.WithLabelValues(
		metrics.AuthorizerDecisionDenied, "deny-authorizer",
	).Write(m); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if counterValue(m) != 1 {
		t.Errorf("expected authorizer_requests_total{denied,deny-authorizer}=1, got %v", counterValue(m))
	}

	// Verify denied-principal-hits counter.
	m2 := &dto.Metric{}
	if err := metrics.AuthorizerDeniedPrincipalHitsTotal.WithLabelValues("deny-authorizer").Write(m2); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if counterValue(m2) != 1 {
		t.Errorf("expected authorizer_denied_principal_hits_total{deny-authorizer}=1, got %v", counterValue(m2))
	}
}

func TestServeHTTPMetrics_DecodeError(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rec.Code)
	}

	// Error counter should be incremented.
	m := &dto.Metric{}
	if err := metrics.AuthorizerRequestsTotal.WithLabelValues(
		metrics.AuthorizerDecisionError, metrics.AuthorizerNameNone,
	).Write(m); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if counterValue(m) != 1 {
		t.Errorf("expected authorizer_requests_total{error,none}=1, got %v", counterValue(m))
	}
}

func TestServeHTTPMetrics_ActiveRules(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	wa1 := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "rule-1"},
		Spec:       authzv1alpha1.WebhookAuthorizerSpec{},
	}
	wa2 := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "rule-2"},
		Spec:       authzv1alpha1.WebhookAuthorizerSpec{},
	}

	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&wa1, &wa2).
		Build()

	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "somebody",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
			},
		},
	}
	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Verify active-rules gauge reflects the two authorizer objects.
	m := &dto.Metric{}
	if err := metrics.AuthorizerActiveRules.Write(m); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if m.Gauge == nil || m.Gauge.GetValue() != 2 {
		got := float64(0)
		if m.Gauge != nil {
			got = m.Gauge.GetValue()
		}
		t.Errorf("expected authorizer_active_rules=2, got %v", got)
	}
}

func TestEvaluateSAR_ReturnsResult(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "test-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			DeniedPrincipals:  []authzv1alpha1.Principal{{User: "bob"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}

	waList := &authzv1alpha1.WebhookAuthorizerList{Items: []authzv1alpha1.WebhookAuthorizer{wa}}

	t.Run("allowed", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "alice",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if !res.allowed {
			t.Fatalf("expected allowed=true, got false")
		}
		if res.authorizerName != "test-wa" {
			t.Errorf("expected authorizerName=test-wa, got %s", res.authorizerName)
		}
	})

	t.Run("denied by principal", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "bob",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if res.allowed {
			t.Fatal("expected allowed=false")
		}
		if !res.deniedByPrincipal {
			t.Error("expected deniedByPrincipal=true")
		}
		if res.authorizerName != "test-wa" {
			t.Errorf("expected authorizerName=test-wa, got %s", res.authorizerName)
		}
	})

	t.Run("no matching rules", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "charlie",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
			},
		}
		res := handler.evaluateSAR(context.Background(), sar, waList)
		if res.allowed {
			t.Fatal("expected allowed=false")
		}
		if res.deniedByPrincipal {
			t.Error("expected deniedByPrincipal=false for no-match denial")
		}
		if res.authorizerName != metrics.AuthorizerNameNone {
			t.Errorf("expected authorizerName=%s, got %s", metrics.AuthorizerNameNone, res.authorizerName)
		}
	})
}

func TestServeHTTP_OversizedBody(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	// Create a body larger than 1MB.
	oversizedBody := make([]byte, 1<<20+1)
	for i := range oversizedBody {
		oversizedBody[i] = 'A'
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestServeHTTP_ErrorResponseDoesNotLeakInternals(t *testing.T) {
	resetAuthorizerMetrics()

	scheme := runtime.NewScheme()
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{Client: cl, Log: logr.Discard()}

	malformedInputs := []struct {
		name string
		body string
	}{
		{"truncated json", `{"spec": {"user": `},
		{"wrong type", `{"spec": "not an object"}`},
		{"array instead of object", `[1,2,3]`},
	}

	internalPatterns := []string{
		"json:",
		"cannot unmarshal",
		"unexpected end",
		"invalid character",
		".go:",
		"runtime error",
	}

	for _, tt := range malformedInputs {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader([]byte(tt.body)))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
			}

			body := rec.Body.String()
			for _, pattern := range internalPatterns {
				if bytes.Contains([]byte(body), []byte(pattern)) {
					t.Errorf("error response leaks internal details (contains %q): %q", pattern, body)
				}
			}
		})
	}
}

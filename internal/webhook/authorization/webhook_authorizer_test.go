/*
Copyright © 2026 Deutsche Telekom AG.
*/

package webhooks_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(authzv1alpha1.AddToScheme(s))
	return s
}

func TestServeHTTP_OversizedBody(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	// Create a body larger than 1MB
	oversizedBody := make([]byte, 1<<20+1)
	for i := range oversizedBody {
		oversizedBody[i] = 'A'
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic error message, got %q", body)
	}
}

func TestServeHTTP_InvalidJSON(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	body := w.Body.String()
	// Verify the error message does NOT leak internal details
	if strings.Contains(body, "json") || strings.Contains(body, "invalid character") {
		t.Errorf("error response leaks internal details: %q", body)
	}
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic error message, got %q", body)
	}
}

func TestServeHTTP_ValidSAR(t *testing.T) {
	scheme := newTestScheme()

	waObj := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-wa",
		},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{
				{User: "test-user"},
			},
			ResourceRules: []authzv1.ResourceRule{
				{
					Verbs:     []string{"get"},
					APIGroups: []string{""},
					Resources: []string{"pods"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(waObj).
		Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "test-user",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Resource: "pods",
				Group:    "",
			},
		},
	}

	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Status.Allowed {
		t.Errorf("expected allowed=true, got allowed=false, reason=%q", resp.Status.Reason)
	}
}

func TestServeHTTP_DeniedSAR(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "unauthorized-user",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "delete",
				Resource: "pods",
			},
		},
	}

	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status.Allowed {
		t.Error("expected allowed=false, got allowed=true")
	}
}

func TestServeHTTP_NonResourceSAR(t *testing.T) {
	scheme := newTestScheme()

	waObj := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-nonresource-wa",
		},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{
				{User: "admin-user"},
			},
			NonResourceRules: []authzv1.NonResourceRule{
				{
					Verbs:           []string{"get"},
					NonResourceURLs: []string{"/healthz"},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(waObj).
		Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "admin-user",
			NonResourceAttributes: &authzv1.NonResourceAttributes{
				Verb: "get",
				Path: "/healthz",
			},
		},
	}

	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Status.Allowed {
		t.Errorf("expected allowed=true for non-resource rule, got denied: %q", resp.Status.Reason)
	}
}

func TestServeHTTP_EmptyBody(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(""))
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "invalid request body") {
		t.Errorf("expected generic error message, got %q", body)
	}
}

func TestServeHTTP_ErrorResponseDoesNotLeakInternals(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	// Test with various malformed inputs
	malformedInputs := []struct {
		name string
		body string
	}{
		{"truncated json", `{"spec": {"user": `},
		{"wrong type", `{"spec": "not an object"}`},
		{"array instead of object", `[1,2,3]`},
	}

	for _, tt := range malformedInputs {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(tt.body))
			w := httptest.NewRecorder()

			authorizer.ServeHTTP(w, req)

			body := w.Body.String()

			// Response must NOT contain any of these internal details
			internalPatterns := []string{
				"json:",
				"cannot unmarshal",
				"unexpected end",
				"invalid character",
				".go:",
				"runtime error",
			}
			for _, pattern := range internalPatterns {
				if strings.Contains(body, pattern) {
					t.Errorf("error response leaks internal details (contains %q): %q", pattern, body)
				}
			}
		})
	}
}

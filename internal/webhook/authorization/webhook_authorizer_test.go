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
	"github.com/telekom/auth-operator/pkg/indexer"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(authzv1alpha1.AddToScheme(s))
	return s
}

// newIndexedFakeClient builds a fake client with the WebhookAuthorizer
// hasNamespaceSelector field index registered, matching the real manager setup.
func newIndexedFakeClient(scheme *runtime.Scheme, objs ...client.Object) client.Client {
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

func TestServeHTTP_OversizedBody(t *testing.T) {
	scheme := newTestScheme()
	fakeClient := newIndexedFakeClient(scheme)

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
	fakeClient := newIndexedFakeClient(scheme)

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

	fakeClient := newIndexedFakeClient(scheme, waObj)

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
	fakeClient := newIndexedFakeClient(scheme)

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

	fakeClient := newIndexedFakeClient(scheme, waObj)

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
	fakeClient := newIndexedFakeClient(scheme)

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
	fakeClient := newIndexedFakeClient(scheme)

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

func TestServeHTTP_NamespaceScopedAuthorizerSkippedForNonNamespacedSAR(t *testing.T) {
	scheme := newTestScheme()

	// Create a namespace-scoped authorizer that should NOT match cluster-level requests.
	waScoped := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-scoped"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "scoped-user"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}

	fakeClient := newIndexedFakeClient(scheme, waScoped)

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	// SAR without a namespace — scoped authorizer should not be consulted.
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "scoped-user",
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
	w := httptest.NewRecorder()

	authorizer.ServeHTTP(w, req)

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Scoped authorizer should be excluded for non-namespaced SAR, so access is denied.
	if resp.Status.Allowed {
		t.Error("expected denied for non-namespaced SAR with only scoped authorizer")
	}
}

func TestServeHTTP_GlobalAndScopedAuthorizers(t *testing.T) {
	scheme := newTestScheme()

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}

	waGlobal := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-global"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "global-user"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"services"}},
			},
		},
	}

	waScoped := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-scoped"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "scoped-user"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}

	fakeClient := newIndexedFakeClient(scheme, ns, waGlobal, waScoped)

	authorizer := &webhooks.Authorizer{
		Client: fakeClient,
		Log:    zap.New(zap.WriteTo(io.Discard)),
	}

	// Test 1: Global user can access services (global authorizer, no namespace).
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "global-user",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "list",
				Resource: "services",
				Group:    "",
			},
		},
	}
	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("test 1: failed to marshal SAR: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	authorizer.ServeHTTP(w, req)

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("test 1: failed to decode: %v", err)
	}
	if !resp.Status.Allowed {
		t.Errorf("test 1: expected global user allowed, got denied: %s", resp.Status.Reason)
	}

	// Test 2: Scoped user can access pods in matching namespace.
	sar2 := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "scoped-user",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      "get",
				Resource:  "pods",
				Group:     "",
				Namespace: "test-ns",
			},
		},
	}
	body2, err := json.Marshal(sar2)
	if err != nil {
		t.Fatalf("test 2: failed to marshal SAR: %v", err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/authorize", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	authorizer.ServeHTTP(w2, req2)

	var resp2 authzv1.SubjectAccessReview
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatalf("test 2: failed to decode: %v", err)
	}
	if !resp2.Status.Allowed {
		t.Errorf("test 2: expected scoped user allowed in matching namespace, got denied: %s", resp2.Status.Reason)
	}
}

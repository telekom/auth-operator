package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/indexer"
	pkgmetrics "github.com/telekom/auth-operator/pkg/metrics"
)

// namespaceGetCountingClient wraps a client.Client and counts Get calls for
// Namespace objects so tests can verify the per-request namespace label cache
// eliminates redundant lookups.
type namespaceGetCountingClient struct {
	client.Client
	getCount atomic.Int64
}

func (c *namespaceGetCountingClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*corev1.Namespace); ok {
		c.getCount.Add(1)
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

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
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("failed to add corev1 to scheme: %v", err)
	}
	return s
}

func newSchemeWithCore(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := newScheme(t)
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("failed to add clientgoscheme to scheme: %v", err)
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

func TestServeHTTP_EvaluatesMatchingAuthorizersByName(t *testing.T) {
	scheme := newScheme(t)
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Group:    "",
				Resource: "pods",
			},
		},
	}

	newAllowAuthorizer := func(name string) authzv1alpha1.WebhookAuthorizer {
		return authzv1alpha1.WebhookAuthorizer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authzv1alpha1.WebhookAuthorizerSpec{
				AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
				ResourceRules: []authzv1.ResourceRule{
					{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			},
		}
	}
	newDenyAuthorizer := func(name string) authzv1alpha1.WebhookAuthorizer {
		return authzv1alpha1.WebhookAuthorizer{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authzv1alpha1.WebhookAuthorizerSpec{
				DeniedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
				ResourceRules: []authzv1.ResourceRule{
					{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				},
			},
		}
	}

	tests := []struct {
		name             string
		authorizer       []authzv1alpha1.WebhookAuthorizer
		wantAllow        bool
		wantPublicReason string
	}{
		{
			name: "first authorizer allows before later deny",
			authorizer: []authzv1alpha1.WebhookAuthorizer{
				newDenyAuthorizer("zzz-deny"),
				newAllowAuthorizer("aaa-allow"),
			},
			wantAllow:        true,
			wantPublicReason: "Access granted by WebhookAuthorizer",
		},
		{
			name: "first authorizer denies before later allow",
			authorizer: []authzv1alpha1.WebhookAuthorizer{
				newAllowAuthorizer("zzz-allow"),
				newDenyAuthorizer("aaa-deny"),
			},
			wantAllow:        false,
			wantPublicReason: "Access denied by WebhookAuthorizer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]client.Object, 0, len(tt.authorizer))
			for i := range tt.authorizer {
				objs = append(objs, &tt.authorizer[i])
			}
			handler := &Authorizer{
				AllowUnauthenticatedAuthorize: true,
				Client:                        newIndexedClient(scheme, objs...),
				Log:                           logr.Discard(),
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}

			var resp authzv1.SubjectAccessReview
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}
			if resp.Status.Allowed != tt.wantAllow {
				t.Fatalf("expected allowed=%t, got %+v", tt.wantAllow, resp.Status)
			}
			if resp.Status.Reason != tt.wantPublicReason {
				t.Fatalf("expected public reason %q, got %q", tt.wantPublicReason, resp.Status.Reason)
			}
			for _, authorizer := range tt.authorizer {
				if strings.Contains(resp.Status.Reason, authorizer.Name) {
					t.Fatalf("public reason leaks authorizer name %q: %q", authorizer.Name, resp.Status.Reason)
				}
			}
		})
	}
}

func TestServeHTTP_AuthorizerRulesUseLiveClient(t *testing.T) {
	scheme := newScheme(t)
	freshDeny := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "fresh-deny"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        newIndexedClient(scheme, freshDeny),
		Log:                           logr.Discard(),
	}
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "get",
				Group:    "",
				Resource: "pods",
			},
		},
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Fatalf("expected fresh reader denial, got %+v", resp.Status)
	}
	if resp.Status.Reason != "Access denied by WebhookAuthorizer" {
		t.Fatalf("expected generic denial reason, got %q", resp.Status.Reason)
	}
	if strings.Contains(resp.Status.Reason, "fresh-deny") {
		t.Fatalf("public reason leaks authorizer name: %q", resp.Status.Reason)
	}
}

func TestServeHTTP_ScopedAuthorizerDeniesClusterScopedResourceSAR(t *testing.T) {
	scheme := newScheme(t)
	scopedDeny := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-cluster-deny"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
			DeniedPrincipals: []authzv1alpha1.Principal{{Groups: []string{"tenant-admins"}}},
			ResourceRules: []authzv1.ResourceRule{{
				Verbs:     []string{"delete"},
				APIGroups: []string{"rbac.authorization.k8s.io"},
				Resources: []string{"clusterroles"},
			}},
		},
	}
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        newIndexedClient(scheme, scopedDeny),
		Log:                           logr.Discard(),
	}
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:   "alice",
			Groups: []string{"tenant-admins"},
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "delete",
				Group:    "rbac.authorization.k8s.io",
				Resource: "clusterroles",
				Name:     "dangerous-role",
			},
		},
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Fatal("expected cluster-scoped SAR to NOT be allowed")
	}
	if resp.Status.Denied {
		t.Fatal("expected Denied=false, scoped authorizer should skip cluster-scoped SAR")
	}
	if strings.Contains(resp.Status.Reason, "WebhookAuthorizer") {
		t.Fatalf("expected fallback reason without authorizer details, got %q", resp.Status.Reason)
	}
}

func TestAuditLog_DenyDecisionAtV0(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{{User: "baduser"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	cl := newIndexedClient(scheme, &wa)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "baduser",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}

	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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

	handler0 := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger0}
	req0 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler1 := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger1}
	body = marshalSAR(t, sar)
	req1 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler0 := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger0}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "unknown",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler1 := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger1}
	body = marshalSAR(t, sar)
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "tracer",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Namespace: "default"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:                  "admin",
			NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/healthz"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

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
		res, err := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if err != nil {
			t.Fatalf("evaluateSAR returned unexpected error: %v", err)
		}
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
		res, err := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if err != nil {
			t.Fatalf("evaluateSAR returned unexpected error: %v", err)
		}
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

	t.Run("denied principal without matching rule is no-opinion", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "bob",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "configmaps"},
			},
		}
		res, err := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if err != nil {
			t.Fatalf("evaluateSAR returned unexpected error: %v", err)
		}
		if res.allowed {
			t.Fatal("expected no-opinion")
		}
		if res.decision != pkgmetrics.AuthorizerDecisionNoOpinion {
			t.Errorf("expected decision=no-opinion, got %s", res.decision)
		}
		if res.matchedRule != -1 {
			t.Errorf("expected matchedRule=-1, got %d", res.matchedRule)
		}
	})

	t.Run("no-opinion when no authorizer matches", func(t *testing.T) {
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:               "charlie",
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
			},
		}
		res, err := handler.evaluateSAR(context.Background(), sar, waList.Items)
		if err != nil {
			t.Fatalf("evaluateSAR returned unexpected error: %v", err)
		}
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

func TestEvaluateSAR_NamespaceGetError(t *testing.T) {
	// Build a scheme with Kubernetes built-in types so the fake client
	// recognises Namespace resources and returns a proper NotFound error.
	s := newSchemeWithCore(t)

	// WebhookAuthorizer with a NamespaceSelector so evaluateSAR will call
	// namespaceMatches, which in turn calls Client.Get for the namespace.
	wa := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}

	// The fake client does NOT have the namespace "missing-ns" — Get will return NotFound.
	cl := newIndexedClient(s, wa)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      "get",
				Resource:  "pods",
				Namespace: "missing-ns",
			},
		},
	}

	_, err := handler.evaluateSAR(context.Background(), sar, []authzv1alpha1.WebhookAuthorizer{*wa})
	if err == nil {
		t.Fatal("expected error from namespace Get failure, got nil")
	}
}

// TestServeHTTP_NamespaceGetError_ReturnsDeniedSAR verifies that when
// evaluateSAR returns an error (e.g. namespace Get fails), ServeHTTP responds
// with a valid denied SAR so the authorization webhook fails closed.
func TestServeHTTP_NamespaceGetError_ReturnsDeniedSAR(t *testing.T) {
	// Build a scheme with Kubernetes built-in types so the fake client
	// recognises Namespace resources and returns a proper NotFound error.
	s := newSchemeWithCore(t)

	// WebhookAuthorizer with a NamespaceSelector so it becomes a scoped authorizer.
	// evaluateSAR will call namespaceMatches, which calls Client.Get for the namespace.
	wa := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa-500"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}

	// Use an indexed client (matching real manager setup) with the WA but without
	// the "missing-ns" Namespace object — Get will return NotFound.
	cl := newIndexedClient(s, wa)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      "get",
				Resource:  "pods",
				Namespace: "missing-ns",
			},
		},
	}

	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 denied SAR when namespace Get fails, got %d", rec.Code)
	}
	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Status.Denied {
		t.Fatal("expected Denied=true for internal namespace lookup failure")
	}
	if resp.Status.Reason != "internal evaluation error" {
		t.Fatalf("expected generic internal evaluation reason, got %q", resp.Status.Reason)
	}
}

func TestServeHTTP_OversizedBody(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	cl := newIndexedClient(scheme)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	// Create a body larger than 1MB
	oversizedBody := make([]byte, 1<<20+1)
	for i := range oversizedBody {
		oversizedBody[i] = 'A'
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(oversizedBody))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for oversized body")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for oversized body")
	}
	if !strings.Contains(resp.Status.Reason, "invalid request body") {
		t.Errorf("expected reason to contain 'invalid request body', got %q", resp.Status.Reason)
	}
}

func TestServeHTTP_InvalidJSON(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)

	cl := newIndexedClient(scheme)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", strings.NewReader("{invalid json"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for invalid JSON")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for invalid JSON")
	}
	// Verify the reason does NOT leak internal JSON parse details
	if strings.Contains(resp.Status.Reason, "json") || strings.Contains(resp.Status.Reason, "invalid character") {
		t.Errorf("response reason leaks internal details: %q", resp.Status.Reason)
	}
	if !strings.Contains(resp.Status.Reason, "invalid request body") {
		t.Errorf("expected reason to contain 'invalid request body', got %q", resp.Status.Reason)
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
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"delete"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}},
			},
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}
	denySAR := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "blocked",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, denySAR)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	req = httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader([]byte("not-json")))
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

func TestMetrics_ActiveRulesCountsMixedGlobalAndScopedAuthorizers(t *testing.T) {
	scheme := newScheme(t)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{"team": "alpha"},
		},
	}
	global := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "z-global"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	scoped := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "a-scoped"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"team": "alpha"}},
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
				{Verbs: []string{"watch"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        newIndexedClient(scheme, ns, &global, &scoped),
		Log:                           logr.Discard(),
	}

	pkgmetrics.AuthorizerActiveRules.Set(0)
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "team-a",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	activeRules := testutil.ToFloat64(pkgmetrics.AuthorizerActiveRules)
	if activeRules != 3 {
		t.Fatalf("expected AuthorizerActiveRules=3, got %v", activeRules)
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
		AllowUnauthenticatedAuthorize: true,
		Client:                        cl,
		Log:                           logger,
		Limiter:                       rate.NewLimiter(rate.Limit(0), 1), // 0 rps, burst 1
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
	initialDeniedCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionDenied, pkgmetrics.AuthorizerNameNone))

	// First request should succeed (uses the burst token).
	req1 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Errorf("expected first request to succeed with status %d, got %d", http.StatusOK, rec1.Code)
	}

	// Second request should be rate limited (no tokens left, 0 rps).
	// Per the Kubernetes authorization webhook protocol, the response is HTTP 200
	// with Allowed=false (non-200 would be treated as a webhook failure).
	req2 := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
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
	afterDeniedCount := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionDenied, pkgmetrics.AuthorizerNameNone))
	if afterDeniedCount-initialDeniedCount < 1 {
		t.Errorf("AuthorizerRequestsTotal denied metric did not increment: before=%v, after=%v", initialDeniedCount, afterDeniedCount)
	}
}

func TestServeHTTP_BearerTokenRequiredBeforeRateLimit(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        cl,
		Log:                           logr.Discard(),
		BearerToken:                   "shared-token",
		Limiter:                       rate.NewLimiter(rate.Limit(0), 1),
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
	assertUnauthorizedDeny := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("expected %s to return %d with a denied SubjectAccessReview, got %d", name, http.StatusOK, rec.Code)
		}
		var response authzv1.SubjectAccessReview
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fatalf("decode %s response: %v", name, err)
		}
		if response.Status.Allowed {
			t.Fatalf("%s response should have Allowed=false", name)
		}
		if !response.Status.Denied {
			t.Fatalf("%s response should have Denied=true", name)
		}
		if response.Status.Reason != reasonUnauthorized {
			t.Fatalf("expected %s reason %q, got %q", name, reasonUnauthorized, response.Status.Reason)
		}
	}

	unauthorizedReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	unauthorizedRec := httptest.NewRecorder()
	handler.ServeHTTP(unauthorizedRec, unauthorizedReq)
	assertUnauthorizedDeny("missing bearer token", unauthorizedRec)

	wrongTokenReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	wrongTokenReq.Header.Set("Authorization", "Bearer wrong-token")
	wrongTokenRec := httptest.NewRecorder()
	handler.ServeHTTP(wrongTokenRec, wrongTokenReq)
	assertUnauthorizedDeny("wrong bearer token", wrongTokenRec)

	authorizedReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	authorizedReq.Header.Set("Authorization", "Bearer shared-token")
	authorizedRec := httptest.NewRecorder()
	handler.ServeHTTP(authorizedRec, authorizedReq)
	if authorizedRec.Code != http.StatusOK {
		t.Fatalf("expected valid bearer token to return %d, got %d", http.StatusOK, authorizedRec.Code)
	}
	var firstResponse authzv1.SubjectAccessReview
	if err := json.NewDecoder(authorizedRec.Body).Decode(&firstResponse); err != nil {
		t.Fatalf("decode authorized response: %v", err)
	}
	if firstResponse.Status.Reason == "rate limit exceeded" {
		t.Fatal("unauthorized requests consumed the subject rate-limit bucket")
	}

	rateLimitedReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rateLimitedReq.Header.Set("Authorization", "Bearer shared-token")
	rateLimitedRec := httptest.NewRecorder()
	handler.ServeHTTP(rateLimitedRec, rateLimitedReq)
	var secondResponse authzv1.SubjectAccessReview
	if err := json.NewDecoder(rateLimitedRec.Body).Decode(&secondResponse); err != nil {
		t.Fatalf("decode rate-limited response: %v", err)
	}
	if secondResponse.Status.Reason != "rate limit exceeded" {
		t.Fatalf("expected second authenticated request to be rate-limited, got reason %q", secondResponse.Status.Reason)
	}
}

func TestAuthenticateRequest_DeniesEmptyExpectedTokenByDefault(t *testing.T) {
	handler := &Authorizer{
		Log: logr.Discard(),
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	rec := httptest.NewRecorder()
	if handler.authenticateRequest(rec, req) {
		t.Fatal("request should not authenticate when no bearer token is configured")
	}
	assertUnauthorizedSARResponse(t, rec)
}

func TestAuthenticateRequest_AllowsEmptyExpectedTokenWithExplicitOptOut(t *testing.T) {
	handler := &Authorizer{
		Log:                           logr.Discard(),
		AllowUnauthenticatedAuthorize: true,
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	if !handler.authenticateRequest(httptest.NewRecorder(), req) {
		t.Fatal("request should authenticate when unauthenticated authorize is explicitly allowed")
	}
}

func TestAuthenticateRequest_AcceptsConfiguredBearerToken(t *testing.T) {
	handler := &Authorizer{
		Log:         logr.Discard(),
		BearerToken: "shared-token",
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	req.Header.Set("Authorization", "Bearer shared-token")
	if !handler.authenticateRequest(httptest.NewRecorder(), req) {
		t.Fatal("request should authenticate with the configured bearer token")
	}
}

func assertUnauthorizedSARResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected denied SAR response to return %d, got %d", http.StatusOK, rec.Code)
	}
	var response authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode denied response: %v", err)
	}
	if response.Status.Allowed {
		t.Fatal("response should have Allowed=false")
	}
	if !response.Status.Denied {
		t.Fatal("response should have Denied=true")
	}
	if response.Status.Reason != reasonUnauthorized {
		t.Fatalf("expected reason %q, got %q", reasonUnauthorized, response.Status.Reason)
	}
}

func TestAuthenticateRequest_ReloadsBearerTokenFile(t *testing.T) {
	tokenFile := t.TempDir() + "/authorize-token"
	if err := os.WriteFile(tokenFile, []byte("old-token\n"), 0o600); err != nil {
		t.Fatalf("write old token: %v", err)
	}

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Log:                           logr.Discard(),
		BearerTokenFile:               tokenFile,
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	req.Header.Set("Authorization", "Bearer old-token")
	if !handler.authenticateRequest(httptest.NewRecorder(), req) {
		t.Fatal("old token should authenticate before rotation")
	}

	if err := os.WriteFile(tokenFile, []byte("new-token\n"), 0o600); err != nil {
		t.Fatalf("write new token: %v", err)
	}

	staleReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	staleReq.Header.Set("Authorization", "Bearer old-token")
	staleRec := httptest.NewRecorder()
	if handler.authenticateRequest(staleRec, staleReq) {
		t.Fatal("old token should be rejected after rotation")
	}
	var staleResponse authzv1.SubjectAccessReview
	if err := json.NewDecoder(staleRec.Body).Decode(&staleResponse); err != nil {
		t.Fatalf("decode stale-token response: %v", err)
	}
	if staleResponse.Status.Reason != reasonUnauthorized {
		t.Fatalf("expected stale-token reason %q, got %q", reasonUnauthorized, staleResponse.Status.Reason)
	}

	rotatedReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
	rotatedReq.Header.Set("Authorization", "Bearer new-token")
	if !handler.authenticateRequest(httptest.NewRecorder(), rotatedReq) {
		t.Fatal("new token should authenticate after rotation")
	}
}

func TestAuthenticateRequest_DeniesWhenBearerTokenFileUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) string
	}{
		{
			name: "missing file",
			setup: func(t *testing.T) string {
				t.Helper()
				return t.TempDir() + "/missing-token"
			},
		},
		{
			name: "empty file",
			setup: func(t *testing.T) string {
				t.Helper()
				tokenFile := t.TempDir() + "/empty-token"
				if err := os.WriteFile(tokenFile, []byte(" \n\t"), 0o600); err != nil {
					t.Fatalf("write empty token: %v", err)
				}
				return tokenFile
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenFile := tc.setup(t)
			handler := &Authorizer{
				AllowUnauthenticatedAuthorize: true,
				Log:                           logr.Discard(),
				BearerTokenFile:               tokenFile,
			}

			if _, err := handler.expectedBearerToken(); err == nil {
				t.Fatal("expected token file load to fail")
			} else if !strings.Contains(err.Error(), tokenFile) {
				t.Fatalf("expected error %q to include token file %q", err.Error(), tokenFile)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", nil)
			req.Header.Set("Authorization", "Bearer any-token")
			rec := httptest.NewRecorder()
			if handler.authenticateRequest(rec, req) {
				t.Fatal("request should not authenticate when token file cannot be loaded")
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("expected denied SAR response to return %d, got %d", http.StatusOK, rec.Code)
			}
			var response authzv1.SubjectAccessReview
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("decode denied response: %v", err)
			}
			if response.Status.Allowed {
				t.Fatal("response should have Allowed=false")
			}
			if !response.Status.Denied {
				t.Fatal("response should have Denied=true")
			}
			if response.Status.Reason != reasonUnauthorized {
				t.Fatalf("expected reason %q, got %q", reasonUnauthorized, response.Status.Reason)
			}
		})
	}
}

func TestServeHTTP_RateLimitingIsPerSubject(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        cl,
		Log:                           logr.Discard(),
		Limiter:                       rate.NewLimiter(rate.Limit(0), 1),
	}

	sarFor := func(user string, groups ...string) []byte {
		return marshalSAR(t, authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User:   user,
				Groups: groups,
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb:     "get",
					Resource: "pods",
				},
			},
		})
	}
	request := func(body []byte) authzv1.SubjectAccessReview {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
		}
		var resp authzv1.SubjectAccessReview
		if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		return resp
	}

	request(sarFor("alice", "team-a", "system:authenticated"))
	reorderedGroupResponse := request(sarFor("alice", "system:authenticated", "team-a"))
	if reorderedGroupResponse.Status.Reason != "rate limit exceeded" {
		t.Fatalf("expected same user with reordered groups to share a rate-limit bucket, got reason %q", reorderedGroupResponse.Status.Reason)
	}
	duplicateGroupResponse := request(sarFor("alice", "team-a", "team-a", "system:authenticated"))
	if duplicateGroupResponse.Status.Reason != "rate limit exceeded" {
		t.Fatalf("expected duplicate groups to share a rate-limit bucket, got reason %q", duplicateGroupResponse.Status.Reason)
	}
	differentGroupResponse := request(sarFor("alice", "team-b", "system:authenticated"))
	if differentGroupResponse.Status.Reason == "rate limit exceeded" {
		t.Fatal("expected same user with different groups to use an independent rate-limit bucket")
	}
	bobResponse := request(sarFor("bob", "team-a", "system:authenticated"))
	if bobResponse.Status.Reason == "rate limit exceeded" {
		t.Fatal("expected bob to use an independent rate-limit bucket")
	}
}

func TestSubjectLimiterCacheIsBounded(t *testing.T) {
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Log:                           logr.Discard(),
		Limiter:                       rate.NewLimiter(rate.Limit(1), 1),
		subjectLimiters:               make(map[string]*subjectLimiterEntry, maxSubjectLimiters),
		subjectLimiterCleanupAt:       time.Now().Add(time.Hour),
	}
	for i := range maxSubjectLimiters {
		handler.subjectLimiters[rateLimitSubjectKey(&authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "user-" + strconv.Itoa(i)}})] = &subjectLimiterEntry{
			limiter:  rate.NewLimiter(rate.Limit(1), 1),
			lastSeen: time.Unix(int64(i), 0),
		}
	}

	handler.subjectLimiter("new-user")
	if len(handler.subjectLimiters) != maxSubjectLimiters {
		t.Fatalf("expected limiter cache size %d, got %d", maxSubjectLimiters, len(handler.subjectLimiters))
	}
	if _, exists := handler.subjectLimiters[rateLimitSubjectKey(&authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "user-0"}})]; exists {
		t.Fatal("expected oldest limiter entry to be evicted")
	}
	if _, exists := handler.subjectLimiters["new-user"]; !exists {
		t.Fatal("expected new limiter entry to be present")
	}
}

func TestServeHTTP_NoRateLimiter(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 0)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	// No Limiter set — rate limiting should be disabled.
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        cl,
		Log:                           logger,
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
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status %d, got %d", i, http.StatusOK, rec.Code)
		}
	}
}

func TestServeHTTP_RejectsEmptyIdentity(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 1)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}

	beforeReqs := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionDenied, pkgmetrics.AuthorizerNameNone))

	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for empty identity")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for empty identity")
	}
	if resp.Status.Reason != reasonEmptyIdentity {
		t.Errorf("unexpected reason: %s", resp.Status.Reason)
	}
	if !strings.Contains(buf.String(), "rejecting malformed SubjectAccessReview") {
		t.Errorf("expected rejection log entry, got:\n%s", buf.String())
	}

	afterReqs := testutil.ToFloat64(pkgmetrics.AuthorizerRequestsTotal.WithLabelValues(
		pkgmetrics.AuthorizerDecisionDenied, pkgmetrics.AuthorizerNameNone))
	if afterReqs-beforeReqs < 1 {
		t.Error("expected denied metrics to be recorded for empty identity rejection")
	}
}

func TestServeHTTP_AcceptsEmptyUserWithGroups(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "",
			Groups:             []string{"system:masters"},
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for SAR with empty user but valid groups")
	}
	if resp.Status.Denied {
		t.Error("expected Denied=false (no-opinion) for SAR with empty user but valid groups")
	}
}

func TestServeHTTP_RejectsNoAttributes(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 1)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "some-user",
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for SAR with no attributes")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for SAR with no attributes")
	}
	if !strings.Contains(resp.Status.Reason, reasonMissingAttrs) {
		t.Errorf("expected reason about missing attributes, got: %s", resp.Status.Reason)
	}
	if !strings.Contains(buf.String(), "rejecting malformed SubjectAccessReview") {
		t.Errorf("expected rejection log entry, got:\n%s", buf.String())
	}
}

func TestServeHTTP_RejectsBothResourceAndNonResourceAttributes(t *testing.T) {
	var buf strings.Builder
	logger := capturingLogger(&buf, 1)
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logger}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:                  "some-user",
			ResourceAttributes:    &authzv1.ResourceAttributes{Verb: "delete", Resource: "secrets"},
			NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/healthz"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for SAR with both resource and non-resource attributes")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for SAR with both resource and non-resource attributes")
	}
	if resp.Status.Reason != reasonMultipleAttrs {
		t.Errorf("expected reason %q, got: %s", reasonMultipleAttrs, resp.Status.Reason)
	}
	if !strings.Contains(buf.String(), "rejecting malformed SubjectAccessReview") {
		t.Errorf("expected rejection log entry, got:\n%s", buf.String())
	}
}

func TestServeHTTP_AcceptsNonResourceAttributes(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:                  "some-user",
			NonResourceAttributes: &authzv1.NonResourceAttributes{Verb: "get", Path: "/healthz"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Reason == reasonMissingAttrs ||
		resp.Status.Reason == reasonEmptyIdentity {
		t.Errorf("non-resource SAR should not be rejected by validation, but got reason: %s", resp.Status.Reason)
	}
}

func TestServeHTTP_UsesSingleEvaluationDeadline(t *testing.T) {
	scheme := newScheme(t)
	wa := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}},
			AllowedPrincipals: []authzv1alpha1.Principal{
				{User: "alice"},
			},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{"team": "a"},
		},
	}
	var deadlines []time.Time
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithIndex(&authzv1alpha1.WebhookAuthorizer{}, indexer.WebhookAuthorizerHasNamespaceSelectorField, indexer.WebhookAuthorizerHasNamespaceSelectorFunc).
		WithObjects(wa, ns).
		WithInterceptorFuncs(interceptor.Funcs{
			List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*authzv1alpha1.WebhookAuthorizerList); ok {
					if deadline, ok := ctx.Deadline(); ok {
						deadlines = append(deadlines, deadline)
					}
					time.Sleep(25 * time.Millisecond)
				}
				return c.List(ctx, list, opts...)
			},
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok && key.Name == "team-a" {
					if deadline, ok := ctx.Deadline(); ok {
						deadlines = append(deadlines, deadline)
					}
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:      "get",
				Resource:  "pods",
				Namespace: "team-a",
			},
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}
	if len(deadlines) < 2 {
		t.Fatalf("expected authorizer list and namespace get deadlines, got %d", len(deadlines))
	}
	for i := 1; i < len(deadlines); i++ {
		diff := deadlines[i].Sub(deadlines[0])
		if diff < 0 {
			diff = -diff
		}
		if diff > 10*time.Millisecond {
			t.Fatalf("expected all external calls to share an evaluation deadline, got difference %s at index %d", diff, i)
		}
	}
}

func TestServeHTTP_DeniedResponseSetsDeniedTrue(t *testing.T) {
	scheme := newScheme(t)

	wa := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-uid-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			DeniedPrincipals: []authzv1alpha1.Principal{{User: "blocked-user"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	cl := newIndexedClient(scheme, &wa)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "blocked-user",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for denied request")
	}
	// Per K8s SAR semantics: Allowed=false without Denied=true means
	// "no opinion" — subsequent authorizers could still allow the request.
	// A genuine deny MUST set Denied=true.
	if !resp.Status.Denied {
		t.Error("expected Denied=true for explicit deny decision; without it, subsequent authorizers can override the denial")
	}
}

func TestServeHTTP_NoOpinionResponseDoesNotSetDeniedTrue(t *testing.T) {
	// No-opinion (no authorizer matched) must NOT set Denied=true, otherwise
	// Kubernetes would treat it as a hard deny instead of passing through to
	// the next authorizer.
	scheme := newScheme(t)
	cl := newIndexedClient(scheme) // no authorizers
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "unknown-user",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for no-opinion")
	}
	if resp.Status.Denied {
		t.Error("expected Denied=false for no-opinion; Denied=true would prevent fallthrough to next authorizer")
	}
}

func TestServeHTTP_RateLimitResponseSetsDeniedTrue(t *testing.T) {
	scheme := newScheme(t)
	cl := newIndexedClient(scheme)

	// Limiter with burst=0: every request is rate-limited.
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        cl,
		Log:                           logr.Discard(),
		Limiter:                       rate.NewLimiter(rate.Limit(0), 0),
	}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User:               "rate-limited-user",
			ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods"},
		},
	}
	body := marshalSAR(t, sar)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode rate-limit response: %v", err)
	}
	if resp.Status.Allowed {
		t.Error("expected Allowed=false for rate-limited request")
	}
	if !resp.Status.Denied {
		t.Error("expected Denied=true for rate-limited request; without it, subsequent authorizers could allow the request")
	}
}

func TestPrincipalMatches_ServiceAccountNamespaceScope(t *testing.T) {
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Log: logr.Discard()}

	tests := []struct {
		name       string
		user       string
		groups     []string
		principals []authzv1alpha1.Principal
		want       bool
	}{
		{
			name:       "namespaced service account matches same namespace and name",
			user:       "system:serviceaccount:team-a:deployer",
			principals: []authzv1alpha1.Principal{{User: "deployer", Namespace: "team-a"}},
			want:       true,
		},
		{
			name:       "namespaced service account matches fully qualified principal",
			user:       "system:serviceaccount:team-a:deployer",
			principals: []authzv1alpha1.Principal{{User: "system:serviceaccount:team-a:deployer", Namespace: "team-a"}},
			want:       true,
		},
		{
			name:       "namespaced service account rejects fully qualified principal from different namespace",
			user:       "system:serviceaccount:team-a:deployer",
			principals: []authzv1alpha1.Principal{{User: "system:serviceaccount:team-b:deployer", Namespace: "team-b"}},
			want:       false,
		},
		{
			name:       "namespaced service account rejects same name in different namespace",
			user:       "system:serviceaccount:team-b:deployer",
			principals: []authzv1alpha1.Principal{{User: "deployer", Namespace: "team-a"}},
			want:       false,
		},
		{
			name:       "namespaced principal does not match plain user",
			user:       "deployer",
			principals: []authzv1alpha1.Principal{{User: "deployer", Namespace: "team-a"}},
			want:       false,
		},
		{
			name:       "namespaced principal does not match groups",
			user:       "alice",
			groups:     []string{"deployer"},
			principals: []authzv1alpha1.Principal{{Groups: []string{"deployer"}, Namespace: "team-a"}},
			want:       false,
		},
		{
			name:       "plain user still matches without namespace",
			user:       "deployer",
			principals: []authzv1alpha1.Principal{{User: "deployer"}},
			want:       true,
		},
		{
			name:       "plain group still matches without namespace",
			user:       "alice",
			groups:     []string{"deployer"},
			principals: []authzv1alpha1.Principal{{Groups: []string{"deployer"}}},
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := handler.principalMatches(tt.user, tt.groups, tt.principals); got != tt.want {
				t.Fatalf("principalMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestResourceRuleIndex_SubresourceMatching(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	rules := []authzv1.ResourceRule{
		// Rule 0: allows "pods" but NOT "pods/log"
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		// Rule 1: explicitly allows "pods/log"
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/log"}},
	}

	t.Run("pods request matches pods rule", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx != 0 {
			t.Errorf("expected rule index 0 for pods, got %d", idx)
		}
	})

	t.Run("pods/log subresource matches pods/log rule not pods rule", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Subresource: "log"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx != 1 {
			t.Errorf("expected rule index 1 for pods/log subresource, got %d (a pods-only rule must NOT match pods/log)", idx)
		}
	})

	t.Run("pods/exec subresource not matched by any rule", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Subresource: "exec"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx >= 0 {
			t.Errorf("expected no match for pods/exec subresource, got rule index %d", idx)
		}
	})
}

func TestResourceRuleIndex_ResourceNamesMatching(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	rules := []authzv1.ResourceRule{
		// Rule 0: allows only specific-pod by name
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"specific-pod"}},
		// Rule 1: allows all pods (no ResourceNames restriction)
		{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
	}

	t.Run("named pod matches rule with matching ResourceName", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Name: "specific-pod"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx != 0 {
			t.Errorf("expected rule index 0 for specific-pod, got %d", idx)
		}
	})

	t.Run("different pod name does not match ResourceNames-restricted rule", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Name: "other-pod"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx >= 0 {
			t.Errorf("expected no match for other-pod when rule restricts ResourceNames, got rule index %d", idx)
		}
	})

	t.Run("list with no name restriction matches rule without ResourceNames", func(t *testing.T) {
		attr := &authzv1.ResourceAttributes{Verb: "list", Group: "", Resource: "pods"}
		idx := handler.resourceRuleIndex(rules, attr)
		if idx != 1 {
			t.Errorf("expected rule index 1 for list pods, got %d", idx)
		}
	})

	t.Run("wildcard ResourceName matches any request name", func(t *testing.T) {
		wildcardRules := []authzv1.ResourceRule{
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"*"}},
		}
		attr := &authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Name: "any-pod"}
		idx := handler.resourceRuleIndex(wildcardRules, attr)
		if idx != 0 {
			t.Errorf("expected rule index 0 for wildcard ResourceNames, got %d", idx)
		}
	})
}

func TestResourceRuleIndex_KubernetesWildcardSemantics(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	tests := []struct {
		name string
		rule authzv1.ResourceRule
		attr authzv1.ResourceAttributes
		want bool
	}{
		{
			name: "resource prefix wildcard is not supported",
			rule: authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pod*"}},
			attr: authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
		},
		{
			name: "all resources subresource wildcard matches requested subresource",
			rule: authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"*/log"}},
			attr: authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods", Subresource: "log"},
			want: true,
		},
		{
			name: "api group prefix wildcard is not supported",
			rule: authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{"apps*"}, Resources: []string{"deployments"}},
			attr: authzv1.ResourceAttributes{Verb: "get", Group: "apps.example.com", Resource: "deployments"},
		},
		{
			name: "resource name prefix wildcard is not supported",
			rule: authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"prod-*"}},
			attr: authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "secrets", Name: "prod-secret"},
		},
		{
			name: "verb prefix wildcard is not supported",
			rule: authzv1.ResourceRule{Verbs: []string{"get*"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			attr: authzv1.ResourceAttributes{Verb: "get", Group: "", Resource: "pods"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := handler.resourceRuleIndex([]authzv1.ResourceRule{tt.rule}, &tt.attr)
			got := idx >= 0
			if got != tt.want {
				t.Fatalf("resourceRuleIndex() matched = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNonResourceRuleIndex_SuffixWildcardMatching(t *testing.T) {
	scheme := newScheme(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	rules := []authzv1.NonResourceRule{
		{Verbs: []string{"get"}, NonResourceURLs: []string{"/api/*"}},
	}

	t.Run("suffix wildcard matches child path", func(t *testing.T) {
		attr := &authzv1.NonResourceAttributes{Verb: "get", Path: "/api/v1"}
		idx := handler.nonResourceRuleIndex(rules, attr)
		if idx != 0 {
			t.Errorf("expected rule index 0 for /api/*, got %d", idx)
		}
	})

	t.Run("suffix wildcard does not match unrelated path", func(t *testing.T) {
		attr := &authzv1.NonResourceAttributes{Verb: "get", Path: "/apis/v1"}
		idx := handler.nonResourceRuleIndex(rules, attr)
		if idx >= 0 {
			t.Errorf("expected no match for unrelated path, got rule index %d", idx)
		}
	})

	t.Run("non-terminal wildcard does not match child path", func(t *testing.T) {
		prefixRules := []authzv1.NonResourceRule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{"/api*"}},
		}
		attr := &authzv1.NonResourceAttributes{Verb: "get", Path: "/api/v1"}
		idx := handler.nonResourceRuleIndex(prefixRules, attr)
		if idx >= 0 {
			t.Errorf("expected no match for unsupported /api* wildcard, got rule index %d", idx)
		}
	})

	t.Run("non-terminal wildcard does not match sibling path", func(t *testing.T) {
		prefixRules := []authzv1.NonResourceRule{
			{Verbs: []string{"get"}, NonResourceURLs: []string{"/api*"}},
		}
		attr := &authzv1.NonResourceAttributes{Verb: "get", Path: "/apis"}
		idx := handler.nonResourceRuleIndex(prefixRules, attr)
		if idx >= 0 {
			t.Errorf("expected no match for unsupported /api* wildcard, got rule index %d", idx)
		}
	})
}

func TestEvaluateSAR_NamespaceLabelCache_SingleGetPerNamespace(t *testing.T) {
	scheme := newScheme(t)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "target-ns",
			Labels: map[string]string{"env": "prod"},
		},
	}

	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"env": "prod"},
	}

	wa1 := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa-1"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: selector,
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	wa2 := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa-2"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: selector,
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "bob"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	wa3 := authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa-3"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: selector,
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "carol"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"delete"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}

	t.Run("single Get per namespace when namespace exists", func(t *testing.T) {
		base := newIndexedClient(scheme, ns, &wa1, &wa2, &wa3)

		counter := &namespaceGetCountingClient{Client: base}
		handler := &Authorizer{
			AllowUnauthenticatedAuthorize: true, Client: counter, Log: logr.Discard()}

		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				User: "unknown",
				ResourceAttributes: &authzv1.ResourceAttributes{
					Namespace: "target-ns",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		}

		if _, err := handler.evaluateSAR(context.Background(), sar, []authzv1alpha1.WebhookAuthorizer{wa1, wa2, wa3}); err != nil {
			t.Fatalf("evaluateSAR returned unexpected error: %v", err)
		}

		if got := counter.getCount.Load(); got != 1 {
			t.Errorf("expected exactly 1 namespace Get() for 3 authorizers targeting the same namespace, got %d", got)
		}
	})

	t.Run("single Get per namespace when namespace is missing", func(t *testing.T) {
		base := newIndexedClient(scheme)

		counter := &namespaceGetCountingClient{Client: base}
		handler := &Authorizer{
			AllowUnauthenticatedAuthorize: true, Client: counter, Log: logr.Discard()}

		cache := make(map[string]namespaceLabelCacheEntry)
		selector := &wa1.Spec.NamespaceSelector
		for range 2 {
			matches, err := handler.namespaceMatches(context.Background(), "missing-ns", selector, cache)
			if err == nil {
				t.Fatal("expected namespace lookup error, got nil")
			}
			if matches {
				t.Fatal("namespaceMatches returned true for missing namespace")
			}
		}

		if got := counter.getCount.Load(); got != 1 {
			t.Errorf("expected exactly 1 namespace Get() for repeated missing namespace lookup, got %d", got)
		}
	})
}

func TestServeHTTP_NamespaceLabelCacheError_ReturnsDeniedSAR(t *testing.T) {
	scheme := newScheme(t)

	wa := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped-wa"},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	cl := newIndexedClient(scheme, wa)
	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true, Client: cl, Log: logr.Discard()}

	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "missing-ns",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body, err := json.Marshal(sar)
	if err != nil {
		t.Fatalf("failed to marshal SAR: %v", err)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Status.Denied {
		t.Fatal("expected Denied=true for namespace label cache error")
	}
	if resp.Status.Reason != "internal evaluation error" {
		t.Fatalf("expected generic internal evaluation reason, got %q", resp.Status.Reason)
	}
}

func TestServeHTTP_SkipsUnconfiguredAuthorizers(t *testing.T) {
	scheme := newScheme(t)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "team-a",
			Labels: map[string]string{"env": "prod"},
		},
	}
	stalled := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "aaa-stalled", Generation: 1},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "env",
					Operator: metav1.LabelSelectorOpIn,
				}},
			},
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	conditions.MarkStalled(stalled, stalled.Generation,
		authzv1alpha1.StalledReasonError, authzv1alpha1.StalledMessageError)
	stalled.Status.ObservedGeneration = stalled.Generation
	stalled.Status.AuthorizerConfigured = false

	configured := &authzv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "zzz-configured", Generation: 1},
		Spec: authzv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			AllowedPrincipals: []authzv1alpha1.Principal{{User: "alice"}},
			ResourceRules: []authzv1.ResourceRule{
				{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
			},
		},
	}
	conditions.MarkReady(configured, configured.Generation,
		authzv1alpha1.ReadyReasonReconciled, authzv1alpha1.ReadyMessageReconciled)
	configured.Status.ObservedGeneration = configured.Generation
	configured.Status.AuthorizerConfigured = true

	handler := &Authorizer{
		AllowUnauthenticatedAuthorize: true,
		Client:                        newIndexedClient(scheme, ns, stalled, configured),
		Log:                           logr.Discard(),
	}

	pkgmetrics.AuthorizerActiveRules.Set(0)
	sar := authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "alice",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: "team-a",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d; body: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !resp.Status.Allowed {
		t.Fatalf("expected request to be allowed by configured authorizer, got %+v", resp.Status)
	}
	if resp.Status.Reason != "Access granted by WebhookAuthorizer" {
		t.Fatalf("expected public allow reason, got %q", resp.Status.Reason)
	}
	if activeRules := testutil.ToFloat64(pkgmetrics.AuthorizerActiveRules); activeRules != 1 {
		t.Fatalf("expected AuthorizerActiveRules to count only configured rules, got %v", activeRules)
	}
}

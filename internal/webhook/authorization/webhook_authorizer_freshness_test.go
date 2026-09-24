// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func TestWebhookAuthorizerLiveRevocationWithCachedIndex(t *testing.T) {
	rule := authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}
	cached := &authz.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "scoped"},
		Spec: authz.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			AllowedPrincipals: []authz.Principal{{User: "alice"}},
			ResourceRules:     []authzv1.ResourceRule{rule},
		},
	}
	sar := authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "pods", Namespace: "team-a"},
	}}
	for _, tc := range []struct {
		name       string
		changeWA   func(*authz.WebhookAuthorizer)
		liveLabels map[string]string
		deleted    bool
		allowed    bool
		denied     bool
	}{
		{name: "live allow", allowed: true},
		{name: "live rule removed", changeWA: func(wa *authz.WebhookAuthorizer) { wa.Spec.ResourceRules = nil }},
		{name: "live principal revoked", changeWA: func(wa *authz.WebhookAuthorizer) { wa.Spec.AllowedPrincipals = nil }},
		{name: "live deny added", changeWA: func(wa *authz.WebhookAuthorizer) {
			wa.Spec.DeniedPrincipals = []authz.Principal{{User: "alice"}}
		}, denied: true},
		{name: "live namespace label changed", liveLabels: map[string]string{"env": "dev"}},
		{name: "live authorizer deleted", deleted: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := newScheme(t)
			cachedClient := newIndexedClient(scheme, cached.DeepCopy(),
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"env": "prod"}}})
			liveObjects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
				Name: "team-a", Labels: map[string]string{"env": "prod"},
			}}}
			if tc.liveLabels != nil {
				liveObjects[0].(*corev1.Namespace).Labels = tc.liveLabels
			}
			if !tc.deleted {
				liveWA := cached.DeepCopy()
				if tc.changeWA != nil {
					tc.changeWA(liveWA)
				}
				liveObjects = append(liveObjects, liveWA)
			}
			live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(liveObjects...).Build()
			handler := &Authorizer{
				Client: cachedClient, LiveReader: live, Log: logr.Discard(), AllowUnauthenticatedAuthorize: true,
			}
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("unexpected HTTP %d: %s", rec.Code, rec.Body.String())
			}
			var resp authzv1.SubjectAccessReview
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if resp.Status.Allowed != tc.allowed || resp.Status.Denied != tc.denied {
				t.Fatalf("authorization status = %+v, want allowed=%v denied=%v", resp.Status, tc.allowed, tc.denied)
			}
		})
	}
}

func TestWebhookAuthorizerLiveGlobalDenyCachedAsScoped(t *testing.T) {
	scheme := newScheme(t)
	rule := authzv1.ResourceRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"nodes"}}
	cached := &authz.WebhookAuthorizer{ObjectMeta: metav1.ObjectMeta{Name: "formerly-scoped"}, Spec: authz.WebhookAuthorizerSpec{
		NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		ResourceRules:     []authzv1.ResourceRule{rule},
	}}
	live := cached.DeepCopy()
	live.Spec.NamespaceSelector = metav1.LabelSelector{}
	live.Spec.DeniedPrincipals = []authz.Principal{{User: "alice"}}
	handler := &Authorizer{
		Client:     newIndexedClient(scheme, cached),
		LiveReader: fake.NewClientBuilder().WithScheme(scheme).WithObjects(live).Build(),
		Log:        logr.Discard(), AllowUnauthenticatedAuthorize: true,
	}
	sar := authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", ResourceAttributes: &authzv1.ResourceAttributes{Verb: "get", Resource: "nodes"},
	}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar))))
	var resp authzv1.SubjectAccessReview
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !resp.Status.Denied || resp.Status.Allowed {
		t.Fatalf("HTTP %d status %+v; expected explicit deny", rec.Code, resp.Status)
	}
}

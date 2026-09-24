// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
)

func TestBindDefinitionBridgeLiveDenyNotInCache(t *testing.T) {
	scheme := newSchemeWithCore(t)
	bd := &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bridge"}, Spec: authz.BindDefinitionSpec{
		Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}},
		RoleBindings: []authz.NamespaceBinding{{AuthorizeBeforeBinding: true,
			ClusterRoleRefs: []string{"reader"}, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{"env": "prod"}}},
		}},
	}}
	cached := fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&authz.WebhookAuthorizer{}, indexer.WebhookAuthorizerHasNamespaceSelectorField, indexer.WebhookAuthorizerHasNamespaceSelectorFunc).
		WithIndex(&authz.BindDefinition{}, indexer.BindDefinitionBridgeSubjectField, indexer.BindDefinitionBridgeSubjectFunc).
		WithObjects(bd).Build()
	liveObjects := []client.Object{
		bd.DeepCopy(),
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"env": "prod"}}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "reader"}, Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"},
		}}},
		&authz.WebhookAuthorizer{ObjectMeta: metav1.ObjectMeta{Name: "new-deny"}, Spec: authz.WebhookAuthorizerSpec{
			DeniedPrincipals:  []authz.Principal{{User: "alice"}},
			NamespaceSelector: metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			ResourceRules:     []authzv1.ResourceRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
		}},
	}
	sar := authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods"},
	}}
	for _, tc := range []struct {
		name           string
		change         func()
		denied         bool
		allow          bool
		listError      bool
		namespaceError bool
	}{
		{name: "new deny absent from cache", denied: true},
		{name: "live deny list unavailable", listError: true},
		{name: "live deny namespace lookup unavailable", namespaceError: true},
		{name: "nonmatching namespace", change: func() {
			liveObjects[3].(*authz.WebhookAuthorizer).Spec.NamespaceSelector.MatchLabels["env"] = "dev"
		}, allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.change != nil {
				tc.change()
			}
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(liveObjects...)
			namespaceReads := 0
			builder = builder.WithInterceptorFuncs(interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if tc.listError {
						if _, ok := list.(*authz.WebhookAuthorizerList); ok {
							return errors.New("live deny list unavailable")
						}
					}
					return c.List(ctx, list, opts...)
				},
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.Namespace); ok {
						namespaceReads++
						if tc.namespaceError && namespaceReads > 1 {
							return errors.New("live namespace unavailable")
						}
					}
					return c.Get(ctx, key, obj, opts...)
				},
			})
			live := builder.Build()
			handler := &Authorizer{Client: cached, LiveReader: live, Discovery: bridgeTestDiscovery(), Log: logr.Discard(), AllowUnauthenticatedAuthorize: true}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar))))
			var resp authzv1.SubjectAccessReview
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusOK || resp.Status.Denied != tc.denied || resp.Status.Allowed != tc.allow {
				t.Fatalf("HTTP %d status %+v; expected allowed=%t denied=%t", rec.Code, resp.Status, tc.allow, tc.denied)
			}
		})
	}
}

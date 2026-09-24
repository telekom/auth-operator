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
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	fakediscovery "k8s.io/client-go/discovery/fake"
	clientgotesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
	"github.com/telekom/auth-operator/pkg/metrics"
)

func bridgeTestDiscovery() discovery.DiscoveryInterfaceWithContext {
	return &fakediscovery.FakeDiscovery{Fake: &clientgotesting.Fake{Resources: []*metav1.APIResourceList{
		{GroupVersion: "v1", APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true}, {Name: "secrets", Namespaced: true}, {Name: "configmaps", Namespaced: true},
		}},
		{GroupVersion: "apps/v1", APIResources: []metav1.APIResource{{Name: "deployments", Namespaced: true}}},
		{GroupVersion: rbacv1.GroupName + "/v1", APIResources: []metav1.APIResource{{Name: "clusterroles", Namespaced: false}}},
	}}}
}

//nolint:gocyclo // The test table covers independent authorization failure modes.
func TestBindDefinitionBridgeAuthorize(t *testing.T) {
	selector := metav1.LabelSelector{MatchLabels: map[string]string{authz.LabelKeyTenant: "team-a"}}
	unprotected := metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
		Key: authz.LabelKeyProtected, Operator: metav1.LabelSelectorOpDoesNotExist,
	}}}
	baseRule := rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}
	tests := []struct {
		name         string
		subjects     []rbacv1.Subject
		user         string
		groups       []string
		attr         authzv1.ResourceAttributes
		binding      authz.NamespaceBinding
		rule         rbacv1.PolicyRule
		namespace    *corev1.Namespace
		extra        []client.Object
		intercept    interceptor.Funcs
		allowed      bool
		explicitDeny bool
	}{
		{name: "opted in cluster role", allowed: true},
		{name: "wildcard SAR API version", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods", Version: "*"}, allowed: true},
		{name: "opted out", binding: authz.NamespaceBinding{NamespaceSelector: []metav1.LabelSelector{selector}, ClusterRoleRefs: []string{"reader"}}},
		{name: "explicit namespace cannot opt in", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, Namespace: "team-a", NamespaceSelector: []metav1.LabelSelector{selector}, ClusterRoleRefs: []string{"reader"}}},
		{name: "missing selector cannot opt in", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, ClusterRoleRefs: []string{"reader"}}},
		{name: "service account exact match", user: "system:serviceaccount:team-a:worker", subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "team-a", Name: "worker"}}, allowed: true},
		{name: "service account other namespace", user: "system:serviceaccount:team-b:worker", subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: "team-a", Name: "worker"}}},
		{name: "user match", subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}}, allowed: true},
		{name: "invalid user API group", subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "alice"}}},
		{name: "user mismatch", user: "bob"},
		{name: "group match", user: "bob", groups: []string{"developers"}, subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "developers"}}, allowed: true},
		{name: "invalid group API group", user: "bob", groups: []string{"developers"}, subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, Name: "developers"}}},
		{name: "group mismatch", user: "bob", groups: []string{"auditors"}, subjects: []rbacv1.Subject{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "developers"}}},
		{name: "selector OR matches second", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{authz.LabelKeyTenant: "team-b"}}, selector}, ClusterRoleRefs: []string{"reader"}}, allowed: true},
		{name: "protected namespace excluded", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector, unprotected}, ClusterRoleRefs: []string{"reader"}}, namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyTenant: "team-b", authz.LabelKeyProtected: "true"}}}},
		{name: "DoesNotExist unprotected", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{unprotected}, ClusterRoleRefs: []string{"reader"}}, allowed: true},
		{name: "DoesNotExist protected", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{unprotected}, ClusterRoleRefs: []string{"reader"}}, namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyProtected: "true"}}}},
		{name: "cross tenant mismatch", namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyTenant: "team-b"}}}},
		{name: "absent namespace", attr: authzv1.ResourceAttributes{Namespace: "missing", Verb: "get", Resource: "pods"}},
		{name: "terminating namespace", namespace: &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyTenant: "team-a"}}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating}}},
		{name: "cluster-scoped request", attr: authzv1.ResourceAttributes{Verb: "get", Resource: "pods"}},
		{name: "cluster resource with forged namespace", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Group: rbacv1.GroupName, Resource: "clusterroles"}, rule: rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{rbacv1.GroupName}, Resources: []string{"clusterroles"}}},
		{name: "unknown resource", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "unknowns"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		{name: "cluster binding only", binding: authz.NamespaceBinding{}},
		{name: "role ref in target namespace", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector}, RoleRefs: []string{"local-reader"}}, extra: []client.Object{&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "local-reader", Namespace: "team-a"}, Rules: []rbacv1.PolicyRule{baseRule}}}, allowed: true},
		{name: "role ref in other namespace", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector}, RoleRefs: []string{"local-reader"}}, extra: []client.Object{&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "local-reader", Namespace: "team-b"}, Rules: []rbacv1.PolicyRule{baseRule}}}},
		{name: "missing cluster role", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector}, ClusterRoleRefs: []string{"missing"}}},
		{name: "missing role after matching cluster role", binding: authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector}, ClusterRoleRefs: []string{"reader"}, RoleRefs: []string{"missing"}}},
		{name: "named resource matches", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods", Name: "selected"}, rule: rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"selected"}}, allowed: true},
		{name: "named resource mismatch", rule: rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"selected"}}},
		{name: "subresource matches", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods", Subresource: "log"}, rule: rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/log"}}, allowed: true},
		{name: "parent resource does not grant subresource", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods", Subresource: "log"}},
		{name: "wildcards grant ordinary verb", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "list", Group: "apps", Resource: "deployments"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}, allowed: true},
		{name: "wrong API group", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Group: "apps", Resource: "pods"}},
		{name: "bind is never bridged", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "bind", Resource: "pods"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		{name: "escalate is never bridged", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "escalate", Resource: "pods"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		{name: "impersonate is never bridged", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: "impersonate", Resource: "pods"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		{name: "constrained impersonation is never bridged", attr: authzv1.ResourceAttributes{Namespace: "team-a", Verb: authz.IdentityVerb(authz.ImpersonationModeServiceAccount), Resource: "serviceaccounts"}, rule: rbacv1.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}},
		{name: "cached list error", intercept: interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			if _, ok := list.(*authz.BindDefinitionList); ok {
				return errors.New("cache unavailable")
			}

			return c.List(ctx, list, opts...)
		}}},
		{name: "role read error", intercept: interceptor.Funcs{Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*rbacv1.ClusterRole); ok {
				return errors.New("role unavailable")
			}
			return c.Get(ctx, key, obj, opts...)
		}}},
		{name: "existing explicit deny takes precedence", explicitDeny: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.user == "" {
				tc.user = "alice"
			}
			if tc.subjects == nil {
				tc.subjects = []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}}
			}
			if tc.attr == (authzv1.ResourceAttributes{}) {
				tc.attr = authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods"}
			}
			if tc.binding.NamespaceSelector == nil && tc.binding.Namespace == "" && tc.binding.ClusterRoleRefs == nil && tc.binding.RoleRefs == nil && tc.name != "cluster binding only" {
				tc.binding = authz.NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: []metav1.LabelSelector{selector}, ClusterRoleRefs: []string{"reader"}}
			}
			if tc.rule.Verbs == nil {
				tc.rule = baseRule
			}
			bd := &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bridge"}, Spec: authz.BindDefinitionSpec{
				Subjects: tc.subjects, RoleBindings: []authz.NamespaceBinding{tc.binding},
			}}
			if tc.name == "cluster binding only" {
				bd.Spec.RoleBindings = nil
				bd.Spec.ClusterRoleBindings.ClusterRoleRefs = []string{"reader"}
			}
			objs := []client.Object{
				bd,
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "reader"}, Rules: []rbacv1.PolicyRule{tc.rule}},
			}
			if tc.namespace != nil {
				objs = append(objs, tc.namespace)
			} else {
				objs = append(objs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyTenant: "team-a"}}})
			}
			objs = append(objs, tc.extra...)
			if tc.explicitDeny {
				objs = append(objs, &authz.WebhookAuthorizer{ObjectMeta: metav1.ObjectMeta{Name: "deny"}, Spec: authz.WebhookAuthorizerSpec{
					DeniedPrincipals: []authz.Principal{{User: "alice"}},
					ResourceRules:    []authzv1.ResourceRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}},
				}})
			}
			builder := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).
				WithIndex(&authz.WebhookAuthorizer{}, indexer.WebhookAuthorizerHasNamespaceSelectorField, indexer.WebhookAuthorizerHasNamespaceSelectorFunc).
				WithIndex(&authz.BindDefinition{}, indexer.BindDefinitionBridgeSubjectField, indexer.BindDefinitionBridgeSubjectFunc).
				WithObjects(objs...)
			if tc.intercept.List != nil || tc.intercept.Get != nil {
				builder = builder.WithInterceptorFuncs(tc.intercept)
			}
			reader := builder.Build()
			handler := &Authorizer{Client: reader, LiveReader: reader, Discovery: bridgeTestDiscovery(), Log: logr.Discard(), AllowUnauthenticatedAuthorize: true}
			sar := authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: tc.user, Groups: tc.groups, ResourceAttributes: &tc.attr}}
			before := testutil.ToFloat64(metrics.AuthorizerBridgedAllowsTotal)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/authorize", bytes.NewReader(marshalSAR(t, sar)))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
			}
			var resp authzv1.SubjectAccessReview
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatal(err)
			}
			if resp.Status.Allowed != tc.allowed || resp.Status.Denied != tc.explicitDeny {
				t.Fatalf("status = %+v, want allowed=%t denied=%t", resp.Status, tc.allowed, tc.explicitDeny)
			}
			if tc.allowed && !strings.Contains(resp.Status.Reason, "BindDefinition") {
				t.Fatalf("expected bridge reason, got %q", resp.Status.Reason)
			}
			if got := testutil.ToFloat64(metrics.AuthorizerBridgedAllowsTotal) - before; got != map[bool]float64{true: 1, false: 0}[tc.allowed] {
				t.Fatalf("bridged allow metric increment = %v", got)
			}
		})
	}
}

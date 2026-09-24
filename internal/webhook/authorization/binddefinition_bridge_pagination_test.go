// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/metrics"
)

func TestBridgeLiveDenyFindsLaterPage(t *testing.T) {
	calls := 0
	live := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).
		WithInterceptorFuncs(interceptor.Funcs{List: func(_ context.Context, _ client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
			options := &client.ListOptions{}
			options.ApplyOptions(opts)
			expected := ""
			if calls == 1 {
				expected = "next"
			}
			if options.Limit != bridgeDenyPageSize || options.Continue != expected {
				t.Fatalf("page %d options: limit=%d continue=%q", calls, options.Limit, options.Continue)
			}
			authorizers := list.(*authz.WebhookAuthorizerList)
			if calls == 0 {
				authorizers.Items = make([]authz.WebhookAuthorizer, bridgeDenyPageSize)
				authorizers.Continue = "next"
			} else {
				authorizers.Items = []authz.WebhookAuthorizer{{Spec: authz.WebhookAuthorizerSpec{
					DeniedPrincipals: []authz.Principal{{User: "alice"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"},
					}},
				}}}
			}
			calls++
			return nil
		}}).Build()
	wa := &Authorizer{LiveReader: live}
	result, err := wa.liveBridgeDeny(t.Context(), &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods"},
	}})
	if err != nil || result.allowed || result.decision != metrics.AuthorizerDecisionDenied || calls != 2 {
		t.Fatalf("expected deny on second page; result=%+v calls=%d err=%v", result, calls, err)
	}
}

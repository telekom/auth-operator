// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	pkgmetrics "github.com/telekom/auth-operator/pkg/metrics"
)

func impersonationTestAuthorizer() *Authorizer {
	return &Authorizer{Log: logr.Discard()}
}

func TestEffectiveImpersonationVerbPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		set  authzv1alpha1.ImpersonationVerbPolicy
		want authzv1alpha1.ImpersonationVerbPolicy
	}{
		{
			// Objects stored before the field existed have the zero value, and the CRD
			// default only applies on write. Defaulting in code is what keeps the
			// hardening effective for pre-existing authorizers.
			name: "empty defaults to RequireExplicitVerb",
			want: authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
		},
		{
			name: "explicit AllowWildcard is respected",
			set:  authzv1alpha1.ImpersonationVerbPolicyAllowWildcard,
			want: authzv1alpha1.ImpersonationVerbPolicyAllowWildcard,
		},
		{
			name: "explicit Deny is respected",
			set:  authzv1alpha1.ImpersonationVerbPolicyDeny,
			want: authzv1alpha1.ImpersonationVerbPolicyDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			wa := &authzv1alpha1.WebhookAuthorizer{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{ImpersonationVerbPolicy: tt.set},
			}
			if got := effectiveImpersonationVerbPolicy(wa); got != tt.want {
				t.Errorf("effectiveImpersonationVerbPolicy() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchesVerb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		patterns []string
		verb     string
		policy   authzv1alpha1.ImpersonationVerbPolicy
		want     bool
	}{
		// Ordinary verbs must behave exactly as before, on every policy.
		{
			name:     "plain verb exact match",
			patterns: []string{"get", "list"},
			verb:     "list",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     true,
		},
		{
			name:     "plain verb wildcard match is unaffected by the policy",
			patterns: []string{rbacv1.VerbAll},
			verb:     "list",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     true,
		},
		{
			name:     "legacy impersonate verb still matches a wildcard rule",
			patterns: []string{rbacv1.VerbAll},
			verb:     authzv1alpha1.LegacyImpersonateVerb,
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     true,
		},
		{
			name:     "legacy impersonate verb still matches an exact rule",
			patterns: []string{authzv1alpha1.LegacyImpersonateVerb},
			verb:     authzv1alpha1.LegacyImpersonateVerb,
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     true,
		},
		// RequireExplicitVerb: this is the KEP-5284 hardening.
		{
			name:     "RequireExplicitVerb: wildcard does NOT match an identity verb",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     false,
		},
		{
			name:     "RequireExplicitVerb: wildcard does NOT match an action verb",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate-on:user-info:list",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     false,
		},
		{
			name:     "RequireExplicitVerb: literal identity verb matches",
			patterns: []string{"impersonate:user-info"},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     true,
		},
		{
			name:     "RequireExplicitVerb: a different mode does not match",
			patterns: []string{"impersonate:serviceaccount"},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyRequireExplicitVerb,
			want:     false,
		},
		// AllowWildcard restores plain RBAC semantics.
		{
			name:     "AllowWildcard: wildcard matches an identity verb",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyAllowWildcard,
			want:     true,
		},
		{
			name:     "AllowWildcard: wildcard matches an action verb",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate-on:serviceaccount:get",
			policy:   authzv1alpha1.ImpersonationVerbPolicyAllowWildcard,
			want:     true,
		},
		// Deny uses plain RBAC semantics: ignoring "*" is fail-safe when granting but
		// fail-open when denying, and Deny is documented as a kill switch.
		{
			name:     "Deny: wildcard DOES select the rule so the kill switch fires",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyDeny,
			want:     true,
		},
		{
			name:     "Deny: wildcard selects an action verb too",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate-on:serviceaccount:get",
			policy:   authzv1alpha1.ImpersonationVerbPolicyDeny,
			want:     true,
		},
		{
			name:     "Deny: literal verb selects the rule",
			patterns: []string{"impersonate:user-info"},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyDeny,
			want:     true,
		},
		{
			name:     "Deny: an unrelated verb list still does not select the rule",
			patterns: []string{"get", "list"},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicyDeny,
			want:     false,
		},
		// An unset or unrecognised policy must fall back to the fail-safe behaviour
		// rather than the permissive branch.
		{
			name:     "unset policy is fail-safe: wildcard does not match",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate:user-info",
			policy:   "",
			want:     false,
		},
		{
			name:     "unrecognised policy is fail-safe: wildcard does not match",
			patterns: []string{rbacv1.VerbAll},
			verb:     "impersonate:user-info",
			policy:   authzv1alpha1.ImpersonationVerbPolicy("SomethingNew"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesVerb(tt.patterns, tt.verb, tt.policy); got != tt.want {
				t.Errorf("matchesVerb(%v, %q, %q) = %t, want %t", tt.patterns, tt.verb, tt.policy, got, tt.want)
			}
		})
	}
}

func TestPrincipalMatchesUIDAndExtra(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		sar        authzv1.SubjectAccessReviewSpec
		principals []authzv1alpha1.Principal
		want       bool
	}{
		{
			name: "user-only principal still matches (backwards compatible)",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane"},
			principals: []authzv1alpha1.Principal{
				{User: "jane"},
			},
			want: true,
		},
		{
			name: "group-only principal still matches (backwards compatible)",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane", Groups: []string{"dev", "ops"}},
			principals: []authzv1alpha1.Principal{
				{Groups: []string{"ops"}},
			},
			want: true,
		},
		{
			name: "UID matcher matches",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane", UID: "uid-123"},
			principals: []authzv1alpha1.Principal{
				{User: "jane", UID: "uid-123"},
			},
			want: true,
		},
		{
			name: "UID matcher mismatch rejects even when the user matches",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane", UID: "uid-999"},
			principals: []authzv1alpha1.Principal{
				{User: "jane", UID: "uid-123"},
			},
			want: false,
		},
		{
			name: "UID-only principal matches on UID alone",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane", UID: "uid-123"},
			principals: []authzv1alpha1.Principal{
				{UID: "uid-123"},
			},
			want: true,
		},
		{
			name: "extra matcher matches the node-name attribute",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "system:serviceaccount:kube-system:node-agent",
				Extra: map[string]authzv1.ExtraValue{"authentication.kubernetes.io/node-name": {"worker-1"}},
			},
			principals: []authzv1alpha1.Principal{{
				User: "system:serviceaccount:kube-system:node-agent",
				Extra: []authzv1alpha1.PrincipalExtraMatch{
					{Key: "authentication.kubernetes.io/node-name", Values: []string{"worker-1"}},
				},
			}},
			want: true,
		},
		{
			name: "extra matcher value mismatch rejects",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "jane",
				Extra: map[string]authzv1.ExtraValue{"authentication.kubernetes.io/node-name": {"worker-2"}},
			},
			principals: []authzv1alpha1.Principal{{
				User: "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{
					{Key: "authentication.kubernetes.io/node-name", Values: []string{"worker-1"}},
				},
			}},
			want: false,
		},
		{
			name: "extra matcher missing key rejects",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane"},
			principals: []authzv1alpha1.Principal{{
				User:  "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{{Key: "example.com/scopes", Values: []string{"read"}}},
			}},
			want: false,
		},
		{
			name: "extra wildcard matches any non-empty value",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "jane",
				Extra: map[string]authzv1.ExtraValue{"example.com/scopes": {"anything"}},
			},
			principals: []authzv1alpha1.Principal{{
				User:  "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{{Key: "example.com/scopes", Values: []string{rbacv1.VerbAll}}},
			}},
			want: true,
		},
		{
			name: "extra wildcard does not match an empty-string value",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "jane",
				Extra: map[string]authzv1.ExtraValue{"example.com/scopes": {""}},
			},
			principals: []authzv1alpha1.Principal{{
				User:  "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{{Key: "example.com/scopes", Values: []string{rbacv1.VerbAll}}},
			}},
			want: false,
		},
		{
			name: "multiple extra matchers are ANDed: one missing rejects",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "jane",
				Extra: map[string]authzv1.ExtraValue{"example.com/a": {"1"}},
			},
			principals: []authzv1alpha1.Principal{{
				User: "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{
					{Key: "example.com/a", Values: []string{"1"}},
					{Key: "example.com/b", Values: []string{"2"}},
				},
			}},
			want: false,
		},
		{
			name: "multiple extra matchers are ANDed: all present matches",
			sar: authzv1.SubjectAccessReviewSpec{
				User: "jane",
				Extra: map[string]authzv1.ExtraValue{
					"example.com/a": {"1"},
					"example.com/b": {"2", "3"},
				},
			},
			principals: []authzv1alpha1.Principal{{
				User: "jane",
				Extra: []authzv1alpha1.PrincipalExtraMatch{
					{Key: "example.com/a", Values: []string{"1"}},
					{Key: "example.com/b", Values: []string{"3"}},
				},
			}},
			want: true,
		},
		{
			name: "extra-only principal matches on extra alone",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "anyone",
				Extra: map[string]authzv1.ExtraValue{"example.com/tier": {"platform"}},
			},
			principals: []authzv1alpha1.Principal{{
				Extra: []authzv1alpha1.PrincipalExtraMatch{{Key: "example.com/tier", Values: []string{"platform"}}},
			}},
			want: true,
		},
		{
			name: "UID plus extra plus user all required",
			sar: authzv1.SubjectAccessReviewSpec{
				User:  "jane",
				UID:   "uid-1",
				Extra: map[string]authzv1.ExtraValue{"example.com/tier": {"platform"}},
			},
			principals: []authzv1alpha1.Principal{{
				User:  "jane",
				UID:   "uid-1",
				Extra: []authzv1alpha1.PrincipalExtraMatch{{Key: "example.com/tier", Values: []string{"platform"}}},
			}},
			want: true,
		},
		{
			name: "fully empty principal never matches (defensive allow-all guard)",
			sar:  authzv1.SubjectAccessReviewSpec{User: "jane"},
			principals: []authzv1alpha1.Principal{
				{},
			},
			want: false,
		},
		{
			name: "namespaced ServiceAccount principal still matches",
			sar:  authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:team-a:applier"},
			principals: []authzv1alpha1.Principal{
				{User: "applier", Namespace: "team-a"},
			},
			want: true,
		},
		{
			name: "namespaced principal with a matching UID matches",
			sar:  authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:team-a:applier", UID: "uid-7"},
			principals: []authzv1alpha1.Principal{
				{User: "applier", Namespace: "team-a", UID: "uid-7"},
			},
			want: true,
		},
		{
			name: "namespaced principal with a mismatched UID rejects",
			sar:  authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:team-a:applier", UID: "uid-8"},
			principals: []authzv1alpha1.Principal{
				{User: "applier", Namespace: "team-a", UID: "uid-7"},
			},
			want: false,
		},
		{
			name: "namespaced principal does not match a different namespace",
			sar:  authzv1.SubjectAccessReviewSpec{User: "system:serviceaccount:team-b:applier"},
			principals: []authzv1alpha1.Principal{
				{User: "applier", Namespace: "team-a"},
			},
			want: false,
		},
	}

	handler := impersonationTestAuthorizer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sar := &authzv1.SubjectAccessReview{Spec: tt.sar}
			if got := handler.principalMatches(sar, tt.principals); got != tt.want {
				t.Errorf("principalMatches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestEvaluateSARImpersonationVerbs(t *testing.T) {
	t.Parallel()

	readyStatus := authzv1alpha1.WebhookAuthorizerStatus{AuthorizerConfigured: true}

	// A pre-existing broad authorizer: verbs ["*"] on all resources. Under plain RBAC
	// semantics this would silently grant constrained impersonation the moment the
	// feature gate turns on, which KEP-5284 explicitly calls out as a hazard.
	wildcardAuthorizer := func(policy authzv1alpha1.ImpersonationVerbPolicy) authzv1alpha1.WebhookAuthorizer {
		return authzv1alpha1.WebhookAuthorizer{
			Spec: authzv1alpha1.WebhookAuthorizerSpec{
				ImpersonationVerbPolicy: policy,
				AllowedPrincipals:       []authzv1alpha1.Principal{{User: "jane"}},
				ResourceRules: []authzv1.ResourceRule{{
					Verbs:     []string{rbacv1.VerbAll},
					APIGroups: []string{rbacv1.APIGroupAll},
					Resources: []string{rbacv1.ResourceAll},
				}},
			},
			Status: readyStatus,
		}
	}

	impersonationSAR := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "jane",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb:     "impersonate:user-info",
				Group:    "authentication.k8s.io",
				Resource: "users",
				Name:     "target-user",
			},
		},
	}
	plainSAR := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "jane",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb: "list", Resource: "pods", Namespace: "default",
			},
		},
	}
	legacySAR := &authzv1.SubjectAccessReview{
		Spec: authzv1.SubjectAccessReviewSpec{
			User: "jane",
			ResourceAttributes: &authzv1.ResourceAttributes{
				Verb: authzv1alpha1.LegacyImpersonateVerb, Resource: "serviceaccounts", Namespace: "team-a",
			},
		},
	}

	tests := []struct {
		name         string
		authorizers  []authzv1alpha1.WebhookAuthorizer
		sar          *authzv1.SubjectAccessReview
		wantDecision string
	}{
		{
			name:         "default policy: wildcard rule does not grant constrained impersonation",
			authorizers:  []authzv1alpha1.WebhookAuthorizer{wildcardAuthorizer("")},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionNoOpinion,
		},
		{
			name:         "default policy: wildcard rule still grants ordinary verbs",
			authorizers:  []authzv1alpha1.WebhookAuthorizer{wildcardAuthorizer("")},
			sar:          plainSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "default policy: wildcard rule still grants the LEGACY impersonate verb (no regression)",
			// This is the explicit no-regression assertion: existing legacy
			// impersonation authorization behaviour must be untouched.
			authorizers:  []authzv1alpha1.WebhookAuthorizer{wildcardAuthorizer("")},
			sar:          legacySAR,
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name:         "AllowWildcard: wildcard rule grants constrained impersonation",
			authorizers:  []authzv1alpha1.WebhookAuthorizer{wildcardAuthorizer(authzv1alpha1.ImpersonationVerbPolicyAllowWildcard)},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "explicit verb grant is allowed under the default policy",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{User: "jane"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:         []string{"impersonate:user-info"},
						APIGroups:     []string{"authentication.k8s.io"},
						Resources:     []string{"users"},
						ResourceNames: []string{"target-user"},
					}},
				},
				Status: readyStatus,
			}},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "explicit verb grant respects resourceNames",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{User: "jane"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:         []string{"impersonate:user-info"},
						APIGroups:     []string{"authentication.k8s.io"},
						Resources:     []string{"users"},
						ResourceNames: []string{"someone-else"},
					}},
				},
				Status: readyStatus,
			}},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionNoOpinion,
		},
		{
			name: "Deny policy explicitly rejects constrained impersonation regardless of principals",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					ImpersonationVerbPolicy: authzv1alpha1.ImpersonationVerbPolicyDeny,
					// Deliberately lists an unrelated principal: the kill switch must not
					// depend on the principal lists.
					AllowedPrincipals: []authzv1alpha1.Principal{{User: "someone-else"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{"impersonate:user-info"},
						APIGroups: []string{rbacv1.APIGroupAll},
						Resources: []string{rbacv1.ResourceAll},
					}},
				},
				Status: readyStatus,
			}},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionDenied,
		},
		{
			// This is the kill-switch case Copilot flagged on #513: an operator shuts
			// impersonation off with verbs: ["*"] rather than enumerating every
			// impersonate:<mode> and impersonate-on:<mode>:<verb> combination. Before the
			// fix matchesVerb required a literal verb under Deny, so this rule matched
			// nothing and the request fell through to NoOpinion.
			name: "Deny policy with a wildcard verb still fires the kill switch",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					ImpersonationVerbPolicy: authzv1alpha1.ImpersonationVerbPolicyDeny,
					AllowedPrincipals:       []authzv1alpha1.Principal{{User: "someone-else"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{rbacv1.VerbAll},
						APIGroups: []string{rbacv1.APIGroupAll},
						Resources: []string{rbacv1.ResourceAll},
					}},
				},
				Status: readyStatus,
			}},
			sar:          impersonationSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionDenied,
		},
		{
			name: "Deny policy leaves ordinary verbs alone",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					ImpersonationVerbPolicy: authzv1alpha1.ImpersonationVerbPolicyDeny,
					AllowedPrincipals:       []authzv1alpha1.Principal{{User: "jane"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{rbacv1.VerbAll},
						APIGroups: []string{rbacv1.APIGroupAll},
						Resources: []string{rbacv1.ResourceAll},
					}},
				},
				Status: readyStatus,
			}},
			sar:          plainSAR,
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "action verb grant is allowed when listed explicitly",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{User: "jane"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{"impersonate-on:user-info:list"},
						APIGroups: []string{""},
						Resources: []string{"pods"},
					}},
				},
				Status: readyStatus,
			}},
			sar: &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
				User: "jane",
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb: "impersonate-on:user-info:list", Resource: "pods",
				},
			}},
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "UID-scoped principal gates an impersonation grant",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{User: "jane", UID: "uid-expected"}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{"impersonate:user-info"},
						APIGroups: []string{"authentication.k8s.io"},
						Resources: []string{"users"},
					}},
				},
				Status: readyStatus,
			}},
			sar: &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
				User: "jane",
				UID:  "uid-other",
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb: "impersonate:user-info", Group: "authentication.k8s.io", Resource: "users",
				},
			}},
			wantDecision: pkgmetrics.AuthorizerDecisionNoOpinion,
		},
		{
			name: "extra-scoped principal permits associated-node impersonation for the right node",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{
						User: "system:serviceaccount:kube-system:node-agent",
						Extra: []authzv1alpha1.PrincipalExtraMatch{
							{Key: "authentication.kubernetes.io/node-name", Values: []string{"worker-1"}},
						},
					}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{"impersonate:associated-node"},
						APIGroups: []string{"authentication.k8s.io"},
						Resources: []string{"nodes"},
					}},
				},
				Status: readyStatus,
			}},
			sar: &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
				User:  "system:serviceaccount:kube-system:node-agent",
				Extra: map[string]authzv1.ExtraValue{"authentication.kubernetes.io/node-name": {"worker-1"}},
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb: "impersonate:associated-node", Group: "authentication.k8s.io", Resource: "nodes", Name: "*",
				},
			}},
			wantDecision: pkgmetrics.AuthorizerDecisionAllowed,
		},
		{
			name: "extra-scoped principal rejects associated-node impersonation for the wrong node",
			authorizers: []authzv1alpha1.WebhookAuthorizer{{
				Spec: authzv1alpha1.WebhookAuthorizerSpec{
					AllowedPrincipals: []authzv1alpha1.Principal{{
						User: "system:serviceaccount:kube-system:node-agent",
						Extra: []authzv1alpha1.PrincipalExtraMatch{
							{Key: "authentication.kubernetes.io/node-name", Values: []string{"worker-1"}},
						},
					}},
					ResourceRules: []authzv1.ResourceRule{{
						Verbs:     []string{"impersonate:associated-node"},
						APIGroups: []string{"authentication.k8s.io"},
						Resources: []string{"nodes"},
					}},
				},
				Status: readyStatus,
			}},
			sar: &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
				User:  "system:serviceaccount:kube-system:node-agent",
				Extra: map[string]authzv1.ExtraValue{"authentication.kubernetes.io/node-name": {"worker-9"}},
				ResourceAttributes: &authzv1.ResourceAttributes{
					Verb: "impersonate:associated-node", Group: "authentication.k8s.io", Resource: "nodes", Name: "*",
				},
			}},
			wantDecision: pkgmetrics.AuthorizerDecisionNoOpinion,
		},
	}

	handler := impersonationTestAuthorizer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := handler.evaluateSAR(context.Background(), tt.sar, tt.authorizers)
			if err != nil {
				t.Fatalf("evaluateSAR() unexpected error: %v", err)
			}
			if result.decision != tt.wantDecision {
				t.Errorf("decision = %q, want %q (reason: %s)", result.decision, tt.wantDecision, result.reason)
			}
		})
	}
}

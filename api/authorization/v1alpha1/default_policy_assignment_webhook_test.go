// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestParseRequesterServiceAccount(t *testing.T) {
	tests := []struct {
		name     string
		username string
		expectSA bool
		expectNS string
		expectN  string
	}{
		{name: "valid serviceaccount username", username: "system:serviceaccount:team-a:rbac-applier", expectSA: true, expectNS: "team-a", expectN: "rbac-applier"},
		{name: "regular user", username: "alice", expectSA: false},
		{name: "malformed serviceaccount", username: "system:serviceaccount:missing-parts", expectSA: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sa := parseRequesterServiceAccount(tt.username)
			if sa.IsServiceAccount != tt.expectSA {
				t.Fatalf("expected IsServiceAccount=%v, got %v", tt.expectSA, sa.IsServiceAccount)
			}
			if sa.Namespace != tt.expectNS {
				t.Fatalf("expected namespace %q, got %q", tt.expectNS, sa.Namespace)
			}
			if sa.Name != tt.expectN {
				t.Fatalf("expected name %q, got %q", tt.expectN, sa.Name)
			}
		})
	}
}

func TestRequesterMatchesDefaultAssignment(t *testing.T) {
	da := &DefaultPolicyAssignment{
		Groups: []string{"oidc:platform-operators"},
		ServiceAccounts: []SARef{
			{Name: "rbac-applier", Namespace: "team-a"},
		},
	}

	if !requesterMatchesDefaultAssignment(da, "alice", []string{"oidc:platform-operators"}) {
		t.Fatal("expected group match to be true")
	}

	if !requesterMatchesDefaultAssignment(da, "system:serviceaccount:team-a:rbac-applier", nil) {
		t.Fatal("expected serviceaccount match to be true")
	}

	if requesterMatchesDefaultAssignment(da, "system:serviceaccount:team-b:rbac-applier", nil) {
		t.Fatal("expected non-matching serviceaccount to be false")
	}
}

func TestValidateDefaultPolicyForRequester(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}

	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{Namespaces: []string{"default"}},
				DefaultAssignment: &DefaultPolicyAssignment{
					Groups: []string{"oidc:team-a-admins"},
				},
			},
		},
		&RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-b"},
			Spec: RBACPolicySpec{
				AppliesTo: PolicyScope{Namespaces: []string{"default"}},
				DefaultAssignment: &DefaultPolicyAssignment{
					ServiceAccounts: []SARef{{Name: "rbac-applier", Namespace: "team-a"}},
				},
			},
		},
	).Build()

	gk := schema.GroupKind{Group: GroupVersion.Group, Kind: "RestrictedRoleDefinition"}

	ctxGroup := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"oidc:team-a-admins"},
			},
		},
	})
	if err := validateDefaultPolicyForRequester(ctxGroup, client, gk, "rrd-a", "policy-a"); err != nil {
		t.Fatalf("expected policy-a to be allowed, got err: %v", err)
	}

	if err := validateDefaultPolicyForRequester(ctxGroup, client, gk, "rrd-a", "policy-b"); err == nil {
		t.Fatal("expected mismatch error for group-based default policy")
	} else if !strings.Contains(err.Error(), "must use one of the default policies") {
		t.Fatalf("unexpected error: %v", err)
	}

	ctxSA := admission.NewContextWithRequest(context.Background(), admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:team-a:rbac-applier",
			},
		},
	})
	if err := validateDefaultPolicyForRequester(ctxSA, client, gk, "rrd-b", "policy-b"); err != nil {
		t.Fatalf("expected policy-b to be allowed, got err: %v", err)
	}

	// No admission request in context: skip enforcement.
	if err := validateDefaultPolicyForRequester(context.Background(), client, gk, "rrd-c", "anything"); err != nil {
		t.Fatalf("expected no error without admission context, got: %v", err)
	}
}

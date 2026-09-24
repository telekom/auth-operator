// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"fmt"
	"testing"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/indexer"
)

func TestBindDefinitionBridgeFreshness(t *testing.T) {
	original := &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bridge"}, Spec: authz.BindDefinitionSpec{
		Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}},
		RoleBindings: []authz.NamespaceBinding{{
			AuthorizeBeforeBinding: true,
			ClusterRoleRefs:        []string{"reader"},
			NamespaceSelector:      []metav1.LabelSelector{{MatchLabels: map[string]string{authz.LabelKeyTenant: "team-a"}}},
		}},
	}}
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", ResourceAttributes: &authzv1.ResourceAttributes{Namespace: "team-a", Verb: "get", Resource: "pods"},
	}}
	for _, tc := range []struct {
		name   string
		stale  bool
		mutate func(*authz.BindDefinition)
		allow  bool
	}{
		{name: "live match", allow: true},
		{name: "stale cache misses a new opt-in", stale: true},
		{name: "live opt-out", mutate: func(bd *authz.BindDefinition) { bd.Spec.RoleBindings[0].AuthorizeBeforeBinding = false }},
		{name: "live subject revoked", mutate: func(bd *authz.BindDefinition) { bd.Spec.Subjects[0].Name = "bob" }},
		{name: "live selector revoked", mutate: func(bd *authz.BindDefinition) {
			bd.Spec.RoleBindings[0].NamespaceSelector[0].MatchLabels[authz.LabelKeyTenant] = "team-b"
		}},
		{name: "deletion requested", mutate: func(bd *authz.BindDefinition) {
			now := metav1.Now()
			bd.DeletionTimestamp = &now
			bd.Finalizers = []string{"cleanup"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bd := original.DeepCopy()
			if tc.mutate != nil {
				tc.mutate(bd)
			}
			cached := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).
				WithIndex(&authz.BindDefinition{}, indexer.BindDefinitionBridgeSubjectField, indexer.BindDefinitionBridgeSubjectFunc)
			if !tc.stale {
				cached = cached.WithObjects(original.DeepCopy())
			}
			live := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).WithObjects(bd,
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{authz.LabelKeyTenant: "team-a"}}},
				&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "reader"}, Rules: []rbacv1.PolicyRule{{
					Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"},
				}}},
			).Build()
			wa := &Authorizer{Client: cached.Build(), LiveReader: live}
			allowed, _ := wa.bridgeBindDefinition(t.Context(), sar)
			if allowed != tc.allow {
				t.Fatalf("allowed=%v, expected %v", allowed, tc.allow)
			}
		})
	}
}

func TestBindDefinitionBridgeCandidateLimits(t *testing.T) {
	objects := make([]client.Object, maxBridgeCandidates+1)
	for i := range objects {
		objects[i] = &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("bridge-%d", i)},
			Spec: authz.BindDefinitionSpec{
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}},
				RoleBindings: []authz.NamespaceBinding{{
					AuthorizeBeforeBinding: true, ClusterRoleRefs: []string{"reader"},
					NamespaceSelector: []metav1.LabelSelector{{}},
				}},
			}}
	}
	cached := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).
		WithIndex(&authz.BindDefinition{}, indexer.BindDefinitionBridgeSubjectField, indexer.BindDefinitionBridgeSubjectFunc).
		WithObjects(objects...).Build()
	wa := &Authorizer{Client: cached}
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "alice"}}
	if _, err := wa.bridgeCandidates(context.Background(), sar); err == nil {
		t.Fatal("expected candidate limit to return NoOpinion")
	}
	sar.Spec.Groups = make([]string, maxBridgeGroups+1)
	if _, err := wa.bridgeCandidates(context.Background(), sar); err == nil {
		t.Fatal("expected group limit to return NoOpinion")
	}
}

func TestBindDefinitionBridgeRoleReadLimit(t *testing.T) {
	reader := fake.NewClientBuilder().WithScheme(newSchemeWithCore(t)).WithObjects(
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "reader"}},
	).Build()
	wa := &Authorizer{LiveReader: reader}
	binding := authz.NamespaceBinding{ClusterRoleRefs: make([]string, maxBridgeRoleReads+1)}
	for i := range binding.ClusterRoleRefs {
		binding.ClusterRoleRefs[i] = "reader"
	}
	reads := 0
	_, err := wa.bridgeBindingAllows(t.Context(), binding, &authzv1.ResourceAttributes{Namespace: "team-a"}, &reads)
	if err == nil || reads != maxBridgeRoleReads {
		t.Fatalf("expected role read limit at %d, got reads=%d, err=%v", maxBridgeRoleReads, reads, err)
	}
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestAuthorizeBeforeBindingValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	validator := &BindDefinitionValidator{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&BindDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*BindDefinition).Spec.TargetName}
		}).
		WithIndex(&RestrictedBindDefinition{}, TargetNameField, func(obj client.Object) []string {
			return []string{obj.(*RestrictedBindDefinition).Spec.TargetName}
		}).Build()}
	selector := []metav1.LabelSelector{{MatchLabels: map[string]string{LabelKeyTenant: "team-a"}}}
	for _, tc := range []struct {
		name    string
		binding NamespaceBinding
		valid   bool
	}{
		{"selector with ClusterRole", NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: selector, ClusterRoleRefs: []string{"reader"}}, true},
		{"selector with Role", NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: selector, RoleRefs: []string{"reader"}}, true},
		{"disabled with explicit namespace", NamespaceBinding{Namespace: "team-a", RoleRefs: []string{"reader"}}, true},
		{"enabled with explicit namespace", NamespaceBinding{AuthorizeBeforeBinding: true, Namespace: "team-a", RoleRefs: []string{"reader"}}, false},
		{"enabled with namespace and selector", NamespaceBinding{AuthorizeBeforeBinding: true, Namespace: "team-a", NamespaceSelector: selector, RoleRefs: []string{"reader"}}, false},
		{"enabled without selector", NamespaceBinding{AuthorizeBeforeBinding: true, ClusterRoleRefs: []string{"reader"}}, false},
		{"enabled without role refs", NamespaceBinding{AuthorizeBeforeBinding: true, NamespaceSelector: selector}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator.ValidateCreate(context.Background(), &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "bridge", Annotations: map[string]string{MissingRolePolicyAnnotation: string(MissingRolePolicyIgnore)}},
				Spec: BindDefinitionSpec{
					TargetName:          "bridge",
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"}},
					ClusterRoleBindings: ClusterBinding{ClusterRoleRefs: []string{"reader"}},
					RoleBindings:        []NamespaceBinding{tc.binding},
				},
			})
			if tc.valid && err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "spec.roleBindings[0].authorizeBeforeBinding")) {
				t.Fatalf("expected authorizeBeforeBinding validation error, got %v", err)
			}
		})
	}
}

func TestRestrictedBindDefinitionRejectsBridge(t *testing.T) {
	obj := &RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "restricted-bridge"},
		Spec: RestrictedBindDefinitionSpec{
			RoleBindings: []NamespaceBinding{{
				AuthorizeBeforeBinding: true,
				NamespaceSelector:      []metav1.LabelSelector{{MatchLabels: map[string]string{LabelKeyTenant: "team-a"}}},
				ClusterRoleRefs:        []string{"reader"},
			}},
		},
	}
	err := (&RestrictedBindDefinitionValidator{}).validateRestrictedBindDefinitionSpec(context.Background(), obj)
	if err == nil || !strings.Contains(err.Error(), "spec.roleBindings[0].authorizeBeforeBinding") {
		t.Fatalf("expected restricted bridge validation error, got %v", err)
	}
}

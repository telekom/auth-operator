// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestBindDefinitionValidatorSanitizesInternalErrors(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add authorization scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add rbac scheme: %v", err)
	}

	subjects := []rbacv1.Subject{{
		Kind:     rbacv1.GroupKind,
		APIGroup: rbacv1.GroupName,
		Name:     "team-a",
	}}
	injectedErr := errors.New("backend leaked detail: token=secret, host=10.0.0.1")

	namespacedRoleBinding := NamespaceBinding{
		Namespace: "team-a",
		RoleRefs:  []string{"reader"},
	}
	selectorRoleBinding := NamespaceBinding{
		NamespaceSelector: []metav1.LabelSelector{{
			MatchLabels: map[string]string{"team": "a"},
		}},
		RoleRefs: []string{"reader"},
	}

	testCases := []struct {
		name    string
		bd      *BindDefinition
		objects []client.Object
		funcs   interceptor.Funcs
		want    string
	}{
		{
			name: "clusterrole get error",
			bd: bindDefinitionForSanitization("clusterrole-error", subjects, func(spec *BindDefinitionSpec) {
				spec.ClusterRoleBindings = ClusterBinding{ClusterRoleRefs: []string{"reader"}}
			}),
			funcs: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*rbacv1.ClusterRole); ok {
						return injectedErr
					}
					return c.Get(ctx, key, obj, opts...)
				},
			},
			want: "unable to fetch ClusterRole",
		},
		{
			name: "namespace selector list error",
			bd: bindDefinitionForSanitization("namespace-list-error", subjects, func(spec *BindDefinitionSpec) {
				spec.RoleBindings = []NamespaceBinding{selectorRoleBinding}
			}),
			funcs: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*corev1.NamespaceList); ok {
						return injectedErr
					}
					return c.List(ctx, list, opts...)
				},
			},
			want: "unable to list namespaces",
		},
		{
			name: "explicit namespace get error",
			bd: bindDefinitionForSanitization("namespace-get-error", subjects, func(spec *BindDefinitionSpec) {
				spec.RoleBindings = []NamespaceBinding{namespacedRoleBinding}
			}),
			funcs: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*corev1.Namespace); ok {
						return injectedErr
					}
					return c.Get(ctx, key, obj, opts...)
				},
			},
			want: "unable to get namespace",
		},
		{
			name: "role reference get error",
			bd: bindDefinitionForSanitization("role-get-error", subjects, func(spec *BindDefinitionSpec) {
				spec.RoleBindings = []NamespaceBinding{namespacedRoleBinding}
			}),
			objects: []client.Object{
				&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "team-a"}},
			},
			funcs: interceptor.Funcs{
				Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
					if _, ok := obj.(*rbacv1.Role); ok {
						return injectedErr
					}
					return c.Get(ctx, key, obj, opts...)
				},
			},
			want: "unable to validate role reference",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := &BindDefinitionValidator{
				Client: fake.NewClientBuilder().
					WithScheme(scheme).
					WithObjects(tc.objects...).
					WithIndex(&BindDefinition{}, TargetNameField, func(obj client.Object) []string {
						return []string{obj.(*BindDefinition).Spec.TargetName}
					}).
					WithIndex(&RestrictedBindDefinition{}, TargetNameField, func(obj client.Object) []string {
						return []string{obj.(*RestrictedBindDefinition).Spec.TargetName}
					}).
					WithInterceptorFuncs(tc.funcs).
					Build(),
			}

			_, err := validator.validateBindDefinitionSpec(context.Background(), tc.bd)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !apierrors.IsInternalError(err) {
				t.Fatalf("expected internal admission error, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error to contain %q, got %q", tc.want, err.Error())
			}
			if strings.Contains(err.Error(), injectedErr.Error()) ||
				strings.Contains(err.Error(), "token=secret") ||
				strings.Contains(err.Error(), "10.0.0.1") {
				t.Fatalf("internal admission error leaked backend details: %q", err.Error())
			}
		})
	}
}

func TestBindDefinitionValidatorRejectsRequiredAndSubjectShape(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := AddToScheme(scheme); err != nil {
		t.Fatalf("add authorization scheme: %v", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add rbac scheme: %v", err)
	}

	validator := &BindDefinitionValidator{
		Client: fake.NewClientBuilder().
			WithScheme(scheme).
			WithIndex(&BindDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*BindDefinition).Spec.TargetName}
			}).
			WithIndex(&RestrictedBindDefinition{}, TargetNameField, func(obj client.Object) []string {
				return []string{obj.(*RestrictedBindDefinition).Spec.TargetName}
			}).
			Build(),
	}

	testCases := []struct {
		name string
		bd   *BindDefinition
		want []string
	}{
		{
			name: "empty spec",
			bd: &BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "empty-spec"},
			},
			want: []string{"spec.targetName", "spec.subjects", "at least one binding"},
		},
		{
			name: "empty subject name",
			bd: bindDefinitionForSubjectValidation("empty-subject-name", []rbacv1.Subject{{
				Kind:     rbacv1.UserKind,
				APIGroup: rbacv1.GroupName,
			}}),
			want: []string{"spec.subjects[0].name", "subject name is required"},
		},
		{
			name: "user subject namespace",
			bd: bindDefinitionForSubjectValidation("user-namespace", []rbacv1.Subject{{
				Kind:      rbacv1.UserKind,
				APIGroup:  rbacv1.GroupName,
				Name:      "alice",
				Namespace: "default",
			}}),
			want: []string{"spec.subjects[0].namespace", "must not set namespace"},
		},
		{
			name: "group subject apiGroup",
			bd: bindDefinitionForSubjectValidation("group-apigroup", []rbacv1.Subject{{
				Kind:     rbacv1.GroupKind,
				APIGroup: "",
				Name:     "team-a",
			}}),
			want: []string{"spec.subjects[0].apiGroup", rbacv1.GroupName},
		},
		{
			name: "serviceaccount subject apiGroup",
			bd: bindDefinitionForSubjectValidation("serviceaccount-apigroup", []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				APIGroup:  rbacv1.GroupName,
				Name:      "robot",
				Namespace: "default",
			}}),
			want: []string{"spec.subjects[0].apiGroup", "must not set apiGroup"},
		},
		{
			name: "serviceaccount subject invalid namespace",
			bd: bindDefinitionForSubjectValidation("serviceaccount-invalid-namespace", []rbacv1.Subject{{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      "robot",
				Namespace: "Bad/Name",
			}}),
			want: []string{"spec.subjects[0].namespace", "Bad/Name"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validator.validateBindDefinitionSpec(context.Background(), tc.bd)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			got := err.Error()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("expected error to contain %q, got %q", want, got)
				}
			}
		})
	}
}

func bindDefinitionForSanitization(name string, subjects []rbacv1.Subject, mutate func(*BindDefinitionSpec)) *BindDefinition {
	spec := BindDefinitionSpec{
		TargetName: name,
		Subjects:   subjects,
	}
	mutate(&spec)
	return &BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       spec,
	}
}

func bindDefinitionForSubjectValidation(name string, subjects []rbacv1.Subject) *BindDefinition {
	return &BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				MissingRolePolicyAnnotation: string(MissingRolePolicyIgnore),
			},
		},
		Spec: BindDefinitionSpec{
			TargetName: name,
			Subjects:   subjects,
			ClusterRoleBindings: ClusterBinding{
				ClusterRoleRefs: []string{"view"},
			},
		},
	}
}

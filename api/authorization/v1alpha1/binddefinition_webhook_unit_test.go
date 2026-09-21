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
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			MatchLabels: map[string]string{LabelKeyOwner: "team-a"},
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
			want: []string{"spec.targetName", "spec.subjects", "spec: Required value", "at least one binding"},
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

func TestValidateNamespaceBindingsAllowsWellKnownTCAASLabels(t *testing.T) {
	testCases := []struct {
		name      string
		selector  metav1.LabelSelector
		wantError bool
	}{
		{
			name: "protected match expression",
			selector: metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      LabelKeyProtected,
				Operator: metav1.LabelSelectorOpDoesNotExist,
			}}},
		},
		{
			name: "protected match label",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{
				LabelKeyProtected: "true",
			}},
		},
		{
			name: "well-known domain match label",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"t-caas.telekom.com/quarantine": "true",
			}},
		},
		{
			name: "lookalike t-caas domain",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"not-t-caas.telekom.com/protected": "true",
			}},
			wantError: true,
		},
		{
			name: "matching path outside t-caas domain",
			selector: metav1.LabelSelector{MatchLabels: map[string]string{
				"example.com/protected": "true",
			}},
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateNamespaceBindings(
				schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind},
				"test-binddefinition",
				[]NamespaceBinding{{
					ClusterRoleRefs:   []string{"view"},
					NamespaceSelector: []metav1.LabelSelector{tc.selector},
				}},
			)
			if tc.wantError && err == nil {
				t.Fatal("expected selector validation error, got nil")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("expected selector to be allowed, got %v", err)
			}
		})
	}
}

// Protected classification remains part of the built-in admission contract even
// when an installation replaces the default configurable label domains.
func TestProtectedNamespaceSelectorsWithCustomLabelGroups(t *testing.T) {
	for _, kind := range []string{BindDefinitionKind, RestrictedBindDefinitionKind} {
		for _, selector := range []metav1.LabelSelector{
			{MatchLabels: map[string]string{LabelKeyProtected: "tenant-a"}},
			{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: LabelKeyProtected, Operator: metav1.LabelSelectorOpIn, Values: []string{"tenant-a"},
			}}},
			{MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key: LabelKeyProtected, Operator: metav1.LabelSelectorOpDoesNotExist,
			}}},
		} {
			t.Run(kind+"/"+metav1.FormatLabelSelector(&selector), func(t *testing.T) {
				err := validateNamespaceBindingsWithLabelGroups(
					schema.GroupKind{Group: GroupVersion.Group, Kind: kind}, "protected",
					[]NamespaceBinding{{ClusterRoleRefs: []string{"view"}, NamespaceSelector: []metav1.LabelSelector{selector}}},
					[]string{"platform.example.com"},
				)
				if err != nil {
					t.Fatalf("built-in protected selector must remain allowed: %v", err)
				}
			})
		}
	}
}

func TestValidateNamespaceBindingsUsesConfiguredLabelGroups(t *testing.T) {
	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind}
	selector := func(key string) []NamespaceBinding {
		return []NamespaceBinding{{
			ClusterRoleRefs: []string{"view"},
			NamespaceSelector: []metav1.LabelSelector{{
				MatchLabels: map[string]string{key: "true"},
			}},
		}}
	}

	if err := validateNamespaceBindingsWithLabelGroups(kind, "custom-group", selector("platform.example.com/managed"), []string{"platform.example.com"}); err != nil {
		t.Fatalf("configured label group should be allowed: %v", err)
	}
	if err := validateNamespaceBindingsWithLabelGroups(kind, "custom-group", selector("t-caas.telekom.com/quarantine"), []string{"platform.example.com"}); err == nil {
		t.Fatal("default label group should not be allowed when custom groups replace it")
	}
	if err := validateNamespaceBindingsWithLabelGroups(kind, "custom-group", selector("platform.example.com.evil/managed"), []string{"platform.example.com"}); err == nil {
		t.Fatal("lookalike label group should be rejected")
	}
}

func TestValidateNamespaceBindingsReportsMatchExpressionIndex(t *testing.T) {
	kind := schema.GroupKind{Group: GroupVersion.Group, Kind: BindDefinitionKind}
	err := validateNamespaceBindings(kind, "expression-path", []NamespaceBinding{{
		ClusterRoleRefs: []string{"view"},
		NamespaceSelector: []metav1.LabelSelector{{
			MatchExpressions: []metav1.LabelSelectorRequirement{{
				Key:      "example.com/not-allowed",
				Operator: metav1.LabelSelectorOpExists,
			}},
		}},
	}})
	if err == nil {
		t.Fatal("expected selector validation error, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "spec.roleBindings[0].namespaceSelector[0].matchExpressions[0].key") {
		t.Fatalf("expected indexed match expression path, got %q", got)
	}
}

func TestValidateNamespaceAdmissionSelectorLabelGroups(t *testing.T) {
	testCases := []struct {
		name   string
		groups []string
		valid  bool
	}{
		{name: "default", groups: nil, valid: true},
		{name: "multiple DNS domains", groups: []string{"platform.example.com", "corp.example"}, valid: true},
		{name: "empty group", groups: []string{""}, valid: false},
		{name: "wildcard group", groups: []string{"platform.example.com/*"}, valid: false},
		{name: "group with slash", groups: []string{"platform.example.com/"}, valid: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNamespaceAdmissionSelectorLabelGroups(tc.groups)
			if tc.valid && err != nil {
				t.Fatalf("expected valid groups, got %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("expected invalid groups to be rejected")
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

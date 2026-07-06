/*
Copyright © 2026 Deutsche Telekom AG
*/
package indexer

import (
	"context"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func TestIndexerConstants(t *testing.T) {
	if RoleDefinitionTargetNameField != ".spec.targetName" {
		t.Errorf("RoleDefinitionTargetNameField = %q, want %q", RoleDefinitionTargetNameField, ".spec.targetName")
	}
	if RoleDefinitionTargetRoleField != ".spec.targetRole" {
		t.Errorf("RoleDefinitionTargetRoleField = %q, want %q", RoleDefinitionTargetRoleField, ".spec.targetRole")
	}
	if RoleDefinitionTargetNamespaceField != ".spec.targetNamespace" {
		t.Errorf("RoleDefinitionTargetNamespaceField = %q, want %q", RoleDefinitionTargetNamespaceField, ".spec.targetNamespace")
	}
	if BindDefinitionTargetNameField != ".spec.targetName" {
		t.Errorf("BindDefinitionTargetNameField = %q, want %q", BindDefinitionTargetNameField, ".spec.targetName")
	}
	if WebhookAuthorizerHasNamespaceSelectorField != ".spec.hasNamespaceSelector" {
		t.Errorf("WebhookAuthorizerHasNamespaceSelectorField = %q, want %q",
			WebhookAuthorizerHasNamespaceSelectorField, ".spec.hasNamespaceSelector")
	}
	if RestrictedBindDefinitionServiceAccountSubjectField != ".spec.subjects.serviceAccount" {
		t.Errorf("RestrictedBindDefinitionServiceAccountSubjectField = %q, want %q",
			RestrictedBindDefinitionServiceAccountSubjectField, ".spec.subjects.serviceAccount")
	}
	if RestrictedBindDefinitionServiceAccountSubjectNamespaceField != ".spec.subjects.serviceAccountNamespace" {
		t.Errorf("RestrictedBindDefinitionServiceAccountSubjectNamespaceField = %q, want %q",
			RestrictedBindDefinitionServiceAccountSubjectNamespaceField, ".spec.subjects.serviceAccountNamespace")
	}
	if RBACPolicyHasDefaultAssignmentField != ".spec.hasDefaultAssignment" {
		t.Errorf("RBACPolicyHasDefaultAssignmentField = %q, want %q",
			RBACPolicyHasDefaultAssignmentField, ".spec.hasDefaultAssignment")
	}
}

// indexExtractorTest represents a test case for index extractor functions
type indexExtractorTest struct {
	name       string
	object     client.Object
	indexFunc  func(client.Object) []string
	wantValues []string
}

// runIndexExtractorTests runs a set of index extractor test cases
func runIndexExtractorTests(t *testing.T, tests []indexExtractorTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.indexFunc(tt.object)
			if len(got) != len(tt.wantValues) {
				t.Errorf("indexFunc() returned %v, want %v", got, tt.wantValues)
				return
			}
			for i := range got {
				if got[i] != tt.wantValues[i] {
					t.Errorf("indexFunc()[%d] = %q, want %q", i, got[i], tt.wantValues[i])
				}
			}
		})
	}
}

func TestBindDefinitionHasRoleBindingsIndexWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	subject := rbacv1.Subject{Kind: rbacv1.UserKind, Name: "alice"}

	bdWithRoleBindings := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "bd-with-rb"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "with-rb",
			Subjects:   []rbacv1.Subject{subject},
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{
				{ClusterRoleRefs: []string{"view"}},
			},
		},
	}

	bdWithoutRoleBindings := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "bd-without-rb"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "without-rb",
			Subjects:   []rbacv1.Subject{subject},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(bdWithRoleBindings, bdWithoutRoleBindings).
		WithIndex(
			&authorizationv1alpha1.BindDefinition{},
			BindDefinitionHasRoleBindingsField,
			BindDefinitionHasRoleBindingsFunc,
		).
		Build()

	ctx := context.Background()

	var withRB authorizationv1alpha1.BindDefinitionList
	if err := fakeClient.List(ctx, &withRB, client.MatchingFields{BindDefinitionHasRoleBindingsField: BindDefinitionHasRoleBindingsTrue}); err != nil {
		t.Fatalf("failed to list BindDefinitions with role bindings: %v", err)
	}
	if len(withRB.Items) != 1 {
		t.Errorf("expected 1 BindDefinition with role bindings, got %d", len(withRB.Items))
	} else if withRB.Items[0].Name != "bd-with-rb" {
		t.Errorf("expected bd-with-rb, got %s", withRB.Items[0].Name)
	}

	var withoutRB authorizationv1alpha1.BindDefinitionList
	if err := fakeClient.List(ctx, &withoutRB, client.MatchingFields{BindDefinitionHasRoleBindingsField: BindDefinitionHasRoleBindingsFalse}); err != nil {
		t.Fatalf("failed to list BindDefinitions without role bindings: %v", err)
	}
	if len(withoutRB.Items) != 0 {
		t.Errorf("expected sparse false index to return 0 BindDefinitions, got %d", len(withoutRB.Items))
	}
}

func TestRoleDefinitionIndexExtractor(t *testing.T) {
	runIndexExtractorTests(t, []indexExtractorTest{
		{
			name: "valid RoleDefinition with targetName",
			object: &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rd",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName: "test-role",
				},
			},
			indexFunc:  RoleDefinitionTargetNameFunc,
			wantValues: []string{"test-role"},
		},
		{
			name: "RoleDefinition with empty targetName",
			object: &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rd",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName: "",
				},
			},
			indexFunc:  RoleDefinitionTargetNameFunc,
			wantValues: nil,
		},
		{
			name: "valid RoleDefinition with targetRole",
			object: &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-rd"},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: authorizationv1alpha1.DefinitionNamespacedRole,
				},
			},
			indexFunc:  RoleDefinitionTargetRoleFunc,
			wantValues: []string{authorizationv1alpha1.DefinitionNamespacedRole},
		},
		{
			name: "valid RoleDefinition with targetNamespace",
			object: &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-rd"},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetNamespace: "team-a",
				},
			},
			indexFunc:  RoleDefinitionTargetNamespaceFunc,
			wantValues: []string{"team-a"},
		},
	})
}

func TestBindDefinitionIndexExtractor(t *testing.T) {
	indexFunc := func(obj client.Object) []string {
		bd, ok := obj.(*authorizationv1alpha1.BindDefinition)
		if !ok || bd.Spec.TargetName == "" {
			return nil
		}
		return []string{bd.Spec.TargetName}
	}

	runIndexExtractorTests(t, []indexExtractorTest{
		{
			name: "valid BindDefinition with targetName",
			object: &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-binding",
				},
			},
			indexFunc:  indexFunc,
			wantValues: []string{"test-binding"},
		},
		{
			name: "BindDefinition with empty targetName",
			object: &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "",
				},
			},
			indexFunc:  indexFunc,
			wantValues: nil,
		},
	})
}

func TestIndexerWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	rd1 := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rd-1",
			Namespace: "default",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName: "shared-target",
		},
	}
	rd2 := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rd-2",
			Namespace: "default",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName: "shared-target",
		},
	}
	rd3 := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rd-3",
			Namespace: "default",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName: "unique-target",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(rd1, rd2, rd3).
		WithIndex(&authorizationv1alpha1.RoleDefinition{}, RoleDefinitionTargetNameField, func(obj client.Object) []string {
			rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
			if !ok || rd.Spec.TargetName == "" {
				return nil
			}
			return []string{rd.Spec.TargetName}
		}).
		Build()

	ctx := context.Background()

	var list authorizationv1alpha1.RoleDefinitionList
	err := fakeClient.List(ctx, &list, client.MatchingFields{RoleDefinitionTargetNameField: "shared-target"})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}

	if len(list.Items) != 2 {
		t.Errorf("expected 2 RoleDefinitions with shared-target, got %d", len(list.Items))
	}

	list = authorizationv1alpha1.RoleDefinitionList{}
	err = fakeClient.List(ctx, &list, client.MatchingFields{RoleDefinitionTargetNameField: "unique-target"})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}

	if len(list.Items) != 1 {
		t.Errorf("expected 1 RoleDefinition with unique-target, got %d", len(list.Items))
	}

	list = authorizationv1alpha1.RoleDefinitionList{}
	err = fakeClient.List(ctx, &list, client.MatchingFields{RoleDefinitionTargetNameField: "non-existent"})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}

	if len(list.Items) != 0 {
		t.Errorf("expected 0 RoleDefinitions with non-existent target, got %d", len(list.Items))
	}
}

func TestRoleDefinitionScopedTargetIndexesWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	rdTeamA := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rd-team-a"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName:      "reader",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetNamespace: "team-a",
		},
	}
	rdTeamB := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rd-team-b"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName:      "reader",
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetNamespace: "team-b",
		},
	}
	rdCluster := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rd-cluster"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetName: "reader",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(rdTeamA, rdTeamB, rdCluster).
		WithIndex(&authorizationv1alpha1.RoleDefinition{}, RoleDefinitionTargetNameField, RoleDefinitionTargetNameFunc).
		WithIndex(&authorizationv1alpha1.RoleDefinition{}, RoleDefinitionTargetRoleField, RoleDefinitionTargetRoleFunc).
		WithIndex(&authorizationv1alpha1.RoleDefinition{}, RoleDefinitionTargetNamespaceField, RoleDefinitionTargetNamespaceFunc).
		Build()

	var list authorizationv1alpha1.RoleDefinitionList
	if err := fakeClient.List(context.Background(), &list, client.MatchingFields{
		RoleDefinitionTargetNameField:      "reader",
		RoleDefinitionTargetRoleField:      authorizationv1alpha1.DefinitionNamespacedRole,
		RoleDefinitionTargetNamespaceField: "team-a",
	}); err != nil {
		t.Fatalf("failed to list scoped RoleDefinitions: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "rd-team-a" {
		t.Fatalf("expected only rd-team-a, got %#v", list.Items)
	}

	list = authorizationv1alpha1.RoleDefinitionList{}
	if err := fakeClient.List(context.Background(), &list, client.MatchingFields{
		RoleDefinitionTargetNameField: "reader",
		RoleDefinitionTargetRoleField: authorizationv1alpha1.DefinitionClusterRole,
	}); err != nil {
		t.Fatalf("failed to list cluster RoleDefinitions: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != "rd-cluster" {
		t.Fatalf("expected only rd-cluster, got %#v", list.Items)
	}
}

func TestIndexerWithWrongObjectType(t *testing.T) {
	indexFunc := func(obj client.Object) []string {
		rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
		if !ok || rd.Spec.TargetName == "" {
			return nil
		}
		return []string{rd.Spec.TargetName}
	}

	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-bd",
			Namespace: "default",
		},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
		},
	}

	result := indexFunc(bd)
	if result != nil {
		t.Errorf("expected nil for wrong object type, got %v", result)
	}
}

func TestWebhookAuthorizerHasNamespaceSelectorFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "with non-empty namespace selector returns true",
			object: &authorizationv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-scoped"},
				Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{"env": "prod"},
					},
				},
			},
			indexFunc:  WebhookAuthorizerHasNamespaceSelectorFunc,
			wantValues: []string{WebhookAuthorizerHasNamespaceSelectorTrue},
		},
		{
			name: "with empty namespace selector returns false",
			object: &authorizationv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-global"},
				Spec:       authorizationv1alpha1.WebhookAuthorizerSpec{},
			},
			indexFunc:  WebhookAuthorizerHasNamespaceSelectorFunc,
			wantValues: []string{WebhookAuthorizerHasNamespaceSelectorFalse},
		},
		{
			name: "with match expressions returns true",
			object: &authorizationv1alpha1.WebhookAuthorizer{
				ObjectMeta: metav1.ObjectMeta{Name: "wa-expr"},
				Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
					NamespaceSelector: metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend"}},
						},
					},
				},
			},
			indexFunc:  WebhookAuthorizerHasNamespaceSelectorFunc,
			wantValues: []string{WebhookAuthorizerHasNamespaceSelectorTrue},
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd"}},
			indexFunc:  WebhookAuthorizerHasNamespaceSelectorFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestWebhookAuthorizerIndexWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	waGlobal := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-global"},
		Spec:       authorizationv1alpha1.WebhookAuthorizerSpec{},
	}
	waScoped := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-scoped"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"env": "prod"},
			},
		},
	}
	waScoped2 := &authorizationv1alpha1.WebhookAuthorizer{
		ObjectMeta: metav1.ObjectMeta{Name: "wa-scoped-2"},
		Spec: authorizationv1alpha1.WebhookAuthorizerSpec{
			NamespaceSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpExists},
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(waGlobal, waScoped, waScoped2).
		WithIndex(
			&authorizationv1alpha1.WebhookAuthorizer{},
			WebhookAuthorizerHasNamespaceSelectorField,
			WebhookAuthorizerHasNamespaceSelectorFunc,
		).
		Build()

	ctx := context.Background()

	// Query global authorizers (no namespace selector).
	var globalList authorizationv1alpha1.WebhookAuthorizerList
	err := fakeClient.List(ctx, &globalList, client.MatchingFields{
		WebhookAuthorizerHasNamespaceSelectorField: WebhookAuthorizerHasNamespaceSelectorFalse,
	})
	if err != nil {
		t.Fatalf("failed to list global authorizers: %v", err)
	}
	if len(globalList.Items) != 1 {
		t.Errorf("expected 1 global authorizer, got %d", len(globalList.Items))
	} else if globalList.Items[0].Name != "wa-global" {
		t.Errorf("expected wa-global, got %s", globalList.Items[0].Name)
	}

	// Query scoped authorizers (with namespace selector).
	var scopedList authorizationv1alpha1.WebhookAuthorizerList
	err = fakeClient.List(ctx, &scopedList, client.MatchingFields{
		WebhookAuthorizerHasNamespaceSelectorField: WebhookAuthorizerHasNamespaceSelectorTrue,
	})
	if err != nil {
		t.Fatalf("failed to list scoped authorizers: %v", err)
	}
	if len(scopedList.Items) != 2 {
		t.Errorf("expected 2 scoped authorizers, got %d", len(scopedList.Items))
	}

	// Query non-existent index value returns empty.
	var emptyList authorizationv1alpha1.WebhookAuthorizerList
	err = fakeClient.List(ctx, &emptyList, client.MatchingFields{
		WebhookAuthorizerHasNamespaceSelectorField: "invalid",
	})
	if err != nil {
		t.Fatalf("failed to list with invalid index value: %v", err)
	}
	if len(emptyList.Items) != 0 {
		t.Errorf("expected 0 authorizers for invalid index value, got %d", len(emptyList.Items))
	}
}

func TestBindDefinitionHasRoleBindingsFunc(t *testing.T) {
	subject := rbacv1.Subject{Kind: rbacv1.UserKind, Name: "alice"}

	tests := []indexExtractorTest{
		{
			name: "BD with RoleBindings returns true",
			object: &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "bd-with-rb"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "with-rb",
					Subjects:   []rbacv1.Subject{subject},
					RoleBindings: []authorizationv1alpha1.NamespaceBinding{
						{ClusterRoleRefs: []string{"view"}},
					},
				},
			},
			indexFunc:  BindDefinitionHasRoleBindingsFunc,
			wantValues: []string{BindDefinitionHasRoleBindingsTrue},
		},
		{
			name: "BD without RoleBindings is omitted from sparse index",
			object: &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "bd-without-rb"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "without-rb",
					Subjects:   []rbacv1.Subject{subject},
				},
			},
			indexFunc:  BindDefinitionHasRoleBindingsFunc,
			wantValues: nil,
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd"}},
			indexFunc:  BindDefinitionHasRoleBindingsFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRBACPolicyHasDefaultAssignmentFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "policy with defaultAssignment returns true",
			object: &authorizationv1alpha1.RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-with-default"},
				Spec: authorizationv1alpha1.RBACPolicySpec{
					DefaultAssignment: &authorizationv1alpha1.DefaultPolicyAssignment{
						Groups: []string{"oidc:team-a"},
					},
				},
			},
			indexFunc:  RBACPolicyHasDefaultAssignmentFunc,
			wantValues: []string{"true"},
		},
		{
			name: "policy without defaultAssignment returns false",
			object: &authorizationv1alpha1.RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "policy-without-default"},
			},
			indexFunc:  RBACPolicyHasDefaultAssignmentFunc,
			wantValues: []string{"false"},
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd"}},
			indexFunc:  RBACPolicyHasDefaultAssignmentFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRBACPolicyHasDefaultAssignmentIndexWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	withDefault := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "with-default"},
		Spec: authorizationv1alpha1.RBACPolicySpec{
			DefaultAssignment: &authorizationv1alpha1.DefaultPolicyAssignment{
				Groups: []string{"oidc:team-a"},
			},
		},
	}
	withoutDefault := &authorizationv1alpha1.RBACPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "without-default"},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(withDefault, withoutDefault).
		WithIndex(
			&authorizationv1alpha1.RBACPolicy{},
			RBACPolicyHasDefaultAssignmentField,
			RBACPolicyHasDefaultAssignmentFunc,
		).
		Build()

	var withDefaultList authorizationv1alpha1.RBACPolicyList
	if err := fakeClient.List(context.Background(), &withDefaultList, client.MatchingFields{
		RBACPolicyHasDefaultAssignmentField: "true",
	}); err != nil {
		t.Fatalf("failed to list RBACPolicies with defaultAssignment: %v", err)
	}
	if len(withDefaultList.Items) != 1 || withDefaultList.Items[0].Name != "with-default" {
		t.Fatalf("expected only with-default, got %#v", withDefaultList.Items)
	}

	var withoutDefaultList authorizationv1alpha1.RBACPolicyList
	if err := fakeClient.List(context.Background(), &withoutDefaultList, client.MatchingFields{
		RBACPolicyHasDefaultAssignmentField: "false",
	}); err != nil {
		t.Fatalf("failed to list RBACPolicies without defaultAssignment: %v", err)
	}
	if len(withoutDefaultList.Items) != 1 || withoutDefaultList.Items[0].Name != "without-default" {
		t.Fatalf("expected only without-default, got %#v", withoutDefaultList.Items)
	}
}

func TestRestrictedBindDefinitionPolicyRefFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "with policy ref returns name",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-1"},
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "my-policy"},
				},
			},
			indexFunc:  RestrictedBindDefinitionPolicyRefFunc,
			wantValues: []string{"my-policy"},
		},
		{
			name: "with empty policy ref returns nil",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-2"},
				Spec:       authorizationv1alpha1.RestrictedBindDefinitionSpec{},
			},
			indexFunc:  RestrictedBindDefinitionPolicyRefFunc,
			wantValues: nil,
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.RoleDefinition{ObjectMeta: metav1.ObjectMeta{Name: "rd"}},
			indexFunc:  RestrictedBindDefinitionPolicyRefFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRestrictedRoleDefinitionPolicyRefFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "with policy ref returns name",
			object: &authorizationv1alpha1.RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rrd-1"},
				Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
					PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "team-policy"},
				},
			},
			indexFunc:  RestrictedRoleDefinitionPolicyRefFunc,
			wantValues: []string{"team-policy"},
		},
		{
			name: "with empty policy ref returns nil",
			object: &authorizationv1alpha1.RestrictedRoleDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rrd-2"},
				Spec:       authorizationv1alpha1.RestrictedRoleDefinitionSpec{},
			},
			indexFunc:  RestrictedRoleDefinitionPolicyRefFunc,
			wantValues: nil,
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bd"}},
			indexFunc:  RestrictedRoleDefinitionPolicyRefFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRestrictedBindDefinitionServiceAccountSubjectFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "serviceaccount subjects return namespace name keys",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-sa"},
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-b", Name: "runner"},
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "devs"},
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-a", Name: "runner"},
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-b", Name: "runner"},
					},
				},
			},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectFunc,
			wantValues: []string{"team-a/runner", "team-b/runner"},
		},
		{
			name: "serviceaccount subject without namespace is ignored",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-sa-empty-ns"},
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "runner"},
					},
				},
			},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectFunc,
			wantValues: nil,
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bd"}},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRestrictedBindDefinitionServiceAccountSubjectNamespaceFunc(t *testing.T) {
	tests := []indexExtractorTest{
		{
			name: "serviceaccount subjects return sorted unique namespaces",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-sa-ns"},
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-b", Name: "runner"},
						{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "devs"},
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-a", Name: "runner"},
						{Kind: rbacv1.ServiceAccountKind, Namespace: "team-b", Name: "builder"},
					},
				},
			},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectNamespaceFunc,
			wantValues: []string{"team-a", "team-b"},
		},
		{
			name: "serviceaccount subject without namespace is ignored",
			object: &authorizationv1alpha1.RestrictedBindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "rbd-sa-empty-ns"},
				Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "runner"},
					},
				},
			},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectNamespaceFunc,
			wantValues: nil,
		},
		{
			name:       "wrong object type returns nil",
			object:     &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bd"}},
			indexFunc:  RestrictedBindDefinitionServiceAccountSubjectNamespaceFunc,
			wantValues: nil,
		},
	}

	runIndexExtractorTests(t, tests)
}

func TestRestrictedBindDefinitionPolicyRefWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	rbd1 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rbd-1"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "shared-policy"},
		},
	}
	rbd2 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rbd-2"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "shared-policy"},
		},
	}
	rbd3 := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rbd-3"},
		Spec: authorizationv1alpha1.RestrictedBindDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "other-policy"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(rbd1, rbd2, rbd3).
		WithIndex(
			&authorizationv1alpha1.RestrictedBindDefinition{},
			RestrictedBindDefinitionPolicyRefField,
			RestrictedBindDefinitionPolicyRefFunc,
		).
		Build()

	ctx := context.Background()

	var list authorizationv1alpha1.RestrictedBindDefinitionList
	err := fakeClient.List(ctx, &list, client.MatchingFields{
		RestrictedBindDefinitionPolicyRefField: "shared-policy",
	})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list.Items) != 2 {
		t.Errorf("expected 2 RestrictedBindDefinitions with shared-policy, got %d", len(list.Items))
	}

	list = authorizationv1alpha1.RestrictedBindDefinitionList{}
	err = fakeClient.List(ctx, &list, client.MatchingFields{
		RestrictedBindDefinitionPolicyRefField: "other-policy",
	})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 RestrictedBindDefinition with other-policy, got %d", len(list.Items))
	}

	list = authorizationv1alpha1.RestrictedBindDefinitionList{}
	err = fakeClient.List(ctx, &list, client.MatchingFields{
		RestrictedBindDefinitionPolicyRefField: "nonexistent",
	})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("expected 0 RestrictedBindDefinitions with nonexistent, got %d", len(list.Items))
	}
}

func TestRestrictedRoleDefinitionPolicyRefWithFakeClient(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := authorizationv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add scheme: %v", err)
	}

	rrd1 := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rrd-1"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "shared-policy"},
		},
	}
	rrd2 := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "rrd-2"},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			PolicyRef: authorizationv1alpha1.RBACPolicyReference{Name: "unique-policy"},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithRuntimeObjects(rrd1, rrd2).
		WithIndex(
			&authorizationv1alpha1.RestrictedRoleDefinition{},
			RestrictedRoleDefinitionPolicyRefField,
			RestrictedRoleDefinitionPolicyRefFunc,
		).
		Build()

	ctx := context.Background()

	var list authorizationv1alpha1.RestrictedRoleDefinitionList
	err := fakeClient.List(ctx, &list, client.MatchingFields{
		RestrictedRoleDefinitionPolicyRefField: "shared-policy",
	})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 RestrictedRoleDefinition with shared-policy, got %d", len(list.Items))
	}

	list = authorizationv1alpha1.RestrictedRoleDefinitionList{}
	err = fakeClient.List(ctx, &list, client.MatchingFields{
		RestrictedRoleDefinitionPolicyRefField: "nonexistent",
	})
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("expected 0 RestrictedRoleDefinitions with nonexistent, got %d", len(list.Items))
	}
}

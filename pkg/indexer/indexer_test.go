/*
Copyright © 2026 Deutsche Telekom AG
*/
package indexer

import (
	"context"
	"testing"

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
	if BindDefinitionTargetNameField != ".spec.targetName" {
		t.Errorf("BindDefinitionTargetNameField = %q, want %q", BindDefinitionTargetNameField, ".spec.targetName")
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

func TestRoleDefinitionIndexExtractor(t *testing.T) {
	indexFunc := func(obj client.Object) []string {
		rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
		if !ok || rd.Spec.TargetName == "" {
			return nil
		}
		return []string{rd.Spec.TargetName}
	}

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
			indexFunc:  indexFunc,
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
			indexFunc:  indexFunc,
			wantValues: nil,
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

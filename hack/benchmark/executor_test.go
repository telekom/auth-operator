// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestCleanupCellUsesOwnedLabel(t *testing.T) {
	s, _ := specFor("serviceaccount")
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		apiVersionField: "v1", kindField: kindServiceAccount,
		metadataField: map[string]interface{}{
			"name": "owned", "namespace": "bench",
			labelsField: map[string]interface{}{"t-caas.telekom.com/benchmark": benchmarkLabelValue},
		},
	}}
	cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{s.gvr: "ServiceAccountList"})
	_, _ = cl.Resource(s.gvr).Namespace("bench").Create(context.Background(), u, metav1.CreateOptions{})
	if e := cleanupCell(context.Background(), cl, s, "bench"); e != nil {
		t.Fatal(e)
	}
	if _, e := cl.Resource(s.gvr).Namespace("bench").Get(context.Background(), "owned", metav1.GetOptions{}); !apierrors.IsNotFound(e) {
		t.Fatalf("owned object remains after cleanup: %v", e)
	}
}

func TestObjectForUsesCanonicalKindsAndServiceAccountSubjects(t *testing.T) {
	for resource, wantKind := range map[string]string{
		resourceServiceAccount:     "ServiceAccount",
		resourceRoleBinding:        "RoleBinding",
		resourceClusterRoleBinding: "ClusterRoleBinding",
		resourceBindDefinition:     "BindDefinition",
	} {
		cell := Cell{Engine: engineMap, Tier: "t1", Mode: modeProtect, RunID: fallbackRunID, Phase: phaseCreate, Kind: resource}
		s, err := specFor(resource)
		if err != nil {
			t.Fatal(err)
		}
		u := objectFor(cell, "object", "bench", s)
		if got := u.GetKind(); got != wantKind {
			t.Fatalf("%s kind = %q, want %q", resource, got, wantKind)
		}
		var subject map[string]interface{}
		switch resource {
		case resourceRoleBinding, resourceClusterRoleBinding:
			subjects, _, err := unstructured.NestedSlice(u.Object, "subjects")
			if err != nil || len(subjects) != 1 {
				t.Fatalf("%s subjects = %#v, err %v", resource, subjects, err)
			}
			subject, _ = subjects[0].(map[string]interface{})
		case resourceBindDefinition:
			subjects, _, err := unstructured.NestedSlice(u.Object, "spec", "subjects")
			if err != nil || len(subjects) != 1 {
				t.Fatalf("BindDefinition subjects = %#v, err %v", subjects, err)
			}
			subject, _ = subjects[0].(map[string]interface{})
		}
		if _, found := subject[apiGroupField]; found {
			t.Fatalf("%s ServiceAccount subject has apiGroup", resource)
		}
	}
}

func TestCleanupResourceKindsIncludesSelectedIsolationResource(t *testing.T) {
	selected := resourceRoleDefinition
	got := cleanupResourceKinds(nil, selected)
	if !reflect.DeepEqual(got, []string{selected}) {
		t.Fatalf("isolation cleanup kinds = %#v, want %#v", got, []string{selected})
	}
	mix := []string{resourceServiceAccount, resourceRole}
	if got := cleanupResourceKinds(mix, selected); !reflect.DeepEqual(got, mix) {
		t.Fatalf("tier cleanup kinds = %#v, want %#v", got, mix)
	}
}

func TestObjectForAnnotatesIsolationScope(t *testing.T) {
	s, err := specFor(resourceRole)
	if err != nil {
		t.Fatal(err)
	}
	u := objectFor(Cell{Engine: engineMap, Tier: "iso-" + isolationRBACGroup, Mode: modeProtect, Kind: resourceRole}, "object", "", s)
	got, _, err := unstructured.NestedString(u.Object, metadataField, annotationsField, "t-caas.telekom.com/benchmark-scope")
	if err != nil || got != isolationRBACGroup {
		t.Fatalf("isolation scope = %q, err %v", got, err)
	}
}

func TestJournalStateReflectsCleanupFailure(t *testing.T) {
	if got := journalState(fmt.Errorf("cleanup failed")); got != statusFailed {
		t.Fatalf("journal state after cleanup failure = %q, want %q", got, statusFailed)
	}
	if got := journalState(nil); got != statusComplete {
		t.Fatalf("journal state without cleanup failure = %q, want %q", got, statusComplete)
	}
}

func TestMixedObjectsHaveValidReferences(t *testing.T) {
	cell := Cell{Engine: "map", Tier: "t4", Mode: "protect", RunID: "run-1", Phase: "create"}
	for _, kind := range []string{"serviceaccount", "role", "rolebinding", "clusterrole", "clusterrolebinding", "roledefinition", "binddefinition"} {
		cell.Kind = kind
		s, err := specFor(kind)
		if err != nil {
			t.Fatal(err)
		}
		u := objectFor(cell, dependencyName(cell), "bench", s)
		if kind == "rolebinding" || kind == "clusterrolebinding" {
			ref, found, _ := unstructured.NestedString(u.Object, "roleRef", "name")
			if !found || ref != dependencyName(cell) {
				t.Fatalf("%s role reference = %q", kind, ref)
			}
		}
		if kind == "binddefinition" {
			refs, found, _ := unstructured.NestedStringSlice(u.Object, "spec", "clusterRoleBindings", "clusterRoleRefs")
			if !found || !reflect.DeepEqual(refs, []string{dependencyName(cell)}) {
				t.Fatalf("bind references = %#v", refs)
			}
		}
	}
}

func TestDeleteAndWaitOwnedDependentsHonorsOwnerUID(t *testing.T) {
	s, _ := specFor("clusterrole")
	owner := types.UID("definition-1")
	owned := objectFor(Cell{Engine: "map", Tier: "t4", Mode: "protect", RunID: "run-1", Kind: "clusterrole"}, "owned", "", s)
	owned.SetOwnerReferences([]metav1.OwnerReference{{UID: owner}})
	foreign := objectFor(Cell{Engine: "map", Tier: "t4", Mode: "protect", RunID: "other", Kind: "clusterrole"}, "foreign", "", s)
	cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{s.gvr: "ClusterRoleList"})
	_, _ = cl.Resource(s.gvr).Create(context.Background(), owned, metav1.CreateOptions{})
	_, _ = cl.Resource(s.gvr).Create(context.Background(), foreign, metav1.CreateOptions{})
	if err := deleteAndWaitOwnedDependents(context.Background(), cl.Resource(s.gvr), map[types.UID]bool{owner: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Resource(s.gvr).Get(context.Background(), "owned", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("owned dependent remains: %v", err)
	}
	if _, err := cl.Resource(s.gvr).Get(context.Background(), "foreign", metav1.GetOptions{}); err != nil {
		t.Fatalf("foreign object removed: %v", err)
	}
}

func TestCleanupOwnedDependentsPropagatesListError(t *testing.T) {
	listKinds := map[schema.GroupVersionResource]string{
		resourceSpecs["serviceaccount"].gvr:     "ServiceAccountList",
		resourceSpecs["role"].gvr:               "RoleList",
		resourceSpecs["rolebinding"].gvr:        "RoleBindingList",
		resourceSpecs["clusterrole"].gvr:        "ClusterRoleList",
		resourceSpecs["clusterrolebinding"].gvr: "ClusterRoleBindingList",
	}
	cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	cl.PrependReactor("list", "clusterroles", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("simulated RBAC discovery outage")
	})
	if err := cleanupOwnedDependentsWithClient(context.Background(), cl, []types.UID{"owner"}); err == nil || !strings.Contains(err.Error(), "clusterrole") {
		t.Fatalf("expected clusterrole list error, got %v", err)
	}
}

func TestCollectDefinitionUIDsPropagatesListError(t *testing.T) {
	s, _ := specFor("roledefinition")
	cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{s.gvr: "RoleDefinitionList"})
	cl.PrependReactor("list", "roledefinitions", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("simulated definition API outage")
	})
	if _, err := collectDefinitionUIDsWithClient(context.Background(), cl, "bench", "run", ""); err == nil || !strings.Contains(err.Error(), "roledefinition") {
		t.Fatalf("expected roledefinition list error, got %v", err)
	}
}

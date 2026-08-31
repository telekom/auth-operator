// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
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
	foreign := u.DeepCopy()
	foreign.SetName("foreign")
	foreign.SetLabels(map[string]string{"t-caas.telekom.com/benchmark": "other"})
	cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{s.gvr: "ServiceAccountList"})
	_, _ = cl.Resource(s.gvr).Namespace("bench").Create(context.Background(), u, metav1.CreateOptions{})
	_, _ = cl.Resource(s.gvr).Namespace("bench").Create(context.Background(), foreign, metav1.CreateOptions{})
	if e := cleanupCell(context.Background(), cl, s, "bench"); e != nil {
		t.Fatal(e)
	}
	if _, e := cl.Resource(s.gvr).Namespace("bench").Get(context.Background(), "owned", metav1.GetOptions{}); !apierrors.IsNotFound(e) {
		t.Fatalf("owned object remains after cleanup: %v", e)
	}
	if _, e := cl.Resource(s.gvr).Namespace("bench").Get(context.Background(), "foreign", metav1.GetOptions{}); e != nil {
		t.Fatalf("foreign object was removed: %v", e)
	}
}

func TestObjectForUsesCanonicalKindsAndServiceAccountSubjects(t *testing.T) {
	for resource, wantKind := range map[string]string{
		resourceServiceAccount:     kindServiceAccount,
		resourceRoleBinding:        kindRoleBinding,
		resourceClusterRoleBinding: kindClusterRoleBinding,
		resourceBindDefinition:     kindBindDefinition,
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

func TestObjectForUsesCanonicalKinds(t *testing.T) {
	want := map[string]string{
		resourceNamespace:          kindNamespace,
		resourceServiceAccount:     kindServiceAccount,
		resourceSecret:             kindSecret,
		resourceRole:               kindRole,
		resourceRoleBinding:        kindRoleBinding,
		resourceClusterRole:        kindClusterRole,
		resourceClusterRoleBinding: kindClusterRoleBinding,
		resourceRoleDefinition:     kindRoleDefinition,
		resourceBindDefinition:     kindBindDefinition,
		resourceRBACPolicy:         kindRBACPolicy,
	}
	for resource, expectedKind := range want {
		t.Run(resource, func(t *testing.T) {
			s, err := specFor(resource)
			if err != nil {
				t.Fatal(err)
			}
			cell := Cell{Engine: engineMap, Tier: "t4", Mode: modeProtect, RunID: "run-1", Kind: resource}
			if got := objectFor(cell, "object", "bench", s).GetKind(); got != expectedKind {
				t.Fatalf("generated kind = %q, want %q", got, expectedKind)
			}
		})
	}
}

func TestRBACSubjectAPIGroupSemantics(t *testing.T) {
	for _, resource := range []string{resourceRoleBinding, resourceClusterRoleBinding} {
		t.Run(resource, func(t *testing.T) {
			s, err := specFor(resource)
			if err != nil {
				t.Fatal(err)
			}
			cell := Cell{Engine: engineMap, Tier: "t4", Mode: modeProtect, RunID: "run-1", Kind: resource}
			subjects, found, err := unstructured.NestedSlice(objectFor(cell, "object", "bench", s).Object, "subjects")
			if err != nil || !found || len(subjects) != 1 {
				t.Fatalf("subjects = %#v, found=%t, err=%v", subjects, found, err)
			}
			subject, ok := subjects[0].(map[string]interface{})
			if !ok {
				t.Fatalf("subject has unexpected type %T", subjects[0])
			}
			if _, found := subject[apiGroupField]; found {
				t.Fatalf("ServiceAccount subject unexpectedly has apiGroup: %#v", subject)
			}
		})
	}
	t.Run(resourceBindDefinition, func(t *testing.T) {
		s, err := specFor(resourceBindDefinition)
		if err != nil {
			t.Fatal(err)
		}
		cell := Cell{Engine: engineMap, Tier: "t4", Mode: modeProtect, RunID: "run-1", Kind: resourceBindDefinition}
		subjects, found, err := unstructured.NestedSlice(objectFor(cell, "object", "bench", s).Object, "spec", "subjects")
		if err != nil || !found || len(subjects) != 1 {
			t.Fatalf("subjects = %#v, found=%t, err=%v", subjects, found, err)
		}
		subject, ok := subjects[0].(map[string]interface{})
		if !ok {
			t.Fatalf("subject has unexpected type %T", subjects[0])
		}
		if _, found := subject[apiGroupField]; found {
			t.Fatalf("BindDefinition ServiceAccount subject unexpectedly has apiGroup: %#v", subject)
		}
	})
	for _, kind := range []string{"User", "Group"} {
		t.Run(kind, func(t *testing.T) {
			subject := subjectFor(kind, "subject", "bench")
			if got := subject[apiGroupField]; got != rbacv1.GroupName {
				t.Fatalf("apiGroup = %#v, want %q", got, rbacv1.GroupName)
			}
			if _, found := subject[resourceNamespace]; found {
				t.Fatalf("%s subject unexpectedly has namespace: %#v", kind, subject)
			}
		})
	}
}

func TestMetricDeltaCounterPreservesTelemetryState(t *testing.T) {
	metricName := "benchmark_counter"
	for _, test := range []struct {
		name  string
		state MetricState
		code  int
	}{
		{name: "unauthorized", state: MetricUnauthorized, code: 403},
		{name: "unavailable", state: MetricUnavailable, code: 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := MetricsSnapshot{StatusCode: http.StatusOK, State: MetricAvailable, Body: metricName + " 4\n"}
			after := MetricsSnapshot{StatusCode: test.code, State: test.state}
			got := metricDeltaCounter(before, after, metricName)
			if got.State != test.state || got.Value != 0 {
				t.Fatalf("delta = %#v, want state=%q and zero value", got, test.state)
			}
		})
	}
	reset := metricDeltaCounter(
		MetricsSnapshot{StatusCode: http.StatusOK, State: MetricAvailable, Body: metricName + " 10\n"},
		MetricsSnapshot{StatusCode: http.StatusOK, State: MetricAvailable, Body: metricName + " 2\n"},
		metricName,
	)
	if reset.State != MetricReset || reset.Value != 0 {
		t.Fatalf("reset delta = %#v, want reset with zero value", reset)
	}
	for _, test := range []struct {
		name  string
		code  int
		state MetricState
	}{
		{name: "status-only unauthorized", code: http.StatusForbidden, state: MetricUnauthorized},
		{name: "status-only unavailable", code: http.StatusInternalServerError, state: MetricUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := MetricsSnapshot{StatusCode: http.StatusOK, Body: metricName + " 4\n"}
			after := MetricsSnapshot{StatusCode: test.code}
			got := metricDeltaCounter(before, after, metricName)
			if got.State != test.state || got.Value != 0 {
				t.Fatalf("status-only delta = %#v, want state=%q and zero value", got, test.state)
			}
		})
	}
}

func TestStatusForWrappedAPIError(t *testing.T) {
	err := fmt.Errorf("update benchmark object: %w", apierrors.NewTooManyRequests("busy", 1))
	if got := statusFor(verbUpdate, err); got != http.StatusTooManyRequests {
		t.Fatalf("wrapped API error status = %d, want %d", got, http.StatusTooManyRequests)
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

func TestArtifactBaseNameIncludesCellDiscriminators(t *testing.T) {
	core := Cell{Engine: engineMap, Tier: "t1", Mode: modeProtect, Variant: variantEnabled}
	excluded := core
	excluded.Variant = variantExcluded
	if artifactBaseName(core) == artifactBaseName(excluded) {
		t.Fatalf("core and excluded artifacts collide: %q", artifactBaseName(core))
	}
	if want := "map-t1-protect-enabled"; artifactBaseName(core) != want {
		t.Fatalf("artifact base name = %q, want %q", artifactBaseName(core), want)
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

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"reflect"
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRBACAugmentationIsIdempotent(t *testing.T) {
	input := APIResourcesByGroupVersion{
		"v1": {
			{Name: "nodes", Kind: "Node", Verbs: metav1.Verbs{verbGet}},
			{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{verbGet}},
			{Name: "pods/status", Kind: "Pod", Namespaced: true, Verbs: metav1.Verbs{verbUpdate}},
		},
		"rbac.authorization.k8s.io/v1": {
			{Name: rbacResourceRoles, Verbs: metav1.Verbs{verbGet, verbBind}},
		},
	}
	first := augmentRBACResources(context.Background(), input.DeepCopy())
	second := augmentRBACResources(context.Background(), first.DeepCopy())
	if !reflect.DeepEqual(first, second) {
		t.Fatal("retained partial-discovery snapshots were augmented twice")
	}
	for gv, resources := range first {
		seen := map[string]bool{}
		for _, resource := range resources {
			if seen[resource.Name] {
				t.Fatalf("duplicate resource %s/%s", gv, resource.Name)
			}
			seen[resource.Name] = true
			switch resource.Name {
			case "nodes/metrics":
				if !slices.Contains(resource.Verbs, verbGet) {
					t.Fatal("node metrics is missing get")
				}
			case "pods/status", "pods/finalizers":
				if !slices.Contains(resource.Verbs, verbList) || !slices.Contains(resource.Verbs, verbWatch) {
					t.Fatal("synthetic status/finalizer verbs are missing")
				}
			case rbacResourceRoles:
				if !slices.Contains(resource.Verbs, verbBind) || !slices.Contains(resource.Verbs, verbEscalate) {
					t.Fatal("explicit RBAC verbs are missing")
				}
			}
		}
	}
	if len(input["v1"]) != 3 || len(input["rbac.authorization.k8s.io/v1"][0].Verbs) != 2 {
		t.Fatal("augmenting a copy changed the original discovery snapshot")
	}
}

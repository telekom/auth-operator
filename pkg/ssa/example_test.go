// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/telekom/auth-operator/pkg/ssa"
)

// ExampleApplier shows how another operator defines a descriptor for its own
// type and gets skip-if-unchanged Server-Side Apply.
func ExampleApplier() {
	configMaps := ssa.Applier[*corev1.ConfigMap, *corev1ac.ConfigMapApplyConfiguration]{
		Kind:       "ConfigMap",
		Namespaced: true,
		New:        func() *corev1.ConfigMap { return &corev1.ConfigMap{} },
		Matches: func(existing *corev1.ConfigMap, desired *corev1ac.ConfigMapApplyConfiguration) bool {
			return maps.Equal(existing.Data, desired.Data)
		},
		Extract: corev1ac.ExtractConfigMap,
	}

	ctx := context.Background()
	c := fake.NewClientBuilder().WithReturnManagedFields().Build()
	for range 2 {
		desired := corev1ac.ConfigMap("settings", "default").WithData(map[string]string{"mode": "fast"})
		result, err := configMaps.PatchApply(ctx, c, desired, false, client.FieldOwner("my-operator"))
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		fmt.Println(result)
	}
	// Output:
	// created
	// skipped
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/auth-operator/pkg/ssa"
)

var _ = Describe("SSA library compatibility", Label("ssa-migration"), func() {
	DescribeTable("ServiceAccount writes retain preconditions excluded only from no-op comparisons",
		func(precondition string) {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "ssa-adoption-"}}
			Expect(k8sClient.Create(testCtx, ns)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, ns)).To(Succeed()) })
			name := fmt.Sprintf("precondition-%d", time.Now().UnixNano())
			_, err := ssa.PatchApplyServiceAccount(testCtx, k8sClient,
				ssa.ServiceAccountWith(name, ns.Name, nil, true), ssa.FieldOwner)
			Expect(err).NotTo(HaveOccurred())
			obj := &corev1.ServiceAccount{}
			key := client.ObjectKey{Name: name, Namespace: ns.Name}
			Expect(k8sClient.Get(testCtx, key, obj)).To(Succeed())
			DeferCleanup(func() { Expect(k8sClient.Delete(testCtx, obj)).To(Succeed()) })
			rv := obj.ResourceVersion
			changed := ssa.ServiceAccountWith(name, ns.Name, map[string]string{"must-not-persist": "true"}, true)
			if precondition == "uid" {
				changed.WithUID("wrong-uid")
			} else {
				changed.WithResourceVersion("1")
			}
			c := &applyCountingClient{Client: k8sClient}
			_, err = ssa.PatchApplyServiceAccount(testCtx, c, changed, ssa.FieldOwner)
			Expect(err).To(HaveOccurred())
			Expect(c.applyCalls).To(Equal(1), "changed configurations must reach the real server")
			Expect(k8sClient.Get(testCtx, key, obj)).To(Succeed())
			Expect(obj.ResourceVersion).To(Equal(rv))
			Expect(obj.Labels).NotTo(HaveKey("must-not-persist"))
		},
		Entry("UID", "uid"),
		Entry("resourceVersion", "resourceVersion"),
	)
})

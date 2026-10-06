// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	statusssa "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
)

var _ = Describe("SSA library patch adoption", Label("ssa-migration"), func() {
	It("treats status cleanup as complete when the parent disappears between read and patch", func() {
		ctx := context.Background()
		bd := migrationObject("BindDefinition", fmt.Sprintf("cleanup-race-%d", time.Now().UnixNano())).(*authorizationv1alpha1.BindDefinition)
		Expect(k8sClient.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() { Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, bd))).To(Succeed()) })
		bd.Status.GeneratedServiceAccounts = []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "generated", Namespace: "default"}}
		Expect(statusssa.ApplyBindDefinitionStatus(ctx, k8sClient, bd)).To(Succeed())
		patches := 0
		c := interceptor.NewClient(k8sClient, interceptor.Funcs{
			SubResourcePatch: func(ctx context.Context, c client.Client, subresource string, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
				patches++
				Expect(k8sClient.Delete(ctx, bd)).To(Succeed())
				err := c.SubResource(subresource).Patch(ctx, obj, patch, opts...)
				Expect(apierrors.IsNotFound(err)).To(BeTrue())
				return err
			},
		})
		r := &BindDefinitionReconciler{client: c, reader: k8sClient}
		Expect(r.clearGeneratedServiceAccountsStatus(ctx, bd)).To(Succeed())
		Expect(patches).To(Equal(1))
	})
})

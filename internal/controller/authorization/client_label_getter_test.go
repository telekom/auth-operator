// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"testing"

	"github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestClientLabelGetterNotFoundDoesNotRecordError(t *testing.T) {
	g := gomega.NewWithT(t)

	c := fake.NewClientBuilder().WithScheme(newTestScheme()).Build()
	getter := newLabelGetter(c)

	_, found := getter.GetNamespaceLabels(context.Background(), "missing")

	g.Expect(found).To(gomega.BeFalse())
	g.Expect(getter.Err()).NotTo(gomega.HaveOccurred())
}

func TestClientLabelGetterRecordsTransientErrors(t *testing.T) {
	g := gomega.NewWithT(t)

	c := fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok && key.Name == "team-a" {
					return fmt.Errorf("injected namespace get error")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
			List: func(ctx context.Context, cl client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
				if _, ok := list.(*corev1.NamespaceList); ok {
					return fmt.Errorf("injected namespace list error")
				}
				return cl.List(ctx, list, opts...)
			},
		}).
		Build()
	getter := newLabelGetter(c)

	_, found := getter.GetNamespaceLabels(context.Background(), "team-a")
	_, listErr := getter.ListNamespacesBySelector(context.Background(), &metav1.LabelSelector{
		MatchLabels: map[string]string{"team": "a"},
	})

	g.Expect(found).To(gomega.BeFalse())
	g.Expect(listErr).To(gomega.HaveOccurred())
	g.Expect(getter.Err()).To(gomega.MatchError(gomega.And(
		gomega.ContainSubstring("get namespace team-a labels"),
		gomega.ContainSubstring("list namespaces by selector"),
	)))
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestReconcileResourcesPreservesReclassifiedServiceAccountWithStaleCache(t *testing.T) {
	ctx := context.Background()
	scheme := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{
		authorizationv1alpha1.AddToScheme, corev1.AddToScheme, rbacv1.AddToScheme,
	} {
		if err := register(scheme); err != nil {
			t.Fatal(err)
		}
	}
	subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "transferred", Namespace: "workload"}
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "transfer-bd", UID: "transfer-uid"},
		Spec:       authorizationv1alpha1.BindDefinitionSpec{Subjects: []rbacv1.Subject{subject}},
		Status: authorizationv1alpha1.BindDefinitionStatus{
			GeneratedServiceAccounts: []rbacv1.Subject{subject},
		},
	}
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
		Name: subject.Name, Namespace: subject.Namespace,
		Labels:      map[string]string{helpers.ManagedByLabelStandard: "ExternalController"},
		Annotations: helpers.BuildManagedSAAnnotations(bd.Name),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: authorizationv1alpha1.BindDefinitionKind,
			Name: bd.Name, UID: bd.UID,
		}},
	}}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: subject.Namespace},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd, sa, ns).Build()
	detached := false
	cached := interceptor.NewClient(base, interceptor.Funcs{
		Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
			return &apierrors.StatusError{ErrStatus: metav1.Status{
				Reason: metav1.StatusReasonConflict,
				Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{
					Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.app.kubernetes.io/managed-by",
					Message: `conflict with "unknown-controller"`,
				}}},
			}}
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if err := c.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if account, ok := obj.(*corev1.ServiceAccount); ok && detached {
				account.OwnerReferences = append([]metav1.OwnerReference(nil), sa.OwnerReferences...)
			}
			return nil
		},
		Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if err := c.Patch(ctx, obj, patch, opts...); err != nil {
				return err
			}
			if account, ok := obj.(*corev1.ServiceAccount); ok && !hasOwnerRef(account, bd) {
				detached = true
			}
			return nil
		},
	})
	r := &BindDefinitionReconciler{client: cached, reader: base, scheme: scheme, recorder: events.NewFakeRecorder(20)}
	if _, err := r.reconcileResources(ctx, bd, nil, nil); err != nil {
		t.Fatal(err)
	}
	preserved := &corev1.ServiceAccount{}
	if err := base.Get(ctx, types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}, preserved); err != nil {
		t.Fatalf("reclassified ServiceAccount was pruned through stale cache ownership: %v", err)
	}
	if hasOwnerRef(preserved, bd) {
		t.Fatal("lifecycle ownership was not relinquished")
	}
	if len(bd.Status.ExternalServiceAccounts) != 1 || bd.Status.ExternalServiceAccounts[0] != "workload/transferred" {
		t.Fatalf("unexpected external classification: %v", bd.Status.ExternalServiceAccounts)
	}
}

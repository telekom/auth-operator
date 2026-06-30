/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package authorization

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
)

func newTestScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)
	return s
}

func testBindDefinitionControllerOwnerRef(name string, uid types.UID) metav1.OwnerReference {
	controller := true
	return metav1.OwnerReference{
		APIVersion: authorizationv1alpha1.GroupVersion.String(),
		Kind:       "BindDefinition",
		Name:       name,
		UID:        uid,
		Controller: &controller,
	}
}

func testBindDefinition() *authorizationv1alpha1.BindDefinition {
	return &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bd", UID: types.UID("bd-uid")},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName},
			},
		},
	}
}

type fakeAPIResourceProvider struct {
	resources discovery.APIResourcesByGroupVersion
	err       error
}

func (f fakeAPIResourceProvider) GetAPIResources() (discovery.APIResourcesByGroupVersion, error) {
	return f.resources, f.err
}

func TestIsOwnedByBindDefinition(t *testing.T) {
	t.Run("empty owner references returns false", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(isOwnedByBindDefinition(nil)).To(BeFalse())
		g.Expect(isOwnedByBindDefinition([]metav1.OwnerReference{})).To(BeFalse())
	})

	t.Run("wrong Kind returns false", func(t *testing.T) {
		g := NewWithT(t)
		refs := []metav1.OwnerReference{
			{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       "test",
			},
		}
		g.Expect(isOwnedByBindDefinition(refs)).To(BeFalse())
	})

	t.Run("wrong APIVersion returns false", func(t *testing.T) {
		g := NewWithT(t)
		refs := []metav1.OwnerReference{
			{
				APIVersion: "wrong.group/v1",
				Kind:       "BindDefinition",
				Name:       "test",
			},
		}
		g.Expect(isOwnedByBindDefinition(refs)).To(BeFalse())
	})

	t.Run("correct BindDefinition owner returns true", func(t *testing.T) {
		g := NewWithT(t)
		refs := []metav1.OwnerReference{
			{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
				Name:       "test-bd",
				UID:        "test-bd-uid",
			},
		}
		g.Expect(isOwnedByBindDefinition(refs)).To(BeTrue())
	})

	t.Run("mixed owner references with BindDefinition returns true", func(t *testing.T) {
		g := NewWithT(t)
		refs := []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "Deployment", Name: "dep"},
			{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "bd", UID: "bd-uid"},
		}
		g.Expect(isOwnedByBindDefinition(refs)).To(BeTrue())
	})

	t.Run("incomplete BindDefinition owner returns false", func(t *testing.T) {
		g := NewWithT(t)
		refs := []metav1.OwnerReference{
			{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "bd"},
		}
		g.Expect(isOwnedByBindDefinition(refs)).To(BeFalse())
	})
}

func TestSupportsList(t *testing.T) {
	t.Run("has list verb", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(supportsList([]string{"get", "list", "watch"})).To(BeTrue())
	})

	t.Run("no list verb", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(supportsList([]string{"get", "watch", "create"})).To(BeFalse())
	})

	t.Run("empty verbs", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(supportsList(nil)).To(BeFalse())
		g.Expect(supportsList([]string{})).To(BeFalse())
	})

	t.Run("only list", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(supportsList([]string{"list"})).To(BeTrue())
	})
}

func TestFormatBlockingResourcesMessage(t *testing.T) {
	t.Run("single resource with name", func(t *testing.T) {
		g := NewWithT(t)
		resources := []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", APIGroup: "", Count: 1, Names: []string{"my-pod"}},
		}
		msg := formatBlockingResourcesMessage(resources)
		g.Expect(msg).To(Equal("pods: my-pod"))
	})

	t.Run("resource with API group", func(t *testing.T) {
		g := NewWithT(t)
		resources := []namespaceDeletionResourceBlocking{
			{ResourceType: "deployments", APIGroup: "apps", Count: 2, Names: []string{"dep1", "dep2"}},
		}
		msg := formatBlockingResourcesMessage(resources)
		g.Expect(msg).To(ContainSubstring("deployments (apps)"))
		g.Expect(msg).To(ContainSubstring("dep1"))
	})

	t.Run("multiple resources combined", func(t *testing.T) {
		g := NewWithT(t)
		resources := []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", APIGroup: "", Count: 1, Names: []string{"pod1"}},
			{ResourceType: "services", APIGroup: "", Count: 1, Names: []string{"svc1"}},
		}
		msg := formatBlockingResourcesMessage(resources)
		g.Expect(msg).To(ContainSubstring("pods: pod1"))
		g.Expect(msg).To(ContainSubstring("services: svc1"))
	})

	t.Run("resource with many names truncated", func(t *testing.T) {
		g := NewWithT(t)
		resources := []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", APIGroup: "", Count: 5, Names: []string{"p1", "p2", "p3", "p4", "p5"}},
		}
		msg := formatBlockingResourcesMessage(resources)
		g.Expect(msg).To(ContainSubstring("+2 more"))
	})

	t.Run("resource with no names", func(t *testing.T) {
		g := NewWithT(t)
		resources := []namespaceDeletionResourceBlocking{
			{ResourceType: "configmaps", APIGroup: "", Count: 3, Names: nil},
		}
		msg := formatBlockingResourcesMessage(resources)
		g.Expect(msg).To(Equal("configmaps (3)"))
	})
}

func TestGetOwningBindDefinition(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	t.Run("returns BindDefinition when found", func(t *testing.T) {
		g := NewWithT(t)

		bd := &authorizationv1alpha1.BindDefinition{
			ObjectMeta: metav1.ObjectMeta{Name: "test-bd", UID: "test-bd-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "test-target",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "grp", APIGroup: rbacv1.GroupName}},
			},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme}

		refs := []metav1.OwnerReference{testBindDefinitionControllerOwnerRef("test-bd", "test-bd-uid")}
		result, err := r.getOwningBindDefinition(ctx, refs)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.Name).To(Equal("test-bd"))
	})

	t.Run("returns error when no BindDefinition owner ref", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme}

		refs := []metav1.OwnerReference{
			{APIVersion: "apps/v1", Kind: "Deployment", Name: "dep"},
		}
		_, err := r.getOwningBindDefinition(ctx, refs)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("no controlling BindDefinition owner reference found"))
	})

	t.Run("returns error when BindDefinition not found in cluster", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme}

		refs := []metav1.OwnerReference{testBindDefinitionControllerOwnerRef("nonexistent", "nonexistent-uid")}
		_, err := r.getOwningBindDefinition(ctx, refs)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("failed to get BindDefinition nonexistent"))
	})
}

func TestRoleBindingTerminatorReconcile(t *testing.T) {
	ctx := context.Background()
	scheme := newTestScheme()

	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")

	t.Run("RoleBinding not found returns empty result", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(scheme).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "nonexistent", Namespace: "default"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))
	})

	t.Run("RoleBinding not owned by BindDefinition is ignored", func(t *testing.T) {
		g := NewWithT(t)

		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unowned-rb",
				Namespace: "default",
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "unowned-rb", Namespace: "default"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))
	})

	t.Run("RoleBinding with non-controller BindDefinition ownerRef is ignored", func(t *testing.T) {
		g := NewWithT(t)

		ownerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
		controller := false
		ownerRef.Controller = &controller
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "non-controller-rb",
				Namespace:       "default",
				OwnerReferences: []metav1.OwnerReference{ownerRef},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "non-controller-rb", Namespace: "default"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))

		updated := &rbacv1.RoleBinding{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "non-controller-rb", Namespace: "default"}, updated)).To(Succeed())
		g.Expect(updated.Finalizers).NotTo(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
	})

	t.Run("RoleBinding with nonexistent BindDefinition ownerRef does not get finalizer", func(t *testing.T) {
		g := NewWithT(t)

		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "missing-owner-rb",
				Namespace:       "default",
				OwnerReferences: []metav1.OwnerReference{testBindDefinitionControllerOwnerRef("missing-bd", "missing-uid")},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "missing-owner-rb", Namespace: "default"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))

		updated := &rbacv1.RoleBinding{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "missing-owner-rb", Namespace: "default"}, updated)).To(Succeed())
		g.Expect(updated.Finalizers).NotTo(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
	})

	t.Run("RoleBinding not being deleted gets finalizer added", func(t *testing.T) {
		g := NewWithT(t)

		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "owned-rb",
				Namespace:       "default",
				OwnerReferences: []metav1.OwnerReference{bdOwnerRef},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "owned-rb", Namespace: "default"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))

		// Verify finalizer was added
		updated := &rbacv1.RoleBinding{}
		g.Expect(c.Get(ctx, types.NamespacedName{Name: "owned-rb", Namespace: "default"}, updated)).To(Succeed())
		g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
	})

	t.Run("Deleting RoleBinding in non-terminating namespace removes finalizer", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "deleting-rb",
				Namespace:         "active-ns",
				OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
				DeletionTimestamp: &now,
				Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "active-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "deleting-rb", Namespace: "active-ns"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))

		// Fake client auto-deletes when last finalizer is removed on a deleting object
		updated := &rbacv1.RoleBinding{}
		err = c.Get(ctx, types.NamespacedName{Name: "deleting-rb", Namespace: "active-ns"}, updated)
		g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should be gone after finalizer removal")
	})

	t.Run("Deleting RoleBinding when namespace not found returns empty result", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "orphan-rb",
				Namespace:         "gone-ns",
				OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
				DeletionTimestamp: &now,
				Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}
		// No namespace created - simulating namespace already deleted
		c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).Build()
		r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

		result, err := r.Reconcile(ctx, reconcile.Request{
			NamespacedName: types.NamespacedName{Name: "orphan-rb", Namespace: "gone-ns"},
		})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(reconcile.Result{}))
	})
}

func TestNewNamespaceTerminationStatus(t *testing.T) {
	g := NewWithT(t)

	status := newNamespaceTerminationStatus()
	g.Expect(status).NotTo(BeNil())
	g.Expect(status.blockingResources).To(BeEmpty())
	g.Expect(status.lastError).ToNot(HaveOccurred())
	g.Expect(status.fetchedAt.IsZero()).To(BeTrue())
	// Rate limiter should have the configured interval
	g.Expect(status.rateLimiter.Interval).To(Equal(10 * time.Second))
}

func TestTerminationResourceChannelSize(t *testing.T) {
	g := NewWithT(t)
	// Verify the constant is defined and reasonable.
	g.Expect(terminationResourceChannelSize).To(Equal(100))
}

func TestRBTerminatorReconcileTerminatingNamespaceWithBlockingResources(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "term-rb",
			Namespace:         "terminating-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "terminating-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(rb, ns, testBindDefinition()).
		WithStatusSubresource(ns).
		Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	// Pre-populate the cache with blocking resources.
	// Burn the first rate limiter call so subsequent Do() won't re-execute.
	cacheEntry := &namespaceTerminationStatus{
		blockingResources: []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", APIGroup: "", Count: 3, Names: []string{"pod-a", "pod-b", "pod-c"}},
		},
		rateLimiter: rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {}) // burn first call
	r.namespaceTerminationResourcesCache.Store("terminating-ns", cacheEntry)

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "term-rb", Namespace: "terminating-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(terminatingNamespaceRequeueInterval))

	// Verify finalizer was NOT removed
	updated := &rbacv1.RoleBinding{}
	g.Expect(c.Get(ctx, types.NamespacedName{Name: "term-rb", Namespace: "terminating-ns"}, updated)).To(Succeed())
	g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
}

func TestRBTerminatorReconcileTerminatingNamespaceNoBlockingResources(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bd := &authorizationv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "test-bd", UID: "bd-uid"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "test-target",
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			},
		},
	}
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "term-rb-clean",
			Namespace:         "clean-term-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "clean-term-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(rb, ns, bd).
		WithStatusSubresource(ns, bd).
		Build()
	fakeRecorder := events.NewFakeRecorder(10)
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: fakeRecorder}

	// Pre-populate the cache with NO blocking resources.
	cacheEntry := &namespaceTerminationStatus{
		blockingResources: nil, // empty = termination allowed
		rateLimiter:       rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {}) // burn first call
	r.namespaceTerminationResourcesCache.Store("clean-term-ns", cacheEntry)

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "term-rb-clean", Namespace: "clean-term-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(reconcile.Result{}))

	// Fake client auto-deletes when last finalizer is removed on a deleting object
	updated := &rbacv1.RoleBinding{}
	err = c.Get(ctx, types.NamespacedName{Name: "term-rb-clean", Namespace: "clean-term-ns"}, updated)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should be gone after finalizer removal")

	// Cache entry should be evicted after successful finalizer removal in the
	// terminating path — the namespace cleanup is progressing and the cached
	// data is stale.
	_, loaded := r.namespaceTerminationResourcesCache.Load("clean-term-ns")
	g.Expect(loaded).To(BeFalse(), "cache entry should be evicted after finalizer removal in terminating namespace")
}

func TestRBTerminatorCacheEvictionOnNonTerminatingNamespace(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "evict-rb",
			Namespace:         "evict-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "evict-ns"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	// Pre-populate the cache (simulates a previous termination check)
	r.namespaceTerminationResourcesCache.Store("evict-ns", newNamespaceTerminationStatus())

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "evict-rb", Namespace: "evict-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(reconcile.Result{}))

	// Verify cache entry was evicted (#142)
	_, loaded := r.namespaceTerminationResourcesCache.Load("evict-ns")
	g.Expect(loaded).To(BeFalse(), "cache entry should be evicted when namespace is not terminating")
}

func TestRBTerminatorReconcileErrorAddingFinalizer(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "err-rb",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{bdOwnerRef},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, obj client.Object, _ client.Patch, _ ...client.PatchOption) error {
				if _, ok := obj.(*rbacv1.RoleBinding); ok {
					return fmt.Errorf("injected patch error")
				}
				return nil
			},
		}).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "err-rb", Namespace: "default"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected patch error"))
}

func TestRBTerminatorReconcileNamespaceGetError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "ns-err-rb",
			Namespace:         "some-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.Namespace); ok {
					return fmt.Errorf("injected namespace get error")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "ns-err-rb", Namespace: "some-ns"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected namespace get error"))
}

func TestRBTerminatorReconcileBlockingResourcesError(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "block-err-rb",
			Namespace:         "term-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "term-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	// Pre-populate the cache with an error
	cacheEntry := &namespaceTerminationStatus{
		lastError:   fmt.Errorf("injected blocking resources error"),
		rateLimiter: rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {}) // burn first call
	r.namespaceTerminationResourcesCache.Store("term-ns", cacheEntry)

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "block-err-rb", Namespace: "term-ns"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected blocking resources error"))
}

func TestRBTerminatorReconcileDynamicListErrorKeepsFinalizer(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "list-error-rb",
			Namespace:         "list-error-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "list-error-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).Build()
	podGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{podGVR: "PodList"},
	)
	dynamicClient.PrependReactor("list", "pods", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("injected pod list error")
	})
	resourceTracker := fakeAPIResourceProvider{
		resources: discovery.APIResourcesByGroupVersion{
			"v1": {
				{Name: "pods", Namespaced: true, Verbs: metav1.Verbs{"list"}},
			},
		},
	}
	r := &RoleBindingTerminator{
		client:          c,
		scheme:          scheme,
		dynamicClient:   dynamicClient,
		resourceTracker: resourceTracker,
		recorder:        events.NewFakeRecorder(10),
	}

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "list-error-rb", Namespace: "list-error-ns"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected pod list error"))

	var updated rbacv1.RoleBinding
	g.Expect(c.Get(ctx, types.NamespacedName{Name: "list-error-rb", Namespace: "list-error-ns"}, &updated)).To(Succeed())
	g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
}

func TestRBTerminatorReconcileSkipsClusterScopedResources(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "cluster-scoped-rb",
			Namespace:         "cluster-scoped-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "cluster-scoped-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(rb, ns, testBindDefinition()).
		WithStatusSubresource(ns).
		Build()
	nodeGVR := schema.GroupVersionResource{Version: "v1", Resource: "nodes"}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{nodeGVR: "NodeList"},
	)
	dynamicClient.PrependReactor("list", "nodes", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("cluster-scoped nodes should not be listed through a namespace")
	})
	resourceTracker := fakeAPIResourceProvider{
		resources: discovery.APIResourcesByGroupVersion{
			"v1": {
				{Name: "nodes", Namespaced: false, Verbs: metav1.Verbs{"list"}},
			},
		},
	}
	r := &RoleBindingTerminator{
		client:          c,
		scheme:          scheme,
		dynamicClient:   dynamicClient,
		resourceTracker: resourceTracker,
		recorder:        events.NewFakeRecorder(10),
	}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "cluster-scoped-rb", Namespace: "cluster-scoped-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(reconcile.Result{}))

	var updated rbacv1.RoleBinding
	err = c.Get(ctx, types.NamespacedName{Name: "cluster-scoped-rb", Namespace: "cluster-scoped-ns"}, &updated)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should be gone after finalizer removal")
}

func TestRBTerminatorReconcileErrorRemovingFinalizerNonTerminating(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "rm-err-rb",
			Namespace:         "active-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "active-ns"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).
		WithInterceptorFuncs(interceptor.Funcs{
			Patch: func(_ context.Context, _ client.WithWatch, _ client.Object, _ client.Patch, _ ...client.PatchOption) error {
				return fmt.Errorf("injected patch error")
			},
		}).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	_, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "rm-err-rb", Namespace: "active-ns"},
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected patch error"))
}

func TestRBTerminatorReconcileFinalizerAlreadyPresent(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "has-finalizer-rb",
			Namespace:       "default",
			OwnerReferences: []metav1.OwnerReference{bdOwnerRef},
			Finalizers:      []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, testBindDefinition()).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "has-finalizer-rb", Namespace: "default"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(reconcile.Result{}))
}

func TestRBTerminatorReconcileInvalidOwnerRemovesFinalizer(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("nonexistent-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "owner-err-rb",
			Namespace:         "clean-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "clean-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rb, ns, testBindDefinition()).
		WithStatusSubresource(ns).Build()
	r := &RoleBindingTerminator{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	// No blocking resources
	cacheEntry := &namespaceTerminationStatus{
		blockingResources: nil,
		rateLimiter:       rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {}) // burn first call
	r.namespaceTerminationResourcesCache.Store("clean-ns", cacheEntry)

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "owner-err-rb", Namespace: "clean-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result).To(Equal(reconcile.Result{}))

	updated := &rbacv1.RoleBinding{}
	err = c.Get(ctx, types.NamespacedName{Name: "owner-err-rb", Namespace: "clean-ns"}, updated)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "RoleBinding should be gone after invalid finalizer removal")
}

func TestRBTerminatorReconcileUsesLiveReaderForStaleOwnerCache(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "stale-owner-rb",
			Namespace:         "blocked-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	staleCache := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rb.DeepCopy(), ns.DeepCopy()).
		WithStatusSubresource(ns).
		Build()
	liveReader := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testBindDefinition()).
		Build()
	r := &RoleBindingTerminator{client: staleCache, reader: liveReader, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	cacheEntry := &namespaceTerminationStatus{
		blockingResources: []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", Count: 1, Names: []string{"still-running"}},
		},
		rateLimiter: rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {})
	r.namespaceTerminationResourcesCache.Store("blocked-ns", cacheEntry)

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "stale-owner-rb", Namespace: "blocked-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(terminatingNamespaceRequeueInterval))

	updated := &rbacv1.RoleBinding{}
	err = staleCache.Get(ctx, types.NamespacedName{Name: "stale-owner-rb", Namespace: "blocked-ns"}, updated)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
}

func TestRBTerminatorReconcileUsesLiveReaderForStaleOwnerUID(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "stale-owner-uid-rb",
			Namespace:         "blocked-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "blocked-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}
	staleBD := testBindDefinition()
	staleBD.UID = types.UID("old-bd-uid")

	staleCache := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(rb.DeepCopy(), ns.DeepCopy(), staleBD).
		WithStatusSubresource(ns).
		Build()
	liveReader := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(testBindDefinition()).
		Build()
	r := &RoleBindingTerminator{client: staleCache, reader: liveReader, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	cacheEntry := &namespaceTerminationStatus{
		blockingResources: []namespaceDeletionResourceBlocking{
			{ResourceType: "pods", Count: 1, Names: []string{"still-running"}},
		},
		rateLimiter: rate.Sometimes{},
	}
	cacheEntry.rateLimiter.Do(func() {})
	r.namespaceTerminationResourcesCache.Store("blocked-ns", cacheEntry)

	result, err := r.Reconcile(ctx, reconcile.Request{
		NamespacedName: types.NamespacedName{Name: "stale-owner-uid-rb", Namespace: "blocked-ns"},
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.RequeueAfter).To(Equal(terminatingNamespaceRequeueInterval))

	updated := &rbacv1.RoleBinding{}
	err = staleCache.Get(ctx, types.NamespacedName{Name: "stale-owner-uid-rb", Namespace: "blocked-ns"}, updated)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer))
}

func TestRBTerminator_NamespaceHasResources_NetworkRoleBindings(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := newTestScheme()

	now := metav1.Now()
	bdOwnerRef := testBindDefinitionControllerOwnerRef("test-bd", "bd-uid")
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-rb",
			Namespace:         "test-ns",
			OwnerReferences:   []metav1.OwnerReference{bdOwnerRef},
			DeletionTimestamp: &now,
			Finalizers:        []string{authorizationv1alpha1.RoleBindingFinalizer},
		},
		RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
	}
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "test-ns",
			DeletionTimestamp: &now,
			Finalizers:        []string{"kubernetes"},
		},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(rb, ns, testBindDefinition()).
		WithStatusSubresource(ns).
		Build()

	networkGVR := schema.GroupVersionResource{Group: "network.example.com", Version: "v1", Resource: "networkrolebindings"}
	dynamicClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		runtime.NewScheme(),
		map[schema.GroupVersionResource]string{networkGVR: "NetworkRoleBindingList"},
	)

	unstructuredList := &unstructured.UnstructuredList{}
	unstructuredList.SetGroupVersionKind(schema.GroupVersionKind{Group: "network.example.com", Version: "v1", Kind: "NetworkRoleBindingList"})
	unstructuredList.Items = []unstructured.Unstructured{
		{
			Object: map[string]interface{}{
				"apiVersion": "network.example.com/v1",
				"kind":       "NetworkRoleBinding",
				"metadata": map[string]interface{}{
					"name":      "test-networkrb",
					"namespace": "test-ns",
				},
			},
		},
	}
	dynamicClient.PrependReactor("list", "networkrolebindings", func(_ k8stesting.Action) (bool, runtime.Object, error) {
		return true, unstructuredList, nil
	})

	resourceTracker := fakeAPIResourceProvider{
		resources: discovery.APIResourcesByGroupVersion{
			"network.example.com/v1": {
				{
					Name:       "networkrolebindings",
					Kind:       "NetworkRoleBinding",
					Verbs:      []string{"list"},
					Namespaced: true,
				},
			},
		},
	}

	r := &RoleBindingTerminator{
		client:          c,
		scheme:          scheme,
		dynamicClient:   dynamicClient,
		resourceTracker: resourceTracker,
		recorder:        events.NewFakeRecorder(10),
	}

	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "test-ns", Name: "test-rb"}})
	g.Expect(err).NotTo(HaveOccurred())

	// We expect termination to be BLOCKED, so the finalizer stays, and RequeueAfter is set.
	g.Expect(res.RequeueAfter).To(Equal(terminatingNamespaceRequeueInterval), "Termination should be blocked by networkrolebindings")

	var updatedRB rbacv1.RoleBinding
	g.Expect(c.Get(ctx, types.NamespacedName{Namespace: "test-ns", Name: "test-rb"}, &updatedRB)).To(Succeed())
	g.Expect(updatedRB.Finalizers).To(ContainElement(authorizationv1alpha1.RoleBindingFinalizer), "Finalizer should not be removed while resources exist")
}

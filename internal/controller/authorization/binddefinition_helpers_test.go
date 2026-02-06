package authorization

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
)

func TestBuildBindingName(t *testing.T) {
	tests := []struct {
		targetName string
		roleRef    string
		want       string
	}{
		{"platform-admin", "cluster-admin", "platform-admin-cluster-admin-binding"},
		{"tenant-user", "view", "tenant-user-view-binding"},
		{"my-service", "edit", "my-service-edit-binding"},
	}

	for _, tt := range tests {
		t.Run(tt.targetName+"-"+tt.roleRef, func(t *testing.T) {
			got := helpers.BuildBindingName(tt.targetName, tt.roleRef)
			if got != tt.want {
				t.Errorf("helpers.BuildBindingName(%q, %q) = %q, want %q",
					tt.targetName, tt.roleRef, got, tt.want)
			}
		})
	}
}

// TestLogStatusApplyError tests that logStatusApplyError handles nil and non-nil errors
func TestLogStatusApplyError(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		err      error
		resource string
	}{
		{
			name:     "nil error does nothing",
			err:      nil,
			resource: "test-resource",
		},
		{
			name:     "non-nil error logs without panicking",
			err:      errors.New("status apply failed"),
			resource: "test-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic regardless of error value
			logStatusApplyError(ctx, tt.err, tt.resource)
		})
	}
}

var _ = Describe("BindDefinition Helpers", func() {
	ctx := context.Background()

	Describe("deleteServiceAccount", func() {
		It("should return deleteResultNotFound when ServiceAccount does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "nonexistent-sa", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when ServiceAccount has no controller reference", func() {
			// Create ServiceAccount without owner reference
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-no-owner",
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-no-owner",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-no-owner", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultDeleted when ServiceAccount is successfully deleted", func() {
			// Create BindDefinition first
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-delete",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx,
				client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create ServiceAccount with owner reference
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-delete",
					Namespace: "default",
				},
			}
			Expect(controllerutil.SetControllerReference(bindDef, sa, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-delete", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("deleteClusterRoleBinding", func() {
		It("should return deleteResultNotFound when ClusterRoleBinding does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-crb-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-crb",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "nonexistent-role")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when ClusterRoleBinding has no controller reference", func() {
			// Create ClusterRoleBinding without owner reference
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-crb-no-owner-test-role-binding",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "view",
				},
			}
			Expect(k8sClient.Create(ctx, crb)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-crb-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-crb-no-owner",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "test-role")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, crb)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("deleteRoleBinding", func() {
		It("should return deleteResultNotFound when RoleBinding does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-rb",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "nonexistent-role", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when RoleBinding has no controller reference", func() {
			// Create RoleBinding without owner reference
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rb-no-owner-view-binding",
					Namespace: "default",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "view",
				},
			}
			Expect(k8sClient.Create(ctx, rb)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-rb-no-owner",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "view", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, rb)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultDeleted when RoleBinding is successfully deleted", func() {
			// Create BindDefinition first
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-rb-delete",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx,
				client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create RoleBinding with owner reference
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rb-delete-view-binding",
					Namespace: "default",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "view",
				},
			}
			Expect(controllerutil.SetControllerReference(bindDef, rb, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, rb)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "view", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("ensureServiceAccounts", func() {
		It("should create ServiceAccount with automountServiceAccountToken=true when field is nil (backward compatibility)", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-nil-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-nil-automount",
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-nil-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: nil, // Explicitly nil - should default to true
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=true (backward compatibility)
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-nil-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should create ServiceAccount with automountServiceAccountToken=true when explicitly set", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-true-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-true-automount",
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-true-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(true),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=true
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-true-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should create ServiceAccount with automountServiceAccountToken=false when explicitly set", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-false-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-false-automount",
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-false-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(false),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=false
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-false-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeFalse())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("ensureServiceAccounts update scenarios", func() {
		It("should update ServiceAccount automountServiceAccountToken when value changes from false to true", func() {
			// Create BindDefinition first with automountServiceAccountToken=false
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-update-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-update-automount",
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-update-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(false),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create ServiceAccount with owner reference and automountServiceAccountToken=false
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-update-automount",
					Namespace: "default",
					Labels:    helpers.BuildResourceLabels(bindDef.Labels),
				},
				AutomountServiceAccountToken: ptr.To(false),
			}
			Expect(controllerutil.SetControllerReference(bindDef, sa, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			// Update BindDefinition to set automountServiceAccountToken=true
			bindDef.Spec.AutomountServiceAccountToken = ptr.To(true)
			Expect(k8sClient.Update(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			// ensureServiceAccounts handles both create and update
			_, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was updated with automountServiceAccountToken=true
			updatedSa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-update-automount", Namespace: "default"}, updatedSa)).To(Succeed())
			Expect(updatedSa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*updatedSa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, updatedSa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should update ServiceAccount automountServiceAccountToken when value changes from true to false", func() {
			// Create BindDefinition first with automountServiceAccountToken=true
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-update-to-false",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-update-to-false",
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-update-to-false",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(true),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create ServiceAccount with owner reference and automountServiceAccountToken=true
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-update-to-false",
					Namespace: "default",
					Labels:    helpers.BuildResourceLabels(bindDef.Labels),
				},
				AutomountServiceAccountToken: ptr.To(true),
			}
			Expect(controllerutil.SetControllerReference(bindDef, sa, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			// Update BindDefinition to set automountServiceAccountToken=false
			bindDef.Spec.AutomountServiceAccountToken = ptr.To(false)
			Expect(k8sClient.Update(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			// ensureServiceAccounts handles both create and update
			_, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was updated with automountServiceAccountToken=false
			updatedSa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-update-to-false", Namespace: "default"}, updatedSa)).To(Succeed())
			Expect(updatedSa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*updatedSa.AutomountServiceAccountToken).To(BeFalse())

			// Cleanup
			Expect(k8sClient.Delete(ctx, updatedSa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})
})

func TestDeleteClusterRoleBinding(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned CRB successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-crb-bd", UID: "del-crb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-crb-target",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		crbName := helpers.BuildBindingName("del-crb-target", "admin")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-crb-bd", UID: "del-crb-uid", Controller: &isController},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, crb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "admin")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent CRB", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-crb-bd", UID: "nf-crb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "nonexistent")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns NoOwnerRef for unowned CRB", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-crb-bd", UID: "unowned-crb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-target"},
		}

		crbName := helpers.BuildBindingName("unowned-target", "admin")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: crbName},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, crb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "admin")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})
}

func TestDeleteRoleBinding(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned RoleBinding successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-rb-bd", UID: "del-rb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-rb-target",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		rbName := helpers.BuildBindingName("del-rb-target", "view")
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-rb-bd", UID: "del-rb-uid", Controller: &isController},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, rb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent RoleBinding", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-rb-bd", UID: "nf-rb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-rb-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "gone-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns NoOwnerRef for unowned RoleBinding", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-rb-bd", UID: "unowned-rb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-rb-target"},
		}

		rbName := helpers.BuildBindingName("unowned-rb-target", "view")
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: rbName, Namespace: "test-ns"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, rb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})
}

func TestDeleteServiceAccountUnit(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned SA successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-sa-bd", UID: "del-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-sa-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "my-sa", Namespace: "test-ns"}},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-sa",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-sa-bd", UID: "del-sa-uid", Controller: &isController},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "my-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent SA", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-sa-bd", UID: "nf-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-sa-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "gone-sa", "gone-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns NoOwnerRef for unowned SA", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-sa-bd", UID: "unowned-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-sa-target"},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-sa", Namespace: "test-ns"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "unowned-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})

	t.Run("skips SA referenced by other BindDefinitions", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "shared-sa-bd", UID: "shared-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "shared-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "test-ns"}},
			},
		}

		otherBD := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "other-bd", UID: "other-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "other-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "test-ns"}},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shared-sa",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "shared-sa-bd", UID: "shared-sa-uid", Controller: &isController},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, otherBD, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "shared-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})
}

func TestValidateServiceAccountNamespace(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("returns namespace when it exists and is active", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "existing-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).NotTo(BeNil())
		g.Expect(result.Name).To(Equal("existing-ns"))
	})

	t.Run("returns nil,nil for terminating namespace", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "term-ns",
				DeletionTimestamp: &now,
				Finalizers:        []string{"kubernetes"},
			},
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "term-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})

	t.Run("returns nil,nil for non-existent namespace", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "missing-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})
}

func TestFilterActiveNamespaces(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("filters out terminating namespaces", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "filter-bd"},
		}

		now := metav1.Now()
		namespaces := map[string]corev1.Namespace{
			"active-ns": {
				ObjectMeta: metav1.ObjectMeta{Name: "active-ns"},
				Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
			},
			"terminating-ns": {
				ObjectMeta: metav1.ObjectMeta{
					Name:              "terminating-ns",
					DeletionTimestamp: &now,
					Finalizers:        []string{"kubernetes"},
				},
				Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result := r.filterActiveNamespaces(ctx, bindDef, namespaces)
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("active-ns"))
	})

	t.Run("returns empty for all terminating", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "filter-empty-bd"},
		}

		now := metav1.Now()
		namespaces := map[string]corev1.Namespace{
			"term1": {
				ObjectMeta: metav1.ObjectMeta{Name: "term1", DeletionTimestamp: &now, Finalizers: []string{"k"}},
				Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result := r.filterActiveNamespaces(ctx, bindDef, namespaces)
		g.Expect(result).To(BeEmpty())
	})
}

func TestResolveRoleBindingNamespaces(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("resolves explicit namespace", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "explicit-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			Namespace:       "explicit-ns",
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("explicit-ns"))
	})

	t.Run("returns nil for non-existent explicit namespace", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			Namespace:       "missing-ns",
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})

	t.Run("resolves namespaces by label selector", func(t *testing.T) {
		g := NewWithT(t)

		ns1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "labeled-ns", Labels: map[string]string{"env": "test"}},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "unlabeled-ns"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns1, ns2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			NamespaceSelector: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"env": "test"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("labeled-ns"))
	})

	t.Run("deduplicates namespaces from multiple selectors", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "multi-label-ns",
				Labels: map[string]string{"env": "test", "team": "alpha"},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			NamespaceSelector: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"env": "test"}},
				{MatchLabels: map[string]string{"team": "alpha"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1)) // deduplicated
	})
}

func TestEnsureServiceAccountsUnit(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("creates SA in existing namespace", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "ensure-sa-bd", UID: "ensure-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "ensure-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "new-sa", Namespace: "sa-ns"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef, ns).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(HaveLen(1))
		g.Expect(generatedSAs[0].Name).To(Equal("new-sa"))

		// Verify SA was created
		sa := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, client.ObjectKey{Name: "new-sa", Namespace: "sa-ns"}, sa)).To(Succeed())
	})

	t.Run("skips non-ServiceAccount subjects", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "skip-sa-bd", UID: "skip-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "skip-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
					{Kind: "User", Name: "admin", APIGroup: rbacv1.GroupName},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(BeEmpty())
	})

	t.Run("skips SA in non-existent namespace", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "no-ns-sa-bd", UID: "no-ns-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "no-ns-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "orphan-sa", Namespace: "nonexistent-ns"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(BeEmpty())
	})
}

var _ = Describe("BindDefinition Event Assertions", func() {
	ctx := context.Background()

	Describe("deleteServiceAccount events", func() {
		It("should emit a Deletion event when ServiceAccount has no OwnerRef", func() {
			// Create ServiceAccount without owner reference.
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-event-no-owner",
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, sa) }()

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd-event-no-owner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-event-no-owner",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-event-no-owner", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Not deleting"))
			Expect(event).To(ContainSubstring("OwnerRef"))
		})

		It("should emit a Deletion event when ServiceAccount is deleted", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd-event-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-sa-event-delete",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			// Fetch to get UID for owner reference.
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-event-delete",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         authorizationv1alpha1.GroupVersion.String(),
							Kind:               "BindDefinition",
							Name:               bindDef.Name,
							UID:                bindDef.UID,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-event-delete", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Deleting target resource ServiceAccount"))
		})
	})

	Describe("deleteClusterRoleBinding events", func() {
		It("should emit a Deletion event when CRB has no OwnerRef", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bd-crb-event"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "test-crb-event",
					Subjects:   []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			// Create ClusterRoleBinding without owner reference.
			crbName := helpers.BuildBindingName(bindDef.Spec.TargetName, "cluster-admin")
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: crbName},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			}
			Expect(k8sClient.Create(ctx, crb)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, crb) }()

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "cluster-admin")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Not deleting"))
		})
	})
})

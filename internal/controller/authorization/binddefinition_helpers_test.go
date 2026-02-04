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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
			got := buildBindingName(tt.targetName, tt.roleRef)
			if got != tt.want {
				t.Errorf("buildBindingName(%q, %q) = %q, want %q",
					tt.targetName, tt.roleRef, got, tt.want)
			}
		})
	}
}

func TestSubjectsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []rbacv1.Subject
		b    []rbacv1.Subject
		want bool
	}{
		{
			name: "both empty",
			a:    []rbacv1.Subject{},
			b:    []rbacv1.Subject{},
			want: true,
		},
		{
			name: "same single subject",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			want: true,
		},
		{
			name: "different length",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:    []rbacv1.Subject{},
			want: false,
		},
		{
			name: "different subjects",
			a:    []rbacv1.Subject{{Kind: "Group", Name: "admins"}},
			b:    []rbacv1.Subject{{Kind: "Group", Name: "users"}},
			want: false,
		},
		{
			name: "multiple equal subjects",
			a: []rbacv1.Subject{
				{Kind: "Group", Name: "admins"},
				{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
			},
			b: []rbacv1.Subject{
				{Kind: "Group", Name: "admins"},
				{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := helpers.SubjectsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("SubjectsEqual() = %v, want %v", got, tt.want)
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

	Describe("createServiceAccounts", func() {
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

			result := reconciler.createServiceAccounts(ctx, bindDef)
			Expect(result.err).NotTo(HaveOccurred())

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

			result := reconciler.createServiceAccounts(ctx, bindDef)
			Expect(result.err).NotTo(HaveOccurred())

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

			result := reconciler.createServiceAccounts(ctx, bindDef)
			Expect(result.err).NotTo(HaveOccurred())

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

	Describe("updateServiceAccounts", func() {
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
					Labels:    buildResourceLabels(bindDef.Labels),
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

			err := reconciler.updateServiceAccounts(ctx, bindDef)
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
					Labels:    buildResourceLabels(bindDef.Labels),
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

			err := reconciler.updateServiceAccounts(ctx, bindDef)
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

// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
)

func TestSSA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "API SSA Suite")
}

func newTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	err := authv1alpha1.AddToScheme(scheme)
	Expect(err).NotTo(HaveOccurred())
	return scheme
}

var _ = Describe("SSA Status Apply Functions", func() {
	Context("FieldOwner constant", func() {
		It("should be set to auth-operator", func() {
			Expect(ssa.FieldOwner).To(Equal("auth-operator"))
		})
	})

	Context("ApplyRoleDefinitionStatus", func() {
		It("should successfully apply status to an existing RoleDefinition", func() {
			scheme := newTestScheme()

			rd := &authv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-roledefinition",
				},
				Spec: authv1alpha1.RoleDefinitionSpec{
					TargetRole: authv1alpha1.DefinitionClusterRole,
					TargetName: "test-role",
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(rd).
				WithStatusSubresource(&authv1alpha1.RoleDefinition{}).
				Build()

			// Update status
			rd.Status.RoleReconciled = true
			rd.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Reconciled",
					Message:            "RoleDefinition is ready",
					LastTransitionTime: metav1.Now(),
				},
			}

			err := ssa.ApplyRoleDefinitionStatus(context.Background(), c, rd)
			Expect(err).NotTo(HaveOccurred())

			// Verify the status was updated
			var updated authv1alpha1.RoleDefinition
			err = c.Get(context.Background(), client.ObjectKeyFromObject(rd), &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.RoleReconciled).To(BeTrue())
			Expect(updated.Status.Conditions).To(HaveLen(1))
			Expect(updated.Status.Conditions[0].Type).To(Equal("Ready"))
		})

		It("should return error when RoleDefinition does not exist", func() {
			scheme := newTestScheme()

			// The fake client does not enforce status subresource semantics for SSA,
			// so we use an interceptor to simulate the real API-server behaviour:
			// SubResource("status").Apply on a non-existent parent returns NotFound.
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&authv1alpha1.RoleDefinition{}).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
						return fmt.Errorf("roledefinitions \"non-existent\" not found")
					},
				}).
				Build()

			rd := &authv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent",
				},
				Status: authv1alpha1.RoleDefinitionStatus{
					RoleReconciled: true,
				},
			}

			// Status apply on a non-existent object must fail (matches real API server behavior).
			err := ssa.ApplyRoleDefinitionStatus(context.Background(), c, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("non-existent"))
		})

		It("should update existing status with new conditions", func() {
			scheme := newTestScheme()

			rd := &authv1alpha1.RoleDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-roledefinition",
				},
				Spec: authv1alpha1.RoleDefinitionSpec{
					TargetRole: authv1alpha1.DefinitionClusterRole,
					TargetName: "test-role",
				},
				Status: authv1alpha1.RoleDefinitionStatus{
					RoleReconciled: false,
					Conditions: []metav1.Condition{
						{
							Type:               "Ready",
							Status:             metav1.ConditionFalse,
							Reason:             "Pending",
							Message:            "Not ready yet",
							LastTransitionTime: metav1.Now(),
						},
					},
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(rd).
				WithStatusSubresource(&authv1alpha1.RoleDefinition{}).
				Build()

			// First update
			rd.Status.RoleReconciled = true
			rd.Status.Conditions[0].Status = metav1.ConditionTrue
			rd.Status.Conditions[0].Reason = "Reconciled"
			rd.Status.Conditions[0].Message = "Ready"

			err := ssa.ApplyRoleDefinitionStatus(context.Background(), c, rd)
			Expect(err).NotTo(HaveOccurred())

			// Verify first update
			var updated authv1alpha1.RoleDefinition
			err = c.Get(context.Background(), client.ObjectKeyFromObject(rd), &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.RoleReconciled).To(BeTrue())

			// Second update - add another condition
			updated.Status.Conditions = append(updated.Status.Conditions, metav1.Condition{
				Type:               "Progressing",
				Status:             metav1.ConditionFalse,
				Reason:             "Complete",
				Message:            "Done",
				LastTransitionTime: metav1.Now(),
			})

			err = ssa.ApplyRoleDefinitionStatus(context.Background(), c, &updated)
			Expect(err).NotTo(HaveOccurred())

			// Verify second update
			var finalUpdated authv1alpha1.RoleDefinition
			err = c.Get(context.Background(), client.ObjectKeyFromObject(rd), &finalUpdated)
			Expect(err).NotTo(HaveOccurred())
			Expect(finalUpdated.Status.Conditions).To(HaveLen(2))
		})
	})

	Context("ApplyBindDefinitionStatus", func() {
		It("should successfully apply status with service accounts", func() {
			scheme := newTestScheme()

			bd := &authv1alpha1.BindDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "BindDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-binddefinition",
				},
				Spec: authv1alpha1.BindDefinitionSpec{
					TargetName: "test-binding",
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
					},
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(bd).
				WithStatusSubresource(&authv1alpha1.BindDefinition{}).
				Build()

			// Update status
			bd.Status.BindReconciled = true
			bd.Status.GeneratedServiceAccounts = []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"},
			}
			bd.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Reconciled",
					Message:            "BindDefinition is ready",
					LastTransitionTime: metav1.Now(),
				},
			}

			err := ssa.ApplyBindDefinitionStatus(context.Background(), c, bd)
			Expect(err).NotTo(HaveOccurred())

			// Verify the status was updated
			var updated authv1alpha1.BindDefinition
			err = c.Get(context.Background(), client.ObjectKeyFromObject(bd), &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.BindReconciled).To(BeTrue())
			Expect(updated.Status.GeneratedServiceAccounts).To(HaveLen(1))
			Expect(updated.Status.GeneratedServiceAccounts[0].Name).To(Equal("test-sa"))
			Expect(updated.Status.Conditions).To(HaveLen(1))
		})

		It("should return error when BindDefinition does not exist", func() {
			scheme := newTestScheme()

			// The fake client does not enforce status subresource semantics for SSA,
			// so we use an interceptor to simulate the real API-server behaviour:
			// SubResource("status").Apply on a non-existent parent returns NotFound.
			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithStatusSubresource(&authv1alpha1.BindDefinition{}).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceApply: func(_ context.Context, _ client.Client, _ string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
						return fmt.Errorf("binddefinitions \"non-existent\" not found")
					},
				}).
				Build()

			bd := &authv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "non-existent",
				},
				Status: authv1alpha1.BindDefinitionStatus{
					BindReconciled: true,
				},
			}

			// Status apply on a non-existent object must fail (matches real API server behavior).
			err := ssa.ApplyBindDefinitionStatus(context.Background(), c, bd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("non-existent"))
		})

		It("should handle multiple conditions", func() {
			scheme := newTestScheme()

			bd := &authv1alpha1.BindDefinition{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "BindDefinition",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-binddefinition",
				},
				Spec: authv1alpha1.BindDefinitionSpec{
					TargetName: "test-binding",
					Subjects: []rbacv1.Subject{
						{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
					},
				},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(bd).
				WithStatusSubresource(&authv1alpha1.BindDefinition{}).
				Build()

			// Set multiple conditions
			bd.Status.BindReconciled = true
			bd.Status.Conditions = []metav1.Condition{
				{
					Type:               "Finalizer",
					Status:             metav1.ConditionTrue,
					Reason:             "Set",
					Message:            "Finalizer set",
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               "RoleRefValid",
					Status:             metav1.ConditionTrue,
					Reason:             "Valid",
					Message:            "All role refs exist",
					LastTransitionTime: metav1.Now(),
				},
				{
					Type:               "Create",
					Status:             metav1.ConditionTrue,
					Reason:             "Created",
					Message:            "Bindings created",
					LastTransitionTime: metav1.Now(),
				},
			}

			err := ssa.ApplyBindDefinitionStatus(context.Background(), c, bd)
			Expect(err).NotTo(HaveOccurred())

			var updated authv1alpha1.BindDefinition
			err = c.Get(context.Background(), client.ObjectKeyFromObject(bd), &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.BindReconciled).To(BeTrue())
			Expect(updated.Status.Conditions).To(HaveLen(3))
		})
	})

	Context("ApplyWebhookAuthorizerStatus", func() {
		It("should successfully apply status", func() {
			scheme := newTestScheme()

			wa := &authv1alpha1.WebhookAuthorizer{
				TypeMeta: metav1.TypeMeta{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "WebhookAuthorizer",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-webhookauthorizer",
				},
				Spec: authv1alpha1.WebhookAuthorizerSpec{},
			}

			c := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(wa).
				WithStatusSubresource(&authv1alpha1.WebhookAuthorizer{}).
				Build()

			// Update status
			wa.Status.AuthorizerConfigured = true
			wa.Status.Conditions = []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "Configured",
					Message:            "WebhookAuthorizer is configured",
					LastTransitionTime: metav1.Now(),
				},
			}

			err := ssa.ApplyWebhookAuthorizerStatus(context.Background(), c, wa)
			Expect(err).NotTo(HaveOccurred())

			// Verify the status was updated
			var updated authv1alpha1.WebhookAuthorizer
			err = c.Get(context.Background(), client.ObjectKeyFromObject(wa), &updated)
			Expect(err).NotTo(HaveOccurred())
			Expect(updated.Status.AuthorizerConfigured).To(BeTrue())
			Expect(updated.Status.Conditions).To(HaveLen(1))
		})
	})
})

var _ = Describe("SSA Status Conversion Functions", func() {
	Context("RoleDefinitionStatusFrom", func() {
		It("should return nil for nil status", func() {
			result := ssa.RoleDefinitionStatusFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert an empty status", func() {
			status := &authv1alpha1.RoleDefinitionStatus{}
			result := ssa.RoleDefinitionStatusFrom(status)
			Expect(result).NotTo(BeNil())
			Expect(result.RoleReconciled).NotTo(BeNil())
			Expect(*result.RoleReconciled).To(BeFalse())
		})

		It("should convert status with conditions", func() {
			status := &authv1alpha1.RoleDefinitionStatus{
				RoleReconciled: true,
				Conditions: []metav1.Condition{
					{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "Reconciled",
						Message:            "Success",
						ObservedGeneration: 1,
						LastTransitionTime: metav1.Now(),
					},
					{
						Type:               "Progressing",
						Status:             metav1.ConditionFalse,
						Reason:             "Completed",
						Message:            "No longer progressing",
						ObservedGeneration: 1,
						LastTransitionTime: metav1.Now(),
					},
				},
			}

			result := ssa.RoleDefinitionStatusFrom(status)
			Expect(result).NotTo(BeNil())
			Expect(*result.RoleReconciled).To(BeTrue())
			Expect(result.Conditions).To(HaveLen(2))
		})
	})

	Context("BindDefinitionStatusFrom", func() {
		It("should return nil for nil status", func() {
			result := ssa.BindDefinitionStatusFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert status with service accounts", func() {
			status := &authv1alpha1.BindDefinitionStatus{
				BindReconciled: true,
				GeneratedServiceAccounts: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "sa1", Namespace: "ns1"},
					{Kind: "ServiceAccount", Name: "sa2", Namespace: "ns2"},
				},
				Conditions: []metav1.Condition{
					{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "Reconciled",
						Message:            "Success",
						LastTransitionTime: metav1.Now(),
					},
				},
			}

			result := ssa.BindDefinitionStatusFrom(status)
			Expect(result).NotTo(BeNil())
			Expect(*result.BindReconciled).To(BeTrue())
			Expect(result.GeneratedServiceAccounts).To(HaveLen(2))
			Expect(result.Conditions).To(HaveLen(1))
		})
	})

	Context("WebhookAuthorizerStatusFrom", func() {
		It("should return nil for nil status", func() {
			result := ssa.WebhookAuthorizerStatusFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert status with conditions", func() {
			status := &authv1alpha1.WebhookAuthorizerStatus{
				AuthorizerConfigured: true,
				Conditions: []metav1.Condition{
					{
						Type:               "Ready",
						Status:             metav1.ConditionTrue,
						Reason:             "Configured",
						Message:            "Ready",
						LastTransitionTime: metav1.Now(),
					},
				},
			}

			result := ssa.WebhookAuthorizerStatusFrom(status)
			Expect(result).NotTo(BeNil())
			Expect(*result.AuthorizerConfigured).To(BeTrue())
			Expect(result.Conditions).To(HaveLen(1))
		})
	})

	Context("ConditionFrom", func() {
		It("should return nil for nil condition", func() {
			result := ssa.ConditionFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert a full condition", func() {
			now := metav1.Now()
			condition := &metav1.Condition{
				Type:               "Ready",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 5,
				LastTransitionTime: now,
				Reason:             "AllReady",
				Message:            "All components are ready",
			}

			result := ssa.ConditionFrom(condition)
			Expect(result).NotTo(BeNil())
			Expect(*result.Type).To(Equal("Ready"))
			Expect(*result.Status).To(Equal(metav1.ConditionTrue))
			Expect(*result.ObservedGeneration).To(Equal(int64(5)))
			Expect(*result.LastTransitionTime).To(Equal(now))
			Expect(*result.Reason).To(Equal("AllReady"))
			Expect(*result.Message).To(Equal("All components are ready"))
		})
	})
})

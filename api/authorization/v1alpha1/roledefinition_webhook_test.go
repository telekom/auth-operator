/*
Copyright © 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/
package v1alpha1

import (
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var _ = Describe("RoleDefinition Webhook", func() {

	Context("When creating RoleDefinition under Validating Webhook", func() {

		It("Should admit a valid ClusterRole RoleDefinition", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-clusterrole",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-valid-clusterrole",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should admit a valid namespaced Role RoleDefinition", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-valid-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny when targetRole is Role but targetNamespace is empty", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-role-no-ns",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-role-no-ns",
					ScopeNamespaced: true,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("targetNamespace is required when targetRole is 'Role'"))
		})

		It("Should deny when targetRole is ClusterRole but targetNamespace is set", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-cr-with-ns",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-cr-with-ns",
					TargetNamespace: "default",
					ScopeNamespaced: false,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("targetNamespace must be empty when targetRole is 'ClusterRole'"))
		})

		It("Should deny duplicate targetName for the same targetRole", func() {
			rd1 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-first",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-target-name",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd1)).To(Succeed())

			// The webhook validator uses the manager's cached client for MatchingFields lookups.
			// Use DryRun to poll until the informer cache has synced rd1, avoiding side effects.
			rd2 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-second",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "shared-target-name",
					ScopeNamespaced: false,
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("targetName shared-target-name is already in use"))
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd1)).To(Succeed())
		})

		It("Should allow same targetName for different targetRoles", func() {
			rd1 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-cr",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "cross-role-target",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd1)).To(Succeed())

			// Wait for the informer cache to sync rd1 before verifying cross-role allowance.
			rd2 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "cross-role-target",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			Eventually(func(g Gomega) {
				// DryRun: Cache must have synced rd1 for this check to be meaningful.
				// The webhook should allow this since targetRoles differ.
				err := k8sClient.Create(ctx, rd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).NotTo(HaveOccurred())
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			// Now actually create rd2.
			Expect(k8sClient.Create(ctx, rd2)).To(Succeed())

			// Cleanup
			Expect(k8sClient.Delete(ctx, rd1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd2)).To(Succeed())
		})

		It("Should allow same targetName for namespaced Role targets in different namespaces", func() {
			rd1 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-role-team-a",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "shared-role-name",
					TargetNamespace: "team-a",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rd1)).To(Succeed())

			rd2 := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-same-name-role-team-b",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "shared-role-name",
					TargetNamespace: "team-b",
					ScopeNamespaced: true,
				},
			}
			Eventually(func(g Gomega) {
				err := k8sClient.Create(ctx, rd2.DeepCopy(), client.DryRunAll)
				g.Expect(err).NotTo(HaveOccurred())
			}).WithTimeout(10 * time.Second).WithPolling(250 * time.Millisecond).Should(Succeed())

			Expect(k8sClient.Create(ctx, rd2)).To(Succeed())

			Expect(k8sClient.Delete(ctx, rd1)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd2)).To(Succeed())
		})

		It("Should admit a ClusterRole with aggregationLabels", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-labels",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-labels",
					ScopeNamespaced: false,
					AggregationLabels: map[string]string{
						"custom.example.com/aggregate-to-monitoring": "true",
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny aggregationLabels on a namespaced Role", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-labels-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-agg-labels-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
					AggregationLabels: map[string]string{
						"rbac.authorization.k8s.io/aggregate-to-view": "true",
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregationLabels can only be used when targetRole is 'ClusterRole'"))
		})

		It("Should admit a ClusterRole with aggregateFrom", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-from",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-from",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny aggregateFrom on a namespaced Role", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-from-role",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-agg-from-role",
					TargetNamespace: "default",
					ScopeNamespaced: true,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregateFrom can only be used when targetRole is 'ClusterRole'"))
		})

		It("Should deny aggregateFrom with restrictedVerbs", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-restricted",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-restricted",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
						},
					},
					RestrictedVerbs: []string{"delete"},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregateFrom is mutually exclusive"))
		})

		It("Should deny aggregateFrom with empty selectors", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-empty-sel",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-empty-sel",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have at least one clusterRoleSelector"))
		})

		It("Should deny aggregation labels targeting cluster-admin", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-builtin-cluster-admin",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-builtin-cluster-admin",
					ScopeNamespaced: false,
					AggregationLabels: map[string]string{
						"rbac.authorization.k8s.io/aggregate-to-cluster-admin": "true",
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred(), "expected rejection for aggregate-to-cluster-admin")
			Expect(apierrors.IsForbidden(err)).To(BeTrue(), "expected Forbidden status error")
			Expect(err.Error()).To(ContainSubstring("built-in ClusterRole"))
		})

		It("Should allow aggregation labels targeting admin, edit, and view", func() {
			for _, target := range []string{"admin", "edit", "view"} {
				rd := &RoleDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-agg-allowed-" + target,
					},
					Spec: RoleDefinitionSpec{
						TargetRole:      DefinitionClusterRole,
						TargetName:      "test-agg-allowed-" + target,
						ScopeNamespaced: false,
						AggregationLabels: map[string]string{
							"rbac.authorization.k8s.io/aggregate-to-" + target: "true",
						},
					},
				}
				err := k8sClient.Create(ctx, rd)
				Expect(err).NotTo(HaveOccurred(), "aggregate-to-%s should be allowed per issue #51", target)
				DeferCleanup(func() {
					_ = k8sClient.Delete(ctx, rd)
				})
			}
		})

		It("Should deny aggregateFrom with empty selector criteria", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-empty-criteria",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-agg-empty-criteria",
					ScopeNamespaced: false,
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{}, // empty selector — no matchLabels, no matchExpressions
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("empty selector would match all ClusterRoles"))
		})
	})

	Context("RestrictedAPIs version validation", func() {

		It("Should admit a RoleDefinition with valid API version strings", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-versions",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-valid-versions",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name: "apps",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "apps/v1", Version: "v1"},
								{GroupVersion: "apps/v1beta1", Version: "v1beta1"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should deny a version missing the 'v' prefix", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-bad-version-prefix",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-bad-version-prefix",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name: "apps",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "apps/1.0", Version: "1.0"},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must start with 'v'"))
		})

		It("Should deny a version exceeding 20 characters", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-version-too-long",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-version-too-long",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name: "apps",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "apps/v12345678901234567890", Version: "v12345678901234567890"},
							},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must start with 'v' and be at most 20 characters"))
		})

		It("Should admit a version at exactly 20 characters", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-version-boundary",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-version-boundary",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name: "apps",
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "apps/v1234567890123456789", Version: "v1234567890123456789"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})
	})

	Context("Update Immutability", func() {
		It("should deny update that changes targetRole", func() {
			// Create a Role-scoped RD (valid initial state with targetNamespace).
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-targetrole",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-immut-targetrole",
					TargetNamespace: "default",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Changing targetRole to ClusterRole is a valid new state on its
			// own, but our immutability check must reject the mutation.
			rd.Spec.TargetRole = DefinitionClusterRole
			rd.Spec.TargetNamespace = ""
			err := k8sClient.Update(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.targetRole"))
			Expect(err.Error()).To(ContainSubstring("immutable"))

			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("should deny update that changes targetName", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-targetname",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-immut-targetname",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			rd.Spec.TargetName = "changed-target-name"
			err := k8sClient.Update(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.targetName"))
			Expect(err.Error()).To(ContainSubstring("immutable"))

			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("should deny update that changes targetNamespace", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-targetnamespace",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-immut-targetnamespace",
					TargetNamespace: "team-a",
					ScopeNamespaced: true,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			rd.Spec.TargetNamespace = "team-b"
			err := k8sClient.Update(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.targetNamespace"))
			Expect(err.Error()).To(ContainSubstring("immutable"))

			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("should allow update that does not change targetRole or targetName", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-immut-allowed",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-immut-allowed",
					ScopeNamespaced: false,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			// Only change scopeNamespaced (allowed)
			rd.Spec.ScopeNamespaced = true
			Expect(k8sClient.Update(ctx, rd)).To(Succeed())

			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})
	})

	Context("MaxItems and field validation constraints", func() {

		It("should reject RestrictedVerbs exceeding MaxItems=16", func() {
			verbs := make([]string, 17)
			for i := range verbs {
				verbs[i] = "get"
			}
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-maxitems-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-maxitems-verbs",
					ScopeNamespaced: false,
					RestrictedVerbs: verbs,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid status reason")
			statusErr := &apierrors.StatusError{}
			Expect(errors.As(err, &statusErr)).To(BeTrue())
			Expect(statusErr.ErrStatus.Details.Causes).To(ContainElement(
				Satisfy(func(c metav1.StatusCause) bool {
					return c.Field == "spec.restrictedVerbs"
				}),
			), "expected cause targeting spec.restrictedVerbs")
		})

		It("should reject RestrictedVerbs with empty string item", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-verb-empty",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-verb-empty",
					ScopeNamespaced: false,
					RestrictedVerbs: []string{""},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid status reason")
			statusErr := &apierrors.StatusError{}
			Expect(errors.As(err, &statusErr)).To(BeTrue())
			Expect(statusErr.ErrStatus.Details.Causes).To(ContainElement(
				Satisfy(func(c metav1.StatusCause) bool {
					return c.Field == "spec.restrictedVerbs[0]"
				}),
			), "expected cause targeting spec.restrictedVerbs[0]")
		})

		It("should reject RestrictedVerbs with invalid pattern", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-verb-pattern",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-verb-pattern",
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"GET"},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid status reason")
			statusErr := &apierrors.StatusError{}
			Expect(errors.As(err, &statusErr)).To(BeTrue())
			Expect(statusErr.ErrStatus.Details.Causes).To(ContainElement(
				Satisfy(func(c metav1.StatusCause) bool {
					return c.Field == "spec.restrictedVerbs[0]"
				}),
			), "expected cause targeting spec.restrictedVerbs[0]")
		})

		It("should accept valid RestrictedVerbs within limits", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-valid-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-valid-verbs",
					ScopeNamespaced: false,
					RestrictedVerbs: []string{"get", "list", "watch", "*"},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("should reject RestrictedResources exceeding MaxItems=128", func() {
			resources := make([]metav1.APIResource, 129)
			for i := range resources {
				resources[i] = metav1.APIResource{
					Name:         fmt.Sprintf("resource%d", i),
					SingularName: fmt.Sprintf("resource%d", i),
					Kind:         fmt.Sprintf("Resource%d", i),
					Namespaced:   true,
					Verbs:        metav1.Verbs{"get", "list"},
				}
			}
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-maxitems-resources",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:          DefinitionClusterRole,
					TargetName:          "test-maxitems-resources",
					ScopeNamespaced:     false,
					RestrictedResources: resources,
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected Invalid status reason")
			statusErr := &apierrors.StatusError{}
			Expect(errors.As(err, &statusErr)).To(BeTrue())
			Expect(statusErr.ErrStatus.Details.Causes).To(ContainElement(
				Satisfy(func(c metav1.StatusCause) bool {
					return c.Field == "spec.restrictedResources"
				}),
			), "expected cause targeting spec.restrictedResources")
		})
	})

	Context("RestrictedAPIs verb restrictions (Issue #236)", func() {

		It("Should admit a RoleDefinition with per-API-group verb restrictions", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-api-group-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-api-group-verbs",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name:  "storage.k8s.io",
							Verbs: []string{"create", "update", "patch", "delete"},
							Versions: []metav1.GroupVersionForDiscovery{
								{GroupVersion: "storage.k8s.io/v1", Version: "v1"},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should admit a RoleDefinition with empty Verbs (backward compatible full block)", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-empty-verbs-block",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-empty-verbs-block",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{Name: "velero.io"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should admit mixed fully blocked and verb-restricted API groups", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-mixed-api-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-mixed-api-verbs",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{Name: "velero.io"}, // fully blocked
						{
							Name:  "storage.k8s.io",
							Verbs: []string{"create", "delete", "deletecollection"},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())
			Expect(k8sClient.Delete(ctx, rd)).To(Succeed())
		})

		It("Should still reject aggregateFrom with restrictedApis that have Verbs", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-agg-with-api-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-agg-with-api-verbs",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
					RestrictedAPIs: []RestrictedAPIGroup{
						{
							Name:  "apps",
							Verbs: []string{"delete"},
						},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("aggregateFrom is mutually exclusive"))
		})

		It("Should reject duplicate API group names in RestrictedAPIs", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-dup-api-group",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-dup-api-group",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{Name: "apps", Verbs: []string{"delete"}},
						{Name: "apps", Verbs: []string{"create"}},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("duplicate"))
		})

		It("Should reject RestrictedAPIs verbs with invalid pattern (uppercase)", func() {
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-invalid-verb-pattern",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-invalid-verb-pattern",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{Name: "apps", Verbs: []string{"GET"}},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
		})

		It("Should reject RestrictedAPIs verbs exceeding MaxItems=16", func() {
			// Use 17 distinct lowercase-letter-only verbs to match the CRD regex ^([a-z]+|\\*)$
			manyVerbs := []string{
				"get", "list", "create", "update", "patch", "delete", "watch",
				"deletecollection", "proxy", "bind", "escalate", "impersonate",
				"approve", "sign", "attest", "audit", "manage",
			}
			rd := &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-too-many-verbs",
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-too-many-verbs",
					ScopeNamespaced: false,
					RestrictedAPIs: []RestrictedAPIGroup{
						{Name: "apps", Verbs: manyVerbs},
					},
				},
			}
			err := k8sClient.Create(ctx, rd)
			Expect(err).To(HaveOccurred())
		})
	})
})

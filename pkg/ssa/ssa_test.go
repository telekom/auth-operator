// SPDX-FileCopyrightText: 2025 Deutsche Telekom IT GmbH
//
// SPDX-License-Identifier: Apache-2.0

package ssa_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/telekom/auth-operator/pkg/ssa"
)

// Suite-level variables for envtest (shared across integration tests)
var (
	testEnv   *envtest.Environment
	k8sClient client.Client
	testCtx   context.Context
)

func TestSSA(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SSA Suite")
}

// BeforeSuite starts envtest once for all integration tests
var _ = BeforeSuite(func() {
	testCtx = context.Background()

	// Create a fresh scheme to avoid mutating global state
	testScheme := runtime.NewScheme()
	err := rbacv1.AddToScheme(testScheme)
	Expect(err).NotTo(HaveOccurred())

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: false,
	}

	// Only set BinaryAssetsDirectory if KUBEBUILDER_ASSETS is not set.
	// This allows CI to use setup-envtest while still supporting local "go test".
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// Get the directory of this test file to build an absolute path
		_, thisFile, _, ok := goruntime.Caller(0)
		Expect(ok).To(BeTrue(), "failed to determine caller information for BinaryAssetsDirectory")
		repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		// Ensure we have an absolute path (runtime.Caller may return relative paths in some build modes)
		absRepoRoot, absErr := filepath.Abs(repoRoot)
		Expect(absErr).NotTo(HaveOccurred(), "failed to determine absolute repo root for BinaryAssetsDirectory")
		testEnv.BinaryAssetsDirectory = filepath.Join(absRepoRoot, "bin", "k8s",
			fmt.Sprintf("1.34.1-%s-%s", goruntime.GOOS, goruntime.GOARCH))
	}

	cfg, err := testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: testScheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
})

// AfterSuite stops envtest after all tests complete
var _ = AfterSuite(func() {
	if testEnv != nil {
		err := testEnv.Stop()
		Expect(err).NotTo(HaveOccurred())
	}
})

var _ = Describe("SSA Helper Functions", func() {
	Context("FieldOwner constant", func() {
		It("should be set to auth-operator", func() {
			Expect(ssa.FieldOwner).To(Equal("auth-operator"))
		})
	})

	Context("FieldOwnerForBD", func() {
		It("should return prefixed name for short BD names", func() {
			result := ssa.FieldOwnerForBD("my-binddefinition")
			Expect(result).To(Equal("auth-operator/my-binddefinition"))
		})

		It("should fit within 128 characters for any BD name", func() {
			// Very long BD name (253 chars is max K8s name)
			longName := ""
			for range 253 {
				longName += "a"
			}
			result := ssa.FieldOwnerForBD(longName)
			Expect(len(result)).To(BeNumerically("<=", 128))
		})

		It("should produce stable output for same input", func() {
			longName := ""
			for range 200 {
				longName += "x"
			}
			result1 := ssa.FieldOwnerForBD(longName)
			result2 := ssa.FieldOwnerForBD(longName)
			Expect(result1).To(Equal(result2))
		})

		It("should produce different output for different long names", func() {
			longName1 := ""
			longName2 := ""
			for range 200 {
				longName1 += "a"
				longName2 += "b"
			}
			result1 := ssa.FieldOwnerForBD(longName1)
			result2 := ssa.FieldOwnerForBD(longName2)
			Expect(result1).NotTo(Equal(result2))
		})

		It("should not truncate names that fit within limit", func() {
			// 128 - len("auth-operator/") = 114 chars available for BD name
			shortEnoughName := ""
			for range 100 {
				shortEnoughName += "x"
			}
			result := ssa.FieldOwnerForBD(shortEnoughName)
			Expect(result).To(Equal("auth-operator/" + shortEnoughName))
		})
	})

	Context("OwnerReference", func() {
		It("should create an OwnerReference with all fields set", func() {
			uid := types.UID("test-uid-123")
			result := ssa.OwnerReference("v1alpha1", "RoleDefinition", "test-role", uid, true, true)

			Expect(result).NotTo(BeNil())
			Expect(*result.APIVersion).To(Equal("v1alpha1"))
			Expect(*result.Kind).To(Equal("RoleDefinition"))
			Expect(*result.Name).To(Equal("test-role"))
			Expect(*result.UID).To(Equal(uid))
			Expect(*result.Controller).To(BeTrue())
			Expect(*result.BlockOwnerDeletion).To(BeTrue())
		})

		It("should handle non-controller owner references", func() {
			uid := types.UID("test-uid-456")
			result := ssa.OwnerReference("v1", "ConfigMap", "test-cm", uid, false, false)

			Expect(result).NotTo(BeNil())
			Expect(*result.Controller).To(BeFalse())
			Expect(*result.BlockOwnerDeletion).To(BeFalse())
		})
	})

	Context("ClusterRoleWithLabelsAndRules", func() {
		It("should create a ClusterRole with no labels and no rules", func() {
			result := ssa.ClusterRoleWithLabelsAndRules("test-clusterrole", nil, nil)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-clusterrole"))
		})

		It("should create a ClusterRole with labels", func() {
			labels := map[string]string{
				"app":     "auth-operator",
				"version": "v1",
			}
			result := ssa.ClusterRoleWithLabelsAndRules("test-clusterrole", labels, nil)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-clusterrole"))
			Expect(result.Labels).To(Equal(labels))
		})

		It("should create a ClusterRole with rules", func() {
			rules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				},
				{
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployments"},
					Verbs:         []string{"get", "list"},
					ResourceNames: []string{"my-deployment"},
				},
			}
			result := ssa.ClusterRoleWithLabelsAndRules("test-clusterrole", nil, rules)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-clusterrole"))
			Expect(result.Rules).To(HaveLen(2))
		})

		It("should support adding owner references", func() {
			uid := types.UID("test-uid")
			ownerRef := ssa.OwnerReference("authorization.t-caas.telekom.com/v1alpha1", "RoleDefinition", "my-rd", uid, true, true)

			result := ssa.ClusterRoleWithLabelsAndRules("test-cr", nil, nil).
				WithOwnerReferences(ownerRef)

			Expect(result).NotTo(BeNil())
			Expect(result.OwnerReferences).To(HaveLen(1))
			Expect(*result.OwnerReferences[0].Name).To(Equal("my-rd"))
		})
	})

	Context("ClusterRoleWithAggregation", func() {
		It("should create a ClusterRole with aggregation rule and no labels", func() {
			aggRule := &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{"aggregate-to-admin": "true"}},
				},
			}
			result := ssa.ClusterRoleWithAggregation("agg-role", nil, aggRule)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("agg-role"))
			Expect(result.AggregationRule).NotTo(BeNil())
			Expect(result.AggregationRule.ClusterRoleSelectors).To(HaveLen(1))
			Expect(result.AggregationRule.ClusterRoleSelectors[0].MatchLabels).To(
				HaveKeyWithValue("aggregate-to-admin", "true"),
			)
			Expect(result.Rules).To(BeEmpty())
		})

		It("should create a ClusterRole with aggregation rule and labels", func() {
			labels := map[string]string{"app": "auth-operator"}
			aggRule := &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{"role": "viewer"}},
					{MatchLabels: map[string]string{"role": "editor"}},
				},
			}
			result := ssa.ClusterRoleWithAggregation("agg-role-labels", labels, aggRule)

			Expect(result).NotTo(BeNil())
			Expect(result.Labels).To(HaveKeyWithValue("app", "auth-operator"))
			Expect(result.AggregationRule.ClusterRoleSelectors).To(HaveLen(2))
		})

		It("should handle nil aggregation rule", func() {
			result := ssa.ClusterRoleWithAggregation("no-agg", nil, nil)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("no-agg"))
			Expect(result.AggregationRule).To(BeNil())
		})

		It("should handle matchExpressions in selectors", func() {
			aggRule := &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"frontend", "backend"}},
						},
					},
				},
			}
			result := ssa.ClusterRoleWithAggregation("expr-role", nil, aggRule)

			Expect(result).NotTo(BeNil())
			Expect(result.AggregationRule.ClusterRoleSelectors).To(HaveLen(1))
			Expect(result.AggregationRule.ClusterRoleSelectors[0].MatchExpressions).To(HaveLen(1))
			Expect(*result.AggregationRule.ClusterRoleSelectors[0].MatchExpressions[0].Key).To(Equal("tier"))
		})
	})

	Context("LabelSelectorFrom", func() {
		It("should return nil for nil input", func() {
			result := ssa.LabelSelectorFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert matchLabels", func() {
			sel := &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "test"},
			}
			result := ssa.LabelSelectorFrom(sel)
			Expect(result).NotTo(BeNil())
			Expect(result.MatchLabels).To(HaveKeyWithValue("app", "test"))
		})

		It("should convert matchExpressions", func() {
			sel := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "env", Operator: metav1.LabelSelectorOpNotIn, Values: []string{"prod"}},
				},
			}
			result := ssa.LabelSelectorFrom(sel)
			Expect(result).NotTo(BeNil())
			Expect(result.MatchExpressions).To(HaveLen(1))
			Expect(*result.MatchExpressions[0].Key).To(Equal("env"))
		})
	})

	Context("RoleWithLabelsAndRules", func() {
		It("should create a Role with no labels and no rules", func() {
			result := ssa.RoleWithLabelsAndRules("test-role", "default", nil, nil)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-role"))
			Expect(*result.Namespace).To(Equal("default"))
		})

		It("should create a Role with labels and rules", func() {
			labels := map[string]string{
				"app": "auth-operator",
			}
			rules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"configmaps"},
					Verbs:     []string{"get"},
				},
			}
			result := ssa.RoleWithLabelsAndRules("test-role", "test-ns", labels, rules)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-role"))
			Expect(*result.Namespace).To(Equal("test-ns"))
			Expect(result.Labels).To(Equal(labels))
			Expect(result.Rules).To(HaveLen(1))
		})

		It("should support adding owner references", func() {
			uid := types.UID("test-uid")
			ownerRef := ssa.OwnerReference("authorization.t-caas.telekom.com/v1alpha1", "RoleDefinition", "my-rd", uid, true, true)

			result := ssa.RoleWithLabelsAndRules("test-role", "default", nil, nil).
				WithOwnerReferences(ownerRef)

			Expect(result).NotTo(BeNil())
			Expect(result.OwnerReferences).To(HaveLen(1))
			Expect(*result.OwnerReferences[0].Name).To(Equal("my-rd"))
		})
	})

	Context("PolicyRuleFrom", func() {
		It("should return nil for nil rule", func() {
			result := ssa.PolicyRuleFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should handle an empty rule", func() {
			rule := &rbacv1.PolicyRule{}
			result := ssa.PolicyRuleFrom(rule)
			Expect(result).NotTo(BeNil())
		})

		It("should convert a full PolicyRule", func() {
			rule := &rbacv1.PolicyRule{
				APIGroups:       []string{"", "apps"},
				Resources:       []string{"pods", "deployments"},
				Verbs:           []string{"get", "list", "watch", "create"},
				ResourceNames:   []string{"specific-pod"},
				NonResourceURLs: []string{"/healthz"},
			}
			result := ssa.PolicyRuleFrom(rule)

			Expect(result).NotTo(BeNil())
			Expect(result.APIGroups).To(Equal([]string{"", "apps"}))
			Expect(result.Resources).To(Equal([]string{"pods", "deployments"}))
			Expect(result.Verbs).To(Equal([]string{"get", "list", "watch", "create"}))
			Expect(result.ResourceNames).To(Equal([]string{"specific-pod"}))
			Expect(result.NonResourceURLs).To(Equal([]string{"/healthz"}))
		})
	})

	Context("SubjectFrom", func() {
		It("should return nil for nil subject", func() {
			result := ssa.SubjectFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert a User subject", func() {
			subject := &rbacv1.Subject{
				Kind:     "User",
				Name:     "test-user",
				APIGroup: rbacv1.GroupName,
			}
			result := ssa.SubjectFrom(subject)

			Expect(result).NotTo(BeNil())
			Expect(*result.Kind).To(Equal("User"))
			Expect(*result.Name).To(Equal("test-user"))
			Expect(*result.APIGroup).To(Equal(rbacv1.GroupName))
		})

		It("should convert a ServiceAccount subject", func() {
			subject := &rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "test-sa",
				Namespace: "test-ns",
			}
			result := ssa.SubjectFrom(subject)

			Expect(result).NotTo(BeNil())
			Expect(*result.Kind).To(Equal("ServiceAccount"))
			Expect(*result.Name).To(Equal("test-sa"))
			Expect(*result.Namespace).To(Equal("test-ns"))
		})

		It("should convert a Group subject", func() {
			subject := &rbacv1.Subject{
				Kind:     "Group",
				Name:     "test-group",
				APIGroup: rbacv1.GroupName,
			}
			result := ssa.SubjectFrom(subject)

			Expect(result).NotTo(BeNil())
			Expect(*result.Kind).To(Equal("Group"))
			Expect(*result.Name).To(Equal("test-group"))
		})
	})

	Context("RoleRefFrom", func() {
		It("should return nil for nil roleRef", func() {
			result := ssa.RoleRefFrom(nil)
			Expect(result).To(BeNil())
		})

		It("should convert a ClusterRole roleRef", func() {
			roleRef := &rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "admin",
			}
			result := ssa.RoleRefFrom(roleRef)

			Expect(result).NotTo(BeNil())
			Expect(*result.APIGroup).To(Equal(rbacv1.GroupName))
			Expect(*result.Kind).To(Equal("ClusterRole"))
			Expect(*result.Name).To(Equal("admin"))
		})

		It("should convert a Role roleRef", func() {
			roleRef := &rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     "developer",
			}
			result := ssa.RoleRefFrom(roleRef)

			Expect(result).NotTo(BeNil())
			Expect(*result.Kind).To(Equal("Role"))
			Expect(*result.Name).To(Equal("developer"))
		})
	})

	Context("ClusterRoleBindingWithSubjectsAndRoleRef", func() {
		It("should create a ClusterRoleBinding with subjects and roleRef", func() {
			labels := map[string]string{"app": "test"}
			subjects := []rbacv1.Subject{
				{Kind: "User", Name: "user1", APIGroup: rbacv1.GroupName},
				{Kind: "Group", Name: "group1", APIGroup: rbacv1.GroupName},
			}
			roleRef := rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "admin",
			}

			result := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("test-crb", labels, subjects, roleRef)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-crb"))
			Expect(result.Labels).To(Equal(labels))
			Expect(result.Subjects).To(HaveLen(2))
			Expect(result.RoleRef).NotTo(BeNil())
			Expect(*result.RoleRef.Name).To(Equal("admin"))
		})
	})

	Context("RoleBindingWithSubjectsAndRoleRef", func() {
		It("should create a RoleBinding with subjects and roleRef", func() {
			labels := map[string]string{"app": "test"}
			subjects := []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "sa1", Namespace: "ns1"},
			}
			roleRef := rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     "developer",
			}

			result := ssa.RoleBindingWithSubjectsAndRoleRef("test-rb", "test-ns", labels, subjects, roleRef)

			Expect(result).NotTo(BeNil())
			Expect(*result.Name).To(Equal("test-rb"))
			Expect(*result.Namespace).To(Equal("test-ns"))
			Expect(result.Labels).To(Equal(labels))
			Expect(result.Subjects).To(HaveLen(1))
			Expect(result.RoleRef).NotTo(BeNil())
			Expect(*result.RoleRef.Name).To(Equal("developer"))
		})
	})
})

// Integration tests using envtest to verify actual SSA apply behavior
// Uses suite-level envtest setup from BeforeSuite/AfterSuite for efficiency
var _ = Describe("SSA Apply Functions (envtest)", Label("integration"), func() {
	// Use suite-level testCtx and k8sClient from BeforeSuite

	Context("ApplyClusterRole", func() {
		It("should create a new ClusterRole via SSA", func() {
			labels := map[string]string{
				"app.kubernetes.io/managed-by": "auth-operator",
				"test":                         "value",
			}
			rules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ssa-test-clusterrole", labels, rules)

			err := ssa.ApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Verify the ClusterRole was created correctly
			var cr rbacv1.ClusterRole
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-test-clusterrole"}, &cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(cr.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "auth-operator"))
			Expect(cr.Labels).To(HaveKeyWithValue("test", "value"))
			Expect(cr.Rules).To(HaveLen(1))
			Expect(cr.Rules[0].Resources).To(ContainElement("pods"))
			Expect(cr.Rules[0].Verbs).To(ContainElements("get", "list", "watch"))
		})

		It("should update an existing ClusterRole via SSA", func() {
			// First, create the ClusterRole
			rules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get"},
				},
			}
			ac := ssa.ClusterRoleWithLabelsAndRules("ssa-update-clusterrole", nil, rules)
			err := ssa.ApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Update with new rules
			newRules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods", "configmaps"},
					Verbs:     []string{"get", "list", "create"},
				},
			}
			newLabels := map[string]string{"updated": "true"}
			ac = ssa.ClusterRoleWithLabelsAndRules("ssa-update-clusterrole", newLabels, newRules)
			err = ssa.ApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Verify the update
			var cr rbacv1.ClusterRole
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-update-clusterrole"}, &cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(cr.Labels).To(HaveKeyWithValue("updated", "true"))
			Expect(cr.Rules).To(HaveLen(1))
			Expect(cr.Rules[0].Resources).To(ContainElements("pods", "configmaps"))
			Expect(cr.Rules[0].Verbs).To(ContainElements("get", "list", "create"))
		})

		It("should include owner references when specified", func() {
			uid := types.UID("fake-uid-12345")
			ownerRef := ssa.OwnerReference("authorization.t-caas.telekom.com/v1alpha1", "RoleDefinition", "test-rd", uid, true, true)
			ac := ssa.ClusterRoleWithLabelsAndRules("ssa-ownerref-clusterrole", nil, nil).
				WithOwnerReferences(ownerRef)

			err := ssa.ApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var cr rbacv1.ClusterRole
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-ownerref-clusterrole"}, &cr)
			Expect(err).NotTo(HaveOccurred())
			Expect(cr.OwnerReferences).To(HaveLen(1))
			Expect(cr.OwnerReferences[0].Name).To(Equal("test-rd"))
			Expect(*cr.OwnerReferences[0].Controller).To(BeTrue())
		})
	})

	Context("ApplyRole", func() {
		It("should create a new Role via SSA", func() {
			labels := map[string]string{"app.kubernetes.io/managed-by": "auth-operator"}
			rules := []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"secrets"},
					Verbs:     []string{"get", "list"},
				},
			}
			ac := ssa.RoleWithLabelsAndRules("ssa-test-role", "default", labels, rules)

			err := ssa.ApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var r rbacv1.Role
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-test-role", Namespace: "default"}, &r)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Labels).To(HaveKeyWithValue("app.kubernetes.io/managed-by", "auth-operator"))
			Expect(r.Rules).To(HaveLen(1))
			Expect(r.Rules[0].Resources).To(ContainElement("secrets"))
		})

		It("should update an existing Role via SSA", func() {
			rules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
			}
			ac := ssa.RoleWithLabelsAndRules("ssa-update-role", "default", nil, rules)
			err := ssa.ApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Update with new rules
			newRules := []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "services"}, Verbs: []string{"get", "create"}},
			}
			ac = ssa.RoleWithLabelsAndRules("ssa-update-role", "default", map[string]string{"updated": "yes"}, newRules)
			err = ssa.ApplyRole(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var r rbacv1.Role
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-update-role", Namespace: "default"}, &r)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Labels).To(HaveKeyWithValue("updated", "yes"))
			Expect(r.Rules[0].Resources).To(ContainElements("pods", "services"))
		})
	})

	Context("ApplyClusterRoleBinding", func() {
		BeforeEach(func() {
			// Create a ClusterRole for binding
			cr := &rbacv1.ClusterRole{
				ObjectMeta: metav1.ObjectMeta{Name: "binding-target-cr"},
			}
			err := k8sClient.Create(testCtx, cr)
			Expect(client.IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		})

		It("should create a ClusterRoleBinding via SSA", func() {
			subjects := []rbacv1.Subject{
				{Kind: "User", Name: "test-user", APIGroup: rbacv1.GroupName},
			}
			roleRef := rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "binding-target-cr",
			}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ssa-test-crb", map[string]string{"test": "true"}, subjects, roleRef)

			err := ssa.ApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var crb rbacv1.ClusterRoleBinding
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-test-crb"}, &crb)
			Expect(err).NotTo(HaveOccurred())
			Expect(crb.Labels).To(HaveKeyWithValue("test", "true"))
			Expect(crb.Subjects).To(HaveLen(1))
			Expect(crb.Subjects[0].Name).To(Equal("test-user"))
			Expect(crb.RoleRef.Name).To(Equal("binding-target-cr"))
		})

		It("should update subjects via SSA", func() {
			subjects := []rbacv1.Subject{
				{Kind: "User", Name: "user1", APIGroup: rbacv1.GroupName},
			}
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "binding-target-cr"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ssa-update-crb", nil, subjects, roleRef)
			err := ssa.ApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			// Update subjects
			newSubjects := []rbacv1.Subject{
				{Kind: "User", Name: "user1", APIGroup: rbacv1.GroupName},
				{Kind: "Group", Name: "admin-group", APIGroup: rbacv1.GroupName},
			}
			ac = ssa.ClusterRoleBindingWithSubjectsAndRoleRef("ssa-update-crb", nil, newSubjects, roleRef)
			err = ssa.ApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var crb rbacv1.ClusterRoleBinding
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-update-crb"}, &crb)
			Expect(err).NotTo(HaveOccurred())
			Expect(crb.Subjects).To(HaveLen(2))
		})
	})

	Context("ApplyRoleBinding", func() {
		BeforeEach(func() {
			// Create a Role for binding
			r := &rbacv1.Role{
				ObjectMeta: metav1.ObjectMeta{Name: "binding-target-role", Namespace: "default"},
			}
			err := k8sClient.Create(testCtx, r)
			Expect(client.IgnoreAlreadyExists(err)).NotTo(HaveOccurred())
		})

		It("should create a RoleBinding via SSA", func() {
			subjects := []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"},
			}
			roleRef := rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "Role",
				Name:     "binding-target-role",
			}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("ssa-test-rb", "default", map[string]string{"app": "test"}, subjects, roleRef)

			err := ssa.ApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).NotTo(HaveOccurred())

			var rb rbacv1.RoleBinding
			err = k8sClient.Get(testCtx, types.NamespacedName{Name: "ssa-test-rb", Namespace: "default"}, &rb)
			Expect(err).NotTo(HaveOccurred())
			Expect(rb.Labels).To(HaveKeyWithValue("app", "test"))
			Expect(rb.Subjects).To(HaveLen(1))
			Expect(rb.Subjects[0].Name).To(Equal("test-sa"))
			Expect(rb.RoleRef.Name).To(Equal("binding-target-role"))
		})
	})

	Context("Edge cases", func() {
		It("should fail when ApplyClusterRole is called with nil", func() {
			err := ssa.ApplyClusterRole(testCtx, k8sClient, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have a name"))
		})

		It("should fail when ApplyClusterRole is called with empty name", func() {
			ac := ssa.ClusterRoleWithLabelsAndRules("", nil, nil)
			err := ssa.ApplyClusterRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name must not be empty"))
		})

		It("should fail when ApplyRole is called without namespace", func() {
			// Create a RoleApplyConfiguration without namespace
			roleAC := ssa.RoleWithLabelsAndRules("test", "", nil, nil)
			// Set namespace to nil after creation
			roleAC.Namespace = nil
			err := ssa.ApplyRole(testCtx, k8sClient, roleAC)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have a namespace"))
		})

		It("should fail when ApplyRole is called with empty name", func() {
			ac := ssa.RoleWithLabelsAndRules("", "default", nil, nil)
			err := ssa.ApplyRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name must not be empty"))
		})

		It("should fail when ApplyRole is called with empty namespace", func() {
			ac := ssa.RoleWithLabelsAndRules("test", "", nil, nil)
			err := ssa.ApplyRole(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("namespace must not be empty"))
		})

		It("should fail when ApplyClusterRoleBinding is called with nil", func() {
			err := ssa.ApplyClusterRoleBinding(testCtx, k8sClient, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have a name"))
		})

		It("should fail when ApplyClusterRoleBinding is called with empty name", func() {
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"}
			ac := ssa.ClusterRoleBindingWithSubjectsAndRoleRef("", nil, nil, roleRef)
			err := ssa.ApplyClusterRoleBinding(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name must not be empty"))
		})

		It("should fail when ApplyRoleBinding is called with nil", func() {
			err := ssa.ApplyRoleBinding(testCtx, k8sClient, nil)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must have a name"))
		})

		It("should fail when ApplyRoleBinding is called with empty name", func() {
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "developer"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("", "default", nil, nil, roleRef)
			err := ssa.ApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("name must not be empty"))
		})

		It("should fail when ApplyRoleBinding is called with empty namespace", func() {
			roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "developer"}
			ac := ssa.RoleBindingWithSubjectsAndRoleRef("test-rb", "", nil, nil, roleRef)
			err := ssa.ApplyRoleBinding(testCtx, k8sClient, ac)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("namespace must not be empty"))
		})
	})
})

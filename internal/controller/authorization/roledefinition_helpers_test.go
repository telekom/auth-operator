package authorization

import (
	"context"
	"errors"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	rbacv1ac "k8s.io/client-go/applyconfigurations/rbac/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	authorizationv1alpha1ac "github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
)

// TestBuildRoleObject tests the buildRoleObject function
func TestBuildRoleObject(t *testing.T) {
	s := scheme.Scheme
	_ = authorizationv1alpha1.AddToScheme(s)

	recorder := events.NewFakeRecorder(10)
	r := &RoleDefinitionReconciler{
		scheme:   s,
		recorder: recorder,
	}

	tests := []struct {
		name       string
		targetRole string
		wantType   string
		wantErr    error
	}{
		{
			name:       "ClusterRole returns ClusterRole",
			targetRole: authorizationv1alpha1.DefinitionClusterRole,
			wantType:   "*v1.ClusterRole",
			wantErr:    nil,
		},
		{
			name:       "Role returns Role",
			targetRole: authorizationv1alpha1.DefinitionNamespacedRole,
			wantType:   "*v1.Role",
			wantErr:    nil,
		},
		{
			name:       "invalid target returns error",
			targetRole: "InvalidRole",
			wantType:   "",
			wantErr:    ErrInvalidTargetRole,
		},
		{
			name:       "empty string returns error",
			targetRole: "",
			wantType:   "",
			wantErr:    ErrInvalidTargetRole,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := &authorizationv1alpha1.RoleDefinition{
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: tt.targetRole,
				},
			}

			got, err := r.buildRoleObject(rd)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("buildRoleObject() expected error %v, got nil", tt.wantErr)
					return
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("buildRoleObject() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("buildRoleObject() unexpected error = %v", err)
				return
			}

			gotType := ""
			switch got.(type) {
			case *rbacv1.ClusterRole:
				gotType = "*v1.ClusterRole"
			case *rbacv1.Role:
				gotType = "*v1.Role"
			}

			if gotType != tt.wantType {
				t.Errorf("buildRoleObject() returned type %s, want %s", gotType, tt.wantType)
			}
		})
	}
}

func TestCheckRoleOwnership_UnownedExistingRoleRejected(t *testing.T) {
	g := NewWithT(t)

	s := runtime.NewScheme()
	g.Expect(authorizationv1alpha1.AddToScheme(s)).To(Succeed())
	g.Expect(rbacv1.AddToScheme(s)).To(Succeed())

	roleDefinition := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owner-rd",
			UID:  "owner-rd-uid",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "preexisting-role",
		},
	}
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "preexisting-role"},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(roleDefinition, existing).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.checkRoleOwnership(context.Background(), roleDefinition)

	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("already exists and is not owned by RoleDefinition"))
}

func TestCheckRoleOwnership_OwnedExistingRoleAllowed(t *testing.T) {
	g := NewWithT(t)

	s := runtime.NewScheme()
	g.Expect(authorizationv1alpha1.AddToScheme(s)).To(Succeed())
	g.Expect(rbacv1.AddToScheme(s)).To(Succeed())

	roleDefinition := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owner-rd",
			UID:  "owner-rd-uid",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "owned-role",
		},
	}
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "owned-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       roleDefinition.Name,
				UID:        roleDefinition.UID,
			}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(roleDefinition, existing).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	g.Expect(r.checkRoleOwnership(context.Background(), roleDefinition)).To(Succeed())
}

var _ = Describe("RoleDefinition Helpers", func() {
	ctx := context.Background()
	var r *RoleDefinitionReconciler

	BeforeEach(func() {
		resourceTracker := discovery.NewResourceTracker(scheme.Scheme, cfg)

		r = &RoleDefinitionReconciler{
			client:          k8sClient,
			scheme:          scheme.Scheme,
			recorder:        events.NewFakeRecorder(10),
			resourceTracker: resourceTracker,
		}
	})

	Describe("ensureFinalizer", func() {
		It("should add finalizer to RoleDefinition without one", func() {
			eventRecorder := events.NewFakeRecorder(10)
			r.recorder = eventRecorder

			rd := &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ensure-finalizer",
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName: "test-role",
					TargetRole: authorizationv1alpha1.DefinitionClusterRole,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			defer func() {
				_ = k8sClient.Delete(ctx, rd)
			}()

			err := r.ensureFinalizer(ctx, rd)
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer was added.
			updated := &authorizationv1alpha1.RoleDefinition{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rd), updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))

			// Verify event was emitted with correct format.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring("Normal"))
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonFinalizer))
			Expect(event).To(ContainSubstring("Adding finalizer to RoleDefinition"))
		})

		It("should do nothing if finalizer already exists", func() {
			rd := &authorizationv1alpha1.RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test-existing-finalizer",
					Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
				},
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetName: "test-role",
					TargetRole: authorizationv1alpha1.DefinitionClusterRole,
				},
			}
			Expect(k8sClient.Create(ctx, rd)).To(Succeed())

			defer func() {
				rd.Finalizers = nil
				_ = k8sClient.Update(ctx, rd)
				_ = k8sClient.Delete(ctx, rd)
			}()

			err := r.ensureFinalizer(ctx, rd)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("buildRoleObject", func() {
		It("should return ClusterRole for ClusterRole target", func() {
			rd := &authorizationv1alpha1.RoleDefinition{
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: authorizationv1alpha1.DefinitionClusterRole,
				},
			}

			role, err := r.buildRoleObject(rd)
			Expect(err).NotTo(HaveOccurred())
			Expect(role).To(BeAssignableToTypeOf(&rbacv1.ClusterRole{}))
		})

		It("should return Role for Role target", func() {
			rd := &authorizationv1alpha1.RoleDefinition{
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: authorizationv1alpha1.DefinitionNamespacedRole,
				},
			}

			role, err := r.buildRoleObject(rd)
			Expect(err).NotTo(HaveOccurred())
			Expect(role).To(BeAssignableToTypeOf(&rbacv1.Role{}))
		})

		It("should return error for invalid target", func() {
			rd := &authorizationv1alpha1.RoleDefinition{
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole: "InvalidTarget",
				},
			}

			_, err := r.buildRoleObject(rd)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrInvalidTargetRole)).To(BeTrue())
		})
	})
})

// TestBuildFinalRules tests the buildFinalRules function
func TestBuildFinalRules(t *testing.T) {
	s := scheme.Scheme
	_ = authorizationv1alpha1.AddToScheme(s)

	recorder := events.NewFakeRecorder(10)
	r := &RoleDefinitionReconciler{
		scheme:   s,
		recorder: recorder,
	}

	t.Run("should include /metrics non-resource URL for ClusterRole", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				RestrictedVerbs: []string{"delete"},
			},
		}

		rulesByAPIGroupAndVerbs := map[string]*rbacv1.PolicyRule{
			"v1|[get list]": {
				APIGroups: []string{""},
				Resources: []string{"pods", "services"},
				Verbs:     []string{"get", "list"},
			},
		}

		rules := r.buildFinalRules(rd, rulesByAPIGroupAndVerbs)

		// Should have 2 rules: the resource rule + non-resource URL rule
		if len(rules) != 2 {
			t.Fatalf("expected 2 rules, got %d", len(rules))
		}

		// Last rule should be non-resource URL
		lastRule := rules[len(rules)-1]
		if len(lastRule.NonResourceURLs) == 0 {
			t.Error("expected non-resource URL rule at end")
		}
		if lastRule.NonResourceURLs[0] != "/metrics" {
			t.Errorf("expected /metrics, got %s", lastRule.NonResourceURLs[0])
		}
	})

	t.Run("should NOT include /metrics when get is restricted", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				RestrictedVerbs: []string{"get"},
			},
		}

		rulesByAPIGroupAndVerbs := map[string]*rbacv1.PolicyRule{
			"v1|[list]": {
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
		}

		rules := r.buildFinalRules(rd, rulesByAPIGroupAndVerbs)

		for _, rule := range rules {
			if len(rule.NonResourceURLs) > 0 {
				t.Error("expected no non-resource URL rule when get is restricted")
			}
		}
	})

	t.Run("should NOT include /metrics when wildcard is restricted", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				RestrictedVerbs: []string{"*"},
			},
		}

		rules := r.buildFinalRules(rd, map[string]*rbacv1.PolicyRule{})

		if len(rules) != 0 {
			t.Fatalf("expected no rules when wildcard restricts get, got %d", len(rules))
		}
	})

	t.Run("should NOT include /metrics for namespaced Role", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				RestrictedVerbs: []string{"delete"},
			},
		}

		rulesByAPIGroupAndVerbs := map[string]*rbacv1.PolicyRule{
			"v1|[get list]": {
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		}

		rules := r.buildFinalRules(rd, rulesByAPIGroupAndVerbs)

		for _, rule := range rules {
			if len(rule.NonResourceURLs) > 0 {
				t.Error("expected no non-resource URL rule for namespaced Role")
			}
		}
	})

	t.Run("should sort resources within rules deterministically", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole: authorizationv1alpha1.DefinitionNamespacedRole,
			},
		}

		rulesByAPIGroupAndVerbs := map[string]*rbacv1.PolicyRule{
			"v1|[get list]": {
				APIGroups: []string{""},
				Resources: []string{"services", "pods", "configmaps"},
				Verbs:     []string{"list", "get"},
			},
		}

		rules := r.buildFinalRules(rd, rulesByAPIGroupAndVerbs)

		if len(rules) != 1 {
			t.Fatalf("expected 1 rule, got %d", len(rules))
		}

		// Resources should be sorted
		expectedResources := []string{"configmaps", "pods", "services"}
		for i, want := range expectedResources {
			if rules[0].Resources[i] != want {
				t.Errorf("resources not sorted: got %v, want %v", rules[0].Resources, expectedResources)
				break
			}
		}
		// Verbs should be sorted
		if rules[0].Verbs[0] != "get" || rules[0].Verbs[1] != "list" {
			t.Errorf("verbs not sorted: %v", rules[0].Verbs)
		}
	})

	t.Run("should handle empty rules map", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				RestrictedVerbs: []string{"delete"},
			},
		}

		rules := r.buildFinalRules(rd, map[string]*rbacv1.PolicyRule{})

		// Should only have the /metrics rule
		if len(rules) != 1 {
			t.Fatalf("expected 1 rule (/metrics), got %d", len(rules))
		}
		if len(rules[0].NonResourceURLs) == 0 || rules[0].NonResourceURLs[0] != "/metrics" {
			t.Error("expected /metrics non-resource URL rule")
		}
	})
}

// rulesContainResource checks whether any rule in the slice references the given resource name.
func rulesContainResource(rules map[string]*rbacv1.PolicyRule, resource string) bool {
	for _, rule := range rules {
		for _, res := range rule.Resources {
			if res == resource {
				return true
			}
		}
	}
	return false
}

// rulesContainVerb checks whether any rule in the slice references the given verb.
func rulesContainVerb(rules map[string]*rbacv1.PolicyRule, verb string) bool {
	for _, rule := range rules {
		for _, v := range rule.Verbs {
			if v == verb {
				return true
			}
		}
	}
	return false
}

// TestFilterAPIResourcesForRoleDefinition tests the filterAPIResourcesForRoleDefinition function
func TestFilterAPIResourcesForRoleDefinition(t *testing.T) {
	s := scheme.Scheme
	_ = authorizationv1alpha1.AddToScheme(s)

	recorder := events.NewFakeRecorder(10)
	r := &RoleDefinitionReconciler{
		scheme:   s,
		recorder: recorder,
	}
	ctx := context.Background()

	t.Run("should filter restricted API groups", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
				RestrictedAPIs: []authorizationv1alpha1.RestrictedAPIGroup{
					{Name: "apps"},
				},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1":      {{Name: "pods", Verbs: metav1.Verbs{"get", "list"}, Namespaced: false}},
			"apps/v1": {{Name: "deployments", Verbs: metav1.Verbs{"get", "list"}, Namespaced: false}},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rulesContainResource(rules, "deployments") {
			t.Error("restricted API group 'apps' resources should be filtered out")
		}
		if len(rules) == 0 {
			t.Error("expected at least one rule for non-restricted resources")
		}
	})

	t.Run("should filter restricted resources", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
				RestrictedResources: []metav1.APIResource{
					{Name: "secrets", Group: ""},
				},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {
				{Name: "pods", Verbs: metav1.Verbs{"get", "list"}, Namespaced: false},
				{Name: "secrets", Verbs: metav1.Verbs{"get", "list"}, Namespaced: false},
			},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rulesContainResource(rules, "secrets") {
			t.Error("restricted resource 'secrets' should be filtered out")
		}
	})

	t.Run("should filter namespaced resources when ScopeNamespaced is false", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {
				{Name: "nodes", Verbs: metav1.Verbs{"get"}, Namespaced: false},
				{Name: "pods", Verbs: metav1.Verbs{"get"}, Namespaced: true},
			},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rulesContainResource(rules, "pods") {
			t.Error("namespaced resource 'pods' should be filtered when ScopeNamespaced=false")
		}
	})

	t.Run("should include namespaced resources when ScopeNamespaced is true", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				ScopeNamespaced: true,
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {
				{Name: "pods", Verbs: metav1.Verbs{"get", "list"}, Namespaced: true},
				{Name: "nodes", Verbs: metav1.Verbs{"get"}, Namespaced: false},
			},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !rulesContainResource(rules, "pods") {
			t.Error("namespaced resource 'pods' should be included when ScopeNamespaced=true")
		}
		if rulesContainResource(rules, "nodes") {
			t.Error("cluster-scoped resource 'nodes' should be filtered when ScopeNamespaced=true")
		}
	})

	t.Run("should filter restricted verbs", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
				RestrictedVerbs: []string{"delete", "patch"},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {{Name: "pods", Verbs: metav1.Verbs{"get", "list", "delete", "patch"}, Namespaced: false}},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rulesContainVerb(rules, "delete") || rulesContainVerb(rules, "patch") {
			t.Error("restricted verbs should be filtered out")
		}
	})

	t.Run("should filter all verbs when restricted verbs contains wildcard", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
				RestrictedVerbs: []string{"*"},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {{Name: "pods", Verbs: metav1.Verbs{"get", "list", "create", "delete", "*"}, Namespaced: false}},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 0 {
			t.Errorf("expected no rules when wildcard restricts every verb, got %d", len(rules))
		}
	})

	t.Run("should skip resource when all verbs are restricted", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
				ScopeNamespaced: false,
				RestrictedVerbs: []string{"get", "list"},
			},
		}

		apiResources := discovery.APIResourcesByGroupVersion{
			"v1": {{Name: "secrets", Verbs: metav1.Verbs{"get", "list"}, Namespaced: false}},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, apiResources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 0 {
			t.Errorf("expected no rules when all verbs restricted, got %d", len(rules))
		}
	})

	t.Run("should handle empty API resources", func(t *testing.T) {
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}

		rules, err := r.filterAPIResourcesForRoleDefinition(ctx, rd, discovery.APIResourcesByGroupVersion{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 0 {
			t.Errorf("expected no rules for empty API resources, got %d", len(rules))
		}
	})
}

func TestRoleDefinitionMarkStalled(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	t.Run("sets Stalled condition and ObservedGeneration", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "stalled-rd",
				UID:        "stalled-uid",
				Generation: 5,
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "stalled-role",
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
			Status: authorizationv1alpha1.RoleDefinitionStatus{
				RoleReconciled: true,
			},
		}

		var appliedRoleReconciled *bool
		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd).
			WithStatusSubresource(rd).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceApply: func(_ context.Context, _ client.Client, subResourceName string, obj runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
					if subResourceName == "status" {
						if ac, ok := obj.(*authorizationv1alpha1ac.RoleDefinitionApplyConfiguration); ok && ac.Status != nil {
							appliedRoleReconciled = ac.Status.RoleReconciled
						}
					}
					return nil
				},
			}).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		r.markStalled(ctx, rd, fmt.Errorf("discovery error"))

		// Verify condition was set in-memory
		g.Expect(rd.Status.ObservedGeneration).To(Equal(int64(5)))
		g.Expect(rd.Status.RoleReconciled).To(BeFalse())
		stalledFound := false
		for _, cond := range rd.Status.Conditions {
			if cond.Type == "Stalled" {
				stalledFound = true
				g.Expect(cond.Status).To(Equal(metav1.ConditionTrue))
				g.Expect(cond.Message).To(ContainSubstring("check operator logs for details"))
			}
		}
		g.Expect(stalledFound).To(BeTrue(), "Stalled condition should be set")
		g.Expect(appliedRoleReconciled).NotTo(BeNil())
		g.Expect(*appliedRoleReconciled).To(BeFalse())
	})
}

func TestHandleDeletion(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	t.Run("deletes ClusterRole and removes finalizer", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "del-rd",
				UID:        "del-uid",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "del-cluster-role",
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}

		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "del-cluster-role",
				OwnerReferences: []metav1.OwnerReference{roleDefinitionTestOwnerRef(rd)},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd, cr).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		role, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, role)
		g.Expect(err).NotTo(HaveOccurred())
		// First call triggers delete and requeues
		g.Expect(result.RequeueAfter).NotTo(BeZero())
	})

	t.Run("wraps deletion and status update errors", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "failed-delete-rd",
				UID:        "failed-delete-uid",
				Generation: 3,
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "failed-delete-role",
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}
		deleteErr := errors.New("delete failed")
		statusErr := errors.New("status apply failed")

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd).
			WithStatusSubresource(rd).
			WithInterceptorFuncs(interceptor.Funcs{
				SubResourceApply: func(_ context.Context, _ client.Client, subResourceName string, _ runtime.ApplyConfiguration, _ ...client.SubResourceApplyOption) error {
					if subResourceName == "status" {
						return statusErr
					}
					return nil
				},
			}).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		_, err := r.markDeletionFailed(ctx, rd, deleteErr)

		g.Expect(err).To(HaveOccurred())
		g.Expect(errors.Is(err, deleteErr)).To(BeTrue())
		g.Expect(errors.Is(err, statusErr)).To(BeTrue())
	})

	t.Run("removes finalizer when role already deleted", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "del-rd-gone",
				UID:        "del-uid-gone",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "gone-cluster-role",
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}

		// No ClusterRole exists
		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		role, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, role)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.RequeueAfter).To(BeZero())
	})

	t.Run("removes finalizer when Role already deleted", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "del-role-gone",
				UID:        "del-role-gone-uid",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName:      "gone-role",
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				TargetNamespace: "test-ns",
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		role, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, role)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.RequeueAfter).To(BeZero())
	})

	t.Run("deletes existing Role and requeues", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "del-role-exists",
				UID:        "del-role-exists-uid",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName:      "existing-role",
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				TargetNamespace: "test-ns",
			},
		}

		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:            "existing-role",
				Namespace:       "test-ns",
				OwnerReferences: []metav1.OwnerReference{roleDefinitionTestOwnerRef(rd)},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd, role).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		builtRole, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, builtRole)
		g.Expect(err).NotTo(HaveOccurred())
		// Delete triggers requeue to check if deletion succeeded
		g.Expect(result.RequeueAfter).NotTo(BeZero())
	})

	t.Run("skips unowned ClusterRole deletion and removes finalizer", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "skip-unowned-rd",
				UID:        "skip-unowned-rd-uid",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName: "shared-cluster-role",
				TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			},
		}

		cr := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "shared-cluster-role"},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd, cr).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		role, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, role)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.RequeueAfter).To(BeZero())

		var stillThere rbacv1.ClusterRole
		g.Expect(c.Get(ctx, client.ObjectKey{Name: "shared-cluster-role"}, &stillThere)).To(Succeed())

		var updated authorizationv1alpha1.RoleDefinition
		g.Expect(c.Get(ctx, client.ObjectKey{Name: rd.Name}, &updated)).To(Succeed())
		g.Expect(updated.Finalizers).NotTo(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))
	})

	t.Run("skips differently owned Role deletion and removes finalizer", func(t *testing.T) {
		g := NewWithT(t)

		rd := &authorizationv1alpha1.RoleDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:       "skip-owned-rd",
				UID:        "skip-owned-rd-uid",
				Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetName:      "shared-role",
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				TargetNamespace: "test-ns",
			},
		}

		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shared-role",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
					Name:       "other-rd",
					UID:        "other-rd-uid",
				}},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(rd, role).
			WithStatusSubresource(rd).
			Build()
		r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		builtRole, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())

		result, err := r.handleDeletion(ctx, rd, builtRole)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result.RequeueAfter).To(BeZero())

		var stillThere rbacv1.Role
		g.Expect(c.Get(ctx, client.ObjectKey{Namespace: "test-ns", Name: "shared-role"}, &stillThere)).To(Succeed())

		var updated authorizationv1alpha1.RoleDefinition
		g.Expect(c.Get(ctx, client.ObjectKey{Name: rd.Name}, &updated)).To(Succeed())
		g.Expect(updated.Finalizers).NotTo(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))
	})
}

func TestBuildRoleObjectInvalidTarget(t *testing.T) {
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-target"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: "InvalidRole",
			TargetName: "test",
		},
	}

	r := &RoleDefinitionReconciler{scheme: s, recorder: events.NewFakeRecorder(10)}
	_, err := r.buildRoleObject(rd)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("InvalidRole"))
}

func TestBuildRoleObjectBreakglassLabel(t *testing.T) {
	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	r := &RoleDefinitionReconciler{scheme: s, recorder: events.NewFakeRecorder(10)}

	t.Run("ClusterRole with BreakglassAllowed=true has label", func(t *testing.T) {
		g := NewWithT(t)
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:        authorizationv1alpha1.DefinitionClusterRole,
				TargetName:        "test-cr",
				BreakglassAllowed: true,
			},
		}
		obj, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())
		cr := obj.(*rbacv1.ClusterRole)
		g.Expect(cr.Labels).To(HaveKeyWithValue(authorizationv1alpha1.BreakglassCompatibleLabel, "true"))
	})

	t.Run("ClusterRole with BreakglassAllowed=false has label set to false", func(t *testing.T) {
		g := NewWithT(t)
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:        authorizationv1alpha1.DefinitionClusterRole,
				TargetName:        "test-cr",
				BreakglassAllowed: false,
			},
		}
		obj, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())
		cr := obj.(*rbacv1.ClusterRole)
		g.Expect(cr.Labels).To(HaveKeyWithValue(authorizationv1alpha1.BreakglassCompatibleLabel, "false"))
	})

	t.Run("ClusterRole spec overrides metadata breakglass label", func(t *testing.T) {
		g := NewWithT(t)
		rd := &authorizationv1alpha1.RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					authorizationv1alpha1.BreakglassCompatibleLabel: "true",
				},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:        authorizationv1alpha1.DefinitionClusterRole,
				TargetName:        "test-cr",
				BreakglassAllowed: false,
			},
		}
		obj, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())
		cr := obj.(*rbacv1.ClusterRole)
		g.Expect(cr.Labels).To(HaveKeyWithValue(authorizationv1alpha1.BreakglassCompatibleLabel, "false"))
	})

	t.Run("Role ignores BreakglassAllowed", func(t *testing.T) {
		g := NewWithT(t)
		rd := &authorizationv1alpha1.RoleDefinition{
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:        authorizationv1alpha1.DefinitionNamespacedRole,
				TargetName:        "test-role",
				TargetNamespace:   "default",
				BreakglassAllowed: true,
			},
		}
		obj, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())
		role := obj.(*rbacv1.Role)
		g.Expect(role.Labels).NotTo(HaveKey(authorizationv1alpha1.BreakglassCompatibleLabel))
	})

	t.Run("Role strips metadata breakglass label", func(t *testing.T) {
		g := NewWithT(t)
		rd := &authorizationv1alpha1.RoleDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Labels: map[string]string{
					authorizationv1alpha1.BreakglassCompatibleLabel: "true",
					"custom": "keep",
				},
			},
			Spec: authorizationv1alpha1.RoleDefinitionSpec{
				TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
				TargetName:      "test-role",
				TargetNamespace: "default",
			},
		}
		obj, err := r.buildRoleObject(rd)
		g.Expect(err).NotTo(HaveOccurred())
		role := obj.(*rbacv1.Role)
		g.Expect(role.Labels).NotTo(HaveKey(authorizationv1alpha1.BreakglassCompatibleLabel))
		g.Expect(role.Labels).To(HaveKeyWithValue("custom", "keep"))
	})
}

func TestEnsureRoleDefaultCase(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "default-role"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: "InvalidTarget",
			TargetName: "test",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, nil)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("InvalidTarget"))
}

func TestEnsureFinalizerAlreadyPresent(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "has-finalizer",
			Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer},
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: "ClusterRole",
			TargetName: "test",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureFinalizer(ctx, rd)
	g.Expect(err).NotTo(HaveOccurred())
}

func TestEnsureFinalizerAdded(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "no-finalizer"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: "ClusterRole",
			TargetName: "test",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureFinalizer(ctx, rd)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify finalizer was added
	updated := &authorizationv1alpha1.RoleDefinition{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(rd), updated)).To(Succeed())
	g.Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))
}

func TestEnsureRoleBreakglassLabelApplied(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "bg-label-rd", UID: "bg-label-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:        authorizationv1alpha1.DefinitionClusterRole,
			TargetName:        "bg-label-cr",
			BreakglassAllowed: true,
		},
	}

	// Capture the apply configuration to verify labels.
	var appliedLabels map[string]string
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, obj runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				// Type-assert to the concrete ClusterRoleApplyConfiguration.
				if cr, ok := obj.(*rbacv1ac.ClusterRoleApplyConfiguration); ok && cr.ObjectMetaApplyConfiguration != nil {
					appliedLabels = cr.Labels
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(appliedLabels).To(HaveKeyWithValue(authorizationv1alpha1.BreakglassCompatibleLabel, "true"),
		"ensureRole must include the breakglass-compatible label in the SSA apply configuration")
}

func TestEnsureRoleClusterRoleBreakglassSpecOverridesMetadataLabel(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "bg-metadata-rd",
			UID:  "bg-metadata-uid",
			Labels: map[string]string{
				authorizationv1alpha1.BreakglassCompatibleLabel: "true",
			},
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:        authorizationv1alpha1.DefinitionClusterRole,
			TargetName:        "bg-metadata-cr",
			BreakglassAllowed: false,
		},
	}

	var appliedLabels map[string]string
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, obj runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				if cr, ok := obj.(*rbacv1ac.ClusterRoleApplyConfiguration); ok && cr.ObjectMetaApplyConfiguration != nil {
					appliedLabels = cr.Labels
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(appliedLabels).To(HaveKeyWithValue(authorizationv1alpha1.BreakglassCompatibleLabel, "false"))
}

func TestEnsureRoleNamespacedRoleStripsMetadataBreakglassLabel(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "strip-bg-label-rd",
			UID:  "strip-bg-label-uid",
			Labels: map[string]string{
				authorizationv1alpha1.BreakglassCompatibleLabel: "true",
				"custom": "keep",
			},
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "strip-bg-label-role",
			TargetNamespace: "default",
		},
	}

	var appliedLabels map[string]string
	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, obj runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				if role, ok := obj.(*rbacv1ac.RoleApplyConfiguration); ok && role.ObjectMetaApplyConfiguration != nil {
					appliedLabels = role.Labels
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(appliedLabels).NotTo(HaveKey(authorizationv1alpha1.BreakglassCompatibleLabel))
	g.Expect(appliedLabels).To(HaveKeyWithValue("custom", "keep"))
}

func TestEnsureRoleClusterRoleSSAError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "ssa-err-rd", UID: "ssa-err-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "ssa-err-cr",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected ClusterRole SSA error")
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected ClusterRole SSA error"))
}

func TestEnsureRoleNamespacedRoleSSAError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "ssa-ns-err-rd", UID: "ssa-ns-err-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "ssa-ns-err-role",
			TargetNamespace: "default",
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
				return fmt.Errorf("injected Role SSA error")
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}})
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected Role SSA error"))
}

func TestHandleDeletionDeleteError(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	now := metav1.Now()
	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "del-err-rd", UID: "del-err-uid", DeletionTimestamp: &now, Finalizers: []string{authorizationv1alpha1.RoleDefinitionFinalizer}},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "del-err-cr",
		},
	}

	cr := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{
		Name:            "del-err-cr",
		OwnerReferences: []metav1.OwnerReference{roleDefinitionTestOwnerRef(rd)},
	}}

	c := fake.NewClientBuilder().WithScheme(s).
		WithObjects(rd, cr).
		WithStatusSubresource(rd).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.DeleteOption) error {
				if _, ok := obj.(*rbacv1.ClusterRole); ok {
					return fmt.Errorf("injected delete error")
				}
				return nil
			},
		}).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	builtRole, err := r.buildRoleObject(rd)
	g.Expect(err).NotTo(HaveOccurred())

	_, err = r.handleDeletion(ctx, rd, builtRole)
	g.Expect(err).To(HaveOccurred())
	g.Expect(err.Error()).To(ContainSubstring("injected delete error"))
}

func TestEnsureRoleClusterRoleClearsStaleRulesWhenDesiredRulesEmpty(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-rd", UID: "clear-rd-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "clear-rd-cluster-role",
		},
	}
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clear-rd-cluster-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       rd.Name,
				UID:        rd.UID,
			}},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd, existing).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(ctx, client.ObjectKey{Name: "clear-rd-cluster-role"}, &cr)).To(Succeed())
	g.Expect(cr.Rules).To(BeEmpty())
}

func TestEnsureRoleNamespacedRoleClearsStaleRulesWhenDesiredRulesEmpty(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "clear-ns-rd", UID: "clear-ns-rd-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionNamespacedRole,
			TargetName:      "clear-rd-role",
			TargetNamespace: "clear-rd-ns",
		},
	}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "clear-rd-ns"}}
	existing := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "clear-rd-role",
			Namespace: "clear-rd-ns",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       rd.Name,
				UID:        rd.UID,
			}},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd, ns, existing).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	var role rbacv1.Role
	g.Expect(c.Get(ctx, client.ObjectKey{Namespace: "clear-rd-ns", Name: "clear-rd-role"}, &role)).To(Succeed())
	g.Expect(role.Rules).To(BeEmpty())
}

func TestRoleDefinitionCleanupSkipsUnownedTargets(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-rd", UID: "cleanup-rd-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "cleanup-cluster-role",
			TargetNamespace: "cleanup-ns",
		},
	}

	aggregating := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-cluster-role"},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"team": "alpha"}}},
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}
	namespaced := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "cleanup-cluster-role", Namespace: "cleanup-ns"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd, aggregating, namespaced).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	g.Expect(r.clearAggregationRuleIfSet(ctx, rd)).To(Succeed())
	g.Expect(r.clearRulesOnAggregationTransition(ctx, rd)).To(Succeed())
	g.Expect(r.clearClusterRoleRulesIfEmpty(ctx, rd, nil)).To(Succeed())

	var cr rbacv1.ClusterRole
	g.Expect(c.Get(ctx, client.ObjectKey{Name: "cleanup-cluster-role"}, &cr)).To(Succeed())
	g.Expect(cr.AggregationRule).NotTo(BeNil())
	g.Expect(cr.Rules).NotTo(BeEmpty())

	rd.Spec.TargetRole = authorizationv1alpha1.DefinitionNamespacedRole
	g.Expect(r.clearRoleRulesIfEmpty(ctx, rd, nil)).To(Succeed())

	var role rbacv1.Role
	g.Expect(c.Get(ctx, client.ObjectKey{Namespace: "cleanup-ns", Name: "cleanup-cluster-role"}, &role)).To(Succeed())
	g.Expect(role.Rules).NotTo(BeEmpty())
}

func TestCleanupInvalidAggregateFromTargetDeletesOnlyOwnedClusterRole(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "invalid-aggregate-rd", UID: "invalid-aggregate-rd-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
			TargetName: "invalid-aggregate-role",
		},
	}
	owned := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "invalid-aggregate-role",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       rd.Name,
				UID:        rd.UID,
			}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd, owned).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	g.Expect(r.cleanupInvalidAggregateFromTarget(ctx, rd)).To(Succeed())

	var deleted rbacv1.ClusterRole
	err := c.Get(ctx, client.ObjectKey{Name: "invalid-aggregate-role"}, &deleted)
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue())

	unowned := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "invalid-aggregate-role"}}
	c = fake.NewClientBuilder().WithScheme(s).WithObjects(rd, unowned).Build()
	r = &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	g.Expect(r.cleanupInvalidAggregateFromTarget(ctx, rd)).To(Succeed())
	g.Expect(c.Get(ctx, client.ObjectKey{Name: "invalid-aggregate-role"}, &deleted)).To(Succeed())
}

func TestEnsureRoleWithAggregationLabels(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "agg-labels-rd", UID: "agg-labels-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "custom-viewer",
			ScopeNamespaced: false,
			AggregationLabels: map[string]string{
				"custom.example.com/aggregate-to-monitoring": "true",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
	}
	err := r.ensureRole(ctx, rd, rules)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify the ClusterRole was created with aggregation labels merged in
	cr := &rbacv1.ClusterRole{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "custom-viewer"}}), cr)).To(Succeed())
	g.Expect(cr.Labels).To(HaveKeyWithValue("custom.example.com/aggregate-to-monitoring", "true"))
	g.Expect(cr.Rules).To(HaveLen(1))
	g.Expect(cr.AggregationRule).To(BeNil())
}

func TestEnsureRoleFiltersKubernetesRBACAggregationLabels(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "unsafe-agg-labels-rd",
			UID:  "unsafe-agg-labels-uid",
			Labels: map[string]string{
				"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				"custom.example.com/source-label":              "kept",
			},
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "unsafe-custom-viewer",
			ScopeNamespaced: false,
			AggregationLabels: map[string]string{
				"rbac.authorization.k8s.io/aggregate-to-view": "true",
				"custom.example.com/aggregate-to-monitoring":  "true",
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
	}
	g.Expect(r.ensureRole(ctx, rd, rules)).To(Succeed())

	cr := &rbacv1.ClusterRole{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "unsafe-custom-viewer"}}), cr)).To(Succeed())
	g.Expect(cr.Labels).NotTo(HaveKey("rbac.authorization.k8s.io/aggregate-to-admin"))
	g.Expect(cr.Labels).NotTo(HaveKey("rbac.authorization.k8s.io/aggregate-to-view"))
	g.Expect(cr.Labels).To(HaveKeyWithValue("custom.example.com/source-label", "kept"))
	g.Expect(cr.Labels).To(HaveKeyWithValue("custom.example.com/aggregate-to-monitoring", "true"))
}

func TestEnsureRolePrunesExistingKubernetesRBACAggregationLabels(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "prune-unsafe-agg-labels-rd",
			UID:  "prune-unsafe-agg-labels-uid",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "prune-unsafe-custom-viewer",
			ScopeNamespaced: false,
		},
	}
	controller := true
	existing := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: rd.Spec.TargetName,
			Labels: map[string]string{
				"rbac.authorization.k8s.io/aggregate-to-admin": "true",
				"custom.example.com/external":                  "kept",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       rd.Name,
				UID:        rd.UID,
				Controller: &controller,
			}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd, existing).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
	}
	g.Expect(r.ensureRole(ctx, rd, rules)).To(Succeed())

	cr := &rbacv1.ClusterRole{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: rd.Spec.TargetName}}), cr)).To(Succeed())
	g.Expect(cr.Labels).NotTo(HaveKey("rbac.authorization.k8s.io/aggregate-to-admin"))
	g.Expect(cr.Labels).To(HaveKeyWithValue("custom.example.com/external", "kept"))
}

func TestEnsureRoleWithAggregateFrom(t *testing.T) {
	ctx := context.Background()
	g := NewWithT(t)

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)

	rd := &authorizationv1alpha1.RoleDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RoleDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "agg-from-rd", UID: "agg-from-uid"},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "tenant-admin",
			ScopeNamespaced: false,
			AggregateFrom: &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{
						"t-caas.telekom.com/rbac-fragment":   "true",
						"t-caas.telekom.com/aggregate-scope": "tenant-admin",
					}},
				},
			},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	// No rules for aggregating ClusterRole
	err := r.ensureRole(ctx, rd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	// Verify the ClusterRole was created with aggregation rule and no rules
	cr := &rbacv1.ClusterRole{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "tenant-admin"}}), cr)).To(Succeed())
	g.Expect(cr.Rules).To(BeEmpty())
	g.Expect(cr.AggregationRule).NotTo(BeNil())
	g.Expect(cr.AggregationRule.ClusterRoleSelectors).To(HaveLen(1))
	g.Expect(cr.AggregationRule.ClusterRoleSelectors[0].MatchLabels).To(
		HaveKeyWithValue("t-caas.telekom.com/rbac-fragment", "true"),
	)
	g.Expect(cr.AggregationRule.ClusterRoleSelectors[0].MatchLabels).To(
		HaveKeyWithValue("t-caas.telekom.com/aggregate-scope", "tenant-admin"),
	)
}

// TestEnsureRole_TransitionFromRulesToAggregateFrom verifies that switching
// a RoleDefinition from rule-based to aggregateFrom correctly clears the old
// rules and sets the aggregation rule on the existing ClusterRole.
func TestEnsureRole_TransitionFromRulesToAggregateFrom(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = rbacv1.AddToScheme(s)
	_ = authorizationv1alpha1.AddToScheme(s)

	// Now the RoleDefinition switches to aggregateFrom.
	rd := &authorizationv1alpha1.RoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "transition-role",
			UID:  "transition-role-uid",
		},
		Spec: authorizationv1alpha1.RoleDefinitionSpec{
			TargetRole:      authorizationv1alpha1.DefinitionClusterRole,
			TargetName:      "transition-role",
			ScopeNamespaced: false,
			AggregateFrom: &rbacv1.AggregationRule{
				ClusterRoleSelectors: []metav1.LabelSelector{
					{MatchLabels: map[string]string{
						"t-caas.telekom.com/rbac-fragment":   "true",
						"t-caas.telekom.com/aggregate-scope": "transition",
					}},
				},
			},
		},
	}

	// Start with a rule-based ClusterRole already owned by this RoleDefinition.
	existingCR := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "transition-role",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "auth-operator",
			},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "RoleDefinition",
				Name:       rd.Name,
				UID:        rd.UID,
			}},
		},
		Rules: []rbacv1.PolicyRule{
			{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		},
	}

	c := fake.NewClientBuilder().WithScheme(s).WithObjects(existingCR, rd).Build()
	r := &RoleDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

	err := r.ensureRole(ctx, rd, nil)
	g.Expect(err).NotTo(HaveOccurred())

	cr := &rbacv1.ClusterRole{}
	g.Expect(c.Get(ctx, client.ObjectKeyFromObject(existingCR), cr)).To(Succeed())
	g.Expect(cr.Rules).To(BeEmpty(), "rules should be cleared after transition to aggregateFrom")
	g.Expect(cr.AggregationRule).NotTo(BeNil(), "aggregation rule should be set")
	g.Expect(cr.AggregationRule.ClusterRoleSelectors).To(HaveLen(1))
}

package authorization

import (
	"context"
	"errors"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/discovery"
)

// TestBuildRoleObject tests the buildRoleObject function
func TestBuildRoleObject(t *testing.T) {
	s := scheme.Scheme
	_ = authorizationv1alpha1.AddToScheme(s)

	recorder := record.NewFakeRecorder(10)
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

// TestBuildRoleWithRules tests the buildRoleWithRules function
func TestBuildRoleWithRules(t *testing.T) {
	s := scheme.Scheme
	_ = authorizationv1alpha1.AddToScheme(s)

	recorder := record.NewFakeRecorder(10)
	r := &RoleDefinitionReconciler{
		scheme:   s,
		recorder: recorder,
	}

	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get", "list"},
		},
	}

	tests := []struct {
		name          string
		targetRole    string
		targetName    string
		namespace     string
		wantType      string
		wantPopulated bool // whether we expect the returned role to be fully populated
	}{
		{
			name:          "ClusterRole",
			targetRole:    authorizationv1alpha1.DefinitionClusterRole,
			targetName:    "test-cluster-role",
			namespace:     "",
			wantType:      "*v1.ClusterRole",
			wantPopulated: true,
		},
		{
			name:          "Role",
			targetRole:    authorizationv1alpha1.DefinitionNamespacedRole,
			targetName:    "test-role",
			namespace:     "test-ns",
			wantType:      "*v1.Role",
			wantPopulated: true,
		},
		{
			name:          "invalid target returns empty ClusterRole",
			targetRole:    "InvalidRole",
			targetName:    "test-invalid",
			namespace:     "",
			wantType:      "*v1.ClusterRole",
			wantPopulated: false, // Returns empty object for invalid type
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rd := &authorizationv1alpha1.RoleDefinition{
				Spec: authorizationv1alpha1.RoleDefinitionSpec{
					TargetRole:      tt.targetRole,
					TargetName:      tt.targetName,
					TargetNamespace: tt.namespace,
				},
			}

			got, _ := r.buildRoleWithRules(rd, rules)

			gotType := ""
			switch v := got.(type) {
			case *rbacv1.ClusterRole:
				gotType = "*v1.ClusterRole"
				if tt.wantPopulated {
					if v.Name != tt.targetName {
						t.Errorf("ClusterRole name = %s, want %s", v.Name, tt.targetName)
					}
					if len(v.Rules) != len(rules) {
						t.Errorf("ClusterRole rules count = %d, want %d", len(v.Rules), len(rules))
					}
				}
			case *rbacv1.Role:
				gotType = "*v1.Role"
				if tt.wantPopulated {
					if v.Name != tt.targetName {
						t.Errorf("Role name = %s, want %s", v.Name, tt.targetName)
					}
					if v.Namespace != tt.namespace {
						t.Errorf("Role namespace = %s, want %s", v.Namespace, tt.namespace)
					}
					if len(v.Rules) != len(rules) {
						t.Errorf("Role rules count = %d, want %d", len(v.Rules), len(rules))
					}
				}
			}

			if gotType != tt.wantType {
				t.Errorf("buildRoleWithRules() returned type %s, want %s", gotType, tt.wantType)
			}
		})
	}
}

var _ = Describe("RoleDefinition Helpers", func() {
	ctx := context.Background()
	var r *RoleDefinitionReconciler

	BeforeEach(func() {
		resourceTracker := discovery.NewResourceTracker(scheme.Scheme, cfg)

		r = &RoleDefinitionReconciler{
			client:          k8sClient,
			scheme:          scheme.Scheme,
			recorder:        record.NewFakeRecorder(10),
			resourceTracker: resourceTracker,
		}
	})

	Describe("ensureFinalizer", func() {
		It("should add finalizer to RoleDefinition without one", func() {
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

			// Verify finalizer was added
			updated := &authorizationv1alpha1.RoleDefinition{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(rd), updated)).To(Succeed())
			Expect(updated.Finalizers).To(ContainElement(authorizationv1alpha1.RoleDefinitionFinalizer))
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

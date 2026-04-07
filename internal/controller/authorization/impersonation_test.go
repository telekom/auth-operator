// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"errors"
	"testing"

	"github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

func TestImpersonatedUsernameForPolicy(t *testing.T) {
	tests := []struct {
		name          string
		policy        *authorizationv1alpha1.RBACPolicy
		expectUser    string
		expectEnabled bool
		expectError   bool
	}{
		{
			name:          "nil policy",
			policy:        nil,
			expectUser:    "",
			expectEnabled: false,
			expectError:   false,
		},
		{
			name: "impersonation not configured",
			policy: &authorizationv1alpha1.RBACPolicy{
				Spec: authorizationv1alpha1.RBACPolicySpec{},
			},
			expectUser:    "",
			expectEnabled: false,
			expectError:   false,
		},
		{
			name: "impersonation disabled",
			policy: &authorizationv1alpha1.RBACPolicy{
				Spec: authorizationv1alpha1.RBACPolicySpec{
					Impersonation: &authorizationv1alpha1.ImpersonationConfig{Enabled: false},
				},
			},
			expectUser:    "",
			expectEnabled: false,
			expectError:   false,
		},
		{
			name: "enabled without serviceaccount ref",
			policy: &authorizationv1alpha1.RBACPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "p-missing-sa"},
				Spec: authorizationv1alpha1.RBACPolicySpec{
					Impersonation: &authorizationv1alpha1.ImpersonationConfig{Enabled: true},
				},
			},
			expectError: true,
		},
		{
			name: "enabled with complete serviceaccount ref",
			policy: &authorizationv1alpha1.RBACPolicy{
				Spec: authorizationv1alpha1.RBACPolicySpec{
					Impersonation: &authorizationv1alpha1.ImpersonationConfig{
						Enabled: true,
						ServiceAccountRef: &authorizationv1alpha1.SARef{
							Name:      "rbac-applier",
							Namespace: "team-a",
						},
					},
				},
			},
			expectUser:    "system:serviceaccount:team-a:rbac-applier",
			expectEnabled: true,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			username, enabled, err := impersonatedUsernameForPolicy(tt.policy)
			if tt.expectError {
				g.Expect(err).To(gomega.HaveOccurred())
				return
			}
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(username).To(gomega.Equal(tt.expectUser))
			g.Expect(enabled).To(gomega.Equal(tt.expectEnabled))
		})
	}
}

func TestResolvePolicyApplyClient(t *testing.T) {
	scheme := newTestScheme()
	baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("no impersonation returns base client", func(t *testing.T) {
		g := gomega.NewWithT(t)
		policy := &authorizationv1alpha1.RBACPolicy{}

		resolvedClient, username, err := resolvePolicyApplyClient(baseClient, scheme, nil, policy, nil, nil)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		g.Expect(username).To(gomega.BeEmpty())
		g.Expect(resolvedClient).To(gomega.Equal(baseClient))
	})

	t.Run("enabled impersonation requires base rest config", func(t *testing.T) {
		g := gomega.NewWithT(t)
		policy := &authorizationv1alpha1.RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-a"},
			Spec: authorizationv1alpha1.RBACPolicySpec{
				Impersonation: &authorizationv1alpha1.ImpersonationConfig{
					Enabled: true,
					ServiceAccountRef: &authorizationv1alpha1.SARef{
						Name:      "rbac-applier",
						Namespace: "team-a",
					},
				},
			},
		}

		_, _, err := resolvePolicyApplyClient(baseClient, scheme, nil, policy, nil, nil)
		g.Expect(err).To(gomega.HaveOccurred())
		g.Expect(err.Error()).To(gomega.ContainSubstring("rest config is unavailable"))
	})

	t.Run("enabled impersonation uses factory", func(t *testing.T) {
		g := gomega.NewWithT(t)
		policy := &authorizationv1alpha1.RBACPolicy{
			Spec: authorizationv1alpha1.RBACPolicySpec{
				Impersonation: &authorizationv1alpha1.ImpersonationConfig{
					Enabled: true,
					ServiceAccountRef: &authorizationv1alpha1.SARef{
						Name:      "rbac-applier",
						Namespace: "team-a",
					},
				},
			},
		}

		var capturedUser string
		factory := func(_ *rest.Config, _ *runtime.Scheme, username string) (client.Client, error) {
			capturedUser = username
			return baseClient, nil
		}

		resolvedClient, username, err := resolvePolicyApplyClient(
			baseClient,
			scheme,
			&rest.Config{Host: "https://cluster.local"},
			policy,
			factory,
			nil,
		)
		g.Expect(err).NotTo(gomega.HaveOccurred())
		g.Expect(username).To(gomega.Equal("system:serviceaccount:team-a:rbac-applier"))
		g.Expect(capturedUser).To(gomega.Equal(username))
		g.Expect(resolvedClient).To(gomega.Equal(baseClient))
	})

	t.Run("factory error is surfaced", func(t *testing.T) {
		g := gomega.NewWithT(t)
		policy := &authorizationv1alpha1.RBACPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "policy-factory-error"},
			Spec: authorizationv1alpha1.RBACPolicySpec{
				Impersonation: &authorizationv1alpha1.ImpersonationConfig{
					Enabled: true,
					ServiceAccountRef: &authorizationv1alpha1.SARef{
						Name:      "rbac-applier",
						Namespace: "team-a",
					},
				},
			},
		}

		factory := func(_ *rest.Config, _ *runtime.Scheme, _ string) (client.Client, error) {
			return nil, errors.New("factory failed")
		}

		_, _, err := resolvePolicyApplyClient(
			baseClient,
			scheme,
			&rest.Config{Host: "https://cluster.local"},
			policy,
			factory,
			nil,
		)
		g.Expect(err).To(gomega.HaveOccurred())
		g.Expect(err.Error()).To(gomega.ContainSubstring("factory failed"))
	})
}

func TestImpersonatedClientCache(t *testing.T) {
	scheme := newTestScheme()
	baseClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	policy := &authorizationv1alpha1.RBACPolicy{
		Spec: authorizationv1alpha1.RBACPolicySpec{
			Impersonation: &authorizationv1alpha1.ImpersonationConfig{
				Enabled: true,
				ServiceAccountRef: &authorizationv1alpha1.SARef{
					Name:      "rbac-applier",
					Namespace: "team-a",
				},
			},
		},
	}

	t.Run("factory called only once per username", func(t *testing.T) {
		g := gomega.NewWithT(t)
		callCount := 0
		factory := func(_ *rest.Config, _ *runtime.Scheme, _ string) (client.Client, error) {
			callCount++
			return baseClient, nil
		}
		cache := newImpersonatedClientCache()
		cfg := &rest.Config{Host: "https://cluster.local"}

		cl1, _, err := resolvePolicyApplyClient(baseClient, scheme, cfg, policy, factory, cache)
		g.Expect(err).NotTo(gomega.HaveOccurred())

		cl2, _, err := resolvePolicyApplyClient(baseClient, scheme, cfg, policy, factory, cache)
		g.Expect(err).NotTo(gomega.HaveOccurred())

		g.Expect(callCount).To(gomega.Equal(1), "factory should be called exactly once")
		g.Expect(cl1).To(gomega.Equal(cl2), "both calls should return the same cached client")
	})
}

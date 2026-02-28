// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	"testing"

	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestValidateRoleDefinitionSpec(t *testing.T) {
	tests := []struct {
		name    string
		rd      *RoleDefinition
		wantErr string
	}{
		{
			name: "valid ClusterRole with no aggregation",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
				},
			},
		},
		{
			name: "valid ClusterRole with aggregationLabels",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregationLabels: map[string]string{
						"custom.example.com/aggregate-to-monitoring": "true",
					},
				},
			},
		},
		{
			name: "valid ClusterRole with aggregateFrom",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
				},
			},
		},
		{
			name: "reject aggregationLabels on Role",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-role",
					TargetNamespace: "default",
					AggregationLabels: map[string]string{
						"rbac.authorization.k8s.io/aggregate-to-view": "true",
					},
				},
			},
			wantErr: "aggregationLabels can only be used when targetRole is 'ClusterRole'",
		},
		{
			name: "reject aggregateFrom on Role",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-role",
					TargetNamespace: "default",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
				},
			},
			wantErr: "aggregateFrom can only be used when targetRole is 'ClusterRole'",
		},
		{
			name: "reject aggregateFrom with restrictedApis",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
					RestrictedAPIs: []metav1.APIGroup{{Name: "apps"}},
				},
			},
			wantErr: "aggregateFrom is mutually exclusive",
		},
		{
			name: "reject aggregateFrom with restrictedResources",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
					RestrictedResources: []metav1.APIResource{{Name: "secrets"}},
				},
			},
			wantErr: "aggregateFrom is mutually exclusive",
		},
		{
			name: "reject aggregateFrom with restrictedVerbs",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{"role": "viewer"}},
						},
					},
					RestrictedVerbs: []string{"delete"},
				},
			},
			wantErr: "aggregateFrom is mutually exclusive",
		},
		{
			name: "reject aggregateFrom with empty selectors",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{},
					},
				},
			},
			wantErr: "must have at least one clusterRoleSelector",
		},
		{
			name: "reject Role without targetNamespace",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionNamespacedRole,
					TargetName: "test-role",
				},
			},
			wantErr: "targetNamespace is required when targetRole is 'Role'",
		},
		{
			name: "reject ClusterRole with targetNamespace",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionClusterRole,
					TargetName:      "test-role",
					TargetNamespace: "default",
				},
			},
			wantErr: "targetNamespace must not be set when targetRole is 'ClusterRole'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			err := validateRoleDefinitionSpec(tt.rd)
			if tt.wantErr == "" {
				g.Expect(err).NotTo(HaveOccurred())
			} else {
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring(tt.wantErr))
			}
		})
	}
}

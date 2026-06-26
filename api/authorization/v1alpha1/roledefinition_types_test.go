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

func safeAggregateFromSelectorLabels() map[string]string {
	return map[string]string{
		aggregateFromFragmentLabelKey: aggregateFromFragmentLabelValue,
		aggregateFromScopeLabelKey:    "team",
	}
}

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
							{MatchLabels: safeAggregateFromSelectorLabels()},
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
			name: "reject metadata aggregation label on Role",
			rd: &RoleDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-role",
					Labels: map[string]string{
						rbacv1.GroupName + "/aggregate-to-view": "true",
					},
				},
				Spec: RoleDefinitionSpec{
					TargetRole:      DefinitionNamespacedRole,
					TargetName:      "test-role",
					TargetNamespace: "default",
				},
			},
			wantErr: "metadata labels propagate",
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
							{MatchLabels: safeAggregateFromSelectorLabels()},
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
							{MatchLabels: safeAggregateFromSelectorLabels()},
						},
					},
					RestrictedAPIs: []RestrictedAPIGroup{{Name: "apps"}},
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
							{MatchLabels: safeAggregateFromSelectorLabels()},
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
							{MatchLabels: safeAggregateFromSelectorLabels()},
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
			name: "reject aggregateFrom without fragment label",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{
								"t-caas.telekom.com/aggregate-scope": "team",
							}},
						},
					},
				},
			},
			wantErr: "t-caas.telekom.com/rbac-fragment",
		},
		{
			name: "reject aggregateFrom with system label",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{
							{MatchLabels: map[string]string{
								"t-caas.telekom.com/rbac-fragment":   "true",
								"t-caas.telekom.com/aggregate-scope": "team",
								"kubernetes.io/bootstrapping":        "rbac-defaults",
							}},
						},
					},
				},
			},
			wantErr: "aggregateFrom selectors may only use",
		},
		{
			name: "reject aggregateFrom with matchExpressions",
			rd: &RoleDefinition{
				Spec: RoleDefinitionSpec{
					TargetRole: DefinitionClusterRole,
					TargetName: "test-role",
					AggregateFrom: &rbacv1.AggregationRule{
						ClusterRoleSelectors: []metav1.LabelSelector{{
							MatchLabels: safeAggregateFromSelectorLabels(),
							MatchExpressions: []metav1.LabelSelectorRequirement{{
								Key:      "t-caas.telekom.com/aggregate-scope",
								Operator: metav1.LabelSelectorOpExists,
							}},
						}},
					},
				},
			},
			wantErr: "matchExpressions are not allowed",
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
			wantErr: "targetNamespace must be empty when targetRole is 'ClusterRole'",
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

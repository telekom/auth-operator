// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"testing"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetLabelsFromNamespaceSelector(t *testing.T) {
	tests := []struct {
		name     string
		selector metav1.LabelSelector
		want     map[string]string
	}{
		{
			name:     "empty selector",
			selector: metav1.LabelSelector{},
			want:     map[string]string{},
		},
		{
			name: "matchLabels with owner key",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "platform",
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyOwner: "platform",
			},
		},
		{
			name: "matchLabels with tenant key",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyTenant: "team-alpha",
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyTenant: "team-alpha",
			},
		},
		{
			name: "matchLabels with thirdparty key",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyThirdParty: "vendor-x",
			},
		},
		{
			name: "matchLabels with all tracked keys",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner:      "tenant",
					authorizationv1alpha1.LabelKeyTenant:     "team-beta",
					authorizationv1alpha1.LabelKeyThirdParty: "vendor-y",
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyOwner:      "tenant",
				authorizationv1alpha1.LabelKeyTenant:     "team-beta",
				authorizationv1alpha1.LabelKeyThirdParty: "vendor-y",
			},
		},
		{
			name: "matchLabels ignores non-tracked keys",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"kubernetes.io/metadata.name":       "kube-system",
					authorizationv1alpha1.LabelKeyOwner: "platform",
					"some-other-label":                  "value",
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyOwner: "platform",
			},
		},
		{
			name: "matchExpressions with owner key In single value",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyOwner,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"platform"},
					},
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyOwner: "platform",
			},
		},
		{
			name: "matchExpressions with tenant key In single value",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyTenant,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"team-gamma"},
					},
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyTenant: "team-gamma",
			},
		},
		{
			name: "matchExpressions with thirdparty key In single value",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyThirdParty,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"vendor-z"},
					},
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyThirdParty: "vendor-z",
			},
		},
		{
			name: "matchExpressions ignores non-In operator",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyOwner,
						Operator: metav1.LabelSelectorOpNotIn,
						Values:   []string{"platform"},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "matchExpressions ignores multi-value In",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyOwner,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"platform", "tenant"},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "matchExpressions ignores non-tracked keys",
			selector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      "kubernetes.io/metadata.name",
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"kube-system"},
					},
				},
			},
			want: map[string]string{},
		},
		{
			name: "combined matchLabels and matchExpressions",
			selector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: "tenant",
				},
				MatchExpressions: []metav1.LabelSelectorRequirement{
					{
						Key:      authorizationv1alpha1.LabelKeyTenant,
						Operator: metav1.LabelSelectorOpIn,
						Values:   []string{"team-delta"},
					},
				},
			},
			want: map[string]string{
				authorizationv1alpha1.LabelKeyOwner:  "tenant",
				authorizationv1alpha1.LabelKeyTenant: "team-delta",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getLabelsFromNamespaceSelector(tt.selector)
			if len(got) != len(tt.want) {
				t.Errorf("getLabelsFromNamespaceSelector() returned %d labels, want %d: got=%v, want=%v", len(got), len(tt.want), got, tt.want)
				return
			}
			for key, wantVal := range tt.want {
				gotVal, ok := got[key]
				if !ok {
					t.Errorf("getLabelsFromNamespaceSelector() missing key %q, got=%v", key, got)
				} else if gotVal != wantVal {
					t.Errorf("getLabelsFromNamespaceSelector()[%q] = %q, want %q", key, gotVal, wantVal)
				}
			}
		})
	}
}

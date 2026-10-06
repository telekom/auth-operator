// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"maps"
	"testing"

	"github.com/go-logr/logr"
	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestValidTrackedOwnershipLabelsAddon(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		valid  bool
	}{
		{"untracked", nil, true},
		{"addon", map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon, authorizationv1alpha1.LabelKeyAddon: "metrics"}, true},
		{"missing identity", map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon}, false},
		{"empty identity", map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon, authorizationv1alpha1.LabelKeyAddon: ""}, false},
		{"missing owner", map[string]string{authorizationv1alpha1.LabelKeyAddon: "metrics"}, false},
		{"empty owner", map[string]string{authorizationv1alpha1.LabelKeyOwner: "", authorizationv1alpha1.LabelKeyAddon: "metrics"}, false},
		{"unknown owner", map[string]string{authorizationv1alpha1.LabelKeyOwner: "unknown", authorizationv1alpha1.LabelKeyAddon: "metrics"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidTrackedOwnershipLabels(tt.labels); got != tt.valid {
				t.Fatalf("ValidTrackedOwnershipLabels(%v) = %v, want %v", tt.labels, got, tt.valid)
			}
		})
	}
	for owner, identity := range map[string]string{
		authorizationv1alpha1.OwnerPlatform:   "",
		authorizationv1alpha1.OwnerTenant:     authorizationv1alpha1.LabelKeyTenant,
		authorizationv1alpha1.OwnerThirdParty: authorizationv1alpha1.LabelKeyThirdParty,
		authorizationv1alpha1.OwnerAddon:      authorizationv1alpha1.LabelKeyAddon,
	} {
		t.Run(owner, func(t *testing.T) {
			labels := map[string]string{authorizationv1alpha1.LabelKeyOwner: owner}
			if identity != "" {
				labels[identity] = "team"
			}
			if !ValidTrackedOwnershipLabels(labels) {
				t.Fatalf("valid ownership rejected: %v", labels)
			}
			conflicts := []string{authorizationv1alpha1.LabelKeyAddon}
			if owner == authorizationv1alpha1.OwnerAddon {
				conflicts = []string{authorizationv1alpha1.LabelKeyTenant, authorizationv1alpha1.LabelKeyThirdParty}
			}
			for _, key := range conflicts {
				for _, value := range []string{"", "other"} {
					conflicting := maps.Clone(labels)
					conflicting[key] = value
					if ValidTrackedOwnershipLabels(conflicting) {
						t.Errorf("conflicting ownership accepted: %v", conflicting)
					}
				}
			}
		})
	}
}

func TestCompleteTrackedAddonSelector(t *testing.T) {
	addon := map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon, authorizationv1alpha1.LabelKeyAddon: "metrics"}
	tests := []struct {
		name     string
		selector metav1.LabelSelector
		want     map[string]string
	}{
		{"identity implies owner", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "metrics"}}, addon},
		{"explicit owner", metav1.LabelSelector{MatchLabels: addon}, addon},
		{"single expression", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpIn, Values: []string{"metrics"}}}}, addon},
		{"multiple expression values", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpIn, Values: []string{"metrics", "logging"}}}}, map[string]string{}},
		{"empty identity", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: ""}}, map[string]string{}},
		{"owner without identity", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon}}, map[string]string{}},
		{"conflicting owner", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerPlatform, authorizationv1alpha1.LabelKeyAddon: "metrics"}}, map[string]string{}},
		{"conflicting tenant", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyTenant: "team", authorizationv1alpha1.LabelKeyAddon: "metrics"}}, map[string]string{}},
		{"conflicting thirdparty", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyThirdParty: "vendor", authorizationv1alpha1.LabelKeyAddon: "metrics"}}, map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getCompleteTrackedLabelsFromNamespaceSelector(tt.selector); !maps.Equal(got, tt.want) {
				t.Fatalf("derived labels = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddonServiceAccountInheritance(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon, authorizationv1alpha1.LabelKeyAddon: "metrics"}
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-addon-metrics", Labels: labels}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(ns).Build()
	got, err := GetSANamespaceTrackedLabels(context.Background(), c, ServiceAccountInfo{Namespace: ns.Name, IsServiceAccount: true})
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(got, labels) {
		t.Fatalf("inherited labels = %v, want %v", got, labels)
	}
	if extra := FindExtraTrackedKey(labels, map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon}); extra != authorizationv1alpha1.LabelKeyAddon {
		t.Fatalf("extra tracked key = %q", extra)
	}
}

func TestAddonMigrationOwnershipImmutable(t *testing.T) {
	validator := &NamespaceValidator{TDGMigration: true}
	for _, other := range []string{authorizationv1alpha1.OwnerTenant, authorizationv1alpha1.OwnerThirdParty, authorizationv1alpha1.OwnerPlatform} {
		for _, owners := range [][2]string{{authorizationv1alpha1.OwnerAddon, other}, {other, authorizationv1alpha1.OwnerAddon}} {
			t.Run(owners[0]+" to "+owners[1], func(t *testing.T) {
				oldNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{authorizationv1alpha1.LabelKeyOwner: owners[0]}}}
				newNS := oldNS.DeepCopy()
				newNS.Labels[authorizationv1alpha1.LabelKeyOwner] = owners[1]
				if resp := validator.validateLabelImmutability(logr.Discard(), admission.Request{}, newNS, oldNS, BypassCheckResult{AllowProtectedLabelChanges: true}); resp == nil || resp.Allowed {
					t.Fatal("migration bypass allowed add-on owner reclassification")
				}
			})
		}
	}
}

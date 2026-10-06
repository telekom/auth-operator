// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"
	"encoding/json"
	"maps"
	"testing"

	"github.com/go-logr/logr"
	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func TestAddonNamespaceAdmissionSelectorIsolation(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, authorizationv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name     string
		selector metav1.LabelSelector
		allowed  bool
	}{
		{"pinned identity", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "a"}}, true},
		{"other identity", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "b"}}, false},
		{"owner alone", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon}}, false},
		{"owner In addon", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyOwner, Operator: metav1.LabelSelectorOpIn, Values: []string{authorizationv1alpha1.OwnerAddon}}}}, false},
		{"identity Exists", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpExists}}}, false},
		{"identity NotIn", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"b"}}}}, false},
		{"multi-value identity", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpIn, Values: []string{"a", "b"}}}}, false},
		{"pinned In", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpIn, Values: []string{"a"}}}}, true},
		{"pin plus Exists", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "a"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpExists}}}, false},
		{"pin plus NotIn", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "a"}, MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyAddon, Operator: metav1.LabelSelectorOpNotIn, Values: []string{"b"}}}}, false},
		{"owner Exists", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyOwner, Operator: metav1.LabelSelectorOpExists}}}, false},
		{"owner NotIn", metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authorizationv1alpha1.LabelKeyOwner, Operator: metav1.LabelSelectorOpNotIn, Values: []string{authorizationv1alpha1.OwnerTenant}}}}, false},
		{"unrelated selector", metav1.LabelSelector{MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyProtected: "true"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bd := &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "legacy-addon"}, Spec: authorizationv1alpha1.BindDefinitionSpec{
				Subjects:     []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "addon-controller", APIGroup: rbacv1.GroupName}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"view"}, NamespaceSelector: []metav1.LabelSelector{tt.selector}}},
			}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bd).Build()
			mutator := &NamespaceMutator{Client: c, Decoder: admission.NewDecoder(scheme)}
			validator := &NamespaceValidator{Client: c, Decoder: admission.NewDecoder(scheme)}
			for _, operation := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update} {
				ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "t-addon-a", Labels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon,
					authorizationv1alpha1.LabelKeyAddon: "a", authorizationv1alpha1.LabelKeyProtected: "true",
				}}}
				raw, err := json.Marshal(ns)
				if err != nil {
					t.Fatal(err)
				}
				req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
					Name: ns.Name, Operation: operation, Object: runtime.RawExtension{Raw: raw},
					Kind:     metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"},
					UserInfo: authenticationv1.UserInfo{Username: "addon-controller"},
				}}
				if operation == admissionv1.Update {
					req.OldObject = req.Object
				}
				if resp := validator.Handle(context.Background(), req); resp.Allowed != tt.allowed {
					t.Fatalf("%s validation allowed=%v, want %v: %v", operation, resp.Allowed, tt.allowed, resp.Result)
				}
				// CREATE mutation derives the pinned identity; validation above
				// independently rejects a submitted different add-on identity.
				if operation == admissionv1.Create && tt.name == "other identity" {
					continue
				}
				if resp := mutator.Handle(context.Background(), req); resp.Allowed != tt.allowed {
					t.Fatalf("%s mutation allowed=%v, want %v: %v", operation, resp.Allowed, tt.allowed, resp.Result)
				}
			}
		})
	}
}

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

func TestUnmatchedAddonSelectorPreservesServiceAccountFallback(t *testing.T) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{corev1.AddToScheme, authorizationv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			t.Fatal(err)
		}
	}
	for owner, identityKey := range map[string]string{
		authorizationv1alpha1.OwnerTenant:     authorizationv1alpha1.LabelKeyTenant,
		authorizationv1alpha1.OwnerThirdParty: authorizationv1alpha1.LabelKeyThirdParty,
		authorizationv1alpha1.OwnerAddon:      authorizationv1alpha1.LabelKeyAddon,
	} {
		t.Run(owner, func(t *testing.T) {
			source := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: owner + "-system", Labels: map[string]string{
				authorizationv1alpha1.LabelKeyOwner: owner, identityKey: "team",
			}}}
			bd := &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "unrelated-addon"}, Spec: authorizationv1alpha1.BindDefinitionSpec{
				Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Namespace: source.Name, Name: "controller"}},
				RoleBindings: []authorizationv1alpha1.NamespaceBinding{{ClusterRoleRefs: []string{"view"}, NamespaceSelector: []metav1.LabelSelector{{
					MatchLabels: map[string]string{authorizationv1alpha1.LabelKeyAddon: "metrics"},
				}}}},
			}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(source, bd).Build()
			target := source.DeepCopy()
			target.Name = owner + "-app"
			raw, err := json.Marshal(target)
			if err != nil {
				t.Fatal(err)
			}
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Name: target.Name, Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Operation: admissionv1.Update,
				Object: runtime.RawExtension{Raw: raw}, OldObject: runtime.RawExtension{Raw: raw},
				UserInfo: authenticationv1.UserInfo{Username: "system:serviceaccount:" + source.Name + ":controller"},
			}}
			validator := &NamespaceValidator{Client: c, Decoder: admission.NewDecoder(scheme)}
			if resp := validator.Handle(context.Background(), req); !resp.Allowed {
				t.Fatalf("exact-owner ServiceAccount fallback rejected update: %v", resp.Result)
			}
			mutator := &NamespaceMutator{Client: c, Decoder: admission.NewDecoder(scheme)}
			if resp := mutator.Handle(context.Background(), req); !resp.Allowed || len(resp.Patches) != 0 {
				t.Fatalf("unmatched selector interfered with unchanged ownership: %v", resp)
			}
		})
	}
}

func TestAddonMigrationOwnershipImmutable(t *testing.T) {
	validator := &NamespaceValidator{TDGMigration: true}
	t.Run("identity immutable without reclassification", func(t *testing.T) {
		oldNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
			authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon,
			authorizationv1alpha1.LabelKeyAddon: "metrics",
		}}}
		newNS := oldNS.DeepCopy()
		newNS.Labels[authorizationv1alpha1.LabelKeyAddon] = "logging"
		resp := validator.validateLabelImmutability(logr.Discard(), admission.Request{}, newNS, oldNS, BypassCheckResult{AllowProtectedLabelChanges: true})
		if resp == nil || resp.Allowed {
			t.Fatal("migration bypass allowed identity change without owner reclassification")
		}
	})
}

func TestAddonMigrationAdmissionParity(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ownership := func(owner string) map[string]string {
		labels := map[string]string{authorizationv1alpha1.LabelKeyOwner: owner}
		key := map[string]string{
			authorizationv1alpha1.OwnerTenant:     authorizationv1alpha1.LabelKeyTenant,
			authorizationv1alpha1.OwnerThirdParty: authorizationv1alpha1.LabelKeyThirdParty,
			authorizationv1alpha1.OwnerAddon:      authorizationv1alpha1.LabelKeyAddon,
		}[owner]
		if key != "" {
			labels[key] = "identity"
		}
		return labels
	}
	check := func(t *testing.T, oldLabels, newLabels map[string]string, migration, bypass, allowed bool) {
		t.Helper()
		oldNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "migration-ns", Labels: oldLabels}}
		newNS := oldNS.DeepCopy()
		newNS.Labels = newLabels
		oldRaw, err := json.Marshal(oldNS)
		if err != nil {
			t.Fatal(err)
		}
		newRaw, err := json.Marshal(newNS)
		if err != nil {
			t.Fatal(err)
		}
		username := "ordinary-user"
		if bypass {
			username = helmControllerSA
		}
		req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}, Name: oldNS.Name, Operation: admissionv1.Update,
			UserInfo: authenticationv1.UserInfo{Username: username},
			Object:   runtime.RawExtension{Raw: newRaw}, OldObject: runtime.RawExtension{Raw: oldRaw},
		}}
		v := &NamespaceValidator{TDGMigration: migration, Decoder: admission.NewDecoder(scheme)}
		if resp := v.Handle(context.Background(), req); resp.Allowed != allowed {
			t.Fatalf("migration=%v bypass=%v allowed=%v, want %v: %v", migration, bypass, resp.Allowed, allowed, resp.Result)
		}
		if allowed {
			m := &NamespaceMutator{TDGMigration: migration, Decoder: admission.NewDecoder(scheme)}
			if resp := m.Handle(context.Background(), req); !resp.Allowed || len(resp.Patches) != 0 {
				t.Fatalf("migration mutation should preserve submitted replacement labels: %v", resp)
			}
		}
	}
	for _, other := range []string{authorizationv1alpha1.OwnerTenant, authorizationv1alpha1.OwnerThirdParty, authorizationv1alpha1.OwnerPlatform} {
		for _, owners := range [][2]string{{authorizationv1alpha1.OwnerAddon, other}, {other, authorizationv1alpha1.OwnerAddon}} {
			t.Run(owners[0]+" to "+owners[1], func(t *testing.T) {
				for _, gates := range [][2]bool{{true, true}, {true, false}, {false, true}, {false, false}} {
					allowed := gates[0] && gates[1] && other != authorizationv1alpha1.OwnerPlatform
					// Replacing the entire ownership map also exercises removal
					// of the old category's identity label.
					check(t, ownership(owners[0]), ownership(owners[1]), gates[0], gates[1], allowed)
				}
			})
		}
	}
	for _, legacy := range []string{"cas", "tenant", "thirdparty", "platform", "schiff"} {
		t.Run("legacy "+legacy+" adopted as addon", func(t *testing.T) {
			old := map[string]string{legacyOwnerLabel: legacy}
			for _, gates := range [][2]bool{{true, true}, {true, false}, {false, true}} {
				allowed := gates[0] && gates[1] && legacy != "platform" && legacy != "schiff"
				check(t, old, ownership(authorizationv1alpha1.OwnerAddon), gates[0], gates[1], allowed)
			}
		})
	}
	t.Run("conflicting old identity retained", func(t *testing.T) {
		newLabels := ownership(authorizationv1alpha1.OwnerAddon)
		newLabels[authorizationv1alpha1.LabelKeyTenant] = "team"
		check(t, ownership(authorizationv1alpha1.OwnerTenant), newLabels, true, true, false)
	})
}

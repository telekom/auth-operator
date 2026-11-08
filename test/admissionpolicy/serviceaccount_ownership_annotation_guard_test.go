// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package admissionpolicy_test exercises the shipped ValidatingAdmissionPolicy
// manifests against a real envtest API server.
package admissionpolicy_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/yaml"
)

const (
	annotationKey = "t-caas.telekom.com/inherit-hosting-namespace-ownership"
	ns            = "platform-controllers"
)

// TestServiceAccountOwnershipAnnotationGuard applies the kustomize VAP (the
// chart renders the same spec, pinned by the chart render test) and checks
// that a tenant cannot set, change or remove the annotation while
// system:masters can.
func TestServiceAccountOwnershipAnnotationGuard(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	ctx := context.Background()

	admin, tenant := setupGuard(ctx, t, env, cfg)

	sa := func(name string, annotations map[string]string) *corev1.ServiceAccount {
		return &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Annotations: annotations}}
	}
	// Policies activate asynchronously; wait until the guard denies.
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := tenant.Create(ctx, sa("probe", map[string]string{annotationKey: "true"}), client.DryRunAll)
		if err != nil && strings.Contains(err.Error(), "only kubernetes-admin or system:masters") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard never denied a tenant CREATE with the annotation: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	update := func(c client.Client, mutate func(map[string]string)) error {
		current := &corev1.ServiceAccount{}
		if err := c.Get(ctx, client.ObjectKey{Namespace: ns, Name: "flux"}, current); err != nil {
			return err
		}
		if current.Annotations == nil {
			current.Annotations = map[string]string{}
		}
		mutate(current.Annotations)
		return c.Update(ctx, current)
	}
	set := func(value string) func(map[string]string) {
		return func(a map[string]string) { a[annotationKey] = value }
	}
	remove := func(a map[string]string) { delete(a, annotationKey) }
	unrelated := func(a map[string]string) { a["example.com/unrelated"] = time.Now().String() }

	steps := []struct {
		name    string
		run     func() error
		allowed bool
	}{
		{"tenant creates without annotation", func() error { return tenant.Create(ctx, sa("flux", nil)) }, true},
		{"tenant creates with annotation", func() error { return tenant.Create(ctx, sa("other", map[string]string{annotationKey: "false"})) }, false},
		{"tenant sets annotation", func() error { return update(tenant, set("true")) }, false},
		{"tenant edits unrelated annotation", func() error { return update(tenant, unrelated) }, true},
		{"admin sets annotation", func() error { return update(admin, set("true")) }, true},
		{"tenant edits unrelated annotation on annotated SA", func() error { return update(tenant, unrelated) }, true},
		{"tenant changes annotation", func() error { return update(tenant, set("false")) }, false},
		{"tenant removes annotation", func() error { return update(tenant, remove) }, false},
		{"admin removes annotation", func() error { return update(admin, remove) }, true},
		{"admin creates with annotation", func() error { return admin.Create(ctx, sa("admin-made", map[string]string{annotationKey: "true"})) }, true},
	}
	for _, step := range steps {
		err := step.run()
		if step.allowed && err != nil {
			t.Fatalf("%s: expected allowed, got %v", step.name, err)
		}
		if !step.allowed && (err == nil || !strings.Contains(err.Error(), "only kubernetes-admin or system:masters")) {
			t.Fatalf("%s: expected guard denial, got %v", step.name, err)
		}
	}
}

// setupGuard installs the kustomize VAP and returns an admin client and a
// tenant client that may create and update ServiceAccounts in ns.
func setupGuard(ctx context.Context, t *testing.T, env *envtest.Environment, cfg *rest.Config) (admin, tenant client.Client) {
	t.Helper()
	admin, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "webhook", "serviceaccount_ownership_annotation_vap.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	docs := strings.Split(string(raw), "\n---\n")
	policy, binding := &admissionregistrationv1.ValidatingAdmissionPolicy{}, &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	if len(docs) != 2 || yaml.Unmarshal([]byte(docs[0]), policy) != nil || yaml.Unmarshal([]byte(docs[1]), binding) != nil {
		t.Fatalf("expected a policy and a binding in the manifest")
	}
	for _, obj := range []client.Object{policy, binding} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatalf("create %T: %v", obj, err)
		}
	}

	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sa-editor"},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"serviceaccounts"}, Verbs: []string{"get", "create", "update", "patch"}}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "sa-editor"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "sa-editor"},
			Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "tenant"}},
		},
	} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatalf("create %T: %v", obj, err)
		}
	}
	tenantUser, err := env.AddUser(envtest.User{Name: "tenant", Groups: []string{"tenants"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err = client.New(tenantUser.Config(), client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}

	return admin, tenant
}

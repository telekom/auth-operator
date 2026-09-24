package webhooks_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corev1apply "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
)

//nolint:gocyclo // Each failure reports the exact setup or authorization step.
func TestBindDefinitionBridgeOrderedApply(t *testing.T) {
	var handler atomic.Pointer[webhooks.Authorizer]
	webhook := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current := handler.Load(); current != nil {
			current.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(authzv1.SubjectAccessReview{
			Status: authzv1.SubjectAccessReviewStatus{},
		})
	}))
	defer webhook.Close()

	dir := t.TempDir()
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: webhook
  cluster:
    server: %s
    certificate-authority-data: %s
contexts:
- name: webhook
  context:
    cluster: webhook
    user: webhook
current-context: webhook
users:
- name: webhook
  user: {}
`, webhook.URL, base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: webhook.Certificate().Raw})))
	kubeconfigPath := filepath.Join(dir, "webhook.kubeconfig")
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Node
  name: node
- type: RBAC
  name: rbac
- type: Webhook
  name: bridge
  webhook:
    authorizedTTL: 0s
    unauthorizedTTL: 0s
    cacheAuthorizedRequests: false
    cacheUnauthorizedRequests: false
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: NoOpinion
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: %s
`, kubeconfigPath)
	configPath := filepath.Join(dir, "authorization.yaml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")},
	}
	env.ControlPlane.GetAPIServer().Configure().Disable("authorization-mode").Set("authorization-config", configPath)
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	s := runtime.NewScheme()
	for _, register := range []func(*runtime.Scheme) error{corev1.AddToScheme, rbacv1.AddToScheme, authz.AddToScheme} {
		if err := register(s); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(&webhooks.Authorizer{Client: admin, Log: zap.New(), AllowUnauthenticatedAuthorize: true})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	for _, ns := range []*corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "bridge-source"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "bridge-other", Labels: map[string]string{authz.LabelKeyTenant: "other"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "bridge-protected", Labels: map[string]string{
			authz.LabelKeyTenant: "team-a", authz.LabelKeyProtected: "true",
		}}},
	} {
		if err := admin.Create(ctx, ns); err != nil {
			t.Fatal(err)
		}
	}
	subject := rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "gitops", Namespace: "bridge-source"}
	if err := admin.Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: subject.Name, Namespace: subject.Namespace}}); err != nil {
		t.Fatal(err)
	}
	creator := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "bridge-namespace-creator"}, Rules: []rbacv1.PolicyRule{{
		Verbs: []string{"create", "patch"}, APIGroups: []string{""}, Resources: []string{"namespaces"},
	}}}
	if err := admin.Create(ctx, creator); err != nil {
		t.Fatal(err)
	}
	if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "bridge-namespace-creator"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: creator.Name},
		Subjects:   []rbacv1.Subject{subject},
	}); err != nil {
		t.Fatal(err)
	}
	secretRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "bridge-secret-writer"}, Rules: []rbacv1.PolicyRule{{
		Verbs: []string{"patch", "create"}, APIGroups: []string{""}, Resources: []string{"secrets"},
	}}}
	if err := admin.Create(ctx, secretRole); err != nil {
		t.Fatal(err)
	}
	bd := &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{Name: "bridge-apply"}, Spec: authz.BindDefinitionSpec{
		TargetName: "bridge-apply", Subjects: []rbacv1.Subject{subject},
		RoleBindings: []authz.NamespaceBinding{{
			AuthorizeBeforeBinding: true,
			ClusterRoleRefs:        []string{secretRole.Name},
			NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{authz.LabelKeyTenant: "team-a"},
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: authz.LabelKeyProtected, Operator: metav1.LabelSelectorOpDoesNotExist}}}},
		}},
	}}
	if err := admin.Create(ctx, bd); err != nil {
		t.Fatal(err)
	}

	asSA := rest.CopyConfig(cfg)
	asSA.Impersonate = rest.ImpersonationConfig{UserName: "system:serviceaccount:bridge-source:gitops", Groups: []string{
		"system:serviceaccounts", "system:serviceaccounts:bridge-source", "system:authenticated",
	}}
	gitops, err := client.New(asSA, client.Options{Scheme: s})
	if err != nil {
		t.Fatal(err)
	}
	before := corev1apply.Secret("before-namespace", "bridge-target").WithData(map[string][]byte{"key": []byte("value")})
	if err := gitops.Apply(ctx, before, client.FieldOwner("bridge-test")); !apierrors.IsForbidden(err) {
		t.Fatalf("secret before namespace should be forbidden, got %v", err)
	}
	namespace := corev1apply.Namespace("bridge-target").WithLabels(map[string]string{authz.LabelKeyTenant: "team-a"})
	if err := gitops.Apply(ctx, namespace, client.FieldOwner("bridge-test")); err != nil {
		t.Fatalf("namespace apply: %v", err)
	}
	secretData := map[string][]byte{"key": []byte("value")}
	secret := corev1apply.Secret("first-apply", "bridge-target").WithData(secretData)
	if err := gitops.Apply(ctx, secret, client.FieldOwner("bridge-test")); err != nil {
		t.Fatalf("same ordered apply, secret: %v", err)
	}
	var roleBindings rbacv1.RoleBindingList
	if err := admin.List(ctx, &roleBindings, client.InNamespace("bridge-target")); err != nil {
		t.Fatal(err)
	}
	if len(roleBindings.Items) != 0 {
		t.Fatalf("expected no RoleBinding before reconciliation, got %d", len(roleBindings.Items))
	}
	for _, name := range []string{"bridge-other", "bridge-protected"} {
		other := corev1apply.Secret("not-allowed", name).WithData(secretData)
		if err := gitops.Apply(ctx, other, client.FieldOwner("bridge-test")); !apierrors.IsForbidden(err) {
			t.Errorf("secret apply to %s should be forbidden, got %v", name, err)
		}
	}
	current := &corev1.Namespace{}
	if err := admin.Get(ctx, client.ObjectKey{Name: "bridge-target"}, current); err != nil {
		t.Fatal(err)
	}
	current.Labels[authz.LabelKeyTenant] = "other"
	if err := admin.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	revoked := corev1apply.Secret("after-label-change", "bridge-target").WithData(secretData)
	if err := gitops.Apply(ctx, revoked, client.FieldOwner("bridge-test")); !apierrors.IsForbidden(err) {
		t.Fatalf("secret after tenant label change should be forbidden, got %v", err)
	}
}

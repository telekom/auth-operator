// Package poddeletionguard_test runs the pod deletion guard behind a real API
// server, so the matchConditions scoping is evaluated by Kubernetes itself.
package poddeletionguard_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	authorizationwebhook "github.com/telekom/auth-operator/internal/webhook/authorization"
)

const (
	guardPath      = "/validate-v1-pod-deletion-guard"
	delegatedGroup = "delegated-recovery"
	testNamespace  = "guard-test"
)

var target = types.NamespacedName{Namespace: "kube-system", Name: "recovery-target"}

// guardWebhook mirrors the chart's rendering for podDeletionGuard.groups.
func guardWebhook() *admissionregistrationv1.ValidatingWebhookConfiguration {
	return &admissionregistrationv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-deletion-guard"},
		Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name:                    "pod-deletion-guard.validating.webhook.auth.t-caas.telekom.de",
			AdmissionReviewVersions: []string{"v1"},
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				Service: &admissionregistrationv1.ServiceReference{Name: "unused", Namespace: "unused", Path: ptr.To(guardPath)},
			},
			FailurePolicy: ptr.To(admissionregistrationv1.Fail),
			MatchConditions: []admissionregistrationv1.MatchCondition{{
				Name:       "delegated-identity",
				Expression: fmt.Sprintf(`request.userInfo.username in [] || request.userInfo.groups.exists(g, g in [%q])`, delegatedGroup),
			}},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Delete},
				Rule: admissionregistrationv1.Rule{
					APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"pods"},
					Scope: ptr.To(admissionregistrationv1.NamespacedScope),
				},
			}},
			SideEffects:    ptr.To(admissionregistrationv1.SideEffectClassNone),
			TimeoutSeconds: ptr.To[int32](5),
		}},
	}
}

func TestPodDeletionGuardEnvtest(t *testing.T) {
	env := &envtest.Environment{
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			ValidatingWebhooks: []*admissionregistrationv1.ValidatingWebhookConfiguration{guardWebhook()},
		},
	}
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		repoRoot, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
		if err != nil {
			t.Fatal(err)
		}
		env.BinaryAssetsDirectory = filepath.Join(repoRoot, "bin", "k8s",
			fmt.Sprintf("1.34.1-%s-%s", runtime.GOOS, runtime.GOARCH))
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	t.Cleanup(func() { _ = env.Stop() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	opts := env.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: clientgoscheme.Scheme,
		WebhookServer: webhook.NewServer(webhook.Options{
			Host: opts.LocalServingHost, Port: opts.LocalServingPort, CertDir: opts.LocalServingCertDir,
		}),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		Cache: cache.Options{ByObject: map[client.Object]cache.ByObject{
			&corev1.ConfigMap{}: {
				Namespaces: map[string]cache.Config{target.Namespace: {}},
				Field:      fields.OneTermEqualSelector("metadata.name", target.Name),
			},
		}},
	})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	mgr.GetWebhookServer().Register(guardPath, &webhook.Admission{Handler: &authorizationwebhook.PodDeletionGuard{
		Reader:    mgr.GetClient(),
		Decoder:   admission.NewDecoder(mgr.GetScheme()),
		ConfigMap: target,
		NodeKey:   "node",
		UserKey:   "user",
	}})
	go func() { _ = mgr.Start(ctx) }()

	admin, err := client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	mustCreate(t, admin, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}})
	// Grant pod deletion through RBAC, as the guard only narrows granted rights.
	mustCreate(t, admin, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "guard-test-delete"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: delegatedGroup},
			{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: "system:serviceaccounts"},
		},
	})

	alice := impersonate(t, cfg, "alice", delegatedGroup)
	bob := impersonate(t, cfg, "bob", delegatedGroup)
	controller := impersonate(t, cfg, "system:serviceaccount:kube-system:replicaset-controller", "system:serviceaccounts")

	// Wait for the webhook server to serve: a guarded delete is denied once it answers.
	podOn(t, admin, "probe", "node-a")
	deadline := time.Now().Add(time.Minute)
	for {
		err := alice.Delete(ctx, pod("probe"))
		if err != nil && apierrors.IsForbidden(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard webhook did not start serving: last error %v", err)
		}
		time.Sleep(time.Second)
	}

	t.Run("ConfigMap missing: the guarded user is denied", func(t *testing.T) {
		podOn(t, admin, "missing-guarded", "node-a")
		expectDenied(t, alice.Delete(ctx, pod("missing-guarded")), "not found; denied (fail closed)")
	})
	t.Run("ConfigMap missing: controller and admin deletes still succeed", func(t *testing.T) {
		podOn(t, admin, "missing-controller", "node-a")
		podOn(t, admin, "missing-admin", "node-b")
		if err := controller.Delete(ctx, pod("missing-controller")); err != nil {
			t.Fatalf("controller delete: %v", err)
		}
		if err := admin.Delete(ctx, pod("missing-admin")); err != nil {
			t.Fatalf("admin delete: %v", err)
		}
	})

	mustCreate(t, admin, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: target.Namespace, Name: target.Name},
		Data:       map[string]string{"node": "node-a", "user": "alice"},
	})
	t.Run("target set: wrong node is denied", func(t *testing.T) {
		podOn(t, admin, "wrong-node", "node-b")
		expectEventuallyDenied(t, func() error { return alice.Delete(ctx, pod("wrong-node")) }, `not on the target node "node-a"`)
	})
	t.Run("target set: another delegated user is denied", func(t *testing.T) {
		podOn(t, admin, "other-user", "node-a")
		expectDenied(t, bob.Delete(ctx, pod("other-user")), "belongs to another user")
	})
	t.Run("target set: the target user on the target node is allowed", func(t *testing.T) {
		podOn(t, admin, "allowed", "node-a")
		if err := alice.Delete(ctx, pod("allowed")); err != nil {
			t.Fatalf("guarded delete on the target node: %v", err)
		}
	})
}

func impersonate(t *testing.T, cfg *rest.Config, user string, groups ...string) client.Client {
	t.Helper()
	c := rest.CopyConfig(cfg)
	c.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
	cl, err := client.New(c, client.Options{Scheme: clientgoscheme.Scheme})
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func pod(name string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name}}
}

func podOn(t *testing.T, c client.Client, name, node string) {
	t.Helper()
	p := pod(name)
	p.Spec = corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "c", Image: "busybox"}}}
	mustCreate(t, c, p)
}

func mustCreate(t *testing.T, c client.Client, obj client.Object) {
	t.Helper()
	if err := c.Create(context.Background(), obj); err != nil {
		t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

func expectDenied(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !apierrors.IsForbidden(err) {
		t.Fatalf("expected a Forbidden denial containing %q, got %v", want, err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("denial %q does not contain %q", err, want)
	}
}

// expectEventuallyDenied waits for the guard's cache to see a ConfigMap change.
func expectEventuallyDenied(t *testing.T, call func() error, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := call()
		if err != nil && apierrors.IsForbidden(err) && strings.Contains(err.Error(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected a denial containing %q, got %v", want, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

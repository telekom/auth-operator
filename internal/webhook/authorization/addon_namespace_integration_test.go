// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks_test

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var _ = Describe("Add-on namespace admission", func() {
	It("allows authorized non-bypass updates, keeps ownership immutable, and leaves deletion to the controller", func(ctx SpecContext) {
		live, err := client.New(envCfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "t-addon-metrics-", Labels: map[string]string{
			authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon,
			authorizationv1alpha1.LabelKeyAddon: "metrics",
		}}}
		Expect(live.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), ns) })

		user, err := envTestEnv.AddUser(envtest.User{Name: "addon-controller", Groups: []string{"addon-controllers"}}, envCfg)
		Expect(err).NotTo(HaveOccurred())
		userClient, err := client.New(user.Config(), client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
		role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{GenerateName: "addon-namespace-"}, Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get", "update", "delete"},
		}}}
		Expect(live.Create(ctx, role)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), role) })
		binding := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{GenerateName: "addon-namespace-"},
			RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
			Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: "addon-controller"}},
		}
		Expect(live.Create(ctx, binding)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), binding) })
		bd := &authorizationv1alpha1.BindDefinition{ObjectMeta: metav1.ObjectMeta{GenerateName: "addon-namespace-"}, Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName: "addon-namespace",
			Subjects:   binding.Subjects,
			RoleBindings: []authorizationv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{role.Name},
				NamespaceSelector: []metav1.LabelSelector{{MatchLabels: map[string]string{
					authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon,
				}}},
			}},
		}}
		Expect(live.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), bd) })

		validator := &webhooks.NamespaceValidator{Client: envClient, Reader: live, Decoder: crAdmission.NewDecoder(scheme.Scheme), DeletionProtection: true}
		mutator := &webhooks.NamespaceMutator{Client: envClient, Reader: live, Decoder: crAdmission.NewDecoder(scheme.Scheme)}
		mux := http.NewServeMux()
		mux.Handle("/validate", &crAdmission.Webhook{Handler: validator})
		mux.Handle("/mutate", &crAdmission.Webhook{Handler: mutator})
		server := httptest.NewTLSServer(mux)
		DeferCleanup(server.Close)
		url := server.URL + "/validate"
		fail := admissionregistrationv1.Fail
		sideEffects := admissionregistrationv1.SideEffectClassNone
		hook := &admissionregistrationv1.ValidatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{GenerateName: "addon-namespace-"}, Webhooks: []admissionregistrationv1.ValidatingWebhook{{
			Name: "addon-namespace.test.telekom.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL: &url, CABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}),
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Delete},
				Rule:       admissionregistrationv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"namespaces"}},
			}},
			ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{corev1.LabelMetadataName: ns.Name}},
			FailurePolicy:  &fail, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
		}}}
		Expect(live.Create(ctx, hook)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), hook) })
		mutationURL := server.URL + "/mutate"
		mutationHook := &admissionregistrationv1.MutatingWebhookConfiguration{ObjectMeta: metav1.ObjectMeta{GenerateName: "addon-namespace-"}, Webhooks: []admissionregistrationv1.MutatingWebhook{{
			Name: "addon-namespace-mutation.test.telekom.com",
			ClientConfig: admissionregistrationv1.WebhookClientConfig{
				URL: &mutationURL, CABundle: hook.Webhooks[0].ClientConfig.CABundle,
			},
			Rules: []admissionregistrationv1.RuleWithOperations{{
				Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Update},
				Rule:       hook.Webhooks[0].Rules[0].Rule,
			}},
			ObjectSelector: hook.Webhooks[0].ObjectSelector,
			FailurePolicy:  &fail, SideEffects: &sideEffects, AdmissionReviewVersions: []string{"v1"},
		}}}
		Expect(live.Create(ctx, mutationHook)).To(Succeed())
		DeferCleanup(func() { _ = live.Delete(context.Background(), mutationHook) })

		// Wait for API-server webhook registration and RBAC propagation by
		// observing a real denial, not merely a successful update.
		Eventually(func() error {
			current := &corev1.Namespace{}
			if getErr := userClient.Get(ctx, client.ObjectKeyFromObject(ns), current); getErr != nil {
				return getErr
			}
			current.Labels[authorizationv1alpha1.LabelKeyAddon] = "logging"
			updateErr := userClient.Update(ctx, current, client.DryRunAll)
			if updateErr == nil {
				return nil
			}
			if apierrors.IsForbidden(updateErr) {
				return updateErr
			}
			return nil
		}).WithTimeout(10 * time.Second).Should(MatchError(ContainSubstring("admission webhook")))

		current := &corev1.Namespace{}
		Expect(userClient.Get(ctx, client.ObjectKeyFromObject(ns), current)).To(Succeed())
		current.Annotations = map[string]string{"test.telekom.com/updated": "true"}
		Expect(userClient.Update(ctx, current)).To(Succeed())
		persisted := &corev1.Namespace{}
		Expect(live.Get(ctx, client.ObjectKeyFromObject(ns), persisted)).To(Succeed())
		Expect(persisted.Annotations).To(HaveKeyWithValue("test.telekom.com/updated", "true"))

		By("requiring a matching selector for ordinary user updates")
		bd.Spec.RoleBindings[0].NamespaceSelector[0].MatchLabels[authorizationv1alpha1.LabelKeyOwner] = authorizationv1alpha1.OwnerTenant
		Expect(live.Update(ctx, bd)).To(Succeed())
		Expect(apierrors.IsForbidden(userClient.Update(ctx, persisted.DeepCopy()))).To(BeTrue())
		bd.Spec.RoleBindings[0].NamespaceSelector[0].MatchLabels[authorizationv1alpha1.LabelKeyOwner] = authorizationv1alpha1.OwnerAddon
		Expect(live.Update(ctx, bd)).To(Succeed())

		for _, selector := range []map[string]string{
			{authorizationv1alpha1.LabelKeyOwner: authorizationv1alpha1.OwnerAddon},
			{authorizationv1alpha1.LabelKeyAddon: "metrics"},
		} {
			By("checking immutability with selector " + metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: selector}))
			bd.Spec.RoleBindings[0].NamespaceSelector[0].MatchLabels = selector
			Expect(live.Update(ctx, bd)).To(Succeed())
			Expect(userClient.Update(ctx, persisted)).To(Succeed())
			for _, key := range []string{authorizationv1alpha1.LabelKeyOwner, authorizationv1alpha1.LabelKeyAddon} {
				By("denying changes and removal of " + key)
				changed := persisted.DeepCopy()
				changed.Labels[key] = "other"
				Expect(apierrors.IsForbidden(userClient.Update(ctx, changed))).To(BeTrue())
				removed := persisted.DeepCopy()
				delete(removed.Labels, key)
				Expect(apierrors.IsForbidden(userClient.Update(ctx, removed))).To(BeTrue())
			}
		}
		for _, key := range []string{authorizationv1alpha1.LabelKeyTenant, authorizationv1alpha1.LabelKeyThirdParty} {
			By("denying conflicting " + key)
			conflicting := persisted.DeepCopy()
			conflicting.Labels[key] = "team"
			Expect(apierrors.IsForbidden(userClient.Update(ctx, conflicting))).To(BeTrue())
		}

		By("retaining explicit deletion protection opt-in for add-on namespaces")
		protected := persisted.DeepCopy()
		protected.Labels[authorizationv1alpha1.LabelKeyDeletionProtection] = authorizationv1alpha1.DeletionProtectionEnabled
		Expect(userClient.Update(ctx, protected)).To(Succeed())
		Expect(apierrors.IsForbidden(userClient.Delete(ctx, protected))).To(BeTrue())
		protected.Annotations[authorizationv1alpha1.AnnotationKeyAllowDeletion] = authorizationv1alpha1.AllowDeletionTrue
		Expect(userClient.Update(ctx, protected)).To(Succeed())
		// Unlock protection in a separate request before clearing the escape hatch.
		delete(protected.Labels, authorizationv1alpha1.LabelKeyDeletionProtection)
		Expect(userClient.Update(ctx, protected)).To(Succeed())
		delete(protected.Annotations, authorizationv1alpha1.AnnotationKeyAllowDeletion)
		Expect(userClient.Update(ctx, protected)).To(Succeed())
		Expect(userClient.Delete(ctx, protected)).To(Succeed())
	})
})

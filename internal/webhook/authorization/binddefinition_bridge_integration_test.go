// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks_test

import (
	"context"
	"io"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	authz "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	webhooks "github.com/telekom/auth-operator/internal/webhook/authorization"
)

var _ = Describe("BindDefinition authorization bridge", func() {
	It("authorizes a live selector-backed binding before any RoleBinding exists and stops on label change", func(ctx SpecContext) {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "bridge-", Labels: map[string]string{authz.LabelKeyTenant: "team-a"}}}
		Expect(envClient.Create(ctx, ns)).To(Succeed())
		DeferCleanup(func() { _ = envClient.Delete(context.Background(), ns) })
		role := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{GenerateName: "bridge-reader-"}, Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"},
		}}}
		Expect(envClient.Create(ctx, role)).To(Succeed())
		DeferCleanup(func() { _ = envClient.Delete(context.Background(), role) })
		local := &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "bridge-local", Namespace: ns.Name}, Rules: []rbacv1.PolicyRule{{
			Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"configmaps"},
		}}}
		Expect(envClient.Create(ctx, local)).To(Succeed())
		DeferCleanup(func() { _ = envClient.Delete(context.Background(), local) })
		bd := &authz.BindDefinition{ObjectMeta: metav1.ObjectMeta{GenerateName: "bridge-"}, Spec: authz.BindDefinitionSpec{
			TargetName: "bridge",
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "bridge-user"}},
			RoleBindings: []authz.NamespaceBinding{{
				AuthorizeBeforeBinding: true,
				NamespaceSelector:      []metav1.LabelSelector{{MatchLabels: map[string]string{authz.LabelKeyTenant: "team-a"}}},
				ClusterRoleRefs:        []string{role.Name},
				RoleRefs:               []string{local.Name},
			}},
		}}
		Expect(envClient.Create(ctx, bd)).To(Succeed())
		DeferCleanup(func() { _ = envClient.Delete(context.Background(), bd) })

		live, err := client.New(envCfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
		discoveryClient, err := discovery.NewDiscoveryClientForConfig(envCfg)
		Expect(err).NotTo(HaveOccurred())
		authorizer := &webhooks.Authorizer{Client: envClient, LiveReader: live, Discovery: discoveryClient, Log: zap.New(zap.WriteTo(io.Discard)), AllowUnauthenticatedAuthorize: true}
		sar := authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
			User: "bridge-user", ResourceAttributes: &authzv1.ResourceAttributes{
				Namespace: ns.Name, Verb: "get", Resource: "pods",
			},
		}}
		var bindings rbacv1.RoleBindingList
		Expect(live.List(ctx, &bindings, client.InNamespace(ns.Name))).To(Succeed())
		Expect(bindings.Items).To(BeEmpty())
		Eventually(func() bool { return sendSAR(authorizer, sar).Status.Allowed }).
			WithTimeout(10 * time.Second).Should(BeTrue())
		sar.Spec.ResourceAttributes.Resource = "configmaps"
		Expect(sendSAR(authorizer, sar).Status.Allowed).To(BeTrue())
		Expect(live.List(ctx, &bindings, client.InNamespace(ns.Name))).To(Succeed())
		Expect(bindings.Items).To(BeEmpty())

		current := &corev1.Namespace{}
		Expect(live.Get(ctx, client.ObjectKeyFromObject(ns), current)).To(Succeed())
		current.Labels[authz.LabelKeyTenant] = "team-b"
		Expect(live.Update(ctx, current)).To(Succeed())
		Eventually(func() bool {
			status := sendSAR(authorizer, sar).Status
			return !status.Allowed && !status.Denied
		}).WithTimeout(10 * time.Second).Should(BeTrue())
	})
})

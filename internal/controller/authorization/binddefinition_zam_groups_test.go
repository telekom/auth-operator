// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
)

// ZAM role groups ("dttcaas-" + {tenant}_{scope}_{privilege}, LDAP CN at most
// 64 characters, [A-Za-z0-9_.-]) reach the apiserver as OIDC group strings,
// optionally behind --oidc-groups-prefix. The rendered ClusterRoleBinding must
// carry them byte for byte: a case or separator change would bind a different
// group, and case variants must stay distinct subjects.
func TestBindDefinitionRendersZAMGroupSubjectsUnchanged(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()
	scheme := runtime.NewScheme()
	g.Expect(authorizationv1alpha1.AddToScheme(scheme)).To(Succeed())
	g.Expect(rbacv1.AddToScheme(scheme)).To(Succeed())

	groups := []string{
		"dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted",      // longest (64)
		"oidc:dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted", // prefixed (69)
		"dttcaas-zam-tenant.123_tcaas-mgmt-nord-1.prd.b_reader-restricted",      // case variant
		"dttcaas-multi-idp-tenant_bm4x-fra-1_poweruser",
		"dttcaas-first-line_fixed-core",
	}
	subjects := make([]rbacv1.Subject, 0, len(groups))
	for _, group := range groups {
		subjects = append(subjects, rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: group})
	}
	bindDef := &authorizationv1alpha1.BindDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "zam-groups", UID: "test-uid-zam-groups"},
		Spec: authorizationv1alpha1.BindDefinitionSpec{
			TargetName:          "zam-groups",
			Subjects:            subjects,
			ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(bindDef).Build()
	r := &BindDefinitionReconciler{client: c, scheme: scheme, recorder: events.NewFakeRecorder(10)}

	g.Expect(r.ensureClusterRoleBindings(ctx, bindDef)).To(Succeed())

	crb := &rbacv1.ClusterRoleBinding{}
	g.Expect(c.Get(ctx, types.NamespacedName{Name: "zam-groups-view-binding"}, crb)).To(Succeed())
	// The controller sorts subjects; the names themselves must be unchanged.
	g.Expect(crb.Subjects).To(ConsistOf(subjects))
}

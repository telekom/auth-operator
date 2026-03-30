// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	"github.com/onsi/gomega"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/policy"
)

func helperCtx() context.Context {
	return ctrllog.IntoContext(context.Background(), logr.Discard())
}

func TestOwnerRefForRestricted(t *testing.T) {
	g := gomega.NewWithT(t)

	obj := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rbd",
			UID:  types.UID("uid-abc"),
		},
	}

	ref := ownerRefForRestricted(obj, "RestrictedBindDefinition")
	g.Expect(ref).NotTo(gomega.BeNil())
	g.Expect(*ref.Name).To(gomega.Equal("test-rbd"))
	g.Expect(*ref.UID).To(gomega.Equal(types.UID("uid-abc")))
	g.Expect(*ref.Kind).To(gomega.Equal("RestrictedBindDefinition"))
	g.Expect(*ref.APIVersion).To(gomega.Equal("authorization.t-caas.telekom.com/v1alpha1"))
	g.Expect(*ref.Controller).To(gomega.BeTrue())
	g.Expect(*ref.BlockOwnerDeletion).To(gomega.BeTrue())
}

func TestOwnerRefForRestricted_DifferentKind(t *testing.T) {
	g := gomega.NewWithT(t)

	obj := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
			UID:  types.UID("uid-def"),
		},
	}

	ref := ownerRefForRestricted(obj, "RestrictedRoleDefinition")
	g.Expect(*ref.Kind).To(gomega.Equal("RestrictedRoleDefinition"))
	g.Expect(*ref.Name).To(gomega.Equal("test-rrd"))
}

func TestHandlePolicyViolations_Success(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "test-rbd", Generation: 2},
	}

	deprovisionCalled := false
	reconciledValue := true
	statusApplied := false

	violations := []policy.Violation{
		{Field: "spec.subjects", Message: "too many subjects"},
	}

	recorder := events.NewFakeRecorder(10)
	result, err := handlePolicyViolations(helperCtx(), rbd, rbd.Generation, violations,
		recorder, rbd, ViolationHandlerConfig{
			ControllerLabel: metrics.ControllerRestrictedBindDefinition,
			ResourceKind:    "RestrictedBindDefinition",
			Deprovision:     func(ctx context.Context) error { deprovisionCalled = true; return nil },
			MarkStalled:     func(ctx context.Context, err error) {},
			SetReconciled:   func(v bool) { reconciledValue = v },
			ApplyStatus:     func(ctx context.Context) error { statusApplied = true; return nil },
		})

	g.Expect(err).NotTo(gomega.HaveOccurred())
	g.Expect(result.RequeueAfter).To(gomega.Equal(DefaultRequeueInterval))
	g.Expect(deprovisionCalled).To(gomega.BeTrue())
	g.Expect(reconciledValue).To(gomega.BeFalse())
	g.Expect(statusApplied).To(gomega.BeTrue())

	// Verify conditions were set.
	condPolicyCompliant := conditions.Get(rbd, authorizationv1alpha1.PolicyCompliantCondition)
	g.Expect(condPolicyCompliant).NotTo(gomega.BeNil())
	g.Expect(condPolicyCompliant.Status).To(gomega.Equal(metav1.ConditionFalse))

	condReady := conditions.Get(rbd, conditions.ReadyConditionType)
	g.Expect(condReady).NotTo(gomega.BeNil())
	g.Expect(condReady.Status).To(gomega.Equal(metav1.ConditionFalse))
	g.Expect(condReady.Reason).To(gomega.Equal(string(authorizationv1alpha1.DeprovisionedReason)))
}

func TestHandlePolicyViolations_DeprovisionError(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "dep-err-rbd", Generation: 1},
	}

	stalledCalled := false
	violations := []policy.Violation{
		{Field: "spec.subjects", Message: "invalid"},
	}

	recorder := events.NewFakeRecorder(10)
	_, err := handlePolicyViolations(helperCtx(), rbd, rbd.Generation, violations,
		recorder, rbd, ViolationHandlerConfig{
			ControllerLabel: metrics.ControllerRestrictedBindDefinition,
			ResourceKind:    "RestrictedBindDefinition",
			Deprovision:     func(ctx context.Context) error { return errors.New("deprovision failed") },
			MarkStalled:     func(ctx context.Context, err error) { stalledCalled = true },
			SetReconciled:   func(v bool) {},
			ApplyStatus:     func(ctx context.Context) error { return nil },
		})

	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("deprovision"))
	g.Expect(stalledCalled).To(gomega.BeTrue())
}

func TestMarkPolicyCompliant(t *testing.T) {
	g := gomega.NewWithT(t)

	rbd := &authorizationv1alpha1.RestrictedBindDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: "compliant-rbd", Generation: 3},
	}

	recorder := events.NewFakeRecorder(10)
	markPolicyCompliant(rbd, rbd.Generation, recorder, rbd, "test-policy", metrics.ControllerRestrictedBindDefinition)

	cond := conditions.Get(rbd, authorizationv1alpha1.PolicyCompliantCondition)
	g.Expect(cond).NotTo(gomega.BeNil())
	g.Expect(cond.Status).To(gomega.Equal(metav1.ConditionTrue))
	g.Expect(cond.Reason).To(gomega.Equal(string(authorizationv1alpha1.PolicyCompliantReasonAllChecksPass)))
}

func TestIsOwnedByRestrictedBindDefinition(t *testing.T) {
	tests := []struct {
		name   string
		refs   []metav1.OwnerReference
		expect bool
	}{
		{
			name:   "nil refs",
			refs:   nil,
			expect: false,
		},
		{
			name:   "empty refs",
			refs:   []metav1.OwnerReference{},
			expect: false,
		},
		{
			name: "owned by BindDefinition",
			refs: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "bd1"},
			},
			expect: false,
		},
		{
			name: "owned by RestrictedBindDefinition",
			refs: []metav1.OwnerReference{
				{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "RestrictedBindDefinition", Name: "rbd1"},
			},
			expect: true,
		},
		{
			name: "wrong API version",
			refs: []metav1.OwnerReference{
				{APIVersion: "apps/v1", Kind: "RestrictedBindDefinition", Name: "rbd1"},
			},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			g.Expect(isOwnedByRestrictedBindDefinition(tt.refs)).To(gomega.Equal(tt.expect))
		})
	}
}

func newFakeClient(objs ...client.Object) client.Client {
	return fake.NewClientBuilder().
		WithScheme(newTestScheme()).
		WithObjects(objs...).
		Build()
}

func TestCheckRestrictedRoleOwnership_Conflict(t *testing.T) {
	g := gomega.NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
			UID:  "rrd-uid-111",
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "conflicting-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	controller := true
	existingRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "conflicting-role",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
					Name:       "other-owner",
					UID:        "other-uid-999",
					Controller: &controller,
				},
			},
		},
	}

	c := newFakeClient(existingRole)
	recorder := events.NewFakeRecorder(10)
	err := checkRestrictedRoleOwnership(helperCtx(), c, recorder, rrd,
		rrd.Spec.TargetRole, rrd.Spec.TargetName, "")
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already controlled by"))
	g.Expect(err.Error()).To(gomega.ContainSubstring("other-owner"))
}

func TestCheckRestrictedRoleOwnership_NoConflict(t *testing.T) {
	g := gomega.NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
			UID:  "rrd-uid-111",
		},
		Spec: authorizationv1alpha1.RestrictedRoleDefinitionSpec{
			TargetName: "my-role",
			TargetRole: authorizationv1alpha1.DefinitionClusterRole,
		},
	}

	controller := true
	existingRole := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "my-role",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RestrictedRoleDefinition",
					Name:       "test-rrd",
					UID:        "rrd-uid-111",
					Controller: &controller,
				},
			},
		},
	}

	c := newFakeClient(existingRole)
	recorder := events.NewFakeRecorder(10)
	err := checkRestrictedRoleOwnership(helperCtx(), c, recorder, rrd,
		rrd.Spec.TargetRole, rrd.Spec.TargetName, "")
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCheckRestrictedRoleOwnership_NotFound(t *testing.T) {
	g := gomega.NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
			UID:  "rrd-uid-111",
		},
	}

	c := newFakeClient() // no existing roles
	recorder := events.NewFakeRecorder(10)
	err := checkRestrictedRoleOwnership(helperCtx(), c, recorder, rrd,
		authorizationv1alpha1.DefinitionClusterRole, "nonexistent-role", "")
	g.Expect(err).NotTo(gomega.HaveOccurred())
}

func TestCheckRestrictedRoleOwnership_NamespacedRole(t *testing.T) {
	g := gomega.NewWithT(t)

	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rrd",
			UID:  "rrd-uid-111",
		},
	}

	controller := true
	existingRole := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ns-role",
			Namespace: "test-ns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       "RoleDefinition",
					Name:       "other-rd",
					UID:        "other-uid",
					Controller: &controller,
				},
			},
		},
	}

	c := newFakeClient(existingRole)
	recorder := events.NewFakeRecorder(10)
	err := checkRestrictedRoleOwnership(helperCtx(), c, recorder, rrd,
		authorizationv1alpha1.DefinitionNamespacedRole, "ns-role", "test-ns")
	g.Expect(err).To(gomega.HaveOccurred())
	g.Expect(err.Error()).To(gomega.ContainSubstring("already controlled by"))
}

package authorization

import (
	"context"
	"errors"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	corev1ac "k8s.io/client-go/applyconfigurations/core/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

func TestBuildBindingName(t *testing.T) {
	tests := []struct {
		targetName string
		roleRef    string
		want       string
	}{
		{"platform-admin", "cluster-admin", "platform-admin-cluster-admin-binding"},
		{"tenant-user", "view", "tenant-user-view-binding"},
		{"my-service", "edit", "my-service-edit-binding"},
	}

	for _, tt := range tests {
		t.Run(tt.targetName+"-"+tt.roleRef, func(t *testing.T) {
			got := helpers.BuildBindingName(tt.targetName, tt.roleRef)
			if got != tt.want {
				t.Errorf("helpers.BuildBindingName(%q, %q) = %q, want %q",
					tt.targetName, tt.roleRef, got, tt.want)
			}
		})
	}
}

func TestServiceAccountSSAConflictDetails(t *testing.T) {
	t.Parallel()

	t.Run("extracts managers from label-only conflicts", func(t *testing.T) {
		t.Parallel()
		err := &apierrors.StatusError{ErrStatus: metav1.Status{
			Reason: metav1.StatusReasonConflict,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.app.kubernetes.io/managed-by", Message: `conflicts with "helm-controller" using v1`},
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.helm.toolkit.fluxcd.io/name", Message: `conflicts with "helm-controller" using v1`},
			}},
		}}

		managers, labelOnly := serviceAccountSSAConflictDetails(err)
		if !labelOnly {
			t.Fatal("expected label-only conflict")
		}
		if len(managers) != 1 || managers[0] != "helm-controller" {
			t.Fatalf("unexpected managers: %v", managers)
		}
	})

	t.Run("rejects non-label conflicts", func(t *testing.T) {
		t.Parallel()
		err := &apierrors.StatusError{ErrStatus: metav1.Status{
			Reason: metav1.StatusReasonConflict,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".automountServiceAccountToken", Message: `conflict with "workload-controller"`},
			}},
		}}

		if managers, labelOnly := serviceAccountSSAConflictDetails(err); labelOnly || managers != nil {
			t.Fatalf("non-label conflict must remain fatal, got managers=%v labelOnly=%v", managers, labelOnly)
		}
	})

	t.Run("rejects mixed label and non-label conflicts", func(t *testing.T) {
		t.Parallel()
		err := &apierrors.StatusError{ErrStatus: metav1.Status{
			Reason: metav1.StatusReasonConflict,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.app.kubernetes.io/managed-by", Message: `conflict with "helm-controller"`},
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".automountServiceAccountToken", Message: `conflict with "workload-controller"`},
			}},
		}}

		if managers, labelOnly := serviceAccountSSAConflictDetails(err); labelOnly || managers != nil {
			t.Fatalf("mixed conflicts must remain fatal, got managers=%v labelOnly=%v", managers, labelOnly)
		}
	})

	t.Run("sorts multiple managers", func(t *testing.T) {
		t.Parallel()
		err := &apierrors.StatusError{ErrStatus: metav1.Status{
			Reason: metav1.StatusReasonConflict,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.first", Message: `conflict with "z-controller"`},
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.second", Message: `conflict with "a-controller"`},
			}},
		}}

		managers, labelOnly := serviceAccountSSAConflictDetails(err)
		if !labelOnly || len(managers) != 2 || managers[0] != "a-controller" || managers[1] != "z-controller" {
			t.Fatalf("unexpected details: managers=%v labelOnly=%v", managers, labelOnly)
		}
	})

	t.Run("reports unknown when the API omits a manager", func(t *testing.T) {
		t.Parallel()
		err := &apierrors.StatusError{ErrStatus: metav1.Status{
			Reason: metav1.StatusReasonConflict,
			Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{
				{Type: metav1.CauseType("FieldManagerConflict"), Field: ".metadata.labels.shared", Message: "field ownership conflict"},
			}},
		}}

		managers, labelOnly := serviceAccountSSAConflictDetails(err)
		if !labelOnly || len(managers) != 1 || managers[0] != "unknown" {
			t.Fatalf("unexpected details: managers=%v labelOnly=%v", managers, labelOnly)
		}
	})
}

//nolint:gocyclo // table-driven coverage exercises each ownership outcome.
func TestEnsureServiceAccountsReportsExternalFieldManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		conflictMessage string
		conflictField   string
		wantManager     string
		wantTransfer    bool
	}{
		{name: "named controller", conflictMessage: `conflict with "custom-release-controller"`, conflictField: ".metadata.labels.app.kubernetes.io/managed-by", wantManager: "custom-release-controller", wantTransfer: true},
		{name: "unknown controller", conflictMessage: "field ownership conflict", conflictField: ".metadata.labels.app.kubernetes.io/managed-by", wantManager: "unknown", wantTransfer: true},
		{name: "non-label conflict remains fatal", conflictMessage: `conflict with "workload-controller"`, conflictField: ".automountServiceAccountToken", wantManager: "workload-controller", wantTransfer: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			s := runtime.NewScheme()
			if err := authorizationv1alpha1.AddToScheme(s); err != nil {
				t.Fatal(err)
			}
			if err := corev1.AddToScheme(s); err != nil {
				t.Fatal(err)
			}

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "controller-reporting-bd", UID: "controller-reporting-uid"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					Subjects: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "shared-sa", Namespace: "workload"}},
				},
				Status: authorizationv1alpha1.BindDefinitionStatus{
					GeneratedServiceAccounts: []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "shared-sa", Namespace: "workload"}},
				},
			}
			peerBindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "peer-bd", UID: "peer-bd-uid"},
			}
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name: "shared-sa", Namespace: "workload",
				Labels:      map[string]string{helpers.ManagedByLabelStandard: "external"},
				Annotations: helpers.BuildManagedSAAnnotations(helpers.MergeSourceNames(bindDef.Name, peerBindDef.Name)),
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: authorizationv1alpha1.BindDefinitionKind,
					Name: bindDef.Name, UID: bindDef.UID,
				}, {
					APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: authorizationv1alpha1.BindDefinitionKind,
					Name: peerBindDef.Name, UID: peerBindDef.UID,
				}},
			}}
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "workload"}, Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
			conflict := &apierrors.StatusError{ErrStatus: metav1.Status{
				Reason: metav1.StatusReasonConflict,
				Details: &metav1.StatusDetails{Causes: []metav1.StatusCause{{
					Type: metav1.CauseType("FieldManagerConflict"), Field: tt.conflictField, Message: tt.conflictMessage,
				}}},
			}}

			c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa, ns).
				WithInterceptorFuncs(interceptor.Funcs{
					Apply: func(_ context.Context, _ client.WithWatch, _ runtime.ApplyConfiguration, _ ...client.ApplyOption) error {
						return conflict
					},
				}).Build()
			recorder := events.NewFakeRecorder(10)
			r := &BindDefinitionReconciler{client: c, scheme: s, recorder: recorder}

			generated, external, err := r.ensureServiceAccounts(ctx, bindDef)
			if !tt.wantTransfer {
				if err == nil {
					t.Fatal("expected non-label SSA conflict to remain fatal")
				}
				updated := &corev1.ServiceAccount{}
				if getErr := c.Get(ctx, client.ObjectKey{Name: "shared-sa", Namespace: "workload"}, updated); getErr != nil {
					t.Fatal(getErr)
				}
				if !hasOwnerRef(updated, bindDef) {
					t.Fatal("fatal non-label conflict removed the BindDefinition owner reference")
				}
				if updated.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy] != "" {
					t.Fatalf("fatal non-label conflict reclassified the ServiceAccount: %v", updated.Annotations)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensureServiceAccounts returned error: %v", err)
			}
			if len(generated) != 0 || len(external) != 1 || external[0] != "workload/shared-sa" {
				t.Fatalf("unexpected classification: generated=%v external=%v", generated, external)
			}
			condition := conditions.Get(bindDef, authorizationv1alpha1.ServiceAccountOwnershipTransferredCondition)
			if condition == nil || !strings.Contains(condition.Message, tt.wantManager) {
				t.Fatalf("manager %q not reported in condition: %#v", tt.wantManager, condition)
			}
			event := <-recorder.Events
			if !strings.Contains(event, corev1.EventTypeWarning) ||
				!strings.Contains(event, authorizationv1alpha1.EventReasonServiceAccountOwnershipTransferred) ||
				!strings.Contains(event, tt.wantManager) {
				t.Fatalf("manager takeover not reported in warning event: %q", event)
			}

			updated := &corev1.ServiceAccount{}
			if err := c.Get(ctx, client.ObjectKey{Name: "shared-sa", Namespace: "workload"}, updated); err != nil {
				t.Fatal(err)
			}
			if hasOwnerRef(updated, bindDef) {
				t.Fatal("BindDefinition owner reference was not removed")
			}
			if !hasOwnerRef(updated, peerBindDef) {
				t.Fatal("peer BindDefinition owner reference was not preserved")
			}
			if updated.Annotations[helpers.SourceNamesAnnotation] != peerBindDef.Name {
				t.Fatalf("peer source name was not preserved: %v", updated.Annotations)
			}
			if updated.Annotations[authorizationv1alpha1.AnnotationKeyReferencedBy] != bindDef.Name {
				t.Fatalf("external reference not recorded: %v", updated.Annotations)
			}
			if updated.Annotations[authorizationv1alpha1.AnnotationKeyExternalFieldManagers] != tt.wantManager {
				t.Fatalf("external field manager not recorded: %v", updated.Annotations)
			}

			bindDef.Spec.Subjects = nil
			if _, _, err := r.ensureServiceAccounts(ctx, bindDef); err != nil {
				t.Fatalf("ensureServiceAccounts after subject removal returned error: %v", err)
			}
			if condition := conditions.Get(bindDef, authorizationv1alpha1.ServiceAccountOwnershipTransferredCondition); condition != nil {
				t.Fatalf("stale takeover condition was not cleared: %#v", condition)
			}
		})
	}
}

// TestLogStatusApplyError tests that logStatusApplyError handles nil and non-nil errors
func TestLogStatusApplyError(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		err      error
		resource string
	}{
		{
			name:     "nil error does nothing",
			err:      nil,
			resource: "test-resource",
		},
		{
			name:     "non-nil error logs without panicking",
			err:      errors.New("status apply failed"),
			resource: "test-resource",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic regardless of error value
			logStatusApplyError(ctx, tt.err, tt.resource)
		})
	}
}

var _ = Describe("BindDefinition Helpers", func() {
	ctx := context.Background()

	Describe("deleteServiceAccount", func() {
		It("should return deleteResultNotFound when ServiceAccount does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "nonexistent-sa", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when ServiceAccount has no controller reference", func() {
			// Create ServiceAccount without owner reference
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-no-owner",
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-no-owner",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-no-owner", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultDeleted when ServiceAccount is successfully deleted", func() {
			// Create BindDefinition first
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-delete",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx,
				client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create ServiceAccount with owner reference
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-delete",
					Namespace: "default",
				},
			}
			Expect(controllerutil.SetControllerReference(bindDef, sa, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-delete", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("deleteClusterRoleBinding", func() {
		It("should return deleteResultNotFound when ClusterRoleBinding does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-crb-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-crb",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "nonexistent-role")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when ClusterRoleBinding has no controller reference", func() {
			// Create ClusterRoleBinding without owner reference
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-crb-no-owner-test-role-binding",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "ClusterRole",
					Name:     "view",
				},
			}
			Expect(k8sClient.Create(ctx, crb)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-crb-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-crb-no-owner",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "test-role")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, crb)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("deleteRoleBinding", func() {
		It("should return deleteResultNotFound when RoleBinding does not exist", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-notfound",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-rb",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "nonexistent-role", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNotFound))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultNoOwnerRef when RoleBinding has no controller reference", func() {
			// Create RoleBinding without owner reference
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rb-no-owner-view-binding",
					Namespace: "default",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "view",
				},
			}
			Expect(k8sClient.Create(ctx, rb)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-noowner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-rb-no-owner",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "view", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			Expect(k8sClient.Delete(ctx, rb)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should return deleteResultDeleted when RoleBinding is successfully deleted", func() {
			// Create BindDefinition first
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-rb-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-rb-delete",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx,
				client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create RoleBinding with owner reference
			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-rb-delete-view-binding",
					Namespace: "default",
				},
				RoleRef: rbacv1.RoleRef{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Role",
					Name:     "view",
				},
			}
			Expect(controllerutil.SetControllerReference(bindDef, rb, k8sClient.Scheme())).To(Succeed())
			Expect(k8sClient.Create(ctx, rb)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			result, err := reconciler.deleteRoleBinding(ctx, bindDef, "view", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("ensureServiceAccounts", func() {
		It("should leave an opted-out existing ServiceAccount external and detach only this BindDefinition metadata", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-binddef-sa-opted-out", Namespace: "default"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-opted-out",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "test-sa-opted-out", Namespace: "default"}},
					ExternalServiceAccountRefs: []authorizationv1alpha1.SARef{{
						Name: "test-sa-opted-out", Namespace: "default",
					}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			controller := false
			sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{
				Name:      "test-sa-opted-out",
				Namespace: "default",
				Labels: map[string]string{
					"app.kubernetes.io/managed-by": "Helm",
					"helm.toolkit.fluxcd.io/name":  "auth-custom-resources",
				},
				Annotations: map[string]string{
					helpers.SourceKindAnnotation:  authorizationv1alpha1.BindDefinitionKind,
					helpers.SourceNamesAnnotation: bindDef.Name,
				},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: authorizationv1alpha1.GroupVersion.String(),
					Kind:       authorizationv1alpha1.BindDefinitionKind,
					Name:       bindDef.Name,
					UID:        bindDef.UID,
					Controller: &controller,
				}},
			}}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			reconciler := &BindDefinitionReconciler{client: k8sClient, scheme: k8sClient.Scheme(), recorder: recorder}
			generated, external, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())
			Expect(generated).To(BeEmpty())
			Expect(external).To(ConsistOf("default/test-sa-opted-out"))
			Expect(bindDef.Status.SkippedServiceAccounts).To(BeEmpty())

			updated := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(sa), updated)).To(Succeed())
			Expect(updated.Labels).To(Equal(sa.Labels))
			Expect(updated.OwnerReferences).To(BeEmpty())
			Expect(updated.Annotations).NotTo(HaveKey(helpers.SourceKindAnnotation))
			Expect(updated.Annotations).NotTo(HaveKey(helpers.SourceNamesAnnotation))
			Expect(updated.Annotations).NotTo(HaveKey(authorizationv1alpha1.AnnotationKeyReferencedBy))

			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should report a missing opted-out ServiceAccount without creating it", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-binddef-sa-opted-out-missing", Namespace: "default"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-opted-out-missing",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "test-sa-opted-out-missing", Namespace: "default"}},
					ExternalServiceAccountRefs: []authorizationv1alpha1.SARef{{
						Name: "test-sa-opted-out-missing", Namespace: "default",
					}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{client: k8sClient, scheme: k8sClient.Scheme(), recorder: recorder}
			generated, external, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())
			Expect(generated).To(BeEmpty())
			Expect(external).To(BeEmpty())
			Expect(bindDef.Status.SkippedServiceAccounts).To(ConsistOf("default/test-sa-opted-out-missing: not found (creation opted out)"))

			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-opted-out-missing", Namespace: "default"}, sa)).NotTo(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should create ServiceAccount with automountServiceAccountToken=true when field is nil (backward compatibility)", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-nil-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-nil-automount",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects: []rbacv1.Subject{
						{
							Kind:      rbacv1.ServiceAccountKind,
							Name:      "test-sa-nil-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: nil, // Explicitly nil - should default to true
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, _, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=true (backward compatibility)
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-nil-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should create ServiceAccount with automountServiceAccountToken=true when explicitly set", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-true-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-true-automount",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-true-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(true),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, _, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=true
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-true-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should create ServiceAccount with automountServiceAccountToken=false when explicitly set", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-false-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-false-automount",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-false-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(false),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			_, _, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was created with automountServiceAccountToken=false
			sa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-false-automount", Namespace: "default"}, sa)).To(Succeed())
			Expect(sa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*sa.AutomountServiceAccountToken).To(BeFalse())

			// Cleanup
			Expect(k8sClient.Delete(ctx, sa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("ensureServiceAccounts update scenarios", func() {
		It("keeps a Helm-owned ServiceAccount and reaches Ready after SSA label conflicts", func() {
			const (
				namespaceName        = "sa-ssa-coexistence-test"
				serviceAccountName   = "kustomize-controller"
				bindDefinitionName   = "platform-serviceaccounts-ssa-coexistence"
				clusterRoleName      = "sa-ssa-coexistence-role"
				helmReleaseNameLabel = "helm.toolkit.fluxcd.io/name"
			)
			key := client.ObjectKey{Name: serviceAccountName, Namespace: namespaceName}

			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName}}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())
			clusterRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: clusterRoleName}}
			Expect(k8sClient.Create(ctx, clusterRole)).To(Succeed())

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:       bindDefinitionName,
					Finalizers: []string{authorizationv1alpha1.BindDefinitionFinalizer},
					Labels: map[string]string{
						helpers.ManagedByLabelStandard: "Helm",
						helmReleaseNameLabel:           "authn-authz-crs",
					},
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName: "platform-serviceaccounts",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{
						ClusterRoleRefs: []string{clusterRoleName},
					},
					Subjects: []rbacv1.Subject{{
						Kind: rbacv1.ServiceAccountKind, Name: serviceAccountName, Namespace: namespaceName,
					}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())
			bindDef.Status.GeneratedServiceAccounts = append([]rbacv1.Subject(nil), bindDef.Spec.Subjects...)
			Expect(k8sClient.Status().Update(ctx, bindDef)).To(Succeed())

			helmLabels := map[string]string{
				helpers.ManagedByLabelStandard: "Helm",
				helmReleaseNameLabel:           "flux",
			}
			helmSA := corev1ac.ServiceAccount(serviceAccountName, namespaceName).WithLabels(helmLabels)
			Expect(k8sClient.Apply(ctx, helmSA, client.FieldOwner("helm-controller"))).To(Succeed())

			// Reproduce the historical state: auth-operator recorded and owned the SA,
			// while Helm retained SSA ownership of its identifying labels.
			legacyAuthMetadata := corev1ac.ServiceAccount(serviceAccountName, namespaceName).
				WithOwnerReferences(saOwnerRefForBindDefinition(bindDef)).
				WithAnnotations(helpers.BuildManagedSAAnnotations(bindDef.Name))
			Expect(k8sClient.Apply(ctx, legacyAuthMetadata,
				client.FieldOwner(pkgssa.FieldOwnerFor(bindDef.Name, authorizationv1alpha1.BindDefinitionKind)))).To(Succeed())

			takeoverRecorder := events.NewFakeRecorder(20)
			reconciler := &BindDefinitionReconciler{
				client: k8sClient, scheme: k8sClient.Scheme(), recorder: takeoverRecorder,
			}
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: bindDef.Name},
			})
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				for {
					select {
					case event := <-takeoverRecorder.Events:
						if strings.Contains(event, authorizationv1alpha1.EventReasonServiceAccountOwnershipTransferred) &&
							strings.Contains(event, "helm-controller") {
							return true
						}
					default:
						return false
					}
				}
			}).Should(BeTrue(), "expected takeover warning event with helm-controller")

			updatedBindDef := &authorizationv1alpha1.BindDefinition{}
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), updatedBindDef)).To(Succeed())
			Expect(updatedBindDef.Status.BindReconciled).To(BeTrue())
			Expect(conditions.IsReady(updatedBindDef)).To(BeTrue())
			Expect(updatedBindDef.Status.GeneratedServiceAccounts).NotTo(BeNil())
			Expect(updatedBindDef.Status.GeneratedServiceAccounts).To(BeEmpty())
			Expect(updatedBindDef.Status.ExternalServiceAccounts).To(ConsistOf(namespaceName + "/" + serviceAccountName))
			takeoverCondition := conditions.Get(updatedBindDef, authorizationv1alpha1.ServiceAccountOwnershipTransferredCondition)
			Expect(takeoverCondition).NotTo(BeNil())
			Expect(takeoverCondition.Status).To(Equal(metav1.ConditionTrue))
			Expect(takeoverCondition.Reason).To(Equal(string(authorizationv1alpha1.ServiceAccountOwnershipTransferredReason)))
			Expect(takeoverCondition.Message).To(ContainSubstring(namespaceName + "/" + serviceAccountName))
			Expect(takeoverCondition.Message).To(ContainSubstring("helm-controller"))

			updatedSA := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, key, updatedSA)).To(Succeed())
			Expect(updatedSA.Labels).To(Equal(helmLabels))
			Expect(hasOwnerRef(updatedSA, bindDef)).To(BeFalse())
			Expect(updatedSA.Annotations).To(HaveKeyWithValue(
				authorizationv1alpha1.AnnotationKeyReferencedBy, bindDef.Name))
			Expect(updatedSA.Annotations).To(HaveKeyWithValue(
				authorizationv1alpha1.AnnotationKeyExternalFieldManagers, "helm-controller"))
			Expect(updatedSA.Annotations).NotTo(HaveKey(helpers.SourceNamesAnnotation))

			var helmManagedFields string
			for _, managedField := range updatedSA.ManagedFields {
				if managedField.Manager == "helm-controller" && managedField.FieldsV1 != nil {
					helmManagedFields = managedField.FieldsV1.GetRawString()
				}
			}
			Expect(helmManagedFields).To(ContainSubstring("f:app.kubernetes.io/managed-by"))
			Expect(helmManagedFields).To(ContainSubstring("f:helm.toolkit.fluxcd.io/name"))

			updatedBindDef.Finalizers = nil
			Expect(k8sClient.Update(ctx, updatedBindDef)).To(Succeed())
			Expect(k8sClient.Delete(ctx, updatedBindDef)).To(Succeed())
			Expect(k8sClient.Delete(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{
				Name: helpers.BuildBindingName(bindDef.Spec.TargetName, clusterRoleName),
			}})).To(Succeed())
			Expect(k8sClient.Delete(ctx, clusterRole)).To(Succeed())
			Expect(k8sClient.Delete(ctx, updatedSA)).To(Succeed())
			Expect(k8sClient.Delete(ctx, ns)).To(Succeed())
		})

		It("should update ServiceAccount automountServiceAccountToken when value changes from false to true", func() {
			// Create BindDefinition first with automountServiceAccountToken=false
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-update-automount",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-update-automount",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-update-automount",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(false),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			bindDef.Status.GeneratedServiceAccounts = []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: bindDef.Spec.Subjects[0].Name, Namespace: "default"},
			}
			Expect(k8sClient.Status().Update(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			saAC := pkgssa.ServiceAccountWith("test-sa-update-automount", "default",
				helpers.BuildResourceLabels(bindDef.Labels), false).
				WithOwnerReferences(saOwnerRefForBindDefinition(bindDef)).
				WithAnnotations(helpers.BuildManagedSAAnnotations(bindDef.Name))
			_, applyErr := pkgssa.PatchApplyServiceAccount(ctx, k8sClient, saAC, pkgssa.FieldOwnerFor(bindDef.Name, authorizationv1alpha1.BindDefinitionKind))
			Expect(applyErr).NotTo(HaveOccurred())

			// Update BindDefinition to set automountServiceAccountToken=true
			bindDef.Spec.AutomountServiceAccountToken = ptr.To(true)
			Expect(k8sClient.Update(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			// ensureServiceAccounts handles both create and update
			_, _, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was updated with automountServiceAccountToken=true
			updatedSa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-update-automount", Namespace: "default"}, updatedSa)).To(Succeed())
			Expect(updatedSa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*updatedSa.AutomountServiceAccountToken).To(BeTrue())

			// Cleanup
			Expect(k8sClient.Delete(ctx, updatedSa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})

		It("should update ServiceAccount automountServiceAccountToken when value changes from true to false", func() {
			// Create BindDefinition first with automountServiceAccountToken=true
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-binddef-sa-update-to-false",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-update-to-false",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects: []rbacv1.Subject{
						{
							Kind:      "ServiceAccount",
							Name:      "test-sa-update-to-false",
							Namespace: "default",
						},
					},
					AutomountServiceAccountToken: ptr.To(true),
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			bindDef.Status.GeneratedServiceAccounts = []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: bindDef.Spec.Subjects[0].Name, Namespace: "default"},
			}
			Expect(k8sClient.Status().Update(ctx, bindDef)).To(Succeed())

			// Fetch to get UID
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			// Create ServiceAccount with owner reference and automountServiceAccountToken=true
			saAC2 := pkgssa.ServiceAccountWith("test-sa-update-to-false", "default",
				helpers.BuildResourceLabels(bindDef.Labels), true).
				WithOwnerReferences(saOwnerRefForBindDefinition(bindDef)).
				WithAnnotations(helpers.BuildManagedSAAnnotations(bindDef.Name))
			_, err2 := pkgssa.PatchApplyServiceAccount(ctx, k8sClient, saAC2, pkgssa.FieldOwnerFor(bindDef.Name, authorizationv1alpha1.BindDefinitionKind))
			Expect(err2).NotTo(HaveOccurred())

			// Update BindDefinition to set automountServiceAccountToken=false
			bindDef.Spec.AutomountServiceAccountToken = ptr.To(false)
			Expect(k8sClient.Update(ctx, bindDef)).To(Succeed())

			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: recorder,
			}

			// ensureServiceAccounts handles both create and update
			_, _, err := reconciler.ensureServiceAccounts(ctx, bindDef)
			Expect(err).NotTo(HaveOccurred())

			// Verify ServiceAccount was updated with automountServiceAccountToken=false
			updatedSa := &corev1.ServiceAccount{}
			Expect(k8sClient.Get(ctx, client.ObjectKey{Name: "test-sa-update-to-false", Namespace: "default"}, updatedSa)).To(Succeed())
			Expect(updatedSa.AutomountServiceAccountToken).NotTo(BeNil())
			Expect(*updatedSa.AutomountServiceAccountToken).To(BeFalse())

			// Cleanup
			Expect(k8sClient.Delete(ctx, updatedSa)).To(Succeed())
			Expect(k8sClient.Delete(ctx, bindDef)).To(Succeed())
		})
	})

	Describe("bindDefinitionServiceAccountsForDeletion", func() {
		It("should never include explicitly external ServiceAccounts", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					Subjects: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "external-sa", Namespace: "external-ns"},
						{Kind: rbacv1.ServiceAccountKind, Name: "managed-sa", Namespace: "managed-ns"},
					},
					ExternalServiceAccountRefs: []authorizationv1alpha1.SARef{{Name: "external-sa", Namespace: "external-ns"}},
				},
				Status: authorizationv1alpha1.BindDefinitionStatus{
					GeneratedServiceAccounts: []rbacv1.Subject{
						{Kind: rbacv1.ServiceAccountKind, Name: "external-sa", Namespace: "external-ns"},
						{Kind: rbacv1.ServiceAccountKind, Name: "managed-sa", Namespace: "managed-ns"},
					},
				},
			}
			Expect(bindDefinitionServiceAccountsForDeletion(bindDef)).To(ConsistOf(
				rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "managed-sa", Namespace: "managed-ns"},
			))
		})
	})
})

func TestDeleteClusterRoleBinding(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned CRB successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-crb-bd", UID: "del-crb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-crb-target",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		crbName := helpers.BuildBindingName("del-crb-target", "admin")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-crb-bd", UID: "del-crb-uid", Controller: &isController},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, crb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "admin")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent CRB", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-crb-bd", UID: "nf-crb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "nonexistent")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns NoOwnerRef for unowned CRB", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-crb-bd", UID: "unowned-crb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-target"},
		}

		crbName := helpers.BuildBindingName("unowned-target", "admin")
		crb := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: crbName},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "admin"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, crb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteClusterRoleBinding(ctx, bindDef, "admin")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})
}

func TestDeleteRoleBinding(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned RoleBinding successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-rb-bd", UID: "del-rb-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-rb-target",
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "g", APIGroup: rbacv1.GroupName}},
			},
		}

		rbName := helpers.BuildBindingName("del-rb-target", "view")
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-rb-bd", UID: "del-rb-uid", Controller: &isController},
				},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, rb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent RoleBinding", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-rb-bd", UID: "nf-rb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-rb-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "gone-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns NoOwnerRef for unowned RoleBinding", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-rb-bd", UID: "unowned-rb-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-rb-target"},
		}

		rbName := helpers.BuildBindingName("unowned-rb-target", "view")
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: rbName, Namespace: "test-ns"},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "view"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, rb).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteRoleBinding(ctx, bindDef, "view", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})
}

func TestDeleteServiceAccountUnit(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	isController := true

	t.Run("deletes owned SA successfully", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "del-sa-bd", UID: "del-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "del-sa-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "my-sa", Namespace: "test-ns"}},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-sa",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "del-sa-bd", UID: "del-sa-uid", Controller: &isController},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "my-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("deletes SA with non-controller ownerRef", func(t *testing.T) {
		g := NewWithT(t)

		isNotController := false
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nc-sa-bd", UID: "nc-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "nc-sa-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "nc-sa", Namespace: "test-ns"}},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "nc-sa",
				Namespace: "test-ns",
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "nc-sa-bd", UID: "nc-sa-uid", Controller: &isNotController},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "nc-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultDeleted))
	})

	t.Run("returns NotFound for non-existent SA", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "nf-sa-bd", UID: "nf-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "nf-sa-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "gone-sa", "gone-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNotFound))
	})

	t.Run("returns deleteResultUnknown on Get error", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "err-bd", UID: "err-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "err-target"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, obj client.Object, _ ...client.GetOption) error {
					if _, ok := obj.(*corev1.ServiceAccount); ok {
						return errors.New("simulated API error")
					}
					return nil
				},
			}).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "any-sa", "any-ns")
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("simulated API error"))
		g.Expect(result).To(Equal(deleteResultUnknown))
	})

	t.Run("returns NoOwnerRef for unowned SA", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-sa-bd", UID: "unowned-sa-uid"},
			Spec:       authorizationv1alpha1.BindDefinitionSpec{TargetName: "unowned-sa-target"},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "unowned-sa", Namespace: "test-ns"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "unowned-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))
	})

	t.Run("skips SA referenced by other BindDefinitions", func(t *testing.T) {
		g := NewWithT(t)

		isNotController := false
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "shared-sa-bd", UID: "shared-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "shared-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "test-ns"}},
			},
		}

		otherBD := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "other-bd", UID: "other-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "other-target",
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "shared-sa", Namespace: "test-ns"}},
			},
		}

		sa := &corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "shared-sa",
				Namespace: "test-ns",
				Annotations: map[string]string{
					helpers.SourceNamesAnnotation: "other-bd,shared-sa-bd",
				},
				OwnerReferences: []metav1.OwnerReference{
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "shared-sa-bd", UID: "shared-sa-uid", Controller: &isNotController},
					{APIVersion: authorizationv1alpha1.GroupVersion.String(), Kind: "BindDefinition", Name: "other-bd", UID: "other-uid", Controller: &isNotController},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(bindDef, otherBD, sa).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.deleteServiceAccount(ctx, bindDef, "shared-sa", "test-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(Equal(deleteResultNoOwnerRef))

		retainedSA := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, client.ObjectKey{Name: "shared-sa", Namespace: "test-ns"}, retainedSA)).To(Succeed())
		g.Expect(retainedSA.Annotations).To(HaveKeyWithValue(helpers.SourceNamesAnnotation, "other-bd"))
		g.Expect(retainedSA.OwnerReferences).To(ContainElement(WithTransform(func(ref metav1.OwnerReference) string {
			return ref.Name
		}, Equal("other-bd"))))
		g.Expect(retainedSA.OwnerReferences).NotTo(ContainElement(WithTransform(func(ref metav1.OwnerReference) string {
			return ref.Name
		}, Equal("shared-sa-bd"))))
	})
}

func TestValidateServiceAccountNamespace(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("returns namespace when it exists and is active", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "existing-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).NotTo(BeNil())
		g.Expect(result.Name).To(Equal("existing-ns"))
	})

	t.Run("returns nil,nil for terminating namespace", func(t *testing.T) {
		g := NewWithT(t)

		now := metav1.Now()
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "term-ns",
				DeletionTimestamp: &now,
				Finalizers:        []string{"kubernetes"},
			},
			Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "term-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})

	t.Run("returns nil,nil for non-existent namespace", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result, err := r.validateServiceAccountNamespace(ctx, "test-bd", "missing-ns")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})
}

func TestFilterActiveNamespaces(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("filters out terminating namespaces", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "filter-bd"},
		}

		now := metav1.Now()
		namespaces := map[string]corev1.Namespace{
			"active-ns": {
				ObjectMeta: metav1.ObjectMeta{Name: "active-ns"},
				Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
			},
			"terminating-ns": {
				ObjectMeta: metav1.ObjectMeta{
					Name:              "terminating-ns",
					DeletionTimestamp: &now,
					Finalizers:        []string{"kubernetes"},
				},
				Status: corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result := r.filterActiveNamespaces(ctx, bindDef, namespaces)
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("active-ns"))
	})

	t.Run("returns empty for all terminating", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "filter-empty-bd"},
		}

		now := metav1.Now()
		namespaces := map[string]corev1.Namespace{
			"term1": {
				ObjectMeta: metav1.ObjectMeta{Name: "term1", DeletionTimestamp: &now, Finalizers: []string{"k"}},
				Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceTerminating},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		result := r.filterActiveNamespaces(ctx, bindDef, namespaces)
		g.Expect(result).To(BeEmpty())
	})
}

func TestResolveRoleBindingNamespaces(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("resolves explicit namespace", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "explicit-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			Namespace:       "explicit-ns",
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("explicit-ns"))
	})

	t.Run("returns nil for non-existent explicit namespace", func(t *testing.T) {
		g := NewWithT(t)

		c := fake.NewClientBuilder().WithScheme(s).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			Namespace:       "missing-ns",
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(BeNil())
	})

	t.Run("resolves namespaces by label selector", func(t *testing.T) {
		g := NewWithT(t)

		ns1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "labeled-ns", Labels: map[string]string{"env": "test"}},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "unlabeled-ns"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns1, ns2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			NamespaceSelector: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"env": "test"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("labeled-ns"))
	})

	t.Run("deduplicates namespaces from multiple selectors", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "multi-label-ns",
				Labels: map[string]string{"env": "test", "team": "alpha"},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		binding := authorizationv1alpha1.NamespaceBinding{
			NamespaceSelector: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"env": "test"}},
				{MatchLabels: map[string]string{"team": "alpha"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1)) // deduplicated
	})

	t.Run("empty label selector matches all namespaces per Kubernetes semantics", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "ns1", Labels: map[string]string{"env": "test"}},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "ns2"},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns, ns2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		// An empty selector ({}) matches all namespaces, consistent with the
		// BindDefinition validating webhook behavior.
		binding := authorizationv1alpha1.NamespaceBinding{
			NamespaceSelector: []metav1.LabelSelector{
				{}, // empty - matches all namespaces
				{MatchLabels: map[string]string{"env": "test"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(2)) // both ns1 and ns2 matched (deduplicated)
	})

	t.Run("explicit namespace takes precedence over selectors", func(t *testing.T) {
		g := NewWithT(t)

		ns1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "explicit-ns", Labels: map[string]string{"env": "test"}},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "selected-ns", Labels: map[string]string{"env": "test"}},
		}

		c := fake.NewClientBuilder().WithScheme(s).WithObjects(ns1, ns2).Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		// When both Namespace and NamespaceSelector are set, only the explicit
		// namespace should be returned (selectors are ignored).
		binding := authorizationv1alpha1.NamespaceBinding{
			Namespace: "explicit-ns",
			NamespaceSelector: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"env": "test"}},
			},
			ClusterRoleRefs: []string{"view"},
		}

		result, err := r.resolveRoleBindingNamespaces(ctx, binding)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(result).To(HaveLen(1))
		g.Expect(result[0].Name).To(Equal("explicit-ns"))
	})
}

func TestEnsureServiceAccountsUnit(t *testing.T) {
	ctx := context.Background()

	s := runtime.NewScheme()
	_ = authorizationv1alpha1.AddToScheme(s)
	_ = rbacv1.AddToScheme(s)
	_ = corev1.AddToScheme(s)

	t.Run("creates SA in existing namespace", func(t *testing.T) {
		g := NewWithT(t)

		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "sa-ns"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		}
		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "ensure-sa-bd", UID: "ensure-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "ensure-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "new-sa", Namespace: "sa-ns"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef, ns).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(HaveLen(1))
		g.Expect(generatedSAs[0].Name).To(Equal("new-sa"))

		// Verify SA was created
		sa := &corev1.ServiceAccount{}
		g.Expect(c.Get(ctx, client.ObjectKey{Name: "new-sa", Namespace: "sa-ns"}, sa)).To(Succeed())
	})

	t.Run("skips non-ServiceAccount subjects", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "skip-sa-bd", UID: "skip-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "skip-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "Group", Name: "devs", APIGroup: rbacv1.GroupName},
					{Kind: "User", Name: "admin", APIGroup: rbacv1.GroupName},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(BeEmpty())
	})

	t.Run("skips SA in non-existent namespace", func(t *testing.T) {
		g := NewWithT(t)

		bindDef := &authorizationv1alpha1.BindDefinition{
			TypeMeta: metav1.TypeMeta{
				APIVersion: authorizationv1alpha1.GroupVersion.String(),
				Kind:       "BindDefinition",
			},
			ObjectMeta: metav1.ObjectMeta{Name: "no-ns-sa-bd", UID: "no-ns-sa-uid"},
			Spec: authorizationv1alpha1.BindDefinitionSpec{
				TargetName: "no-ns-sa",
				Subjects: []rbacv1.Subject{
					{Kind: "ServiceAccount", Name: "orphan-sa", Namespace: "nonexistent-ns"},
				},
			},
		}

		c := fake.NewClientBuilder().WithScheme(s).
			WithObjects(bindDef).
			WithStatusSubresource(bindDef).
			Build()
		r := &BindDefinitionReconciler{client: c, scheme: s, recorder: events.NewFakeRecorder(10)}

		generatedSAs, _, err := r.ensureServiceAccounts(ctx, bindDef)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(generatedSAs).To(BeEmpty())
	})
}

var _ = Describe("BindDefinition Event Assertions", func() {
	ctx := context.Background()

	Describe("deleteServiceAccount events", func() {
		It("should emit a Deletion event when ServiceAccount has no OwnerRef", func() {
			// Create ServiceAccount without owner reference.
			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-event-no-owner",
					Namespace: "default",
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, sa) }()

			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd-event-no-owner",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-event-no-owner",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-event-no-owner", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Not deleting"))
			Expect(event).To(ContainSubstring("OwnerRef"))
		})

		It("should emit a Deletion event when ServiceAccount is deleted", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-bd-event-delete",
					Namespace: "default",
				},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-sa-event-delete",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			// Fetch to get UID for owner reference.
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(bindDef), bindDef)).To(Succeed())

			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa-event-delete",
					Namespace: "default",
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion:         authorizationv1alpha1.GroupVersion.String(),
							Kind:               "BindDefinition",
							Name:               bindDef.Name,
							UID:                bindDef.UID,
							Controller:         ptr.To(true),
							BlockOwnerDeletion: ptr.To(true),
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, sa)).To(Succeed())

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteServiceAccount(ctx, bindDef, "test-sa-event-delete", "default")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultDeleted))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Deleting target resource ServiceAccount"))
		})
	})

	Describe("deleteClusterRoleBinding events", func() {
		It("should emit a Deletion event when CRB has no OwnerRef", func() {
			bindDef := &authorizationv1alpha1.BindDefinition{
				ObjectMeta: metav1.ObjectMeta{Name: "test-bd-crb-event"},
				Spec: authorizationv1alpha1.BindDefinitionSpec{
					TargetName:          "test-crb-event",
					ClusterRoleBindings: authorizationv1alpha1.ClusterBinding{ClusterRoleRefs: []string{"view"}},
					Subjects:            []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: "test-user", APIGroup: rbacv1.GroupName}},
				},
			}
			Expect(k8sClient.Create(ctx, bindDef)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, bindDef) }()

			// Create ClusterRoleBinding without owner reference.
			crbName := helpers.BuildBindingName(bindDef.Spec.TargetName, "cluster-admin")
			crb := &rbacv1.ClusterRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: crbName},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
			}
			Expect(k8sClient.Create(ctx, crb)).To(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, crb) }()

			eventRecorder := events.NewFakeRecorder(10)
			reconciler := &BindDefinitionReconciler{
				client:   k8sClient,
				scheme:   k8sClient.Scheme(),
				recorder: eventRecorder,
			}

			result, err := reconciler.deleteClusterRoleBinding(ctx, bindDef, "cluster-admin")
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(deleteResultNoOwnerRef))

			// Verify event was emitted.
			Expect(eventRecorder.Events).To(HaveLen(1))
			event := <-eventRecorder.Events
			Expect(event).To(ContainSubstring(authorizationv1alpha1.EventReasonDeletion))
			Expect(event).To(ContainSubstring("Not deleting"))
		})
	})
})

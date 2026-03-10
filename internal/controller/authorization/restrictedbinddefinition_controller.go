// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/events"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/policy"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
	"github.com/telekom/auth-operator/pkg/tracing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions/finalizers,verbs=update

// RestrictedBindDefinitionReconciler reconciles a RestrictedBindDefinition object.
type RestrictedBindDefinitionReconciler struct {
	client   client.Client
	scheme   *runtime.Scheme
	recorder events.EventRecorder
	tracer   trace.Tracer
}

// setTracer implements tracerSetter.
func (r *RestrictedBindDefinitionReconciler) setTracer(t trace.Tracer) { r.tracer = t }

// NewRestrictedBindDefinitionReconciler creates a new RestrictedBindDefinition reconciler.
func NewRestrictedBindDefinitionReconciler(
	cachedClient client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	opts ...ReconcilerOption,
) *RestrictedBindDefinitionReconciler {
	r := &RestrictedBindDefinitionReconciler{
		client:   cachedClient,
		scheme:   scheme,
		recorder: recorder,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// SetupWithManager sets up the controller with the Manager.
func (r *RestrictedBindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authorizationv1alpha1.RestrictedBindDefinition{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestForOwner(mgr.GetScheme(), mgr.GetRESTMapper(),
				&authorizationv1alpha1.RestrictedBindDefinition{}, handler.OnlyControllerOwner()),
		).
		// Re-reconcile when the referenced RBACPolicy changes.
		Watches(&authorizationv1alpha1.RBACPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.policyToRestrictedBindDefinitions),
		).
		// Re-reconcile when namespaces change (label changes affect namespace selectors).
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToRestrictedBindDefinitions),
		).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

// policyToRestrictedBindDefinitions maps an RBACPolicy event to reconcile requests
// for all RestrictedBindDefinitions referencing that policy.
func (r *RestrictedBindDefinitionReconciler) policyToRestrictedBindDefinitions(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rbdList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	if err := r.client.List(ctx, rbdList,
		client.MatchingFields{indexer.RestrictedBindDefinitionPolicyRefField: obj.GetName()}); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions for policy", "policy", obj.GetName())
		return nil
	}
	requests := make([]reconcile.Request, len(rbdList.Items))
	for i, rbd := range rbdList.Items {
		requests[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}}
	}
	return requests
}

// namespaceToRestrictedBindDefinitions maps a Namespace event to reconcile requests
// for all RestrictedBindDefinitions that may be affected.
func (r *RestrictedBindDefinitionReconciler) namespaceToRestrictedBindDefinitions(ctx context.Context, _ client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rbdList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	if err := r.client.List(ctx, rbdList); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions")
		return nil
	}
	requests := make([]reconcile.Request, len(rbdList.Items))
	for i, rbd := range rbdList.Items {
		requests[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: rbd.Name}}
	}
	return requests
}

// Reconcile handles the reconciliation loop for RestrictedBindDefinition resources.
func (r *RestrictedBindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	if r.tracer != nil {
		var span trace.Span
		ctx, span = r.tracer.Start(ctx, "reconcile.RestrictedBindDefinition",
			trace.WithAttributes(
				tracing.AttrController.String("RestrictedBindDefinition"),
				tracing.AttrResource.String(req.Name),
			))
		defer func() {
			if retErr != nil {
				span.RecordError(retErr)
				span.SetStatus(codes.Error, retErr.Error())
			}
			span.End()
		}()
	}

	logger.V(1).Info("=== Reconcile START ===", "restrictedBindDefinition", req.Name)

	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerRestrictedBindDefinition).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===", "restrictedBindDefinition", req.Name, "duration", duration.String())
	}()

	// Step 1: Fetch the RestrictedBindDefinition.
	rbd := &authorizationv1alpha1.RestrictedBindDefinition{}
	if err := r.client.Get(ctx, req.NamespacedName, rbd); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("RestrictedBindDefinition not found (deleted), skipping", "name", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch RestrictedBindDefinition %s: %w", req.Name, err)
	}

	// Step 2: Handle deletion.
	if !rbd.DeletionTimestamp.IsZero() {
		logger.V(1).Info("RestrictedBindDefinition marked for deletion", "name", rbd.Name)
		if err := r.reconcileDelete(ctx, rbd); err != nil {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
			return ctrl.Result{}, err
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultFinalized).Inc()
		return ctrl.Result{}, nil
	}

	// Step 3: Mark Reconciling.
	conditions.MarkReconciling(rbd, rbd.Generation,
		authorizationv1alpha1.ReconcilingReasonProgressing, authorizationv1alpha1.ReconcilingMessageProgressing)
	rbd.Status.ObservedGeneration = rbd.Generation

	// Step 4: Ensure finalizer.
	if !controllerutil.ContainsFinalizer(rbd, authorizationv1alpha1.RestrictedBindDefinitionFinalizer) {
		old := rbd.DeepCopy()
		controllerutil.AddFinalizer(rbd, authorizationv1alpha1.RestrictedBindDefinitionFinalizer)
		if err := r.client.Patch(ctx, rbd, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			r.rbdMarkStalled(ctx, rbd, err)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
			return ctrl.Result{}, fmt.Errorf("add finalizer to RestrictedBindDefinition %s: %w", rbd.Name, err)
		}
	}

	// Step 5: Fetch referenced RBACPolicy.
	rbacPolicy := &authorizationv1alpha1.RBACPolicy{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: rbd.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("referenced RBACPolicy not found", "name", rbd.Name, "policyRef", rbd.Spec.PolicyRef.Name)
			conditions.MarkFalse(rbd, authorizationv1alpha1.PolicyCompliantCondition, rbd.Generation,
				authorizationv1alpha1.PolicyCompliantReasonPolicyNotFound, "referenced RBACPolicy %q not found", rbd.Spec.PolicyRef.Name)
			r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
				authorizationv1alpha1.EventReasonPolicyNotFound, "Reconcile",
				"Referenced RBACPolicy %q not found", rbd.Spec.PolicyRef.Name)
			rbd.Status.PolicyViolations = []string{fmt.Sprintf("policy %q not found", rbd.Spec.PolicyRef.Name)}
			r.rbdApplyStatusAndMarkStalled(ctx, rbd)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultDegraded).Inc()
			return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
		}
		r.rbdMarkStalled(ctx, rbd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch RBACPolicy %s: %w", rbd.Spec.PolicyRef.Name, err)
	}

	// Step 6: Evaluate policy compliance.
	violations := policy.EvaluateBindDefinition(rbacPolicy, rbd)
	if len(violations) > 0 { //nolint:dupl // structurally similar to RRD but type-specific
		violationStrings := make([]string, len(violations))
		for i, v := range violations {
			violationStrings[i] = v.String()
		}
		logger.Info("policy violations detected",
			"name", rbd.Name, "violations", violationStrings)
		conditions.MarkFalse(rbd, authorizationv1alpha1.PolicyCompliantCondition, rbd.Generation,
			authorizationv1alpha1.PolicyCompliantReasonViolationsDetected, "policy violations: %v", violationStrings)
		rbd.Status.PolicyViolations = violationStrings

		r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
			authorizationv1alpha1.EventReasonPolicyViolation, "Reconcile",
			"Policy violations detected: %v", violationStrings)

		// Deprovision: delete all owned RBAC resources.
		if err := r.rbdDeprovision(ctx, rbd); err != nil {
			r.rbdMarkStalled(ctx, rbd, err)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
			return ctrl.Result{}, fmt.Errorf("deprovision RestrictedBindDefinition %s: %w", rbd.Name, err)
		}

		rbd.Status.BindReconciled = false
		conditions.MarkFalse(rbd, conditions.ReadyConditionType, rbd.Generation,
			authorizationv1alpha1.DeprovisionedReason, "deprovisioned due to policy violations")

		if err := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); err != nil {
			logger.Error(err, "failed to apply status after deprovisioning", "name", rbd.Name)
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultDegraded).Inc()
		return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
	}

	// Policy compliant.
	conditions.MarkTrue(rbd, authorizationv1alpha1.PolicyCompliantCondition, rbd.Generation,
		authorizationv1alpha1.PolicyCompliantReasonAllChecksPass, "all policy checks passed")
	rbd.Status.PolicyViolations = nil

	r.recorder.Eventf(rbd, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonPolicyCompliance, "Reconcile",
		"All policy checks passed for RBACPolicy %q", rbacPolicy.Name)

	// Step 7: Reconcile RBAC resources.
	if err := r.rbdReconcileResources(ctx, rbd); err != nil {
		r.rbdMarkStalled(ctx, rbd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		return ctrl.Result{}, err
	}

	// Step 8: Mark Ready.
	rbd.Status.BindReconciled = true
	conditions.MarkReady(rbd, rbd.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)

	if err := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); err != nil {
		logger.Error(err, "failed to apply RestrictedBindDefinition status", "name", rbd.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		return ctrl.Result{}, fmt.Errorf("apply RestrictedBindDefinition %s status: %w", rbd.Name, err)
	}

	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// rbdReconcileResources ensures all RBAC resources for the RestrictedBindDefinition exist.
func (r *RestrictedBindDefinitionReconciler) rbdReconcileResources(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
) error {
	logger := log.FromContext(ctx)

	// Ensure ServiceAccounts.
	automountToken := ptr.Deref(rbd.Spec.AutomountServiceAccountToken, true)
	for _, subject := range rbd.Spec.Subjects {
		if subject.Kind != authorizationv1alpha1.BindSubjectServiceAccount {
			continue
		}
		ns := &corev1.Namespace{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: subject.Namespace}, ns); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(2).Info("SA namespace not found, skipping", "namespace", subject.Namespace)
				continue
			}
			return fmt.Errorf("get namespace %s: %w", subject.Namespace, err)
		}
		if conditions.IsNamespaceTerminating(ns) {
			continue
		}
		ac := pkgssa.ServiceAccountWith(subject.Name, subject.Namespace,
			helpers.BuildResourceLabels(rbd.Labels), automountToken).
			WithOwnerReferences(rbdOwnerRef(rbd)).
			WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))
		if _, err := pkgssa.PatchApplyServiceAccount(ctx, r.client, ac, pkgssa.FieldOwnerForBD(rbd.Name)); err != nil {
			return fmt.Errorf("apply ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
		}
	}

	// Ensure ClusterRoleBindings.
	for _, clusterRoleRef := range rbd.Spec.ClusterRoleBindings.ClusterRoleRefs {
		crbName := helpers.BuildBindingName(rbd.Spec.TargetName, clusterRoleRef)
		ac := pkgssa.ClusterRoleBindingWithSubjectsAndRoleRef(
			crbName, helpers.BuildResourceLabels(rbd.Labels), rbd.Spec.Subjects,
			rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRoleRef},
		)
		ac.WithOwnerReferences(rbdOwnerRef(rbd)).
			WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))

		if _, err := pkgssa.PatchApplyClusterRoleBinding(ctx, r.client, ac); err != nil {
			return fmt.Errorf("ensure ClusterRoleBinding %s: %w", crbName, err)
		}
	}

	// Ensure RoleBindings.
	for _, roleBinding := range rbd.Spec.RoleBindings {
		targetNamespaces, err := r.rbdResolveNamespaces(ctx, roleBinding)
		if err != nil {
			return fmt.Errorf("resolve namespaces: %w", err)
		}
		for _, ns := range targetNamespaces {
			if conditions.IsNamespaceTerminating(&ns) {
				continue
			}
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.rbdEnsureRoleBinding(ctx, rbd, ns.Name, clusterRoleRef, "ClusterRole"); err != nil {
					return err
				}
			}
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.rbdEnsureRoleBinding(ctx, rbd, ns.Name, roleRef, "Role"); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// rbdEnsureRoleBinding ensures a single RoleBinding exists.
func (r *RestrictedBindDefinitionReconciler) rbdEnsureRoleBinding(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	namespace, roleRef, roleKind string,
) error {
	rbName := helpers.BuildBindingName(rbd.Spec.TargetName, roleRef)
	ac := pkgssa.RoleBindingWithSubjectsAndRoleRef(
		rbName, namespace, helpers.BuildResourceLabels(rbd.Labels), rbd.Spec.Subjects,
		rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: roleKind, Name: roleRef},
	)
	ac.WithOwnerReferences(rbdOwnerRef(rbd)).
		WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))

	if _, err := pkgssa.PatchApplyRoleBinding(ctx, r.client, ac); err != nil {
		return fmt.Errorf("ensure RoleBinding %s/%s: %w", namespace, rbName, err)
	}
	return nil
}

// rbdResolveNamespaces resolves namespaces for a NamespaceBinding.
func (r *RestrictedBindDefinitionReconciler) rbdResolveNamespaces(
	ctx context.Context,
	binding authorizationv1alpha1.NamespaceBinding,
) ([]corev1.Namespace, error) {
	if binding.Namespace != "" {
		ns := &corev1.Namespace{}
		if err := r.client.Get(ctx, types.NamespacedName{Name: binding.Namespace}, ns); err != nil {
			if apierrors.IsNotFound(err) {
				return nil, nil
			}
			return nil, fmt.Errorf("get namespace %s: %w", binding.Namespace, err)
		}
		return []corev1.Namespace{*ns}, nil
	}

	seen := make(map[string]bool)
	var namespaces []corev1.Namespace
	for _, nsSelector := range binding.NamespaceSelector {
		selector, err := metav1.LabelSelectorAsSelector(&nsSelector)
		if err != nil {
			return nil, fmt.Errorf("parse namespace selector: %w", err)
		}
		nsList := &corev1.NamespaceList{}
		if err := r.client.List(ctx, nsList, client.MatchingLabelsSelector{Selector: selector}); err != nil {
			return nil, fmt.Errorf("list namespaces: %w", err)
		}
		for _, ns := range nsList.Items {
			if !seen[ns.Name] {
				seen[ns.Name] = true
				namespaces = append(namespaces, ns)
			}
		}
	}

	return namespaces, nil
}

// rbdDeprovision deletes all RBAC resources owned by the RestrictedBindDefinition.
// TODO: Use label selectors to narrow the list scope in large clusters.
func (r *RestrictedBindDefinitionReconciler) rbdDeprovision(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
) error {
	logger := log.FromContext(ctx)
	logger.Info("deprovisioning RestrictedBindDefinition", "name", rbd.Name)

	// Delete owned ClusterRoleBindings.
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.client.List(ctx, crbList); err != nil {
		return fmt.Errorf("list ClusterRoleBindings: %w", err)
	}
	for i := range crbList.Items {
		if isOwnedBy(&crbList.Items[i], rbd) {
			if err := r.client.Delete(ctx, &crbList.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete ClusterRoleBinding %s: %w", crbList.Items[i].Name, err)
			}
		}
	}

	// Delete owned RoleBindings.
	rbList := &rbacv1.RoleBindingList{}
	if err := r.client.List(ctx, rbList); err != nil {
		return fmt.Errorf("list RoleBindings: %w", err)
	}
	for i := range rbList.Items {
		if isOwnedBy(&rbList.Items[i], rbd) {
			if err := r.client.Delete(ctx, &rbList.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete RoleBinding %s/%s: %w", rbList.Items[i].Namespace, rbList.Items[i].Name, err)
			}
		}
	}

	r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonDeprovisioned, "Reconcile",
		"Deprovisioned all RBAC resources due to policy violations")

	return nil
}

// reconcileDelete handles deletion of a RestrictedBindDefinition.
func (r *RestrictedBindDefinitionReconciler) reconcileDelete(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
) error {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(rbd, authorizationv1alpha1.RestrictedBindDefinitionFinalizer) {
		return nil
	}

	// Clean up owned resources.
	if err := r.rbdDeprovision(ctx, rbd); err != nil {
		logger.Error(err, "failed to deprovision during deletion", "name", rbd.Name)
		return fmt.Errorf("delete cleanup for RestrictedBindDefinition %s: %w", rbd.Name, err)
	}

	// Remove finalizer.
	old := rbd.DeepCopy()
	controllerutil.RemoveFinalizer(rbd, authorizationv1alpha1.RestrictedBindDefinitionFinalizer)
	if err := r.client.Patch(ctx, rbd, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("remove finalizer from RestrictedBindDefinition %s: %w", rbd.Name, err)
	}

	logger.V(1).Info("finalizer removed, deletion complete", "name", rbd.Name)
	return nil
}

// rbdMarkStalled marks the RestrictedBindDefinition as stalled.
func (r *RestrictedBindDefinitionReconciler) rbdMarkStalled(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	err error,
) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("marking RestrictedBindDefinition as stalled", "name", rbd.Name, "error", err)
	conditions.MarkStalled(rbd, rbd.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, "check operator logs for details")
	rbd.Status.ObservedGeneration = rbd.Generation
	if updateErr := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "name", rbd.Name)
	}
}

// rbdApplyStatusAndMarkStalled applies current status and marks the RBD as stalled.
func (r *RestrictedBindDefinitionReconciler) rbdApplyStatusAndMarkStalled(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
) {
	logger := log.FromContext(ctx)
	conditions.MarkStalled(rbd, rbd.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, "policy not found")
	rbd.Status.ObservedGeneration = rbd.Generation
	if err := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); err != nil {
		logger.Error(err, "failed to apply status via SSA", "name", rbd.Name)
	}
}

// rbdOwnerRef creates an OwnerReference for a RestrictedBindDefinition.
func rbdOwnerRef(rbd *authorizationv1alpha1.RestrictedBindDefinition) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authorizationv1alpha1.GroupVersion.String(),
		"RestrictedBindDefinition",
		rbd.Name,
		rbd.UID,
		true,
		true,
	)
}

// isOwnedBy checks if the object is owned by the given owner (cluster-scoped).
func isOwnedBy(obj, owner metav1.ObjectMetaAccessor) bool {
	ownerUID := owner.(metav1.Object).GetUID()
	for _, ref := range obj.(metav1.Object).GetOwnerReferences() {
		if ref.UID == ownerUID {
			return true
		}
	}
	return false
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"math"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/indexer"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/tracing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=rbacpolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=rbacpolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=rbacpolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedbinddefinitions,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions,verbs=get;list;watch

// RBACPolicyReconciler reconciles an RBACPolicy object.
type RBACPolicyReconciler struct {
	client   client.Client
	scheme   *runtime.Scheme
	recorder events.EventRecorder
	tracer   trace.Tracer
}

// setTracer implements tracerSetter.
func (r *RBACPolicyReconciler) setTracer(t trace.Tracer) { r.tracer = t }

// NewRBACPolicyReconciler creates a new RBACPolicy reconciler.
func NewRBACPolicyReconciler(
	cachedClient client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	opts ...ReconcilerOption,
) *RBACPolicyReconciler {
	r := &RBACPolicyReconciler{
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
func (r *RBACPolicyReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager, concurrency int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authorizationv1alpha1.RBACPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Watch RestrictedBindDefinitions and re-reconcile the referenced RBACPolicy.
		Watches(&authorizationv1alpha1.RestrictedBindDefinition{},
			handler.EnqueueRequestsFromMapFunc(r.restrictedResourceToPolicyRequests),
		).
		// Watch RestrictedRoleDefinitions and re-reconcile the referenced RBACPolicy.
		Watches(&authorizationv1alpha1.RestrictedRoleDefinition{},
			handler.EnqueueRequestsFromMapFunc(r.restrictedResourceToPolicyRequests),
		).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

// restrictedResourceToPolicyRequests maps a RestrictedBindDefinition or
// RestrictedRoleDefinition event to a reconcile request for its referenced RBACPolicy.
func (r *RBACPolicyReconciler) restrictedResourceToPolicyRequests(_ context.Context, obj client.Object) []reconcile.Request {
	var policyName string
	switch v := obj.(type) {
	case *authorizationv1alpha1.RestrictedBindDefinition:
		policyName = v.Spec.PolicyRef.Name
	case *authorizationv1alpha1.RestrictedRoleDefinition:
		policyName = v.Spec.PolicyRef.Name
	default:
		return nil
	}
	if policyName == "" {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Name: policyName}}}
}

// Reconcile handles the reconciliation loop for RBACPolicy resources.
func (r *RBACPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	if r.tracer != nil {
		var span trace.Span
		ctx, span = r.tracer.Start(ctx, "reconcile.RBACPolicy",
			trace.WithAttributes(
				tracing.AttrController.String("RBACPolicy"),
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

	logger.V(1).Info("=== Reconcile START ===", "rbacPolicy", req.Name)

	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerRBACPolicy).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===", "rbacPolicy", req.Name, "duration", duration.String())
	}()

	// Step 1: Fetch the RBACPolicy.
	policy := &authorizationv1alpha1.RBACPolicy{}
	if err := r.client.Get(ctx, req.NamespacedName, policy); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("RBACPolicy not found (deleted), skipping", "rbacPolicy", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch RBACPolicy %s: %w", req.Name, err)
	}

	// Step 2: Mark as Reconciling.
	conditions.MarkReconciling(policy, policy.Generation,
		authorizationv1alpha1.ReconcilingReasonProgressing, authorizationv1alpha1.ReconcilingMessageProgressing)
	policy.Status.ObservedGeneration = policy.Generation

	// Step 3: Count bound RestrictedBindDefinitions.
	rbdList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	if err := r.client.List(ctx, rbdList,
		client.MatchingFields{indexer.RestrictedBindDefinitionPolicyRefField: policy.Name}); err != nil {
		logger.Error(err, "failed to list RestrictedBindDefinitions", "rbacPolicy", policy.Name)
		r.markStalled(ctx, policy, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("list RestrictedBindDefinitions for policy %s: %w", policy.Name, err)
	}

	// Step 4: Count bound RestrictedRoleDefinitions.
	rrdList := &authorizationv1alpha1.RestrictedRoleDefinitionList{}
	if err := r.client.List(ctx, rrdList,
		client.MatchingFields{indexer.RestrictedRoleDefinitionPolicyRefField: policy.Name}); err != nil {
		logger.Error(err, "failed to list RestrictedRoleDefinitions", "rbacPolicy", policy.Name)
		r.markStalled(ctx, policy, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("list RestrictedRoleDefinitions for policy %s: %w", policy.Name, err)
	}

	// Step 5: Update status.
	total := len(rbdList.Items) + len(rrdList.Items)
	if total > math.MaxInt32 {
		total = math.MaxInt32
	}
	boundCount := int32(total) // #nosec G115 -- bounded by the check above
	policy.Status.BoundResourceCount = boundCount
	logger.V(2).Info("bound resource count updated",
		"rbacPolicy", policy.Name,
		"restrictedBindDefinitions", len(rbdList.Items),
		"restrictedRoleDefinitions", len(rrdList.Items),
		"totalBound", boundCount)

	// Step 6: Mark Ready and apply status.
	conditions.MarkReady(policy, policy.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)

	if err := ssa.ApplyRBACPolicyStatus(ctx, r.client, policy); err != nil {
		logger.Error(err, "failed to apply RBACPolicy status", "rbacPolicy", policy.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply RBACPolicy %s status: %w", policy.Name, err)
	}

	logger.V(1).Info("Reconcile completed successfully",
		"rbacPolicy", policy.Name, "requeueAfter", DefaultRequeueInterval)
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRBACPolicy, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// markStalled marks the RBACPolicy as stalled.
func (r *RBACPolicyReconciler) markStalled(ctx context.Context, policy *authorizationv1alpha1.RBACPolicy, err error) {
	logger := log.FromContext(ctx)
	logger.V(1).Info("marking RBACPolicy as stalled", "rbacPolicy", policy.Name, "error", err)
	conditions.MarkStalled(policy, policy.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, "check operator logs for details")
	policy.Status.ObservedGeneration = policy.Generation
	if updateErr := ssa.ApplyRBACPolicyStatus(ctx, r.client, policy); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "rbacPolicy", policy.Name)
	}
}

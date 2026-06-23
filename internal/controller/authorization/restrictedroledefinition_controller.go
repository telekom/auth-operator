// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/discovery"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/indexer"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/policy"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
	"github.com/telekom/auth-operator/pkg/tracing"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=restrictedroledefinitions/finalizers,verbs=update
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=rbacpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;patch;delete;escalate;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch;create;patch;delete;escalate;bind
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=create;patch;update

// RestrictedRoleDefinitionReconciler reconciles a RestrictedRoleDefinition object.
type RestrictedRoleDefinitionReconciler struct {
	client          client.Client
	reader          client.Reader
	scheme          *runtime.Scheme
	recorder        events.EventRecorder
	resourceTracker *discovery.ResourceTracker
	trackerEvents   chan event.TypedGenericEvent[client.Object]
	tracer          trace.Tracer

	restConfig                *rest.Config
	impersonatedClientFactory impersonatedClientFactory
	impersonatedClientCache   *impersonatedClientCache
}

// setTracer implements tracerSetter.
func (r *RestrictedRoleDefinitionReconciler) setTracer(t trace.Tracer) { r.tracer = t }

// NewRestrictedRoleDefinitionReconciler creates a new RestrictedRoleDefinition reconciler.
func NewRestrictedRoleDefinitionReconciler(
	cachedClient client.Client,
	scheme *runtime.Scheme,
	recorder events.EventRecorder,
	resourceTracker *discovery.ResourceTracker,
	opts ...ReconcilerOption,
) (*RestrictedRoleDefinitionReconciler, error) {
	if resourceTracker == nil {
		return nil, fmt.Errorf("resourceTracker cannot be nil")
	}
	trackerEvents := make(chan event.TypedGenericEvent[client.Object], 100)
	trackerCallback := func() error {
		trackerEvents <- event.TypedGenericEvent[client.Object]{}
		return nil
	}
	resourceTracker.AddSignalFunc(trackerCallback)

	r := &RestrictedRoleDefinitionReconciler{
		client:                    cachedClient,
		reader:                    cachedClient,
		scheme:                    scheme,
		recorder:                  recorder,
		resourceTracker:           resourceTracker,
		trackerEvents:             trackerEvents,
		impersonatedClientFactory: newImpersonatedClient,
		impersonatedClientCache:   newImpersonatedClientCache(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RestrictedRoleDefinitionReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	if r.restConfig == nil {
		r.restConfig = mgr.GetConfig()
	}
	if r.reader == nil || r.reader == r.client {
		r.reader = mgr.GetAPIReader()
	}

	trackerChannel := source.Channel(r.trackerEvents, handler.EnqueueRequestsFromMapFunc(r.queueAll()))

	return ctrl.NewControllerManagedBy(mgr).
		For(&authorizationv1alpha1.RestrictedRoleDefinition{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.Role{}).
		// Re-reconcile when the referenced RBACPolicy changes.
		Watches(&authorizationv1alpha1.RBACPolicy{},
			handler.EnqueueRequestsFromMapFunc(r.policyToRestrictedRoleDefinitions),
		).
		// Re-reconcile namespaced Role targets when namespace labels or phase
		// change. Policy appliesTo namespace selectors are evaluated against
		// spec.targetNamespace.
		Watches(&corev1.Namespace{},
			handler.EnqueueRequestsFromMapFunc(r.namespaceToRestrictedRoleDefinitions),
			builder.WithPredicates(namespaceLabelOrPhaseChangePredicate()),
		).
		WatchesRawSource(trackerChannel).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

func (r *RestrictedRoleDefinitionReconciler) ownershipReader() client.Reader {
	if r.reader != nil {
		return r.reader
	}
	return r.client
}

func (r *RestrictedRoleDefinitionReconciler) rrdResolveApplyClient(
	rbacPolicy *authorizationv1alpha1.RBACPolicy,
) (client.Client, string, error) {
	return resolvePolicyApplyClient(
		r.client,
		r.scheme,
		r.restConfig,
		rbacPolicy,
		r.impersonatedClientFactory,
		r.impersonatedClientCache,
	)
}

func (r *RestrictedRoleDefinitionReconciler) rrdEvaluatePolicy(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	rbacPolicy *authorizationv1alpha1.RBACPolicy,
	applyClient client.Client,
) (result ctrl.Result, handled bool, retErr error) {
	labelGetter := newLabelGetter(r.ownershipReader())
	violations := policy.EvaluateRoleDefinitionWithLabels(ctx, rbacPolicy, rrd, labelGetter)
	if err := labelGetter.Err(); err != nil {
		if deprovisionErr := r.rrdDeprovision(ctx, rrd, applyClient); deprovisionErr != nil {
			err = errors.Join(err, fmt.Errorf("deprovision after policy selector evaluation failure: %w", deprovisionErr))
		}
		markPolicyEvaluationError(rrd, rrd.Generation, err)
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, true, fmt.Errorf("evaluate policy selectors for RestrictedRoleDefinition %s: %w", rrd.Name, err)
	}
	if len(violations) == 0 {
		return ctrl.Result{}, false, nil
	}

	rrd.Status.PolicyViolations = policy.ViolationStrings(violations)
	result, err := handlePolicyViolations(ctx, rrd, rrd.Generation, violations, r.recorder, rrd, ViolationHandlerConfig{
		ControllerLabel: metrics.ControllerRestrictedRoleDefinition,
		ResourceKind:    "RestrictedRoleDefinition",
		Deprovision:     func(ctx context.Context) error { return r.rrdDeprovision(ctx, rrd, applyClient) },
		MarkStalled:     func(ctx context.Context, err error) { r.rrdMarkStalled(ctx, rrd, err) },
		SetReconciled:   func(v bool) { rrd.Status.RoleReconciled = v },
		ApplyStatus:     func(ctx context.Context) error { return ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd) },
	})
	return result, true, err
}

// queueAll enqueues all RestrictedRoleDefinitions for reconciliation.
func (r *RestrictedRoleDefinitionReconciler) queueAll() handler.MapFunc {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		logger := log.FromContext(ctx)
		list := &authorizationv1alpha1.RestrictedRoleDefinitionList{}
		listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
		defer cancel()
		if err := r.client.List(listCtx, list); err != nil {
			logger.Error(err, "failed to list RestrictedRoleDefinitions")
			return nil
		}
		requests := make([]reconcile.Request, len(list.Items))
		for i, item := range list.Items {
			requests[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: item.Name}}
		}
		return requests
	}
}

// policyToRestrictedRoleDefinitions maps an RBACPolicy event to reconcile requests
// for all RestrictedRoleDefinitions referencing that policy.
//
//nolint:dupl // Restricted bind/role reconcilers keep type-specific event mapping for controller-runtime indexes.
func (r *RestrictedRoleDefinitionReconciler) policyToRestrictedRoleDefinitions(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	list := &authorizationv1alpha1.RestrictedRoleDefinitionList{}
	listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
	defer cancel()
	if err := r.client.List(listCtx, list,
		client.MatchingFields{indexer.RestrictedRoleDefinitionPolicyRefField: obj.GetName()}); err != nil {
		if helpers.IsMissingFieldIndexError(err) {
			logger.V(2).Info("policyRef field index unavailable, falling back to full RestrictedRoleDefinition scan", "policy", obj.GetName())
			if listErr := r.client.List(listCtx, list); listErr != nil {
				logger.Error(listErr, "failed to list RestrictedRoleDefinitions for policy", "policy", obj.GetName())
				return nil
			}
			requests := make([]reconcile.Request, 0, len(list.Items))
			for i := range list.Items {
				if list.Items[i].Spec.PolicyRef.Name == obj.GetName() {
					requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name}})
				}
			}
			return requests
		}
		logger.Error(err, "failed to list RestrictedRoleDefinitions for policy", "policy", obj.GetName())
		return nil
	}
	requests := make([]reconcile.Request, len(list.Items))
	for i, rrd := range list.Items {
		requests[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: rrd.Name}}
	}
	return requests
}

// namespaceToRestrictedRoleDefinitions maps a Namespace event to namespaced
// RestrictedRoleDefinitions that target the changed namespace.
func (r *RestrictedRoleDefinitionReconciler) namespaceToRestrictedRoleDefinitions(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", fmt.Sprintf("%T", obj))
		return nil
	}

	list := &authorizationv1alpha1.RestrictedRoleDefinitionList{}
	listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
	defer cancel()
	if err := r.client.List(listCtx, list,
		client.MatchingFields{indexer.RestrictedRoleDefinitionTargetNamespaceField: namespace.Name}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			logger.Error(err, "failed to list RestrictedRoleDefinitions by target namespace", "namespace", namespace.Name)
			return nil
		}
		logger.V(2).Info("targetNamespace field index unavailable, falling back to full RestrictedRoleDefinition scan", "namespace", namespace.Name)
		if listErr := r.client.List(listCtx, list); listErr != nil {
			logger.Error(listErr, "failed to list RestrictedRoleDefinitions for namespace", "namespace", namespace.Name)
			return nil
		}
	}

	requests := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		rrd := &list.Items[i]
		if rrd.Spec.TargetRole != authorizationv1alpha1.DefinitionNamespacedRole ||
			rrd.Spec.TargetNamespace != namespace.Name {
			continue
		}
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: rrd.Name}})
	}
	return requests
}

// Reconcile handles the reconciliation loop for RestrictedRoleDefinition resources.
func (r *RestrictedRoleDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, retErr error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	if r.tracer != nil {
		var span trace.Span
		ctx, span = r.tracer.Start(ctx, "reconcile.RestrictedRoleDefinition",
			trace.WithAttributes(
				tracing.AttrController.String("RestrictedRoleDefinition"),
				tracing.AttrResource.String(req.Name),
				tracing.AttrNamespace.String(req.Namespace),
			))
		defer func() {
			if retErr != nil {
				span.RecordError(errors.New("restricted role definition reconciliation failed"))
				span.SetStatus(codes.Error, "restricted role definition reconciliation failed")
			}
			span.End()
		}()
	}

	logger.V(1).Info("=== Reconcile START ===", "restrictedRoleDefinition", req.Name)

	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerRestrictedRoleDefinition).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===", "restrictedRoleDefinition", req.Name, "duration", duration.String())
	}()

	// Step 1: Fetch the RestrictedRoleDefinition.
	rrd := &authorizationv1alpha1.RestrictedRoleDefinition{}
	if err := r.client.Get(ctx, req.NamespacedName, rrd); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("RestrictedRoleDefinition not found (deleted), skipping", "name", req.Name)
			metrics.DeletePolicyViolationContribution(metrics.ControllerRestrictedRoleDefinition, req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch RestrictedRoleDefinition %s: %w", req.Name, err)
	}

	// Step 2: Handle deletion.
	if !rrd.DeletionTimestamp.IsZero() {
		if err := r.rrdHandleDeletion(ctx, rrd); err != nil {
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
			metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
			return ctrl.Result{}, err
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultFinalized).Inc()
		return ctrl.Result{}, nil
	}

	// Step 3: Initialize status.
	conditions.MarkReconciling(rrd, rrd.Generation,
		authorizationv1alpha1.ReconcilingReasonProgressing, authorizationv1alpha1.ReconcilingMessageProgressing)
	rrd.Status.ObservedGeneration = rrd.Generation

	// Step 4: Ensure finalizer.
	if !controllerutil.ContainsFinalizer(rrd, authorizationv1alpha1.RestrictedRoleDefinitionFinalizer) {
		old := rrd.DeepCopy()
		controllerutil.AddFinalizer(rrd, authorizationv1alpha1.RestrictedRoleDefinitionFinalizer)
		if err := r.client.Patch(ctx, rrd, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
			if apierrors.IsConflict(err) {
				logger.V(1).Info("conflict adding finalizer, requeuing", "name", rrd.Name)
				return ctrl.Result{Requeue: true}, nil
			}
			r.rrdMarkStalled(ctx, rrd, err)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
			return ctrl.Result{}, fmt.Errorf("add finalizer to RestrictedRoleDefinition %s: %w", rrd.Name, err)
		}
	}

	// Step 5: Fetch referenced RBACPolicy.
	rbacPolicy := &authorizationv1alpha1.RBACPolicy{}
	if err := r.ownershipReader().Get(ctx, types.NamespacedName{Name: rrd.Spec.PolicyRef.Name}, rbacPolicy); err != nil {
		if apierrors.IsNotFound(err) {
			return r.rrdHandleMissingPolicy(ctx, rrd)
		}
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch RBACPolicy %s: %w", rrd.Spec.PolicyRef.Name, err)
	}
	if rbacPolicy.GetDeletionTimestamp() != nil {
		return r.rrdHandleDeletingPolicy(ctx, rrd, rbacPolicy)
	}

	applyClient, impersonatedUser, err := r.rrdResolveApplyClient(rbacPolicy)
	if err != nil {
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("resolve apply client for RestrictedRoleDefinition %s: %w", rrd.Name, err)
	}
	r.rrdLogApplyIdentity(ctx, rrd.Name, rbacPolicy.Name, impersonatedUser)

	// Step 6: Evaluate policy compliance.
	if result, handled, err := r.rrdEvaluatePolicy(ctx, rrd, rbacPolicy, applyClient); handled {
		return result, err
	}

	// Policy compliant.
	markPolicyCompliant(rrd, rrd.Generation, r.recorder, rrd, rbacPolicy.Name, metrics.ControllerRestrictedRoleDefinition)
	rrd.Status.PolicyViolations = nil

	// Step 7: Discover and filter API resources.
	finalRules, requeue, err := r.rrdDiscoverAndFilter(ctx, rrd)
	if err != nil {
		if deprovisionErr := r.rrdDeprovision(ctx, rrd, applyClient); deprovisionErr != nil {
			err = errors.Join(err, fmt.Errorf("deprovision after role discovery failure: %w", deprovisionErr))
		}
		markPolicyEvaluationError(rrd, rrd.Generation, err)
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	if requeue {
		if err := ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd); err != nil {
			return ctrl.Result{}, fmt.Errorf("apply status before requeue for RestrictedRoleDefinition %s: %w", rrd.Name, err)
		}
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultRequeue).Inc()
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	// Step 7.5: Check MaxRulesPerRole (requires generated rule count).
	if v := policy.CheckMaxRulesPerRole(rbacPolicy.Spec.RoleLimits, len(finalRules)); v != nil {
		rrd.Status.PolicyViolations = []string{v.String()}
		result, err := handlePolicyViolations(ctx, rrd, rrd.Generation, []policy.Violation{*v}, r.recorder, rrd, ViolationHandlerConfig{
			ControllerLabel: metrics.ControllerRestrictedRoleDefinition,
			ResourceKind:    "RestrictedRoleDefinition",
			Deprovision:     func(ctx context.Context) error { return r.rrdDeprovision(ctx, rrd, applyClient) },
			MarkStalled:     func(ctx context.Context, err error) { r.rrdMarkStalled(ctx, rrd, err) },
			SetReconciled:   func(v bool) { rrd.Status.RoleReconciled = v },
			ApplyStatus:     func(ctx context.Context) error { return ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd) },
		})
		return result, err
	}

	// Step 8: Ensure the target role exists.
	if err := r.rrdEnsureRole(ctx, rrd, finalRules, applyClient); err != nil {
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	// Step 9: Apply final status.
	rrd.Status.RoleReconciled = true
	conditions.MarkReady(rrd, rrd.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)

	if err := ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd); err != nil {
		logger.Error(err, "failed to apply RestrictedRoleDefinition status", "name", rrd.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply RestrictedRoleDefinition %s status: %w", rrd.Name, err)
	}

	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

func (r *RestrictedRoleDefinitionReconciler) rrdHandleMissingPolicy(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("referenced RBACPolicy not found", "name", rrd.Name, "policyRef", rrd.Spec.PolicyRef.Name)
	conditions.MarkFalse(rrd, authorizationv1alpha1.PolicyCompliantCondition, rrd.Generation,
		authorizationv1alpha1.PolicyCompliantReasonPolicyNotFound, authorizationv1alpha1.PolicyCompliantMessagePolicyNotFound, rrd.Spec.PolicyRef.Name)
	rrd.Status.PolicyViolations = []string{fmt.Sprintf("policy %q not found", rrd.Spec.PolicyRef.Name)}
	r.recorder.Eventf(rrd, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonPolicyNotFound, authorizationv1alpha1.EventActionReconcile,
		"Referenced RBACPolicy %q not found", rrd.Spec.PolicyRef.Name)

	if err := r.rrdDeprovision(ctx, rrd, r.client); err != nil {
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("deprovision RestrictedRoleDefinition %s after missing policy %s: %w", rrd.Name, rrd.Spec.PolicyRef.Name, err)
	}

	if err := r.rrdApplyStatusAndMarkStalled(ctx, rrd, "policy not found"); err != nil {
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply stalled status for RestrictedRoleDefinition %s after missing policy %s: %w", rrd.Name, rrd.Spec.PolicyRef.Name, err)
	}
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultDegraded).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

func (r *RestrictedRoleDefinitionReconciler) rrdHandleDeletingPolicy(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	rbacPolicy *authorizationv1alpha1.RBACPolicy,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("referenced RBACPolicy is deleting", "name", rrd.Name, "policyRef", rbacPolicy.Name)
	conditions.MarkFalse(rrd, authorizationv1alpha1.PolicyCompliantCondition, rrd.Generation,
		authorizationv1alpha1.PolicyCompliantReasonPolicyDeleting, authorizationv1alpha1.PolicyCompliantMessagePolicyDeleting, rbacPolicy.Name)
	rrd.Status.PolicyViolations = []string{fmt.Sprintf("policy %q is being deleted", rbacPolicy.Name)}
	r.recorder.Eventf(rrd, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonPolicyViolation, authorizationv1alpha1.EventActionReconcile,
		"Referenced RBACPolicy %q is being deleted", rbacPolicy.Name)

	if err := r.rrdDeprovision(ctx, rrd, r.client); err != nil {
		r.rrdMarkStalled(ctx, rrd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("deprovision RestrictedRoleDefinition %s after deleting policy %s: %w", rrd.Name, rbacPolicy.Name, err)
	}
	if err := r.rrdApplyStatusAndMarkStalled(ctx, rrd, "policy deleting"); err != nil {
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply stalled status for RestrictedRoleDefinition %s after deleting policy %s: %w", rrd.Name, rbacPolicy.Name, err)
	}
	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedRoleDefinition, metrics.ResultDegraded).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// rrdDiscoverAndFilter discovers API resources and filters based on the spec.
func (r *RestrictedRoleDefinitionReconciler) rrdDiscoverAndFilter(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
) ([]rbacv1.PolicyRule, bool, error) {
	logger := log.FromContext(ctx)

	apiResources, err := r.resourceTracker.GetAPIResources()
	if errors.Is(err, discovery.ErrResourceTrackerNotStarted) {
		logger.V(1).Info("ResourceTracker not started yet - requeuing", "name", rrd.Name)
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get API resources: %w", err)
	}

	rulesByKey := make(map[string]*rbacv1.PolicyRule)
	for gv, resources := range apiResources {
		groupVersion, err := schema.ParseGroupVersion(gv)
		if err != nil {
			return nil, false, fmt.Errorf("parse GroupVersion %q: %w", gv, err)
		}

		// Check if this group/version is restricted and collect per-API-group verb restrictions.
		apiIsRestricted, apiGroupRestrictedVerbs := rrdCheckAPIRestriction(rrd.Spec.RestrictedAPIs, groupVersion)

		// Skip fully restricted API groups (no verb-level granularity)
		if apiIsRestricted && len(apiGroupRestrictedVerbs) == 0 {
			continue
		}

		for _, res := range resources {
			rrdFilterResource(rrd, groupVersion, res, apiGroupRestrictedVerbs, rulesByKey)
		}
	}

	// Build sorted final rules.
	finalRules := make([]rbacv1.PolicyRule, 0, len(rulesByKey))
	for _, rule := range rulesByKey {
		finalRules = append(finalRules, *rule)
	}

	// Sort resources within each rule for deterministic output.
	for i := range finalRules {
		slices.Sort(finalRules[i].APIGroups)
		slices.Sort(finalRules[i].Resources)
		slices.Sort(finalRules[i].Verbs)
	}

	// Sort rules for consistent ordering.
	slices.SortFunc(finalRules, func(a, b rbacv1.PolicyRule) int {
		if c := strings.Compare(strings.Join(a.APIGroups, ","), strings.Join(b.APIGroups, ",")); c != 0 {
			return c
		}
		if c := strings.Compare(strings.Join(a.Resources, ","), strings.Join(b.Resources, ",")); c != 0 {
			return c
		}
		return strings.Compare(strings.Join(a.Verbs, ","), strings.Join(b.Verbs, ","))
	})

	logger.V(2).Info("discovery and filtering complete", "name", rrd.Name, "ruleCount", len(finalRules))
	return finalRules, false, nil
}

// rrdFilterResource evaluates a single API resource against the spec restrictions
// and adds matching verbs to the rulesByKey map.
func rrdFilterResource(
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	groupVersion schema.GroupVersion,
	res metav1.APIResource,
	apiGroupRestrictedVerbs []string,
	rulesByKey map[string]*rbacv1.PolicyRule,
) {
	// Check restricted resources.
	// An empty Group in the restriction matches all API groups.
	resourceIsRestricted := slices.ContainsFunc(rrd.Spec.RestrictedResources, func(rule metav1.APIResource) bool {
		return restrictedAPIResourceMatches(res.Name, groupVersion.Group, rule, true)
	})
	if resourceIsRestricted {
		return
	}

	// Filter by namespace scope.
	if res.Namespaced != rrd.Spec.ScopeNamespaced {
		return
	}

	// Filter verbs: remove globally restricted verbs AND per-API-group restricted verbs.
	verbs := make([]string, 0, len(res.Verbs))
	for _, verb := range res.Verbs {
		if !policy.ContainsStringOrWildcard(rrd.Spec.RestrictedVerbs, verb) &&
			!policy.ContainsStringOrWildcard(apiGroupRestrictedVerbs, verb) {
			verbs = append(verbs, verb)
		}
	}
	if len(verbs) == 0 {
		return
	}

	slices.Sort(verbs)
	key := fmt.Sprintf("%s|%s", groupVersion.Group, strings.Join(verbs, ","))
	existing, exists := rulesByKey[key]
	if !exists {
		existing = &rbacv1.PolicyRule{
			APIGroups: []string{groupVersion.Group},
			Verbs:     verbs,
		}
		rulesByKey[key] = existing
	}
	if !slices.Contains(existing.Resources, res.Name) {
		existing.Resources = append(existing.Resources, res.Name)
	}
}

func restrictedAPIResourceMatches(resourceName, apiGroup string, rule metav1.APIResource, emptyGroupMatchesAll bool) bool {
	groupMatches := policy.MatchesAPIGroup(rule.Group, apiGroup) || (emptyGroupMatchesAll && rule.Group == "")
	if !groupMatches {
		return false
	}
	return policy.MatchesResourceName(rule.Name, resourceName)
}

// rrdCheckAPIRestriction checks whether a given group/version matches any entry
// in the RestrictedAPIs list. It returns whether the API is restricted and the
// per-API-group restricted verbs (empty means fully blocked).
func rrdCheckAPIRestriction(
	restrictedAPIs []authorizationv1alpha1.RestrictedAPIGroup,
	groupVersion schema.GroupVersion,
) (restricted bool, verbs []string) {
	verbSet := make(map[string]struct{})
	for _, ag := range restrictedAPIs {
		if !policy.MatchesAPIGroup(ag.Name, groupVersion.Group) {
			continue
		}
		if len(ag.Versions) > 0 {
			if !slices.ContainsFunc(ag.Versions, func(v metav1.GroupVersionForDiscovery) bool {
				return v.Version == groupVersion.Version
			}) {
				continue
			}
		}
		restricted = true
		if len(ag.Verbs) == 0 {
			return true, nil
		}
		for _, verb := range ag.Verbs {
			verbSet[verb] = struct{}{}
		}
	}
	if !restricted {
		return false, nil
	}
	verbs = make([]string, 0, len(verbSet))
	for verb := range verbSet {
		verbs = append(verbs, verb)
	}
	slices.Sort(verbs)
	return true, verbs
}

// rrdEnsureRole ensures the target role exists with the computed rules.
func (r *RestrictedRoleDefinitionReconciler) rrdEnsureRole(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	finalRules []rbacv1.PolicyRule,
	applyClient client.Client,
) error {
	logger := log.FromContext(ctx)

	// Pre-flight ownership check: verify the target role is not already controlled
	// by a different owner. This produces a clearer error/event than the raw API rejection.
	if err := checkRestrictedRoleOwnership(ctx, r.ownershipReader(), r.recorder, rrd,
		rrd.Spec.TargetRole, rrd.Spec.TargetName, rrd.Spec.TargetNamespace); err != nil {
		conditions.MarkFalse(rrd, authorizationv1alpha1.OwnerRefCondition, rrd.Generation,
			authorizationv1alpha1.OwnerRefReason, "ownership conflict (check operator logs for details)")
		return err
	}

	ownerRef := ownerRefForRestricted(rrd, authorizationv1alpha1.RestrictedRoleDefinitionKind)
	annotations := helpers.BuildResourceAnnotations("RestrictedRoleDefinition", rrd.Name)

	switch rrd.Spec.TargetRole {
	case authorizationv1alpha1.DefinitionClusterRole:
		labelsMap := helpers.BuildRestrictedResourceLabels(nil)
		if err := r.rrdNormalizeOwnedClusterRoleMetadata(ctx, applyClient, rrd, rrd.Spec.TargetName, labelsMap); err != nil {
			return err
		}
		if err := r.rrdClearClusterRoleRulesIfEmpty(ctx, applyClient, rrd, rrd.Spec.TargetName, finalRules); err != nil {
			return err
		}
		ac := pkgssa.ClusterRoleWithLabelsAndRules(
			rrd.Spec.TargetName, labelsMap, finalRules,
		).WithOwnerReferences(ownerRef).WithAnnotations(annotations)

		result, err := pkgssa.PatchApplyClusterRolePruningLabelsAlways(ctx, applyClient, ac, helpers.IsProtectedRestrictedLabel, client.ForceOwnership)
		if err != nil {
			return fmt.Errorf("apply ClusterRole %s: %w", rrd.Spec.TargetName, err)
		}
		if result == pkgssa.PatchApplyResultSkipped {
			metrics.RBACResourcesSkipped.WithLabelValues(metrics.ResourceClusterRole).Inc()
		} else {
			metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceClusterRole).Inc()
		}
	case authorizationv1alpha1.DefinitionNamespacedRole:
		if err := r.rrdClearRoleRulesIfEmpty(ctx, applyClient, rrd, rrd.Spec.TargetNamespace, rrd.Spec.TargetName, finalRules); err != nil {
			return err
		}
		labelsMap := helpers.BuildRestrictedResourceLabels(rrd.Labels)
		ac := pkgssa.RoleWithLabelsAndRules(
			rrd.Spec.TargetName, rrd.Spec.TargetNamespace, labelsMap, finalRules,
		).WithOwnerReferences(ownerRef).WithAnnotations(annotations)

		result, err := pkgssa.PatchApplyRoleAlways(ctx, applyClient, ac, client.ForceOwnership)
		if err != nil {
			return fmt.Errorf("apply Role %s/%s: %w", rrd.Spec.TargetNamespace, rrd.Spec.TargetName, err)
		}
		if result == pkgssa.PatchApplyResultSkipped {
			metrics.RBACResourcesSkipped.WithLabelValues(metrics.ResourceRole).Inc()
		} else {
			metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceRole).Inc()
		}
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTargetRole, rrd.Spec.TargetRole)
	}

	logger.V(1).Info("role ensured", "name", rrd.Name, "targetRole", rrd.Spec.TargetRole, "targetName", rrd.Spec.TargetName)
	r.recorder.Eventf(rrd, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonCreation, authorizationv1alpha1.EventActionReconcile,
		"Ensured target resource %s %s", rrd.Spec.TargetRole, rrd.Spec.TargetName)
	return nil
}

func (r *RestrictedRoleDefinitionReconciler) rrdNormalizeOwnedClusterRoleMetadata(
	ctx context.Context,
	applyClient client.Client,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	name string,
	desiredLabels map[string]string,
) error {
	existing := &rbacv1.ClusterRole{}
	if err := r.ownershipReader().Get(ctx, client.ObjectKey{Name: name}, existing); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !hasControllerOwnerRef(existing, rrd) {
		return nil
	}

	patched := existing.DeepCopy()
	changed := false
	if !stringMapEqual(patched.Labels, desiredLabels) {
		patched.Labels = copyStringMap(desiredLabels)
		changed = true
	}
	if patched.AggregationRule != nil {
		patched.AggregationRule = nil
		changed = true
	}
	if !changed {
		return nil
	}
	if err := applyClient.Patch(ctx, patched, client.MergeFrom(existing)); err != nil {
		return fmt.Errorf("normalize owned ClusterRole %s metadata: %w", name, err)
	}
	return nil
}

func stringMapEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (r *RestrictedRoleDefinitionReconciler) rrdClearClusterRoleRulesIfEmpty(
	ctx context.Context,
	applyClient client.Client,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	name string,
	finalRules []rbacv1.PolicyRule,
) error {
	if len(finalRules) > 0 {
		return nil
	}
	existing := &rbacv1.ClusterRole{}
	if err := r.ownershipReader().Get(ctx, client.ObjectKey{Name: name}, existing); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !hasControllerOwnerRef(existing, rrd) {
		return nil
	}
	if len(existing.Rules) == 0 {
		return nil
	}
	patch := client.RawPatch(types.MergePatchType, []byte(`{"rules":null}`))
	if err := applyClient.Patch(ctx, existing, patch); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("clear ClusterRole %s rules: %w", name, err)
	}
	return nil
}

//nolint:dupl // RoleBinding subjects and Role rules use mirrored empty-state patch flow for distinct RBAC kinds.
func (r *RestrictedRoleDefinitionReconciler) rrdClearRoleRulesIfEmpty(
	ctx context.Context,
	applyClient client.Client,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	namespace string,
	name string,
	finalRules []rbacv1.PolicyRule,
) error {
	if len(finalRules) > 0 {
		return nil
	}
	existing := &rbacv1.Role{}
	if err := r.ownershipReader().Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, existing); err != nil {
		return client.IgnoreNotFound(err)
	}
	if !hasControllerOwnerRef(existing, rrd) {
		return nil
	}
	if len(existing.Rules) == 0 {
		return nil
	}
	patch := client.RawPatch(types.MergePatchType, []byte(`{"rules":null}`))
	if err := applyClient.Patch(ctx, existing, patch); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("clear Role %s/%s rules: %w", namespace, name, err)
	}
	return nil
}

// rrdDeprovision deletes the managed role.
func (r *RestrictedRoleDefinitionReconciler) rrdDeprovision(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	deleteClient client.Client,
) error {
	logger := log.FromContext(ctx)
	logger.Info("deprovisioning RestrictedRoleDefinition", "name", rrd.Name)
	if deleteClient == nil {
		deleteClient = r.client
	}

	var role client.Object
	switch rrd.Spec.TargetRole {
	case authorizationv1alpha1.DefinitionClusterRole:
		role = &rbacv1.ClusterRole{}
		role.SetName(rrd.Spec.TargetName)
	case authorizationv1alpha1.DefinitionNamespacedRole:
		role = &rbacv1.Role{}
		role.SetName(rrd.Spec.TargetName)
		role.SetNamespace(rrd.Spec.TargetNamespace)
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTargetRole, rrd.Spec.TargetRole)
	}

	if err := r.ownershipReader().Get(ctx, client.ObjectKeyFromObject(role), role); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get %s %s before deprovision: %w", rrd.Spec.TargetRole, rrd.Spec.TargetName, err)
	}
	if !hasControllerOwnerRef(role, rrd) {
		logger.Info("skipping deprovision of target role because it is not owned by this RestrictedRoleDefinition",
			"targetRole", rrd.Spec.TargetRole,
			"targetName", rrd.Spec.TargetName,
			"targetNamespace", rrd.Spec.TargetNamespace,
			"rrd", rrd.Name)
		r.recorder.Eventf(rrd, nil, corev1.EventTypeWarning,
			authorizationv1alpha1.EventReasonOwnership, authorizationv1alpha1.EventActionReconcile,
			"Skipped deprovisioning %s %s because it is not owned by this RestrictedRoleDefinition",
			rrd.Spec.TargetRole, rrd.Spec.TargetName)
		return nil
	}

	if err := deleteClient.Delete(ctx, role); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete %s %s: %w", rrd.Spec.TargetRole, rrd.Spec.TargetName, err)
	}
	switch rrd.Spec.TargetRole {
	case authorizationv1alpha1.DefinitionClusterRole:
		metrics.RBACResourcesDeleted.WithLabelValues(metrics.ResourceClusterRole).Inc()
	case authorizationv1alpha1.DefinitionNamespacedRole:
		metrics.RBACResourcesDeleted.WithLabelValues(metrics.ResourceRole).Inc()
	}

	r.recorder.Eventf(rrd, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonDeprovisioned, authorizationv1alpha1.EventActionReconcile,
		"Deprovisioned owned %s %s", rrd.Spec.TargetRole, rrd.Spec.TargetName)
	return nil
}

// rrdHandleDeletion handles deletion of a RestrictedRoleDefinition.
func (r *RestrictedRoleDefinitionReconciler) rrdHandleDeletion(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
) error {
	logger := log.FromContext(ctx)

	if !controllerutil.ContainsFinalizer(rrd, authorizationv1alpha1.RestrictedRoleDefinitionFinalizer) {
		return nil
	}

	// Delete the managed role.
	if err := r.rrdDeprovision(ctx, rrd, r.client); err != nil {
		return fmt.Errorf("delete cleanup for RestrictedRoleDefinition %s: %w", rrd.Name, err)
	}

	// Clean up metric series.
	metrics.DeletePolicyViolationContribution(metrics.ControllerRestrictedRoleDefinition, rrd.Name)

	// Remove finalizer.
	old := rrd.DeepCopy()
	controllerutil.RemoveFinalizer(rrd, authorizationv1alpha1.RestrictedRoleDefinitionFinalizer)
	if err := r.client.Patch(ctx, rrd, client.MergeFromWithOptions(old, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("remove finalizer from RestrictedRoleDefinition %s: %w", rrd.Name, err)
	}

	logger.V(1).Info("finalizer removed, deletion complete", "name", rrd.Name)
	return nil
}

// rrdMarkStalled marks the RestrictedRoleDefinition as stalled.
func (r *RestrictedRoleDefinitionReconciler) rrdMarkStalled(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	err error,
) {
	logger := log.FromContext(ctx)
	detail := stalledErrorDetail(err)
	logger.V(1).Info("marking RestrictedRoleDefinition as stalled", "name", rrd.Name, "error", err, "detail", detail)
	conditions.MarkStalled(rrd, rrd.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, detail)
	rrd.Status.RoleReconciled = false
	rrd.Status.ObservedGeneration = rrd.Generation
	if updateErr := ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA", "name", rrd.Name)
	}
}

// rrdApplyStatusAndMarkStalled applies current status and marks the RRD as stalled.
func (r *RestrictedRoleDefinitionReconciler) rrdApplyStatusAndMarkStalled(
	ctx context.Context,
	rrd *authorizationv1alpha1.RestrictedRoleDefinition,
	msg string,
) error {
	logger := log.FromContext(ctx)
	conditions.MarkStalled(rrd, rrd.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, msg)
	rrd.Status.RoleReconciled = false
	rrd.Status.ObservedGeneration = rrd.Generation
	if err := ssa.ApplyRestrictedRoleDefinitionStatus(ctx, r.client, rrd); err != nil {
		logger.Error(err, "failed to apply status via SSA", "name", rrd.Name)
		return fmt.Errorf("apply stalled status: %w", err)
	}
	return nil
}

func (r *RestrictedRoleDefinitionReconciler) rrdLogApplyIdentity(
	ctx context.Context,
	resourceName, policyName, impersonatedUser string,
) {
	if impersonatedUser == "" {
		return
	}

	logger := log.FromContext(ctx)
	trace.SpanFromContext(ctx).SetAttributes(tracing.AttrUser.String(impersonatedUser))
	logger.V(2).Info("using impersonated apply identity", "name", resourceName, "impersonatedUser", impersonatedUser, "policy", policyName)
}

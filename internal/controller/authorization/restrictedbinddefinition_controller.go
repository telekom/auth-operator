// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
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
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=rbacpolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete;escalate
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=create;delete;get;list;patch;update;watch
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=impersonate
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=create;patch;update

// RestrictedBindDefinitionReconciler reconciles a RestrictedBindDefinition object.
type RestrictedBindDefinitionReconciler struct {
	client   client.Client
	scheme   *runtime.Scheme
	recorder events.EventRecorder
	tracer   trace.Tracer

	restConfig                *rest.Config
	impersonatedClientFactory impersonatedClientFactory
	impersonatedClientCache   *impersonatedClientCache
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
		client:                    cachedClient,
		scheme:                    scheme,
		recorder:                  recorder,
		impersonatedClientFactory: newImpersonatedClient,
		impersonatedClientCache:   newImpersonatedClientCache(),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// SetupWithManager sets up the controller with the Manager.
func (r *RestrictedBindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	if r.restConfig == nil {
		r.restConfig = mgr.GetConfig()
	}

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
			builder.WithPredicates(namespaceLabelOrPhaseChangePredicate()),
		).
		WithOptions(controller.TypedOptions[reconcile.Request]{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

func (r *RestrictedBindDefinitionReconciler) rbdResolveApplyClient(
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

// policyToRestrictedBindDefinitions maps an RBACPolicy event to reconcile requests
// for all RestrictedBindDefinitions referencing that policy.
func (r *RestrictedBindDefinitionReconciler) policyToRestrictedBindDefinitions(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)
	rbdList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
	defer cancel()
	if err := r.client.List(listCtx, rbdList,
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
// for RestrictedBindDefinitions whose namespace selectors or explicit namespace
// references match the changed namespace.
func (r *RestrictedBindDefinitionReconciler) namespaceToRestrictedBindDefinitions(ctx context.Context, obj client.Object) []reconcile.Request {
	logger := log.FromContext(ctx)

	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		logger.Error(fmt.Errorf("unexpected type"), "Expected *Namespace", "got", fmt.Sprintf("%T", obj))
		return nil
	}

	listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
	defer cancel()

	explicitNamespaceList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	explicitErr := r.client.List(listCtx, explicitNamespaceList,
		client.MatchingFields{indexer.RestrictedBindDefinitionRoleBindingNamespaceField: namespace.Name})

	selectorList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
	selectorErr := r.client.List(listCtx, selectorList,
		client.MatchingFields{indexer.RestrictedBindDefinitionHasNamespaceSelectorField: "true"})

	optimizedIndexPathAvailable := explicitErr == nil && selectorErr == nil
	if !optimizedIndexPathAvailable &&
		(!helpers.IsMissingFieldIndexError(explicitErr) || !helpers.IsMissingFieldIndexError(selectorErr)) {
		if explicitErr != nil {
			logger.Error(explicitErr, "failed to list RestrictedBindDefinitions by explicit namespace index", "namespace", namespace.Name)
		}
		if selectorErr != nil {
			logger.Error(selectorErr, "failed to list RestrictedBindDefinitions by selector index")
		}
		return nil
	}

	if !optimizedIndexPathAvailable {
		logger.V(2).Info("field indexes not available, falling back to full RestrictedBindDefinition scan")
		fullList := &authorizationv1alpha1.RestrictedBindDefinitionList{}
		if err := r.client.List(listCtx, fullList); err != nil {
			logger.Error(err, "failed to list RestrictedBindDefinitions")
			return nil
		}

		requests := make([]reconcile.Request, 0, len(fullList.Items))
		for i := range fullList.Items {
			rbd := &fullList.Items[i]
			if !restrictedBindDefinitionMatchesNamespace(rbd, namespace) {
				metrics.NamespaceFanoutSkipped.Inc()
				continue
			}
			metrics.NamespaceFanoutEnqueued.Inc()
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: rbd.Name},
			})
		}
		return requests
	}

	queued := make(map[string]struct{}, len(explicitNamespaceList.Items)+len(selectorList.Items))
	requests := make([]reconcile.Request, 0, len(explicitNamespaceList.Items)+len(selectorList.Items))
	queueRequest := func(name string) {
		if _, exists := queued[name]; exists {
			return
		}
		queued[name] = struct{}{}
		metrics.NamespaceFanoutEnqueued.Inc()
		requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: name}})
	}

	for i := range explicitNamespaceList.Items {
		queueRequest(explicitNamespaceList.Items[i].Name)
	}

	for i := range selectorList.Items {
		rbd := &selectorList.Items[i]
		if !restrictedBindDefinitionMatchesNamespace(rbd, namespace) {
			metrics.NamespaceFanoutSkipped.Inc()
			continue
		}
		queueRequest(rbd.Name)
	}

	return requests
}

// restrictedBindDefinitionMatchesNamespace returns true if the RBD has any
// roleBinding entry whose explicit namespace or namespace selector matches ns.
func restrictedBindDefinitionMatchesNamespace(rbd *authorizationv1alpha1.RestrictedBindDefinition, ns *corev1.Namespace) bool {
	if len(rbd.Spec.RoleBindings) == 0 {
		return false
	}
	if conditions.IsNamespaceTerminating(ns) {
		return true
	}
	nsLabels := labels.Set(ns.GetLabels())
	selectorCache := make(map[string]labels.Selector)
	for _, rb := range rbd.Spec.RoleBindings {
		if rb.Namespace == ns.Name {
			return true
		}
		for _, sel := range rb.NamespaceSelector {
			cacheKey := metav1.FormatLabelSelector(&sel)
			selector, ok := selectorCache[cacheKey]
			if !ok {
				var err error
				selector, err = metav1.LabelSelectorAsSelector(&sel)
				if err != nil {
					return true
				}
				selectorCache[cacheKey] = selector
			}
			if selector.Matches(nsLabels) {
				return true
			}
		}
	}
	return false
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
				tracing.AttrNamespace.String(req.Namespace),
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
			metrics.DeletePolicyViolationContribution(metrics.ControllerRestrictedBindDefinition, req.Name)
			metrics.RoleRefsMissing.DeleteLabelValues(req.Name)
			metrics.NamespacesActive.DeleteLabelValues(req.Name)
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
			if apierrors.IsConflict(err) {
				logger.V(1).Info("conflict adding finalizer, requeuing", "name", rbd.Name)
				return ctrl.Result{Requeue: true}, nil
			}
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
				authorizationv1alpha1.PolicyCompliantReasonPolicyNotFound, authorizationv1alpha1.PolicyCompliantMessagePolicyNotFound, rbd.Spec.PolicyRef.Name)
			r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
				authorizationv1alpha1.EventReasonPolicyNotFound, authorizationv1alpha1.EventActionReconcile,
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
	violations := policy.EvaluateBindDefinition(ctx, rbacPolicy, rbd, newLabelGetter(r.client))
	if len(violations) > 0 {
		rbd.Status.PolicyViolations = policy.ViolationStrings(violations)
		result, err := handlePolicyViolations(ctx, rbd, rbd.Generation, violations, r.recorder, rbd, ViolationHandlerConfig{
			ControllerLabel: metrics.ControllerRestrictedBindDefinition,
			ResourceKind:    "RestrictedBindDefinition",
			Deprovision:     func(ctx context.Context) error { return r.rbdDeprovision(ctx, rbd) },
			MarkStalled:     func(ctx context.Context, err error) { r.rbdMarkStalled(ctx, rbd, err) },
			SetReconciled:   func(v bool) { rbd.Status.BindReconciled = v },
			ApplyStatus:     func(ctx context.Context) error { return ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd) },
		})
		return result, err
	}

	// Policy compliant.
	markPolicyCompliant(rbd, rbd.Generation, r.recorder, rbd, rbacPolicy.Name, metrics.ControllerRestrictedBindDefinition)
	rbd.Status.PolicyViolations = nil
	applyClient, impersonatedUser, err := r.rbdResolveApplyClient(rbacPolicy)
	if err != nil {
		r.rbdMarkStalled(ctx, rbd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("resolve apply client for RestrictedBindDefinition %s: %w", rbd.Name, err)
	}
	if impersonatedUser != "" {
		trace.SpanFromContext(ctx).SetAttributes(tracing.AttrUser.String(impersonatedUser))
		logger.V(2).Info("using impersonated apply identity", "name", rbd.Name, "impersonatedUser", impersonatedUser, "policy", rbacPolicy.Name)
	}

	// Step 7: Reconcile RBAC resources.
	saCreationConfig := rbdSACreationConfig(rbacPolicy)
	if err := r.rbdReconcileResources(ctx, rbd, applyClient, saCreationConfig); err != nil {
		r.rbdMarkStalled(ctx, rbd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}

	// Step 7.5: Validate role references.
	missingRoles, err := r.rbdValidateRoleReferences(ctx, rbd)
	if err != nil {
		r.rbdMarkStalled(ctx, rbd, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, err
	}
	rbd.Status.MissingRoleRefs = missingRoles
	metrics.RoleRefsMissing.WithLabelValues(rbd.Name).Set(float64(len(missingRoles)))

	// Step 8: Mark Ready.
	// Ready=true is intentional even when missingRoleRefs is non-empty: bindings are
	// created immediately and become effective once referenced roles appear (best-effort,
	// eventually-consistent behaviour). Missing refs are observable via
	// status.missingRoleRefs and the RoleRefsMissing metric. Unlike BindDefinition, no
	// RoleRefsValid condition is emitted here; add one if stricter signalling is needed.
	rbd.Status.BindReconciled = true
	conditions.MarkReady(rbd, rbd.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)

	if err := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); err != nil {
		logger.Error(err, "failed to apply RestrictedBindDefinition status", "name", rbd.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply RestrictedBindDefinition %s status: %w", rbd.Name, err)
	}

	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerRestrictedBindDefinition, metrics.ResultSuccess).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// rbdReconcileResources ensures all RBAC resources for the RestrictedBindDefinition exist.
func (r *RestrictedBindDefinitionReconciler) rbdReconcileResources(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	applyClient client.Client,
	saCreationConfig *authorizationv1alpha1.SACreationConfig,
) error {
	// Ensure ServiceAccounts.
	if err := r.rbdEnsureServiceAccounts(ctx, rbd, applyClient, saCreationConfig); err != nil {
		return err
	}

	// Ensure ClusterRoleBindings.
	desiredCRBs := make(map[string]struct{})
	for _, clusterRoleRef := range restrictedClusterRoleRefs(rbd.Spec.ClusterRoleBindings) {
		crbName := helpers.BuildBindingName(rbd.Spec.TargetName, clusterRoleRef)
		desiredCRBs[crbName] = struct{}{}
		ac := pkgssa.ClusterRoleBindingWithSubjectsAndRoleRef(
			crbName, helpers.BuildResourceLabels(rbd.Labels), rbd.Spec.Subjects,
			rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: clusterRoleRef},
		)
		ac.WithOwnerReferences(ownerRefForRestricted(rbd, "RestrictedBindDefinition")).
			WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))

		if result, err := pkgssa.PatchApplyClusterRoleBinding(ctx, applyClient, ac, pkgssa.FieldOwnerFor(rbd.Name)); err != nil {
			return fmt.Errorf("ensure ClusterRoleBinding %s: %w", crbName, err)
		} else if result == pkgssa.PatchApplyResultSkipped {
			metrics.RBACResourcesSkipped.WithLabelValues(metrics.ResourceClusterRoleBinding).Inc()
		} else {
			metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceClusterRoleBinding).Inc()
		}
	}

	// Ensure RoleBindings.
	desiredRBs := make(map[string]struct{})
	activeNamespaces := make(map[string]struct{})
	for _, roleBinding := range rbd.Spec.RoleBindings {
		targetNamespaces, err := r.rbdResolveNamespaces(ctx, roleBinding)
		if err != nil {
			return fmt.Errorf("resolve namespaces: %w", err)
		}
		for _, ns := range targetNamespaces {
			if conditions.IsNamespaceTerminating(&ns) {
				continue
			}
			activeNamespaces[ns.Name] = struct{}{}
			for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
				if err := r.rbdEnsureRoleBinding(ctx, rbd, ns.Name, clusterRoleRef, "ClusterRole", applyClient); err != nil {
					return err
				}
				desiredRBs[ns.Name+"/"+helpers.BuildBindingName(rbd.Spec.TargetName, clusterRoleRef)] = struct{}{}
			}
			for _, roleRef := range roleBinding.RoleRefs {
				if err := r.rbdEnsureRoleBinding(ctx, rbd, ns.Name, roleRef, "Role", applyClient); err != nil {
					return err
				}
				desiredRBs[ns.Name+"/"+helpers.BuildBindingName(rbd.Spec.TargetName, roleRef)] = struct{}{}
			}
		}
	}

	metrics.NamespacesActive.WithLabelValues(rbd.Name).Set(float64(len(activeNamespaces)))

	// Prune stale owned resources that are no longer in the desired set.
	return r.rbdPruneStaleResources(ctx, rbd, desiredCRBs, desiredRBs)
}

// rbdPruneStaleResources deletes owned ClusterRoleBindings and RoleBindings
// that are no longer in the desired set after a spec change.
func (r *RestrictedBindDefinitionReconciler) rbdPruneStaleResources(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	desiredCRBs map[string]struct{},
	desiredRBs map[string]struct{},
) error {
	logger := log.FromContext(ctx)

	// Prune stale ClusterRoleBindings.
	crbList := &rbacv1.ClusterRoleBindingList{}
	if err := r.client.List(ctx, crbList,
		client.MatchingFields{indexer.RestrictedBindDefinitionOwnerRefField: rbd.Name}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			return fmt.Errorf("list owned ClusterRoleBindings for pruning: %w", err)
		}
		// Index unavailable — fall back to label scan.
		if listErr := r.client.List(ctx, crbList,
			client.MatchingLabels{helpers.ManagedByLabelStandard: helpers.ManagedByValue}); listErr != nil {
			return fmt.Errorf("list ClusterRoleBindings for pruning (fallback): %w", listErr)
		}
	}
	for i := range crbList.Items {
		crb := &crbList.Items[i]
		if !hasOwnerRef(crb, rbd) {
			continue
		}
		if _, ok := desiredCRBs[crb.Name]; !ok {
			logger.Info("pruning stale ClusterRoleBinding", "name", crb.Name, "rbd", rbd.Name)
			if err := r.client.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete stale ClusterRoleBinding %s: %w", crb.Name, err)
			}
			metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceClusterRoleBinding).Inc()
		}
	}

	// Prune stale RoleBindings.
	rbList := &rbacv1.RoleBindingList{}
	if err := r.client.List(ctx, rbList,
		client.MatchingFields{indexer.RestrictedBindDefinitionOwnerRefField: rbd.Name}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			return fmt.Errorf("list owned RoleBindings for pruning: %w", err)
		}
		if listErr := r.client.List(ctx, rbList,
			client.MatchingLabels{helpers.ManagedByLabelStandard: helpers.ManagedByValue}); listErr != nil {
			return fmt.Errorf("list RoleBindings for pruning (fallback): %w", listErr)
		}
	}
	for i := range rbList.Items {
		rb := &rbList.Items[i]
		if !hasOwnerRef(rb, rbd) {
			continue
		}
		key := rb.Namespace + "/" + rb.Name
		if _, ok := desiredRBs[key]; !ok {
			logger.Info("pruning stale RoleBinding", "namespace", rb.Namespace, "name", rb.Name, "rbd", rbd.Name)
			if err := r.client.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete stale RoleBinding %s/%s: %w", rb.Namespace, rb.Name, err)
			}
			metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceRoleBinding).Inc()
		}
	}

	return nil
}

// rbdEnsureServiceAccounts ensures all ServiceAccount subjects exist, tracking
// which were generated vs pre-existing (external).
// AllowAutoCreate and DisableAdoption from saCreationConfig are enforced here.
func (r *RestrictedBindDefinitionReconciler) rbdEnsureServiceAccounts(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	applyClient client.Client,
	saCreationConfig *authorizationv1alpha1.SACreationConfig,
) error {
	logger := log.FromContext(ctx)
	automountToken := ptr.Deref(rbd.Spec.AutomountServiceAccountToken, true)
	var generatedSAs []rbacv1.Subject
	var externalSAs []string

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

		// Check if SA pre-exists and is not owned by any RestrictedBindDefinition.
		existing := &corev1.ServiceAccount{}
		err := r.client.Get(ctx, types.NamespacedName{Name: subject.Name, Namespace: subject.Namespace}, existing)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("get ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
		}

		saExists := err == nil
		if saExists && !isOwnedByRestrictedBindDefinition(existing.OwnerReferences) {
			// SA exists and is not managed by any RestrictedBindDefinition — treat as external.
			externalSAs = append(externalSAs, fmt.Sprintf("%s/%s", subject.Namespace, subject.Name))
			logger.V(1).Info("skipping pre-existing ServiceAccount",
				"serviceAccount", subject.Name, "namespace", subject.Namespace)
			continue
		}

		if !saExists {
			// SA does not exist — check AllowAutoCreate before creating.
			if saCreationConfig == nil || !saCreationConfig.AllowAutoCreate {
				logger.V(1).Info("skipping ServiceAccount creation: AllowAutoCreate is false",
					"serviceAccount", subject.Name, "namespace", subject.Namespace)
				continue
			}
		} else {
			// SA exists and is managed by a RestrictedBindDefinition — verify UID ownership.
			// If the SA's ownerRef points to a DIFFERENT RBD (different UID), taking it
			// over would silently break the other RBD's management. Surface an event and
			// treat the SA as external instead.
			if ownerRBD := findOwningRBDRef(existing.OwnerReferences); ownerRBD != nil && ownerRBD.UID != rbd.UID {
				logger.Info("ServiceAccount owned by a different RestrictedBindDefinition, skipping adoption",
					"serviceAccount", subject.Name, "namespace", subject.Namespace,
					"ownerUID", ownerRBD.UID, "currentUID", rbd.UID)
				r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
					authorizationv1alpha1.EventReasonOwnership, authorizationv1alpha1.EventActionReconcile,
					"ServiceAccount %s/%s is already owned by a different RestrictedBindDefinition (UID: %s)",
					subject.Namespace, subject.Name, ownerRBD.UID)
				externalSAs = append(externalSAs, fmt.Sprintf("%s/%s", subject.Namespace, subject.Name))
				continue
			}
			// Check DisableAdoption.
			if saCreationConfig != nil && saCreationConfig.DisableAdoption {
				logger.V(1).Info("skipping ServiceAccount adoption: DisableAdoption is true",
					"serviceAccount", subject.Name, "namespace", subject.Namespace)
				externalSAs = append(externalSAs, fmt.Sprintf("%s/%s", subject.Namespace, subject.Name))
				continue
			}
		}

		ac := pkgssa.ServiceAccountWith(subject.Name, subject.Namespace,
			helpers.BuildResourceLabels(rbd.Labels), automountToken).
			WithOwnerReferences(ownerRefForRestricted(rbd, "RestrictedBindDefinition")).
			WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))
		if _, err := pkgssa.PatchApplyServiceAccount(ctx, applyClient, ac, pkgssa.FieldOwnerFor(rbd.Name)); err != nil {
			return fmt.Errorf("apply ServiceAccount %s/%s: %w", subject.Namespace, subject.Name, err)
		}
		if !helpers.SubjectExists(generatedSAs, subject) {
			generatedSAs = append(generatedSAs, subject)
		}
	}

	rbd.Status.GeneratedServiceAccounts = generatedSAs
	rbd.Status.ExternalServiceAccounts = externalSAs
	return nil
}

// rbdEnsureRoleBinding ensures a single RoleBinding exists.
func (r *RestrictedBindDefinitionReconciler) rbdEnsureRoleBinding(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
	namespace, roleRef, roleKind string,
	applyClient client.Client,
) error {
	rbName := helpers.BuildBindingName(rbd.Spec.TargetName, roleRef)
	ac := pkgssa.RoleBindingWithSubjectsAndRoleRef(
		rbName, namespace, helpers.BuildResourceLabels(rbd.Labels), rbd.Spec.Subjects,
		rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: roleKind, Name: roleRef},
	)
	ac.WithOwnerReferences(ownerRefForRestricted(rbd, "RestrictedBindDefinition")).
		WithAnnotations(helpers.BuildResourceAnnotations("RestrictedBindDefinition", rbd.Name))

	if result, err := pkgssa.PatchApplyRoleBinding(ctx, applyClient, ac, pkgssa.FieldOwnerFor(rbd.Name)); err != nil {
		return fmt.Errorf("ensure RoleBinding %s/%s: %w", namespace, rbName, err)
	} else if result == pkgssa.PatchApplyResultSkipped {
		metrics.RBACResourcesSkipped.WithLabelValues(metrics.ResourceRoleBinding).Inc()
	} else {
		metrics.RBACResourcesApplied.WithLabelValues(metrics.ResourceRoleBinding).Inc()
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
	if err := r.client.List(ctx, crbList,
		client.MatchingFields{indexer.RestrictedBindDefinitionOwnerRefField: rbd.Name}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			return fmt.Errorf("list ClusterRoleBindings by owner index: %w", err)
		}
		logger.V(2).Info("owner-reference index unavailable for ClusterRoleBinding cleanup, falling back to label scan")
		if listErr := r.client.List(ctx, crbList,
			client.MatchingLabels{helpers.ManagedByLabelStandard: helpers.ManagedByValue}); listErr != nil {
			return fmt.Errorf("list ClusterRoleBindings: %w", listErr)
		}
	}
	for i := range crbList.Items {
		if hasOwnerRef(&crbList.Items[i], rbd) {
			if err := r.client.Delete(ctx, &crbList.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete ClusterRoleBinding %s: %w", crbList.Items[i].Name, err)
			}
		}
	}

	// Delete owned RoleBindings.
	rbList := &rbacv1.RoleBindingList{}
	if err := r.client.List(ctx, rbList,
		client.MatchingFields{indexer.RestrictedBindDefinitionOwnerRefField: rbd.Name}); err != nil {
		if !helpers.IsMissingFieldIndexError(err) {
			return fmt.Errorf("list RoleBindings by owner index: %w", err)
		}
		logger.V(2).Info("owner-reference index unavailable for RoleBinding cleanup, falling back to label scan")
		if listErr := r.client.List(ctx, rbList,
			client.MatchingLabels{helpers.ManagedByLabelStandard: helpers.ManagedByValue}); listErr != nil {
			return fmt.Errorf("list RoleBindings: %w", listErr)
		}
	}
	for i := range rbList.Items {
		if hasOwnerRef(&rbList.Items[i], rbd) {
			if err := r.client.Delete(ctx, &rbList.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete RoleBinding %s/%s: %w", rbList.Items[i].Namespace, rbList.Items[i].Name, err)
			}
		}
	}

	r.recorder.Eventf(rbd, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonDeprovisioned, authorizationv1alpha1.EventActionReconcile,
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

	// Clean up metric series.
	metrics.DeletePolicyViolationContribution(metrics.ControllerRestrictedBindDefinition, rbd.Name)
	metrics.RoleRefsMissing.DeleteLabelValues(rbd.Name)
	metrics.NamespacesActive.DeleteLabelValues(rbd.Name)

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
	detail := stalledErrorDetail(err)
	logger.V(1).Info("marking RestrictedBindDefinition as stalled", "name", rbd.Name, "error", err, "detail", detail)
	conditions.MarkStalled(rbd, rbd.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, detail)
	rbd.Status.BindReconciled = false
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
	rbd.Status.BindReconciled = false
	rbd.Status.ObservedGeneration = rbd.Generation
	if err := ssa.ApplyRestrictedBindDefinitionStatus(ctx, r.client, rbd); err != nil {
		logger.Error(err, "failed to apply status via SSA", "name", rbd.Name)
	}
}

// rbdValidateRoleReferences checks that all referenced ClusterRoles and Roles exist.
// Returns the list of missing references in the format "ClusterRole/<name>" or
// "Role/<namespace>/<name>".
func (r *RestrictedBindDefinitionReconciler) rbdValidateRoleReferences(
	ctx context.Context,
	rbd *authorizationv1alpha1.RestrictedBindDefinition,
) ([]string, error) {
	logger := log.FromContext(ctx)
	missingRoleSet := make(map[string]struct{})
	clusterRoleExists := make(map[string]bool)
	roleExists := make(map[string]bool)

	addMissingRole := func(roleName string, logKeysAndValues ...interface{}) {
		if _, exists := missingRoleSet[roleName]; exists {
			return
		}
		logger.V(1).Info("referenced role not found", logKeysAndValues...)
		missingRoleSet[roleName] = struct{}{}
	}

	// Check ClusterRoleRefs in ClusterRoleBindings.
	for _, clusterRoleRef := range restrictedClusterRoleRefs(rbd.Spec.ClusterRoleBindings) {
		exists, err := r.clusterRoleExists(ctx, clusterRoleRef, clusterRoleExists)
		if err != nil {
			return sortedMissingRoles(missingRoleSet), err
		}
		if !exists {
			addMissingRole(fmt.Sprintf("ClusterRole/%s", clusterRoleRef), "clusterRole", clusterRoleRef)
		}
	}

	// Check ClusterRoleRefs and RoleRefs in RoleBindings.
	for _, roleBinding := range rbd.Spec.RoleBindings {
		for _, clusterRoleRef := range roleBinding.ClusterRoleRefs {
			exists, err := r.clusterRoleExists(ctx, clusterRoleRef, clusterRoleExists)
			if err != nil {
				return sortedMissingRoles(missingRoleSet), err
			}
			if !exists {
				addMissingRole(fmt.Sprintf("ClusterRole/%s", clusterRoleRef), "clusterRole", clusterRoleRef)
			}
		}

		// Resolve namespaces for this roleBinding to check RoleRefs.
		targetNamespaces, err := r.rbdResolveNamespaces(ctx, roleBinding)
		if err != nil {
			return sortedMissingRoles(missingRoleSet), fmt.Errorf("resolve namespaces for roleBinding during validation: %w", err)
		}

		for _, roleRef := range roleBinding.RoleRefs {
			for _, ns := range targetNamespaces {
				if conditions.IsNamespaceTerminating(&ns) {
					continue
				}
				exists, err := r.roleExists(ctx, ns.Name, roleRef, roleExists)
				if err != nil {
					return sortedMissingRoles(missingRoleSet), err
				}
				if !exists {
					addMissingRole(fmt.Sprintf("Role/%s/%s", ns.Name, roleRef), "role", roleRef, "namespace", ns.Name)
				}
			}
		}
	}

	return sortedMissingRoles(missingRoleSet), nil
}

func sortedMissingRoles(missingRoleSet map[string]struct{}) []string {
	missingRoles := make([]string, 0, len(missingRoleSet))
	for roleName := range missingRoleSet {
		missingRoles = append(missingRoles, roleName)
	}
	slices.Sort(missingRoles)
	return missingRoles
}

func restrictedClusterRoleRefs(binding *authorizationv1alpha1.ClusterBinding) []string {
	if binding == nil {
		return nil
	}
	return binding.ClusterRoleRefs
}

func (r *RestrictedBindDefinitionReconciler) clusterRoleExists(
	ctx context.Context,
	clusterRoleRef string,
	cache map[string]bool,
) (bool, error) {
	if exists, ok := cache[clusterRoleRef]; ok {
		return exists, nil
	}

	cr := &rbacv1.ClusterRole{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: clusterRoleRef}, cr); err != nil {
		if apierrors.IsNotFound(err) {
			cache[clusterRoleRef] = false
			return false, nil
		}
		return false, fmt.Errorf("check ClusterRole %q existence: %w", clusterRoleRef, err)
	}

	cache[clusterRoleRef] = true
	return true, nil
}

func (r *RestrictedBindDefinitionReconciler) roleExists(
	ctx context.Context,
	namespace, roleRef string,
	cache map[string]bool,
) (bool, error) {
	cacheKey := fmt.Sprintf("%s/%s", namespace, roleRef)
	if exists, ok := cache[cacheKey]; ok {
		return exists, nil
	}

	role := &rbacv1.Role{}
	if err := r.client.Get(ctx, types.NamespacedName{Name: roleRef, Namespace: namespace}, role); err != nil {
		if apierrors.IsNotFound(err) {
			cache[cacheKey] = false
			return false, nil
		}
		return false, fmt.Errorf("check Role %s/%s existence: %w", namespace, roleRef, err)
	}

	cache[cacheKey] = true
	return true, nil
}

func rbdSACreationConfig(rbacPolicy *authorizationv1alpha1.RBACPolicy) *authorizationv1alpha1.SACreationConfig {
	if rbacPolicy.Spec.SubjectLimits == nil {
		return nil
	}
	if rbacPolicy.Spec.SubjectLimits.ServiceAccountLimits == nil {
		return nil
	}
	return rbacPolicy.Spec.SubjectLimits.ServiceAccountLimits.Creation
}

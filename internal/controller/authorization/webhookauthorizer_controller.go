// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/api/authorization/v1alpha1/applyconfiguration/ssa"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/metrics"
)

// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=webhookauthorizers,verbs=get;list;watch
// +kubebuilder:rbac:groups=authorization.t-caas.telekom.com,resources=webhookauthorizers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch;update
// +kubebuilder:rbac:groups="events.k8s.io",resources=events,verbs=create;patch;update

// WebhookAuthorizerReconciler reconciles a WebhookAuthorizer object.
// It validates the spec, updates status.observedGeneration, sets
// status.authorizerConfigured, and manages Ready/Stalled conditions.
type WebhookAuthorizerReconciler struct {
	client   client.Client
	recorder events.EventRecorder
}

// NewWebhookAuthorizerReconciler creates a new WebhookAuthorizer reconciler.
func NewWebhookAuthorizerReconciler(
	c client.Client,
	recorder events.EventRecorder,
) *WebhookAuthorizerReconciler {
	return &WebhookAuthorizerReconciler{
		client:   c,
		recorder: recorder,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *WebhookAuthorizerReconciler) SetupWithManager(mgr ctrl.Manager, concurrency int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authorizationv1alpha1.WebhookAuthorizer{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: concurrency}).
		Complete(r)
}

// Reconcile handles the reconciliation loop for WebhookAuthorizer resources.
//
// The reconciliation flow:
//  1. Fetch the WebhookAuthorizer (return early if not found)
//  2. Mark as Reconciling
//  3. Validate NamespaceSelector can be parsed
//  4. Optionally validate that matching namespaces exist
//  5. Update status.observedGeneration
//  6. Set status.authorizerConfigured = true
//  7. Mark Ready and apply status via SSA
func (r *WebhookAuthorizerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	startTime := time.Now()
	logger := log.FromContext(ctx)

	logger.V(1).Info("=== Reconcile START ===",
		"webhookAuthorizer", req.Name)

	defer func() {
		duration := time.Since(startTime)
		metrics.ReconcileDuration.WithLabelValues(metrics.ControllerWebhookAuthorizer).Observe(duration.Seconds())
		logger.V(1).Info("=== Reconcile END ===",
			"webhookAuthorizer", req.Name,
			"duration", duration.String())
	}()

	// Step 1: Fetch the WebhookAuthorizer
	wa := &authorizationv1alpha1.WebhookAuthorizer{}
	if err := r.client.Get(ctx, req.NamespacedName, wa); err != nil {
		if apierrors.IsNotFound(err) {
			logger.V(1).Info("WebhookAuthorizer not found (deleted), skipping reconcile",
				"webhookAuthorizer", req.Name)
			metrics.ReconcileTotal.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ResultSkipped).Inc()
			return ctrl.Result{}, nil
		}
		logger.Error(err, "failed to fetch WebhookAuthorizer",
			"webhookAuthorizer", req.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("fetch WebhookAuthorizer %s: %w", req.Name, err)
	}

	// Step 2: Mark as Reconciling
	conditions.MarkReconciling(wa, wa.Generation,
		authorizationv1alpha1.ReconcilingReasonProgressing, authorizationv1alpha1.ReconcilingMessageProgressing)
	wa.Status.ObservedGeneration = wa.Generation

	// Step 3: Validate NamespaceSelector
	if err := r.validateNamespaceSelector(ctx, wa); err != nil {
		r.markStalled(ctx, wa, err)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ErrorTypeValidation).Inc()
		// Return nil — this is a permanent user error. GenerationChangedPredicate
		// will re-reconcile only when the user fixes the spec.
		logger.Error(err, "namespace selector validation failed",
			"webhookAuthorizer", wa.Name)
		return ctrl.Result{}, nil
	}

	// Step 4: Mark as configured and ready
	wa.Status.AuthorizerConfigured = true
	conditions.MarkReady(wa, wa.Generation,
		authorizationv1alpha1.ReadyReasonReconciled, authorizationv1alpha1.ReadyMessageReconciled)

	// Step 5: Apply status via SSA
	if err := ssa.ApplyWebhookAuthorizerStatus(ctx, r.client, wa); err != nil {
		logger.Error(err, "failed to apply status via SSA",
			"webhookAuthorizer", wa.Name)
		metrics.ReconcileTotal.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply WebhookAuthorizer %s status: %w", wa.Name, err)
	}

	r.recorder.Eventf(wa, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonReconciled, authorizationv1alpha1.EventActionReconcile,
		"WebhookAuthorizer %s reconciled successfully", wa.Name)

	metrics.ReconcileTotal.WithLabelValues(metrics.ControllerWebhookAuthorizer, metrics.ResultSuccess).Inc()
	logger.V(1).Info("WebhookAuthorizer reconciled successfully",
		"webhookAuthorizer", wa.Name,
		"generation", wa.Generation)

	return ctrl.Result{}, nil
}

// validateNamespaceSelector validates that the NamespaceSelector can be parsed
// and checks that at least one matching namespace exists (logging a warning if
// no namespaces match).
func (r *WebhookAuthorizerReconciler) validateNamespaceSelector(
	ctx context.Context,
	wa *authorizationv1alpha1.WebhookAuthorizer,
) error {
	logger := log.FromContext(ctx)

	// An empty selector matches everything — valid, skip further validation.
	if len(wa.Spec.NamespaceSelector.MatchLabels) == 0 && len(wa.Spec.NamespaceSelector.MatchExpressions) == 0 {
		logger.V(2).Info("NamespaceSelector is empty, matches all namespaces")
		return nil
	}

	// Parse the LabelSelector
	selector, err := metav1.LabelSelectorAsSelector(&wa.Spec.NamespaceSelector)
	if err != nil {
		return fmt.Errorf("invalid NamespaceSelector: %w", err)
	}

	// Check that at least one namespace matches (using Limit:1 to avoid
	// loading potentially large lists just for a debug message).
	nsList := &corev1.NamespaceList{}
	if err := r.client.List(ctx, nsList, &client.ListOptions{
		LabelSelector: selector,
		Limit:         1,
	}); err != nil {
		return fmt.Errorf("list namespaces for selector validation: %w", err)
	}

	logger.V(2).Info("NamespaceSelector validation",
		"matchingNamespaces", len(nsList.Items),
		"selector", selector.String())

	return nil
}

// markStalled marks the WebhookAuthorizer as stalled with the given error.
func (r *WebhookAuthorizerReconciler) markStalled(
	ctx context.Context,
	wa *authorizationv1alpha1.WebhookAuthorizer,
	err error,
) {
	logger := log.FromContext(ctx)
	conditions.MarkStalled(wa, wa.Generation,
		authorizationv1alpha1.StalledReasonError, authorizationv1alpha1.StalledMessageError, err.Error())
	wa.Status.ObservedGeneration = wa.Generation
	wa.Status.AuthorizerConfigured = false
	if updateErr := ssa.ApplyWebhookAuthorizerStatus(ctx, r.client, wa); updateErr != nil {
		logger.Error(updateErr, "failed to apply Stalled status via SSA",
			"webhookAuthorizer", wa.Name)
	}
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/helpers"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/policy"
)

// mapPolicyToRestrictedRequests is a shared watch mapper for policy-to-restricted resources.
func mapPolicyToRestrictedRequests(
	ctx context.Context,
	c client.Client,
	obj client.Object,
	list client.ObjectList,
	fieldIndex string,
	kind string,
	getItems func() []client.Object,
	getPolicyRef func(client.Object) string,
) []reconcile.Request {
	logger := log.FromContext(ctx)
	listCtx, cancel := context.WithTimeout(ctx, queueAllTimeout)
	defer cancel()

	if err := c.List(listCtx, list, client.MatchingFields{fieldIndex: obj.GetName()}); err != nil {
		if helpers.IsMissingFieldIndexError(err) {
			logger.V(2).Info(fmt.Sprintf("policyRef field index unavailable, falling back to full %s scan", kind), "policy", obj.GetName())
			if listErr := c.List(listCtx, list); listErr != nil {
				logger.Error(listErr, fmt.Sprintf("failed to list %ss for policy", kind), "policy", obj.GetName())
				return nil
			}
			items := getItems()
			requests := make([]reconcile.Request, 0, len(items))
			for _, item := range items {
				if getPolicyRef(item) == obj.GetName() {
					requests = append(requests, reconcile.Request{NamespacedName: types.NamespacedName{Name: item.GetName(), Namespace: item.GetNamespace()}})
				}
			}
			return requests
		}
		logger.Error(err, fmt.Sprintf("failed to list %ss for policy", kind), "policy", obj.GetName())
		return nil
	}

	items := getItems()
	requests := make([]reconcile.Request, len(items))
	for i, item := range items {
		requests[i] = reconcile.Request{NamespacedName: types.NamespacedName{Name: item.GetName(), Namespace: item.GetNamespace()}}
	}
	return requests
}

// restrictedPolicyLifecycleConfig holds the callbacks for the shared restricted policy lifecycle helper.
type restrictedPolicyLifecycleConfig struct {
	ResourceName    string
	ResourceKind    string
	PolicyRefName   string
	ControllerLabel string
	Recorder        events.EventRecorder

	Evaluate                  func(context.Context, *authorizationv1alpha1.RBACPolicy) ([]policy.Violation, error)
	Deprovision               func(context.Context) error
	MarkStalled               func(context.Context, error)
	ApplyStatusAndMarkStalled func(context.Context, string) error
	SetPolicyViolations       func([]string)
	MarkPolicyCompliantFalse  func(reason authorizationv1alpha1.AuthZConditionReason, message authorizationv1alpha1.AuthZConditionMessage, arg string)
}

// RestrictedPolicyObject combines client.Object and conditions.Setter.
// Required interface for handling restricted policy conditions.
type RestrictedPolicyObject interface {
	client.Object
	conditions.Setter
}

func evaluateRestrictedPolicy(
	ctx context.Context,
	cfg restrictedPolicyLifecycleConfig,
	obj RestrictedPolicyObject,
	rbacPolicy *authorizationv1alpha1.RBACPolicy,
) (violations []policy.Violation, handled bool, retErr error) {
	var err error
	violations, err = cfg.Evaluate(ctx, rbacPolicy)
	if err != nil {
		if deprovisionErr := cfg.Deprovision(ctx); deprovisionErr != nil {
			err = errors.Join(err, fmt.Errorf("deprovision after policy selector evaluation failure: %w", deprovisionErr))
		}
		markPolicyEvaluationError(obj, obj.GetGeneration(), err)
		cfg.MarkStalled(ctx, err)
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return nil, true, fmt.Errorf("evaluate policy selectors for %s %s: %w", cfg.ResourceKind, cfg.ResourceName, err)
	}

	if len(violations) == 0 {
		return nil, false, nil
	}

	cfg.SetPolicyViolations(policy.ViolationStrings(violations))
	return violations, true, nil
}

func handleMissingRestrictedPolicy(
	ctx context.Context,
	cfg restrictedPolicyLifecycleConfig,
	obj client.Object,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("referenced RBACPolicy not found", "name", cfg.ResourceName, "policyRef", cfg.PolicyRefName)

	cfg.MarkPolicyCompliantFalse(
		authorizationv1alpha1.PolicyCompliantReasonPolicyNotFound,
		authorizationv1alpha1.PolicyCompliantMessagePolicyNotFound,
		cfg.PolicyRefName,
	)

	cfg.Recorder.Eventf(obj, nil, corev1.EventTypeWarning,
		string(authorizationv1alpha1.EventReasonPolicyNotFound), string(authorizationv1alpha1.EventActionReconcile),
		"Referenced RBACPolicy %q not found", cfg.PolicyRefName)

	cfg.SetPolicyViolations([]string{fmt.Sprintf("policy %q not found", cfg.PolicyRefName)})
	metrics.SetPolicyViolationsActive(cfg.ControllerLabel, cfg.ResourceName, 1)

	if err := cfg.Deprovision(ctx); err != nil {
		cfg.MarkStalled(ctx, err)
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("deprovision %s %s after missing policy %s: %w", cfg.ResourceKind, cfg.ResourceName, cfg.PolicyRefName, err)
	}

	if err := cfg.ApplyStatusAndMarkStalled(ctx, "policy not found"); err != nil {
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply stalled status for %s %s after missing policy %s: %w", cfg.ResourceKind, cfg.ResourceName, cfg.PolicyRefName, err)
	}
	metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultDegraded).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

func handleDeletingRestrictedPolicy(
	ctx context.Context,
	cfg restrictedPolicyLifecycleConfig,
	obj client.Object,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("referenced RBACPolicy is deleting", "name", cfg.ResourceName, "policyRef", cfg.PolicyRefName)

	cfg.MarkPolicyCompliantFalse(
		authorizationv1alpha1.PolicyCompliantReasonPolicyDeleting,
		authorizationv1alpha1.PolicyCompliantMessagePolicyDeleting,
		cfg.PolicyRefName,
	)

	cfg.SetPolicyViolations([]string{fmt.Sprintf("policy %q is being deleted", cfg.PolicyRefName)})
	metrics.SetPolicyViolationsActive(cfg.ControllerLabel, cfg.ResourceName, 1)

	cfg.Recorder.Eventf(obj, nil, corev1.EventTypeWarning,
		string(authorizationv1alpha1.EventReasonPolicyViolation), string(authorizationv1alpha1.EventActionReconcile),
		"Referenced RBACPolicy %q is being deleted", cfg.PolicyRefName)

	if err := cfg.Deprovision(ctx); err != nil {
		cfg.MarkStalled(ctx, err)
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("deprovision %s %s after deleting policy %s: %w", cfg.ResourceKind, cfg.ResourceName, cfg.PolicyRefName, err)
	}

	if err := cfg.ApplyStatusAndMarkStalled(ctx, "policy deleting"); err != nil {
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply stalled status for %s %s after deleting policy %s: %w", cfg.ResourceKind, cfg.ResourceName, cfg.PolicyRefName, err)
	}

	metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultDegraded).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

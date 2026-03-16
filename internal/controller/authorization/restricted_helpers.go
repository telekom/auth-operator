// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1ac "k8s.io/client-go/applyconfigurations/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	conditions "github.com/telekom/auth-operator/pkg/conditions"
	"github.com/telekom/auth-operator/pkg/metrics"
	"github.com/telekom/auth-operator/pkg/policy"
	pkgssa "github.com/telekom/auth-operator/pkg/ssa"
)

// ownerRefForRestricted creates an OwnerReference ApplyConfiguration for a restricted CRD.
// Uses hardcoded GVK to avoid empty APIVersion/Kind after client.Get()
// (TypeMeta is not populated by the API server).
func ownerRefForRestricted(obj client.Object, kind string) *metav1ac.OwnerReferenceApplyConfiguration {
	return pkgssa.OwnerReference(
		authorizationv1alpha1.GroupVersion.String(),
		kind,
		obj.GetName(),
		obj.GetUID(),
		true, // controller
		true, // blockOwnerDeletion
	)
}

// ViolationHandlerConfig holds type-specific callbacks for policy violation handling.
type ViolationHandlerConfig struct {
	// ControllerLabel is the metrics label for this controller.
	ControllerLabel string
	// ResourceKind is the CRD kind name (e.g. "RestrictedBindDefinition").
	ResourceKind string
	// Deprovision removes all managed RBAC resources.
	Deprovision func(context.Context) error
	// MarkStalled marks the resource as stalled with an error.
	MarkStalled func(context.Context, error)
	// SetReconciled sets the type-specific reconciled status field.
	SetReconciled func(bool)
	// ApplyStatus applies the current status via SSA.
	ApplyStatus func(context.Context) error
}

// maxViolationsInMessage is the maximum number of violation strings included in
// condition messages and Kubernetes events. The full list is always available in
// status.policyViolations.
const maxViolationsInMessage = 10

// handlePolicyViolations processes detected policy violations for a restricted resource.
// It marks the resource as non-compliant, deprovisions RBAC resources, and returns
// a requeue result. Returns (result, nil) on success, or (result, error) if
// deprovisioning fails.
func handlePolicyViolations(
	ctx context.Context,
	obj conditions.Setter,
	generation int64,
	violations []policy.Violation,
	recorder events.EventRecorder,
	runtimeObj client.Object,
	cfg ViolationHandlerConfig,
) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	violationStrings := policy.ViolationStrings(violations)
	logger.Info("policy violations detected",
		"name", runtimeObj.GetName(), "violations", violationStrings)

	// Cap the message to avoid oversized condition messages and events.
	// The full list is stored in status.policyViolations.
	msgStrings := violationStrings
	if len(msgStrings) > maxViolationsInMessage {
		msgStrings = append(msgStrings[:maxViolationsInMessage:maxViolationsInMessage],
			fmt.Sprintf("and %d more", len(violationStrings)-maxViolationsInMessage))
	}

	conditions.MarkFalse(obj, authorizationv1alpha1.PolicyCompliantCondition, generation,
		authorizationv1alpha1.PolicyCompliantReasonViolationsDetected, authorizationv1alpha1.PolicyCompliantMessageViolationsDetected, strings.Join(msgStrings, "; "))

	metrics.SetPolicyViolationsActive(cfg.ControllerLabel, runtimeObj.GetName(), float64(len(violations)))

	recorder.Eventf(runtimeObj, nil, corev1.EventTypeWarning,
		authorizationv1alpha1.EventReasonPolicyViolation, authorizationv1alpha1.EventActionReconcile,
		"Policy violations detected: %s", strings.Join(msgStrings, "; "))

	// Deprovision: delete all owned RBAC resources.
	if err := cfg.Deprovision(ctx); err != nil {
		cfg.MarkStalled(ctx, err)
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("deprovision %s %s: %w", cfg.ResourceKind, runtimeObj.GetName(), err)
	}

	cfg.SetReconciled(false)
	conditions.MarkFalse(obj, conditions.ReadyConditionType, generation,
		authorizationv1alpha1.DeprovisionedReason, "deprovisioned due to policy violations")

	if err := cfg.ApplyStatus(ctx); err != nil {
		metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultError).Inc()
		metrics.ReconcileErrors.WithLabelValues(cfg.ControllerLabel, metrics.ErrorTypeAPI).Inc()
		return ctrl.Result{}, fmt.Errorf("apply status after deprovisioning %s %s: %w", cfg.ResourceKind, runtimeObj.GetName(), err)
	}
	metrics.ReconcileTotal.WithLabelValues(cfg.ControllerLabel, metrics.ResultDegraded).Inc()
	return ctrl.Result{RequeueAfter: DefaultRequeueInterval}, nil
}

// markPolicyCompliant marks a restricted resource as policy-compliant and records an event.
func markPolicyCompliant(
	obj conditions.Setter,
	generation int64,
	recorder events.EventRecorder,
	runtimeObj client.Object,
	policyName string,
	controllerLabel string,
) {
	conditions.MarkTrue(obj, authorizationv1alpha1.PolicyCompliantCondition, generation,
		authorizationv1alpha1.PolicyCompliantReasonAllChecksPass, authorizationv1alpha1.PolicyCompliantMessageAllChecksPass)

	metrics.SetPolicyViolationsActive(controllerLabel, runtimeObj.GetName(), 0)

	recorder.Eventf(runtimeObj, nil, corev1.EventTypeNormal,
		authorizationv1alpha1.EventReasonPolicyCompliance, authorizationv1alpha1.EventActionReconcile,
		"All policy checks passed for RBACPolicy %q", policyName)
}

// isOwnedByRestrictedBindDefinition checks whether the given owner references
// contain an entry for a RestrictedBindDefinition resource.
func isOwnedByRestrictedBindDefinition(ownerReferences []metav1.OwnerReference) bool {
	for _, ref := range ownerReferences {
		if ref.Kind == "RestrictedBindDefinition" && ref.APIVersion == authorizationv1alpha1.GroupVersion.String() {
			return true
		}
	}
	return false
}

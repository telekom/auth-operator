// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// kstatus condition types as defined by:
// https://github.com/kubernetes-sigs/cli-utils/blob/master/pkg/kstatus/README.md
const (
	// ReadyConditionType is the kstatus Ready condition type.
	ReadyConditionType ConditionType = "Ready"
	// ReconcilingConditionType is the kstatus Reconciling condition type (abnormal-true).
	ReconcilingConditionType ConditionType = "Reconciling"
	// StalledConditionType is the kstatus Stalled condition type (abnormal-true).
	StalledConditionType ConditionType = "Stalled"
)

// ObservedGenerationSetter is an interface for objects that track observed generation.
type ObservedGenerationSetter interface {
	Setter
	SetObservedGeneration(gen int64)
}

// MarkReady sets the Ready condition to True and removes Reconciling/Stalled conditions.
// This indicates the resource is fully reconciled.
func MarkReady(to Setter, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	MarkTrue(to, ReadyConditionType, gen, reason, message, messageArgs...)
	// Remove abnormal-true conditions when ready
	Delete(to, ReconcilingConditionType)
	Delete(to, StalledConditionType)
}

// MarkNotReady sets the Ready condition to False.
// This indicates the resource is not yet fully reconciled.
func MarkNotReady(to Setter, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	MarkFalse(to, ReadyConditionType, gen, reason, message, messageArgs...)
}

// MarkReconciling sets the Reconciling condition to True and Ready to False.
// This indicates the controller is actively working on reconciling the resource.
// Following the "abnormal-true" pattern - present when reconciling.
func MarkReconciling(to Setter, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	MarkTrue(to, ReconcilingConditionType, gen, reason, message, messageArgs...)
	MarkFalse(to, ReadyConditionType, gen, reason, message, messageArgs...)
	// Clear stalled if we're making progress
	Delete(to, StalledConditionType)
}

// MarkStalled sets the Stalled condition to True and Ready to False.
// This indicates the controller has encountered an error or made insufficient progress.
// Following the "abnormal-true" pattern - present when stalled.
func MarkStalled(to Setter, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	MarkTrue(to, StalledConditionType, gen, reason, message, messageArgs...)
	MarkFalse(to, ReadyConditionType, gen, reason, message, messageArgs...)
	// Clear reconciling if we're stalled
	Delete(to, ReconcilingConditionType)
}

// IsReady returns true if the Ready condition is True.
func IsReady(from Getter) bool {
	cond := Get(from, ReadyConditionType)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// IsReconciling returns true if the Reconciling condition is True.
func IsReconciling(from Getter) bool {
	cond := Get(from, ReconcilingConditionType)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

// IsStalled returns true if the Stalled condition is True.
func IsStalled(from Getter) bool {
	cond := Get(from, StalledConditionType)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

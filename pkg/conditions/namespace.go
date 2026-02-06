package conditions

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// namespaceWrapper is a wrapper around corev1.Namespace to implement Setter interface.
type namespaceWrapper struct {
	*corev1.Namespace
}

var _ Setter = &namespaceWrapper{}

// NewNamespaceWrapper creates a new Setter wrapper around a Namespace.
func NewNamespaceWrapper(ns *corev1.Namespace) Setter {
	return &namespaceWrapper{ns}
}

// GetConditions returns the conditions from the namespace status.
func (nw *namespaceWrapper) GetConditions() []metav1.Condition {
	if nw.Namespace == nil {
		return nil
	}

	result := make([]metav1.Condition, len(nw.Status.Conditions))
	for i, c := range nw.Status.Conditions {
		result[i] = metav1.Condition{
			Type:               string(c.Type),
			Status:             metav1.ConditionStatus(c.Status),
			LastTransitionTime: c.LastTransitionTime,
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
	return result
}

// SetConditions sets the conditions on the namespace status.
func (nw *namespaceWrapper) SetConditions(conditions []metav1.Condition) {
	if nw.Namespace == nil {
		return
	}
	nw.Status.Conditions = make([]corev1.NamespaceCondition, len(conditions))
	for i, c := range conditions {
		nw.Status.Conditions[i] = corev1.NamespaceCondition{
			Type:               corev1.NamespaceConditionType(c.Type),
			Status:             corev1.ConditionStatus(c.Status),
			LastTransitionTime: c.LastTransitionTime,
			Reason:             c.Reason,
			Message:            c.Message,
		}
	}
}

// IsNamespaceTerminating checks if a namespace is in the terminating phase.
// This is a common check used across controllers to skip operations
// on namespaces that are being deleted.
func IsNamespaceTerminating(ns *corev1.Namespace) bool {
	return ns != nil && ns.Status.Phase == corev1.NamespaceTerminating
}

// IsNamespaceActive checks if a namespace is active (not terminating).
// This is the inverse of IsNamespaceTerminating for cleaner code.
func IsNamespaceActive(ns *corev1.Namespace) bool {
	return ns != nil && ns.Status.Phase != corev1.NamespaceTerminating
}

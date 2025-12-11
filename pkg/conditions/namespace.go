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

func NewNamespaceWrapper(ns *corev1.Namespace) Setter {
	return &namespaceWrapper{ns}
}

func (nw *namespaceWrapper) GetConditions() []metav1.Condition {
	if nw.Namespace == nil {
		return nil
	}

	result := make([]metav1.Condition, len(nw.Namespace.Status.Conditions))
	for i, c := range nw.Namespace.Status.Conditions {
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

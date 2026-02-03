package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Getter is an interface for objects that have conditions.
type Getter interface {
	client.Object
	GetConditions() []metav1.Condition
}

// Get returns the condition with the given type from the object, or nil if not found.
func Get(from Getter, t ConditionType) *metav1.Condition {
	conditions := from.GetConditions()
	if conditions == nil {
		return nil
	}

	for _, condition := range conditions {
		if ConditionType(condition.Type) == t {
			return &condition
		}
	}

	return nil
}

// Has returns true if the object has a condition with the given type.
func Has(from Getter, t ConditionType) bool {
	return Get(from, t) != nil
}

// IsTrue returns true if the condition with the given type has status True.
func IsTrue(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionTrue
	}
	return false
}

// IsFalse returns true if the condition with the given type has status False.
func IsFalse(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionFalse
	}
	return false
}

// IsUnknown returns true if the condition with the given type has status Unknown or does not exist.
func IsUnknown(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionUnknown
	}
	return true
}

// GetObservedGeneration returns the observed generation from the condition, or 0 if not found.
func GetObservedGeneration(from Getter, t ConditionType) int64 {
	if c := Get(from, t); c != nil {
		return c.ObservedGeneration
	}
	return 0
}

// GetLastTransitionTime returns the last transition time from the condition, or nil if not found.
func GetLastTransitionTime(from Getter, t ConditionType) *metav1.Time {
	if c := Get(from, t); c != nil {
		return &c.LastTransitionTime
	}
	return nil
}

// GetReason returns the reason from the condition, or empty string if not found.
func GetReason(from Getter, t ConditionType) string {
	if c := Get(from, t); c != nil {
		return c.Reason
	}
	return ""
}

// GetMessage returns the message from the condition, or empty string if not found.
func GetMessage(from Getter, t ConditionType) string {
	if c := Get(from, t); c != nil {
		return c.Message
	}
	return ""
}

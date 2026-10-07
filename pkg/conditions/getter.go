package conditions

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Getter is an interface for objects that have conditions.
type Getter interface {
	GetConditions() []metav1.Condition
}

// Get returns the condition with the given type from the object, or nil if not found.
func Get(from Getter, t ConditionType) *metav1.Condition {
	if condition := meta.FindStatusCondition(from.GetConditions(), string(t)); condition != nil {
		// Keep the returned condition detached from the object's status.
		return condition.DeepCopy()
	}

	return nil
}

// Has returns true if the object has a condition with the given type.
func Has(from Getter, t ConditionType) bool {
	return Get(from, t) != nil
}

// IsTrue returns true if the condition with the given type has status True.
func IsTrue(from Getter, t ConditionType) bool {
	return meta.IsStatusConditionTrue(from.GetConditions(), string(t))
}

// IsFalse returns true if the condition with the given type has status False.
func IsFalse(from Getter, t ConditionType) bool {
	return meta.IsStatusConditionFalse(from.GetConditions(), string(t))
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

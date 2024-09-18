package conditions

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Getter interface {
	client.Object
	GetConditions() []metav1.Condition
}

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

func Has(from Getter, t ConditionType) bool {
	return Get(from, t) != nil
}

func IsTrue(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionTrue
	}
	return false
}

func IsFalse(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionFalse
	}
	return false
}

func IsUnknown(from Getter, t ConditionType) bool {
	if c := Get(from, t); c != nil {
		return c.Status == metav1.ConditionUnknown
	}
	return true
}

func GetObservedGeneration(from Getter, t ConditionType) int64 {
	if c := Get(from, t); c != nil {
		return c.ObservedGeneration
	}
	return 0
}

func GetLastTransitionTime(from Getter, t ConditionType) *metav1.Time {
	if c := Get(from, t); c != nil {
		return &c.LastTransitionTime
	}
	return nil
}

func GetReason(from Getter, t ConditionType) string {
	if c := Get(from, t); c != nil {
		return c.Reason
	}
	return ""
}

func GetMessage(from Getter, t ConditionType) string {
	if c := Get(from, t); c != nil {
		return c.Message
	}
	return ""
}

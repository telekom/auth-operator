package conditions

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Setter is an interface for objects that can have conditions set.
type Setter interface {
	Getter
	SetConditions([]metav1.Condition)
}

// Set sets or updates a condition on the object.
func Set(to Setter, condition *metav1.Condition) {
	if to == nil || condition == nil {
		return
	}

	conditions := to.GetConditions()
	exists := false
	for i := range conditions {
		existingCondition := conditions[i]
		if existingCondition.Type == condition.Type {
			exists = true
			if !hasSameState(&existingCondition, condition) {
				condition.LastTransitionTime = metav1.NewTime(time.Now().UTC().Truncate(time.Second))
				conditions[i] = *condition
				break
			}
			condition.LastTransitionTime = existingCondition.LastTransitionTime
			break
		}
	}

	if !exists {
		if condition.LastTransitionTime.IsZero() {
			condition.LastTransitionTime = metav1.NewTime(time.Now().UTC().Truncate(time.Second))
		}
		conditions = append(conditions, *condition)
	}

	to.SetConditions(conditions)
}

// TrueCondition creates a new condition with status True.
func TrueCondition(
	t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

// FalseCondition creates a new condition with status False.
func FalseCondition(
	t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

// UnknownCondition creates a new condition with status Unknown.
func UnknownCondition(
	t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionUnknown,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

// MarkTrue sets a condition with status True on the object.
func MarkTrue(
	to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) {
	Set(to, TrueCondition(t, gen, reason, message, messageArgs...))
}

// MarkFalse sets a condition with status False on the object.
func MarkFalse(
	to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) {
	Set(to, FalseCondition(t, gen, reason, message, messageArgs...))
}

// MarkUnknown sets a condition with status Unknown on the object.
func MarkUnknown(
	to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{},
) {
	Set(to, UnknownCondition(t, gen, reason, message, messageArgs...))
}

// Delete removes a condition with the given type from the object.
func Delete(to Setter, t ConditionType) {
	if to == nil {
		return
	}

	conditions := to.GetConditions()
	newConditions := make([]metav1.Condition, 0, len(conditions))
	for _, condition := range conditions {
		if condition.Type != string(t) {
			newConditions = append(newConditions, condition)
		}
	}
	to.SetConditions(newConditions)
}

func hasSameState(i, j *metav1.Condition) bool {
	return i.Type == j.Type &&
		i.Status == j.Status &&
		i.ObservedGeneration == j.ObservedGeneration &&
		i.Reason == j.Reason &&
		i.Message == j.Message
}

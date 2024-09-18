package conditions

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Setter interface {
	Getter
	SetConditions([]metav1.Condition)
}

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

func TrueCondition(t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionTrue,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

func FalseCondition(t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionFalse,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

func UnknownCondition(t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) *metav1.Condition {
	return &metav1.Condition{
		Type:               string(t),
		Status:             metav1.ConditionUnknown,
		ObservedGeneration: gen,
		Reason:             string(reason),
		Message:            fmt.Sprintf(string(message), messageArgs...),
	}
}

func MarkTrue(to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	Set(to, TrueCondition(t, gen, reason, message, messageArgs...))
}

func MarkFalse(to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	Set(to, FalseCondition(t, gen, reason, message, messageArgs...))
}

func MarkUnknown(to Setter, t ConditionType, gen int64, reason ConditionReason, message ConditionMessage, messageArgs ...interface{}) {
	Set(to, UnknownCondition(t, gen, reason, message, messageArgs...))
}

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

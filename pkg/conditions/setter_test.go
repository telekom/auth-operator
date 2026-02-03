/*
Copyright © 2026 Deutsche Telekom AG
*/
package conditions

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSet(t *testing.T) {
	t.Run("set new condition", func(t *testing.T) {
		obj := &testObject{}
		cond := &metav1.Condition{
			Type:    string(TestConditionType),
			Status:  metav1.ConditionTrue,
			Reason:  "TestReason",
			Message: "Test message",
		}

		Set(obj, cond)

		if len(obj.conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
		}
		if obj.conditions[0].Type != string(TestConditionType) {
			t.Errorf("condition type = %q, want %q", obj.conditions[0].Type, TestConditionType)
		}
		if obj.conditions[0].LastTransitionTime.IsZero() {
			t.Error("LastTransitionTime should be set")
		}
	})

	t.Run("update condition with same state preserves LastTransitionTime", func(t *testing.T) {
		now := metav1.Now()
		obj := &testObject{conditions: []metav1.Condition{
			{
				Type:               string(TestConditionType),
				Status:             metav1.ConditionTrue,
				Reason:             "TestReason",
				Message:            "Test message",
				LastTransitionTime: now,
			},
		}}

		// Set condition with same state
		cond := &metav1.Condition{
			Type:    string(TestConditionType),
			Status:  metav1.ConditionTrue,
			Reason:  "TestReason",
			Message: "Test message",
		}

		Set(obj, cond)

		if len(obj.conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
		}
		if !obj.conditions[0].LastTransitionTime.Equal(&now) {
			t.Error("LastTransitionTime should be preserved when state doesn't change")
		}
	})

	t.Run("update condition with different state updates LastTransitionTime", func(t *testing.T) {
		oldTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))
		obj := &testObject{conditions: []metav1.Condition{
			{
				Type:               string(TestConditionType),
				Status:             metav1.ConditionTrue,
				Reason:             "TestReason",
				Message:            "Test message",
				LastTransitionTime: oldTime,
			},
		}}

		// Set condition with different state
		cond := &metav1.Condition{
			Type:    string(TestConditionType),
			Status:  metav1.ConditionFalse, // Changed status
			Reason:  "NewReason",
			Message: "New message",
		}

		Set(obj, cond)

		if len(obj.conditions) != 1 {
			t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
		}
		if obj.conditions[0].LastTransitionTime.Equal(&oldTime) {
			t.Error("LastTransitionTime should be updated when state changes")
		}
	})

	t.Run("nil object or condition is no-op", func(t *testing.T) {
		Set(nil, &metav1.Condition{})
		obj := &testObject{}
		Set(obj, nil)
		if len(obj.conditions) != 0 {
			t.Error("expected no conditions after nil set")
		}
	})
}

func TestTrueCondition(t *testing.T) {
	cond := TrueCondition(TestConditionType, 1, TestReason, TestMessage, "arg1")

	if cond.Type != string(TestConditionType) {
		t.Errorf("Type = %q, want %q", cond.Type, TestConditionType)
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want %v", cond.Status, metav1.ConditionTrue)
	}
	if cond.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %d, want 1", cond.ObservedGeneration)
	}
	if cond.Reason != string(TestReason) {
		t.Errorf("Reason = %q, want %q", cond.Reason, TestReason)
	}
	if cond.Message != "Test message: arg1" {
		t.Errorf("Message = %q, want %q", cond.Message, "Test message: arg1")
	}
}

func TestFalseCondition(t *testing.T) {
	cond := FalseCondition(TestConditionType, 2, TestReason, TestMessage, "arg2")

	if cond.Status != metav1.ConditionFalse {
		t.Errorf("Status = %v, want %v", cond.Status, metav1.ConditionFalse)
	}
	if cond.ObservedGeneration != 2 {
		t.Errorf("ObservedGeneration = %d, want 2", cond.ObservedGeneration)
	}
	if cond.Message != "Test message: arg2" {
		t.Errorf("Message = %q, want %q", cond.Message, "Test message: arg2")
	}
}

func TestUnknownCondition(t *testing.T) {
	cond := UnknownCondition(TestConditionType, 3, TestReason, TestMessage, "arg3")

	if cond.Status != metav1.ConditionUnknown {
		t.Errorf("Status = %v, want %v", cond.Status, metav1.ConditionUnknown)
	}
	if cond.ObservedGeneration != 3 {
		t.Errorf("ObservedGeneration = %d, want 3", cond.ObservedGeneration)
	}
}

func TestMarkTrue(t *testing.T) {
	obj := &testObject{}
	MarkTrue(obj, TestConditionType, 1, TestReason, TestMessage, "marked")

	if len(obj.conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
	}
	if obj.conditions[0].Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want %v", obj.conditions[0].Status, metav1.ConditionTrue)
	}
}

func TestMarkFalse(t *testing.T) {
	obj := &testObject{}
	MarkFalse(obj, TestConditionType, 1, TestReason, TestMessage, "marked")

	if len(obj.conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
	}
	if obj.conditions[0].Status != metav1.ConditionFalse {
		t.Errorf("Status = %v, want %v", obj.conditions[0].Status, metav1.ConditionFalse)
	}
}

func TestMarkUnknown(t *testing.T) {
	obj := &testObject{}
	MarkUnknown(obj, TestConditionType, 1, TestReason, TestMessage, "marked")

	if len(obj.conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(obj.conditions))
	}
	if obj.conditions[0].Status != metav1.ConditionUnknown {
		t.Errorf("Status = %v, want %v", obj.conditions[0].Status, metav1.ConditionUnknown)
	}
}

func TestDelete(t *testing.T) {
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue},
		{Type: string(OtherConditionType), Status: metav1.ConditionFalse},
	}}

	Delete(obj, TestConditionType)

	if len(obj.conditions) != 1 {
		t.Fatalf("expected 1 condition after delete, got %d", len(obj.conditions))
	}
	if obj.conditions[0].Type != string(OtherConditionType) {
		t.Errorf("remaining condition type = %q, want %q", obj.conditions[0].Type, OtherConditionType)
	}
}

func TestDeleteNilObject(t *testing.T) {
	// Should not panic
	Delete(nil, TestConditionType)
}

func TestHasSameState(t *testing.T) {
	tests := []struct {
		name string
		i, j *metav1.Condition
		want bool
	}{
		{
			name: "same state",
			i: &metav1.Condition{
				Type:               "Test",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "Reason",
				Message:            "Message",
			},
			j: &metav1.Condition{
				Type:               "Test",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
				Reason:             "Reason",
				Message:            "Message",
			},
			want: true,
		},
		{
			name: "different status",
			i: &metav1.Condition{
				Type:   "Test",
				Status: metav1.ConditionTrue,
			},
			j: &metav1.Condition{
				Type:   "Test",
				Status: metav1.ConditionFalse,
			},
			want: false,
		},
		{
			name: "different reason",
			i: &metav1.Condition{
				Type:   "Test",
				Status: metav1.ConditionTrue,
				Reason: "Reason1",
			},
			j: &metav1.Condition{
				Type:   "Test",
				Status: metav1.ConditionTrue,
				Reason: "Reason2",
			},
			want: false,
		},
		{
			name: "different message",
			i: &metav1.Condition{
				Type:    "Test",
				Status:  metav1.ConditionTrue,
				Message: "Message1",
			},
			j: &metav1.Condition{
				Type:    "Test",
				Status:  metav1.ConditionTrue,
				Message: "Message2",
			},
			want: false,
		},
		{
			name: "different observedGeneration",
			i: &metav1.Condition{
				Type:               "Test",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
			},
			j: &metav1.Condition{
				Type:               "Test",
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 2,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSameState(tt.i, tt.j)
			if got != tt.want {
				t.Errorf("hasSameState() = %v, want %v", got, tt.want)
			}
		})
	}
}

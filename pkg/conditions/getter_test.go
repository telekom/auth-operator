/*
Copyright © 2026 Deutsche Telekom AG
*/
package conditions

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

// testObject implements both Getter and Setter interfaces for testing
type testObject struct {
	conditions []metav1.Condition
}

func (t *testObject) GetConditions() []metav1.Condition {
	return t.conditions
}

func (t *testObject) SetConditions(conditions []metav1.Condition) {
	t.conditions = conditions
}

// Implement client.Object interface requirements
func (t *testObject) GetObjectKind() schema.ObjectKind                           { return nil }
func (t *testObject) DeepCopyObject() runtime.Object                             { return nil }
func (t *testObject) GetNamespace() string                                       { return "" }
func (t *testObject) SetNamespace(namespace string)                              {}
func (t *testObject) GetName() string                                            { return "test" }
func (t *testObject) SetName(name string)                                        {}
func (t *testObject) GetGenerateName() string                                    { return "" }
func (t *testObject) SetGenerateName(name string)                                {}
func (t *testObject) GetUID() types.UID                                          { return "" }
func (t *testObject) SetUID(uid types.UID)                                       {}
func (t *testObject) GetResourceVersion() string                                 { return "" }
func (t *testObject) SetResourceVersion(version string)                          {}
func (t *testObject) GetGeneration() int64                                       { return 0 }
func (t *testObject) SetGeneration(generation int64)                             {}
func (t *testObject) GetSelfLink() string                                        { return "" }
func (t *testObject) SetSelfLink(selfLink string)                                {}
func (t *testObject) GetCreationTimestamp() metav1.Time                          { return metav1.Time{} }
func (t *testObject) SetCreationTimestamp(timestamp metav1.Time)                 {}
func (t *testObject) GetDeletionTimestamp() *metav1.Time                         { return nil }
func (t *testObject) SetDeletionTimestamp(timestamp *metav1.Time)                {}
func (t *testObject) GetDeletionGracePeriodSeconds() *int64                      { return nil }
func (t *testObject) SetDeletionGracePeriodSeconds(i *int64)                     {}
func (t *testObject) GetLabels() map[string]string                               { return nil }
func (t *testObject) SetLabels(labels map[string]string)                         {}
func (t *testObject) GetAnnotations() map[string]string                          { return nil }
func (t *testObject) SetAnnotations(annotations map[string]string)               {}
func (t *testObject) GetFinalizers() []string                                    { return nil }
func (t *testObject) SetFinalizers(finalizers []string)                          {}
func (t *testObject) GetOwnerReferences() []metav1.OwnerReference                { return nil }
func (t *testObject) SetOwnerReferences([]metav1.OwnerReference)                 {}
func (t *testObject) GetManagedFields() []metav1.ManagedFieldsEntry              { return nil }
func (t *testObject) SetManagedFields(managedFields []metav1.ManagedFieldsEntry) {}

const (
	TestConditionType  ConditionType    = "TestCondition"
	OtherConditionType ConditionType    = "OtherCondition"
	TestReason         ConditionReason  = "TestReason"
	TestMessage        ConditionMessage = "Test message: %s"
)

func TestGet(t *testing.T) {
	now := metav1.Now()
	tests := []struct {
		name       string
		conditions []metav1.Condition
		condType   ConditionType
		wantNil    bool
		wantStatus metav1.ConditionStatus
	}{
		{
			name:       "nil conditions returns nil",
			conditions: nil,
			condType:   TestConditionType,
			wantNil:    true,
		},
		{
			name:       "empty conditions returns nil",
			conditions: []metav1.Condition{},
			condType:   TestConditionType,
			wantNil:    true,
		},
		{
			name: "condition not found",
			conditions: []metav1.Condition{
				{Type: string(OtherConditionType), Status: metav1.ConditionTrue},
			},
			condType: TestConditionType,
			wantNil:  true,
		},
		{
			name: "condition found - True",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionTrue, LastTransitionTime: now},
			},
			condType:   TestConditionType,
			wantNil:    false,
			wantStatus: metav1.ConditionTrue,
		},
		{
			name: "condition found - False",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionFalse, LastTransitionTime: now},
			},
			condType:   TestConditionType,
			wantNil:    false,
			wantStatus: metav1.ConditionFalse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &testObject{conditions: tt.conditions}
			got := Get(obj, tt.condType)
			if tt.wantNil {
				if got != nil {
					t.Errorf("Get() = %v, want nil", got)
				}
			} else {
				if got == nil {
					t.Error("Get() = nil, want non-nil")
				} else if got.Status != tt.wantStatus {
					t.Errorf("Get().Status = %v, want %v", got.Status, tt.wantStatus)
				}
			}
		})
	}
}

func TestHas(t *testing.T) {
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue},
	}}

	if !Has(obj, TestConditionType) {
		t.Error("Has() = false, want true for existing condition")
	}
	if Has(obj, OtherConditionType) {
		t.Error("Has() = true, want false for non-existing condition")
	}
}

func TestIsTrue(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		want       bool
	}{
		{
			name:       "no conditions",
			conditions: nil,
			want:       false,
		},
		{
			name: "condition true",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionTrue},
			},
			want: true,
		},
		{
			name: "condition false",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionFalse},
			},
			want: false,
		},
		{
			name: "condition unknown",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionUnknown},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &testObject{conditions: tt.conditions}
			if got := IsTrue(obj, TestConditionType); got != tt.want {
				t.Errorf("IsTrue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsFalse(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		want       bool
	}{
		{
			name:       "no conditions",
			conditions: nil,
			want:       false,
		},
		{
			name: "condition true",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionTrue},
			},
			want: false,
		},
		{
			name: "condition false",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionFalse},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &testObject{conditions: tt.conditions}
			if got := IsFalse(obj, TestConditionType); got != tt.want {
				t.Errorf("IsFalse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsUnknown(t *testing.T) {
	tests := []struct {
		name       string
		conditions []metav1.Condition
		want       bool
	}{
		{
			name:       "no conditions - returns true (default unknown)",
			conditions: nil,
			want:       true,
		},
		{
			name: "condition true",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionTrue},
			},
			want: false,
		},
		{
			name: "condition unknown",
			conditions: []metav1.Condition{
				{Type: string(TestConditionType), Status: metav1.ConditionUnknown},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &testObject{conditions: tt.conditions}
			if got := IsUnknown(obj, TestConditionType); got != tt.want {
				t.Errorf("IsUnknown() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetObservedGeneration(t *testing.T) {
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue, ObservedGeneration: 5},
	}}

	if got := GetObservedGeneration(obj, TestConditionType); got != 5 {
		t.Errorf("GetObservedGeneration() = %v, want 5", got)
	}
	if got := GetObservedGeneration(obj, OtherConditionType); got != 0 {
		t.Errorf("GetObservedGeneration() for missing = %v, want 0", got)
	}
}

func TestGetReason(t *testing.T) {
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue, Reason: "TestReason"},
	}}

	if got := GetReason(obj, TestConditionType); got != "TestReason" {
		t.Errorf("GetReason() = %q, want %q", got, "TestReason")
	}
	if got := GetReason(obj, OtherConditionType); got != "" {
		t.Errorf("GetReason() for missing = %q, want empty", got)
	}
}

func TestGetMessage(t *testing.T) {
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue, Message: "Test message"},
	}}

	if got := GetMessage(obj, TestConditionType); got != "Test message" {
		t.Errorf("GetMessage() = %q, want %q", got, "Test message")
	}
	if got := GetMessage(obj, OtherConditionType); got != "" {
		t.Errorf("GetMessage() for missing = %q, want empty", got)
	}
}

func TestGetLastTransitionTime(t *testing.T) {
	now := metav1.Now()
	obj := &testObject{conditions: []metav1.Condition{
		{Type: string(TestConditionType), Status: metav1.ConditionTrue, LastTransitionTime: now},
	}}

	got := GetLastTransitionTime(obj, TestConditionType)
	if got == nil {
		t.Fatal("GetLastTransitionTime() = nil, want non-nil")
	}
	if !got.Equal(&now) {
		t.Errorf("GetLastTransitionTime() = %v, want %v", got, now)
	}
	if got := GetLastTransitionTime(obj, OtherConditionType); got != nil {
		t.Errorf("GetLastTransitionTime() for missing = %v, want nil", got)
	}
}

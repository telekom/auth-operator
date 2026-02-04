// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMarkReady(t *testing.T) {
	t.Run("should set Ready=True and remove Reconciling/Stalled", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Setup: first mark as reconciling
		MarkReconciling(obj, 1, "Progressing", "Working")
		if !IsReconciling(obj) {
			t.Error("expected IsReconciling to be true")
		}
		if IsReady(obj) {
			t.Error("expected IsReady to be false")
		}

		// Now mark ready
		MarkReady(obj, 1, "Reconciled", "Done")

		if !IsReady(obj) {
			t.Error("expected IsReady to be true after MarkReady")
		}
		if IsReconciling(obj) {
			t.Error("expected IsReconciling to be false after MarkReady")
		}
		if IsStalled(obj) {
			t.Error("expected IsStalled to be false after MarkReady")
		}
	})

	t.Run("should clear Stalled condition when marking Ready", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Setup: first mark as stalled
		MarkStalled(obj, 1, "Error", "Something went wrong")
		if !IsStalled(obj) {
			t.Error("expected IsStalled to be true")
		}

		// Now mark ready
		MarkReady(obj, 1, "Reconciled", "Done")

		if !IsReady(obj) {
			t.Error("expected IsReady to be true after MarkReady")
		}
		if IsStalled(obj) {
			t.Error("expected IsStalled to be false after MarkReady")
		}
	})
}

func TestMarkNotReady(t *testing.T) {
	t.Run("should set Ready=False", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		MarkNotReady(obj, 1, "NotReady", "Resource not ready")

		cond := Get(obj, ReadyConditionType)
		if cond == nil {
			t.Fatal("expected Ready condition to exist")
		}
		if cond.Status != metav1.ConditionFalse {
			t.Errorf("expected Ready.Status to be False, got %v", cond.Status)
		}
		if IsReady(obj) {
			t.Error("expected IsReady to be false")
		}
	})
}

func TestMarkReconciling(t *testing.T) {
	t.Run("should set Reconciling=True and Ready=False", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		MarkReconciling(obj, 1, "Progressing", "Working")

		if !IsReconciling(obj) {
			t.Error("expected IsReconciling to be true")
		}
		if IsReady(obj) {
			t.Error("expected IsReady to be false")
		}
	})

	t.Run("should clear Stalled condition", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Setup: first mark as stalled
		MarkStalled(obj, 1, "Error", "Failed")
		if !IsStalled(obj) {
			t.Error("expected IsStalled to be true")
		}

		// Now mark reconciling
		MarkReconciling(obj, 1, "Progressing", "Retrying")

		if !IsReconciling(obj) {
			t.Error("expected IsReconciling to be true")
		}
		if IsStalled(obj) {
			t.Error("expected IsStalled to be false after MarkReconciling")
		}
	})
}

func TestMarkStalled(t *testing.T) {
	t.Run("should set Stalled=True and Ready=False", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		MarkStalled(obj, 1, "Error", "Something went wrong")

		if !IsStalled(obj) {
			t.Error("expected IsStalled to be true")
		}
		if IsReady(obj) {
			t.Error("expected IsReady to be false")
		}
	})

	t.Run("should clear Reconciling condition", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Setup: first mark as reconciling
		MarkReconciling(obj, 1, "Progressing", "Working")
		if !IsReconciling(obj) {
			t.Error("expected IsReconciling to be true")
		}

		// Now mark stalled
		MarkStalled(obj, 1, "Error", "Something went wrong")

		if !IsStalled(obj) {
			t.Error("expected IsStalled to be true")
		}
		if IsReconciling(obj) {
			t.Error("expected IsReconciling to be false after MarkStalled")
		}
	})
}

func TestIsReady(t *testing.T) {
	t.Run("returns false when no Ready condition exists", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		if IsReady(obj) {
			t.Error("expected IsReady to be false for empty conditions")
		}
	})

	t.Run("returns true when Ready=True", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		MarkReady(obj, 1, "Reconciled", "Done")
		if !IsReady(obj) {
			t.Error("expected IsReady to be true")
		}
	})

	t.Run("returns false when Ready=False", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		MarkNotReady(obj, 1, "NotReady", "Not ready")
		if IsReady(obj) {
			t.Error("expected IsReady to be false")
		}
	})
}

func TestIsReconciling(t *testing.T) {
	t.Run("returns false when no Reconciling condition exists", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		if IsReconciling(obj) {
			t.Error("expected IsReconciling to be false for empty conditions")
		}
	})

	t.Run("returns true when Reconciling=True", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		MarkReconciling(obj, 1, "Progressing", "Working")
		if !IsReconciling(obj) {
			t.Error("expected IsReconciling to be true")
		}
	})
}

func TestIsStalled(t *testing.T) {
	t.Run("returns false when no Stalled condition exists", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		if IsStalled(obj) {
			t.Error("expected IsStalled to be false for empty conditions")
		}
	})

	t.Run("returns true when Stalled=True", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}
		MarkStalled(obj, 1, "Error", "Failed")
		if !IsStalled(obj) {
			t.Error("expected IsStalled to be true")
		}
	})
}

func TestKstatusLifecycle(t *testing.T) {
	t.Run("typical reconciliation lifecycle", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Initial state - no conditions
		if IsReady(obj) {
			t.Error("initial: expected IsReady to be false")
		}
		if IsReconciling(obj) {
			t.Error("initial: expected IsReconciling to be false")
		}
		if IsStalled(obj) {
			t.Error("initial: expected IsStalled to be false")
		}

		// Start reconciling
		MarkReconciling(obj, 1, "Progressing", "Starting reconciliation")
		if !IsReconciling(obj) {
			t.Error("reconciling: expected IsReconciling to be true")
		}
		if IsReady(obj) {
			t.Error("reconciling: expected IsReady to be false")
		}
		if IsStalled(obj) {
			t.Error("reconciling: expected IsStalled to be false")
		}

		// Successfully complete
		MarkReady(obj, 1, "Reconciled", "Reconciliation complete")
		if !IsReady(obj) {
			t.Error("ready: expected IsReady to be true")
		}
		if IsReconciling(obj) {
			t.Error("ready: expected IsReconciling to be false")
		}
		if IsStalled(obj) {
			t.Error("ready: expected IsStalled to be false")
		}
	})

	t.Run("error scenario with retry", func(t *testing.T) {
		obj := &testObject{conditions: []metav1.Condition{}}

		// Start reconciling
		MarkReconciling(obj, 1, "Progressing", "Starting")
		if !IsReconciling(obj) {
			t.Error("start: expected IsReconciling to be true")
		}

		// Error occurs
		MarkStalled(obj, 1, "Error", "Failed to create resource")
		if !IsStalled(obj) {
			t.Error("error: expected IsStalled to be true")
		}
		if IsReconciling(obj) {
			t.Error("error: expected IsReconciling to be false")
		}
		if IsReady(obj) {
			t.Error("error: expected IsReady to be false")
		}

		// Retry - start reconciling again
		MarkReconciling(obj, 2, "Progressing", "Retrying")
		if !IsReconciling(obj) {
			t.Error("retry: expected IsReconciling to be true")
		}
		if IsStalled(obj) {
			t.Error("retry: expected IsStalled to be false")
		}

		// Success
		MarkReady(obj, 2, "Reconciled", "Done")
		if !IsReady(obj) {
			t.Error("success: expected IsReady to be true")
		}
		if IsReconciling(obj) {
			t.Error("success: expected IsReconciling to be false")
		}
		if IsStalled(obj) {
			t.Error("success: expected IsStalled to be false")
		}
	})
}

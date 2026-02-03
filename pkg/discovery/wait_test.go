/*
Copyright © 2026 Deutsche Telekom AG
*/
package discovery

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

func TestNewForeverWatchBackoff(t *testing.T) {
	backoff := NewForeverWatchBackoff()

	// Verify initial configuration
	if backoff.Duration != 250*time.Millisecond {
		t.Errorf("Expected Duration 250ms, got %v", backoff.Duration)
	}
	if backoff.Factor != 1.5 {
		t.Errorf("Expected Factor 1.5, got %v", backoff.Factor)
	}
	if backoff.Steps != 20 {
		t.Errorf("Expected Steps 20, got %v", backoff.Steps)
	}
	if backoff.Jitter != 0.1 {
		t.Errorf("Expected Jitter 0.1, got %v", backoff.Jitter)
	}

	// Verify exponential growth (without jitter consideration)
	// First step should return 250ms (with possible jitter)
	firstStep := backoff.Step()
	if firstStep < 225*time.Millisecond || firstStep > 275*time.Millisecond {
		t.Errorf("First step out of expected range: got %v", firstStep)
	}
}

func TestExponentialBackoffWithContext_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel immediately
	cancel()

	backoff := wait.Backoff{
		Duration: 1 * time.Second,
		Factor:   2.0,
		Steps:    10,
	}

	var callCount int32
	err := ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) {
		atomic.AddInt32(&callCount, 1)
	})

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled error, got %v", err)
	}

	// Operation should not have been called since context was cancelled
	if atomic.LoadInt32(&callCount) != 0 {
		t.Errorf("Expected 0 calls, got %d", callCount)
	}
}

func TestExponentialBackoffWithContext_ContextCancelledDuringWait(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	backoff := wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.0,
		Steps:    10,
	}

	var callCount int32
	done := make(chan error, 1)

	go func() {
		err := ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) {
			count := atomic.AddInt32(&callCount, 1)
			// Cancel after first call
			if count == 1 {
				cancel()
			}
		})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for context cancellation")
	}

	// Should have been called at least once
	count := atomic.LoadInt32(&callCount)
	if count < 1 {
		t.Errorf("Expected at least 1 call, got %d", count)
	}
}

func TestExponentialBackoffWithContext_MultipleIterations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backoff := wait.Backoff{
		Duration: 10 * time.Millisecond, // Very short for testing
		Factor:   1.0,
		Steps:    100,
	}

	var callCount int32
	done := make(chan error, 1)

	go func() {
		err := ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) {
			if atomic.AddInt32(&callCount, 1) >= 3 {
				cancel() // Stop after 3 calls
			}
		})
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for completion")
	}

	count := atomic.LoadInt32(&callCount)
	if count != 3 {
		t.Errorf("Expected 3 calls, got %d", count)
	}
}

func TestExponentialBackoffWithContext_DeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	backoff := wait.Backoff{
		Duration: 100 * time.Millisecond, // Longer than context deadline
		Factor:   1.0,
		Steps:    10,
	}

	var callCount int32
	err := ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) {
		atomic.AddInt32(&callCount, 1)
	})

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded, got %v", err)
	}
}

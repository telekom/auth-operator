package discovery

import (
	"context"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
)

// NewForeverWatchBackoff creates a new API Machinery backoff parameter set suitable for use with watches
// that should retry forever with an exponential backoff.
func NewForeverWatchBackoff() wait.Backoff {
	// Return a exponential backoff configuration which returns durations for a max time of ~8m.
	// Jitter is added as a random fraction of the duration multiplied by the jitter factor.
	return wait.Backoff{
		Duration: 250 * time.Millisecond,
		Factor:   1.5,
		Steps:    20,
		Jitter:   0.1,
	}
}

// ExponentialBackoffWithContext repeats an operation with exponential backoff and keeps it running forever.
// It immediately returns if the context is cancelled
func ExponentialBackoffWithContext(ctx context.Context, backoff wait.Backoff, operation func(context.Context)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		operation(ctx)

		waitBeforeRetry := backoff.Step()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitBeforeRetry):
		}
	}
}

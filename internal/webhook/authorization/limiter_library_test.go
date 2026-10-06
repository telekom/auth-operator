// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
)

func TestSubjectLimiterTemplateCompatibility(t *testing.T) {
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: "alice"}}
	t.Run("unlimited template", func(t *testing.T) {
		handler := &Authorizer{Limiter: rate.NewLimiter(rate.Inf, 0)}
		for range 3 {
			if !handler.allowSubjectRequest(sar) {
				t.Fatal("unlimited template was rejected")
			}
		}
	})
	t.Run("zero-rate initial burst", func(t *testing.T) {
		handler := &Authorizer{Limiter: rate.NewLimiter(0, 1)}
		if !handler.allowSubjectRequest(sar) || handler.allowSubjectRequest(sar) {
			t.Fatal("zero-rate template did not preserve its initial burst")
		}
		other := sar.DeepCopy()
		other.Spec.User = "bob"
		if !handler.allowSubjectRequest(other) {
			t.Fatal("zero-rate templates did not isolate subject budgets")
		}
	})
	t.Run("extremely slow refill", func(t *testing.T) {
		if ttl := subjectLimiterIdleTTL(rate.NewLimiter(math.SmallestNonzeroFloat64, 1)); ttl != time.Duration(math.MaxInt64) {
			t.Fatalf("refill overflow shortened the TTL: %v", ttl)
		}
	})
	t.Run("concurrent first budget", func(t *testing.T) {
		handler := &Authorizer{Limiter: rate.NewLimiter(0, 1)}
		var allowed atomic.Int32
		var workers sync.WaitGroup
		for range 32 {
			workers.Go(func() {
				if handler.allowSubjectRequest(sar) {
					allowed.Add(1)
				}
			})
		}
		workers.Wait()
		if got := allowed.Load(); got != 1 {
			t.Fatalf("concurrent initialization granted %d requests, want 1", got)
		}
	})
	t.Run("unsupported template fails closed", func(t *testing.T) {
		handler := &Authorizer{Limiter: rate.NewLimiter(1e9+1, 1)}
		if handler.allowSubjectRequest(sar) {
			t.Fatal("unsupported template granted a request")
		}
	})
}

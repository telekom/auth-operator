// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
)

func TestSubjectLimiterIdleEviction(t *testing.T) {
	handler := &Authorizer{Limiter: rate.NewLimiter(1, 1)}
	expired := handler.subjectLimiter("expired")
	active := handler.subjectLimiter("active")
	now := time.Now()
	handler.subjectLimiters["expired"].lastSeen = now.Add(-subjectLimiterIdleTTL(handler.Limiter) - time.Second)
	handler.subjectLimiters["active"].lastSeen = now
	handler.pruneSubjectLimitersLocked(now)
	if _, exists := handler.subjectLimiters["expired"]; exists {
		t.Fatal("idle entry was not evicted")
	}
	if handler.subjectLimiter("active") != active {
		t.Fatal("active limiter was replaced")
	}
	if handler.subjectLimiter("expired") == expired {
		t.Fatal("expired limiter was reused")
	}
}

func TestSubjectLimiterIdleTTLIncludesRefill(t *testing.T) {
	for _, tc := range []struct {
		name    string
		limiter *rate.Limiter
		want    time.Duration
	}{
		{name: "disabled", want: minSubjectLimiterIdleTTL},
		{name: "zero rate", limiter: rate.NewLimiter(0, 1), want: minSubjectLimiterIdleTTL},
		{name: "short refill", limiter: rate.NewLimiter(100, 1), want: minSubjectLimiterIdleTTL},
		{name: "slow refill", limiter: rate.NewLimiter(0.001, 1), want: 1000 * time.Second},
		{name: "whole burst refill", limiter: rate.NewLimiter(0.01, 10), want: 1000 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := subjectLimiterIdleTTL(tc.limiter); got != tc.want {
				t.Fatalf("idle TTL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRateLimitSubjectKeyCanonicalGroups(t *testing.T) {
	sar := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", Groups: []string{"z", "a", "z"},
	}}
	canonical := &authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{
		User: "alice", Groups: []string{"a", "z"},
	}}
	if rateLimitSubjectKey(sar) != rateLimitSubjectKey(canonical) {
		t.Fatal("equivalent groups do not share a limiter key")
	}
	if sar.Spec.Groups[0] != "z" || len(sar.Spec.Groups) != 3 {
		t.Fatal("key generation mutated the SAR groups")
	}
	canonical.Spec.User = "bob"
	if rateLimitSubjectKey(sar) == rateLimitSubjectKey(canonical) {
		t.Fatal("different users share a limiter key")
	}
}

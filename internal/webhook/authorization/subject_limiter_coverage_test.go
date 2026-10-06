// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"math"
	"testing"
	"time"

	"github.com/telekom/t-caas-go-library/pkg/ratelimit"
	"golang.org/x/time/rate"
	authzv1 "k8s.io/api/authorization/v1"
	clocktesting "k8s.io/utils/clock/testing"
)

func TestSubjectLimiterIdleEviction(t *testing.T) {
	clock := clocktesting.NewFakeClock(time.Now())
	handler := &Authorizer{Limiter: rate.NewLimiter(0, 1)}
	var err error
	handler.subjectLimiters, err = ratelimit.New(ratelimit.Config{
		Rate: math.SmallestNonzeroFloat64, Burst: 1, MaxKeys: maxSubjectLimiters,
		IdleTTL: subjectLimiterIdleTTL(handler.Limiter), Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(user string) bool {
		return handler.allowSubjectRequest(&authzv1.SubjectAccessReview{Spec: authzv1.SubjectAccessReviewSpec{User: user}})
	}
	if !request("expired") || !request("active") {
		t.Fatal("initial bursts were not available")
	}
	clock.Step(minSubjectLimiterIdleTTL - time.Second)
	if request("active") {
		t.Fatal("active limiter's exhausted budget was reset")
	}
	clock.Step(2 * time.Second)
	if !request("expired") {
		t.Fatal("idle limiter was not replaced with a fresh budget")
	}
	if request("active") {
		t.Fatal("active limiter was replaced")
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

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	testingclient "k8s.io/client-go/testing"
)

func TestMixedWorkerCountsUseTotalBudget(t *testing.T) {
	for _, tc := range []struct {
		workers int
		kinds   int
		want    []int
	}{
		{workers: 8, kinds: 3, want: []int{3, 3, 2}},
		{workers: 3, kinds: 3, want: []int{1, 1, 1}},
		{workers: 1, kinds: 3, want: []int{1, 0, 0}},
	} {
		got := mixedWorkerCounts(tc.workers, tc.kinds)
		if len(got) != len(tc.want) {
			t.Fatalf("mixedWorkerCounts(%d, %d) length = %d, want %d", tc.workers, tc.kinds, len(got), len(tc.want))
		}
		total := 0
		for i, n := range got {
			total += n
			if n != tc.want[i] {
				t.Fatalf("mixedWorkerCounts(%d, %d) = %v, want %v", tc.workers, tc.kinds, got, tc.want)
			}
		}
		if total > tc.workers {
			t.Fatalf("mixedWorkerCounts(%d, %d) total = %d", tc.workers, tc.kinds, total)
		}
	}
}

func TestMixedSustainedNeverExceedsTotalWorkerBudget(t *testing.T) {
	var mu sync.Mutex
	active, maxActive := 0, 0
	seen := map[string]int{}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "serviceaccounts"}:                           "ServiceAccountList",
		{Version: "v1", Resource: "secrets"}:                                   "SecretList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}: "RoleList",
	})
	client.PrependReactor("create", "*", func(action testingclient.Action) (bool, runtime.Object, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		seen[action.GetResource().Resource]++
		mu.Unlock()
		time.Sleep(8 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
		return false, nil, nil
	})
	run := runMixedPhaseWithOffset(context.Background(), []dynamic.Interface{client}, []string{"serviceaccount", "secret", "role"}, Cell{
		Engine: "baseline", Tier: "t3", Mode: "create-only", Phase: "sustained", Kind: "serviceaccount", Verb: "mixed", RunID: "budget", Sustained: true,
	}, 0, 4, []string{"creator-bench-000"}, "bench", 55*time.Millisecond, 0, nil)
	if run.Status != "complete" {
		t.Fatalf("sustained run status = %q, error = %q", run.Status, run.Error)
	}
	if maxActive > 4 {
		t.Fatalf("mixed sustained exceeded total worker budget: max active = %d", maxActive)
	}
	for _, resource := range []string{"serviceaccounts", "secrets", "roles"} {
		if seen[resource] == 0 {
			t.Fatalf("sustained run did not exercise %s: %#v", resource, seen)
		}
	}
}

func TestMixedSustainedUsesOneDeadlineAcrossKinds(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "serviceaccounts"}:                           "ServiceAccountList",
		{Version: "v1", Resource: "secrets"}:                                   "SecretList",
		{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}: "RoleList",
	})
	client.PrependReactor("create", "*", func(action testingclient.Action) (bool, runtime.Object, error) {
		time.Sleep(8 * time.Millisecond)
		mu.Lock()
		seen[action.GetResource().Resource]++
		mu.Unlock()
		return false, nil, nil
	})

	started := time.Now()
	run := runMixedPhaseWithOffset(context.Background(), []dynamic.Interface{client}, []string{"serviceaccount", "secret", "role"}, Cell{
		Engine: "baseline", Tier: "t3", Mode: "create-only", Phase: "sustained", Kind: "serviceaccount", Verb: "mixed", RunID: "timing", Sustained: true,
	}, 0, 1, []string{"creator-bench-000"}, "bench", 45*time.Millisecond, 0, nil)
	elapsed := time.Since(started)
	if run.Status != "complete" {
		t.Fatalf("sustained run status = %q, error = %q", run.Status, run.Error)
	}
	if len(run.Operations) == 0 {
		t.Fatal("sustained run produced no operations")
	}
	for _, resource := range []string{"serviceaccounts", "secrets", "roles"} {
		if seen[resource] == 0 {
			t.Fatalf("sustained run did not exercise %s: %#v", resource, seen)
		}
	}
	// The deadline is shared by all three kinds. A per-kind duration would
	// take roughly three times as long with the deliberately slow reactor.
	if elapsed > 100*time.Millisecond {
		t.Fatalf("mixed sustained phase exceeded one configured duration: %s", elapsed)
	}
}

func TestMixedSustainedHonorsCancellation(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("create", "*", func(action testingclient.Action) (bool, runtime.Object, error) {
		time.Sleep(20 * time.Millisecond)
		return false, nil, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	run := runMixedPhaseWithOffset(ctx, []dynamic.Interface{client}, []string{"serviceaccount", "secret"}, Cell{
		Engine: "baseline", Tier: "t2", Mode: "create-only", Phase: "sustained", Kind: "serviceaccount", Verb: "mixed", RunID: "cancel", Sustained: true,
	}, 0, 1, []string{"creator-bench-000"}, "bench", time.Second, 0, nil)
	if run.Status != "failed" || run.Error == "" {
		t.Fatalf("cancellation status = %q, error = %q", run.Status, run.Error)
	}
}

func TestMixedSustainedPreCancelledDoesNotReportComplete(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run := runMixedPhaseWithOffset(ctx, []dynamic.Interface{client}, []string{"serviceaccount", "secret", "role"}, Cell{
		Engine: "baseline", Tier: "t2", Mode: "create-only", Phase: "sustained", Kind: "serviceaccount", Verb: "mixed", RunID: "pre-cancel", Sustained: true,
	}, 0, 1, []string{"creator-bench-000"}, "bench", time.Second, 0, nil)
	if run.Status != "failed" || run.Error == "" {
		t.Fatalf("pre-cancelled mixed sustained status = %q, error = %q", run.Status, run.Error)
	}
	if run.Successes != 0 || run.Samples != 0 {
		t.Fatalf("pre-cancelled mixed sustained recorded samples: successes=%d samples=%d", run.Successes, run.Samples)
	}
}

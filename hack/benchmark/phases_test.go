// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	testingclient "k8s.io/client-go/testing"
)

func TestStatusForWarmupCreate(t *testing.T) {
	if got := statusFor(phaseWarmup, nil); got != 201 {
		t.Fatalf("warmup status = %d, want 201", got)
	}
	if got := statusFor(phaseCreate, nil); got != 201 {
		t.Fatalf("create status = %d, want 201", got)
	}
}

func TestOperationalModeMapsComponentMeasurements(t *testing.T) {
	tests := map[string]string{
		modeComponentStamp:   modeCreateOnly,
		modeComponentRestore: modeProtect,
		modeComponentContrib: modeContributors,
		modeProtect:          modeProtect,
	}
	for input, want := range tests {
		if got := operationalMode(input); got != want {
			t.Errorf("operationalMode(%q) = %q, want %q", input, got, want)
		}
	}
}

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

func TestWarmupCreateRecordsCreatedStatus(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	s, err := specFor(resourceServiceAccount)
	if err != nil {
		t.Fatalf("specFor(%q): %v", resourceServiceAccount, err)
	}
	run := runPhaseWithClientsProgressOffset(
		context.Background(),
		[]dynamic.ResourceInterface{client.Resource(s.gvr).Namespace("bench")},
		Cell{
			Engine: "baseline", Tier: "t1", Mode: modeProtect,
			Phase: phaseWarmup, Kind: resourceServiceAccount, Verb: verbMixed,
			RunID: "warmup-status",
		},
		1, 1, nil, "bench", 0, 0, nil,
	)
	if run.Status != statusComplete {
		t.Fatalf("warmup run status = %q, error = %q", run.Status, run.Error)
	}
	if len(run.Operations) != 1 {
		t.Fatalf("warmup operation count = %d, want 1", len(run.Operations))
	}
	if got := run.Operations[0].Status; got != 201 {
		t.Fatalf("warmup create status = %d, want 201", got)
	}
}

func TestCreateOnlyChurnRemainsAnUpdateWorkload(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	s, err := specFor(resourceServiceAccount)
	if err != nil {
		t.Fatalf("specFor(%q): %v", resourceServiceAccount, err)
	}
	createCell := Cell{
		Engine: engineBaseline, Tier: "t1", Mode: modeCreateOnly, Phase: phaseCreate,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
		RunID: "create-only-churn",
	}
	r := client.Resource(s.gvr).Namespace("bench")
	for i := range 4 {
		seed := objectFor(createCell, deterministicName(createCell, i), "bench", s)
		if i == 0 {
			labels := seed.GetLabels()
			labels["example.com/foreign-label"] = "keep"
			seed.SetLabels(labels)
			annotations := seed.GetAnnotations()
			annotations["example.com/foreign-annotation"] = "keep"
			seed.SetAnnotations(annotations)
		}
		if _, err := r.Create(context.Background(), seed, metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed object %d: %v", i, err)
		}
	}
	run := runPhaseWithClientsProgressOffset(context.Background(), []dynamic.ResourceInterface{r}, Cell{
		Engine: engineBaseline, Tier: "t1", Mode: modeCreateOnly, Phase: phaseChurn,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
		RunID: "create-only-churn", Objects: 4,
	}, 4, 1, []string{defaultEditorIdentity}, "bench", 0, 0, nil)
	if run.Status != statusComplete {
		t.Fatalf("churn status = %q, error = %q", run.Status, run.Error)
	}
	if len(run.Operations) != 4 {
		t.Fatalf("churn operations = %d, want 4", len(run.Operations))
	}
	for _, op := range run.Operations {
		if op.Verb != verbUpdate {
			t.Fatalf("create-only churn verb = %q, want update", op.Verb)
		}
	}
	for _, action := range client.Actions()[4:] {
		if action.GetVerb() != "update" && action.GetVerb() != "get" {
			t.Fatalf("create-only churn issued %s instead of update/get", action.GetVerb())
		}
	}
	var update *unstructured.Unstructured
	for _, action := range client.Actions()[4:] {
		if action.GetVerb() == "update" {
			update = action.(testingclient.UpdateAction).GetObject().(*unstructured.Unstructured)
			break
		}
	}
	if update == nil {
		t.Fatal("create-only churn did not issue an update")
	}
	if got := update.GetLabels()["example.com/foreign-label"]; got != "keep" {
		t.Fatalf("foreign label after annotation update = %q, want keep", got)
	}
	if got := update.GetAnnotations()["example.com/foreign-annotation"]; got != "keep" {
		t.Fatalf("foreign annotation after annotation update = %q, want keep", got)
	}
}

func TestSustainedContainsCreatesAndUpdatesForEveryMode(t *testing.T) {
	for _, mode := range []string{modeCreateOnly, modeProtect, modeContributors} {
		t.Run(mode, func(t *testing.T) {
			client := fake.NewSimpleDynamicClient(runtime.NewScheme())
			s, err := specFor(resourceServiceAccount)
			if err != nil {
				t.Fatalf("specFor(%q): %v", resourceServiceAccount, err)
			}
			createCell := Cell{
				Engine: engineBaseline, Tier: "t1", Mode: mode, Phase: phaseCreate,
				Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
				RunID: "sustained-" + mode,
			}
			r := client.Resource(s.gvr).Namespace("bench")
			for i := range 2 {
				if _, err := r.Create(context.Background(), objectFor(createCell, deterministicName(createCell, i), "bench", s), metav1.CreateOptions{}); err != nil {
					t.Fatalf("seed object %d: %v", i, err)
				}
			}
			run := runPhaseWithClientsProgressOffset(context.Background(), []dynamic.ResourceInterface{r}, Cell{
				Engine: engineBaseline, Tier: "t1", Mode: mode, Phase: phaseSustained,
				Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
				RunID: "sustained-" + mode, Objects: 2,
			}, 0, 1, []string{defaultEditorIdentity}, "bench", 25*time.Millisecond, 0, nil)
			if run.Status != statusComplete {
				t.Fatalf("sustained status = %q, error = %q", run.Status, run.Error)
			}
			creates, updates := 0, 0
			for _, op := range run.Operations {
				switch op.Verb {
				case phaseCreate:
					creates++
				case verbUpdate:
					updates++
				default:
					t.Fatalf("unexpected sustained verb %q", op.Verb)
				}
			}
			if creates == 0 || updates == 0 {
				t.Fatalf("sustained verbs = create:%d update:%d", creates, updates)
			}
		})
	}
}

func TestContributorEditorsRotateByObjectRound(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	s, err := specFor(resourceServiceAccount)
	if err != nil {
		t.Fatalf("specFor(%q): %v", resourceServiceAccount, err)
	}
	createCell := Cell{
		Engine: engineBaseline, Tier: "t1", Mode: modeContributors, Phase: phaseCreate,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
		RunID: "contributors-rounds",
	}
	r := client.Resource(s.gvr).Namespace("bench")
	name := deterministicName(createCell, 0)
	if _, err := r.Create(context.Background(), objectFor(createCell, name, "bench", s), metav1.CreateOptions{}); err != nil {
		t.Fatalf("seed object: %v", err)
	}
	seen := map[string]int{}
	client.PrependReactor("update", resourceServiceAccounts, func(action testingclient.Action) (bool, runtime.Object, error) {
		u := action.(testingclient.UpdateAction).GetObject().(*unstructured.Unstructured)
		seen[u.GetAnnotations()[annotationEditor]]++
		return false, nil, nil
	})
	resources := make([]dynamic.ResourceInterface, 10)
	for i := range resources {
		resources[i] = r
	}
	run := runPhaseWithClientsProgressOffset(context.Background(), resources, Cell{
		Engine: engineBaseline, Tier: "t1", Mode: modeContributors, Phase: phaseChurn,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
		RunID: "contributors-rounds", Objects: 1,
	}, 4, 1, syntheticIdentities(), "bench", 0, 0, nil)
	if run.Status != statusComplete {
		t.Fatalf("contributors status = %q, error = %q", run.Status, run.Error)
	}
	identities := syntheticIdentities()
	for _, identity := range identities[:4] {
		if seen[identity] != 1 {
			t.Fatalf("contributors editor rotation = %#v, want one request for %q", seen, identity)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("contributors editor rotation = %#v, want four identities", seen)
	}
}

func TestContributorClientIndexRotatesOncePerObjectRound(t *testing.T) {
	tests := []struct {
		name    string
		objects int
		indices []int
	}{
		{name: "churn", objects: 3, indices: []int{0, 0, 0, 1, 1, 1, 2, 2, 2, 3}},
		{name: "single object", objects: 1, indices: []int{0, 1, 2, 3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for i, want := range tc.indices {
				if got := contributorClientIndex(i, tc.objects, 10); got != want {
					t.Fatalf("contributorClientIndex(%d, %d, 10) = %d, want %d", i, tc.objects, got, want)
				}
			}
		})
	}
}

func TestMixedPhaseCreatesOpsPerKind(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	run := runMixedPhaseWithOffset(context.Background(), []dynamic.Interface{client}, []string{resourceServiceAccount, resourceSecret}, Cell{
		Engine: engineBaseline, Tier: "t2", Mode: modeCreateOnly, Phase: phaseCreate,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled, RunID: "per-kind",
	}, 3, 1, []string{defaultEditorIdentity}, "bench", 0, 0, nil)
	if run.Status != statusComplete {
		t.Fatalf("mixed create status = %q, error = %q", run.Status, run.Error)
	}
	counts := map[string]int{}
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			counts[action.GetResource().Resource]++
		}
	}
	if counts[resourceServiceAccounts] != 3 || counts[resourceSecrets] != 3 {
		t.Fatalf("per-kind create counts = %#v, want 3 each", counts)
	}
}

func TestMixedChurnReusesPerKindObjectPool(t *testing.T) {
	client := fake.NewSimpleDynamicClient(runtime.NewScheme())
	cell := Cell{
		Engine: engineBaseline, Tier: "t2", Mode: modeProtect, Phase: phaseCreate,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled, RunID: "mixed-churn",
	}
	kinds := []string{resourceServiceAccount, resourceSecret}
	created := runMixedPhaseWithOffset(context.Background(), []dynamic.Interface{client}, kinds, cell, 3, 1, []string{defaultEditorIdentity}, "bench", 0, 0, nil)
	if created.Status != statusComplete {
		t.Fatalf("mixed create status = %q, error = %q", created.Status, created.Error)
	}
	cell.Phase = phaseChurn
	cell.Objects = 3
	churned := runMixedPhaseWithOffset(context.Background(), []dynamic.Interface{client}, kinds, cell, 6, 1, []string{defaultEditorIdentity}, "bench", 0, 0, nil)
	if churned.Status != statusComplete || churned.Errors != 0 {
		t.Fatalf("mixed churn status = %q, errors = %d, error = %q", churned.Status, churned.Errors, churned.Error)
	}
	if len(churned.Operations) != 12 {
		t.Fatalf("mixed churn operations = %d, want 12", len(churned.Operations))
	}
}

func TestObjectForSeedsComparableTrackingAnnotationsWithoutClobberingLabels(t *testing.T) {
	s, err := specFor(resourceServiceAccount)
	if err != nil {
		t.Fatalf("specFor(%q): %v", resourceServiceAccount, err)
	}
	u := objectFor(Cell{
		Engine: engineBaseline, Tier: "t1", Mode: modeProtect, Phase: phaseCreate,
		Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled,
		RunID: "metadata",
	}, "object", "bench", s)
	if got := u.GetAnnotations()[annotationCreator]; got != spoofedCreator {
		t.Fatalf("creator spoof annotation = %q, want %q", got, spoofedCreator)
	}
	if got := u.GetAnnotations()[annotationGroups]; got != spoofedGroups {
		t.Fatalf("group spoof annotation = %q, want %q", got, spoofedGroups)
	}
	if got := u.GetLabels()["t-caas.telekom.com/benchmark"]; got != benchmarkLabelValue {
		t.Fatalf("ownership label = %q, want %q", got, benchmarkLabelValue)
	}
	if len(u.GetLabels()) < 2 {
		t.Fatalf("object labels unexpectedly sparse: %#v", u.GetLabels())
	}
}

func seedSustainedObjectPool(t *testing.T, client *fake.FakeDynamicClient, tier, runID string, kinds []string) {
	t.Helper()
	for _, kind := range kinds {
		s, err := specFor(kind)
		if err != nil {
			t.Fatalf("specFor(%q): %v", kind, err)
		}
		cell := Cell{Engine: engineBaseline, Tier: tier, Mode: modeCreateOnly, Phase: phaseCreate, Kind: kind, Verb: verbMixed, Variant: variantEnabled, RunID: runID}
		var r dynamic.ResourceInterface
		if s.namespaced {
			r = client.Resource(s.gvr).Namespace("bench")
		} else {
			r = client.Resource(s.gvr)
		}
		if _, err := r.Create(context.Background(), objectFor(cell, deterministicName(cell, 0), "bench", s), metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed %s: %v", kind, err)
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
	seedSustainedObjectPool(t, client, "t3", "budget", []string{resourceServiceAccount, resourceSecret, resourceRole})
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
	seedSustainedObjectPool(t, client, "t3", "timing", []string{resourceServiceAccount, resourceSecret, resourceRole})
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

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"flag"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseOptionsUsesPrivateFlagSet(t *testing.T) {
	originalCommandLine := flag.CommandLine
	flag.CommandLine = flag.NewFlagSet("global-test", flag.ContinueOnError)
	t.Cleanup(func() { flag.CommandLine = originalCommandLine })
	flag.CommandLine.String("kubeconfig", "global-kubeconfig", "flag registered by the caller")

	o, err := parseOptions([]string{
		"-engine", "map",
		"-tier", "t2",
		"-mode", "contributors",
		"-ops", "42",
		"-churn-rounds", "3",
		"-identities", "10",
		"-concurrency", "4,8",
		"-warmup", "5",
		"-sustained-duration", "2s",
		"-out", t.TempDir(),
		"-kubeconfig", "explicit-kubeconfig",
		"-run-id", "run-1",
		"-input-hash", "expected-hash",
	})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if o.engine != engineMap || o.tier != "t2" || o.mode != modeContributors {
		t.Fatalf("parsed identity options = %#v", o)
	}
	if o.ops != 42 || o.churn != 3 || o.identities != 10 || o.warmup != 5 {
		t.Fatalf("parsed workload options = %#v", o)
	}
	if !reflect.DeepEqual(o.concurrency, []int{4, 8}) {
		t.Fatalf("parsed concurrency = %#v", o.concurrency)
	}
	if o.sustained != 2*time.Second || o.kubeconfig != "explicit-kubeconfig" || o.runID != "run-1" || o.inputHash != "expected-hash" {
		t.Fatalf("parsed output options = %#v", o)
	}
}

func TestParseOptionsResumeRequiresRunID(t *testing.T) {
	_, err := parseOptions([]string{"-resume", "-kubeconfig", "resume-kubeconfig"})
	if err == nil || !strings.Contains(err.Error(), "-resume requires -run-id") {
		t.Fatalf("parseOptions resume error = %v, want missing run ID", err)
	}
}

func TestParseOptionsRejectsTrailingConcurrencyText(t *testing.T) {
	_, err := parseOptions([]string{"-concurrency", "8x", "-kubeconfig", "invalid-concurrency-kubeconfig"})
	if err == nil || !strings.Contains(err.Error(), `invalid concurrency "8x"`) {
		t.Fatalf("parseOptions concurrency error = %v", err)
	}
}

func TestParseOptionsRejectsDuplicateConcurrency(t *testing.T) {
	_, err := parseOptions([]string{"-concurrency", "8,8", "-kubeconfig", "duplicate-concurrency-kubeconfig"})
	if err == nil || !strings.Contains(err.Error(), "duplicate concurrency 8") {
		t.Fatalf("parseOptions duplicate concurrency error = %v", err)
	}
}

func TestParseOptionsSortsConcurrency(t *testing.T) {
	o, err := parseOptions([]string{"-concurrency", "64,8,32", "-kubeconfig", "unsorted-concurrency-kubeconfig"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if !reflect.DeepEqual(o.concurrency, []int{8, 32, 64}) {
		t.Fatalf("sorted concurrency = %#v", o.concurrency)
	}
}

func TestQuickOptionsHonorRunnerOperationBudget(t *testing.T) {
	o, err := parseOptions([]string{"-quick", "-kubeconfig", "quick-kubeconfig"})
	if err != nil {
		t.Fatalf("parseOptions() error = %v", err)
	}
	if o.ops != 500 {
		t.Fatalf("quick operations = %d, want runner budget 500", o.ops)
	}
	if o.warmup != 10 || o.churn != 2 || o.sustained != 10*time.Second {
		t.Fatalf("quick reductions = ops %d warmup %d churn %d sustained %s", o.ops, o.warmup, o.churn, o.sustained)
	}
}

func TestExecutionTimeoutIncludesEveryConcurrencyLevel(t *testing.T) {
	o := options{sustained: 5 * time.Minute, concurrency: []int{8, 32, 64}}
	if got, want := executionTimeout(o), 45*time.Minute; got != want {
		t.Fatalf("execution timeout = %s, want %s", got, want)
	}
	if got, want := executionTimeout(options{sustained: time.Minute}), 31*time.Minute; got != want {
		t.Fatalf("single-level execution timeout = %s, want %s", got, want)
	}
}

func TestInputHashMismatchErrorIncludesExpectedAndComputedValues(t *testing.T) {
	err := inputHashMismatchError("expected-hash", "computed-hash")
	if got, want := err.Error(), `input hash mismatch: expected "expected-hash", computed "computed-hash"`; got != want {
		t.Fatalf("input hash error = %q, want %q", got, want)
	}
}

func TestCellsQuickShape(t *testing.T) {
	if len(Cells(true)) != 8 {
		t.Fatal(len(Cells(true)))
	}
}
func TestPlannedCellsHasSharedBaselines(t *testing.T) {
	planned := PlannedCells(false)
	if len(planned) != 60 {
		t.Fatalf("planned cells = %d", len(planned))
	}
	for i := range 12 {
		if planned[i].Engine != engineBaseline || planned[i].Variant != engineBaseline {
			t.Fatalf("not shared baseline: %#v", planned[i])
		}
	}
}

func TestPlannedAuxiliaryCellsCoverIsolationComponentsAndExclusion(t *testing.T) {
	aux := PlannedAuxiliaryCells()
	if len(aux) != 24 {
		t.Fatalf("auxiliary logical cells = %d, want 24", len(aux))
	}
	if got := len(PlannedFullCells(false)); got != 84 {
		t.Fatalf("full logical cells = %d, want 84", got)
	}
	seen := map[string]bool{}
	for _, c := range aux {
		key := plannedKey(c)
		if seen[key] {
			t.Fatalf("duplicate auxiliary cell %#v", c)
		}
		seen[key] = true
	}
	for _, tier := range isolationTiers() {
		count := 0
		wantKind, err := IsolationKind(tier)
		if err != nil {
			t.Fatalf("isolation kind for %q: %v", tier, err)
		}
		for _, c := range aux {
			if c.Tier == tier {
				count++
				if c.Kind != wantKind {
					t.Fatalf("isolation tier %q planned kind = %q, want %q", tier, c.Kind, wantKind)
				}
			}
		}
		if count != 4 {
			t.Fatalf("isolation tier %q has %d cells, want 4", tier, count)
		}
	}
	for _, mode := range []string{modeComponentStamp, modeComponentRestore, modeComponentContrib} {
		count := 0
		for _, c := range aux {
			if c.Mode == mode {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("component mode %q has %d cells, want 1", mode, count)
		}
	}
}

func TestPlannedFullExecutionPreservesCoreAndAddsAuxiliaryResults(t *testing.T) {
	concurrency := []int{8, 32, 64}
	if got := len(PlannedExecutionCells(false, concurrency)); got != 720 {
		t.Fatalf("core execution cells = %d, want 720", got)
	}
	if got := len(PlannedAuxiliaryExecutionCells(false, concurrency)); got != 288 {
		t.Fatalf("auxiliary execution cells = %d, want 288", got)
	}
	if got := len(PlannedFullExecutionCells(false, concurrency)); got != 1008 {
		t.Fatalf("full execution cells = %d, want 1008", got)
	}
	if got := len(PlannedFullExecutionCells(true, []int{8})); got != 16 {
		t.Fatalf("quick execution cells = %d, want 16", got)
	}
}

func TestComponentModesAreAcceptedByBenchmarkValidation(t *testing.T) {
	for _, mode := range []string{modeComponentStamp, modeComponentRestore, modeComponentContrib} {
		if !validBenchmarkMode(mode) {
			t.Errorf("component mode %q was rejected", mode)
		}
	}
	if validBenchmarkMode("component-unknown") {
		t.Fatal("unknown component mode was accepted")
	}
}

func TestExecutionCellUsesExcludedVariant(t *testing.T) {
	o := options{engine: engineMap, tier: "t1", mode: modeProtect, concurrency: []int{8}, excluded: true}
	c := executionCell(o)
	if c.Variant != variantExcluded {
		t.Fatalf("excluded execution variant = %q, want %q", c.Variant, variantExcluded)
	}
	if c.Engine != engineMap || c.Tier != "t1" || c.Mode != modeProtect {
		t.Fatalf("execution cell identity = %#v", c)
	}
}

func TestPlannedExecutionCellsMatchesProductionContract(t *testing.T) {
	got := PlannedExecutionCells(false, []int{8})
	if len(got) != (12+48)*len(BenchmarkPhases()) {
		t.Fatalf("planned execution cells = %d", len(got))
	}
	for _, c := range got {
		if c.Phase == phaseCore || c.Concurrency != 8 || c.Verb != verbMixed {
			t.Fatalf("invalid executable cell: %#v", c)
		}
	}
}

func TestQuickPlanMatchesRunnerContract(t *testing.T) {
	logical := PlannedCells(true)
	if len(logical) != 4 {
		t.Fatalf("quick logical cells = %d", len(logical))
	}
	if len(PlannedExecutionCells(true, []int{8})) != 16 {
		t.Fatalf("quick executable cells = %d", len(PlannedExecutionCells(true, []int{8})))
	}
	for _, c := range logical {
		if c.Mode != modeProtect || (c.Engine != engineBaseline && c.Engine != engineMap) || (c.Tier != "t1" && c.Tier != "t2") {
			t.Fatalf("unexpected quick cell %#v", c)
		}
	}
}

func TestContributorTraceContract(t *testing.T) {
	r := Result{
		Cell:  Cell{Engine: engineMap, Tier: "t1", Mode: modeContributors, Phase: phaseChurn, Kind: resourceServiceAccount, Verb: verbUpdate, Variant: variantEnabled, Concurrency: 8},
		RunID: fallbackRunID, InputHash: "input", EnvironmentID: "env", Status: "complete", Samples: 1,
		Trace: []MutationTrace{{Editor: "creator-bench-000", Object: "object", Repeated: true, Deduplicated: true, TamperTested: true, Restored: true}},
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(r.Trace) != 1 || !r.Trace[0].Repeated || !r.Trace[0].Deduplicated || !r.Trace[0].TamperTested || !r.Trace[0].Restored {
		t.Fatalf("trace %#v", r.Trace)
	}
}

func TestResultValidationAllowsUnavailableSupportingTelemetry(t *testing.T) {
	r := Result{
		Cell: Cell{
			Engine: engineBaseline, Tier: "t1", Mode: modeProtect, Phase: phaseCreate,
			Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled, Concurrency: 8,
		},
		RunID: fallbackRunID, InputHash: "input", EnvironmentID: "env",
		Status: statusComplete, Samples: 1,
		MetricBeforeState: MetricUnavailable, MetricAfterState: MetricUnauthorized,
		MetricDeltaState: MetricUnavailable, MetricDelta: Counter{State: MetricUnavailable},
		WebhookDelta: HistogramDelta{State: MetricMissing},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("supporting telemetry state must not invalidate latency result: %v", err)
	}
}

func TestResultValidationRequiresKindAndVariant(t *testing.T) {
	valid := Result{
		Cell: Cell{
			Engine: engineBaseline, Tier: "t1", Mode: modeProtect, Phase: phaseCreate,
			Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled, Concurrency: 8,
		},
		RunID: fallbackRunID, InputHash: "input", EnvironmentID: "env",
		Status: statusComplete, Samples: 1,
	}
	for _, tc := range []struct {
		name string
		edit func(*Result)
	}{
		{name: "kind", edit: func(r *Result) { r.Cell.Kind = "" }},
		{name: "variant", edit: func(r *Result) { r.Cell.Variant = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalid := valid
			tc.edit(&invalid)
			if err := invalid.Validate(); err == nil {
				t.Fatalf("result without %s was accepted", tc.name)
			}
		})
	}
}

func TestComparisonConfigHashExcludesEngineOnly(t *testing.T) {
	a := options{engine: engineBaseline, tier: "t1", mode: modeProtect, ops: 10, churn: 2, identities: 10, warmup: 1, sustained: time.Second, concurrency: []int{8}}
	b := a
	b.engine = engineMap
	if comparisonConfigHash(a) != comparisonConfigHash(b) {
		t.Fatal("engine must not affect comparison hash")
	}
	b.ops++
	if comparisonConfigHash(a) == comparisonConfigHash(b) {
		t.Fatal("workload config must affect comparison hash")
	}
	b.ops = a.ops
	b.inputHash = "engine-specific-input"
	if comparisonConfigHash(a) != comparisonConfigHash(b) {
		t.Fatal("engine-specific input hash must not affect comparison hash")
	}
}

func TestComparisonConfigHashIgnoresResumeAndReportFlags(t *testing.T) {
	a := options{engine: engineBaseline, tier: "t1", mode: modeProtect, ops: 10, churn: 2, identities: 10, warmup: 1, sustained: time.Second, concurrency: []int{8}}
	b := a
	b.resume = true
	b.report = true
	if comparisonConfigHash(a) != comparisonConfigHash(b) {
		t.Fatal("resume/report control flags must not change the execution config hash")
	}
}
func TestInputHash(t *testing.T) {
	a := Cell{Engine: engineMap}
	b := a
	b.Mode = "protect"
	if InputHash(a, nil) == InputHash(b, nil) {
		t.Fatal("hash unchanged")
	}
}

func TestCellInputHashIgnoresExecutionSchedulingFields(t *testing.T) {
	t.Setenv("BENCHMARK_INPUT_MATERIAL", "")
	base := Cell{
		Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseCore,
		Concurrency: 8, Kind: resourceServiceAccount, Verb: verbMixed,
		Variant: variantEnabled, RunID: "run-a", Objects: 500,
	}
	want := cellInputHash(base)
	for name, mutate := range map[string]func(*Cell){
		"phase":       func(c *Cell) { c.Phase = phaseChurn },
		"concurrency": func(c *Cell) { c.Concurrency = 64 },
		"sustained":   func(c *Cell) { c.Sustained = true },
		"run ID":      func(c *Cell) { c.RunID = "run-b" },
		"objects":     func(c *Cell) { c.Objects = 5000 },
	} {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			if hash := cellInputHash(got); hash != want {
				t.Fatalf("cellInputHash changed for %s: got %q, want %q", name, hash, want)
			}
		})
	}
}

func TestCellInputHashIncludesLogicalIdentity(t *testing.T) {
	t.Setenv("BENCHMARK_INPUT_MATERIAL", "")
	base := Cell{Engine: engineMap, Tier: "t1", Mode: modeProtect, Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled}
	want := cellInputHash(base)
	for name, mutate := range map[string]func(*Cell){
		"engine":  func(c *Cell) { c.Engine = engineKyvernoWebhook },
		"tier":    func(c *Cell) { c.Tier = "t2" },
		"mode":    func(c *Cell) { c.Mode = modeContributors },
		"kind":    func(c *Cell) { c.Kind = resourceSecret },
		"verb":    func(c *Cell) { c.Verb = verbUpdate },
		"variant": func(c *Cell) { c.Variant = variantExcluded },
	} {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			if hash := cellInputHash(got); hash == want {
				t.Fatalf("cellInputHash did not change for %s", name)
			}
		})
	}
}

func TestValidateOptionsRequiresWarmup(t *testing.T) {
	o := options{engine: engineBaseline, tier: "t1", mode: modeProtect, ops: 1, churn: 1, identities: 10, sustained: time.Second}
	if err := validateOptions(o); err == nil {
		t.Fatal("expected zero warmup to be rejected")
	}
}

func TestValidateRunID(t *testing.T) {
	tests := []struct {
		name  string
		runID string
		want  bool
	}{
		{name: "shell generated", runID: "20260831t120000z-0123456789abcdef", want: true},
		{name: "single character", runID: "a", want: true},
		{name: "maximum namespace-safe length", runID: strings.Repeat("a", 49), want: true},
		{name: "empty", runID: "", want: false},
		{name: "uppercase", runID: "Run-1", want: false},
		{name: "leading hyphen", runID: "-run", want: false},
		{name: "trailing hyphen", runID: "run-", want: false},
		{name: "path separator", runID: "run/1", want: false},
		{name: "namespace-overflow", runID: strings.Repeat("a", 50), want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRunID(test.runID)
			if (err == nil) != test.want {
				t.Fatalf("validateRunID(%q) error = %v, want valid = %t", test.runID, err, test.want)
			}
		})
	}
}

func TestDefaultRunIDIsDNSLabel(t *testing.T) {
	runID := defaultRunID(time.Date(2026, time.August, 31, 12, 34, 56, 0, time.UTC))
	if runID != "20260831t123456z" {
		t.Fatalf("defaultRunID() = %q", runID)
	}
	if err := validateRunID(runID); err != nil {
		t.Fatalf("defaultRunID() is invalid: %v", err)
	}
}

func TestCounterDelta(t *testing.T) {
	if CounterDelta(Counter{10, MetricAvailable}, Counter{2, MetricAvailable}).State != MetricReset {
		t.Fatal("reset")
	}
}
func TestReportDeterministic(t *testing.T) {
	rs := []Result{{Cell: Cell{Engine: "z"}}, {Cell: Cell{Engine: "a"}}}
	var a, b bytes.Buffer
	WriteCSV(&a, rs)
	WriteCSV(&b, rs)
	if a.String() != b.String() {
		t.Fatal("nondeterministic")
	}
}

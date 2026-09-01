// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Cell struct {
	Engine      string `json:"engine"`
	Tier        string `json:"tier"`
	Mode        string `json:"mode"`
	Phase       string `json:"phase"`
	Concurrency int    `json:"concurrency"`
	Kind        string `json:"kind"`
	Verb        string `json:"verb"`
	Variant     string `json:"variant"`
	Sustained   bool   `json:"sustained"`
	RunID       string `json:"run_id,omitempty"`
	Objects     int    `json:"objects,omitempty"`
}
type Result struct {
	Cell              Cell            `json:"cell"`
	InputHash         string          `json:"input_hash"`
	RunID             string          `json:"run_id,omitempty"`
	EnvironmentID     string          `json:"environment_id,omitempty"`
	Environment       Environment     `json:"environment,omitempty"`
	WorkloadHash      string          `json:"workload_hash,omitempty"`
	ConfigHash        string          `json:"config_hash,omitempty"`
	Status            string          `json:"status"`
	Error             string          `json:"error,omitempty"`
	Samples           int             `json:"samples"`
	Successes         int             `json:"successes,omitempty"`
	Errors            int             `json:"errors,omitempty"`
	Errors429         int             `json:"errors_429,omitempty"`
	Operations        []Operation     `json:"operations,omitempty"`
	Trace             []MutationTrace `json:"trace,omitempty"`
	P50Micros         int64           `json:"p50_micros,omitempty"`
	P95Micros         int64           `json:"p95_micros,omitempty"`
	P99Micros         int64           `json:"p99_micros,omitempty"`
	MaxMicros         int64           `json:"max_micros,omitempty"`
	Throughput        float64         `json:"throughput_ops_per_sec,omitempty"`
	StartedAt         string          `json:"started_at,omitempty"`
	EndedAt           string          `json:"ended_at,omitempty"`
	MetricBefore      Counter         `json:"metric_before"`
	MetricAfter       Counter         `json:"metric_after"`
	MetricDelta       Counter         `json:"metric_delta"`
	WebhookBefore     HistogramDelta  `json:"webhook_before"`
	WebhookAfter      HistogramDelta  `json:"webhook_after"`
	WebhookDelta      HistogramDelta  `json:"webhook_delta"`
	MetricBeforeState MetricState     `json:"metric_before_state,omitempty"`
	MetricAfterState  MetricState     `json:"metric_after_state,omitempty"`
	MetricDeltaState  MetricState     `json:"metric_delta_state,omitempty"`
	MetricError       string          `json:"metric_error,omitempty"`
	PodRestartsBefore Counter         `json:"pod_restarts_before"`
	PodRestartsAfter  Counter         `json:"pod_restarts_after"`
	PodRestartsDelta  Counter         `json:"pod_restarts_delta"`
}

type MutationTrace struct {
	Editor       string `json:"editor"`
	Object       string `json:"object"`
	Repeated     bool   `json:"repeated"`
	Deduplicated bool   `json:"deduplicated"`
	TamperTested bool   `json:"tamper_tested"`
	Restored     bool   `json:"restored"`
}

func (r Result) Validate() error {
	if err := validateCell(r.Cell); err != nil {
		return err
	}
	if r.RunID == "" || r.InputHash == "" || r.EnvironmentID == "" {
		return fmt.Errorf("run, input, and environment metadata are required")
	}
	if err := validateResultStatus(r); err != nil {
		return err
	}
	return validateFiniteResultValues(r)
}

func validateCell(c Cell) error {
	if c.Engine == "" || c.Tier == "" || c.Mode == "" || c.Phase == "" ||
		c.Kind == "" || c.Verb == "" || c.Variant == "" || c.Concurrency < 1 {
		return fmt.Errorf("cell identity is incomplete")
	}
	return nil
}

func validateResultStatus(r Result) error {
	if r.Status != statusComplete && r.Status != statusFailed {
		return fmt.Errorf("invalid status %q", r.Status)
	}
	if r.Status == statusComplete && (r.Samples < 1 || r.Errors != 0) {
		return fmt.Errorf("complete result must have successful samples and no errors")
	}
	if r.Status == statusFailed && r.Error == "" {
		return fmt.Errorf("failed result must include an error")
	}
	return nil
}

func validateFiniteResultValues(r Result) error {
	values := map[string]float64{
		"throughput":    r.Throughput,
		"metric_before": r.MetricBefore.Value,
		"metric_after":  r.MetricAfter.Value,
		"metric_delta":  r.MetricDelta.Value,
	}
	for name, v := range values {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("%s is non-finite", name)
		}
	}
	return nil
}

func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal canonical value: %v", err))
	}
	return b
}
func InputHash(c Cell, m []byte) string {
	h := sha256.New()
	_, _ = h.Write(canonical(c))
	_, _ = h.Write(m)
	return hex.EncodeToString(h.Sum(nil))
}
func hashBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func cellInputHash(c Cell) string {
	b, e := cellInputMaterial(c)
	if e != nil {
		b = canonical(c)
	}
	return InputHash(c, b)
}
func cellInputMaterial(c Cell) ([]byte, error) {
	if material := os.Getenv("BENCHMARK_INPUT_MATERIAL"); material != "" {
		b, e := readBenchmarkArtifact(material)
		if e != nil {
			return nil, fmt.Errorf("benchmark input material: %w", e)
		}
		return b, nil
	}
	if filepath.Base(c.Engine) != c.Engine {
		return nil, fmt.Errorf("invalid engine name %q", c.Engine)
	}
	// The engine name is checked above. G703 cannot infer that validation through Cell.
	return os.ReadFile(filepath.Join("hack", "benchmark", "manifests", c.Engine+".yaml")) // #nosec G703 -- validated engine name cannot escape manifests
}
func ProductionCoreCells() []Cell {
	out := make([]Cell, 0, 48)
	for _, e := range []string{engineMap, engineKyvernoWebhook, engineKyvernoMAP, engineCoexist} {
		for _, t := range []string{"t1", "t2", "t3", "t4"} {
			for _, m := range []string{modeCreateOnly, modeProtect, modeContributors} {
				out = append(out, Cell{Engine: e, Tier: t, Mode: m, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled})
			}
		}
	}
	return out
}
func Cells(q bool) []Cell {
	out := ProductionCoreCells()
	if q {
		return out[:min(8, len(out))]
	}
	return out
}
func PlannedCells(q bool) []Cell {
	if q {
		// Quick mode is intentionally a four-cell comparison: baseline and MAP
		// for t1/t2 in protect mode. The runner and plan use this same contract.
		return []Cell{
			{Engine: engineBaseline, Tier: "t1", Mode: modeProtect, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: engineBaseline},
			{Engine: engineBaseline, Tier: "t2", Mode: modeProtect, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: engineBaseline},
			{Engine: engineMap, Tier: "t1", Mode: modeProtect, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled},
			{Engine: engineMap, Tier: "t2", Mode: modeProtect, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: variantEnabled},
		}
	}
	base := Cells(q)
	out := make([]Cell, 0, 60)
	for _, tier := range []string{"t1", "t2", "t3", "t4"} {
		for _, mode := range []string{modeCreateOnly, modeProtect, modeContributors} {
			out = append(out, Cell{Engine: engineBaseline, Tier: tier, Mode: mode, Phase: phaseCore, Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed, Variant: engineBaseline})
		}
	}
	if q {
		base = ProductionCoreCells()[:8]
	}
	for _, c := range base {
		c.Variant = variantEnabled
		out = append(out, c)
	}
	return out
}

// PlannedAuxiliaryCells contains the measurements required by the benchmark
// plan in addition to the authoritative 60-cell core. They are deliberately
// kept out of PlannedCells so the core and quick contracts remain stable.
// Isolation cells run each enabled engine against one resource family at a
// time. Component cells isolate the native MAP's stamp, restore, and
// contributor paths; the exclusion toggle covers the map t1/protect path.
func PlannedAuxiliaryCells() []Cell {
	const componentTier = "t1"
	engines := []string{engineMap, engineKyvernoWebhook, engineKyvernoMAP, engineCoexist}
	out := make([]Cell, 0, len(engines)*len(isolationTiers())+4)
	for _, engine := range engines {
		for _, tier := range isolationTiers() {
			kind, err := IsolationKind(tier)
			if err != nil {
				panic(err)
			}
			out = append(out, Cell{
				Engine: engine, Tier: tier, Mode: modeProtect, Phase: phaseCore,
				Concurrency: 1, Kind: kind, Verb: verbMixed,
				Variant: variantEnabled,
			})
		}
	}
	for _, mode := range []string{modeComponentStamp, modeComponentRestore, modeComponentContrib} {
		out = append(out, Cell{
			Engine: engineMap, Tier: componentTier, Mode: mode, Phase: phaseCore,
			Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed,
			Variant: variantEnabled,
		})
	}
	out = append(out, Cell{
		Engine: engineMap, Tier: componentTier, Mode: modeProtect, Phase: phaseCore,
		Concurrency: 1, Kind: resourceServiceAccount, Verb: verbMixed,
		Variant: variantExcluded,
	})
	return out
}

// PlannedFullCells is the complete logical plan. The 60 core cells are
// followed by the explicitly named isolation/component and exclusion cells.
func PlannedFullCells(q bool) []Cell {
	core := PlannedCells(q)
	if q {
		return core
	}
	out := make([]Cell, 0, len(core)+len(PlannedAuxiliaryCells()))
	out = append(out, core...)
	return append(out, PlannedAuxiliaryCells()...)
}

// PlannedExecutionCells expands the logical matrix into the exact result
// keys emitted by executeBenchmark. Baselines are deliberately shared: one
// disabled cell per tier/mode is compared with all four enabled engines.
func PlannedExecutionCells(q bool, concurrency []int) []Cell {
	logical := PlannedCells(q)
	if len(concurrency) == 0 {
		concurrency = ConcurrencySweep(q)
	}
	out := make([]Cell, 0, len(logical)*len(BenchmarkPhases())*len(concurrency))
	for _, c := range logical {
		for _, n := range concurrency {
			for _, phase := range BenchmarkPhases() {
				p := c
				p.Phase, p.Concurrency, p.RunID = phase, n, ""
				p.Sustained = phase == phaseSustained
				out = append(out, p)
			}
		}
	}
	return out
}

// PlannedAuxiliaryExecutionCells expands only the non-core plan. Keeping this
// separate makes it possible for callers and reports to state core and
// auxiliary counts without changing the established 720-result contract.
func PlannedAuxiliaryExecutionCells(q bool, concurrency []int) []Cell {
	logical := PlannedAuxiliaryCells()
	if q {
		return nil
	}
	if len(concurrency) == 0 {
		concurrency = ConcurrencySweep(q)
	}
	out := make([]Cell, 0, len(logical)*len(BenchmarkPhases())*len(concurrency))
	for _, c := range logical {
		for _, n := range concurrency {
			for _, phase := range BenchmarkPhases() {
				p := c
				p.Phase, p.Concurrency, p.RunID = phase, n, ""
				p.Sustained = phase == phaseSustained
				out = append(out, p)
			}
		}
	}
	return out
}

// PlannedFullExecutionCells is the set written to a full run's plan file.
// Quick mode intentionally remains the existing 16-result smoke matrix.
func PlannedFullExecutionCells(q bool, concurrency []int) []Cell {
	if q {
		return PlannedExecutionCells(true, concurrency)
	}
	core := PlannedExecutionCells(false, concurrency)
	return append(core, PlannedAuxiliaryExecutionCells(false, concurrency)...)
}
func resultPath(d string, c Cell) string {
	return filepath.Join(d, cellFilename(c.RunID, c, c.Phase))
}
func sanitizeName(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return fallbackRunID
	}
	return s
}

func validateRunID(runID string) error {
	const maxRunIDLength = 49 // namespaceFor adds the 14-character creator-bench- prefix.

	if runID == "" {
		return fmt.Errorf("run ID must not be empty")
	}
	if len(runID) > maxRunIDLength {
		return fmt.Errorf("run ID %q is too long (maximum %d characters)", runID, maxRunIDLength)
	}
	for i, r := range runID {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !valid || (i == 0 && r == '-') || (i == len(runID)-1 && r == '-') {
			return fmt.Errorf("run ID %q must be a lowercase DNS label", runID)
		}
	}
	return nil
}

func defaultRunID(now time.Time) string {
	return strings.ToLower(now.UTC().Format("20060102T150405Z"))
}

func executionCell(o options) Cell {
	variant := variantEnabled
	if o.engine == engineBaseline {
		variant = engineBaseline
	}
	if o.excluded {
		variant = variantExcluded
	}
	return Cell{
		Engine: o.engine, Tier: o.tier, Mode: o.mode, Phase: phaseSustained,
		Concurrency: o.concurrency[len(o.concurrency)-1], Kind: resourceServiceAccount,
		Verb: verbMixed, Variant: variant, Sustained: true,
	}
}

func writeResult(p string, r Result) error {
	if e := os.MkdirAll(filepath.Dir(p), 0o700); e != nil {
		return e
	}
	t, e := os.CreateTemp(filepath.Dir(p), ".result-")
	if e != nil {
		return e
	}
	n := t.Name()
	defer func() { _ = os.Remove(n) }()
	x := json.NewEncoder(t)
	x.SetIndent("", "  ")
	if e = x.Encode(r); e != nil {
		_ = t.Close()
		return e
	}
	if closeErr := t.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(n, p)
}
func writePlan(dir string, cells []Cell) error {
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return fmt.Errorf("create plan directory: %w", e)
	}
	b, e := json.MarshalIndent(struct {
		Cells []Cell `json:"cells"`
	}{cells}, "", "  ")
	if e != nil {
		return fmt.Errorf("marshal plan: %w", e)
	}
	b = append(b, '\n')
	t, e := os.CreateTemp(dir, ".plan-*")
	if e != nil {
		return fmt.Errorf("create plan: %w", e)
	}
	n := t.Name()
	defer func() { _ = os.Remove(n) }()
	if _, e = t.Write(b); e != nil {
		_ = t.Close()
		return fmt.Errorf("write plan: %w", e)
	}
	if e = t.Chmod(0o600); e != nil {
		_ = t.Close()
		return fmt.Errorf("protect plan: %w", e)
	}
	if e = t.Close(); e != nil {
		return fmt.Errorf("close plan: %w", e)
	}
	if e = os.Rename(n, filepath.Join(dir, "plan.json")); e != nil {
		return fmt.Errorf("publish plan: %w", e)
	}
	return nil
}
func sortedResults(in []Result) []Result {
	o := append([]Result(nil), in...)
	sort.Slice(o, func(i, j int) bool { return string(canonical(o[i].Cell)) < string(canonical(o[j].Cell)) })
	return o
}
func BenchmarkPhases() []string {
	return []string{phaseWarmup, phaseCreate, phaseChurn, phaseSustained}
}
func ConcurrencySweep(q bool) []int {
	if q {
		return []int{8}
	}
	return []int{8, 32, 64}
}
func syntheticIdentities() []string {
	const n = 10
	o := make([]string, n)
	for i := range o {
		o[i] = fmt.Sprintf("creator-bench-%03d", i)
	}
	return o
}

type options struct {
	engine, tier, mode, kind, out, kubeconfig, runID, inputHash string
	ops, churn, identities, warmup                              int
	concurrency                                                 []int
	excluded, quick, resume                                     bool
	sustained                                                   time.Duration
	report                                                      bool
}

func parseOptions(args []string) (options, error) {
	var o options
	var cs string
	seenConcurrency := make(map[int]struct{})
	fs := flag.NewFlagSet("creator-tracking-benchmark", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.engine, "engine", engineBaseline, "engine: baseline|map|kyverno-webhook|kyverno-map|coexist")
	fs.StringVar(&o.tier, "tier", "t1", "tier t1..t4 or iso-...")
	fs.StringVar(&o.mode, "mode", "protect", "mode create-only|protect|contributors|component-*")
	fs.IntVar(&o.ops, "ops", 5000, "measured operations")
	fs.IntVar(&o.churn, "churn-rounds", 10, "update rounds")
	fs.IntVar(&o.identities, "identities", 10, "exactly ten synthetic identities")
	fs.StringVar(&cs, "concurrency", "8,32,64", "comma-separated concurrency levels")
	fs.IntVar(&o.warmup, "warmup", 200, "warmup operations")
	fs.BoolVar(&o.excluded, "excluded-usernames-bench", false, "mark the populated excluded-usernames comparison")
	fs.DurationVar(&o.sustained, "sustained-duration", 5*time.Minute, "sustained phase duration")
	fs.StringVar(&o.out, "out", "benchmarks/data/result", "CSV/JSON result prefix")
	fs.StringVar(&o.kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "kubeconfig")
	fs.StringVar(&o.runID, "run-id", "", "run identifier")
	fs.StringVar(&o.inputHash, "input-hash", "", "expected input hash")
	fs.BoolVar(&o.quick, "quick", false, "explicitly reduce operations and duration")
	fs.BoolVar(&o.report, "report", false, "validate planned cell results and write deterministic reports")
	fs.BoolVar(&o.resume, "resume", false, "resume a matching incomplete cell journal")
	if err := fs.Parse(args); err != nil {
		return o, fmt.Errorf("parse options: %w", err)
	}
	for _, s := range strings.Split(cs, ",") {
		n, e := strconv.Atoi(strings.TrimSpace(s))
		if e != nil || n < 1 {
			return o, fmt.Errorf("invalid concurrency %q", s)
		}
		if _, ok := seenConcurrency[n]; ok {
			return o, fmt.Errorf("duplicate concurrency %d", n)
		}
		seenConcurrency[n] = struct{}{}
		o.concurrency = append(o.concurrency, n)
	}
	sort.Ints(o.concurrency)
	if o.quick {
		o.concurrency = []int{8}
		o.ops = min(o.ops, 500)
		o.warmup = min(o.warmup, 10)
		o.churn = min(o.churn, 2)
		if o.sustained > 10*time.Second {
			o.sustained = 10 * time.Second
		}
	}
	return o, validateOptions(o)
}
func validateOptions(o options) error {
	if o.resume && !o.report && o.runID == "" {
		return fmt.Errorf("-resume requires -run-id")
	}
	if o.runID != "" {
		if err := validateRunID(o.runID); err != nil {
			return err
		}
	}
	if !map[string]bool{engineBaseline: true, engineMap: true, engineKyvernoWebhook: true, engineKyvernoMAP: true, engineCoexist: true}[o.engine] {
		return fmt.Errorf("invalid engine %q", o.engine)
	}
	if o.tier == "" || o.mode == "" {
		return fmt.Errorf("tier and mode are required")
	}
	if _, err := TierResources(o.tier); err != nil {
		if _, isolationErr := IsolationResource(o.tier); isolationErr != nil {
			return fmt.Errorf("invalid tier %q: %w", o.tier, err)
		}
	}
	if !validBenchmarkMode(o.mode) {
		return fmt.Errorf("invalid mode %q", o.mode)
	}
	if o.ops < 1 || o.churn < 1 || o.identities != 10 || o.warmup < 1 || o.sustained <= 0 {
		return fmt.Errorf("ops, churn-rounds, and warmup must be positive, identities must be exactly 10, and sustained-duration must be positive")
	}
	if o.kubeconfig == "" && !o.report {
		return fmt.Errorf("kubeconfig is required")
	}
	return nil
}

// executionTimeout covers one sustained phase for every configured
// concurrency level, plus the fixed lifecycle allowance for setup, warmup,
// churn, cleanup, and API-server settling. Concurrency levels are executed
// serially within a cell, so budgeting only one sustained duration can cancel
// a valid multi-level run prematurely.
func executionTimeout(o options) time.Duration {
	levels := len(o.concurrency)
	if levels < 1 {
		levels = 1
	}
	return time.Duration(levels)*o.sustained + 30*time.Minute
}

func inputHashMismatchError(expected, computed string) error {
	return fmt.Errorf("input hash mismatch: expected %q, computed %q", expected, computed)
}

func main() {
	os.Exit(runMain(os.Args[1:]))
}

func runMain(args []string) int {
	o, e := parseOptions(args)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if o.runID == "" {
		o.runID = defaultRunID(time.Now())
	}
	if e = validateRunID(o.runID); e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 2
	}
	if o.report {
		rs, reportErr := LoadResults(filepath.Clean(o.out))
		if reportErr == nil {
			if _, planErr := LoadPlannedResults(filepath.Clean(o.out)); planErr != nil {
				reportErr = WritePartialReports(filepath.Clean(o.out), rs)
				if reportErr == nil {
					reportErr = planErr
				}
			} else {
				reportErr = WriteReports(filepath.Clean(o.out), rs)
			}
		}
		if reportErr != nil {
			fmt.Fprintln(os.Stderr, reportErr)
			return 1
		}
		return 0
	}
	planPath := filepath.Join(filepath.Clean(o.out), "plan.json")
	if _, statErr := os.Stat(planPath); os.IsNotExist(statErr) {
		if e = writePlan(filepath.Clean(o.out), PlannedFullExecutionCells(o.quick, o.concurrency)); e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 1
		}
	} else if statErr != nil {
		fmt.Fprintln(os.Stderr, statErr)
		return 1
	}
	base, e := loadConfig(o.kubeconfig)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), executionTimeout(o))
	c := executionCell(o)
	if o.inputHash != "" {
		computedInputHash := cellInputHash(c)
		if o.inputHash != computedInputHash {
			fmt.Fprintln(os.Stderr, inputHashMismatchError(o.inputHash, computedInputHash))
			cancel()
			return 2
		}
	}
	if e = executeBenchmark(ctx, base, c, o, filepath.Clean(o.out)); e != nil {
		fmt.Fprintln(os.Stderr, e)
		cancel()
		return 1
	}
	cancel()
	return 0
}

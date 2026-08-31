// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

func deterministicName(cell Cell, i int) string {
	parts := []string{"creator-bench", cell.RunID, cell.Engine, cell.Tier, cell.Mode, cell.Phase, fmt.Sprintf("%05d", i)}
	name := strings.Trim(strings.Join(parts, "-"), "-")
	if len(name) > 63 {
		suffix := fmt.Sprintf("-%x", sha256.Sum256([]byte(name)))[:9]
		name = name[:63-len(suffix)] + suffix
	}
	return name
}
func percentile(v []int64, p float64) int64 {
	if len(v) == 0 {
		return 0
	}
	x := append([]int64(nil), v...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	n := int(math.Ceil(p*float64(len(x)))) - 1
	if n < 0 {
		n = 0
	}
	if n >= len(x) {
		n = len(x) - 1
	}
	return x[n]
}
func summarize(r *CellRun, started time.Time) {
	var l []int64
	for _, o := range r.Operations {
		if o.Error == "" {
			l = append(l, o.LatencyMicros)
		}
	}
	r.Samples = len(l)
	r.Successes = r.Samples
	r.Errors = len(r.Operations) - r.Samples
	for _, op := range r.Operations {
		if op.Status == 429 {
			r.Errors429++
		}
	}
	r.P50Micros = percentile(l, .5)
	r.P95Micros = percentile(l, .95)
	r.P99Micros = percentile(l, .99)
	for _, x := range l {
		if x > r.MaxMicros {
			r.MaxMicros = x
		}
	}
	if r.Errors > 0 && r.Error == "" {
		r.Error = fmt.Sprintf("%d operations failed", r.Errors)
	}
	if d := time.Since(started).Seconds(); d > 0 {
		r.Throughput = float64(r.Samples) / d
	}
}
func statusFor(verb string, e error) int {
	if e != nil {
		if s, ok := e.(apierrors.APIStatus); ok {
			return int(s.Status().Code)
		}
		return 0
	}
	if verb == phaseCreate || verb == phaseWarmup {
		return 201
	}
	return 200
}

//nolint:gocyclo // The benchmark operation loop keeps mode-specific mutation semantics together.
func runPhaseWithClientsProgressOffset(
	ctx context.Context, resources []dynamic.ResourceInterface, cell Cell,
	ops, workers int, ids []string, namespace string, duration time.Duration,
	offset int, progress func(int) error,
) CellRun {
	started := time.Now()
	out := CellRun{Cell: cell, Status: statusRunning, StartedAt: started.UTC().Format(time.RFC3339Nano), InputHash: InputHash(cell, canonical(cell))}
	if len(ids) == 0 {
		ids = []string{defaultEditorIdentity}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var progressErr error
	addTrace := func(t MutationTrace) { mu.Lock(); out.Trace = append(out.Trace, t); mu.Unlock() }
	next := offset
	rec := func(o Operation) {
		mu.Lock()
		out.Operations = append(out.Operations, o)
		n := len(out.Operations)
		mu.Unlock()
		if progress != nil && n%100 == 0 {
			if err := progress(offset + n); err != nil {
				mu.Lock()
				if progressErr == nil {
					progressErr = err
				}
				mu.Unlock()
			}
		}
	}
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				i := next
				next++
				mu.Unlock()
				if duration <= 0 && i >= ops {
					return
				}
				if duration > 0 && time.Since(started) >= duration {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				verb := cell.Phase
				name := deterministicName(cell, i)
				if cell.Phase == phaseChurn {
					verb = verbUpdate
					objects := cell.Objects
					if objects < 1 {
						objects = 1
					}
					if cell.Mode == modeCreateOnly {
						verb = phaseCreate
						name = deterministicName(cell, i)
					} else {
						name = deterministicName(Cell{RunID: cell.RunID, Engine: cell.Engine, Tier: cell.Tier, Mode: cell.Mode, Phase: phaseCreate}, i%objects)
					}
				}
				if cell.Phase == phaseSustained && i%2 == 1 {
					if cell.Mode == modeCreateOnly {
						verb = phaseCreate
						name = deterministicName(cell, i)
					} else {
						verb = verbUpdate
						name = deterministicName(Cell{RunID: cell.RunID, Engine: cell.Engine, Tier: cell.Tier, Mode: cell.Mode, Phase: phaseCreate}, i/2)
					}
				}
				s, e := specFor(cell.Kind)
				if e != nil {
					rec(Operation{Verb: verb, Error: e.Error()})
					continue
				}
				r := resources[i%len(resources)]
				obj := objectFor(cell, name, namespace, s)
				st := time.Now()
				var err error
				// create-only is intentionally a pure create workload. Protect
				// exercises the admission restoration path by forging labels before
				// restoring the protected object; contributors rotate identities on
				// every request through the resource slice above.
				if cell.Mode == modeCreateOnly {
					verb = phaseCreate
				}
				if verb == verbUpdate {
					old, getErr := r.Get(ctx, name, metav1.GetOptions{})
					if getErr != nil {
						err = getErr
					} else {
						restoredByContributor := false
						switch cell.Mode {
						case modeProtect:
							forged := old.DeepCopy()
							forged.SetLabels(map[string]string{"t-caas.telekom.com/benchmark-forged": booleanTrue})
							// A protected webhook may reject the forged update; that is the
							// expected outcome. Always issue the restoration update.
							_, _ = r.Update(ctx, forged, metav1.UpdateOptions{})
							if refreshed, refreshErr := r.Get(ctx, name, metav1.GetOptions{}); refreshErr == nil {
								old = refreshed
							}
						case modeContributors:
							// Exercise the same editor twice, then attempt a forged
							// replacement/removal and verify the managed labels return.
							editor := ids[i%len(ids)]
							first := old.DeepCopy()
							annotations := first.GetAnnotations()
							if annotations == nil {
								annotations = map[string]string{}
							}
							annotations["t-caas.telekom.com/benchmark-editor"] = editor
							first.SetAnnotations(annotations)
							var updated *unstructured.Unstructured
							repeatedOK := false
							updated, err = r.Update(ctx, first, metav1.UpdateOptions{})
							if err == nil {
								first = updated
							}
							if err == nil {
								updated, err = r.Update(ctx, first.DeepCopy(), metav1.UpdateOptions{})
								if err == nil {
									first = updated
									repeatedOK = true
								}
							}
							forged := first.DeepCopy()
							forged.SetLabels(map[string]string{"t-caas.telekom.com/benchmark-forged": booleanTrue})
							if forgedResult, forgeErr := r.Update(ctx, forged, metav1.UpdateOptions{}); forgeErr == nil {
								forged = forgedResult
							}
							old = forged
							old.SetLabels(obj.GetLabels())
							restored, restoreErr := r.Update(ctx, old, metav1.UpdateOptions{})
							if restoreErr != nil && err == nil {
								err = restoreErr
							}
							if restoreErr == nil {
								old = restored
							}
							observed, getErr := r.Get(ctx, name, metav1.GetOptions{})
							addTrace(MutationTrace{
								Editor: editor, Object: name, Repeated: true,
								Deduplicated: repeatedOK, TamperTested: true,
								Restored: getErr == nil && labelsEqual(
									observed.GetLabels(), obj.GetLabels(),
								),
							})
							restoredByContributor = true
						default:
							// Other modes use the common restoration path below.
						}
						if !restoredByContributor {
							old.SetLabels(obj.GetLabels())
							_, err = r.Update(ctx, old, metav1.UpdateOptions{})
						}
					}
				} else {
					_, err = r.Create(ctx, obj, metav1.CreateOptions{})
				}
				op := Operation{Verb: verb, LatencyMicros: time.Since(st).Microseconds(), Status: statusFor(verb, err)}
				if err != nil {
					op.Error = err.Error()
				}
				rec(op)
			}
		}()
	}
	wg.Wait()
	summarize(&out, started)
	out.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if ctx.Err() != nil {
		out.Status = statusFailed
		out.Error = ctx.Err().Error()
	} else if out.Error == "" && out.Errors == 0 {
		out.Status = statusComplete
	}
	if out.Samples == 0 {
		out.Status = statusFailed
		if out.Error == "" {
			out.Error = "zero successful samples"
		}
	}
	if out.Errors > 0 {
		out.Status = statusFailed
	}
	if progressErr != nil {
		out.Status = statusFailed
		out.Error = fmt.Errorf("journal checkpoint: %w", progressErr).Error()
	}
	return out
}

func labelsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// runMixedPhase executes the ordered tier resource mix. Each identity gets a
// client for every resource and the work is partitioned across resources, so
// tier annotations cannot accidentally stand in for real API traffic.
func runMixedPhaseWithOffset(
	ctx context.Context, clients []dynamic.Interface, kinds []string, cell Cell,
	ops, workers int, ids []string, namespace string, duration time.Duration,
	offset int, progress func(int) error,
) CellRun {
	started := time.Now()
	out := CellRun{Cell: cell, Status: statusRunning, StartedAt: started.UTC().Format(time.RFC3339Nano), InputHash: InputHash(cell, canonical(cell))}
	if len(kinds) == 0 {
		kinds = []string{cell.Kind}
	}
	if duration > 0 {
		return runMixedSustained(ctx, clients, kinds, cell, workers, ids, namespace, duration, offset, progress)
	}
	consumed := 0
	for ri, kind := range kinds {
		s, err := specFor(kind)
		if err != nil {
			out.Status = statusFailed
			out.Error = err.Error()
			return out
		}
		targets := make([]dynamic.ResourceInterface, len(clients))
		for i, cl := range clients {
			if s.namespaced {
				targets[i] = cl.Resource(s.gvr).Namespace(namespace)
			} else {
				targets[i] = cl.Resource(s.gvr)
			}
		}
		count := ops / len(kinds)
		if ri < ops%len(kinds) {
			count++
		}
		localOffset := offset - consumed
		if localOffset < 0 {
			localOffset = 0
		}
		if localOffset > count {
			localOffset = count
		}
		partCell := Cell{
			Engine: cell.Engine, Tier: cell.Tier, Mode: cell.Mode, Phase: cell.Phase,
			Concurrency: cell.Concurrency, Kind: kind, Verb: cell.Verb,
			Variant: cell.Variant, Sustained: cell.Sustained, RunID: cell.RunID,
			Objects: cell.Objects,
		}
		part := runPhaseWithClientsProgressOffset(ctx, targets, partCell, count,
			workers, ids, namespace, 0, localOffset, func(n int) error {
				if progress != nil {
					return progress(consumed + n)
				}
				return nil
			})
		out.Operations = append(out.Operations, part.Operations...)
		out.Trace = append(out.Trace, part.Trace...)
		if part.Error != "" && out.Error == "" {
			out.Error = part.Error
		}
		if part.Status != statusComplete {
			out.Status = statusFailed
		}
		consumed += count
	}
	summarize(&out, started)
	out.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if ctx.Err() != nil {
		out.Status = statusFailed
		out.Error = ctx.Err().Error()
	} else if out.Error == "" && out.Errors == 0 {
		out.Status = statusComplete
	}
	if out.Errors > 0 {
		out.Status = statusFailed
	}
	return out
}

// mixedWorkerCounts partitions the configured concurrency across resource
// kinds. The concurrency value is a total budget for a mixed cell, rather
// than a per-kind multiplier. When there are enough workers, every kind gets
// one and the remainder is distributed deterministically.
func mixedWorkerCounts(workers, kindCount int) []int {
	if workers < 1 || kindCount < 1 {
		return make([]int, kindCount)
	}
	counts := make([]int, kindCount)
	if workers < kindCount {
		// It is impossible to service every kind concurrently with fewer
		// workers than kinds. Assign the available budget deterministically;
		// the caller gates remaining kinds into later slots.
		for i := range workers {
			counts[i] = 1
		}
		return counts
	}
	for i := range counts {
		counts[i] = 1
	}
	for i := range workers - kindCount {
		counts[i%kindCount]++
	}
	return counts
}

// runMixedSustained runs every resource kind against one shared deadline. A
// sustained tier is a mixed workload, so serially spending the whole deadline
// on the first kind would silently omit the remaining resources.
//
//nolint:gocyclo // Sustained mixed scheduling handles shared deadlines and resume accounting here.
func runMixedSustained(
	ctx context.Context, clients []dynamic.Interface, kinds []string, cell Cell,
	workers int, ids []string, namespace string, duration time.Duration,
	offset int, progress func(int) error,
) CellRun {
	started := time.Now()
	deadline := started.Add(duration)
	phaseCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	out := CellRun{Cell: cell, Status: statusComplete, StartedAt: started.UTC().Format(time.RFC3339Nano), InputHash: InputHash(cell, canonical(cell))}
	var wg sync.WaitGroup
	var mu sync.Mutex
	progressByKind := make([]int, len(kinds))
	var progressErr error
	workerCounts := mixedWorkerCounts(workers, len(kinds))
	// With fewer workers than kinds, serialize kind slots so every kind gets
	// work while preserving the configured total concurrency budget and the
	// single cell deadline.
	kindSlots := 1
	if workers > 0 && workers < len(kinds) {
		kindSlots = (len(kinds) + workers - 1) / workers
	}
	gateCapacity := workers
	if gateCapacity < 1 {
		gateCapacity = 1
	}
	kindGate := make(chan struct{}, gateCapacity)
	for ri, kind := range kinds {
		kindWorkers := workerCounts[ri]
		if kindWorkers == 0 {
			kindWorkers = 1
		}
		s, err := specFor(kind)
		if err != nil {
			out.Status = statusFailed
			out.Error = err.Error()
			return out
		}
		targets := make([]dynamic.ResourceInterface, len(clients))
		for i, cl := range clients {
			if s.namespaced {
				targets[i] = cl.Resource(s.gvr).Namespace(namespace)
			} else {
				targets[i] = cl.Resource(s.gvr)
			}
		}
		localOffset := offset / len(kinds)
		if ri < offset%len(kinds) {
			localOffset++
		}
		wg.Add(1)
		go func(ri int, kind string, targets []dynamic.ResourceInterface, localOffset, kindWorkers int) {
			defer wg.Done()
			select {
			case kindGate <- struct{}{}:
			case <-phaseCtx.Done():
				return
			}
			defer func() { <-kindGate }()
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return
			}
			kindDuration := remaining
			if kindSlots > 1 {
				kindDuration = duration / time.Duration(kindSlots)
				if kindDuration <= 0 {
					kindDuration = remaining
				}
			}
			partCell := Cell{
				Engine: cell.Engine, Tier: cell.Tier, Mode: cell.Mode,
				Phase: cell.Phase, Concurrency: cell.Concurrency, Kind: kind,
				Verb: cell.Verb, Variant: cell.Variant, Sustained: cell.Sustained,
				RunID: cell.RunID, Objects: cell.Objects,
			}
			part := runPhaseWithClientsProgressOffset(phaseCtx, targets, partCell,
				0, kindWorkers, ids, namespace, kindDuration, localOffset, func(n int) error {
					mu.Lock()
					progressByKind[ri] = n - localOffset
					total := offset
					for _, done := range progressByKind {
						total += done
					}
					if progress != nil && progressErr == nil {
						progressErr = progress(total)
					}
					mu.Unlock()
					return progressErr
				})
			mu.Lock()
			out.Operations = append(out.Operations, part.Operations...)
			out.Trace = append(out.Trace, part.Trace...)
			// A slot may end at its local duration boundary with a successful
			// operation but a zero-sample status from the child phase. Preserve
			// the aggregate success rather than turning the mixed cell into a
			// failure solely because that slot stopped on time.
			if part.Error != "" && out.Error == "" && (part.Errors > 0 || len(part.Operations) == 0) {
				out.Error = part.Error
			}
			if part.Status != statusComplete && phaseCtx.Err() == nil {
				out.Status = statusFailed
			}
			mu.Unlock()
		}(ri, kind, targets, localOffset, kindWorkers)
	}
	wg.Wait()
	summarize(&out, started)
	out.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	switch {
	case ctx.Err() != nil:
		out.Status = statusFailed
		out.Error = ctx.Err().Error()
	case progressErr != nil:
		out.Status = statusFailed
		out.Error = fmt.Errorf("journal checkpoint: %w", progressErr).Error()
	case out.Errors > 0:
		out.Status = statusFailed
	}
	if out.Samples == 0 {
		out.Status = statusFailed
		if out.Error == "" {
			out.Error = "zero successful samples"
		}
	}
	return out
}

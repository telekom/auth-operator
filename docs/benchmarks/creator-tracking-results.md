# Creator-tracking benchmark results

## Status: pending

No authorized runtime benchmark result is committed yet. The quick benchmark
is a smoke check and is not release evidence. Do not interpret the absence of a
row as zero overhead, and do not use this document to claim a default-on
recommendation.

The reproducible workload and lifecycle are defined in the [benchmark
methodology](creator-tracking-methodology.md). This report will be populated
only after the complete run, provenance validation, and review finish.

## Planned evidence

The final report will include the following, with raw data committed under
`docs/benchmarks/data/`:

- Environment and provenance: architecture, CPU and memory capacity, Go, Kind,
  Kubernetes, Helm, Kyverno, node image digest, chart and operator versions,
  container runtime, host information, policy/configuration hashes, and run ID.
- Absolute results for the 60-cell core matrix and its 720 phase/concurrency
  results, plus the auxiliary per-kind, component, and exclusion cells.
- Separate CREATE and UPDATE measurements for warmup, create, churn, and
  sustained phases at concurrency 8, 32, and 64.
- p50, p95, p99, maximum latency, successful-operation throughput, errors, and
  HTTP 429 counts.
- Supporting API-server mutating-admission and webhook metric deltas,
  including unavailable and reset states, plus operator pod restart deltas.
- Relative rows against a matching same-run baseline, including delta in
  milliseconds and percentage overhead.
- Tier marginal cost, mode marginal cost, per-kind isolation, concurrency
  summaries, and an interpretation of native CEL, Kyverno generated MAP, and
  Kyverno webhook behavior.

## Decision gate

This section is intentionally unresolved until the evidence above is complete.
The final verdict must explicitly decide:

1. Whether the default resource list remains unchanged.
2. Whether `protect` remains the default mode.
3. Whether creator tracking remains opt-in or becomes enabled by default.

The current provisional decision is to keep `enabled: false`, `mode: protect`,
and the reviewed resource list. This is a configuration safeguard, not a
benchmark result. Any later default change must update the chart values,
schema, chart README, render tests, native and Kyverno E2E coverage, and this
report together.

## Publication checklist

- [ ] Complete the quick run and interruption/resume proof.
- [ ] Complete the full core and auxiliary matrix without reducing it.
- [ ] Validate all raw rows, hashes, baseline joins, metric states, and
  environment provenance.
- [ ] Copy validated CSV evidence into `docs/benchmarks/data/`.
- [ ] Render and review the absolute and relative tables.
- [ ] Record the measured default verdict and update the final documentation.

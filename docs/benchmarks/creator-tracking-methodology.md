# Creator-tracking benchmark methodology

This benchmark is an explicit, reproducible plan. It does not make a default
decision from a smoke test or from measurements taken on a shared cluster.

## Current status

Runtime authorization and measured benchmark results are pending. The
[results report](creator-tracking-results.md) is intentionally a pending
shell until the complete matrix, auxiliary cells, and provenance checks pass.

## Lifecycle plan

1. Acquire the persistent private benchmark lock (`0600`).
2. Create a collision-resistant run directory (`0700`), kubeconfig, run ID,
   image tag, and Kind cluster name. Fresh runs refuse pre-existing targets;
   resume runs require the exact ownership marker and identity file.
3. Build the current operator image, create Kind Kubernetes 1.36.1 using the
   pinned node digest, and load only that run's image.
4. For each mode, measure five variants: the shared disabled baseline, native
   MAP, Kyverno classic webhook, Kyverno-generated MAP, and coexistence (native
   MAP plus the classic Kyverno webhook in the same cluster). Every
   installation is waited on before measured requests. Only the four enabled
   engine variants receive semantic admission probes; the disabled baseline is
   checked for readiness without claiming creator-tracking behavior. The
   selected mode changes native MAP operations, Kyverno MAP operations, and the
   workload; classic Kyverno remains its documented creator-only compatibility
   behavior.
5. Use Kyverno 1.19.0 chart 3.9.0 from its direct archive URL after verifying
   its SHA-256 digest. Generated MAP support is enabled explicitly in Helm
   values.
6. Run the exact full core matrix (five variants, four enabled engines plus the
   baseline, four tiers, three modes, warmup, create, churn, and sustained
   phases at all configured concurrency levels). Each non-sustained phase has
   200 warmup or 5000 CREATE/UPDATE requests per matched resource kind; churn
   performs ten update rounds over that per-kind object pool, and sustained
   keeps an approximately 50/50 CREATE/UPDATE mix for every mode. The core is
   60 logical cells, or 720 phase/concurrency results with the default 8/32/64 sweep. In the same
   run, schedule the auxiliary plan: 20 per-kind isolation cells (five
   resource families across the four enabled engines), three native-MAP
   component cells (stamp, restore, contributor), and one populated
   `excludedUsernames` toggle. This adds 24 logical cells and 288 results,
   for 84 logical cells and 1008 results in a complete run. Auxiliary Kyverno
   cells use the reduced 1000-operation profile from the benchmark plan. The
   quick target remains intentionally reduced to its existing t1/t2 baseline
   and native MAP protect cells; it is not used as the full result.
   The exclusion cell configures `creator-bench-excluded`, outside the ten
   measured identities, so it isolates the matcher cost of a populated list;
   stable and beta E2E tests separately prove matching exclusion behavior.
7. Write raw JSON/CSV and deterministic Markdown reports. Interrupted cells
   keep their journal and can be resumed only with the same run, input, and
   environment metadata.
8. On success, remove only the exact owned cluster, namespaces (with deletion
   confirmation), image, kubeconfig, and run directory, then verify that each
   target is absent. An interrupted fresh run retains its owned state and
   journals for an explicit resume command; failed resume runs retain the same
   state. Engine transitions wait for policy and binding deletion before the
   next engine is installed.

## Entry points and output

The live runner requires a Linux environment with `flock`, `setsid`, Docker,
Kind, Helm, kubectl, Go, and GNU `timeout`. On macOS, use the project's Linux
development VM; the static target remains portable and supplies isolated test
shims for the Linux-only process controls.

- `make benchmark-creator-tracking-static` runs the runner safety checks only.
- `make benchmark-creator-tracking-quick` runs the reduced local and CI smoke
  benchmark. Its measurements are not release evidence.
- `make benchmark-creator-tracking` runs the complete long-running matrix.

Fresh runs write private runtime results below `benchmarks/data/<run-id>/`.
The directory contains aggregate `results.csv`, `results.md`, and
`results.json`, `raw-results.csv`, per-cell journals, and captured input
material. Interrupted aggregation uses the corresponding `partial-results.*`
and `partial-raw-results.csv` names. Curated evidence is copied into
`docs/benchmarks/data/` only after validation.

After an interruption or a failed resume, the runner prints the retained
absolute run-directory path. Resume that exact full run with:

```bash
BENCHMARK_MODE=resume \
BENCHMARK_RUN_DIR=/private/tmp/auth-operator-benchmark.<run-id>.<suffix> \
make benchmark-creator-tracking
```

Use `make benchmark-creator-tracking-quick` instead when resuming a quick run.
If the fresh run used a non-default `RESULTS_DIR`, pass that same canonical
absolute path during resume.

Resume reuses immutable, atomically captured policy input material scoped to
the core, isolation, component, or exclusion pass. Exact completed cells are
skipped. An interrupted or failed cell is cleaned and replayed from its first
phase, so deterministic CREATE names and the state needed by later UPDATE
phases are reconstructed before its prior results are atomically replaced.
Completed-cell replay never cleans the shared workload namespace that may hold
a later interrupted cell.

Client-observed latency is primary. API-server and webhook metrics are
supporting telemetry and are recorded before/after with reset state. Each
measured phase also probes the restartCount values of auth-operator pods before
and after the workload and records the delta (including missing, unavailable,
and reset states); this is evidence of pod restarts, not a synthetic estimate.
Raw and aggregate JSON/CSV plus Markdown expose the same latency, error,
metric, webhook, restart, run ID, input hash, workload hash, configuration hash,
and environment provenance fields. Environment provenance includes the pinned
tool and cluster versions, node image, architecture, capacity, operator/chart
versions, policy hash, container runtime, host model, and captured evidence.
No benchmark result is a default-on recommendation until the complete matrix
and its provenance checks pass.

The reports validate the full plan file, so an incomplete run cannot be
presented as complete: core results remain identifiable as the 60-cell/720
result matrix, while isolation, component, and exclusion rows are reported as
their own `tier`, `mode`, and `variant` values.

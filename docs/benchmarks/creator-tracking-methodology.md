# Creator-tracking benchmark methodology

This benchmark is an explicit, reproducible plan. It does not make a default
decision from a smoke test or from measurements taken on a shared cluster.

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
6. Run the exact full matrix (five variants, four enabled engines plus the
   baseline, four tiers, three modes, warmup,
   create, churn, and sustained phases at all configured concurrency levels).
   The quick target is intentionally reduced to t1/t2 baseline and native MAP
   protect cells; it is not used as the full result.
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

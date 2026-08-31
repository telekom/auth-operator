#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

# Static lifecycle guard. This deliberately does not require Docker, Kind,
# Helm, a cluster, or network access; live lifecycle is exercised separately.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
runner="$root/hack/benchmark/run.sh"
test_tmp_root=$(cd -P -- "${TMPDIR:-/tmp}" && pwd -P)
grep -Fq "flock -n 9" "$runner"
grep -Fq "chmod 600 \"\$lock_file\"" "$runner"
grep -Fq 'source "$repo_root/versions.env"' "$runner"
grep -Fq 'readonly kind_node_image=$E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE' "$runner"
grep -Fq 'readonly kyverno_chart_url=$KYVERNO_CHART_URL' "$runner"
grep -Fq 'readonly kyverno_chart_sha256=$KYVERNO_CHART_SHA256' "$runner"
grep -Fq 'readonly kyverno_chart_version=$KYVERNO_CHART_VERSION' "$runner"
! grep -Fq 'kindest/node:' "$runner"
grep -Fq 'BENCHMARK_MODE' "$runner"
grep -Fq 'BENCHMARK_RUN_DIR' "$runner"
grep -Fq 'RESULTS_DIR is outside the repository or private benchmark temporary area' "$runner"
grep -Fq 'benchmark path is not canonical' "$runner"
grep -Fq 'refusing to adopt existing Kind cluster' "$runner"
grep -Fq "kind delete cluster --name \"\$cluster\"" "$runner"
grep -Fq 'helm uninstall auth-operator' "$runner"
grep -Fq 'crds.groups.policies.mutatingpolicies=true' "$runner"
grep -Fq 'features.generateMutatingAdmissionPolicy.enabled=true' "$runner"
grep -Fq 'engines=(baseline map kyverno-webhook kyverno-map coexist)' "$runner"
grep -Fq 'engines=(baseline map); tiers=(t1 t2); modes=(protect)' "$runner"
grep -Fq 'phase shasum -a 256 -c -' "$runner"
grep -Fq "kubectl wait --for=delete \"namespace/\$namespace\"" "$runner"
grep -Fq 'auth-operator-creator-tracking' "$runner"
grep -Fq 'creator-tracking-kyverno-clusterpolicy.yaml' "$runner"
grep -Fq 'assert_owned_cluster' "$runner"
grep -Fq 'io.x-k8s.kind.cluster' "$runner"
grep -Fq 'benchmark-run' "$runner"
grep -Fq 'probe_admission' "$runner"
grep -Fq 'BENCH_NODE_IMAGE="$kind_node_image"' "$runner"
grep -Fq 'export BENCH_KYVERNO_CHART="$kyverno_chart_version"' "$runner"
grep -Fq 'export BENCH_KYVERNO_VERSION="$kyverno_version"' "$runner"
grep -Fq 'helm show chart "$archive"' "$runner"
grep -Fq 'Kyverno chart appVersion is' "$runner"
grep -Fq 'captured per-engine policy inputs' "$root/hack/benchmark/metadata.go"
grep -Fq 'mutatingadmissionpolicybinding auth-operator-creator-tracking' "$runner"
grep -Fq 'mutatingadmissionpolicybinding mpol-creator-tracking-binding mpol-contributor-tracking-binding' "$runner"
grep -Fq 'Only the four enabled' "$root/docs/benchmarks/creator-tracking-methodology.md"
grep -Fq 'operations: ["CREATE"]' "$runner"
grep -Fq 'bounded_pid' "$runner"
grep -Fq 'terminate_bounded' "$runner"
grep -Fq 'setsid "$timeout_bin"' "$runner"
grep -Fq 'kill -TERM -- "-$pid"' "$runner"
grep -Fq 'wait "$pid"' "$runner"
grep -Fq 'bounded env DOCKER_BUILDKIT=1 docker build' "$runner"
grep -Fq 'validate_owned_tree "$results_dir"' "$runner"
grep -Fq 'validate_owned_tree "$run_dir"' "$runner"
cleanup_source=$(sed -n '/^cleanup_owned()/,/^finish()/p' "$runner")
grep -Fq 'assert_owned_cluster ||' <<<"$cleanup_source"
grep -Fq 'assert_owned_image ||' <<<"$cleanup_source"
grep -Fq 't-caas.telekom.com/benchmark-mode=$mode' "$runner"
grep -Fq 'phase kubectl annotate serviceaccount "$probe_name"' "$runner"
if [[ $(grep -Fc 'phase kubectl create serviceaccount "$probe_name"' "$runner") -ne 1 ]]; then
  echo 'semantic probe must create its ServiceAccount exactly once' >&2
  exit 1
fi
grep -Fq '[[ "$active_mode" == contributors ]]' "$runner"
if sed -n '/^label_policy_mode()/,/^semantic_activate()/p' "$runner" | grep -Fq '|| true'; then
  echo 'benchmark runner must not swallow policy-label or results-security failures' >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq '"$original" == 130 || "$original" == 143' "$runner"
grep -Fq -- '--ignore-not-found --wait=true' "$runner"
grep -Fq 'policy teardown was not confirmed' "$runner"
grep -Fq 'Helm release teardown was not confirmed' "$runner"
if grep -Fq 'helm uninstall kyverno --namespace "$kyverno_namespace" --ignore-not-found || true' "$runner"; then
  echo 'Kyverno teardown must not ignore failures' >&2
  exit 1
fi
grep -Fq 'phase go run ./hack/benchmark' "$runner"
for manifest in baseline map kyverno-webhook kyverno-map coexist; do
  test -s "$root/hack/benchmark/manifests/$manifest.yaml"
  grep -Eq '^apiVersion:' "$root/hack/benchmark/manifests/$manifest.yaml"
  grep -Eq '^kind:' "$root/hack/benchmark/manifests/$manifest.yaml"
done

# Exercise the refusal path with a deliberately incomplete ownership marker.
# This is an interruption/resume safety guard: resume must not query or delete
# a cluster until the exact marker and identity are both valid.
probe_dir=$(mktemp -d "$test_tmp_root/auth-operator-benchmark.test.XXXXXX")
trap 'rm -rf -- "$probe_dir"' EXIT
mkdir -p "$probe_dir/bin"

# The repository Makefile exports its generic E2E cluster name. Benchmark
# targets must scrub every caller-controlled cluster selector before invoking
# the ownership-guarded runner. An invalid mode proves execution reached the
# mode check after all four selector checks.
for target in benchmark-creator-tracking benchmark-creator-tracking-quick; do
  make_error="$probe_dir/$target.error"
  if KUBECONFIG=foreign KIND_CLUSTER_NAME=foreign CLUSTER_NAME=foreign BENCHMARK_CLUSTER=foreign \
    BENCHMARK_MODE=invalid make -s -C "$root" "$target" >/dev/null 2>"$make_error"; then
    echo "$target unexpectedly accepted an invalid benchmark mode" >&2
    exit 1
  fi
  grep -Fq 'BENCHMARK_MODE must be fresh or resume' "$make_error"
done

printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$probe_dir/bin/flock"
chmod 700 "$probe_dir/bin/flock"
printf '%s\n' 'not-the-benchmark-owner' >"$probe_dir/owner"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$probe_dir/bin:$PATH" BENCHMARK_MODE=resume BENCHMARK_RUN_DIR="$probe_dir" bash "$runner" >/dev/null 2>"$probe_dir/error"; then
  echo 'resume accepted an invalid ownership marker' >&2
  exit 1
fi
grep -Eq 'ownership marker|ownership proof|resume identity' "$probe_dir/error"
test -f "$probe_dir/owner"

# A marker with an internally inconsistent cluster identity must also be
# rejected before Kind is queried. This protects resume from adopting a
# different pre-existing cluster with a copied run directory.
resume_dir="$probe_dir"
resume_run='resume-test-0011223344556677'
resume_cluster='auth-operator-bench-other-cluster'
resume_kubeconfig="$resume_dir/kubeconfig"
printf 'run_id=%s\ncluster=%s\nkubeconfig=%s\n' "$resume_run" "$resume_cluster" "$resume_kubeconfig" >"$resume_dir/identity"
printf 'owner=auth-operator-creator-tracking-benchmark/v1\nrun_id=%s\ncluster=%s\nkubeconfig=%s\noperator_image=auth-operator:creator-tracking-benchmark-%s\n' "$resume_run" "$resume_cluster" "$resume_kubeconfig" "$resume_run" >"$resume_dir/owner"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$probe_dir/bin:$PATH" BENCHMARK_MODE=resume BENCHMARK_RUN_DIR="$resume_dir" bash "$runner" >/dev/null 2>"$resume_dir/error"; then
  echo 'resume accepted an inconsistent cluster identity' >&2
  exit 1
fi
grep -Fq 'cluster does not match the run identity' "$resume_dir/error"

# Exercise the real signal path with harmless command shims. A fresh run that
# is interrupted after ownership is established must retain its marker and
# directory so the exact run can be resumed.
signal_dir=$(mktemp -d "$test_tmp_root/auth-operator-benchmark.signal.XXXXXX")
signal_bin="$signal_dir/bin"
mkdir -p "$signal_bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$signal_bin/flock"
printf '%s\n' '#!/usr/bin/env bash' 'shift 3; exec "$@"' >"$signal_bin/timeout"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'case "${1:-}" in info) exit 0;; container) exit 1;; image) exit 1;; build) touch "${SIGNAL_BUILD_MARKER:?}"; sleep 30 & child=$!; printf "%s\n" "$child" >"${SIGNAL_CHILD_PID:?}"; wait "$child";; *) exit 0;; esac' >"$signal_bin/docker"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'case "${1:-}" in get) exit 0;; *) exit 0;; esac' >"$signal_bin/kind"
chmod 700 "$signal_bin"/*
signal_marker="$signal_dir/build-started"
signal_child_pid="$signal_dir/build-child-pid"
signal_log="$signal_dir/log"
env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$signal_bin:$PATH" SIGNAL_BUILD_MARKER="$signal_marker" SIGNAL_CHILD_PID="$signal_child_pid" RUN_ID=interrupt-test RESULTS_DIR="$signal_dir/results" bash "$runner" >"$signal_dir/stdout" 2>"$signal_log" &
signal_pid=$!
for _ in $(seq 1 100); do [[ -f "$signal_marker" ]] && break; sleep 0.1; done
test -f "$signal_marker"
test -s "$signal_child_pid"
kill -TERM "$signal_pid"
if wait "$signal_pid"; then
  echo 'interrupted fresh run unexpectedly succeeded' >&2
  exit 1
fi
child_pid=$(<"$signal_child_pid")
for _ in $(seq 1 50); do
  kill -0 "$child_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$child_pid" 2>/dev/null; then
  echo 'interrupted bounded command left a child process running' >&2
  exit 1
fi
grep -Fq 'benchmark state retained for resume:' "$signal_log"
retained_dir=$(sed -n 's/.*benchmark state retained for resume: //p' "$signal_log" | tail -n 1)
test -n "$retained_dir"
test -f "$retained_dir/owner"
rm -rf -- "$retained_dir" "$signal_dir"

# Caller-controlled output paths must not escape through traversal or symlinked
# path components. These checks happen before Docker/Kind are queried.
path_dir=$(mktemp -d "$test_tmp_root/auth-operator-benchmark.paths.XXXXXX")
trap 'rm -rf -- "$path_dir"' EXIT
mkdir -p "$path_dir/results"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$path_dir/results/../escape" bash "$runner" >/dev/null 2>"$path_dir/traversal-error"; then
  echo 'runner accepted traversal in RESULTS_DIR' >&2
  exit 1
fi
grep -Fq 'benchmark path is not canonical' "$path_dir/traversal-error"
ln -s "$path_dir/results" "$path_dir/results-link"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$path_dir/results-link" bash "$runner" >/dev/null 2>"$path_dir/symlink-error"; then
  echo 'runner accepted symlinked RESULTS_DIR' >&2
  exit 1
fi
grep -Fq 'results directory is a symlink' "$path_dir/symlink-error"
rm -rf -- "$path_dir"
echo 'benchmark runner static checks passed'

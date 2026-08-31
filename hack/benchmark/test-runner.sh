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
grep -Fq 'lock_type=$(stat' "$runner"
grep -Fq 'lock_owner=$(stat' "$runner"
grep -Fq 'lock_mode=$(stat' "$runner"
grep -Fq "fixed lock must be an owned regular file with mode 600" "$runner"
grep -Fq "chmod 600 \"\$lock_file\"" "$runner"
grep -Fq 'readonly lock_dir="$system_tmp_root/auth-operator-creator-tracking-benchmark.lock.$current_uid.d"' "$runner"
grep -Fq "validate_temp_root \"\$private_tmp_root\" 'benchmark temporary root'" "$runner"
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
grep -Fq 'isolation_tiers=(iso-namespaces iso-serviceaccounts iso-secrets iso-rbac-group iso-crd-group)' "$runner"
grep -Fq 'for mode in component-stamp component-restore component-contrib' "$runner"
grep -Fq "args+=(--set-json 'creatorTracking.excludedUsernames=[\"creator-bench-excluded\"]')" "$runner"
grep -Fq "[[ \"\$engine\" != map ]] && isolation_ops=1000" "$runner"
grep -Fq 'input-material-${active_scope}-${engine}-${active_mode}-${active_variant}.yaml' "$runner"
grep -Fq 'material_tmp=$(mktemp "${material}.tmp.XXXXXX")' "$runner"
grep -Fq 'mv -- "$material_tmp" "$material"' "$runner"
for scope in core isolation component exclusion; do
  grep -Fq "active_scope=$scope" "$runner"
done
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
grep -Fq 'local -a native_bindings=(auth-operator-creator-tracking)' "$runner"
grep -Fq 'mutatingadmissionpolicybinding "${native_bindings[@]}"' "$runner"
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
grep -Fq "helm list -A --filter '^(auth-operator|kyverno)$' --short" "$runner"
! grep -Fq -- '--output name' "$runner"
grep -Fq 'available_resources=$(phase kubectl api-resources -o name)' "$runner"
grep -Fq 'grep -Fxq "$resource" <<<"$available_resources" || return 0' "$runner"
grep -Fq 'clusterpolicies.kyverno.io' "$runner"
grep -Fq 'mutatingpolicies.policies.kyverno.io' "$runner"
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
concurrent_root=''
holder_pid=''
reuse_pid=''
signal_dir=''
signal_pid=''
path_dir=''
cleanup_test_runner() {
  local pid path
  for pid in "$holder_pid" "$reuse_pid" "$signal_pid"; do
    if [[ -n "$pid" ]]; then
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  for path in "$probe_dir" "$concurrent_root" "$signal_dir" "$path_dir"; do
    [[ -z "$path" ]] || rm -rf -- "$path"
  done
}
trap cleanup_test_runner EXIT
mkdir -p "$probe_dir/bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$probe_dir/bin/flock"
printf '%s\n' '#!/usr/bin/env bash' 'shift 3; exec "$@"' >"$probe_dir/bin/timeout"
if ! command -v setsid >/dev/null 2>&1; then
  printf '%s\n' '#!/usr/bin/env perl' 'use POSIX qw(setsid);' 'setsid() or die "setsid: $!";' 'exec @ARGV or die "exec: $!";' >"$probe_dir/bin/setsid"
fi
chmod 700 "$probe_dir/bin"/*
chmod 700 "$probe_dir/bin/flock"

# The repository Makefile exports its generic E2E cluster name. Benchmark
# targets must scrub every caller-controlled cluster selector before invoking
# the ownership-guarded runner. An invalid mode proves execution reached the
# mode check after all four selector checks.
for target in benchmark-creator-tracking benchmark-creator-tracking-quick; do
  make_error="$probe_dir/$target.error"
  if KUBECONFIG=foreign KIND_CLUSTER_NAME=foreign CLUSTER_NAME=foreign BENCHMARK_CLUSTER=foreign \
    PATH="$probe_dir/bin:$PATH" \
    BENCHMARK_MODE=invalid make -s -C "$root" "$target" >/dev/null 2>"$make_error"; then
    echo "$target unexpectedly accepted an invalid benchmark mode" >&2
    exit 1
  fi
  if ! grep -Fq 'BENCHMARK_MODE must be fresh or resume' "$make_error"; then
    cat "$make_error" >&2
    exit 1
  fi
done

printf '%s\n' 'not-the-benchmark-owner' >"$probe_dir/owner"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER PATH="$probe_dir/bin:$PATH" BENCHMARK_MODE=resume BENCHMARK_RUN_DIR="$probe_dir" bash "$runner" >/dev/null 2>"$probe_dir/error"; then
  echo 'resume accepted an invalid ownership marker' >&2
  exit 1
fi
grep -Eq 'ownership marker|ownership proof|resume identity' "$probe_dir/error"
test -f "$probe_dir/owner"

# Use the host flock implementation to verify that two runner processes using
# different TMPDIR values still cannot enter concurrently. The first process
# blocks in the harmless docker-info shim after acquiring the stable real lock;
# the second must refuse immediately.
concurrent_root=$(mktemp -d "$test_tmp_root/auth-operator-benchmark.concurrent.XXXXXX")
concurrent_bin="$concurrent_root/bin"
holder_tmp="$concurrent_root/holder-tmp"
contender_tmp="$concurrent_root/contender-tmp"
reuse_tmp="$concurrent_root/reuse-tmp"
mkdir -p "$concurrent_bin"
mkdir -m 700 "$holder_tmp" "$contender_tmp" "$reuse_tmp"
concurrent_marker="$concurrent_root/started"
printf '%s\n' '#!/usr/bin/env bash' 'shift 3; exec "$@"' >"$concurrent_bin/timeout"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'exec 9>&-' 'case "${1:-}" in info) touch "${CONCURRENT_MARKER:?}"; sleep 30;; *) exit 1;; esac' >"$concurrent_bin/docker"
if ! command -v setsid >/dev/null 2>&1; then
  printf '%s\n' '#!/usr/bin/env perl' 'use POSIX qw(setsid);' 'setsid() or die "setsid: $!";' 'exec @ARGV or die "exec: $!";' >"$concurrent_bin/setsid"
fi
if ! command -v flock >/dev/null 2>&1; then
  printf '%s\n' '#!/usr/bin/env perl' 'use Fcntl qw(LOCK_EX LOCK_NB);' 'open(my $fh, "<&=9") or exit 2;' 'if (flock($fh, LOCK_EX | LOCK_NB)) { exit 0; }' 'exit 1;' >"$concurrent_bin/flock"
fi
chmod 700 "$concurrent_bin"/*
env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$holder_tmp" CONCURRENT_MARKER="$concurrent_marker" PATH="$concurrent_bin:$PATH" RUN_ID=lock-holder RESULTS_DIR="$holder_tmp/results" bash "$runner" >"$concurrent_root/holder.out" 2>"$concurrent_root/holder.err" &
holder_pid=$!
for _ in $(seq 1 100); do [[ -f "$concurrent_marker" ]] && break; sleep 0.1; done
test -f "$concurrent_marker"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$contender_tmp" CONCURRENT_MARKER="$concurrent_marker" PATH="$concurrent_bin:$PATH" RUN_ID=lock-contender RESULTS_DIR="$contender_tmp/results" bash "$runner" >/dev/null 2>"$concurrent_root/contender.err"; then
  echo 'concurrent benchmark runner unexpectedly acquired the lock' >&2
  kill -TERM "$holder_pid" 2>/dev/null || true
  wait "$holder_pid" 2>/dev/null || true
  holder_pid=''
  exit 1
fi
grep -Fq 'benchmark already running (lock:' "$concurrent_root/contender.err"
kill -TERM "$holder_pid"
wait "$holder_pid" 2>/dev/null || true
holder_pid=''

# A signal must release the descriptor so a later invocation can acquire the
# same persistent lock inode.
rm -f -- "$concurrent_marker"
env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$reuse_tmp" CONCURRENT_MARKER="$concurrent_marker" PATH="$concurrent_bin:$PATH" RUN_ID=lock-reuse RESULTS_DIR="$reuse_tmp/results" bash "$runner" >"$concurrent_root/reuse.out" 2>"$concurrent_root/reuse.err" &
reuse_pid=$!
for _ in $(seq 1 100); do [[ -f "$concurrent_marker" ]] && break; sleep 0.1; done
test -f "$concurrent_marker"
kill -TERM "$reuse_pid"
wait "$reuse_pid" 2>/dev/null || true
reuse_pid=''
rm -rf -- "$concurrent_root"
concurrent_root=''

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
printf '%s\n' '#!/usr/bin/env bash' 'exec "$@"' >"$signal_bin/setsid"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'case "${1:-}" in info) exit 0;; container) exit 1;; image) exit 1;; build) touch "${SIGNAL_BUILD_MARKER:?}"; sleep 30 & child=$!; printf "%s\n" "$child" >"${SIGNAL_CHILD_PID:?}"; wait "$child";; *) exit 0;; esac' >"$signal_bin/docker"
# shellcheck disable=SC2016
printf '%s\n' '#!/usr/bin/env bash' 'case "${1:-}" in get) exit 0;; *) exit 0;; esac' >"$signal_bin/kind"
chmod 700 "$signal_bin"/*
signal_marker="$signal_dir/build-started"
signal_child_pid="$signal_dir/build-child-pid"
signal_log="$signal_dir/log"
if ! command -v setsid >/dev/null 2>&1; then
  # macOS does not ship util-linux setsid; retain process-group semantics for
  # the signal regression with the POSIX implementation available in Perl.
  printf '%s\n' '#!/usr/bin/env perl' 'use POSIX qw(setsid);' 'setsid() or die "setsid: $!";' 'exec @ARGV or die "exec: $!";' >"$signal_bin/setsid"
fi
if ! command -v flock >/dev/null 2>&1; then
  # macOS also lacks the flock CLI. The inherited descriptor remains locked
  # after this helper exits because the parent retains the same open file.
  printf '%s\n' '#!/usr/bin/env perl' 'use Fcntl qw(LOCK_EX LOCK_NB);' 'open(my $fh, "<&=9") or exit 2;' 'if (flock($fh, LOCK_EX | LOCK_NB)) { exit 0; }' 'exit 1;' >"$signal_bin/flock"
fi
chmod 700 "$signal_bin"/*
env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$signal_dir" PATH="$signal_bin:$PATH" SIGNAL_BUILD_MARKER="$signal_marker" SIGNAL_CHILD_PID="$signal_child_pid" RUN_ID=interrupt-test RESULTS_DIR="$signal_dir/results" bash "$runner" >"$signal_dir/stdout" 2>"$signal_log" &
signal_pid=$!
for _ in $(seq 1 100); do [[ -f "$signal_marker" ]] && break; sleep 0.1; done
test -f "$signal_marker"
test -s "$signal_child_pid"
kill -TERM "$signal_pid"
if wait "$signal_pid"; then
  signal_pid=''
  echo 'interrupted fresh run unexpectedly succeeded' >&2
  exit 1
fi
signal_pid=''
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
signal_dir=''

# Caller-controlled output paths must not escape through traversal or symlinked
# path components. These checks happen before Docker/Kind are queried.
path_dir=$(mktemp -d "$test_tmp_root/auth-operator-benchmark.paths.XXXXXX")
mkdir -p "$path_dir/results"
path_tool_marker="$path_dir/tool-invoked"
for tool in docker kind kubectl helm go curl; do
  printf '%s\n' '#!/usr/bin/env bash' 'touch "${PATH_TOOL_MARKER:?}"' 'exit 97' >"$probe_dir/bin/$tool"
done
chmod 700 "$probe_dir/bin"/*
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$path_dir" PATH_TOOL_MARKER="$path_tool_marker" PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$path_dir/results/../escape" bash "$runner" >/dev/null 2>"$path_dir/traversal-error"; then
  echo 'runner accepted traversal in RESULTS_DIR' >&2
  exit 1
fi
grep -Fq 'benchmark path is not canonical' "$path_dir/traversal-error"
[[ ! -e "$path_tool_marker" ]]
[[ -z "$(find "$path_dir" -mindepth 1 -maxdepth 1 -type d -name 'auth-operator-benchmark.*' -print -quit)" ]]
ln -s "$path_dir/results" "$path_dir/results-link"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$path_dir" PATH_TOOL_MARKER="$path_tool_marker" PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$path_dir/results-link" bash "$runner" >/dev/null 2>"$path_dir/symlink-error"; then
  echo 'runner accepted symlinked RESULTS_DIR' >&2
  exit 1
fi
grep -Fq 'results directory is a symlink' "$path_dir/symlink-error"
[[ ! -e "$path_tool_marker" ]]
[[ -z "$(find "$path_dir" -mindepth 1 -maxdepth 1 -type d -name 'auth-operator-benchmark.*' -print -quit)" ]]

# Rejected paths must be side-effect free even when their parent is absent or
# a symlink. The first candidate is rejected lexically before mkdir -p; the
# second is rejected while checking an existing symlink parent.
absent_rejected_parent="$path_dir/absent-rejected-parent"
absent_rejected="$absent_rejected_parent/../rejected-result"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$path_dir" PATH_TOOL_MARKER="$path_tool_marker" PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$absent_rejected" bash "$runner" >/dev/null 2>"$path_dir/absent-error"; then
  echo 'runner accepted a traversal path with an absent parent' >&2
  exit 1
fi
grep -Fq 'benchmark path is not canonical' "$path_dir/absent-error"
[[ ! -e "$absent_rejected_parent" ]]
[[ ! -e "$path_tool_marker" ]]
[[ -z "$(find "$path_dir" -mindepth 1 -maxdepth 1 -type d -name 'auth-operator-benchmark.*' -print -quit)" ]]
symlink_target="$path_dir/symlink-target"
symlink_parent="$path_dir/symlink-parent"
mkdir -p "$symlink_target"
ln -s "$symlink_target" "$symlink_parent"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$path_dir" PATH_TOOL_MARKER="$path_tool_marker" PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$symlink_parent/new-result" bash "$runner" >/dev/null 2>"$path_dir/parent-symlink-error"; then
  echo 'runner accepted a symlinked parent path' >&2
  exit 1
fi
grep -Fq 'benchmark path parent is a symlink' "$path_dir/parent-symlink-error"
[[ ! -e "$symlink_target/new-result" ]]
[[ ! -e "$path_tool_marker" ]]
[[ -z "$(find "$path_dir" -mindepth 1 -maxdepth 1 -type d -name 'auth-operator-benchmark.*' -print -quit)" ]]

# Refusing a pre-existing non-empty output directory must not modify it.
nonempty_results="$path_dir/nonempty-results"
mkdir -m 755 "$nonempty_results"
printf '%s\n' sentinel >"$nonempty_results/preserved"
if env -u KUBECONFIG -u KIND_CLUSTER_NAME -u CLUSTER_NAME -u BENCHMARK_CLUSTER TMPDIR="$path_dir" PATH_TOOL_MARKER="$path_tool_marker" PATH="$probe_dir/bin:$PATH" RUN_ID=path-test RESULTS_DIR="$nonempty_results" bash "$runner" >/dev/null 2>"$path_dir/nonempty-error"; then
  echo 'runner accepted a non-empty results directory' >&2
  exit 1
fi
grep -Fq 'refusing to overwrite non-empty results directory' "$path_dir/nonempty-error"
test "$(<"$nonempty_results/preserved")" = sentinel
nonempty_mode=$(stat -c '%a' "$nonempty_results" 2>/dev/null || stat -f '%Lp' "$nonempty_results")
test "$nonempty_mode" = 755
[[ ! -e "$path_tool_marker" ]]
[[ -z "$(find "$path_dir" -mindepth 1 -maxdepth 1 -type d -name 'auth-operator-benchmark.*' -print -quit)" ]]
rm -rf -- "$path_dir"
path_dir=''
echo 'benchmark runner static checks passed'

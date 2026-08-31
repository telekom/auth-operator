#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
umask 077

die() { echo "creator-tracking benchmark: $*" >&2; exit 1; }
repo_root=$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
readonly repo_root
[[ -f "$repo_root/versions.env" && ! -L "$repo_root/versions.env" ]] || die 'versions.env must be a regular repository file'
set -a
# shellcheck disable=SC1091
source "$repo_root/versions.env"
set +a
: "${E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE:?versions.env must define E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE}"
: "${KYVERNO_CHART_URL:?versions.env must define KYVERNO_CHART_URL}"
: "${KYVERNO_CHART_SHA256:?versions.env must define KYVERNO_CHART_SHA256}"
: "${KYVERNO_CHART_VERSION:?versions.env must define KYVERNO_CHART_VERSION}"
: "${KYVERNO_VERSION:?versions.env must define KYVERNO_VERSION}"
readonly kind_node_image=$E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE
readonly kyverno_chart_url=$KYVERNO_CHART_URL
readonly kyverno_chart_sha256=$KYVERNO_CHART_SHA256
readonly kyverno_chart_version=$KYVERNO_CHART_VERSION
readonly kyverno_version=$KYVERNO_VERSION
readonly kyverno_app_version=${KYVERNO_VERSION#v}
export BENCH_NODE_IMAGE="$kind_node_image"
export BENCH_KYVERNO_CHART="$kyverno_chart_version"
export BENCH_KYVERNO_CHART_SHA256="$kyverno_chart_sha256"
export BENCH_KYVERNO_VERSION="$kyverno_version"
readonly owner='auth-operator-creator-tracking-benchmark/v1'
readonly phase_timeout=${BENCHMARK_PHASE_TIMEOUT:-30m}
readonly quick=${QUICK:-false}
readonly requested_mode=${BENCHMARK_MODE:-fresh}

command -v flock >/dev/null 2>&1 || die 'flock is required'
[[ -z "${BENCHMARK_LOCK:-}" ]] || die 'BENCHMARK_LOCK is not supported; the lock path is fixed'

for forbidden in KUBECONFIG KIND_CLUSTER_NAME CLUSTER_NAME BENCHMARK_CLUSTER; do
  [[ -z "${!forbidden:-}" ]] || die "$forbidden is not supported; the runner owns its target"
done
case "$requested_mode" in fresh|resume) ;; *) die 'BENCHMARK_MODE must be fresh or resume' ;; esac
command -v timeout >/dev/null 2>&1 || command -v gtimeout >/dev/null 2>&1 || die 'timeout or gtimeout is required'
command -v setsid >/dev/null 2>&1 || die 'setsid is required'
if command -v timeout >/dev/null 2>&1; then readonly timeout_bin=timeout; else readonly timeout_bin=gtimeout; fi
bounded_pid=''
terminate_bounded() {
  local status=$1 pid=$bounded_pid
  bounded_pid=''
  if [[ -n "$pid" ]]; then
    kill -TERM -- "-$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  exit "$status"
}
bounded() {
  setsid "$timeout_bin" --signal=TERM --kill-after=30s "$phase_timeout" "$@" &
  bounded_pid=$!
  local status
  if wait "$bounded_pid"; then status=0; else status=$?; fi
  bounded_pid=''
  return "$status"
}
sanitize() {
  local value=$1
  value=${value//[^a-zA-Z0-9-]/-}; value=${value#-}; value=${value%-}
  [[ -n "$value" ]] || value=run
  printf '%s' "$value" | tr '[:upper:]' '[:lower:]'
}
random_suffix() {
  if command -v openssl >/dev/null 2>&1; then openssl rand -hex 8; else od -An -N8 -tx1 /dev/urandom | tr -d ' \n'; fi
}
private_tmp_root=$(cd -P -- "${TMPDIR:-/tmp}" && pwd -P)
readonly private_tmp_root
system_tmp_root=$(cd -P -- /tmp && pwd -P)
readonly system_tmp_root
current_uid=$(id -u)
validate_temp_root() {
  local path=$1 label=$2 mode uid numeric
  [[ -d "$path" && ! -L "$path" ]] || die "$label is not a real directory: $path"
  mode=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")
  uid=$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")
  [[ "$uid" == "$current_uid" || "$uid" == 0 ]] || die "$label is owned by an untrusted user: $path"
  numeric=$((8#$mode))
  if (( (numeric & 0022) != 0 && (numeric & 01000) == 0 )); then
    die "$label is writable by another user without the sticky bit: $path"
  fi
}
validate_temp_root "$private_tmp_root" 'benchmark temporary root'
validate_temp_root "$system_tmp_root" 'system temporary root'

# Keep the lock in a stable mode-700 directory below the operating system's
# sticky temporary root. It must not follow TMPDIR: otherwise two callers could
# select different temporary roots and bypass the singleton guard. The
# directory is intentionally retained because removing a locked file while a
# contender has it open would allow a later process to create a second inode.
readonly lock_dir="$system_tmp_root/auth-operator-creator-tracking-benchmark.lock.$current_uid.d"
readonly lock_file="$lock_dir/lock"
if [[ -L "$lock_dir" || ( -e "$lock_dir" && ! -d "$lock_dir" ) ]]; then
  die "refusing non-directory lock path $lock_dir"
fi
if [[ ! -e "$lock_dir" ]]; then
  mkdir -m 700 -- "$lock_dir" || die "cannot create private lock directory $lock_dir"
fi
[[ -d "$lock_dir" && ! -L "$lock_dir" ]] || die "private lock directory is not a directory: $lock_dir"
lock_mode=$(stat -c '%a' "$lock_dir" 2>/dev/null || stat -f '%Lp' "$lock_dir")
[[ "$lock_mode" == 700 ]] || die "private lock directory has mode $lock_mode, want 700: $lock_dir"
[[ "$(stat -c '%u' "$lock_dir" 2>/dev/null || stat -f '%u' "$lock_dir")" == "$current_uid" ]] || die "private lock directory is not owned by the current user: $lock_dir"
if [[ -L "$lock_file" || ( -e "$lock_file" && ! -f "$lock_file" ) ]]; then
  die "refusing non-regular lock file $lock_file"
fi
if [[ ! -e "$lock_file" ]]; then
  # noclobber makes this an O_CREAT|O_EXCL operation, so a symlink cannot be
  # followed or truncated even if it appears after mkdir.
  (set -o noclobber; : >"$lock_file") 2>/dev/null || die "cannot create private lock file $lock_file"
fi
[[ -f "$lock_file" && ! -L "$lock_file" ]] || die "private lock file is not regular: $lock_file"
chmod 600 "$lock_file"
[[ "$(stat -c '%u' "$lock_file" 2>/dev/null || stat -f '%u' "$lock_file")" == "$current_uid" ]] || die "private lock file is not owned by the current user: $lock_file"
exec 9>>"$lock_file"
flock -n 9 || die "benchmark already running (lock: $lock_file)"

validate_owned_tree() {
  local root=$1 path mode expected
  while IFS= read -r -d '' path; do
    [[ ! -L "$path" ]] || die "owned artifact is a symlink: $path"
    if [[ -d "$path" ]]; then expected=700; else expected=600; fi
    [[ -f "$path" || -d "$path" ]] || die "owned artifact is not a file or directory: $path"
    mode=$(stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path")
    [[ "$mode" == "$expected" ]] || die "owned artifact has mode $mode, want $expected: $path"
    [[ "$(stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path")" == "$current_uid" ]] || die "owned artifact is not owned by the current user: $path"
  done < <(find "$root" -mindepth 0 -print0)
}
canonical_child_path() {
  local candidate=$1 create_parent=${2:-true} parent base parent_canonical root relative current component
  [[ "$candidate" = /* ]] || die 'benchmark paths must be absolute after expansion'
  [[ "$candidate" != */../* && "$candidate" != */./* && "$candidate" != */. && "$candidate" != */.. ]] || die "benchmark path is not canonical: $candidate"
  parent=$(dirname -- "$candidate")
  base=$(basename -- "$candidate")
  case "$candidate" in
    "$repo_root"/*) root=$repo_root ;;
    "$private_tmp_root"/*) root=$private_tmp_root ;;
    *) die 'benchmark path is outside the repository or private benchmark temporary area' ;;
  esac
  if [[ "$parent" == "$root" ]]; then relative=''; else relative=${parent#"$root"/}; fi
  current=$root
  while [[ -n "$relative" ]]; do
    component=${relative%%/*}
    [[ "$component" != "$relative" ]] && relative=${relative#*/} || relative=''
    current="$current/$component"
    if [[ -L "$current" ]]; then die "benchmark path parent is a symlink: $current"; fi
    if [[ -e "$current" ]]; then
      [[ -d "$current" ]] || die "benchmark path parent is not a directory: $current"
    elif [[ "$create_parent" == true ]]; then
      mkdir -- "$current" || die "cannot create benchmark path parent: $current"
      chmod 700 "$current" || die "cannot protect benchmark path parent: $current"
    else
      die "benchmark path parent does not exist: $current"
    fi
  done
  parent_canonical=$(cd -P -- "$parent" && pwd -P) || die "cannot canonicalize benchmark path parent: $parent"
  [[ "$parent" == "$parent_canonical" ]] || die "benchmark path is not canonical: $candidate"
  printf '%s/%s' "$parent_canonical" "$base"
}

requested_run=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
if [[ "$requested_mode" == resume ]]; then
  [[ -n "${BENCHMARK_RUN_DIR:-}" ]] || die 'BENCHMARK_RUN_DIR is required for resume'
  [[ "$BENCHMARK_RUN_DIR" = /* ]] || die 'resume run directory must be absolute and canonical'
  run_dir=$(canonical_child_path "$BENCHMARK_RUN_DIR" false)
  readonly run_dir
  [[ "$run_dir" == "$BENCHMARK_RUN_DIR" ]] || die 'resume run directory must be canonical'
  [[ -d "$run_dir" && ! -L "$run_dir" ]] || die "resume run directory is not owned: $run_dir"
  [[ -f "$run_dir/owner" && ! -L "$run_dir/owner" ]] || die 'resume ownership marker is missing'
  [[ -f "$run_dir/identity" && ! -L "$run_dir/identity" ]] || die 'resume identity is missing'
  run_id=$(sed -n 's/^run_id=//p' "$run_dir/identity")
  cluster=$(sed -n 's/^cluster=//p' "$run_dir/identity")
  kubeconfig=$(sed -n 's/^kubeconfig=//p' "$run_dir/identity")
  [[ -n "$run_id" && -n "$cluster" && -n "$kubeconfig" ]] || die 'resume identity is incomplete'
  [[ "$(dirname -- "$run_dir")" == "$private_tmp_root" && "$(basename -- "$run_dir")" == auth-operator-benchmark.* ]] || die 'resume run directory is outside the private benchmark temporary area'
  [[ "$kubeconfig" == "$run_dir/kubeconfig" ]] || die 'resume kubeconfig is outside the owned run directory'
  [[ "$cluster" == auth-operator-bench-* ]] || die 'resume cluster is not an owned benchmark name'
  expected_cluster_base=$(sanitize "$run_id")
  expected_cluster="auth-operator-bench-${expected_cluster_base:0:40}"
  expected_image="auth-operator:creator-tracking-benchmark-$run_id"
  expected_owner=$(printf 'owner=%s\nrun_id=%s\ncluster=%s\nkubeconfig=%s\noperator_image=%s' "$owner" "$run_id" "$cluster" "$kubeconfig" "$expected_image")
  [[ "$(<"$run_dir/owner")" == "$expected_owner" ]] || die 'resume ownership marker does not match exact identity'
  [[ "$cluster" == "$expected_cluster" ]] || die 'resume cluster does not match the run identity'
  readonly run_id cluster kubeconfig
else
  nonce=$(random_suffix); readonly nonce
  run_id="$(sanitize "$requested_run")-$nonce"; readonly run_id
  run_dir="$(mktemp -d "$private_tmp_root/auth-operator-benchmark.${run_id}.XXXXXX")"; readonly run_dir
  chmod 700 "$run_dir"
  # Install the preflight cleanup immediately. Path validation below can fail
  # before the ownership-aware lifecycle handler is available.
  trap 'rm -rf -- "$run_dir"' EXIT
  cluster_base=$(sanitize "$run_id"); cluster="auth-operator-bench-${cluster_base:0:40}"; readonly cluster
  kubeconfig="$run_dir/kubeconfig"; readonly kubeconfig
  printf 'run_id=%s\ncluster=%s\nkubeconfig=%s\n' "$run_id" "$cluster" "$kubeconfig" >"$run_dir/identity"
  chmod 600 "$run_dir/identity"
  printf 'owner=%s\nrun_id=%s\ncluster=%s\nkubeconfig=%s\noperator_image=%s\n' "$owner" "$run_id" "$cluster" "$kubeconfig" "auth-operator:creator-tracking-benchmark-$run_id" >"$run_dir/owner"
  chmod 600 "$run_dir/owner"
fi

requested_results_dir=${RESULTS_DIR:-$repo_root/benchmarks/data/$run_id}
if [[ "$requested_results_dir" != /* ]]; then
  requested_results_dir="$repo_root/$requested_results_dir"
fi
results_dir=$(canonical_child_path "$requested_results_dir")
readonly results_dir
[[ "$results_dir" == "$requested_results_dir" ]] || die 'RESULTS_DIR must be canonical'
case "$results_dir" in
  "$repo_root"/*|"$private_tmp_root"/*) ;;
  *) die 'RESULTS_DIR is outside the repository or private benchmark temporary area' ;;
esac
readonly operator_image="auth-operator:creator-tracking-benchmark-$run_id"
readonly kyverno_namespace=kyverno
readonly operator_namespace=auth-operator-system
[[ ! -L "$run_dir" ]] || die 'run directory is a symlink'
expected_owner=$(printf 'owner=%s\nrun_id=%s\ncluster=%s\nkubeconfig=%s\noperator_image=%s' "$owner" "$run_id" "$cluster" "$kubeconfig" "$operator_image")
[[ -f "$run_dir/owner" && ! -L "$run_dir/owner" && "$(<"$run_dir/owner")" == "$expected_owner" ]] || die 'run ownership proof is missing or does not match identity'
[[ ! -L "$results_dir" ]] || die 'results directory is a symlink'
if [[ "$requested_mode" == fresh && -d "$results_dir" && -n "$(find "$results_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
  die "refusing to overwrite non-empty results directory $results_dir"
fi
if [[ "$requested_mode" == resume ]]; then
  [[ -d "$results_dir" ]] || die "resume results directory is missing: $results_dir"
else
  mkdir -p "$results_dir" || die "cannot create results directory: $results_dir"
  chmod 700 "$results_dir" || die "cannot protect results directory: $results_dir"
fi
validate_owned_tree "$results_dir"
if [[ "$requested_mode" == resume ]]; then
  validate_owned_tree "$run_dir"
fi

kind_clusters() { bounded kind get clusters; }
assert_owned_cluster() {
  local label context
  label=$(bounded docker container inspect "${cluster}-control-plane" --format '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}') || die "cannot inspect owned Kind control-plane"
  [[ "$label" == "$cluster" ]] || die "Kind control-plane provenance does not match $cluster"
  context=$(KUBECONFIG="$kubeconfig" bounded kubectl config current-context) || die 'cannot inspect resume kubeconfig context'
  [[ "$context" == "kind-$cluster" ]] || die "kubeconfig context does not belong to $cluster"
}
assert_owned_image() {
  local label
  label=$(bounded docker image inspect "$operator_image" --format '{{ index .Config.Labels "t-caas.telekom.com/benchmark-run" }}') || die "cannot inspect owned benchmark image"
  [[ "$label" == "$run_id" ]] || die 'benchmark image provenance does not match the run identity'
}
assert_fresh_targets_absent() {
  local clusters
  clusters=$(kind_clusters) || die 'cannot query Kind clusters; refusing destructive operation'
  grep -Fxq "$cluster" <<<"$clusters" && die "refusing to adopt existing Kind cluster $cluster"
  if bounded docker container inspect "${cluster}-control-plane" >/dev/null 2>&1; then die "refusing to adopt existing control-plane container ${cluster}-control-plane"; fi
  [[ ! -e "$kubeconfig" && ! -L "$kubeconfig" ]] || die "refusing to overwrite kubeconfig $kubeconfig"
  if bounded docker image inspect "$operator_image" >/dev/null 2>&1; then die "refusing to overwrite existing image $operator_image"; fi
}
if [[ "$requested_mode" == fresh ]]; then
  bounded docker info >/dev/null
  assert_fresh_targets_absent
else
  clusters=$(kind_clusters) || die 'cannot query Kind clusters for resume'
  grep -Fxq "$cluster" <<<"$clusters" || die "owned resume cluster is absent: $cluster"
  [[ -f "$kubeconfig" && ! -L "$kubeconfig" ]] || die 'owned resume kubeconfig is missing'
  assert_owned_cluster
  assert_owned_image
fi

cleanup_status=0
cleanup_owned() {
  local original=$1 clusters namespace_cleanup=0
  [[ -f "$run_dir/owner" && ! -L "$run_dir/owner" && "$(<"$run_dir/owner")" == "$expected_owner" ]] || { echo 'cleanup refused: ownership proof is missing or does not match identity' >&2; return 1; }
  # A failed resume keeps its exact owned directory for explicit resume.
  if [[ "$original" -ne 0 && ( "$requested_mode" == resume || "$original" == 130 || "$original" == 143 ) ]]; then echo "benchmark state retained for resume: $run_dir" >&2; return 0; fi
  if [[ -f "$kubeconfig" && ! -L "$kubeconfig" ]]; then
    assert_owned_cluster || { echo 'cleanup refused: cluster provenance does not match the run' >&2; return 1; }
    for namespace in "$operator_namespace" "$kyverno_namespace"; do
      if KUBECONFIG="$kubeconfig" bounded kubectl get namespace "$namespace" >/dev/null 2>&1; then
        KUBECONFIG="$kubeconfig" bounded kubectl delete namespace "$namespace" --ignore-not-found --wait=true || namespace_cleanup=1
        KUBECONFIG="$kubeconfig" bounded kubectl wait --for=delete "namespace/$namespace" --timeout=10m || namespace_cleanup=1
      fi
    done
  fi
  clusters=$(kind_clusters) || { echo 'cleanup refused: cannot query Kind clusters' >&2; return 1; }
  if grep -Fxq "$cluster" <<<"$clusters"; then
    assert_owned_cluster || { echo 'cleanup refused: cluster provenance changed before deletion' >&2; return 1; }
    bounded kind delete cluster --name "$cluster" || return 1
  fi
  clusters=$(kind_clusters) || { echo 'cleanup verification refused: cannot query Kind clusters' >&2; return 1; }
  grep -Fxq "$cluster" <<<"$clusters" && { echo "cleanup failed: cluster remains $cluster" >&2; return 1; }
  if bounded docker image inspect "$operator_image" >/dev/null 2>&1; then
    assert_owned_image || { echo 'cleanup refused: image provenance changed before deletion' >&2; return 1; }
    bounded docker image rm "$operator_image" >/dev/null || return 1
  fi
  if bounded docker image inspect "$operator_image" >/dev/null 2>&1; then echo "cleanup failed: image remains $operator_image" >&2; return 1; fi
  [[ ! -e "$kubeconfig" && ! -L "$kubeconfig" ]] || rm -f -- "$kubeconfig"
  [[ "$namespace_cleanup" -eq 0 ]] || { echo 'cleanup failed: namespace deletion was not confirmed' >&2; return 1; }
  [[ ! -e "$run_dir" && ! -L "$run_dir" ]] || rm -rf -- "$run_dir"
  [[ ! -e "$kubeconfig" && ! -L "$kubeconfig" ]] || return 1
  [[ ! -e "$run_dir" && ! -L "$run_dir" ]] || return 1
}
finish() {
  local status=$?
  trap - EXIT
  # Do not allow a second ordinary signal to interrupt provenance-checked
  # cleanup halfway through and strand only part of the owned lifecycle.
  trap '' INT TERM
  cleanup_owned "$status" || cleanup_status=$?
  [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]] && status=$cleanup_status
  exit "$status"
}
trap finish EXIT
trap 'terminate_bounded 130' INT
trap 'terminate_bounded 143' TERM

if [[ "$requested_mode" == fresh ]]; then
  bounded env DOCKER_BUILDKIT=1 docker build --label "t-caas.telekom.com/benchmark-run=$run_id" --tag "$operator_image" .
  bounded kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --config test/e2e/kind-config-single.yaml --image "$kind_node_image" --wait 5m
  chmod 600 "$kubeconfig"; export KUBECONFIG="$kubeconfig"
  bounded kind load docker-image "$operator_image" --name "$cluster"
  assert_owned_cluster
  assert_owned_image
else export KUBECONFIG="$kubeconfig"; fi

phase() { echo "benchmark phase: $*" >&2; bounded "$@"; }
helm_operator() {
  local enabled=$1 mode=$2 excluded=${3:-false}
  local -a args=(upgrade --install auth-operator chart/auth-operator --namespace "$operator_namespace" --create-namespace --set image.repository=auth-operator --set image.tag="creator-tracking-benchmark-$run_id" --set image.pullPolicy=Never --set creatorTracking.enabled="$enabled" --set creatorTracking.mode="$mode")
  if [[ "$excluded" == true ]]; then
    args+=(--set-json 'creatorTracking.excludedUsernames=["creator-bench-excluded"]')
  fi
  phase helm "${args[@]}" --wait --timeout 10m
  phase kubectl wait --for=condition=Available deployment -l app.kubernetes.io/name=auth-operator --namespace "$operator_namespace" --timeout=10m
}
helm_kyverno() {
  local archive="$run_dir/kyverno-${kyverno_chart_version}.tgz"
  [[ ! -L "$archive" ]] || die 'refusing symlink Kyverno chart archive'
  if [[ ! -f "$archive" ]]; then
    local archive_tmp
    archive_tmp=$(mktemp "${archive}.tmp.XXXXXX")
    phase curl --fail --location --max-time 5m --output "$archive_tmp" "$kyverno_chart_url"
    chmod 600 "$archive_tmp"
    mv -- "$archive_tmp" "$archive"
  fi
  [[ ! -L "$archive" && -f "$archive" ]] || die 'Kyverno chart archive is not a regular file'
  phase shasum -a 256 -c - <<<"$kyverno_chart_sha256  $archive"
  local chart_version chart_app_version
  chart_version=$(phase helm show chart "$archive" | sed -n 's/^version:[[:space:]]*//p')
  chart_app_version=$(phase helm show chart "$archive" | sed -n 's/^appVersion:[[:space:]]*//p')
  [[ "$chart_version" == "$kyverno_chart_version" ]] || die "Kyverno chart version is $chart_version, want $kyverno_chart_version"
  [[ "$chart_app_version" == "$kyverno_app_version" ]] || die "Kyverno chart appVersion is $chart_app_version, want $kyverno_app_version"
  phase helm upgrade --install kyverno "$archive" --namespace "$kyverno_namespace" --create-namespace --set crds.install=true --set crds.groups.policies.mutatingpolicies=true --set features.generateMutatingAdmissionPolicy.enabled=true --wait --timeout 10m
  phase kubectl wait --for=condition=Available deployment -l app.kubernetes.io/part-of=kyverno --namespace "$kyverno_namespace" --timeout=10m
}
probe_admission() {
  local engine=$1 mode=$2
  local probe_namespace
  probe_namespace="creator-bench-probe-$(sanitize "$run_id")"
  probe_namespace=${probe_namespace:0:63}
  local probe_name
  probe_name="creator-bench-probe-$(sanitize "$mode")"
  probe_name=${probe_name:0:63}
  phase kubectl create namespace "$probe_namespace" --dry-run=server -o yaml >"$run_dir/probe-namespace.yaml"
  phase kubectl apply -f "$run_dir/probe-namespace.yaml"
  phase kubectl wait --for=create "namespace/$probe_namespace" --timeout=2m
  phase kubectl create serviceaccount "$probe_name" --namespace "$probe_namespace"
  local creator updated_creator
  creator=$(phase kubectl get serviceaccount "$probe_name" --namespace "$probe_namespace" -o 'jsonpath={.metadata.annotations.t-caas\.telekom\.com/created-by}')
  [[ -n "$creator" ]] || die "${engine} ${mode} semantic probe did not record creator identity"
  phase kubectl annotate serviceaccount "$probe_name" --namespace "$probe_namespace" t-caas.telekom.com/benchmark-probe=updated --overwrite
  updated_creator=$(phase kubectl get serviceaccount "$probe_name" --namespace "$probe_namespace" -o 'jsonpath={.metadata.annotations.t-caas\.telekom\.com/created-by}')
  [[ "$updated_creator" == "$creator" ]] || die "${engine} ${mode} semantic probe did not preserve creator identity on update"
  phase kubectl delete namespace "$probe_namespace" --ignore-not-found --wait=true
  phase kubectl wait --for=delete "namespace/$probe_namespace" --timeout=2m
}
label_policy_mode() {
  local engine=$1 mode=$2 actual policy
  case "$engine" in
    kyverno-map)
      local -a policies=(creator-tracking)
      [[ "$mode" == contributors ]] && policies+=(contributor-tracking)
      for policy in "${policies[@]}"; do
        phase kubectl label --overwrite mutatingpolicy "$policy" "t-caas.telekom.com/benchmark-mode=$mode" --field-manager="benchmark-$mode"
        actual=$(phase kubectl get mutatingpolicy "$policy" -o 'jsonpath={.metadata.labels.t-caas\.telekom\.com/benchmark-mode}')
        [[ "$actual" == "$mode" ]] || die "mutatingpolicy/$policy mode label is $actual, want $mode"
      done
      ;;
    coexist)
      phase kubectl label --overwrite clusterpolicy creator-tracking "t-caas.telekom.com/benchmark-mode=$mode" --field-manager="benchmark-$mode"
      actual=$(phase kubectl get clusterpolicy creator-tracking -o 'jsonpath={.metadata.labels.t-caas\.telekom\.com/benchmark-mode}')
      [[ "$actual" == "$mode" ]] || die "clusterpolicy/creator-tracking mode label is $actual, want $mode"
      ;;
    *) die "cannot label policies for engine $engine" ;;
  esac
}
semantic_activate() {
  local engine=$1
  case "$engine" in
    map)
      phase kubectl wait --for=create mutatingadmissionpolicy/auth-operator-creator-tracking --timeout=10m
      phase kubectl wait --for=create mutatingadmissionpolicybinding/auth-operator-creator-tracking --timeout=10m
      if [[ "$active_mode" == contributors || "$active_mode" == component-contrib ]]; then
        phase kubectl wait --for=create mutatingadmissionpolicy/auth-operator-contributor-tracking --timeout=10m
        phase kubectl wait --for=create mutatingadmissionpolicybinding/auth-operator-contributor-tracking --timeout=10m
      fi
      ;;
    kyverno-map)
      phase kubectl wait --for=create mutatingadmissionpolicy/mpol-creator-tracking --timeout=10m
      phase kubectl wait --for=create mutatingadmissionpolicybinding/mpol-creator-tracking-binding --timeout=10m
      if [[ "$active_mode" == contributors ]]; then
        phase kubectl wait --for=create mutatingadmissionpolicy/mpol-contributor-tracking --timeout=10m
        phase kubectl wait --for=create mutatingadmissionpolicybinding/mpol-contributor-tracking-binding --timeout=10m
      fi
      ;;
    kyverno-webhook) phase kubectl wait --for=create clusterpolicy/creator-tracking --timeout=10m ;;
    coexist)
      phase kubectl wait --for=create mutatingadmissionpolicy/auth-operator-creator-tracking --timeout=10m
      phase kubectl wait --for=create mutatingadmissionpolicybinding/auth-operator-creator-tracking --timeout=10m
      if [[ "$active_mode" == contributors ]]; then
        phase kubectl wait --for=create mutatingadmissionpolicy/auth-operator-contributor-tracking --timeout=10m
        phase kubectl wait --for=create mutatingadmissionpolicybinding/auth-operator-contributor-tracking --timeout=10m
      fi
      phase kubectl wait --for=create clusterpolicy/creator-tracking --timeout=10m
      ;;
    baseline) phase kubectl apply -f hack/benchmark/manifests/baseline.yaml; phase kubectl get configmap creator-tracking-benchmark-baseline -o name ;;
  esac
  phase kubectl get --raw=/readyz
  [[ "$engine" == baseline ]] || probe_admission "$engine" "$active_mode"
}
capture_input_material() {
  local material="$run_dir/input-material-${active_scope}-${engine}-${active_mode}-${active_variant}.yaml"
  local -a native_policies=(auth-operator-creator-tracking)
  local -a native_bindings=(auth-operator-creator-tracking)
  if [[ "$active_mode" == contributors || "$active_mode" == component-contrib ]]; then
    native_policies+=(auth-operator-contributor-tracking)
    native_bindings+=(auth-operator-contributor-tracking)
  fi
  if [[ "$requested_mode" == resume ]]; then
    [[ -f "$material" && ! -L "$material" ]] || die "resume input material is missing: $material"
    BENCHMARK_INPUT_MATERIAL="$material"
    BENCH_POLICY_PATH="$material"
    export BENCHMARK_INPUT_MATERIAL BENCH_POLICY_PATH
    return
  fi
  local material_tmp
  material_tmp=$(mktemp "${material}.tmp.XXXXXX")
  {
    printf 'scope: %s\nengine: %s\nmode: %s\n' "$active_scope" "$engine" "$active_mode"
    case "$engine" in
      baseline) cat hack/benchmark/manifests/baseline.yaml ;;
      map|coexist)
        KUBECONFIG="$kubeconfig" bounded kubectl get mutatingadmissionpolicy "${native_policies[@]}" -o yaml
        KUBECONFIG="$kubeconfig" bounded kubectl get mutatingadmissionpolicybinding "${native_bindings[@]}" -o yaml
        ;;
    esac
    case "$engine" in
      kyverno-webhook|coexist) KUBECONFIG="$kubeconfig" bounded kubectl get clusterpolicy creator-tracking -o yaml --ignore-not-found ;;
      kyverno-map) KUBECONFIG="$kubeconfig" bounded kubectl get mutatingpolicy creator-tracking contributor-tracking -o yaml --ignore-not-found ;;
    esac
    case "$engine" in
      kyverno-map)
        KUBECONFIG="$kubeconfig" bounded kubectl get mutatingadmissionpolicy mpol-creator-tracking mpol-contributor-tracking -o yaml --ignore-not-found
        KUBECONFIG="$kubeconfig" bounded kubectl get mutatingadmissionpolicybinding mpol-creator-tracking-binding mpol-contributor-tracking-binding -o yaml --ignore-not-found
        ;;
    esac
  } >"$material_tmp"
  chmod 600 "$material_tmp"
  mv -- "$material_tmp" "$material"
  BENCHMARK_INPUT_MATERIAL="$material"
  BENCH_POLICY_PATH="$material"
  export BENCHMARK_INPUT_MATERIAL BENCH_POLICY_PATH
}
uninstall_engines() {
  phase helm uninstall auth-operator --namespace "$operator_namespace" --ignore-not-found
  phase helm uninstall kyverno --namespace "$kyverno_namespace" --ignore-not-found
  local release available_resources
  release=$(phase helm list -A --filter '^(auth-operator|kyverno)$' --short)
  [[ -z "$release" ]] || die "Helm release teardown was not confirmed: $release"
  available_resources=$(phase kubectl api-resources -o name)
  delete_policy() {
    local resource=$1 name=$2 existing
    grep -Fxq "$resource" <<<"$available_resources" || return 0
    existing=$(phase kubectl get "$resource" "$name" --ignore-not-found -o name)
    [[ -z "$existing" ]] && return 0
    phase kubectl delete "$resource" "$name" --wait=true
    phase kubectl wait --for=delete "$resource/$name" --timeout=2m
    if phase kubectl get "$resource" "$name" --ignore-not-found -o name | grep -Fq .; then
      die "policy teardown was not confirmed: $resource/$name"
    fi
  }
  delete_policy clusterpolicies.kyverno.io creator-tracking
  delete_policy clusterpolicies.kyverno.io creator-tracking-benign-label
  delete_policy mutatingpolicies.policies.kyverno.io creator-tracking
  delete_policy mutatingpolicies.policies.kyverno.io contributor-tracking
  delete_policy mutatingadmissionpolicies.admissionregistration.k8s.io auth-operator-creator-tracking
  delete_policy mutatingadmissionpolicies.admissionregistration.k8s.io auth-operator-contributor-tracking
  delete_policy mutatingadmissionpolicies.admissionregistration.k8s.io mpol-creator-tracking
  delete_policy mutatingadmissionpolicies.admissionregistration.k8s.io mpol-contributor-tracking
  delete_policy mutatingadmissionpolicybindings.admissionregistration.k8s.io auth-operator-creator-tracking
  delete_policy mutatingadmissionpolicybindings.admissionregistration.k8s.io auth-operator-contributor-tracking
  delete_policy mutatingadmissionpolicybindings.admissionregistration.k8s.io mpol-creator-tracking-binding
  delete_policy mutatingadmissionpolicybindings.admissionregistration.k8s.io mpol-contributor-tracking-binding
}
apply_engine() {
  local engine=$1 mode=$2 excluded=${3:-false} policy_mode=$2
  case "$mode" in
    component-stamp) policy_mode=create-only ;;
    component-restore) policy_mode=protect ;;
    component-contrib) policy_mode=contributors ;;
  esac
  active_mode=$mode
  active_variant=enabled
  if [[ "$excluded" == true ]]; then
    active_variant='excluded-usernames'
  fi
  uninstall_engines
  case "$engine" in
    baseline) helm_operator false "$policy_mode" "$excluded" ;;
    map) helm_operator true "$policy_mode" "$excluded" ;;
    kyverno-webhook) helm_operator false "$policy_mode" "$excluded"; helm_kyverno; phase kubectl apply -f docs/examples/creator-tracking-kyverno-clusterpolicy.yaml ;;
    kyverno-map)
      helm_operator false "$policy_mode" "$excluded"; helm_kyverno
      local kyverno_policy="$run_dir/kyverno-mutatingpolicy.yaml"
      if [[ "$mode" == contributors ]]; then
        phase kubectl apply -f docs/examples/creator-tracking-kyverno-mutatingpolicy.yaml
      else
        phase awk 'BEGIN { doc=0 } /^---[[:space:]]*$/ { doc++; if (doc > 1) exit } { print }' docs/examples/creator-tracking-kyverno-mutatingpolicy.yaml >"$kyverno_policy"
        if [[ "$mode" == create-only ]]; then
          phase sed -i.benchmark 's/operations: \["CREATE", "UPDATE"\]/operations: ["CREATE"]/g' "$kyverno_policy"
        fi
        phase kubectl apply -f "$kyverno_policy"
      fi
      label_policy_mode "$engine" "$mode"
      ;;
    coexist) helm_operator true "$policy_mode" "$excluded"; helm_kyverno; phase kubectl apply -f docs/examples/creator-tracking-kyverno-clusterpolicy.yaml; label_policy_mode "$engine" "$mode" ;;
    *) die "unknown engine $engine" ;;
  esac
  semantic_activate "$engine"
}
run_cell() {
  local engine=$1 tier=$2 mode=$3 ops=${4:-} excluded=${5:-false}
  local -a args=(-out "$results_dir" -run-id "$run_id" -resume -identities 10 -engine "$engine" -tier "$tier" -mode "$mode")
  if [[ "$quick" == true ]]; then
    args+=(-quick -ops 500)
  elif [[ -n "$ops" ]]; then
    args+=(-ops "$ops")
  fi
  [[ "$excluded" == true ]] && args+=(-excluded-usernames-bench)
  phase go run ./hack/benchmark "${args[@]}"
}

active_scope=core
if [[ "$quick" == true ]]; then engines=(baseline map); tiers=(t1 t2); modes=(protect); else engines=(baseline map kyverno-webhook kyverno-map coexist); tiers=(t1 t2 t3 t4); modes=(create-only protect contributors); fi
for engine in "${engines[@]}"; do
  for mode in "${modes[@]}"; do
    apply_engine "$engine" "$mode"
    capture_input_material
    for tier in "${tiers[@]}"; do run_cell "$engine" "$tier" "$mode"; done
  done
done
if [[ "$quick" != true ]]; then
  active_scope=isolation
  isolation_tiers=(iso-namespaces iso-serviceaccounts iso-secrets iso-rbac-group iso-crd-group)
  for engine in map kyverno-webhook kyverno-map coexist; do
    apply_engine "$engine" protect
    capture_input_material
    isolation_ops=''
    [[ "$engine" != map ]] && isolation_ops=1000
    for tier in "${isolation_tiers[@]}"; do run_cell "$engine" "$tier" protect "$isolation_ops"; done
  done
  active_scope=component
  for mode in component-stamp component-restore component-contrib; do
    apply_engine map "$mode"
    capture_input_material
    run_cell map t1 "$mode"
  done
  active_scope=exclusion
  apply_engine map protect true
  capture_input_material
  run_cell map t1 protect '' true
fi
phase go run ./hack/benchmark -out "$results_dir" -run-id "$run_id" -resume -report
echo "benchmark completed: run_id=$run_id results=$results_dir" >&2

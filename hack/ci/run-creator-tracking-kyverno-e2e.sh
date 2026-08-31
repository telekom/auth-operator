#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
umask 077

readonly cluster=auth-operator-e2e-kyverno
readonly lock=/tmp/auth-operator-e2e-kyverno.lock
readonly kubeconfig=/tmp/auth-operator-e2e-kyverno.kubeconfig
readonly marker=/tmp/auth-operator-e2e-kyverno.owner
readonly run_dir=/tmp/auth-operator-e2e-kyverno-run
# Failure diagnostics are sanitized readiness/version summaries and remain
# local-only; this runner intentionally does not upload cluster metadata.
readonly artifact_dir=/tmp/creator-tracking-kyverno-debug
readonly source_image='auth-operator:creator-tracking-kyverno-source'
readonly e2e_image='auth-operator:creator-tracking-kyverno-e2e'
readonly owner='auth-operator-creator-tracking-kyverno/v1'

mode=${1:-full}
case "$mode" in full|cleanup-only|debug) ;; *) echo "usage: $0 [full|cleanup-only|debug]" >&2; exit 2 ;; esac
[[ -z "${KYVERNO_E2E_CLUSTER+x}${KYVERNO_E2E_LOCK+x}${KYVERNO_E2E_KUBECONFIG+x}" ]] || {
  echo 'KYVERNO_E2E_CLUSTER, KYVERNO_E2E_LOCK, and KYVERNO_E2E_KUBECONFIG are not supported' >&2
  exit 2
}
command -v flock >/dev/null
command -v timeout >/dev/null
[[ ! -L "$lock" ]] || { echo "refusing symlink lock $lock" >&2; exit 1; }
exec 9>"$lock"
chmod 600 "$lock"
flock -n 9 || { echo "Kyverno E2E already running" >&2; exit 1; }

die() { echo "creator-tracking Kyverno E2E: $*" >&2; exit 1; }
is_known_absent() { case "$1" in *'No such image'*|*'No such container'*|*'not found'*|*'does not exist'*) return 0;; *) return 1;; esac; }
bounded() { timeout --signal=TERM --kill-after=30s 30m "$@"; }
assert_image_absent() {
  local image=$1 output rc
  set +e; output=$(docker image inspect "$image" 2>&1); rc=$?; set -e
  if ((rc == 0)); then die "refusing to overwrite existing image $image"; fi
  is_known_absent "$output" || die "cannot establish that image $image is absent: $output"
}
assert_container_absent() {
  local name=$1 output rc
  set +e; output=$(docker container inspect "$name" 2>&1); rc=$?; set -e
  if ((rc == 0)); then die "refusing to reuse existing container $name"; fi
  is_known_absent "$output" || die "cannot establish that container $name is absent: $output"
}
assert_kind_absent() {
  local output rc
  set +e; output=$(kind get clusters 2>&1); rc=$?; set -e
  ((rc == 0)) || die "cannot query Kind clusters: $output"
  if grep -Fxq "$cluster" <<<"$output"; then
    die "refusing to adopt existing Kind cluster $cluster"
  fi
}
assert_regular_absent() {
  local path=$1
  [[ ! -L "$path" ]] || die "refusing symlink artifact $path"
  [[ ! -e "$path" ]] || die "refusing to overwrite existing artifact $path"
}
marker_owned() { [[ -f "$marker" && ! -L "$marker" ]] || return 1; [[ "$(<"$marker")" == "$owner" ]]; }
artifact_owned() {
  [[ -d "$artifact_dir" && ! -L "$artifact_dir" ]] || return 1
  [[ -f "$artifact_dir/.owner" && ! -L "$artifact_dir/.owner" ]] || return 1
  [[ "$(<"$artifact_dir/.owner")" == "$owner" ]]
}
owned_remove_file() { [[ ! -L "$1" ]] || return 1; [[ ! -e "$1" ]] || rm -f -- "$1"; }
owned_remove_dir() { [[ ! -L "$1" ]] || return 1; [[ ! -e "$1" ]] || rm -rf -- "$1"; }

cleanup_owned() {
  local original_status=${1:-0} failures=() clusters output rc image
  if ! marker_owned; then
    echo 'cleanup failures: ownership marker missing' >&2
    return 1
  fi
  set +e; output=$(kind get clusters 2>&1); rc=$?; set -e
  if ((rc != 0)); then failures+=("query Kind clusters: $output"); clusters=''; else clusters=$output; fi
  if ((rc == 0)) && grep -Fxq "$cluster" <<<"$clusters"; then bounded kind delete cluster --name "$cluster" || failures+=("delete Kind cluster"); fi
  [[ ! -e "$kubeconfig" && ! -L "$kubeconfig" ]] || owned_remove_file "$kubeconfig" || failures+=("remove kubeconfig")
  [[ ! -e "$run_dir" && ! -L "$run_dir" ]] || owned_remove_dir "$run_dir" || failures+=("remove run directory")
  for image in "$e2e_image" "$source_image"; do
    set +e; output=$(docker image inspect "$image" 2>&1); rc=$?; set -e
    if ((rc == 0)); then bounded docker image rm "$image" >/dev/null || failures+=("remove image $image"); elif ! is_known_absent "$output"; then failures+=("query image $image: $output"); fi
  done
  if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
    if ! artifact_owned; then
      failures+=("debug artifact ownership is invalid")
    elif [[ "$original_status" -eq 0 ]]; then
      owned_remove_dir "$artifact_dir" || failures+=("remove debug artifacts")
    else
      echo "owned debug artifacts retained at $artifact_dir; run cleanup-only before retrying" >&2
    fi
  fi
  if [[ "$original_status" -eq 0 || ! -e "$artifact_dir" ]]; then
    owned_remove_file "$marker" || failures+=("remove ownership marker")
  else
    echo "ownership marker retained for cleanup-only" >&2
  fi
  set +e; output=$(kind get clusters 2>&1); rc=$?; set -e
  if ((rc != 0)); then failures+=("verify Kind cleanup: $output"); elif grep -Fxq "$cluster" <<<"$output"; then failures+=("Kind cluster remains"); fi
  for image in "$e2e_image" "$source_image"; do
    set +e; output=$(docker image inspect "$image" 2>&1); rc=$?; set -e
    if ((rc == 0)); then failures+=("image remains: $image"); elif ! is_known_absent "$output"; then failures+=("verify image cleanup $image: $output"); fi
  done
  [[ ! -e "$kubeconfig" && ! -L "$kubeconfig" ]] || failures+=("kubeconfig remains")
  [[ ! -e "$run_dir" && ! -L "$run_dir" ]] || failures+=("run directory remains")
  if ((${#failures[@]})); then printf 'cleanup failures: %s\n' "${failures[*]}" >&2; return 1; fi
}

prepare_debug_dir() {
  if [[ -e "$artifact_dir" || -L "$artifact_dir" ]]; then
    artifact_owned || { echo "refusing unsafe debug artifact path $artifact_dir" >&2; return 1; }
    return 0
  fi
  mkdir -- "$artifact_dir" || { echo "cannot create debug artifact directory $artifact_dir" >&2; return 1; }
  chmod 700 "$artifact_dir"
  printf '%s\n' "$owner" >"$artifact_dir/.owner"
  chmod 600 "$artifact_dir/.owner"
}

write_safe_debug() {
  prepare_debug_dir || return 1
  {
    echo "cluster=$cluster"
    echo "kind_image=$kind_image"
    echo "source_image=$source_image"
    echo "e2e_image=$e2e_image"
    kind version 2>&1 | sed -E 's/(token|password|secret|authorization)[^[:space:]]*/[redacted]/Ig' || true
    helm version --short 2>&1 || true
    kubectl version --client 2>&1 || true
  } >"$artifact_dir/versions.txt"
  {
    kubectl get --raw=/readyz 2>&1 || true
    kubectl get nodes -o 'custom-columns=NAME:.metadata.name,READY:.status.conditions[-1].status' 2>&1 || true
    kubectl get deployments -A -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas' 2>&1 || true
    kubectl get pods -A -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,PHASE:.status.phase,READY:.status.conditions[-1].status' 2>&1 || true
  } >"$artifact_dir/readiness.txt"
}

if [[ "$mode" == cleanup-only ]]; then marker_owned || die "cleanup-only requires the exact ownership marker"; cleanup_owned 0; exit $?; fi
if [[ "$mode" == debug ]]; then
  marker_owned || die "debug requires the exact ownership marker"
  [[ -f "$kubeconfig" && ! -L "$kubeconfig" ]] || die "owned kubeconfig is missing"
  KUBECONFIG="$kubeconfig" write_safe_debug
  exit $?
fi

assert_kind_absent
assert_container_absent "${cluster}-control-plane"
assert_regular_absent "$marker"
assert_regular_absent "$kubeconfig"
assert_regular_absent "$run_dir"
assert_regular_absent "$artifact_dir"
docker info >/dev/null
assert_image_absent "$source_image"
assert_image_absent "$e2e_image"
[[ -f versions.env && ! -L versions.env ]] || die 'versions.env must be a regular repository file'
set -a
# The runner validates and loads the repository pin file.
# shellcheck disable=SC1091
source versions.env
set +a
: "${E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE:?versions.env must define E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE}"
readonly kind_image=$E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE
printf '%s\n' "$owner" > "$marker"
chmod 600 "$marker"
status=0
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 && -f "$kubeconfig" && ! -L "$kubeconfig" ]]; then
    KUBECONFIG="$kubeconfig" write_safe_debug || true
  fi
  cleanup_status=0
  cleanup_owned "$status" || cleanup_status=$?
  if [[ "$status" -eq 0 && "$cleanup_status" -ne 0 ]]; then status=$cleanup_status; fi
  exit "$status"
}
trap cleanup EXIT INT TERM
mkdir "$run_dir"
bounded env DOCKER_BUILDKIT=1 docker build --tag "$source_image" .
bounded kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --config test/e2e/kind-config-single.yaml --image "$kind_image" --wait 5m
[[ -f "$kubeconfig" && ! -L "$kubeconfig" ]] || die "Kind did not create a regular kubeconfig"
chmod 600 "$kubeconfig"
export KUBECONFIG="$kubeconfig"
bounded docker tag "$source_image" "$e2e_image"
bounded kind load docker-image "$e2e_image" --name "$cluster"
bounded helm upgrade --install auth-operator chart/auth-operator --namespace auth-operator-system --create-namespace --set image.repository=auth-operator --set image.tag=creator-tracking-kyverno-e2e --set image.pullPolicy=Never --set creatorTracking.enabled=true --wait --timeout 5m
KUBECONFIG="$kubeconfig" KIND_CLUSTER="$cluster" IMG="$e2e_image" KYVERNO_E2E_ARCHIVE_DIR="$run_dir" bounded hack/ci/install-kyverno.sh
KUBECONFIG="$kubeconfig" KIND_CLUSTER="$cluster" IMG="$e2e_image" \
  E2E_EXACT_CLEANUP_ONLY=true SKIP_CLUSTER_SETUP=true \
  bounded go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.fail-on-pending=true -ginkgo.label-filter=creator-tracking-kyverno -timeout 30m

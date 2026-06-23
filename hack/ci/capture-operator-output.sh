#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# capture-operator-output.sh — Capture auth-operator generated RBAC resources
# and CRD statuses, stripping internal K8s fields for clean diffs.
#
# Usage:
#   capture-operator-output.sh <output-dir> [--metrics-namespace <ns>] [--metrics-scheme <http|https>] [--metrics-token-file <path>] [--all-rbac]
#
# The script captures:
#   - ClusterRoles, Roles, ClusterRoleBindings, RoleBindings, ServiceAccounts.
#     By default only objects labelled app.kubernetes.io/managed-by=auth-operator
#     are captured. Pass --all-rbac in security-sensitive CI checks so unlabeled
#     candidate output cannot hide from the diff.
#   - Auth Operator CRD status (for debugging and output-delta checks)
#   - Prometheus metrics (optional, from metrics-service port-forward)
#
# All output is filtered through yq to remove volatile K8s-internal fields
# (creationTimestamp, resourceVersion, uid, generation, managedFields, list metadata).

set -euo pipefail

OUTPUT_DIR="${1:?Usage: $0 <output-dir> [--metrics-namespace <ns>] [--metrics-scheme <http|https>] [--metrics-token-file <path>]}"
shift

METRICS_NS="auth-operator-system"
METRICS_SCHEME="${METRICS_SCHEME:-http}"
METRICS_LOCAL_PORT="${METRICS_LOCAL_PORT:-18080}"
METRICS_TOKEN_FILE=""
CAPTURE_ALL_RBAC=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-namespace) METRICS_NS="$2"; shift 2 ;;
    --metrics-scheme) METRICS_SCHEME="$2"; shift 2 ;;
    --metrics-token-file) METRICS_TOKEN_FILE="$2"; shift 2 ;;
    --all-rbac) CAPTURE_ALL_RBAC=true; shift ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

case "$METRICS_SCHEME" in
  http|https) ;;
  *) echo "Invalid metrics scheme: $METRICS_SCHEME" >&2; exit 1 ;;
esac

mkdir -p "$OUTPUT_DIR"

# yq expression to strip volatile K8s internal fields from list output.
# These fields change between runs and produce noisy, meaningless diffs.
YQ_STRIP_RBAC='del(
  .metadata,
  .items[].metadata.creationTimestamp,
  .items[].metadata.resourceVersion,
  .items[].metadata.uid,
  .items[].metadata.generation,
  .items[].metadata.managedFields,
  .items[].metadata.ownerReferences[].uid
)'

# Additional fields stripped from CRD status captures (observedGeneration and
# lastTransitionTime are also volatile).
YQ_STRIP_CRD='del(
  .metadata,
  .items[].metadata.creationTimestamp,
  .items[].metadata.resourceVersion,
  .items[].metadata.uid,
  .items[].metadata.generation,
  .items[].metadata.managedFields,
  .items[].metadata.ownerReferences[].uid,
  .items[].status.observedGeneration,
  .items[].status.conditions[].lastTransitionTime,
  .items[].status.conditions[].observedGeneration
) | (.items[].status.conditions |= sort_by(.type))'

# --- RBAC resources ---
LABEL="app.kubernetes.io/managed-by=auth-operator"

capture_rbac() {
  local kind="$1" flags="$2" outfile="$3"
  local selector_args=()
  if [ "$CAPTURE_ALL_RBAC" != "true" ]; then
    selector_args=(-l "$LABEL")
  fi

  # shellcheck disable=SC2086
  if kubectl get "$kind" $flags "${selector_args[@]}" -o yaml 2>/dev/null | yq "$YQ_STRIP_RBAC" > "$OUTPUT_DIR/$outfile"; then
    echo "  Captured $outfile"
  else
    echo "# No $kind found" > "$OUTPUT_DIR/$outfile"
    echo "  No $kind found (empty placeholder written)"
  fi
}

echo "Capturing RBAC resources to $OUTPUT_DIR ..."
capture_rbac clusterroles        ""   clusterroles.yaml
capture_rbac roles               "-A" roles.yaml
capture_rbac clusterrolebindings ""   clusterrolebindings.yaml
capture_rbac rolebindings        "-A" rolebindings.yaml
capture_rbac serviceaccounts     "-A" serviceaccounts.yaml

# --- CRD status (for debugging) ---
echo "Capturing CRD statuses ..."
for crd in roledefinitions binddefinitions rbacpolicies restrictedbinddefinitions restrictedroledefinitions webhookauthorizers; do
  if kubectl get "$crd" -o yaml 2>/dev/null | yq "$YQ_STRIP_CRD" > "$OUTPUT_DIR/${crd}-status.yaml"; then
    echo "  Captured ${crd}-status.yaml"
  else
    echo "  No $crd found (skipped)"
    rm -f "$OUTPUT_DIR/${crd}-status.yaml"
  fi
done

# --- Prometheus metrics (optional) ---
echo "Capturing Prometheus metrics ..."
# Discover the metrics service by label; fall back to the kustomize-generated name.
SVC="${METRICS_SVC:-$(kubectl get svc -n "$METRICS_NS" -l control-plane=controller-manager --no-headers -o name 2>/dev/null | head -1)}"
SVC="${SVC:-svc/auth-operator-controller-manager-metrics-service}"
if kubectl get "$SVC" -n "$METRICS_NS" &>/dev/null; then
  PF_PID=""
  metrics_header_file=""
  metrics_response_file=""
  cleanup_metrics_capture() {
    if [ -n "$PF_PID" ]; then
      kill "$PF_PID" 2>/dev/null || true
      wait "$PF_PID" 2>/dev/null || true
    fi
    if [ -n "$metrics_header_file" ]; then
      rm -f "$metrics_header_file"
    fi
    if [ -n "$metrics_response_file" ]; then
      rm -f "$metrics_response_file"
    fi
  }
  trap cleanup_metrics_capture EXIT

  kubectl port-forward --address 127.0.0.1 -n "$METRICS_NS" "$SVC" "${METRICS_LOCAL_PORT}:8080" &>/dev/null &
  PF_PID=$!
  curl_args=(-sS --max-time 10)
  if [ "$METRICS_SCHEME" = "https" ]; then
    # controller-runtime generates a self-signed serving certificate for secure
    # metrics. Output-delta verifies generated metrics content, not TLS trust.
    curl_args+=(-k)
  fi
  if [ -n "$METRICS_TOKEN_FILE" ]; then
    if [ ! -f "$METRICS_TOKEN_FILE" ]; then
      echo "Metrics token file not found: $METRICS_TOKEN_FILE" >&2
      exit 1
    fi
    metrics_token="$(tr -d '\r\n' < "$METRICS_TOKEN_FILE")"
    metrics_header_file="$(mktemp)"
    chmod 600 "$metrics_header_file"
    printf 'Authorization: Bearer %s\n' "$metrics_token" > "$metrics_header_file"
    curl_args+=(-H "@${metrics_header_file}")
  fi

  metrics_response_file="$(mktemp)"
  scrape_ok=false
  for _ in $(seq 1 30); do
    if ! kill -0 "$PF_PID" 2>/dev/null; then
      echo "Metrics port-forward process exited before scrape completed" >&2
      exit 1
    fi
    if curl "${curl_args[@]}" "${METRICS_SCHEME}://127.0.0.1:${METRICS_LOCAL_PORT}/metrics" > "$metrics_response_file" 2>/dev/null; then
      if grep '^auth_operator_' "$metrics_response_file" | sort > "$OUTPUT_DIR/metrics.txt" && [ -s "$OUTPUT_DIR/metrics.txt" ]; then
        scrape_ok=true
        break
      fi
    fi
    sleep 1
  done
  if [ "$scrape_ok" != "true" ]; then
    echo "Metrics service exists but no auth_operator_* metrics could be scraped" >&2
    echo "Last metrics response:" >&2
    cat "$metrics_response_file" >&2 || true
    exit 1
  fi
  echo "  Captured metrics.txt"
else
  echo "# No metrics service found" > "$OUTPUT_DIR/metrics.txt"
  echo "  Metrics service not found in $METRICS_NS (empty placeholder written)"
fi

echo "Done — output in $OUTPUT_DIR"

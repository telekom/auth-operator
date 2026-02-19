#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# capture-operator-output.sh — Capture auth-operator generated RBAC resources
# and CRD statuses, stripping internal K8s fields for clean diffs.
#
# Usage:
#   capture-operator-output.sh <output-dir> [--metrics-namespace <ns>]
#
# The script captures:
#   - ClusterRoles, Roles, ClusterRoleBindings, RoleBindings, ServiceAccounts
#     (labelled app.kubernetes.io/created-by=auth-operator)
#   - RoleDefinition/BindDefinition status (for debugging)
#   - Prometheus metrics (optional, from metrics-service port-forward)
#
# All output is filtered through yq to remove volatile K8s-internal fields
# (creationTimestamp, resourceVersion, uid, generation, managedFields, list metadata).

set -euo pipefail

OUTPUT_DIR="${1:?Usage: $0 <output-dir> [--metrics-namespace <ns>]}"
shift

METRICS_NS="auth-operator-system"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --metrics-namespace) METRICS_NS="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

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
  .items[].status.conditions[].lastTransitionTime
) | (.items[].status.conditions |= sort_by(.type))'

# --- RBAC resources ---
LABEL="app.kubernetes.io/created-by=auth-operator"

capture_rbac() {
  local kind="$1" flags="$2" outfile="$3"
  # shellcheck disable=SC2086
  if kubectl get "$kind" $flags -l "$LABEL" -o yaml 2>/dev/null | yq "$YQ_STRIP_RBAC" > "$OUTPUT_DIR/$outfile"; then
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
for crd in roledefinitions binddefinitions; do
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
  kubectl port-forward -n "$METRICS_NS" "$SVC" 8080:8080 &>/dev/null &
  PF_PID=$!
  sleep 2
  curl -s http://localhost:8080/metrics 2>/dev/null \
    | grep '^auth_operator_' \
    | sort > "$OUTPUT_DIR/metrics.txt" || echo "# No metrics available" > "$OUTPUT_DIR/metrics.txt"
  kill "$PF_PID" 2>/dev/null || true
  echo "  Captured metrics.txt"
else
  echo "# No metrics service found" > "$OUTPUT_DIR/metrics.txt"
  echo "  Metrics service not found in $METRICS_NS (empty placeholder written)"
fi

echo "Done — output in $OUTPUT_DIR"

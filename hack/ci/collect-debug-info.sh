#!/bin/bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
#
# Collect debug information for CI failures
# Usage: ./collect-debug-info.sh <output-dir> [namespace]

set -e

OUTPUT_DIR="${1:-/tmp/e2e-debug}"
NAMESPACE="${2:-auth-operator-system}"

mkdir -p "$OUTPUT_DIR"

echo "=== Collecting debug information to $OUTPUT_DIR ==="

# Collect cluster info
echo "Collecting cluster info..."
kubectl cluster-info dump --output-directory="$OUTPUT_DIR/cluster-dump" 2>/dev/null || true

# Collect all namespaces
echo "Collecting namespace list..."
kubectl get namespaces -o wide > "$OUTPUT_DIR/namespaces.txt" 2>&1 || true

# Collect all pods across all namespaces
echo "Collecting pod status..."
kubectl get pods -A -o wide > "$OUTPUT_DIR/all-pods.txt" 2>&1 || true

# Collect events across all namespaces
echo "Collecting events..."
kubectl get events -A --sort-by='.lastTimestamp' > "$OUTPUT_DIR/all-events.txt" 2>&1 || true

# Collect operator namespace resources
if kubectl get namespace "$NAMESPACE" >/dev/null 2>&1; then
    echo "Collecting resources in namespace $NAMESPACE..."
    mkdir -p "$OUTPUT_DIR/$NAMESPACE"
    
    # Pod descriptions
    kubectl describe pods -n "$NAMESPACE" > "$OUTPUT_DIR/$NAMESPACE/pod-descriptions.txt" 2>&1 || true
    
    # Pod logs for controller-manager
    for pod in $(kubectl get pods -n "$NAMESPACE" -l control-plane=controller-manager -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        echo "Collecting logs for controller-manager pod: $pod"
        kubectl logs -n "$NAMESPACE" "$pod" --all-containers > "$OUTPUT_DIR/$NAMESPACE/logs-$pod.txt" 2>&1 || true
        kubectl logs -n "$NAMESPACE" "$pod" --all-containers --previous > "$OUTPUT_DIR/$NAMESPACE/logs-$pod-previous.txt" 2>&1 || true
    done
    
    # Pod logs for webhook-server
    for pod in $(kubectl get pods -n "$NAMESPACE" -l control-plane=webhook-server -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
        echo "Collecting logs for webhook-server pod: $pod"
        kubectl logs -n "$NAMESPACE" "$pod" --all-containers > "$OUTPUT_DIR/$NAMESPACE/logs-$pod.txt" 2>&1 || true
        kubectl logs -n "$NAMESPACE" "$pod" --all-containers --previous > "$OUTPUT_DIR/$NAMESPACE/logs-$pod-previous.txt" 2>&1 || true
    done
    
    # Services and endpoints
    kubectl get svc,endpoints -n "$NAMESPACE" -o wide > "$OUTPUT_DIR/$NAMESPACE/services.txt" 2>&1 || true
    
    # Deployments
    kubectl get deployments -n "$NAMESPACE" -o wide > "$OUTPUT_DIR/$NAMESPACE/deployments.txt" 2>&1 || true
    kubectl describe deployments -n "$NAMESPACE" > "$OUTPUT_DIR/$NAMESPACE/deployment-descriptions.txt" 2>&1 || true
    
    # Events in operator namespace
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' > "$OUTPUT_DIR/$NAMESPACE/events.txt" 2>&1 || true
    
    # Secrets (only names, not content)
    kubectl get secrets -n "$NAMESPACE" > "$OUTPUT_DIR/$NAMESPACE/secrets.txt" 2>&1 || true
fi

# Collect webhook configurations
echo "Collecting webhook configurations..."
kubectl get mutatingwebhookconfigurations -o yaml > "$OUTPUT_DIR/mutatingwebhooks.yaml" 2>&1 || true
kubectl get validatingwebhookconfigurations -o yaml > "$OUTPUT_DIR/validatingwebhooks.yaml" 2>&1 || true

# Collect CRDs
echo "Collecting CRDs..."
kubectl get crds -o wide | grep -E 't-caas|auth' > "$OUTPUT_DIR/crds.txt" 2>&1 || true

# Collect custom resources
echo "Collecting custom resources..."
kubectl get roledefinitions -A -o yaml > "$OUTPUT_DIR/roledefinitions.yaml" 2>&1 || true
kubectl get binddefinitions -A -o yaml > "$OUTPUT_DIR/binddefinitions.yaml" 2>&1 || true
kubectl get webhookauthorizers -A -o yaml > "$OUTPUT_DIR/webhookauthorizers.yaml" 2>&1 || true

# Collect ClusterRoles and ClusterRoleBindings created by auth-operator
echo "Collecting RBAC resources..."
kubectl get clusterroles -l app.kubernetes.io/created-by=auth-operator -o yaml > "$OUTPUT_DIR/created-clusterroles.yaml" 2>&1 || true
kubectl get clusterrolebindings -l app.kubernetes.io/created-by=auth-operator -o yaml > "$OUTPUT_DIR/created-clusterrolebindings.yaml" 2>&1 || true

# Collect node info
echo "Collecting node info..."
kubectl get nodes -o wide > "$OUTPUT_DIR/nodes.txt" 2>&1 || true
kubectl describe nodes > "$OUTPUT_DIR/node-descriptions.txt" 2>&1 || true

# Summary
echo ""
echo "=== Debug information collected to $OUTPUT_DIR ==="
ls -la "$OUTPUT_DIR"
echo ""
echo "=== Quick Status Summary ==="
echo "Pods in $NAMESPACE:"
kubectl get pods -n "$NAMESPACE" 2>/dev/null || echo "Namespace not found"
echo ""
echo "Recent events in $NAMESPACE:"
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' 2>/dev/null | tail -20 || echo "No events found"

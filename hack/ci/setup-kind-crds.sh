#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-auth-operator-e2e}
CERT_MANAGER_VERSION=${CERT_MANAGER_VERSION:-v1.15.3}
GATEWAY_API_VERSION=${GATEWAY_API_VERSION:-v1.2.0}
PROMETHEUS_OPERATOR_VERSION=${PROMETHEUS_OPERATOR_VERSION:-v0.78.2}
CALICO_VERSION=${CALICO_VERSION:-v3.29.0}
EXTERNAL_SECRETS_VERSION=${EXTERNAL_SECRETS_VERSION:-v0.10.7}
VELERO_VERSION=${VELERO_VERSION:-v1.15.0}

# Use --context to avoid mutating global kubeconfig state
KUBECTL="kubectl --context kind-${KIND_CLUSTER_NAME}"

echo "Installing popular CRDs into kind cluster: ${KIND_CLUSTER_NAME}"

echo "Installing cert-manager CRDs (${CERT_MANAGER_VERSION})"
$KUBECTL apply --server-side -f "https://github.com/cert-manager/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.crds.yaml"

echo "Installing Gateway API CRDs (${GATEWAY_API_VERSION})"
$KUBECTL apply --server-side -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

# Prometheus Operator CRDs are large and require server-side apply to avoid annotation size limits
echo "Installing Prometheus Operator CRDs (${PROMETHEUS_OPERATOR_VERSION})"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_alertmanagerconfigs.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_alertmanagers.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_podmonitors.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_probes.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_prometheusagents.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_prometheuses.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_prometheusrules.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_scrapeconfigs.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/${PROMETHEUS_OPERATOR_VERSION}/example/prometheus-operator-crd/monitoring.coreos.com_thanosrulers.yaml"

# Calico CRDs (referenced in samples for NetworkPolicy restrictions)
echo "Installing Calico CRDs (${CALICO_VERSION})"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/crds.yaml"

# External Secrets Operator CRDs (referenced in samples for secret management)
echo "Installing External Secrets Operator CRDs (${EXTERNAL_SECRETS_VERSION})"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/external-secrets/external-secrets/${EXTERNAL_SECRETS_VERSION}/deploy/crds/bundle.yaml"

# Velero CRDs (referenced in samples for backup API restrictions)
echo "Installing Velero CRDs (${VELERO_VERSION})"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/vmware-tanzu/velero/${VELERO_VERSION}/config/crd/v1/bases/velero.io_backups.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/vmware-tanzu/velero/${VELERO_VERSION}/config/crd/v1/bases/velero.io_restores.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/vmware-tanzu/velero/${VELERO_VERSION}/config/crd/v1/bases/velero.io_schedules.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/vmware-tanzu/velero/${VELERO_VERSION}/config/crd/v1/bases/velero.io_backupstoragelocations.yaml"
$KUBECTL apply --server-side -f "https://raw.githubusercontent.com/vmware-tanzu/velero/${VELERO_VERSION}/config/crd/v1/bases/velero.io_volumesnapshotlocations.yaml"

echo "CRD installation completed."

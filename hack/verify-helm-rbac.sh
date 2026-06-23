#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${ROOT_DIR}/chart/auth-operator"
KUSTOMIZE="${KUSTOMIZE:-${ROOT_DIR}/bin/kustomize}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

default_render="${TMP_DIR}/default.yaml"
namespace_admission_render="${TMP_DIR}/namespace-admission.yaml"
clusterwide_render="${TMP_DIR}/clusterwide.yaml"
scoped_render="${TMP_DIR}/scoped.yaml"
production_render="${TMP_DIR}/production.yaml"
metrics_auth_render="${TMP_DIR}/metrics-auth.yaml"
egress_render="${TMP_DIR}/egress.yaml"
broad_egress_render="${TMP_DIR}/broad-egress.yaml"

helm template auth-operator "${CHART_DIR}" --set image.tag=test >"${default_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=none "${default_render}"

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set namespaceAdmission.enabled=true >"${namespace_admission_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=none "${namespace_admission_render}"

"${KUSTOMIZE}" build "${ROOT_DIR}/config/overlays/production" >"${production_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=none "${production_render}"

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true \
	--set controller.impersonation.clusterWide=true >"${clusterwide_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=clusterwide "${clusterwide_render}"

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true \
	--set controller.impersonation.serviceAccounts[0].namespace=team-a \
	--set controller.impersonation.serviceAccounts[0].name=team-a-rbac-applier >"${scoped_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=scoped --serviceaccount=team-a-rbac-applier "${scoped_render}"
if ! grep -Eq '^kind:[[:space:]]*Role$' "${scoped_render}" ||
	! grep -Eq '^kind:[[:space:]]*RoleBinding$' "${scoped_render}"; then
	echo "scoped impersonation opt-in did not render namespaced Role/RoleBinding grant" >&2
	exit 1
fi

if helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true >/dev/null 2>&1; then
	echo "impersonation enabled without clusterWide or serviceAccounts should fail Helm rendering" >&2
	exit 1
fi

if helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set networkPolicy.enabled=true \
	--set networkPolicy.egress.enabled=true >/dev/null 2>&1; then
	echo "networkPolicy egress without apiServerCIDR or additionalRules should fail Helm rendering" >&2
	exit 1
fi

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set networkPolicy.enabled=true \
	--set networkPolicy.egress.enabled=true \
	--set networkPolicy.egress.apiServerCIDR=10.96.0.1/32 >"${egress_render}"
if ! grep -Eq '^[[:space:]]*cidr:[[:space:]]*"10\.96\.0\.1/32"[[:space:]]*$' "${egress_render}"; then
	echo "networkPolicy egress with apiServerCIDR did not render the API server CIDR" >&2
	exit 1
fi

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set networkPolicy.enabled=true \
	--set networkPolicy.egress.enabled=true \
	--set networkPolicy.egress.allowBroadAPIServerEgress=true >"${broad_egress_render}"
go run "${ROOT_DIR}/hack/verify-rendered-rbac.go" --impersonation=none --require-broad-apiserver-egress "${broad_egress_render}"

if helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set metrics.auth.enabled=true \
	--set metrics.serviceMonitor.enabled=true >/dev/null 2>&1; then
	echo "authenticated metrics ServiceMonitor without caFile or insecureSkipVerify should fail Helm rendering" >&2
	exit 1
fi

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set metrics.auth.enabled=true \
	--set metrics.serviceMonitor.enabled=true \
	--set metrics.serviceMonitor.tlsConfig.insecureSkipVerify=true >"${metrics_auth_render}"
if ! grep -Eq '^[[:space:]]*insecureSkipVerify:[[:space:]]*true[[:space:]]*$' "${metrics_auth_render}"; then
	echo "authenticated metrics ServiceMonitor did not render explicit self-signed TLS opt-in" >&2
	exit 1
fi

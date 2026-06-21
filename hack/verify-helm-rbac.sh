#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${ROOT_DIR}/chart/auth-operator"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

default_render="${TMP_DIR}/default.yaml"
clusterwide_render="${TMP_DIR}/clusterwide.yaml"
scoped_render="${TMP_DIR}/scoped.yaml"

helm template auth-operator "${CHART_DIR}" --set image.tag=test >"${default_render}"
if grep -Eq '^[[:space:]]*-[[:space:]]*impersonate[[:space:]]*$' "${default_render}"; then
	echo "default Helm render must not grant serviceaccounts/impersonate" >&2
	exit 1
fi

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true \
	--set controller.impersonation.clusterWide=true >"${clusterwide_render}"
if ! grep -Eq '^[[:space:]]*-[[:space:]]*impersonate[[:space:]]*$' "${clusterwide_render}"; then
	echo "cluster-wide impersonation opt-in did not render impersonate verb" >&2
	exit 1
fi

helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true \
	--set controller.impersonation.serviceAccounts[0].namespace=team-a \
	--set controller.impersonation.serviceAccounts[0].name=team-a-rbac-applier >"${scoped_render}"
if ! grep -Eq '^kind:[[:space:]]*Role$' "${scoped_render}" ||
	! grep -Eq '^kind:[[:space:]]*RoleBinding$' "${scoped_render}" ||
	! grep -Eq '^[[:space:]]*-[[:space:]]*"team-a-rbac-applier"[[:space:]]*$' "${scoped_render}" ||
	! grep -Eq '^[[:space:]]*-[[:space:]]*impersonate[[:space:]]*$' "${scoped_render}"; then
	echo "scoped impersonation opt-in did not render namespaced Role/RoleBinding grant" >&2
	exit 1
fi

if helm template auth-operator "${CHART_DIR}" \
	--set image.tag=test \
	--set controller.impersonation.enabled=true >/dev/null 2>&1; then
	echo "impersonation enabled without clusterWide or serviceAccounts should fail Helm rendering" >&2
	exit 1
fi

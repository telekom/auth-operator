#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
#
# Provisions the Flux tenant-RBAC e2e environment, reproducing how the T-CaaS
# `flux` function actually deploys Flux. Two modes are supported, matching the
# function's own $mode variable:
#
#   E2E_FLUX_MODE=workload    (default) tenant / workload clusters
#   E2E_FLUX_MODE=management            management clusters
#
# ------------------------------------------------------------------------------
# Workload mode, as deployed on a tenant cluster
# ------------------------------------------------------------------------------
# From the flux function definition.yaml, verified rather than assumed:
#
#   * Every controller sets serviceAccount.create: false and
#     serviceAccount.name: m2m-sa-t-caas-<tenant>. The controller Deployments
#     therefore RUN AS the m2m ServiceAccount; it is their own pod identity, not
#     merely an impersonation target.
#   * m2m-sa-t-caas-<tenant> exists ONLY in t-caas-controllers. It is created by
#     the auth-operator BindDefinition controller from the tenant-serviceaccounts
#     BindDefinition subjects. No platform function creates a ServiceAccount in a
#     tenant namespace, so the only ServiceAccount in a namespace like
#     schiff-tenant is the one Kubernetes auto-creates: `default`.
#   * multitenancy.enabled: false and multitenancy.privileged: true. Consequently
#     the chart's cluster-reconciler-impersonator ClusterRole, which is gated on
#     `multitenancy.enabled AND NOT privileged`, NEVER renders - so nothing grants
#     the m2m ServiceAccount the `impersonate` verb.
#   * The cluster-reconciler ClusterRoleBinding binds cluster-admin to
#     ServiceAccounts literally named kustomize-controller and helm-controller,
#     which the Deployments never use. The m2m SA does not inherit it.
#   * --default-service-account=default (multitenancy.defaultServiceAccount).
#
# This script reproduces that topology exactly and deliberately creates NO
# ServiceAccounts beyond the single m2m SA in t-caas-controllers. In particular it
# does not create an m2m ServiceAccount in a tenant namespace, because none exists
# on a real cluster.
#
# ------------------------------------------------------------------------------
# Management mode
# ------------------------------------------------------------------------------
# Management clusters set extraObjects: [] and run each controller under its own
# locally created ServiceAccount (helm-controller, source-controller, ...). No m2m
# ServiceAccount exists at all. The specs assert that the tenant RBAC objects are
# absent there.
#
# OCI artifacts are pushed to an in-cluster registry so no spec depends on an
# external git host.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

load_version_default() {
  local key=$1
  local value

  if [ -n "${!key:-}" ] || [ ! -f "${ROOT_DIR}/versions.env" ]; then
    return
  fi

  value="$(awk -F= -v key="${key}" '$1 == key {print $2}' "${ROOT_DIR}/versions.env")"
  if [ -n "${value}" ]; then
    printf -v "${key}" '%s' "${value}"
  fi
}

load_version_default E2E_FLUX_VERSION

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-auth-operator-e2e-flux}
FLUX_VERSION=${FLUX_VERSION:-${E2E_FLUX_VERSION:-v2.8.8}}
CONTAINER_TOOL=${CONTAINER_TOOL:-docker}
REGISTRY_NAME=${REGISTRY_NAME:-kind-registry}
REGISTRY_HOST_PORT=${REGISTRY_HOST_PORT:-5001}

# workload (tenant clusters) or management
E2E_FLUX_MODE=${E2E_FLUX_MODE:-workload}

TENANT=${TENANT:-t5g}
CONTROLLERS_NS=${CONTROLLERS_NS:-t-caas-controllers}
TENANT_NS=${TENANT_NS:-schiff-tenant}
FOREIGN_TENANT_NS=${FOREIGN_TENANT_NS:-other-tenant}
UNLABELLED_NS=${UNLABELLED_NS:-unlabelled-tenant}
M2M_SA="m2m-sa-t-caas-${TENANT}"

KUBECTL="kubectl --context kind-${KIND_CLUSTER_NAME}"

echo ">>> Flux e2e setup: cluster=${KIND_CLUSTER_NAME} mode=${E2E_FLUX_MODE} flux=${FLUX_VERSION}"

case "${E2E_FLUX_MODE}" in
  workload | management) ;;
  *)
    echo "!!! E2E_FLUX_MODE must be 'workload' or 'management', got '${E2E_FLUX_MODE}'" >&2
    exit 1
    ;;
esac

#-------------------------------------------------------------------------------
# 1. Local OCI registry, reachable from the kind node
#-------------------------------------------------------------------------------
echo ">>> Ensuring local OCI registry '${REGISTRY_NAME}' on port ${REGISTRY_HOST_PORT}"
if [ "$(${CONTAINER_TOOL} inspect -f '{{.State.Running}}' "${REGISTRY_NAME}" 2>/dev/null || true)" != "true" ]; then
  ${CONTAINER_TOOL} rm -f "${REGISTRY_NAME}" >/dev/null 2>&1 || true
  ${CONTAINER_TOOL} run -d --restart=always \
    -p "127.0.0.1:${REGISTRY_HOST_PORT}:5000" \
    --name "${REGISTRY_NAME}" \
    registry:3
fi

if ! ${CONTAINER_TOOL} network inspect kind -f '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null | grep -qw "${REGISTRY_NAME}"; then
  ${CONTAINER_TOOL} network connect kind "${REGISTRY_NAME}" || true
fi

${KUBECTL} apply --server-side -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${REGISTRY_HOST_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF

#-------------------------------------------------------------------------------
# 2. Namespaces
#-------------------------------------------------------------------------------
echo ">>> Creating namespaces"
${KUBECTL} apply --server-side -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${CONTROLLERS_NS}
  labels:
    t-caas.telekom.com/owner: platform
EOF

if [ "${E2E_FLUX_MODE}" = "workload" ]; then
  # Tenant namespaces, labelled exactly as the auth-operator chart's
  # tenantNamespaceSelector expects.
  ${KUBECTL} apply --server-side -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: ${TENANT_NS}
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: ${TENANT}
---
# A second tenant. Nothing belonging to ${TENANT} may ever reach this namespace.
apiVersion: v1
kind: Namespace
metadata:
  name: ${FOREIGN_TENANT_NS}
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: other
---
# Manually created namespace with no tenant labels. The namespaceSelector must not
# match it, so it must receive no RoleBinding.
apiVersion: v1
kind: Namespace
metadata:
  name: ${UNLABELLED_NS}
EOF
fi

#-------------------------------------------------------------------------------
# 3. Flux controllers
#-------------------------------------------------------------------------------
# The real function installs Flux into t-caas-controllers, not flux-system, and in
# workload mode runs the controllers as the m2m ServiceAccount.
echo ">>> Installing Flux ${FLUX_VERSION} into ${CONTROLLERS_NS}"

if [ "${E2E_FLUX_MODE}" = "workload" ]; then
  # The one ServiceAccount that genuinely exists: created by the auth-operator
  # BindDefinition controller in t-caas-controllers. Created here directly because
  # this fixture does not run the full auth-operator reconcile loop.
  echo ">>> Creating ${CONTROLLERS_NS}/${M2M_SA} (the controllers' own identity)"
  ${KUBECTL} apply --server-side -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${M2M_SA}
  namespace: ${CONTROLLERS_NS}
EOF
fi

if command -v flux >/dev/null 2>&1; then
  flux install \
    --context "kind-${KIND_CLUSTER_NAME}" \
    --namespace "${CONTROLLERS_NS}" \
    --components=source-controller,kustomize-controller,helm-controller \
    --network-policy=false
else
  echo "!!! flux CLI is required (used for install and for pushing OCI artifacts)" >&2
  exit 1
fi

echo ">>> Waiting for Flux controllers to become available"
for deploy in source-controller kustomize-controller helm-controller; do
  ${KUBECTL} -n "${CONTROLLERS_NS}" wait --for=condition=Available "deployment/${deploy}" --timeout=5m
done

if [ "${E2E_FLUX_MODE}" = "workload" ]; then
  # Reproduce the function's workload topology on top of the stock install:
  #   * controllers run as the m2m SA (serviceAccount.create: false)
  #   * --default-service-account=default (multitenancy.defaultServiceAccount)
  # The stock `flux install` gives each controller its own SA and a cluster-admin
  # binding, which is NOT what a tenant cluster looks like, so both are corrected.
  echo ">>> Repointing kustomize/helm controllers at ${M2M_SA} and setting --default-service-account=default"

  for deploy in kustomize-controller helm-controller; do
    ${KUBECTL} -n "${CONTROLLERS_NS}" patch "deployment/${deploy}" --type=merge -p "$(
      cat <<EOF
{"spec":{"template":{"spec":{"serviceAccountName":"${M2M_SA}"}}}}
EOF
    )"

    # Append --default-service-account=default, mirroring the chart's controller args.
    ${KUBECTL} -n "${CONTROLLERS_NS}" patch "deployment/${deploy}" --type=json -p \
      '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--default-service-account=default"}]'
  done

  # Drop the stock cluster-admin grants so the m2m SA holds only what the T-CaaS
  # function actually gives it. Without this the cluster is far more permissive
  # than production and the specs would pass vacuously.
  echo ">>> Removing stock cluster-admin bindings for the Flux controller SAs"
  ${KUBECTL} delete clusterrolebinding cluster-reconciler --ignore-not-found=true
  ${KUBECTL} delete clusterrolebinding crd-controller --ignore-not-found=true

  # The resource-only RBAC the function grants via extraObjects
  # (t-caas-controllers-sa). Deliberately carries NO nonResourceURLs rule and NO
  # impersonate verb, matching definition.yaml.
  echo ">>> Applying t-caas-controllers-sa RBAC (resource-only, as the function ships it)"
  ${KUBECTL} apply --server-side -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: t-caas-controllers-sa
rules:
  - apiGroups: ["kustomize.toolkit.fluxcd.io"]
    resources: ["kustomizations", "kustomizations/status"]
    verbs: ["*"]
  - apiGroups: ["source.toolkit.fluxcd.io"]
    resources:
      - buckets
      - gitrepositories
      - gitrepositories/status
      - helmcharts
      - helmcharts/status
      - helmrepositories
      - helmrepositories/status
      - ocirepositories
      - ocirepositories/status
    verbs: ["*"]
  - apiGroups: ["helm.toolkit.fluxcd.io"]
    resources: ["helmreleases", "helmreleases/status"]
    verbs: ["*"]
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["get", "list", "watch", "create", "patch", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: t-caas-controllers-sa
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: t-caas-controllers-sa
subjects:
  - kind: ServiceAccount
    name: ${M2M_SA}
    namespace: ${CONTROLLERS_NS}
EOF

  # The namespaced tenant permissions the auth-operator grants: RoleBindings
  # created IN each selected tenant namespace, whose subject is the m2m SA in
  # t-caas-controllers. Namespaced RoleBindings cannot convey nonResourceURLs,
  # which is central to the discovery failure.
  echo ">>> Applying tenant namespace RoleBindings (subject is ${CONTROLLERS_NS}/${M2M_SA})"
  ${KUBECTL} apply --server-side -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: e2e-tenant-namespaced-poweruser
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets", "services", "serviceaccounts"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["apps"]
    resources: ["deployments", "statefulsets"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  - apiGroups: ["helm.toolkit.fluxcd.io", "kustomize.toolkit.fluxcd.io", "source.toolkit.fluxcd.io"]
    resources: ["*"]
    verbs: ["*"]
EOF

  for ns in "${TENANT_NS}" "${CONTROLLERS_NS}"; do
    ${KUBECTL} apply --server-side -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: e2e-tenant-namespaced-poweruser
  namespace: ${ns}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: e2e-tenant-namespaced-poweruser
subjects:
  - kind: ServiceAccount
    name: ${M2M_SA}
    namespace: ${CONTROLLERS_NS}
EOF
  done
fi

#-------------------------------------------------------------------------------
# 4. OCI artifacts
#-------------------------------------------------------------------------------
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

mkdir -p "${WORK_DIR}/kustomize"
cat >"${WORK_DIR}/kustomize/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - configmap.yaml
EOF
cat >"${WORK_DIR}/kustomize/configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: e2e-tenant-values
data:
  tenant: ${TENANT}
EOF

mkdir -p "${WORK_DIR}/chart/templates"
cat >"${WORK_DIR}/chart/Chart.yaml" <<EOF
apiVersion: v2
name: e2e-tenant-chart
description: Minimal chart for the Flux tenant-RBAC e2e suite
type: application
version: 0.1.0
appVersion: "0.1.0"
EOF
cat >"${WORK_DIR}/chart/values.yaml" <<EOF
tenant: ${TENANT}
EOF
cat >"${WORK_DIR}/chart/templates/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-values
data:
  tenant: {{ .Values.tenant | quote }}
EOF

REGISTRY_PUSH_HOST="localhost:${REGISTRY_HOST_PORT}"

echo ">>> Pushing kustomize OCI artifact to ${REGISTRY_PUSH_HOST}"
flux push artifact "oci://${REGISTRY_PUSH_HOST}/e2e/tenant-kustomize:v1" \
  --path "${WORK_DIR}/kustomize" \
  --source="e2e" \
  --revision="v1" \
  --provider=generic

echo ">>> Packaging and pushing Helm chart to ${REGISTRY_PUSH_HOST}"
helm package "${WORK_DIR}/chart" --destination "${WORK_DIR}"
helm push "${WORK_DIR}/e2e-tenant-chart-0.1.0.tgz" "oci://${REGISTRY_PUSH_HOST}/e2e/charts"

echo ">>> Flux e2e setup complete (mode=${E2E_FLUX_MODE})."
echo "    registry (host):    ${REGISTRY_PUSH_HOST}"
echo "    registry (in-node): ${REGISTRY_NAME}:5000"
echo "    flux namespace:     ${CONTROLLERS_NS}"
if [ "${E2E_FLUX_MODE}" = "workload" ]; then
  echo "    controller identity: ${CONTROLLERS_NS}/${M2M_SA}"
  echo "    NOTE: no m2m ServiceAccount exists in ${TENANT_NS}; only the auto-created 'default'."
  echo "    NOTE: nothing grants the 'impersonate' verb, matching the real function."
else
  echo "    controller identity: per-controller local ServiceAccounts (no m2m SA)"
fi

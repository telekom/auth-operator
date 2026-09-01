#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

for command in curl sha256sum helm kubectl timeout; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 1
  }
done

: "${KYVERNO_CHART_URL:?set KYVERNO_CHART_URL from versions.env}"
: "${KYVERNO_CHART_SHA256:?set KYVERNO_CHART_SHA256 from versions.env}"
: "${KYVERNO_CHART_VERSION:?set KYVERNO_CHART_VERSION from versions.env}"
: "${KYVERNO_VERSION:?set KYVERNO_VERSION from versions.env}"

case "${KYVERNO_VERSION}:${KYVERNO_CHART_VERSION}" in
  v1.19.0:3.9.0) ;;
  *) echo "unsupported Kyverno pin: app ${KYVERNO_VERSION}, chart ${KYVERNO_CHART_VERSION}; only v1.19.0/3.9.0 is tested" >&2; exit 1 ;;
esac
namespace="kyverno"
archive_root="${KYVERNO_E2E_ARCHIVE_DIR:-${RUNNER_TEMP:-/tmp}}"
[[ -d "$archive_root" && ! -L "$archive_root" ]] || {
  echo "Kyverno archive root must be an existing non-symlink directory: $archive_root" >&2
  exit 1
}
archive_dir=$(mktemp -d -- "${archive_root%/}/auth-operator-kyverno.XXXXXX")
chmod 700 "$archive_dir"
archive="${archive_dir}/kyverno-${KYVERNO_CHART_VERSION}.tgz"
actual="${archive}.sha256"
[[ ! -L "$archive" && ! -e "$archive" ]] || { echo "refusing to overwrite existing archive $archive" >&2; exit 1; }
[[ ! -L "$actual" && ! -e "$actual" ]] || { echo "refusing to overwrite existing checksum $actual" >&2; exit 1; }

timeout --signal=TERM --kill-after=30s 10m curl --fail --location --silent --show-error --retry 3 "${KYVERNO_CHART_URL}" --output "${archive}"
printf '%s  %s\n' "${KYVERNO_CHART_SHA256}" "${archive}" > "${actual}"
timeout --signal=TERM --kill-after=30s 2m sha256sum --check "${actual}"

chart_metadata=$(timeout --signal=TERM --kill-after=30s 2m helm show chart "${archive}")
chart_version=$(awk '$1 == "version:" { print $2; exit }' <<<"${chart_metadata}")
chart_app_version=$(awk '$1 == "appVersion:" { print $2; exit }' <<<"${chart_metadata}")
chart_app_version=${chart_app_version#\"}
chart_app_version=${chart_app_version%\"}
chart_app_version=${chart_app_version#\'}
chart_app_version=${chart_app_version%\'}
[[ "${chart_version}" == "${KYVERNO_CHART_VERSION}" ]] || {
  echo "verified chart metadata reports version ${chart_version:-missing}, expected ${KYVERNO_CHART_VERSION}" >&2
  exit 1
}
[[ "${chart_app_version}" == "${KYVERNO_VERSION}" ]] || {
  echo "verified chart metadata reports appVersion ${chart_app_version:-missing}, expected ${KYVERNO_VERSION}" >&2
  exit 1
}

timeout --signal=TERM --kill-after=30s 15m helm upgrade --install kyverno "${archive}" --namespace "${namespace}" --create-namespace --wait --timeout 10m \
  --set crds.install=true \
  --set crds.groups.policies.mutatingpolicies=true \
  --set features.generateMutatingAdmissionPolicy.enabled=true

timeout --signal=TERM --kill-after=30s 3m kubectl wait --for=condition=Established --timeout=120s crd/mutatingpolicies.policies.kyverno.io
timeout --signal=TERM --kill-after=30s 3m kubectl wait --for=condition=Established --timeout=120s crd/clusterpolicies.kyverno.io
kubectl api-resources --api-group=policies.kyverno.io | grep -Eq '(^|[[:space:]])mutatingpolicies([[:space:]]|$)'
timeout --signal=TERM --kill-after=30s 2m kubectl get --raw /apis/admissionregistration.k8s.io/v1 >/dev/null
kubectl auth can-i create mutatingpolicies.policies.kyverno.io | grep -qx yes
kubectl auth can-i delete mutatingpolicies.policies.kyverno.io | grep -qx yes
timeout --signal=TERM --kill-after=30s 7m kubectl -n "${namespace}" rollout status deployment/kyverno-admission-controller --timeout=5m
timeout --signal=TERM --kill-after=30s 7m kubectl -n "${namespace}" rollout status deployment/kyverno-background-controller --timeout=5m

admission_service_account=$(kubectl -n "${namespace}" get deployment kyverno-admission-controller -o jsonpath='{.spec.template.spec.serviceAccountName}')
[[ -n "${admission_service_account}" && "${admission_service_account}" != *[[:space:]]* ]] || {
  echo 'Kyverno admission controller has no unambiguous service account' >&2
  exit 1
}

for resource in mutatingadmissionpolicies.admissionregistration.k8s.io mutatingadmissionpolicybindings.admissionregistration.k8s.io; do
  for verb in get list watch create update patch delete; do
    kubectl auth can-i --as="system:serviceaccount:${namespace}:${admission_service_account}" "${verb}" "${resource}" | grep -qx yes
  done
done
for verb in get list watch; do
  kubectl auth can-i --as="system:serviceaccount:${namespace}:${admission_service_account}" "${verb}" mutatingpolicies.policies.kyverno.io | grep -qx yes
done
for verb in update patch; do
  kubectl auth can-i --as="system:serviceaccount:${namespace}:${admission_service_account}" "${verb}" mutatingpolicies.policies.kyverno.io/status | grep -qx yes
done

echo "Kyverno chart ${KYVERNO_CHART_VERSION} (app ${KYVERNO_VERSION}) is ready"

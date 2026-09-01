#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

runner=hack/ci/run-creator-tracking-kyverno-e2e.sh
installer=hack/ci/install-kyverno.sh
creator_runner=hack/run-creator-tracking-e2e.sh
workflow=.github/workflows/e2e.yml
bash -n "$runner" "$installer"
bash -n "$creator_runner"

# GNU stat reports an empty regular file as "regular empty file", while BSD
# stat reports "Regular File". All lock guards accept both spellings, retain
# owner/mode checks, and repair only an owned empty stale lock.
for guarded in "$creator_runner" "$runner"; do
  grep -Fq 'regular empty file' "$guarded"
  grep -Fq 'Regular File' "$guarded"
  grep -Fq 'stat -f %HT' "$guarded"
  grep -Fq '! -s' "$guarded"
done
grep -Fq 'regular empty file' "$workflow"
grep -Fq 'Regular File' "$workflow"
grep -Fq 'stat -f %HT' "$workflow"
grep -Fq '[ ! -s "$lock_file" ]' "$workflow"
grep -Fq 'make test-creator-tracking-kyverno-runner' "$workflow"
grep -Fq 'name: Upload Kyverno debug artifacts' "$workflow"
grep -Fq 'path: /tmp/creator-tracking-kyverno-debug/' "$workflow"

# A composite name must brace the variable when nounset is enabled.
braced="assert_container_absent \"\${cluster}-control-plane\""
unbraced="assert_container_absent \"\$cluster-control-plane\""
grep -Fq "$braced" "$runner"
if grep -Fq "$unbraced" "$runner"; then exit 1; fi

# Cleanup is authorized only by the fixed marker and cannot adopt caller paths.
grep -Fq 'readonly marker=/tmp/auth-operator-e2e-kyverno.owner' "$runner"
grep -Fq 'KYVERNO_E2E_CLUSTER, KYVERNO_E2E_LOCK, and KYVERNO_E2E_KUBECONFIG are not supported' "$runner"
grep -Fq 'cleanup-only requires the exact ownership marker' "$runner"
grep -Fq 'marker_owner=$(stat -c %u' "$runner"
grep -Fq 'marker_mode=$(stat -c %a' "$runner"
grep -Fq 'marker_owner" == "$(id -u)"' "$runner"
grep -Fq 'marker_type" == '\''regular file'\''' "$runner"
grep -Fq 'set -C; printf' "$runner"
grep -Fq '"$owner" >"$marker"' "$runner"

# The installer must use the supported Kyverno source CRD and native generated
# admissionregistration resources, never an invented binding CRD.
grep -Fq 'mutatingpolicies.policies.kyverno.io' "$installer"
grep -Fq 'mutatingadmissionpolicies.admissionregistration.k8s.io' "$installer"
grep -Fq 'mutatingadmissionpolicybindings.admissionregistration.k8s.io' "$installer"
# The next three assertions intentionally match shell source literally.
# shellcheck disable=SC2016
grep -Fq 'helm show chart "${archive}"' "$installer"
# shellcheck disable=SC2016
grep -Fq '[[ "${chart_version}" == "${KYVERNO_CHART_VERSION}" ]]' "$installer"
# shellcheck disable=SC2016
grep -Fq '[[ "${chart_app_version}" == "${KYVERNO_VERSION}" ]]' "$installer"
if grep -Fq 'mutatingpolicybindings.policies.kyverno.io' "$installer"; then
  exit 1
fi

# Debug and chart artifacts must be created atomically below validated paths;
# neither runner may follow a caller-controlled directory symlink.
grep -Fq 'mkdir -- "$artifact_dir"' "$runner"
! grep -Fq 'mkdir -p "$artifact_dir"' "$runner"
grep -Fq '[[ -d "$archive_root" && ! -L "$archive_root" ]]' "$installer"
grep -Fq 'mktemp -d -- "${archive_root%/}/auth-operator-kyverno.XXXXXX"' "$installer"
! grep -Fq 'mkdir -p "$archive_dir"' "$installer"

# An empty Kind inventory is a successful preflight state. Exercise the runner
# with bounded fakes and prove that it reaches Docker readiness instead of
# silently exiting on the expected failed cluster-name match under `set -e`.
probe_dir=$(mktemp -d)
trap 'rm -rf "$probe_dir"' EXIT
mkdir "$probe_dir/bin"
cat >"$probe_dir/bin/kind" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-} ${2:-}" == "get clusters" ]]; then
  echo 'No kind clusters found.'
  exit 0
fi
exit 99
EOF
cat >"$probe_dir/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "${1:-} ${2:-}" in
  'container inspect') echo 'No such container' >&2; exit 1 ;;
  'image inspect') echo 'No such image' >&2; exit 1 ;;
  'info ') exit 0 ;;
  'build --tag')
    [[ "${DOCKER_BUILDKIT:-}" == 1 ]]
    printf 'called\n' >"$KYVERNO_RUNNER_PROBE"
    exit 42
    ;;
esac
exit 99
EOF
cat >"$probe_dir/bin/flock" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$probe_dir/bin/stat" <<'EOF'
#!/usr/bin/env bash
case "${2:-}" in
  %F) echo 'regular file' ;;
  %u) id -u ;;
  %a) echo 600 ;;
  *) exit 1 ;;
esac
EOF
cat >"$probe_dir/bin/timeout" <<'EOF'
#!/usr/bin/env bash
while [[ "${1:-}" == --* ]]; do shift; done
shift
exec "$@"
EOF
chmod 0755 "$probe_dir/bin/kind" "$probe_dir/bin/docker" "$probe_dir/bin/flock" "$probe_dir/bin/stat" "$probe_dir/bin/timeout"

for path in \
  /tmp/auth-operator-e2e-kyverno.owner \
  /tmp/auth-operator-e2e-kyverno.kubeconfig \
  /tmp/auth-operator-e2e-kyverno-run \
  /tmp/creator-tracking-kyverno-debug; do
  [[ ! -e "$path" && ! -L "$path" ]]
done
set +e
PATH="$probe_dir/bin:$PATH" KYVERNO_RUNNER_PROBE="$probe_dir/docker-called" "$runner" full
rc=$?
set -e
[[ "$rc" -eq 42 ]]
[[ -f "$probe_dir/docker-called" ]]
[[ ! -e /tmp/auth-operator-e2e-kyverno.owner && ! -L /tmp/auth-operator-e2e-kyverno.owner ]]

# Retained diagnostics keep an exact ownership capability, and cleanup-only
# consumes it while removing the owned artifacts.
grep -Fq ">\"\$artifact_dir/.owner\"" "$runner"
grep -Fq "owned debug artifacts retained at \$artifact_dir; run cleanup-only before retrying" "$runner"
grep -Fq 'cleanup_owned 0' "$runner"
grep -Fq 'source versions.env' "$runner"
grep -Fq 'readonly kind_image=$E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE' "$runner"
! grep -Fq 'kindest/node:' "$runner"
grep -Fq 'E2E_EXACT_CLEANUP_ONLY=true SKIP_CLUSTER_SETUP=true' "$runner"

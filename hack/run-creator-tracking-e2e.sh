#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck disable=SC1091 # Repository-owned version pins.
source "$repo_root/versions.env"

mode=${1:-}
case "$mode" in
full) ;;
*)
	echo "usage: $0 full" >&2
	exit 2
	;;
esac

cluster_name=auth-operator-e2e-creator-tracking
operator_image=auth-operator:creator-tracking-e2e
api_version=${E2E_CREATOR_TRACKING_API_VERSION:?E2E_CREATOR_TRACKING_API_VERSION is required}
expected_helm_version=${E2E_CREATOR_TRACKING_HELM_VERSION:?E2E_CREATOR_TRACKING_HELM_VERSION is required}
lock_file=/tmp/auth-operator-e2e-creator-tracking.lock
webhook_image=auth-operator/creator-reinvocation-webhook:e2e

if [[ -n ${E2E_CREATOR_TRACKING_CLUSTER_NAME:-} && ${E2E_CREATOR_TRACKING_CLUSTER_NAME} != "$cluster_name" ]]; then
	echo "E2E_CREATOR_TRACKING_CLUSTER_NAME cannot override the reserved cluster" >&2
	exit 2
fi
if [[ -n ${E2E_CREATOR_TRACKING_IMG:-} && ${E2E_CREATOR_TRACKING_IMG} != "$operator_image" ]]; then
	echo "E2E_CREATOR_TRACKING_IMG cannot override the reserved image" >&2
	exit 2
fi
if [[ -n ${E2E_CREATOR_TRACKING_WEBHOOK_IMG:-} && ${E2E_CREATOR_TRACKING_WEBHOOK_IMG} != "$webhook_image" ]]; then
	echo "E2E_CREATOR_TRACKING_WEBHOOK_IMG cannot override the reserved image" >&2
	exit 2
fi

for command in docker flock go helm kind kubectl readlink stat timeout; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "$command is required" >&2
		exit 1
	fi
done

umask 077
lock_uid=$(id -u)
if [[ ! -e "$lock_file" && ! -L "$lock_file" ]]; then
	# noclobber makes creation atomic and refuses a file that appeared after the
	# existence check. Never use touch here: it follows a symlink and can block
	# forever when an attacker pre-creates a FIFO at the fixed path.
	if ! (set -C; : >"$lock_file") 2>/dev/null; then
		echo "unable to create fixed creator tracking lock file: $lock_file" >&2
		exit 1
	fi
fi
if [[ -L "$lock_file" ]]; then
	echo "refusing symbolic-link lock file: $lock_file" >&2
	exit 1
fi
lock_type=$(stat -c %F "$lock_file" 2>/dev/null || true)
lock_owner=$(stat -c %u "$lock_file" 2>/dev/null || true)
lock_mode=$(stat -c %a "$lock_file" 2>/dev/null || true)
if [[ $lock_type != "regular file" || $lock_owner != "$lock_uid" || $lock_mode != 600 ]]; then
	echo "creator tracking lock must be an owned regular file with mode 600: $lock_file" >&2
	exit 1
fi
exec 9<>"$lock_file"
if [[ $(readlink -f /proc/$$/fd/9) != "$lock_file" ]]; then
	echo "creator tracking lock descriptor points to the wrong file" >&2
	exit 1
fi
if ! flock -n 9; then
	echo "another creator tracking run owns the fixed cluster and image names" >&2
	exit 1
fi

if [[ $mode == full ]]; then
	set +e
	webhook_image_output=$(timeout --signal=TERM --kill-after=5s 15s docker image inspect "$webhook_image" 2>&1)
	webhook_image_status=$?
	set -e
	if [[ $webhook_image_status -eq 0 ]]; then
		echo "reserved creator tracking webhook image already exists; refusing to overwrite it" >&2
		exit 1
	elif [[ $webhook_image_output != *"No such image"* && $webhook_image_output != *"No such object"* ]]; then
		echo "failed to inspect reserved webhook image; refusing to mutate fixed resources" >&2
		exit 1
	fi
fi

helm_version=$(timeout --signal=TERM --kill-after=5s 15s helm version --short)
if [[ $helm_version != "$expected_helm_version"* ]]; then
	echo "Helm version is $helm_version, want $expected_helm_version" >&2
	exit 1
fi

requested_run_dir=${E2E_CREATOR_TRACKING_RUN_DIR:-}
run_dir_created=false
if [[ -n "$requested_run_dir" ]]; then
	requested_run_dir=$(readlink -m "$requested_run_dir")
	if [[ $(dirname "$requested_run_dir") != /tmp ||
		$(basename "$requested_run_dir") != auth-operator-creator-tracking-* ]]; then
		echo "E2E_CREATOR_TRACKING_RUN_DIR must be an exact path below /tmp" >&2
		exit 1
	fi
	if [[ -e "$requested_run_dir" ]]; then
		echo "creator tracking run directory already exists: $requested_run_dir" >&2
		exit 1
	fi
	mkdir -m 0700 "$requested_run_dir"
	run_dir=$requested_run_dir
	run_dir_created=true
else
	run_dir=$(mktemp -d /tmp/auth-operator-creator-tracking-XXXXXXXX)
	run_dir_created=true
fi
export E2E_CREATOR_TRACKING_RUN_DIR=$run_dir
printf "%s\n" "$cluster_name" > "$run_dir/provenance"
chmod 600 "$run_dir/provenance"
cluster_authorized_marker=$run_dir/cluster-authorized
operator_image_authorized_marker=$run_dir/operator-image-authorized
webhook_image_authorized_marker=$run_dir/webhook-image-authorized
if [[ $mode == full ]]; then
	touch "$webhook_image_authorized_marker"
fi
marker_is_authorized() {
	[[ -f "$1" && ! -L "$1" && $(stat -c %a "$1" 2>/dev/null) == 600 ]]
}

cleanup_failed=false
# shellcheck disable=SC2317 # Called by the EXIT-trap cleanup function.
cleanup_image() {
	local image=$1
	local inspect_output
	if inspect_output=$(timeout --signal=TERM --kill-after=5s 15s docker image inspect "$image" 2>&1); then
		if ! timeout --signal=TERM --kill-after=5s 30s docker image rm "$image"; then
			echo "failed to remove test image $image" >&2
			cleanup_failed=true
		fi
	elif [[ $inspect_output != *"No such image"* && $inspect_output != *"No such object"* ]]; then
		echo "failed to inspect test image $image: $inspect_output" >&2
		cleanup_failed=true
	fi
}

# shellcheck disable=SC2317 # Registered as an EXIT, INT, and TERM trap below.
cleanup() {
	local result=$?
	local delete_output
	trap - EXIT INT TERM
	set +e

	if marker_is_authorized "$cluster_authorized_marker"; then
		if ! delete_output=$(timeout --signal=TERM --kill-after=10s 2m env KUBECONFIG="$kubeconfig" kind delete cluster --name "$cluster_name" 2>&1); then
			echo "failed to delete Kind cluster $cluster_name" >&2
			echo "$delete_output" >&2
			cleanup_failed=true
		fi
	fi
	if marker_is_authorized "$cluster_authorized_marker"; then
		set +e
		container_output=$(timeout --signal=TERM --kill-after=5s 15s docker container inspect "${cluster_name}-control-plane" 2>&1)
		container_status=$?
		set -e
		if [[ $container_status -eq 0 ]]; then
			if ! timeout --signal=TERM --kill-after=10s 30s docker rm -f -v "${cluster_name}-control-plane"; then
				echo "failed to remove Kind container ${cluster_name}-control-plane" >&2
				cleanup_failed=true
			fi
		elif [[ $container_output != *"No such object"* && $container_output != *"No such container"* ]]; then
			echo "failed to inspect test container: $container_output" >&2
			cleanup_failed=true
		fi
	fi
	if marker_is_authorized "$webhook_image_authorized_marker"; then cleanup_image "$webhook_image"; fi
	if marker_is_authorized "$operator_image_authorized_marker"; then cleanup_image "$operator_image"; fi

	if [[ $run_dir_created == true ]] && ! rm -rf -- "$run_dir"; then
		echo "failed to remove creator tracking run directory $run_dir" >&2
		cleanup_failed=true
	elif [[ -e $run_dir ]]; then
		echo "creator tracking run directory still exists: $run_dir" >&2
		cleanup_failed=true
	fi

	if [[ $cleanup_failed == true && $result -eq 0 ]]; then
		result=1
	fi
	exec 9>&-
	exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

kubeconfig=$run_dir/cluster.kubeconfig
: >"$kubeconfig"
chmod 0600 "$kubeconfig"
export KUBECONFIG=$kubeconfig

if [[ $mode == full ]]; then
	node_image=${E2E_CREATOR_TRACKING_NODE_IMAGE:?E2E_CREATOR_TRACKING_NODE_IMAGE is required for a full run}
	kind_config=${E2E_CREATOR_TRACKING_KIND_CONFIG:?E2E_CREATOR_TRACKING_KIND_CONFIG is required for a full run}
	case "$api_version" in
	admissionregistration.k8s.io/v1)
		expected_node_image=$E2E_CREATOR_TRACKING_STABLE_NODE_IMAGE
		expected_kind_config=test/e2e/kind-config-creator-tracking-stable.yaml ;;
	admissionregistration.k8s.io/v1beta1)
		expected_node_image=$E2E_CREATOR_TRACKING_BETA_NODE_IMAGE
		expected_kind_config=test/e2e/kind-config-creator-tracking-beta.yaml ;;
	*) echo "unsupported creator tracking API version: $api_version" >&2; exit 1 ;;
	esac
	if [[ $node_image != "$expected_node_image" || $kind_config != "$expected_kind_config" ]]; then
		echo "creator tracking node image and Kind config must be the pinned pair for $api_version" >&2
		exit 1
	fi

	set +e
	cluster_output=$(timeout --signal=TERM --kill-after=5s 15s kind get clusters 2>&1)
	cluster_status=$?
	set -e
	if [[ $cluster_status -ne 0 ]]; then
		echo "failed to inspect Kind clusters; refusing to mutate fixed resources" >&2
		exit 1
	fi
	if printf "%s\n" "$cluster_output" | grep -Fx "$cluster_name" >/dev/null; then
		echo "reserved creator tracking cluster already exists; refusing to adopt or delete it" >&2
		exit 1
	fi
	set +e
	operator_image_output=$(timeout --signal=TERM --kill-after=5s 15s docker image inspect "$operator_image" 2>&1)
	operator_image_status=$?
	set -e
	if [[ $operator_image_status -eq 0 ]]; then
		echo "reserved creator tracking image already exists; refusing to overwrite it" >&2
		exit 1
	elif [[ $operator_image_output != *"No such image"* && $operator_image_output != *"No such object"* ]]; then
		echo "failed to inspect reserved operator image; refusing to mutate fixed resources" >&2
		exit 1
	fi
	touch "$cluster_authorized_marker"
	timeout --signal=TERM --kill-after=30s 8m kind create cluster \
		--name "$cluster_name" \
		--config "$kind_config" \
		--image "$node_image" \
		--wait 5m
	arch=$(timeout --signal=TERM --kill-after=5s 15s docker version --format '{{.Server.Arch}}')
	case "$arch" in
	amd64 | arm64) ;;
	*)
		echo "unsupported Docker architecture: $arch" >&2
		exit 1
		;;
	esac
	touch "$operator_image_authorized_marker"
	DOCKER_BUILDKIT=1 timeout --signal=TERM --kill-after=30s 15m docker build \
		--build-arg BUILDPLATFORM="linux/$arch" \
		--build-arg TARGETOS=linux \
		--build-arg TARGETARCH="$arch" \
		-t "$operator_image" .
	timeout --signal=TERM --kill-after=30s 5m kind load docker-image "$operator_image" --name "$cluster_name"
fi

# Always replace setup credentials with kubeconfig generated by the exact target.
timeout --signal=TERM --kill-after=5s 30s kind get kubeconfig --name "$cluster_name" >"$kubeconfig"
chmod 0600 "$kubeconfig"
timeout --signal=TERM --kill-after=10s 30s kubectl cluster-info

start_seconds=$(date +%s)
set +e
KIND_CLUSTER="$cluster_name" \
	IMG="$operator_image" \
	E2E_CREATOR_TRACKING_API_VERSION="$api_version" \
	E2E_EXACT_CLEANUP_ONLY=true \
	SKIP_CLUSTER_SETUP=true \
	timeout --signal=TERM --kill-after=30s 40m \
go test -tags e2e ./test/e2e/ -v -ginkgo.v \
	-ginkgo.fail-on-empty -ginkgo.fail-on-pending -ginkgo.label-filter="creator-tracking" -timeout 35m
test_result=$?
set -e
elapsed_seconds=$(($(date +%s) - start_seconds))
echo "creator tracking Go test duration: ${elapsed_seconds}s"
set +e
timeout --signal=TERM --kill-after=30s 10m env \
	KIND_CLUSTER="$cluster_name" IMG="$operator_image" \
	E2E_CREATOR_TRACKING_API_VERSION="$api_version" \
	E2E_EXACT_CLEANUP_ONLY=true SKIP_CLUSTER_SETUP=true \
	go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.fail-on-empty -ginkgo.fail-on-pending \
	-ginkgo.label-filter="creator-tracking-cleanup" -timeout 8m
cleanup_result=$?
set -e
if [[ $test_result -eq 0 && $cleanup_result -ne 0 ]]; then
	test_result=$cleanup_result
fi
exit "$test_result"

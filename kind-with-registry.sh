#!/bin/bash
#
# Adapted from:
# https://github.com/kubernetes-sigs/kind/commits/master/site/static/examples/kind-with-registry.sh
#
# Copyright 2020 The Kubernetes Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CONTAINER_TOOL="${CONTAINER_TOOL:-docker}"

CLUSTER_NAME="${CLUSTER_NAME:-auth-operator}"
K8S_VERSION="${K8S_VERSION:-v1.32.5}"

KIND_IP_FAMILY="ipv4"

set -xo pipefail

# assert registry container exists and is up and running
LOCAL_REGISTRY_NAME="${LOCAL_REGISTRY_NAME_NAME:-local-registry}"
LOCAL_REGISTRY_PORT="${LOCAL_REGISTRY_PORT:-5001}"
running="$(${CONTAINER_TOOL} inspect -f '{{.State.Running}}' "${LOCAL_REGISTRY_NAME}" 2>/dev/null || true)"
if [ "${running}" != 'true' ]; then
  ${CONTAINER_TOOL} run -d --restart=always -p "${LOCAL_REGISTRY_PORT}:5000" --name "${LOCAL_REGISTRY_NAME}" registry:2 2>/dev/null
  ${CONTAINER_TOOL} start "${LOCAL_REGISTRY_NAME}"
fi

# unset all proxy vars from here on out to configure/setup stuff in cluster correctly
# unset HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy

running=$(${CONTAINER_TOOL} ps | grep ${CLUSTER_NAME} | wc -l)
if [ ! -z "${RESET_KIND_CLUSTER}" ] || [ $running -eq 0 ] ; then
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null
fi

# assert kind node image is present in local registry
KIND_IMAGE="kindest/node:${K8S_VERSION}"
# ${CONTAINER_TOOL} image inspect ${KIND_IMAGE} 2>&1 > /dev/null
# if [ $? -ne 0 ]; then
#   # build it for the required k8s version otherwise
#   kind build node-image "${K8S_VERSION}" --image "${KIND_IMAGE}"
# fi

# create the kind cluster with the local registry configured for t-co debugging
KIND_CLUSTER_OPTS="--name ${CLUSTER_NAME} --image ${KIND_IMAGE}"
cat <<EOF | HTTP_PROXY=$DOCKER_PROXY HTTPS_PROXY=$DOCKER_PROXY NO_PROXY=$DOCKER_NO_PROXY kind create cluster $KIND_CLUSTER_OPTS --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "127.0.0.1"
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/12"
  # apiServerPort: 6443
  ipFamily: ${KIND_IP_FAMILY}
nodes:
- role: control-plane
  extraMounts:
    - hostPath: /var/run/docker.sock
      containerPath: /var/run/docker.sock
# containerdConfigPatches:
# - |-
#   [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localmirror:${LOCAL_REGISTRY_PORT}"]
#     endpoint = ["http://${LOCAL_REGISTRY_NAME}:5000"]
EOF

# apply configmap to make the local registry known to the cluster
# this will in turn be picked up by tilt automatically and tilt will then use the local registry as well
# cat <<EOF | kubectl apply -f -
# apiVersion: v1
# kind: ConfigMap
# metadata:
#   name: local-registry-hosting
#   namespace: kube-public
# data:
#   localRegistryHosting.v1: |
#     host: "localmirror:${LOCAL_REGISTRY_PORT}"
#     help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
# EOF

# kind automatically creates a docker network named 'kind'
# assert the registry is connected and reachable from the clusters network
kind_network='kind'
containers=$(${CONTAINER_TOOL} network inspect ${kind_network} -f "{{range .Containers}}{{.Name}} {{end}}")
needs_connect="true"
for c in $containers; do
    if [ "$c" = "${LOCAL_REGISTRY_NAME}" ]; then
        needs_connect="false"
    fi
done
if [ "${needs_connect}" = "true" ]; then
  ${CONTAINER_TOOL} network connect "${kind_network}" "${LOCAL_REGISTRY_NAME}" || true
fi

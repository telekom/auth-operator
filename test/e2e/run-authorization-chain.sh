#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

cd "$(dirname "$0")/../.."
name="${KIND_CLUSTER:-auth-operator-chain-$$}"
release=auth-operator-chain
dir="$PWD/test/e2e/output/$name"
image="${IMG:-auth-operator:e2e-test}"
node_image="${KIND_NODE_IMAGE:-kindest/node:v1.37.0}"
# PROVIDED_CA=true passes CAs generated beforehand to the chart and runs only
# the provided-ca specs instead of the authorization chain specs.
provided_ca="${PROVIDED_CA:-false}"

if [[ ! "$name" =~ ^auth-operator-chain-[a-z0-9-]+$ ]]; then
  echo "KIND_CLUSTER must be a dedicated auth-operator-chain-* cluster name" >&2
  exit 1
fi
clusters="$(kind get clusters)"
if grep -Fxq "$name" <<<"$clusters"; then
  echo "Refusing to replace existing kind cluster $name" >&2
  exit 1
fi
mkdir -p "$(dirname "$dir")"
if [[ -e "$dir" || -L "$dir" ]]; then
  echo "Refusing to replace existing output directory $dir" >&2
  exit 1
fi
mkdir "$dir"
chmod 700 "$dir"
cluster_created=false
cleanup() {
  if [[ "${KEEP_CHAIN_CLUSTER:-false}" != true ]]; then
    if [[ "$cluster_created" == true ]]; then
      kind delete cluster --name "$name"
    fi
    rm -rf "$dir"
  elif [[ "$cluster_created" == true ]]; then
    echo "Cluster retained: $name; remove with kind delete cluster --name $name" >&2
  fi
}
trap cleanup EXIT

label_filter='authorization-chain && !provided-ca'
chart_args=(--set webhookServer.replicas=1)
if [[ "$provided_ca" == true ]]; then
  # Generate the CAs before the cluster exists, as for a CA that is part of the
  # node bootstrap data: the chart starts with ca1 and the test rotates to ca2.
  # The API server trusts both from its start, which is step 1 of the staged
  # rotation. The cert rotator only keeps a self-signed RSA CA with a PKCS#1
  # key, the DNS name "cert" and more than 90 days of validity.
  printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca' 'prompt = no' \
    '[dn]' 'CN = cert' \
    '[ca]' 'basicConstraints = critical,CA:TRUE' 'keyUsage = critical,keyCertSign,digitalSignature' \
    'subjectAltName = DNS:cert' 'subjectKeyIdentifier = hash' >"$dir/ca.cnf"
  for ca in ca1 ca2; do
    openssl req -x509 -config "$dir/ca.cnf" -newkey rsa:2048 -nodes -days 365 \
      -keyout "$dir/$ca.pkcs8" -out "$dir/$ca.crt" 2>/dev/null
    openssl rsa -in "$dir/$ca.pkcs8" -out "$dir/$ca.key" -traditional 2>/dev/null
    grep -q -- '-----BEGIN RSA PRIVATE KEY-----' "$dir/$ca.key"
  done
  cat "$dir/ca1.crt" "$dir/ca2.crt" >"$dir/ca.crt"
  # Two replicas keep admission available while the rotator restarts the
  # leader after it has issued the new serving certificate.
  chart_args=(--set webhookServer.replicas=2
    --set-file webhookServer.certificateAuthority.certificate="$dir/ca1.crt"
    --set-file webhookServer.certificateAuthority.privateKey="$dir/ca1.key")
  label_filter=provided-ca
fi

# Bootstrap with kubeadm's ordinary Node/RBAC chain: kubeadm itself needs to
# create its admin binding before the webhook Service exists. Enable the
# structured configuration only after the Service and CA are ready.
token="$(openssl rand -hex 32)"
cat > "$dir/authorization.yaml" <<'EOF'
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
- type: Node
  name: node
- type: RBAC
  name: rbac
- type: Webhook
  name: auth-operator
  webhook:
    authorizedTTL: 0s
    unauthorizedTTL: 0s
    cacheAuthorizedRequests: false
    cacheUnauthorizedRequests: false
    timeout: 3s
    subjectAccessReviewVersion: v1
    matchConditionSubjectAccessReviewVersion: v1
    failurePolicy: NoOpinion
    connectionInfo:
      type: KubeConfigFile
      kubeConfigFile: /etc/kubernetes/chain-e2e/webhook.kubeconfig
EOF
cat > "$dir/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: $dir
    containerPath: /etc/kubernetes/chain-e2e
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraVolumes:
      - name: chain-e2e
        hostPath: /etc/kubernetes/chain-e2e
        mountPath: /etc/kubernetes/chain-e2e
        readOnly: true
        pathType: Directory
EOF
kind create cluster --name "$name" --config "$dir/kind.yaml" --image "$node_image" --wait 5m
cluster_created=true
kubectl config use-context "kind-$name"
docker buildx build --load -t "$image" .
kind load docker-image "$image" --name "$name"

kubectl create namespace "$release"
kubectl -n "$release" create secret generic "$release-authorize-token" --from-literal="token=$token"
helm upgrade --install "$release" chart/auth-operator -n "$release" \
  --set image.repository="${image%:*}" --set image.tag="${image##*:}" \
  --set image.pullPolicy=Never --set controller.replicas=1 \
  "${chart_args[@]}" \
  --set webhookServer.bindDefinitionNamespaceSelectorLabelGroups[0]=example.com \
  --set webhookServer.authorizeAuth.tokenSecretName="$release-authorize-token" \
  --wait --timeout 5m

if [[ "$provided_ca" != true ]]; then
  ca="$(kubectl -n "$release" get secret "$release-webhook-certs" -o jsonpath='{.data.ca\.crt}')"
  test -n "$ca"
  printf '%s' "$ca" | base64 -d > "$dir/ca.crt"
fi
ip="$(kubectl -n "$release" get service "$release-webhook-service" -o jsonpath='{.spec.clusterIP}')"
# The node's host-network API server cannot resolve *.svc through cluster DNS.
# Connect to the Service IP but validate the service DNS name against its CA.
cat > "$dir/webhook.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: webhook
  cluster:
    server: https://$ip/authorize
    tls-server-name: $release-webhook-service.$release.svc
    certificate-authority: /etc/kubernetes/chain-e2e/ca.crt
users:
- name: webhook
  user:
    token: $token
contexts:
- name: webhook
  context:
    cluster: webhook
    user: webhook
current-context: webhook
EOF
chmod 600 "$dir/webhook.kubeconfig"
# kubeadm's default flag and --authorization-config cannot coexist. The
# extraVolume was installed by kubeadm; switching this single static-pod flag
# restarts kube-apiserver with the structured authorizer and mounted kubeconfig.
old_container="$(docker exec "$name-control-plane" crictl ps -q --name kube-apiserver | head -1)"
test -n "$old_container"
docker exec "$name-control-plane" sed -i \
  's@--authorization-mode=Node,RBAC@--authorization-config=/etc/kubernetes/chain-e2e/authorization.yaml@' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec "$name-control-plane" grep -q -- '--authorization-config=/etc/kubernetes/chain-e2e/authorization.yaml' \
  /etc/kubernetes/manifests/kube-apiserver.yaml
for ((attempt=0; attempt<60; attempt++)); do
  new_container="$(docker exec "$name-control-plane" crictl ps -q --name kube-apiserver | head -1)"
  if [[ -n "$new_container" && "$new_container" != "$old_container" ]] &&
    kubectl get --raw /readyz >/dev/null 2>&1; then break; fi
  sleep 2
done
kubectl get --raw /readyz >/dev/null
KIND_CLUSTER="$name" IMG="$image" SKIP_CLUSTER_SETUP=true E2E_DEBUG_ON_FAILURE=false E2E_PROVIDED_CA_DIR="$dir" \
  go test -v -tags=e2e ./test/e2e -run '^TestE2E$' -count=1 -timeout=15m \
  -ginkgo.label-filter="$label_filter" -ginkgo.v

<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Operator Guide

This guide covers the installation, configuration, and day-to-day operation
of the auth-operator in production Kubernetes environments.

---

## Table of Contents

- [Installation](#installation)
- [Architecture Overview](#architecture-overview)
- [Configuration](#configuration)
- [High Availability](#high-availability)
- [Monitoring](#monitoring)
- [Security Considerations](#security-considerations)
- [Upgrades](#upgrades)
- [Backup and Recovery](#backup-and-recovery)
- [Understanding ScopeNamespaced](#understanding-scopenamespaced)
- [Common Operations](#common-operations)

---

## Installation

### Prerequisites

- Kubernetes 1.28 or later
- Helm 3.17+ (for Helm installation)
- `kubectl` configured with cluster-admin access

> **Note:** cert-manager is **NOT required**. The operator uses
> [cert-controller](https://github.com/open-policy-agent/cert-controller)
> for automatic TLS certificate management.

### Installation Methods

#### Helm (Recommended)

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --namespace auth-operator-system \
  --create-namespace \
  --version <chart-version>
```

#### Kustomize

```bash
git clone https://github.com/telekom/auth-operator.git
cd auth-operator
make deploy OVERLAY=production
```

### Verify Installation

```bash
# Check pods are running
kubectl get pods -n auth-operator-system

# Verify CRDs are installed
kubectl get crds | grep t-caas.telekom.com

# Check controller logs
kubectl logs -n auth-operator-system -l control-plane=controller-manager -f
```

---

## Architecture Overview

The auth-operator consists of two main components:

| Component | Purpose | Replicas |
|-----------|---------|----------|
| **Controller Manager** | Reconciles RoleDefinitions, BindDefinitions | 1 (HA: 2+) |
| **Webhook Server** | Validates namespace operations | 1 (HA: 2+) |

### Component Interaction

```
┌────────────────────────────────────────────────────────────┐
│                    Kubernetes API Server                    │
└───────────┬──────────────────────────────────┬─────────────┘
            │                                  │
            ▼                                  ▼
┌───────────────────────┐        ┌────────────────────────────┐
│   Controller Manager  │        │     Webhook Server         │
│   ─────────────────   │        │     ───────────────        │
│   • RoleDefinition    │        │   • Namespace validation   │
│   • BindDefinition    │        │   • Label injection        │
│   • API Discovery     │        │   • TDG migration          │
└───────────────────────┘        └────────────────────────────┘
            │                                  │
            ▼                                  ▼
┌────────────────────────────────────────────────────────────┐
│   ClusterRoles, Roles, ClusterRoleBindings, RoleBindings   │
│                     ServiceAccounts                          │
└────────────────────────────────────────────────────────────┘
```

### Reconciliation Intervals

| Resource | Default Interval | Purpose |
|----------|------------------|---------|
| RoleDefinition | 60 seconds | Drift protection, CRD discovery |
| BindDefinition | 60 seconds | Drift protection |
| BindDefinition (missing refs) | 10s → 5min (exponential backoff) | Recovery with reduced API load |

### BindDefinition Annotations

| Annotation | Values | Default | Description |
|-----------|--------|---------|-------------|
| `authorization.t-caas.telekom.com/missing-role-policy` | `warn`, `error`, `ignore` | `warn` | Controls behavior when referenced roles don't exist. `warn`: create bindings, surface warning in status. `error`: block binding creation, set condition False. `ignore`: skip validation entirely, set condition Unknown. |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POD_NAMESPACE` | Operator namespace (used as default for `--namespace` flag) | — |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint (alternative to `--tracing-endpoint` flag) | — |

### CLI Flags (Global)

| Flag | Description | Default |
|------|-------------|---------|
| `--namespace` | Operator namespace | `POD_NAMESPACE` |
| `--health-probe-bind-address` | Health probe address | `:8081` |
| `--metrics-bind-address` | Prometheus metrics address | `:8080` |
| `--metrics-secure` | Require authn/authz for metrics endpoint | `false` |
| `--verbosity` / `-v` | Log level (0-9) | `2` |
| `--tracing-enabled` | Enable OpenTelemetry tracing | `false` |
| `--tracing-endpoint` | OTLP collector endpoint | — |
| `--tracing-sampling-rate` | Trace sampling rate (0.0–1.0) | `0.1` |
| `--tracing-insecure` | Use insecure gRPC for tracing | `false` |

### CLI Flags (controller subcommand)

| Flag | Description | Default |
|------|-------------|---------|
| `--leader-elect` | Enable HA leader election | `true` |
| `--binddefinition-concurrency` | Max concurrent BindDefinition reconciliations | `5` |
| `--roledefinition-concurrency` | Max concurrent RoleDefinition reconciliations | `5` |
| `--webhookauthorizer-concurrency` | Max concurrent WebhookAuthorizer reconciliations | `1` |
| `--cache-sync-timeout` | Timeout for waiting for CRDs to become available | `2m` |
| `--graceful-shutdown-timeout` | Timeout for graceful shutdown of the manager | `30s` |
| `--wait-for-crds` | Wait for required CRDs before starting controllers | `true` |

### CLI Flags (webhook subcommand)

| Flag | Description | Default |
|------|-------------|---------|
| `--port` | Webhook server port | `9443` |
| `--leader-elect` | Enable HA leader election | `false` |
| `--certs-dir` | Directory for HTTPS certificates | — |
| `--disable-cert-rotation` | Disable automatic cert rotation | `false` |
| `--enable-http2` | Enable HTTP/2 on the webhook server | `false` |
| `--cert-rotation-dns-name` | DNS name for the generated TLS certificate | — |
| `--cert-rotation-secret-name` | Secret name for the rotated certificate | — |
| `--cert-rotation-mutating-webhook` | Mutating webhook names to patch with CA bundle | — |
| `--cert-rotation-validating-webhook` | Validating webhook names to patch with CA bundle | — |
| `--tdg-migration` | Enable T-DDI to T-CaaS migration mode | `false` |
| `--authorize-rate-limit` | Per-pod sustained requests/second for authorize endpoint | `100` |
| `--authorize-rate-burst` | Burst size for authorize endpoint rate limiter | `200` |

### Helm Values

Key configuration options in `values.yaml`:

```yaml
# Controller configuration
controller:
  replicas: 1
  resources:
    limits:
      cpu: 500m
      memory: 256Mi
    requests:
      cpu: 10m
      memory: 128Mi
  terminationGracePeriodSeconds: 35
  startupProbe:
    failureThreshold: 30
    periodSeconds: 2
  podDisruptionBudget:
    enabled: false
    minAvailable: 1

# Webhook server configuration
webhookServer:
  replicas: 2
  tdgMigration: "false"  # Enable for T-DDI to T-CaaS migration
  authorizeRateLimit: 100   # Per-pod sustained requests/second
  authorizeRateBurst: 200   # Burst size for rate limiter
  resources:
    limits:
      cpu: 150m
      memory: 256Mi
    requests:
      cpu: 50m
      memory: 128Mi
  terminationGracePeriodSeconds: 35
  startupProbe:
    path: /healthz
    port: 8081
    failureThreshold: 60
    periodSeconds: 2
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            labelSelector:
              matchLabels:
                control-plane: webhook-server
            topologyKey: kubernetes.io/hostname
  podDisruptionBudget:
    enabled: true
    minAvailable: 1

# Metrics and monitoring
metrics:
  auth:
    enabled: false  # Require auth for /metrics endpoint
  service:
    enabled: true
    port: 8080
  serviceMonitor:
    enabled: false
    interval: ""
    additionalLabels: {}
```

---

## High Availability

For production environments, deploy multiple replicas with leader election:

### Helm Configuration

The webhook server defaults to **2 replicas** with pod anti-affinity and PDB
enabled. To also enable HA for the controller:

```bash
helm upgrade auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --namespace auth-operator-system \
  --set controller.replicas=2 \
  --set controller.podDisruptionBudget.enabled=true \
  --set controller.podDisruptionBudget.minAvailable=1
```

### Leader Election

Leader election is **enabled by default** in the Go binary (`--leader-elect=true`).
The Helm chart automatically disables it when `controller.replicas` is 1 (single
replica). For multi-replica deployments, leader election ensures only one
controller actively reconciles resources; standby replicas wait to acquire
leadership if the leader fails.

> **Warning:** If you initially deployed with `--leader-elect=false` (e.g.,
> the Helm chart's single-replica default) and later scale the deployment
> without adding `--leader-elect=true`, multiple controllers can run
> simultaneously, causing conflicting RBAC reconciliations.

**Verify leader election:**

```bash
kubectl get lease -n auth-operator-system auth.t-caas.telekom.com -o yaml
```

### Pod Anti-Affinity

For zone/node distribution, add pod anti-affinity rules:

```yaml
controller:
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 100
          podAffinityTerm:
            labelSelector:
              matchLabels:
                control-plane: controller-manager
            topologyKey: kubernetes.io/hostname
```

---

## Monitoring

### Prometheus Metrics

The operator exposes metrics at `:8080/metrics`. When `metrics.auth.enabled`
is set to `true` in the Helm values, the endpoint requires a valid Kubernetes
bearer token with permission to GET the non-resource URL `/metrics`.

**RBAC prerequisites**: The operator pods use `WithAuthenticationAndAuthorization`
to validate metrics requests via the Kubernetes API. This requires both the
controller-manager and webhook-server ServiceAccounts to have
`system:auth-delegator` permissions for TokenReview and SubjectAccessReview
API calls. The Helm chart creates a `ClusterRoleBinding` to
`system:auth-delegator` for both ServiceAccounts automatically when
`metrics.auth.enabled` is `true`.

To allow Prometheus to scrape metrics, the monitoring ServiceAccount needs
the following RBAC:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: auth-operator-metrics-reader
rules:
  - nonResourceURLs: ["/metrics"]
    verbs: ["get"]
```

Bind this ClusterRole to the Prometheus ServiceAccount:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: auth-operator-metrics-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: auth-operator-metrics-reader
subjects:
  - kind: ServiceAccount
    name: prometheus
    namespace: monitoring
```

Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `auth_operator_reconcile_total` | Counter | Reconciliations by result |
| `auth_operator_reconcile_duration_seconds` | Histogram | Reconciliation latency |
| `auth_operator_reconcile_errors_total` | Counter | Errors by type |
| `auth_operator_rbac_resources_applied_total` | Counter | RBAC resources created/updated |
| `auth_operator_role_refs_missing` | Gauge | Missing role references |
| `auth_operator_namespaces_active` | Gauge | Namespaces matching selectors |

### Enable ServiceMonitor

When `metrics.auth.enabled` is `true`, the metrics endpoint requires
authentication. The ServiceMonitor must include a bearer token for
Prometheus to authenticate. The Helm chart configures bearer token
authentication via the in-pod ServiceAccount token (`bearerTokenFile`)
when `metrics.auth.enabled` is set.

```bash
helm upgrade auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.additionalLabels.release=prometheus
```

### Health Checks

| Endpoint | Port | Purpose |
|----------|------|---------|
| `/healthz` | 8081 | Liveness probe |
| `/readyz` | 8081 | Readiness probe |

See [Metrics and Alerting](metrics-and-alerting.md) for detailed metric
descriptions and alerting rules.

---

## Security Considerations

### RBAC Permissions

The operator requires cluster-admin equivalent permissions to manage RBAC
resources. Review the generated `ClusterRole` in:

```bash
kubectl get clusterrole auth-operator-manager-role -o yaml
```

### Webhook Security

- Webhooks use TLS certificates auto-rotated by cert-controller
- Certificates are stored in a Secret in the operator namespace
- FailurePolicy is set to `Fail` to prevent unauthorized namespace changes

### Network Policies

The Helm chart includes `NetworkPolicy` resources that restrict ingress
traffic to the operator pods. Set `networkPolicy.enabled: true` in your
Helm values to create them.

> **Note:** The generated NetworkPolicy uses the built-in
> `kubernetes.io/metadata.name` namespace label for namespace selectors.
> This label is automatically set by the API server (available since Kubernetes 1.21;
> this operator requires Kubernetes 1.28+).

### Rate Limiting

The `/authorize` webhook endpoint supports token-bucket rate limiting to
protect the API server from excessive authorization requests. Configure it
via Helm values:

```yaml
webhookServer:
  authorizeRateLimit: 100   # sustained requests per second per pod
  authorizeRateBurst: 200   # burst capacity
```

When rate limiting is active and the token bucket is exhausted, the webhook
returns a valid `SubjectAccessReview` response with `Allowed: false` and
reason `"rate limit exceeded"`. The `authorizer_rate_limited_total` Prometheus
metric tracks how often this occurs.

> **HA Note:** The rate limit is **per pod**. In deployments with multiple
> replicas, the effective cluster-wide limit is `replicas × authorizeRateLimit`.

Set `authorizeRateLimit: 0` to disable rate limiting entirely.

> **Upgrade Note:** Rate limiting is **enabled by default** at 100 req/s
> (burst 200). Existing clusters upgrading to this version will start
> enforcing the limit automatically. Set `authorizeRateLimit: 0` to
> restore the previous unlimited behaviour.

**Webhook server** — Only allows ingress on port 9443 (webhook) from all
namespaces (required for kube-apiserver on host network) and port 8081
(health probes).

**Controller manager** — Only allows ingress on port 8080 (metrics) from
the monitoring namespace and port 8081 (health probes).

Configure via `values.yaml`:

```yaml
networkPolicy:
  enabled: true               # Toggle NetworkPolicy creation
  metricsNamespace: monitoring # Namespace allowed to scrape metrics
  webhookServer:
    ingressFrom: []            # Override webhook-server ingress rules
  controllerManager:
    ingressFrom: []            # Override controller-manager ingress rules
```

Network policies are **disabled by default** (`networkPolicy.enabled: false`).
To explicitly disable them after previously enabling:

```bash
helm upgrade auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --set networkPolicy.enabled=false
```

To allow a custom CIDR for the webhook (e.g., restricting to a known
kube-apiserver range):

```yaml
networkPolicy:
  webhookServer:
    ingressFrom:
      - ipBlock:
          cidr: 10.0.0.0/8
```

> **Security note:** The default webhook ingress rule uses `namespaceSelector: {}`
> (all namespaces). When kube-apiserver runs on the host network, its traffic
> typically bypasses NetworkPolicy enforcement altogether (most CNIs do not
> intercept host-network traffic). The broad selector ensures compatibility
> with CNIs that **do** enforce policies on host-network pods. If your network
> plugin supports host-network policies, override `webhookServer.ingressFrom`
> with an `ipBlock` rule scoped to the API server's CIDR instead.

#### Egress Rules

When deploying into a namespace with a default-deny egress policy, enable
egress rules so the operator can reach DNS and the Kubernetes API server:

```yaml
networkPolicy:
  egress:
    enabled: true
    dnsNamespace: kube-system        # Namespace where CoreDNS runs
    apiServerCIDR: "10.96.0.1/32"    # Restrict API server egress by CIDR
    additionalRules: []              # Custom egress rules (e.g., cert-manager)
```

> **Warning:** When `apiServerCIDR` is empty, egress to **any** destination on
> ports 443/6443 is allowed. Always set `apiServerCIDR` to your cluster's
> API server IP for proper isolation.

---

## Upgrades

### Pre-Upgrade Checklist

1. **Backup CRD instances:**
   ```bash
   kubectl get roledefinitions -A -o yaml > roledefinitions-backup.yaml
   kubectl get binddefinitions -A -o yaml > binddefinitions-backup.yaml
   ```

2. **Check release notes** for breaking changes

3. **Test in staging** before production upgrade

### Upgrade Procedure

```bash
# Helm upgrade
helm upgrade auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --namespace auth-operator-system \
  --version <new-version>

# Verify pods rolled out
kubectl rollout status deployment/auth-operator-controller-manager -n auth-operator-system
kubectl rollout status deployment/auth-operator-webhook-server -n auth-operator-system
```

### CRD Updates

CRDs are not updated automatically by Helm. Apply manually if needed:

```bash
kubectl apply -f https://raw.githubusercontent.com/telekom/auth-operator/main/config/crd/bases/authorization.t-caas.telekom.com_roledefinitions.yaml
kubectl apply -f https://raw.githubusercontent.com/telekom/auth-operator/main/config/crd/bases/authorization.t-caas.telekom.com_binddefinitions.yaml
kubectl apply -f https://raw.githubusercontent.com/telekom/auth-operator/main/config/crd/bases/authorization.t-caas.telekom.com_webhookauthorizers.yaml
```

### Rollback

```bash
# List revisions
helm history auth-operator -n auth-operator-system

# Rollback to previous
helm rollback auth-operator <revision> -n auth-operator-system
```

---

## Backup and Recovery

### What to Backup

- **RoleDefinition** resources (defines RBAC generation rules)
- **BindDefinition** resources (defines subject bindings)
- **WebhookAuthorizer** resources (defines authorization rules)

### Backup Script

```bash
#!/bin/bash
BACKUP_DIR="auth-operator-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

kubectl get roledefinitions -A -o yaml > "$BACKUP_DIR/roledefinitions.yaml"
kubectl get binddefinitions -A -o yaml > "$BACKUP_DIR/binddefinitions.yaml"
kubectl get webhookauthorizers -A -o yaml > "$BACKUP_DIR/webhookauthorizers.yaml"

echo "Backup saved to $BACKUP_DIR"
```

### Recovery

If the operator is unavailable, managed RBAC resources persist. To recover:

1. Reinstall the operator
2. Reapply CRD instances (the operator will reconcile)

```bash
kubectl apply -f "$BACKUP_DIR/"
```

---

## Understanding ScopeNamespaced

The `scopeNamespaced` field on RoleDefinition controls which API resources
are included in the generated ClusterRole or Role.

### How It Works

| `scopeNamespaced` | Included Resources | Typical Use |
|-------------------|--------------------|-------------|
| `true` | Only **namespaced** resources (Pods, Services, ConfigMaps, etc.) | Tenant roles — daily workload management |
| `false` | Only **cluster-scoped** resources (Nodes, Namespaces, CRDs, etc.) | Platform admin roles — cluster infrastructure |

You can preview which resources fall into each scope:

```bash
# Namespaced resources (scopeNamespaced: true)
kubectl api-resources --namespaced=true -o wide

# Cluster-scoped resources (scopeNamespaced: false)
kubectl api-resources --namespaced=false -o wide
```

### When to Use Each Setting

**`scopeNamespaced: true`** — Use for tenant developers who need to manage
workloads within their namespaces. The generated role contains permissions for
namespace-scoped resources only (e.g., Pods, Deployments, Services). Combine
with BindDefinition's `namespaceSelector` to restrict which namespaces
the role applies to.

**`scopeNamespaced: false`** — Use for platform administrators who need to
manage cluster-level infrastructure. The generated role contains permissions
for cluster-scoped resources only (e.g., Nodes, PersistentVolumes, CRDs).

### Example: Two-Tier Access

```yaml
# Tier 1: Namespace-scoped workload access
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: tenant-workload
spec:
  targetRole: ClusterRole
  targetName: tenant-workload
  scopeNamespaced: true        # Only namespaced resources
  restrictedApis:
    - name: authorization.t-caas.telekom.com
  restrictedResources:
    - name: secrets             # Restrict sensitive resources
---
# Tier 2: Cluster-scoped read access
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: platform-reader
spec:
  targetRole: ClusterRole
  targetName: platform-reader
  scopeNamespaced: false       # Only cluster-scoped resources
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
```

### Interaction with BindDefinition

When used with a BindDefinition:

- A **cluster-scoped** RoleDefinition (`scopeNamespaced: false`) is typically
  bound via `clusterRoleBindings` — the role applies cluster-wide.
- A **namespace-scoped** RoleDefinition (`scopeNamespaced: true`) is typically
  bound via `roleBindings` with a `namespaceSelector` — the role applies only
  in matching namespaces.

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: tenant-alpha
spec:
  targetName: alpha
  subjects:
    - kind: Group
      name: alpha-developers
      apiGroup: rbac.authorization.k8s.io
  clusterRoleBindings:
    clusterRoleRefs:
      - platform-reader           # Cluster-scoped role → ClusterRoleBinding
  roleBindings:
    - clusterRoleRefs:
        - tenant-workload         # Namespace-scoped role → RoleBindings
      namespaceSelector:
        - matchLabels:
            t-caas.telekom.com/owner: alpha
```

---

## Common Operations

### View Managed Resources

```bash
# List all RoleDefinitions
kubectl get roledefinitions -A

# Check a specific RoleDefinition status
kubectl get roledefinition <name> -o yaml

# List generated ClusterRoles
kubectl get clusterroles -l app.kubernetes.io/managed-by=auth-operator

# List all BindDefinitions
kubectl get binddefinitions -A

# List generated bindings
kubectl get clusterrolebindings,rolebindings -A -l app.kubernetes.io/managed-by=auth-operator
```

### Force Reconciliation

Delete the managed resource's status to trigger immediate reconciliation:

```bash
# For RoleDefinition
kubectl patch roledefinition <name> --type=merge -p '{"status":{"roleReconciled":false}}'

# For BindDefinition
kubectl patch binddefinition <name> --type=merge -p '{"status":{"bindReconciled":false}}'
```

### Scaling Operations

```bash
# Scale controller replicas
kubectl scale deployment auth-operator-controller-manager -n auth-operator-system --replicas=3

# Scale webhook replicas
kubectl scale deployment auth-operator-webhook-server -n auth-operator-system --replicas=3
```

### Emergency Disable

If the operator is causing issues, scale to zero:

```bash
kubectl scale deployment auth-operator-controller-manager -n auth-operator-system --replicas=0
kubectl scale deployment auth-operator-webhook-server -n auth-operator-system --replicas=0
```

> **Warning:** Disabling the webhook server may prevent namespace operations.
> Remove the ValidatingWebhookConfiguration if needed:
> ```bash
> kubectl delete validatingwebhookconfiguration auth-operator-validating-webhook-configuration
> ```

---

## OpenTelemetry Tracing

The operator supports distributed tracing via OpenTelemetry (OTLP/gRPC).

### Configuration

| Flag | Env Variable Fallback | Default | Description |
|------|----------------------|---------|-------------|
| `--tracing-enabled` | — | `false` | Enable OTLP trace export |
| `--tracing-endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` | (required when enabled) | OTLP collector endpoint (e.g. `otel-collector:4317`) |
| `--tracing-insecure` | — | `false` | Disable TLS for OTLP connection (auto-inferred from `http://` scheme) |
| `--tracing-sampling-rate` | — | `0.1` | Sampling rate (0.0–1.0) |

### Helm Values

```yaml
tracing:
  enabled: false
  endpoint: ""
  insecure: false
  samplingRate: 0.1  # 10% of traces; use 1.0 for full tracing
```

### Instrumented Components

| Component | Span Name | Description |
|-----------|-----------|-------------|
| RoleDefinition Reconciler | `reconcile.RoleDefinition` | Full reconciliation cycle |
| WebhookAuthorizer | `webhook.SubjectAccessReview` | SAR evaluation including rule matching |
| WebhookAuthorizer | `webhook.NamespaceMatch` | Namespace selector evaluation |

When tracing is disabled, the Tracer is set to `nil` and all tracing code
paths are skipped entirely — header parsing and span creation have zero
overhead on the hot path.

---

## See Also

- [Debugging Guide](debugging-guide.md) — Troubleshooting and diagnostics
- [Metrics and Alerting](metrics-and-alerting.md) — Metric reference and alerts
- [SSA Architecture](ssa-architecture.md) — Server-Side Apply internals
- [Condition Lifecycle](condition-lifecycle.md) — Status condition reference

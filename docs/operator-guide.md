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
| BindDefinition (missing refs) | 10 seconds | Faster recovery |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NAMESPACE` | Operator namespace | `kube-system` |
| `LEADER_ELECTION` | Enable HA leader election | `true` |
| `PROBE_ADDR` | Health probe address | `:8081` |
| `METRICS_ADDR` | Prometheus metrics address | `:8080` |
| `WEBHOOK_PORT` | Webhook server port | `9443` |

### Helm Values

Key configuration options in `values.yaml`:

```yaml
# Controller configuration
controller:
  replicas: 1
  resources:
    limits:
      cpu: 500m
      memory: 128Mi
    requests:
      cpu: 10m
      memory: 64Mi
  podDisruptionBudget:
    enabled: false
    minAvailable: 1

# Webhook server configuration
webhookServer:
  replicas: 1
  tdgMigration: "false"  # Enable for T-DDI to T-CaaS migration
  resources:
    limits:
      cpu: 150m
      memory: 128Mi
    requests:
      cpu: 50m
      memory: 64Mi
  podDisruptionBudget:
    enabled: false
    minAvailable: 1

# Metrics and monitoring
metrics:
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

```bash
helm upgrade auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --namespace auth-operator-system \
  --set controller.replicas=2 \
  --set controller.podDisruptionBudget.enabled=true \
  --set controller.podDisruptionBudget.minAvailable=1 \
  --set webhookServer.replicas=2 \
  --set webhookServer.podDisruptionBudget.enabled=true \
  --set webhookServer.podDisruptionBudget.minAvailable=1
```

### Leader Election

When `controller.replicas > 1`, leader election is automatically enabled.
Only the leader actively reconciles resources; standby replicas wait to
acquire leadership if the leader fails.

**Verify leader election:**

```bash
kubectl get lease -n auth-operator-system auth-operator-leader-election -o yaml
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

The operator exposes metrics at `:8080/metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `auth_operator_reconcile_total` | Counter | Reconciliations by result |
| `auth_operator_reconcile_duration_seconds` | Histogram | Reconciliation latency |
| `auth_operator_reconcile_errors_total` | Counter | Errors by type |
| `auth_operator_rbac_resources_applied_total` | Counter | RBAC resources created/updated |
| `auth_operator_role_refs_missing` | Gauge | Missing role references |
| `auth_operator_namespaces_active` | Gauge | Namespaces matching selectors |

### Enable ServiceMonitor

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

To disable network policies:

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
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
> (all namespaces). This is required because kube-apiserver typically runs on the
> host network and cannot be matched by namespace labels. Override
> `webhookServer.ingressFrom` with an `ipBlock` rule if your CNI supports
> host-network policies.

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

## See Also

- [Debugging Guide](debugging-guide.md) — Troubleshooting and diagnostics
- [Metrics and Alerting](metrics-and-alerting.md) — Metric reference and alerts
- [SSA Architecture](ssa-architecture.md) — Server-Side Apply internals
- [Condition Lifecycle](condition-lifecycle.md) — Status condition reference

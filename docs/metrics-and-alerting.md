<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Metrics and Alerting

Auth Operator exposes Prometheus metrics at `:8080/metrics` on the controller-manager
pod. This document lists every custom metric, explains what it measures, and
provides recommended alerting rules.

## Enabling Metrics Scraping

### Helm Chart

The Helm chart ships a **metrics Service** (enabled by default) and an optional
**ServiceMonitor** for the Prometheus Operator:

```yaml
# values.yaml
metrics:
  service:
    enabled: true   # Dedicated ClusterIP Service on port 8080
    port: 8080
  serviceMonitor:
    enabled: false   # Set true when Prometheus Operator is installed
    interval: ""     # Uses Prometheus global scrape_interval if empty
    scrapeTimeout: ""
    additionalLabels: {}
```

Enable the ServiceMonitor:

```bash
helm upgrade auth-operator chart/auth-operator \
  --set metrics.serviceMonitor.enabled=true
```

### Kustomize

The `config/prometheus/monitor.yaml` defines a ServiceMonitor. To include it,
add `../../prometheus` to your overlay's `resources:` list:

```yaml
# In config/overlays/dev/kustomization.yaml or config/overlays/production/kustomization.yaml
resources:
- ../../base
- ../../prometheus  # Add this line to enable ServiceMonitor
```

Alternatively, you can add the ServiceMonitor directly to your overlay:

```yaml
# In your overlay's kustomization.yaml
resources:
- ../../base
- ../../prometheus/monitor.yaml
```

---

## Metric Reference

### Reconciliation

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_reconcile_total` | Counter | `controller`, `result` | Total reconciliations. `result` is one of `success`, `error`, `requeue`, `skipped`, `finalized`, `degraded`. |
| `auth_operator_reconcile_duration_seconds` | Histogram | `controller` | Wall-clock duration of each reconciliation. |
| `auth_operator_reconcile_errors_total` | Counter | `controller`, `error_type` | Error count categorised by type: `api`, `validation`, `internal`. |

### RBAC Resource Operations

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_rbac_resources_applied_total` | Counter | `resource_type` | Resources created or updated via SSA. Types: `ClusterRole`, `Role`, `ClusterRoleBinding`, `RoleBinding`, `ServiceAccount`. |
| `auth_operator_rbac_resources_deleted_total` | Counter | `resource_type` | Resources deleted during finalizer cleanup. |
| `auth_operator_managed_resources` | Gauge | `controller`, `resource_type`, `name` | Current number of managed resources per source resource (BindDefinition). Use `sum by (resource_type)(…)` for cluster-wide totals. |

### BindDefinition Health

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_role_refs_missing` | Gauge | `binddefinition` | Number of referenced Roles/ClusterRoles that do not exist. Non-zero triggers a faster 10 s requeue. |
| `auth_operator_namespaces_active` | Gauge | `binddefinition` | Number of active (non-terminating) namespaces matching selectors. |
| `auth_operator_serviceaccount_skipped_preexisting_total` | Counter | `binddefinition` | Pre-existing ServiceAccounts that were intentionally not adopted (no OwnerRef added). |

### API Discovery

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_api_discovery_duration_seconds` | Histogram | — | Duration of API resource discovery operations. |
| `auth_operator_api_discovery_errors_total` | Counter | — | Errors during API resource discovery. |

### Webhook Admission

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `auth_operator_webhook_requests_total` | Counter | `webhook`, `operation`, `result` | Total webhook admission requests. `webhook`: `namespace_validator`, `namespace_mutator`. `operation`: `CREATE`, `UPDATE`, `DELETE`. `result`: `allowed`, `denied`, `errored`. |

---

## Recommended Alert Rules

Below are PromQL expressions for common alerting scenarios. Adapt
thresholds and `for` durations to your environment.

### Reconciliation Errors

```yaml
- alert: AuthOperatorReconcileErrorRate
  expr: |
    (
      rate(auth_operator_reconcile_errors_total[5m])
      / on(controller) rate(auth_operator_reconcile_total[5m])
    ) > 0.1
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Auth-operator {{ $labels.controller }} error rate >10%"
    description: "{{ $value | humanizePercentage }} of reconciliations are failing."
```

### Reconciliation Latency

```yaml
- alert: AuthOperatorReconcileLatencyHigh
  expr: |
    histogram_quantile(0.99,
      rate(auth_operator_reconcile_duration_seconds_bucket[5m])
    ) > 10
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Auth-operator {{ $labels.controller }} p99 latency >10 s"
```

### Missing Role References

```yaml
- alert: AuthOperatorMissingRoleRefs
  expr: auth_operator_role_refs_missing > 0
  for: 15m
  labels:
    severity: warning
  annotations:
    summary: "BindDefinition {{ $labels.binddefinition }} has missing role references"
    description: "{{ $value }} role refs are unresolved for >15 min. Check if the referenced RoleDefinition exists."
```

### No Active Namespaces

```yaml
- alert: AuthOperatorNoActiveNamespaces
  expr: auth_operator_namespaces_active == 0
  for: 30m
  labels:
    severity: info
  annotations:
    summary: "BindDefinition {{ $labels.binddefinition }} matches 0 namespaces"
    description: "Namespace selectors may be misconfigured or all matching namespaces have been deleted."
```

### Webhook Denial Spike

```yaml
- alert: AuthOperatorWebhookDenialSpike
  expr: |
    rate(auth_operator_webhook_requests_total{result="denied"}[5m]) > 1
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Auth-operator {{ $labels.webhook }} is denying >1 req/s"
    description: "Sustained webhook denials may indicate misconfigured BindDefinitions or an attack."
```

### Webhook Errors

```yaml
- alert: AuthOperatorWebhookErrors
  expr: |
    rate(auth_operator_webhook_requests_total{result="errored"}[5m]) > 0
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Auth-operator {{ $labels.webhook }} is returning errors"
    description: "Webhook internal errors can cause namespace operations to fail cluster-wide."
```

### API Discovery Failures

```yaml
- alert: AuthOperatorAPIDiscoveryErrors
  expr: rate(auth_operator_api_discovery_errors_total[5m]) > 0
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Auth-operator API discovery is failing"
    description: "RoleDefinition rules may be stale. Check API server connectivity."
```

### Managed Resource Count Drop

```yaml
- alert: AuthOperatorManagedResourceDrop
  expr: |
    delta(sum by (controller, resource_type)(auth_operator_managed_resources)[10m:]) < -5
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Managed {{ $labels.resource_type }} count dropped significantly"
    description: "A sudden decrease in managed resources may indicate mass deletion or drift."
```

---

## Grafana Dashboard

A basic dashboard can be built from the metrics above. Key panels:

1. **Reconcile rate** — `rate(auth_operator_reconcile_total[5m])` by controller and result
2. **Reconcile duration heatmap** — `auth_operator_reconcile_duration_seconds_bucket`
3. **Error rate** — `rate(auth_operator_reconcile_errors_total[5m])` by error_type
4. **Missing role refs** — `auth_operator_role_refs_missing` table
5. **Active namespaces** — `auth_operator_namespaces_active` table
6. **RBAC operations** — `rate(auth_operator_rbac_resources_applied_total[5m])` stacked by type
7. **Webhook traffic** — `rate(auth_operator_webhook_requests_total[5m])` by result
8. **Pre-existing SA skips** — `rate(auth_operator_serviceaccount_skipped_preexisting_total[5m])`

## Controller-Runtime Built-in Metrics

In addition to the custom metrics above, controller-runtime automatically
exposes standard Go and controller metrics including:

- `controller_runtime_reconcile_total` — built-in reconcile counter
- `controller_runtime_reconcile_time_seconds` — built-in reconcile duration
- `workqueue_depth` — current reconcile queue depth
- `workqueue_adds_total` — total items added to the work queue
- `rest_client_requests_total` — Kubernetes API client request count
- `go_goroutines` — current goroutine count
- `process_resident_memory_bytes` — RSS memory usage

These are available without any additional configuration.

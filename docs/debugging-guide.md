<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Debugging Guide

This guide provides comprehensive troubleshooting procedures for the
auth-operator, including common issues, diagnostic commands, and resolution
steps.

---

## Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Understanding Status Conditions](#understanding-status-conditions)
- [Controller Issues](#controller-issues)
- [Webhook Issues](#webhook-issues)
- [RoleDefinition Troubleshooting](#roledefinition-troubleshooting)
- [BindDefinition Troubleshooting](#binddefinition-troubleshooting)
- [Certificate Issues](#certificate-issues)
- [Performance Issues](#performance-issues)
- [Log Analysis](#log-analysis)
- [Collecting Debug Information](#collecting-debug-information)

---

## Quick Diagnostics

Run these commands first when investigating issues:

```bash
# Check operator pods health
kubectl get pods -n auth-operator-system -o wide

# Check for recent events
kubectl get events -n auth-operator-system --sort-by='.lastTimestamp' | tail -20

# View controller logs (last 100 lines)
kubectl logs -n auth-operator-system -l control-plane=controller-manager --tail=100

# View webhook logs (last 100 lines)
kubectl logs -n auth-operator-system -l app=webhook-server --tail=100

# Check CRD status summary
kubectl get roledefinitions -A -o custom-columns='NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,REASON:.status.conditions[?(@.type=="Ready")].reason'
kubectl get binddefinitions -A -o custom-columns='NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,REASON:.status.conditions[?(@.type=="Ready")].reason'
```

---

## Understanding Status Conditions

Each CRD resource has status conditions indicating its health state.

### Ready Condition

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `Reconciled` | Resource fully reconciled |
| `False` | `Reconciling` | Reconciliation in progress |
| `False` | `Failed` | Error prevented reconciliation |

### Stalled Condition (Abnormal-True)

| Status | Reason | Meaning |
|--------|--------|---------|
| `True` | `Error` | Persistent error occurred |
| `True` | `MissingDependency` | Required dependency missing |

### Check Conditions

```bash
# Detailed condition view
kubectl get roledefinition <name> -o jsonpath='{.status.conditions}' | jq .

# Find stalled resources
kubectl get roledefinitions -A -o json | \
  jq '.items[] | select(.status.conditions[]? | select(.type=="Stalled" and .status=="True")) | .metadata.name'

kubectl get binddefinitions -A -o json | \
  jq '.items[] | select(.status.conditions[]? | select(.type=="Stalled" and .status=="True")) | .metadata.name'
```

---

## Controller Issues

### Controller Not Starting

**Symptoms:**
- Pod in CrashLoopBackOff or Error state
- Repeated restarts

**Diagnostics:**

```bash
# Check pod status
kubectl describe pod -n auth-operator-system -l control-plane=controller-manager

# Check previous logs (if restarted)
kubectl logs -n auth-operator-system -l control-plane=controller-manager --previous

# Check resource constraints
kubectl top pod -n auth-operator-system
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| OOMKilled | Increase memory limits |
| Missing RBAC | Verify ClusterRole permissions |
| Invalid config | Check environment variables |
| CRD not installed | Apply CRDs: `make deploy-crds` |

### Controller Not Reconciling

**Symptoms:**
- Resources not being created/updated
- Status not changing

**Diagnostics:**

```bash
# Check if controller is leader (HA mode)
kubectl get lease -n auth-operator-system auth-operator-leader-election -o yaml

# Check work queue metrics
curl -s http://localhost:8080/metrics | grep workqueue

# Enable verbose logging temporarily
kubectl set env deployment/auth-operator-controller-manager -n auth-operator-system LOG_LEVEL=debug
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| Not leader | Wait for election or check other replica |
| Rate limited | Check API server audit logs |
| Watch disconnected | Restart controller pod |

---

## Webhook Issues

### Namespace Operations Failing

**Symptoms:**
- `Error from server (InternalError)` on namespace create/update
- Namespace stuck in Terminating

**Diagnostics:**

```bash
# Check webhook configuration
kubectl get validatingwebhookconfiguration auth-operator-validating-webhook-configuration -o yaml

# Check webhook service
kubectl get svc -n auth-operator-system auth-operator-webhook-service

# Test webhook connectivity
kubectl run test-curl --image=curlimages/curl --rm -it --restart=Never -- \
  curl -k https://auth-operator-webhook-service.auth-operator-system.svc:443/healthz

# Check webhook pod logs
kubectl logs -n auth-operator-system -l app=webhook-server --tail=100
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| Webhook pod not ready | Check pod status and logs |
| Certificate expired | Restart webhook pod (auto-rotates) |
| Network policy blocking | Allow traffic on port 9443 |
| Service not found | Verify service exists |

### Emergency Webhook Disable

If the webhook is blocking all namespace operations:

```bash
# Option 1: Scale down webhook
kubectl scale deployment auth-operator-webhook-server -n auth-operator-system --replicas=0

# Option 2: Remove webhook configuration (allows all operations)
kubectl delete validatingwebhookconfiguration auth-operator-validating-webhook-configuration

# Re-enable after fix
kubectl scale deployment auth-operator-webhook-server -n auth-operator-system --replicas=1
```

---

## RoleDefinition Troubleshooting

### ClusterRole Not Created

**Symptoms:**
- RoleDefinition shows `Ready=False`
- Target ClusterRole doesn't exist

**Diagnostics:**

```bash
# Check RoleDefinition status
kubectl get roledefinition <name> -o yaml

# Look for error conditions
kubectl get roledefinition <name> -o jsonpath='{.status.conditions[?(@.type=="Stalled")]}' | jq .

# Check controller logs for this resource
kubectl logs -n auth-operator-system -l control-plane=controller-manager | grep <name>
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| Invalid targetName | Must be valid DNS name, 5-63 chars |
| API discovery failed | Check API server connectivity |
| SSA conflict | Check `kubectl get clusterrole <name> -o json \| jq '.metadata.managedFields'` |

### ClusterRole Has Wrong Permissions

**Symptoms:**
- Generated ClusterRole missing expected permissions
- Too many or too few rules

**Diagnostics:**

```bash
# Compare spec vs generated role
kubectl get roledefinition <name> -o yaml
kubectl get clusterrole <target-name> -o yaml

# Check API discovery
kubectl api-resources --verbs=list -o wide

# Verify restricted APIs are being filtered
kubectl get roledefinition <name> -o jsonpath='{.spec.restrictedApis}' | jq .
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| New CRD not discovered | Wait for 60s reconciliation cycle |
| restrictedApis typo | Verify API group names exactly match |
| scopeNamespaced wrong | Check `kubectl api-resources --namespaced=true/false` |

---

## BindDefinition Troubleshooting

### Bindings Not Created

**Symptoms:**
- BindDefinition shows `Ready=False`
- No ClusterRoleBindings or RoleBindings exist

**Diagnostics:**

```bash
# Check BindDefinition status
kubectl get binddefinition <name> -o yaml

# Check RoleRefsValid condition
kubectl get binddefinition <name> -o jsonpath='{.status.conditions[?(@.type=="RoleRefsValid")]}' | jq .

# List managed bindings
kubectl get clusterrolebindings,rolebindings -A -l app.kubernetes.io/managed-by=auth-operator
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| Referenced role doesn't exist | Create the ClusterRole/Role first |
| Invalid subject | Verify subject kind, name, namespace |
| Namespace selector matches nothing | Check label selectors |

### Missing Role References

**Symptoms:**
- `RoleRefsValid=False` condition
- Warning events about missing roles
- Faster requeue (10s instead of 60s)

**Diagnostics:**

```bash
# Find missing roles
kubectl get binddefinition <name> -o jsonpath='{.status.conditions[?(@.type=="RoleRefsValid")].message}'

# Check if role exists
kubectl get clusterrole <role-name>
kubectl get role <role-name> -n <namespace>

# Check metrics
curl -s http://localhost:8080/metrics | grep auth_operator_role_refs_missing
```

**Resolution:**

1. Create the missing role (e.g., via RoleDefinition)
2. Or remove the reference from the BindDefinition

### Namespace Selector Issues

**Symptoms:**
- RoleBindings not created in expected namespaces
- Bindings exist in wrong namespaces

**Diagnostics:**

```bash
# Check which namespaces match
kubectl get namespaces -l <your-label-selector>

# Check active namespaces metric
curl -s http://localhost:8080/metrics | grep auth_operator_namespaces_active

# Verify namespace labels
kubectl get namespace <ns> --show-labels
```

---

## Certificate Issues

### TLS Certificate Errors

**Symptoms:**
- Webhook returning `x509: certificate` errors
- `connection refused` to webhook

**Diagnostics:**

```bash
# Check cert-controller rotation
kubectl logs -n auth-operator-system -l app=webhook-server | grep -i cert

# Verify certificate secret exists
kubectl get secret -n auth-operator-system auth-operator-webhook-server-cert

# Check certificate expiry
kubectl get secret -n auth-operator-system auth-operator-webhook-server-cert -o jsonpath='{.data.tls\.crt}' | \
  base64 -d | openssl x509 -noout -dates

# Verify CA bundle in webhook config
kubectl get validatingwebhookconfiguration auth-operator-validating-webhook-configuration \
  -o jsonpath='{.webhooks[0].clientConfig.caBundle}' | base64 -d | openssl x509 -noout -text
```

**Resolution:**

Most certificate issues resolve by restarting the webhook pod:

```bash
kubectl rollout restart deployment/auth-operator-webhook-server -n auth-operator-system
```

---

## Performance Issues

### High Reconciliation Latency

**Symptoms:**
- Slow status updates
- High `auth_operator_reconcile_duration_seconds` metric

**Diagnostics:**

```bash
# Check reconciliation duration
curl -s http://localhost:8080/metrics | grep auth_operator_reconcile_duration

# Check API server latency
curl -s http://localhost:8080/metrics | grep rest_client_request_duration

# Check work queue depth
curl -s http://localhost:8080/metrics | grep workqueue_depth

# Monitor resource usage
kubectl top pod -n auth-operator-system
```

**Common Causes:**

| Issue | Solution |
|-------|----------|
| Too many namespaces matching selector | Narrow namespace selectors |
| API server throttling | Check API server audit logs |
| CPU/memory limits too low | Increase resource limits |
| Large number of CRDs | Expected; discovery takes time |

### High API Server Load

**Symptoms:**
- API server CPU high
- Throttling errors in controller logs

**Diagnostics:**

```bash
# Check API request rate
curl -s http://localhost:8080/metrics | grep rest_client_requests_total

# Look for throttling
kubectl logs -n auth-operator-system -l control-plane=controller-manager | grep -i throttl
```

**Tuning:**

The operator uses Server-Side Apply which minimizes unnecessary writes.
If load is still high, consider reducing the number of RoleDefinitions
or BindDefinitions.

---

## Log Analysis

### Enable Debug Logging

```bash
# Temporarily increase log verbosity
kubectl set env deployment/auth-operator-controller-manager \
  -n auth-operator-system \
  -- -zap-log-level=debug

# Revert to normal logging
kubectl set env deployment/auth-operator-controller-manager \
  -n auth-operator-system \
  -- -zap-log-level=info
```

### Common Log Patterns

| Pattern | Meaning |
|---------|---------|
| `Starting reconciliation` | Normal reconcile cycle |
| `Reconciliation complete` | Successful reconcile |
| `Requeuing after error` | Transient error, will retry |
| `SSA apply failed` | Server-Side Apply conflict |
| `API discovery failed` | Cannot reach API server |
| `Role ref not found` | Referenced role doesn't exist |
| `Finalizer added` | Resource acquired finalizer |
| `Cleanup complete` | Deletion finalizer finished |

### Structured Log Query

```bash
# Find errors
kubectl logs -n auth-operator-system -l control-plane=controller-manager | \
  grep '"level":"error"'

# Find specific resource
kubectl logs -n auth-operator-system -l control-plane=controller-manager | \
  grep '"name":"my-roledefinition"'

# Find reconciliation times
kubectl logs -n auth-operator-system -l control-plane=controller-manager | \
  grep 'Reconciliation complete' | jq -r '.duration'
```

---

## Collecting Debug Information

### Debug Bundle Script

Save this script as `collect-debug.sh`:

```bash
#!/bin/bash
set -e

NAMESPACE=${NAMESPACE:-auth-operator-system}
OUTPUT_DIR="auth-operator-debug-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "Collecting debug information to $OUTPUT_DIR..."

# Cluster info
kubectl cluster-info > "$OUTPUT_DIR/cluster-info.txt" 2>&1
kubectl version > "$OUTPUT_DIR/k8s-version.txt" 2>&1

# Operator resources
kubectl get all -n "$NAMESPACE" -o wide > "$OUTPUT_DIR/operator-resources.txt" 2>&1
kubectl describe pods -n "$NAMESPACE" > "$OUTPUT_DIR/pod-describe.txt" 2>&1

# Logs
kubectl logs -n "$NAMESPACE" -l control-plane=controller-manager --tail=1000 > "$OUTPUT_DIR/controller-logs.txt" 2>&1 || true
kubectl logs -n "$NAMESPACE" -l app=webhook-server --tail=1000 > "$OUTPUT_DIR/webhook-logs.txt" 2>&1 || true

# CRD status
kubectl get roledefinitions -A -o yaml > "$OUTPUT_DIR/roledefinitions.yaml" 2>&1 || true
kubectl get binddefinitions -A -o yaml > "$OUTPUT_DIR/binddefinitions.yaml" 2>&1 || true
kubectl get webhookauthorizers -A -o yaml > "$OUTPUT_DIR/webhookauthorizers.yaml" 2>&1 || true

# Events
kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' > "$OUTPUT_DIR/events.txt" 2>&1

# Managed resources
kubectl get clusterroles -l app.kubernetes.io/managed-by=auth-operator -o yaml > "$OUTPUT_DIR/managed-clusterroles.yaml" 2>&1 || true
kubectl get clusterrolebindings -l app.kubernetes.io/managed-by=auth-operator -o yaml > "$OUTPUT_DIR/managed-clusterrolebindings.yaml" 2>&1 || true
kubectl get rolebindings -A -l app.kubernetes.io/managed-by=auth-operator -o yaml > "$OUTPUT_DIR/managed-rolebindings.yaml" 2>&1 || true

# Webhook config
kubectl get validatingwebhookconfiguration auth-operator-validating-webhook-configuration -o yaml > "$OUTPUT_DIR/webhook-config.yaml" 2>&1 || true

echo "Debug information collected in $OUTPUT_DIR"
tar -czf "${OUTPUT_DIR}.tar.gz" "$OUTPUT_DIR"
echo "Archive created: ${OUTPUT_DIR}.tar.gz"
```

### Using the Script

```bash
chmod +x collect-debug.sh
./collect-debug.sh

# With custom namespace
NAMESPACE=my-namespace ./collect-debug.sh
```

---

## See Also

- [Operator Guide](operator-guide.md) — Installation and configuration
- [Metrics and Alerting](metrics-and-alerting.md) — Metric reference
- [Condition Lifecycle](condition-lifecycle.md) — Status condition details
- [SSA Architecture](ssa-architecture.md) — Server-Side Apply internals
- [E2E Testing Guide](../test/e2e/README.md) — Test suite debugging

<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Integration with k8s-breakglass

This document describes how auth-operator integrates with
[k8s-breakglass](https://github.com/telekom/k8s-breakglass), the temporary
privilege escalation system for Kubernetes.

---

## Overview

The T-CaaS platform uses two complementary authorization systems:

| Component | Purpose | Scope |
|-----------|---------|-------|
| **auth-operator** | Permanent RBAC management | Static roles and bindings |
| **k8s-breakglass** | Temporary privilege escalation | Time-bounded elevated access |

Together, they provide a complete authorization solution:

```
                    ┌─────────────────────────────────────────────────┐
                    │           Kubernetes API Server                 │
                    │  ┌─────────────────────────────────────────┐   │
                    │  │  AuthorizationConfiguration              │   │
                    │  │  1. Node authorizer                      │   │
                    │  │  2. RBAC ← auth-operator manages         │   │
                    │  │  3. Webhook ← k8s-breakglass extends     │   │
                    │  └─────────────────────────────────────────┘   │
                    └─────────────────────────────────────────────────┘
                                          │
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
              ▼                           ▼                           ▼
    ┌───────────────────┐     ┌───────────────────┐     ┌───────────────────┐
    │   auth-operator   │     │  k8s-breakglass   │     │   Native RBAC     │
    │   ─────────────   │     │  ───────────────  │     │   ───────────     │
    │  • RoleDefinition │     │  • BreakglassEsc. │     │  • Manual CRBs    │
    │  • BindDefinition │     │  • BreakglassSess │     │  • Manual RBs     │
    │  • Deny-list gen. │     │  • DenyPolicy     │     │                   │
    └───────────────────┘     └───────────────────┘     └───────────────────┘
              │                           │
              │    ClusterRoles           │    Authorization Decisions
              │    ClusterRoleBindings    │    (via webhook)
              │    RoleBindings           │
              ▼                           ▼
    ┌─────────────────────────────────────────────────────────────────────┐
    │                      Kubernetes RBAC Objects                         │
    │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
    │  │ ClusterRoles │  │    Roles     │  │ ClusterRoleBindings/RBs │  │
    │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
    └─────────────────────────────────────────────────────────────────────┘
```

---

## How They Work Together

### Authorization Chain

1. **RBAC (auth-operator)** — User's request is first evaluated against static
   RBAC rules managed by auth-operator
2. **Breakglass Webhook** — If RBAC denies the request, the breakglass webhook
   is consulted to check for active escalation sessions
3. **DenyPolicy** — Breakglass evaluates deny policies before granting access

### Role Generation Flow

```
┌─────────────────────────────────┐
│        RoleDefinition           │  auth-operator creates base roles
│  ┌───────────────────────────┐  │
│  │ spec:                     │  │
│  │   targetRole: ClusterRole │  │
│  │   targetName: tenant-dev  │  │
│  │   restrictedApis: [...]   │  │
│  └───────────────────────────┘  │
└────────────────┬────────────────┘
                 │ generates
                 ▼
┌─────────────────────────────────┐
│      ClusterRole: tenant-dev    │  Static RBAC for daily operations
└────────────────┬────────────────┘
                 │ referenced by
                 ▼
┌─────────────────────────────────┐
│      BreakglassEscalation       │  Breakglass allows escalation TO this role
│  ┌───────────────────────────┐  │
│  │ spec:                     │  │
│  │   escalatedGroup:         │  │
│  │     "tenant-admin"        │──┼──▶ Can escalate to higher-privilege role
│  │   allowed:                │  │
│  │     clusters: ["prod-*"]  │  │
│  │     groups: ["developers"]│──┼──▶ Users with tenant-dev can request
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

### Typical Workflow

1. **auth-operator** generates `tenant-developer` ClusterRole via RoleDefinition
2. **auth-operator** binds developers group to `tenant-developer` via BindDefinition
3. Developer has normal daily access via static RBAC
4. For incident response, developer requests escalation via **k8s-breakglass**
5. Approver reviews and approves the BreakglassSession
6. Breakglass webhook grants temporary `cluster-admin` access
7. Session expires automatically after configured duration

---

## Integration Points

### Shared Group Names

Both systems should use consistent group naming. The T-CaaS group naming
convention applies to both:

| Group Pattern | Example | Used By |
|---------------|---------|---------|
| `{participant}-{scope}-{role}` | `tenant-cluster-admin` | BindDefinition subjects |
| Same pattern | `tenant-cluster-admin` | BreakglassEscalation.spec.escalatedGroup |

### Shared ClusterRole References

auth-operator generates ClusterRoles that breakglass can reference:

```yaml
# auth-operator generates this via RoleDefinition
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-poweruser
  labels:
    app.kubernetes.io/managed-by: auth-operator
rules:
  # ... generated rules ...
```

```yaml
# k8s-breakglass references it
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: tenant-emergency
spec:
  escalatedGroup: "tenant-poweruser"  # References auth-operator managed role
  allowed:
    groups: ["tenant-developers"]     # Users bound via BindDefinition
  # ...
```

### OIDC/IDP Integration

Both systems integrate with the same identity providers:

- auth-operator's BindDefinition binds groups from OIDC claims
- k8s-breakglass validates users against IdentityProvider CRs

The `oidcPrefixes` configuration in breakglass should match the group names
used in BindDefinition subjects.

### Namespace Labels

Both systems use namespace labels for scoping:

- auth-operator uses `namespaceSelector` in BindDefinition for role binding
- k8s-breakglass uses `namespaceSelector` in DenyPolicy for access restrictions

Ensure consistent label schemas:

```yaml
# Namespace labels used by both systems
metadata:
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: my-tenant
    t-caas.telekom.com/environment: production
```

---

## Deployment Considerations

### Installation Order

1. Install **auth-operator** first to establish base RBAC
2. Install **k8s-breakglass** second with authorization webhook

### Webhook Authorization Chain

Configure the cluster's `AuthorizationConfiguration` with proper ordering:

```yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Node
    name: node
  - type: RBAC          # auth-operator's generated rules evaluated here
    name: rbac
  - type: Webhook       # k8s-breakglass consulted AFTER RBAC denies
    name: breakglass
    webhook:
      timeout: 3s
      failurePolicy: NoOpinion
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
```

### High Availability

Both systems support HA deployment:

| Component | HA Configuration |
|-----------|------------------|
| auth-operator | `controller.replicas=2`, leader election |
| k8s-breakglass | Multiple backend replicas, shared state via CRDs |

---

## Configuration Examples

### T-CaaS Platform Roles

auth-operator generates the base roles:

```yaml
# RoleDefinition for tenant base access
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: tenant-developer
spec:
  targetRole: ClusterRole
  targetName: tenant-developer
  scopeNamespaced: true
  restrictedApis:
    - name: authorization.t-caas.telekom.com
    - name: breakglass.t-caas.telekom.com  # Prevent self-escalation
  restrictedResources:
    - name: secrets
    - name: nodes
```

Breakglass allows emergency escalation:

```yaml
# BreakglassEscalation for emergency access
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: tenant-emergency-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["prod-*"]
    groups: ["tenant-developers"]  # Same group as BindDefinition
  approvers:
    groups: ["security-team", "platform-oncall"]
  maxValidFor: "1h"
  requestReason:
    mandatory: true
    description: "Incident ticket number required"
```

### Binding with Breakglass Fallback

```yaml
# BindDefinition for normal operations
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: tenant-developers
spec:
  targetName: tenant
  subjects:
    - kind: Group
      name: developers@example.com
      apiGroup: rbac.authorization.k8s.io
  clusterRoleBindings:
    clusterRoleRefs:
      - tenant-developer  # Static access
  roleBindings:
    - clusterRoleRefs:
        - edit
      namespaceSelector:
        - matchLabels:
            t-caas.telekom.com/owner: tenant
```

When developers need elevated access, they request via breakglass UI/CLI.

---

## Metrics and Monitoring

### Combined Dashboard

Monitor both systems together for complete visibility:

| Metric | Source | Purpose |
|--------|--------|---------|
| `auth_operator_reconcile_total` | auth-operator | RBAC generation health |
| `auth_operator_role_refs_missing` | auth-operator | Missing role references |
| `breakglass_sessions_total` | k8s-breakglass | Escalation usage |
| `breakglass_webhook_requests_total` | k8s-breakglass | Authorization decisions |

### Alert Correlation

Configure alerts that consider both systems:

```yaml
# Alert if static RBAC fails AND breakglass sessions spike
- alert: PotentialAccessIssue
  expr: |
    (auth_operator_reconcile_errors_total > 0)
    AND
    (rate(breakglass_sessions_total{state="Pending"}[10m]) > 0.5)
  annotations:
    summary: "RBAC generation issues with elevated breakglass requests"
```

---

## Troubleshooting

### User Can't Access Expected Resources

1. Check auth-operator BindDefinition status:
   ```bash
   kubectl get binddefinition <name> -o yaml
   ```

2. Verify generated bindings:
   ```bash
   kubectl get clusterrolebindings,rolebindings -l app.kubernetes.io/managed-by=auth-operator
   ```

3. If user needs emergency access, check breakglass:
   ```bash
   bgctl sessions list --user <user>
   ```

### Breakglass Session Approved But Access Denied

1. Ensure the `escalatedGroup` has RBAC bindings:
   ```bash
   kubectl get clusterrolebinding -o wide | grep <escalatedGroup>
   ```

2. Check if auth-operator manages the referenced ClusterRole:
   ```bash
   kubectl get clusterrole <role> -o yaml | grep managed-by
   ```

3. Verify DenyPolicy isn't blocking:
   ```bash
   kubectl get denypolicy -A
   ```

---

## Related Documentation

### auth-operator
- [Operator Guide](operator-guide.md)
- [Debugging Guide](debugging-guide.md)
- [T-CaaS Integration](t-caas-integration.md)

### k8s-breakglass
- [Quick Start](https://github.com/telekom/k8s-breakglass/blob/main/docs/quickstart.md)
- [BreakglassEscalation](https://github.com/telekom/k8s-breakglass/blob/main/docs/breakglass-escalation.md)
- [Webhook Setup](https://github.com/telekom/k8s-breakglass/blob/main/docs/webhook-setup.md)

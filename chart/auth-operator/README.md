# Auth Operator Helm Chart

A Kubernetes operator for managing RBAC with RoleDefinitions, BindDefinitions, WebhookAuthorizers, RBACPolicies, RestrictedRoleDefinitions, and RestrictedBindDefinitions.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.17+

> **Note:** cert-manager is **NOT required**. The auth-operator uses [cert-controller](https://github.com/open-policy-agent/cert-controller) to self-sign and automatically rotate TLS certificates.

## Installation

### From OCI Registry (Recommended)

Using image digest (preferred for production - immutable reference):

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --version <chart-version> \
  --namespace auth-operator-system \
  --create-namespace \
  --set image.digest=sha256:<digest>  # Use actual digest from release
```

Using image tag:

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --version <chart-version> \
  --namespace auth-operator-system \
  --create-namespace \
  --set image.tag=<image-tag>  # Optional: defaults to Chart.AppVersion if omitted
```

> **Note:** If both `image.digest` and `image.tag` are set, digest takes precedence. If neither is set, defaults to `Chart.AppVersion`.

### From Source

```bash
# Clone the repository
git clone https://github.com/telekom/auth-operator.git
cd auth-operator

# Install the chart
helm install auth-operator ./chart/auth-operator \
  --namespace auth-operator-system \
  --create-namespace \
  --set image.tag=<image-tag>  # Optional: defaults to Chart.AppVersion if omitted
```

## Configuration

### Image Configuration

Image reference precedence: `digest` > `tag` > `Chart.AppVersion`

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Container image repository | `ghcr.io/telekom/auth-operator` |
| `image.digest` | Container image digest, immutable reference (highest precedence) | `""` |
| `image.tag` | Container image tag (if digest not set, falls back to Chart.AppVersion if empty) | `""` |
| `imagePullSecrets` | Image pull secrets | `[]` |

### Controller Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `controller.replicas` | Number of controller replicas | `1` |
| `controller.resources.limits.cpu` | CPU limit | `500m` |
| `controller.resources.limits.memory` | Memory limit | `256Mi` |
| `controller.resources.requests.cpu` | CPU request | `10m` |
| `controller.resources.requests.memory` | Memory request | `128Mi` |
| `controller.terminationGracePeriodSeconds` | Seconds to wait for graceful shutdown | `35` |
| `controller.startupProbe.failureThreshold` | Startup probe consecutive failures before restart | `30` |
| `controller.startupProbe.periodSeconds` | How often to perform the startup probe | `2` |
| `controller.podDisruptionBudget.enabled` | Enable PDB | `false` |
| `controller.podDisruptionBudget.minAvailable` | Minimum available pods. Omit when using `maxUnavailable`. | `1` |
| `controller.podDisruptionBudget.maxUnavailable` | Maximum unavailable pods. Mutually exclusive with `minAvailable`. | `""` |
| `controller.bindDefinitionConcurrency` | Max concurrent BindDefinition reconciliations | `10` |
| `controller.roleDefinitionConcurrency` | Max concurrent RoleDefinition reconciliations | `10` |
| `controller.webhookAuthorizerConcurrency` | Max concurrent WebhookAuthorizer reconciliations | `1` |
| `controller.rbacPolicyConcurrency` | Max concurrent RBACPolicy reconciliations (0 to disable) | `5` |
| `controller.restrictedBindDefinitionConcurrency` | Max concurrent RestrictedBindDefinition reconciliations (0 to disable) | `5` |
| `controller.restrictedRoleDefinitionConcurrency` | Max concurrent RestrictedRoleDefinition reconciliations (0 to disable) | `5` |
| `controller.impersonation.enabled` | Create ServiceAccount impersonation RBAC grants for RBACPolicy apply operations | `false` |
| `controller.impersonation.clusterWide` | Grant serviceaccounts/impersonate cluster-wide when impersonation is enabled | `false` |
| `controller.impersonation.serviceAccounts` | Namespaced ServiceAccounts the controller may impersonate when clusterWide is false | `[]` |

### Webhook Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhookServer.replicas` | Number of webhook server replicas | `2` |
| `webhookServer.tdgMigration` | Enable TDG migration mode | `"false"` |
| `webhookServer.capiOperatorUpdateBypass` | Allow capi-operator-manager to skip BindDefinition authorization for Namespace UPDATE requests; protected-label validation still runs | `"false"` |
| `webhookServer.bindDefinitionNamespaceSelectorLabelGroups` | DNS label key domains allowed in BindDefinition namespace selectors | `[t-caas.telekom.com]` |
| `webhookServer.authorizeRateLimit` | Max sustained requests/sec for /authorize endpoint (per pod, 0 to disable; requires caller auth when >0) | `0` |
| `webhookServer.authorizeRateBurst` | Max burst size for /authorize rate limiter | `200` |
| `webhookServer.allowUnauthenticatedAuthorize` | Explicit insecure opt-out for unauthenticated /authorize callers when no token Secret is configured | `false` |
| `webhookServer.authorizeAuth.tokenSecretName` | Existing Secret with bearer token for /authorize caller authentication | `""` |
| `webhookServer.authorizeAuth.tokenSecretKey` | Secret key containing the /authorize bearer token | `token` |
| `webhookServer.resources.limits.cpu` | CPU limit | `150m` |
| `webhookServer.resources.limits.memory` | Memory limit | `256Mi` |
| `webhookServer.resources.requests.cpu` | CPU request | `50m` |
| `webhookServer.resources.requests.memory` | Memory request | `128Mi` |
| `webhookServer.terminationGracePeriodSeconds` | Seconds to wait for graceful shutdown | `35` |
| `webhookServer.startupProbe.path` | HTTP endpoint for the startup probe | `/healthz` |
| `webhookServer.startupProbe.port` | Port for the startup probe | `8081` |
| `webhookServer.startupProbe.failureThreshold` | Startup probe consecutive failures before restart | `60` |
| `webhookServer.startupProbe.periodSeconds` | How often to perform the startup probe | `2` |
| `webhookServer.affinity` | Pod affinity rules (overrides global `affinity`) | Pod anti-affinity across nodes |
| `webhookServer.service.port` | Service port | `443` |
| `webhookServer.podDisruptionBudget.enabled` | Enable PDB | `true` |
| `webhookServer.podDisruptionBudget.minAvailable` | Minimum available pods. Omit when using `maxUnavailable`. | `1` |
| `webhookServer.podDisruptionBudget.maxUnavailable` | Maximum unavailable pods. Mutually exclusive with `minAvailable`. | `""` |

By default, `/authorize` rejects callers unless
`webhookServer.authorizeAuth.tokenSecretName` is configured. Existing local or
development installs that intentionally need unauthenticated callers can set
`webhookServer.allowUnauthenticatedAuthorize=true` while migrating clients to a
shared bearer token. Keep this opt-out disabled in production.

### Namespace Admission

The cluster-wide namespace mutating and validating webhooks are disabled by
default. Enable them only after the bootstrap `BindDefinition` and
`RBACPolicy` resources that authorize namespace ownership labels are present.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespaceAdmission.enabled` | Install namespace create/update/delete admission webhooks | `false` |

### Namespace Deletion Protection

Protects critical namespaces from accidental deletion. Platform-owned
namespaces (`t-caas.telekom.com/owner=platform`) and namespaces labeled
`t-caas.telekom.com/deletion-protection=enabled` can only be deleted after
annotating them with `t-caas.telekom.com/allow-deletion="true"`; removing
those protection labels requires the same annotation. The system
namespaces `kube-system`, `kube-public`, `kube-node-lease`, and `default` are
never deletable while protection is enabled. There is **no admin bypass** —
even `system:masters` must set the annotation; disabling
`namespaceDeletionProtection.enabled` is the only break-glass for system
namespaces.

Primary enforcement is a `ValidatingAdmissionPolicy` (Kubernetes ≥ 1.30); the
namespace validating webhook (`namespaceAdmission.enabled`) enforces the same
rules as fallback on clusters without VAP support.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespaceDeletionProtection.enabled` | Enable namespace deletion protection (VAP + webhook fallback) | `true` |
| `namespaceDeletionProtection.extraProtectedNamespaces` | Additional namespace names unconditionally protected from deletion | `[]` |
| `namespaceDeletionProtection.vap` | VAP rendering mode: `auto` (render when the cluster supports it), `enabled`, or `disabled`. With `auto`, offline `helm template` needs `--api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy` to render the VAP | `auto` |

### Creator Tracking

Creator tracking is opt-in until performance tests are complete. Set
`creatorTracking.enabled=true` to enable it. Use either the Helm resources or
the standalone examples, never both at the same time.

The policies are cluster-wide and have no namespace selector. They match these
default kinds in every namespace:

| API | Default kinds |
|-----|---------------|
| Core `v1` | `Namespace`, `ServiceAccount`, `Secret` |
| RBAC `v1` | `Role`, `RoleBinding`, `ClusterRole`, `ClusterRoleBinding` |
| Auth operator `v1alpha1` | `RoleDefinition`, `BindDefinition`, `RBACPolicy`, `RestrictedRoleDefinition`, `RestrictedBindDefinition`, `WebhookAuthorizer` |

Tracking values are plain annotations. Anyone who can read an object, including
a Secret, can read its creator identity and creation-time groups.

| Mode | Behavior |
|------|----------|
| `create-only` | Stamp creator username and groups on CREATE. On parent UPDATE, remove a forged `updated-by`; creator values are not restored. |
| `protect` | Stamp on CREATE and restore creator values on parent UPDATE. Remove `updated-by` on parent UPDATE. |
| `contributors` | Protect creator values and record distinct effective usernames on parent UPDATE in first-edit order. The creator appears only after a later UPDATE. |

Only CREATE and parent UPDATE requests are tracked. DELETE and subresources,
including `status`, are not tracked. The annotations do not contain timestamps,
a full change history, or request details. A no-op UPDATE or a controller UPDATE
can add a contributor because it is still an admitted parent UPDATE.

`created-by` contains the literal effective username. Each group or contributor
component escapes `%` as `%25` and then `,` as `%2C` before comma joining. To
decode a list, split on commas, replace `%2C` with `,`, then replace `%25` with
`%` in each component.

These annotations record the effective `request.userInfo` identity seen by the
API server. An authorized impersonator controls that identity; the original
caller is not recorded. The policies use `failurePolicy: Ignore`, preserve old
values, and can skip or remove values at Kubernetes's 262144-byte annotation
limit. The annotations are best-effort operational context, not forensic or
cryptographic proof. Values from an activation or fail-open gap cannot later be
proven authentic.

The policies run in the API server and continue while auth-operator pods are
stopped. Disabling the feature, setting `map: disabled`, rolling back, or
uninstalling removes policy resources but leaves existing annotations. Mode,
resource, and exclusion changes are not retroactive. Re-enabling does not
backfill old objects. Protect mode preserves an old creator value if it exists,
even if that value changed while policies were inactive. Changing from
contributors to protect removes `updated-by` only on the next matching UPDATE.

Remove or disable policies first and verify that their policies and bindings
are gone before cleaning retained annotations. For example:

```bash
kubectl get mutatingadmissionpolicies,mutatingadmissionpolicybindings -o name \
  | grep -E 'creator-tracking|contributor-tracking' || true
```

The command must print nothing before annotation cleanup starts.

This implementation supports Kubernetes 1.34 and newer. Kubernetes 1.32 and
1.33 exposed alpha versions of this upstream feature, but the chart and
standalone examples intentionally support only the beta and stable APIs. With
`map: auto`, the chart emits no policy when a supported API is absent.
`map: enabled` forces stable v1 rendering but does not enable the API or its
feature gate. Kubernetes 1.34 and 1.35 require
`MutatingAdmissionPolicy=true` and
`admissionregistration.k8s.io/v1beta1=true`; the complete Kind example is
`test/e2e/kind-config-creator-tracking-beta.yaml`. Kubernetes 1.36 serves v1,
and the chart prefers v1 when both versions are available. For an upgrade,
keep both endpoints served while Helm upgrades the release through v1. The v1
and v1beta1 endpoints show the same persisted policies and bindings. Verify
them through v1, then stop serving the v1beta1 endpoint.

After installation, verify activation with a disposable Namespace dry-run. The
command must return both creator annotations; it does not create the Namespace.

```bash
kubectl create namespace creator-tracking-check --dry-run=server -o json \
  | jq -e '.metadata.annotations["t-caas.telekom.com/created-by"] and .metadata.annotations["t-caas.telekom.com/created-by-groups"]'
```

Helm-created resources admitted before policy activation remain unstamped. See
`docs/examples/creator-tracking-map.yaml` for standalone protect mode and
`docs/examples/creator-tracking-map-contributors.yaml` for contributor mode.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `creatorTracking.enabled` | Enable creator and contributor tracking | `false` |
| `creatorTracking.mode` | `create-only`, `protect`, or `contributors` | `protect` |
| `creatorTracking.map` | `auto`, `enabled`, or `disabled`. Offline `helm template` with `auto` needs the matching MAP `--api-versions` value | `auto` |
| `creatorTracking.resources` | Resource rules with explicit API groups, versions, and resources | Core, RBAC v1, and auth-operator v1alpha1 resources |
| `creatorTracking.excludedUsernames` | Usernames omitted from new stamps and contributor appends; restoration is still attempted | `[]` |

### Service Account Configuration

The controller and webhook server use separate ServiceAccounts with dedicated
ClusterRoles following the principle of least privilege:

- **`<fullname>-controller-manager`** — RBAC management, API discovery, CRD reconciliation
- **`<fullname>-webhook-server`** — Admission webhook validation, cert-controller TLS rotation

Secrets access (for TLS certificates) is scoped to the operator namespace via
a namespaced Role, not a ClusterRole.

ServiceAccount impersonation for `RBACPolicy` apply operations is opt-in. Prefer
`controller.impersonation.serviceAccounts` for named apply identities; use
`controller.impersonation.clusterWide=true` only when `RBACPolicy` write access
is restricted to platform administrators.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.annotations` | Annotations applied to both ServiceAccounts | `{}` |

### Metrics & Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.auth.enabled` | Require authentication/authorization for `/metrics` and serve metrics over HTTPS. Set to `false` only for trusted opt-out environments that require unauthenticated HTTP metrics. | `true` |
| `metrics.service.enabled` | Create a dedicated metrics Service | `true` |
| `metrics.service.port` | Metrics service port | `8080` |
| `metrics.serviceMonitor.enabled` | Create a Prometheus ServiceMonitor | `false` |
| `metrics.serviceMonitor.interval` | Scrape interval (empty = Prometheus default) | `""` |
| `metrics.serviceMonitor.scrapeTimeout` | Scrape timeout | `""` |
| `metrics.serviceMonitor.additionalLabels` | Extra labels on the ServiceMonitor | `{}` |
| `metrics.serviceMonitor.scraperRBAC.create` | Create ClusterRole/ClusterRoleBinding that permits the Prometheus scraper ServiceAccount to GET `/metrics` when metrics auth is enabled | `false` |
| `metrics.serviceMonitor.scraperRBAC.serviceAccount.name` | Prometheus scraper ServiceAccount name for chart-managed metrics reader RBAC | `""` |
| `metrics.serviceMonitor.scraperRBAC.serviceAccount.namespace` | Prometheus scraper ServiceAccount namespace for chart-managed metrics reader RBAC (defaults to release namespace when empty) | `""` |
| `metrics.serviceMonitor.tlsConfig.caFile` | CA certificate file for TLS verification of the metrics endpoint | `""` |
| `metrics.serviceMonitor.tlsConfig.serverName` | Server name override for TLS SNI verification | `""` |
| `metrics.serviceMonitor.tlsConfig.insecureSkipVerify` | Skip TLS verification for authenticated metrics scraping. Keep `false` unless the scrape endpoint intentionally uses an untrusted self-signed certificate. | `false` |

When `metrics.auth.enabled=true` and `metrics.serviceMonitor.enabled=true`,
the chart requires either `metrics.serviceMonitor.tlsConfig.caFile` or
`metrics.serviceMonitor.tlsConfig.insecureSkipVerify=true`. The metrics server
uses a self-signed serving certificate unless you provide trusted cert material,
so this choice must be explicit.

For the full list of exposed metrics and recommended alert rules, see the
[Metrics and Alerting documentation](https://github.com/telekom/auth-operator/blob/main/docs/metrics-and-alerting.md).

### Network Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `networkPolicy.enabled` | Create NetworkPolicy resources for pod-level ingress isolation | `false` |
| `networkPolicy.metricsNamespace` | Namespace hosting the monitoring stack (Prometheus) | `"monitoring"` |
| `networkPolicy.webhookServer.ingressFrom` | Custom ingress `from` rules for the webhook port (9443) | `[]` |
| `networkPolicy.controllerManager.ingressFrom` | Custom ingress `from` rules for the metrics port (8080) | `[]` |
| `networkPolicy.egress.enabled` | Enable egress rules (for default-deny egress environments) | `false` |
| `networkPolicy.egress.dnsNamespace` | Namespace where CoreDNS runs (for UDP/TCP 53) | `"kube-system"` |
| `networkPolicy.egress.apiServerCIDR` | API server CIDR for egress restriction; required when egress is enabled unless `allowBroadAPIServerEgress=true` or `additionalRules` provides equivalent API-server access | `""` |
| `networkPolicy.egress.allowBroadAPIServerEgress` | Allow any destination on TCP 443/6443 when `apiServerCIDR` is empty | `false` |
| `networkPolicy.egress.additionalRules` | Additional custom egress rules | `[]` |

## High Availability

The webhook server defaults to 2 replicas with pod anti-affinity and PDB enabled.
When multiple replicas are deployed, leader election is automatically enabled so
that only one replica drives certificate rotation. Non-leader replicas detect the
TLS certificate via the Secret volume mount and become ready independently, so all
replicas serve admission webhook traffic. PDBs default to `minAvailable: 1` when
neither `minAvailable` nor `maxUnavailable` is set. To also enable HA for the controller:

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --version <chart-version> \
  --namespace auth-operator-system \
  --create-namespace \
  --set image.digest=sha256:<digest> \
  --set controller.replicas=2 \
  --set controller.podDisruptionBudget.enabled=true
```

## Uninstallation

```bash
helm uninstall auth-operator --namespace auth-operator-system
```

> **Note:** CRDs are not deleted automatically. To remove CRDs:
> ```bash
> kubectl delete crd roledefinitions.authorization.t-caas.telekom.com
> kubectl delete crd binddefinitions.authorization.t-caas.telekom.com
> kubectl delete crd webhookauthorizers.authorization.t-caas.telekom.com
> kubectl delete crd rbacpolicies.authorization.t-caas.telekom.com
> kubectl delete crd restrictedroledefinitions.authorization.t-caas.telekom.com
> kubectl delete crd restrictedbinddefinitions.authorization.t-caas.telekom.com
> ```

## CRDs

This chart installs six Custom Resource Definitions:

- **RoleDefinition** - Trusted-admin API that dynamically generates ClusterRoles/Roles based on API discovery
- **BindDefinition** - Trusted-admin API that creates ClusterRoleBindings/RoleBindings for subjects (Users, Groups, ServiceAccounts)
- **WebhookAuthorizer** - Configures webhook-based authorization decisions
- **RBACPolicy** - Defines policy constraints for restricted RBAC resources
- **RestrictedRoleDefinition** - Policy-governed RoleDefinition with automatic deprovisioning on violations
- **RestrictedBindDefinition** - Policy-governed BindDefinition with automatic deprovisioning on violations

Plain `RoleDefinition` and `BindDefinition` write access is platform-admin
equivalent. Use `RBACPolicy` with restricted CRDs for tenant delegation and
self-service workflows.

For detailed API documentation, see the [API Reference](https://github.com/telekom/auth-operator/blob/main/docs/api-reference/authorization.t-caas.telekom.com.md).

## OpenTelemetry Tracing

Enable distributed tracing via Helm values:

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector.observability:4317"
  insecure: false
  samplingRate: 0.1  # 10% of traces; chart default
```

When disabled (default), tracing has zero overhead — no headers are parsed
and no spans are created.

## Examples

The plain `RoleDefinition` and `BindDefinition` examples below are intended for
platform-owned RBAC. Do not delegate write access to these APIs to tenants; use
`RestrictedRoleDefinition` and `RestrictedBindDefinition` under an `RBACPolicy`
for delegated workflows.

### RoleDefinition

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: tenant-admin
spec:
  targetRole: ClusterRole
  targetName: tenant-admin
  scopeNamespaced: false
  restrictedApis:
    - name: authorization.t-caas.telekom.com
  restrictedResources:
    - name: nodes
    - name: nodes/proxy
  restrictedVerbs:
    - deletecollection
```

### BindDefinition

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: tenant-admin-binding
spec:
  targetName: tenant
  subjects:
    - kind: Group
      name: tenant-admins
      apiGroup: rbac.authorization.k8s.io
  clusterRoleBindings:
    clusterRoleRefs:
      - tenant-admin
```

## License

Apache 2.0 - See [LICENSE](https://github.com/telekom/auth-operator/blob/main/LICENSE)

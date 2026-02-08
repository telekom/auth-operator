# Auth Operator Helm Chart

A Kubernetes operator for managing RBAC with RoleDefinitions, BindDefinitions, and WebhookAuthorizers.

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
| `controller.resources.limits.memory` | Memory limit | `128Mi` |
| `controller.resources.requests.cpu` | CPU request | `10m` |
| `controller.resources.requests.memory` | Memory request | `64Mi` |
| `controller.podDisruptionBudget.enabled` | Enable PDB | `false` |
| `controller.podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

### Webhook Server Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `webhookServer.replicas` | Number of webhook server replicas | `1` |
| `webhookServer.tdgMigration` | Enable TDG migration mode | `"false"` |
| `webhookServer.resources.limits.cpu` | CPU limit | `150m` |
| `webhookServer.resources.limits.memory` | Memory limit | `128Mi` |
| `webhookServer.resources.requests.cpu` | CPU request | `50m` |
| `webhookServer.resources.requests.memory` | Memory request | `64Mi` |
| `webhookServer.service.port` | Service port | `443` |
| `webhookServer.service.type` | Service type | `ClusterIP` |
| `webhookServer.podDisruptionBudget.enabled` | Enable PDB | `false` |
| `webhookServer.podDisruptionBudget.minAvailable` | Minimum available pods | `1` |

### Service Account Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.annotations` | Service account annotations | `{}` |

### Metrics & Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `metrics.service.enabled` | Create a dedicated metrics Service | `true` |
| `metrics.service.port` | Metrics service port | `8080` |
| `metrics.serviceMonitor.enabled` | Create a Prometheus ServiceMonitor | `false` |
| `metrics.serviceMonitor.interval` | Scrape interval (empty = Prometheus default) | `""` |
| `metrics.serviceMonitor.scrapeTimeout` | Scrape timeout | `""` |
| `metrics.serviceMonitor.additionalLabels` | Extra labels on the ServiceMonitor | `{}` |

For the full list of exposed metrics and recommended alert rules, see the
[Metrics and Alerting documentation](https://github.com/telekom/auth-operator/blob/main/docs/metrics-and-alerting.md).

## High Availability

For production deployments, enable high availability with digest-based image reference:

```bash
helm install auth-operator oci://ghcr.io/telekom/charts/auth-operator \
  --version <chart-version> \
  --namespace auth-operator-system \
  --create-namespace \
  --set image.digest=sha256:<digest> \
  --set controller.replicas=2 \
  --set controller.podDisruptionBudget.enabled=true \
  --set webhookServer.replicas=2 \
  --set webhookServer.podDisruptionBudget.enabled=true
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
> ```

## CRDs

This chart installs three Custom Resource Definitions:

- **RoleDefinition** - Dynamically generates ClusterRoles/Roles based on API discovery
- **BindDefinition** - Creates ClusterRoleBindings/RoleBindings for subjects (Users, Groups, ServiceAccounts)
- **WebhookAuthorizer** - Configures webhook-based authorization decisions

For detailed API documentation, see the [API Reference](https://github.com/telekom/auth-operator/blob/main/docs/api-reference/authorization.t-caas.telekom.com.md).

## Examples

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

<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Multi-tenant Platform Integration

Auth Operator can be used in T-CaaS or other Kubernetes platforms to generate
RBAC from declarative definitions. This guide uses fictional tenants and groups;
it does not prescribe a platform's organization, identity providers, or support
processes. The file path is retained for existing links.

## Namespace Ownership

Optional namespace admission recognizes four ownership categories: `platform`,
`tenant`, `thirdparty`, and `addon`. The label keys are part of the operator's
public API contract, regardless of the platform using it. For example:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: example-team
  labels:
    t-caas.telekom.com/owner: tenant
    t-caas.telekom.com/tenant: example-team
```

Namespace admission is opt-in in the Helm chart
(`namespaceAdmission.enabled=false` by default). Before enabling it, install
the definitions that authorize namespace operations. A matching BindDefinition
can authorize ordinary principals; a ServiceAccount with matching namespace
ownership may also create or update a namespace. Kubernetes RBAC authorization
still applies.

For add-ons, each BindDefinition or RestrictedBindDefinition selector term must
pin one non-empty `t-caas.telekom.com/addon` identity. Owner-only and broad
identity selectors cannot grant access to arbitrary add-ons. An add-on
controller can manage namespace lifecycle; add-on namespaces are not implicitly
deletion-protected. See the [namespace label contract](api-reference/namespace-ownership.md)
for validation, migration, and deletion-protection rules.

## Group Mapping

Choose group names appropriate for your identity provider and use the exact
authenticated names in binding subjects. The operator does not create identity
provider groups or require a site, environment, or organization naming scheme.
For example, a fictional tenant could use `example-team-readers` and
`example-team-admins`. Keep administrative groups separate from read-only groups
and scope bindings to the intended namespaces.

See the [BindDefinition sample](../config/samples/authorization_v1alpha1_binddefinition.yaml)
and [RoleDefinition sample](../config/samples/authorization_v1alpha1_roledefinition.yaml).
If webhook authorization is needed, configure the Kubernetes API server to call
the operator's `/authorize` endpoint and define the matching WebhookAuthorizer
rules; creating a WebhookAuthorizer alone does not enable that API server setting.

## Policy-backed RBAC

Use RestrictedRoleDefinition and RestrictedBindDefinition for tenant-authored
RBAC. Both reference an administrator-managed RBACPolicy that limits generated
roles, bindings, subjects, and namespaces.

`RBACPolicy.spec.defaultAssignment` maps authenticated groups and automation
ServiceAccounts to their permitted policy. Admission rejects restricted
resources whose requester is assigned to a different default policy. Keep
RBACPolicy write access limited to platform administrators so tenant writers
cannot relax their own limits.

For example, the following fields scope a policy to a fictional tenant:

```yaml
spec:
  appliesTo:
    namespaceSelector:
      matchLabels:
        t-caas.telekom.com/owner: tenant
        t-caas.telekom.com/tenant: example-team
  defaultAssignment:
    groups:
      - example-team-admins
```

`spec.appliesTo` is enforced for both target namespaces and ServiceAccount
subject namespaces. A deployment ServiceAccount bound into tenant namespaces
must live in a namespace selected by the policy.

### Impersonated Apply

When a policy enables impersonation, restricted controllers apply generated
RBAC as the configured ServiceAccount:

```yaml
spec:
  impersonation:
    enabled: true
    serviceAccountRef:
      namespace: example-team
      name: rbac-applier
```

The Helm value `controller.impersonation.enabled` is disabled by default. Enable
it only after configuring the exact ServiceAccounts the controller may
impersonate. Policy-backed apply, stale-prune, and violation cleanup use the
impersonated ServiceAccount. Missing-policy cleanup and deletion finalizers use
the controller identity because there may be no policy left to resolve an
impersonated client from. Prefer namespaced impersonation grants instead of
cluster-wide grants.

### Recommended Flow

1. Platform administrators define one RBACPolicy per tenant or support scope.
2. Assign authenticated groups and trusted automation ServiceAccounts through
   `defaultAssignment`.
3. Tenant automation submits restricted resources referencing its assigned policy.
4. The controller deprovisions generated RBAC when policy scope, subjects, or
   generated-rule limits are violated.

See [policy samples](../config/samples/authorization_v1alpha1_rbacpolicy.yaml),
the [operator guide](operator-guide.md), and
[breakglass integration](breakglass-integration.md) for further examples.

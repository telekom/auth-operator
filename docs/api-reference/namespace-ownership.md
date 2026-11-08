<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Namespace Ownership Labels

These labels are namespace admission metadata, not new CRD fields.

| `t-caas.telekom.com/owner` | Required non-empty identity label | Forbidden identity labels |
|---|---|---|
| `platform` | None | `tenant`, `thirdparty`, `addon` |
| `tenant` | `t-caas.telekom.com/tenant` | `thirdparty`, `addon` |
| `thirdparty` | `t-caas.telekom.com/thirdparty` | `tenant`, `addon` |
| `addon` | `t-caas.telekom.com/addon` | `tenant`, `thirdparty` |

Forbidden labels must be absent, even when their value would be empty. A
namespace with no tracked ownership labels remains valid. An identity without
an owner, an unknown owner, or a missing/empty required identity is invalid.

For example, an add-on controller can create:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: t-addon-metrics
  labels:
    t-caas.telekom.com/owner: addon
    t-caas.telekom.com/addon: metrics
```

Matching BindDefinitions authorize namespace operations for ordinary users.
On CREATE, a ServiceAccount is authorized only by namespace grants in a
non-restricted BindDefinition, whether the BindDefinition names the
ServiceAccount or one of its groups (for example
`system:serviceaccounts:<namespace>`). Its hosting namespace never widens that
scope, and a ServiceAccount without any such grant cannot CREATE namespaces at
all. Grants in `*-namespaced-reader-restricted` BindDefinitions and
BindDefinitions with only `clusterRoleBindings` do not count. This also applies
when tenant or third-party Flux identities share a platform-owned controller
namespace, and to platform controllers such as
`flux-system/kustomize-controller` and `flux-system/helm-controller`, which need
an explicit grant for the owners they create namespaces for:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: flux-platform-namespaces
spec:
  targetName: flux-platform-namespaces
  subjects:
    - kind: ServiceAccount
      name: kustomize-controller
      namespace: flux-system
    - kind: ServiceAccount
      name: helm-controller
      namespace: flux-system
  roleBindings:
    - clusterRoleRefs: ["view"]
      namespaceSelector:
        - matchLabels:
            t-caas.telekom.com/owner: platform
```

Removing a ServiceAccount's last grant therefore never widens its access.
Requests that skip namespace admission through the existing privileged and
TDG-migration bypasses are unaffected.

UPDATEs keep the hosting-namespace fallback: a ServiceAccount may update a
namespace whose valid, non-empty tracked ownership labels exactly match its
source namespace, even without a matching grant. This fallback never
authorizes DELETE, and Kubernetes RBAC authorization still applies to every
request.

Two transitional escape hatches restore hosting-namespace inheritance on
CREATE. Both may be removed in a future release:

- Webhook flag `--strict-sa-namespace-ownership=false` (Helm
  `webhookServer.strictSANamespaceOwnership: "false"`) applies to every
  ServiceAccount.
- Annotation `t-caas.telekom.com/inherit-hosting-namespace-ownership: "true"`
  on a ServiceAccount applies to that ServiceAccount only. Any other value, or
  no annotation, keeps strict behaviour. The webhook reads the annotation live
  from the API server, so it needs `get` on ServiceAccounts. A failed read
  denies the request.

A ValidatingAdmissionPolicy guards the annotation: only `kubernetes-admin` and
`system:masters`, the identities that may change namespace ownership labels,
may set, change or remove it on ServiceAccount CREATE or UPDATE. Other edits to
an annotated ServiceAccount are unaffected. The TDG-migration bypass
identities are deliberately excluded, because they are GitOps reconcilers that
apply tenant-sourced content. Without the guard, anyone who can create or
update a ServiceAccount in a namespace could arm it, an identity that holds
namespace `create` RBAC, with that namespace's ownership (never more).

The policy needs Kubernetes 1.30 or later (`admissionregistration.k8s.io/v1`):

- Helm: `webhookServer.inheritHostingNamespaceOwnershipGuard` is `auto` by
  default and renders the policy only when the cluster serves that API.
  `enabled` always renders it; `disabled` omits it and leaves the annotation
  unguarded. Offline `helm template` needs
  `--api-versions admissionregistration.k8s.io/v1/ValidatingAdmissionPolicy`.
- Kustomize: `config/webhook` always includes
  `serviceaccount_ownership_annotation_vap.yaml`. On older clusters, remove it
  with a `$patch: delete` overlay.

On clusters without the policy, limit ServiceAccount `create`, `update` and
`patch` in platform-owned namespaces to platform operators. A new
ServiceAccount can carry the annotation, so `create` alone is enough to opt
out, even for identities granted through a group-based BindDefinition.

Non-bypass principals can update an authorized add-on
namespace when ownership is unchanged, but cannot adopt, change, or remove
tracked ownership labels. Existing privileged bypass rules remain unchanged.
With `TDGMigration` enabled, protected-label migration bypass principals may
reclassify in every direction among `tenant`, `thirdparty`, and `addon`.
Replace the previous identity label with the new category's non-empty identity
label; retaining conflicting identity labels is denied. A migration bypass may
also adopt a legacy non-platform namespace as any of these categories.
Reclassification remains denied for ordinary principals and when migration mode
is disabled. Platform ownership is never reclassifiable, and legacy
`schiff.telekom.de/owner=platform` or `schiff` namespaces cannot be adopted as
add-ons. Changing an identity without reclassifying the owner remains denied.
Existing privileged bypass rules remain unchanged.

`t-caas.telekom.com/addon` is a built-in BindDefinition namespace-selector key
regardless of additional allowed label domains. A selector with this identity
alone derives `owner=addon` during creation. Derivation supports `matchLabels`
and single-value `In` expressions. Every selector term targeting add-ons must
pin `t-caas.telekom.com/addon` to exactly one non-empty value, using `matchLabels`
or one single-value `In` expression. A label and an identical single-value `In`
may coexist; multiple add-on expressions, empty values, `Exists`, `NotIn`,
`DoesNotExist` combined with a pin, and multi-value `In` are rejected.
This validation applies to both BindDefinition and RestrictedBindDefinition.

`owner=addon` and `owner In [..., addon]` require a pin. `owner Exists` and
`owner NotIn` also require one unless another requirement explicitly excludes
add-ons (for example `owner NotIn [addon]` or `addon DoesNotExist`).
`addon DoesNotExist` alone is an exclusion and remains valid; combining it with
an explicit add-on owner is rejected. Other add-on-key requirements require
a pin even when the term is contradictory or excludes add-on owners.
Selectors unrelated to ownership retain their admission behavior, but cannot
authorize add-on namespace operations without a pin.

This is a security tightening for new objects and spec-changing updates:
replace broad add-on selectors with one pinned term per permitted add-on.
Metadata-only updates retain the existing spec-validation fast path.
Namespace mutation and validation independently refuse unpinned selectors for
add-on operations, including unchanged ownership updates, even for legacy
BindDefinitions or objects created with BindDefinition admission disabled.
An add-on `a` pin never authorizes an add-on `b` namespace.
On unchanged UPDATEs, the mutator ignores every selector that does not match the
existing namespace, preserving exact-ownership ServiceAccount fallback across
tenant, third-party and add-on categories without deriving unrelated labels.

On CREATE, selector-derived ownership must match the requested namespace name
and any ownership labels already supplied. Alternative selector terms are never
merged: if more than one different ownership set is compatible, creation is
denied as ambiguous. Supply the add-on identity explicitly or constrain each
term with `kubernetes.io/metadata.name` to select the intended add-on. Identical
grants may coexist, and selector order does not affect the result.

```yaml
namespaceSelector:
  - matchLabels:
      t-caas.telekom.com/owner: addon
      t-caas.telekom.com/addon: metrics
```

Add-on namespaces are **not implicitly deletion-protected**, because the add-on
controller owns their lifecycle. Explicit deletion-protection opt-in,
hard-protected system names, and configured extra protected names still apply.
Deployment automation, admission policies, and add-on controllers should use
the same label contract.

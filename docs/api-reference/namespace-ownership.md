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

For example, the T-CaaS add-on controller creates:

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
ServiceAccounts may also CREATE/UPDATE without a matching BindDefinition when
their source namespace has valid, non-empty tracked ownership labels exactly
matching the target. This fallback does not authorize DELETE, and Kubernetes RBAC
authorization still applies to every request.
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
ServiceAccounts inherit the owner and identity labels from their namespace.

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
The T-CaaS auth-operator function, Kyverno policies, and the T-CaaS add-on
controller consume this contract.

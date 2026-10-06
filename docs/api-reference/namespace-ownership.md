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

Matching BindDefinitions authorize namespace operations; ownership labels alone
do not grant access. Non-bypass principals can update an authorized add-on
namespace when ownership is unchanged, but cannot adopt, change, or remove
tracked ownership labels. Existing privileged bypass rules remain unchanged.
Migration reclassification is limited to `tenant` ↔ `thirdparty`; neither
platform nor add-on ownership is reclassifiable.

`t-caas.telekom.com/addon` is a built-in BindDefinition namespace-selector key
regardless of additional allowed label domains. A selector with this identity
alone derives `owner=addon` during creation. Derivation supports `matchLabels`
and single-value `In` expressions. An `owner=addon` selector alone cannot infer
an identity; multi-value selectors also require explicitly supplied labels.
ServiceAccounts inherit the owner and identity labels from their namespace.

Add-on namespaces are **not implicitly deletion-protected**, because the add-on
controller owns their lifecycle. Explicit deletion-protection opt-in,
hard-protected system names, and configured extra protected names still apply.
The T-CaaS auth-operator function, Kyverno policies, and the T-CaaS add-on
controller consume this contract.

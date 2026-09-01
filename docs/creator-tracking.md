# Creator tracking

Auth Operator can record the effective Kubernetes request identity on selected
resources with native `MutatingAdmissionPolicy` policies. The feature is
disabled by default. Enable it only when the cluster serves a supported policy
API and the operational impact is understood.

## Current status

The implementation and interoperability tests are in the creator-tracking
stack. Runtime benchmark authorization and measured results are still pending.
The quick benchmark is a smoke check and is not release evidence. No default
change or performance claim is made in this document.

See the [benchmark methodology](benchmarks/creator-tracking-methodology.md)
and the [pending results report](benchmarks/creator-tracking-results.md) for
the measurement plan and publication status.

## Annotations and encoding

The policies add these annotations to matched parent resources:

| Annotation | Meaning |
| --- | --- |
| `t-caas.telekom.com/created-by` | Literal effective `request.userInfo.username` from the CREATE request. |
| `t-caas.telekom.com/created-by-groups` | The effective request groups from CREATE, stored as a comma-separated encoded list. |
| `t-caas.telekom.com/updated-by` | A comma-separated encoded list of distinct editors, in first-edit order. It is used in `contributors` mode. |

Before a group or contributor component is joined into a list, `%` is encoded
as `%25` and `,` as `%2C`. To decode a component, split the list on commas,
replace `%2C` with `,`, then replace `%25` with `%`.

Anyone who can read object metadata can read these annotations. This includes
the metadata of a Secret. The values contain no timestamp or full change
history.

## Modes

Configure the feature in the Helm chart with
`creatorTracking.enabled`, `creatorTracking.mode`, and `creatorTracking.map`.
The current safe values are `enabled: false`, `mode: protect`, and `map: auto`.

| Mode | Behavior |
| --- | --- |
| `create-only` | Stamp creator username and groups on CREATE, replacing client-supplied creator values. Do not restore creator values on UPDATE. Remove client-supplied `updated-by` on matching updates. |
| `protect` | Apply `create-only` behavior and restore existing creator values when a matching UPDATE changes or removes them. Previously unstamped objects remain unstamped. |
| `contributors` | Apply `protect` behavior and append each distinct effective editor to `updated-by` in first-edit order. The creator is added only if they later perform an UPDATE. |

Only CREATE and parent UPDATE requests are matched. DELETE requests and
subresources such as `status` are not tracked. Resource scope and exclusions
are not retroactive, and enabling the feature does not backfill old objects.

## Trust and failure boundaries

The annotations record the effective identity presented to the API server. An
authorized impersonator controls that identity; the original caller is not
available to the policy. The annotations are operational context, not forensic
or cryptographic proof.

The policies use `failurePolicy: Ignore` so tracking does not block a write.
This can leave a valid object unstamped during an activation or evaluation
gap. Kubernetes still validates the object after a successful mutation.
Annotation keys and values are limited by Kubernetes's total annotation size
limit of 262144 bytes (the sum of annotation keys and values). When a stamp,
contributor append, or restoration would exceed that limit, the mutation is
omitted or the protected value remains absent.
Protection can therefore be lost at the annotation limit.

Excluded usernames suppress new creator stamps and contributor appends. They do
not bypass restoration or removal of forged protected values.

## Server-side apply and operator resources

The policies own only the creator and contributor annotation fields. The
operator does not declare those fields in its server-side apply payloads, so
creator tracking does not intentionally compete with the operator's managed
fields. An operator-created ServiceAccount can therefore be stamped at
admission without changing the operator's RBAC ownership model.

## Kubernetes API availability

Creator tracking requires Kubernetes 1.34 or newer because it uses
`MutatingAdmissionPolicy`; the chart selects the stable or beta endpoint that
the cluster serves.

Kubernetes 1.36 serves the stable
`admissionregistration.k8s.io/v1` API. Kubernetes 1.34 and 1.35 can serve
`v1beta1` when `MutatingAdmissionPolicy=true` and
`admissionregistration.k8s.io/v1beta1=true` are enabled. The chart's `auto`
mode prefers v1 and falls back to v1beta1 when that API is served. It does not
enable an API-server feature gate.

The v1 and v1beta1 endpoints expose views of the same persisted resources.
Keep both endpoints available during an API-version migration and do not
delete the beta objects after applying through v1. See the chart README and
the standalone [native policy example](examples/creator-tracking-map.yaml).

## Kyverno alternatives

Clusters without the native policy path can use the documented Kyverno
alternatives in [Kyverno creator tracking](kyverno-creator-tracking.md).
Prefer Kyverno's generated native MAP path when supported. The legacy
ClusterPolicy webhook path is compatibility-only and has weaker behavior and
budget guarantees.

## Lifecycle

Disabling or uninstalling the chart removes its policy resources but leaves
existing annotations on objects. Before cleaning those annotations, disable or
remove the creator and contributor policies and verify that their policies and
bindings are gone. Changing mode, resource scope, or exclusions affects future
admission requests only.

## Benchmark decision

The measured decision is tracked in
[creator-tracking benchmark results](benchmarks/creator-tracking-results.md).
Until the complete matrix, auxiliary isolation cells, provenance checks, and
review are complete, the feature remains opt-in and the default mode remains
`protect`.

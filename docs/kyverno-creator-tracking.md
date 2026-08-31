# Kyverno creator tracking

These examples provide compatibility paths for clusters that do not use the
operator's native `MutatingAdmissionPolicy`:

- `creator-tracking-kyverno-clusterpolicy.yaml` uses Kyverno's legacy webhook
  engine. It is retained for compatibility only. It sets `background: false`
  because `request.userInfo` is available only during admission.
- `creator-tracking-kyverno-mutatingpolicy.yaml` contains separate creator and
  contributor CEL `MutatingPolicy` resources. Kyverno application 1.19.0 and
  chart 3.9.0 are the tested pins in `versions.env`. Kyverno 1.19 deprecates
  `ClusterPolicy`. Both policies disable background evaluation because request
  identity exists only during admission. This also avoids granting Kyverno
  reporting access to every tracked resource.

The hermetic installer downloads the exact chart archive, verifies its SHA256,
and checks both the chart and application versions in the verified archive
before Helm installs it. It also enables the MutatingPolicy CRD and generated
MutatingAdmissionPolicy controller feature:

```bash
source versions.env
./hack/ci/install-kyverno.sh
```

After applying the CEL example, inspect generated native resources:

```bash
kubectl get mutatingadmissionpolicies mpol-creator-tracking
kubectl get mutatingadmissionpolicybindings mpol-creator-tracking-binding
kubectl get mutatingadmissionpolicies mpol-contributor-tracking
kubectl get mutatingadmissionpolicybindings mpol-contributor-tracking-binding
```

Both paths use `failurePolicy: Ignore`, which lets the API server continue when
policy evaluation fails. Normal admission validation still applies after a
successful mutation. The CEL policies exclude objects with the
`t-caas.telekom.com/creator-tracking: disabled` label from new tracking,
restore old creator values on updates, escape `%` and then `,` in group and
contributor components, and account for annotation bytes against the
262,144-byte limit. Kyverno's legacy policy is tested in a separate phase after
both generated MAPs and bindings have been removed. It is not intended to run
alongside the CEL policies.

The legacy ClusterPolicy intentionally provides creator-only compatibility. It
does not claim contributor history or exact UTF-8 budget parity, and it cannot
prove whether a creator annotation on an unstamped object was forged. Its
background mode is disabled, so it only sees admission request identity.
It matches the same core, RBAC, and auth-operator resource kinds as the CEL
policies. Prefer the generated native path when the API server serves
`MutatingAdmissionPolicy`; use the legacy webhook path only for compatibility.

The runner is isolated from normal Helm tests:

```bash
make test-e2e-creator-tracking-kyverno
```

It uses the `auth-operator-e2e-kyverno` cluster and the
`creator-tracking-kyverno` Ginkgo label.

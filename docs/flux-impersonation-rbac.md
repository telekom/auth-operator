<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Flux Impersonation and API Discovery RBAC

What [Flux](https://fluxcd.io) needs from an authorization layer when a
`Kustomization` or `HelmRelease` reconciles under an impersonated ServiceAccount,
and why the failure mode is opaque when a grant is missing.

This document is reference material for anyone writing RBAC that a Flux controller
will impersonate through, whether that RBAC comes from auth-operator's CRDs, a
`WebhookAuthorizer`, or plain Kubernetes objects. Topology-specific test suites for
particular platforms belong in the repositories that own those topologies, not
here.

---

## Table of Contents

- [What Flux needs from an authorization layer](#what-flux-needs-from-an-authorization-layer)
- [Namespace resolution](#namespace-resolution)
- [The ServiceAccount object need not exist](#the-serviceaccount-object-need-not-exist)
- [Diagnostics gap: the failure is opaque](#diagnostics-gap-the-failure-is-opaque)
- [Worked example](#worked-example)
- [Interaction with WebhookAuthorizer](#interaction-with-webhookauthorizer)
- [Kubernetes 1.36 and constrained impersonation](#kubernetes-136-and-constrained-impersonation)
- [Checklist](#checklist)

---

## What Flux needs from an authorization layer

When a Flux object sets `spec.serviceAccountName`, or the controller runs with
`--default-service-account`, the controller stops using its own client and builds
one that impersonates a ServiceAccount username. Two independent grants are
required, and they apply to two different identities.

### 1. The controller's own identity needs `impersonate`

The identity the controller Deployment actually runs as needs the `impersonate`
verb on `serviceaccounts`. The least-privilege form restricts it with
`resourceNames` rather than granting it cluster-wide:

```yaml
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    resourceNames: ["flux-tenant-reconciler"]   # not a blanket grant
    verbs: ["impersonate"]
```

A blanket `impersonate` on `serviceaccounts` lets the controller assume **any**
ServiceAccount in the cluster, including `kube-system` ones, which in most clusters
is equivalent to cluster-admin. Scope it.

Note that the identity to grant this to is the controller's **pod identity**, which
is not necessarily the ServiceAccount named in the Helm chart's defaults. If a
deployment overrides `serviceAccount.name`, the grant has to follow.

### 2. The impersonated identity needs API discovery

This is the requirement that gets missed. Before the impersonated client can apply
anything it has to build a RESTMapper, which means reading Kubernetes API
discovery. Discovery is not a resource; it is authorized through `nonResourceURLs`
(`/api`, `/apis`, `/apis/*`).

**A namespaced `Role` cannot express `nonResourceURLs` at all.** The field only
exists on `ClusterRole`. So a tenant-scoped `Role`/`RoleBinding` pair, however
generous, can never convey discovery access, and neither can a resource-only
`ClusterRole`.

Normally nobody notices, because kube-apiserver bootstraps a `ClusterRoleBinding`
of the built-in `system:discovery` ClusterRole to the `system:authenticated` group
(`k8s.io/kubernetes@v1.36.2/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go:697`):

```go
rbacv1helpers.NewClusterBinding("system:discovery").Groups(user.AllAuthenticated).BindingOrDie(),
```

Every impersonated non-anonymous identity gets `system:authenticated` (see
[Kubernetes 1.36](#kubernetes-136-and-constrained-impersonation)), so discovery
normally just works. It stops working when something removes that implicit path,
which in practice means an authorization webhook that returns an explicit deny (see
[Interaction with WebhookAuthorizer](#interaction-with-webhookauthorizer)).

---

## Namespace resolution

`spec.serviceAccountName` is resolved in the namespace of the Flux object itself,
never anywhere else. There is no way to point it at a ServiceAccount in another
namespace, and no cluster-wide default namespace for it.

kustomize-controller passes `obj.GetNamespace()` straight through
(`internal/controller/kustomization_controller.go:392-395` at v1.8.5, in
`reconcile()`):

```go
	if r.DefaultServiceAccount != "" || obj.Spec.ServiceAccountName != "" {
		mustImpersonate = true
		impersonatorOpts = append(impersonatorOpts,
			runtimeClient.WithServiceAccount(r.DefaultServiceAccount, obj.Spec.ServiceAccountName, obj.GetNamespace()))
	}
```

So a `Kustomization` in namespace `example-tenant` with
`spec.serviceAccountName: flux-tenant-reconciler` impersonates exactly
`system:serviceaccount:example-tenant:flux-tenant-reconciler`. Bindings must be
written against that username, in that namespace.

---

## The ServiceAccount object need not exist

Kubernetes impersonation authorizes purely from the username string. The API server
does not check that a ServiceAccount object exists behind
`system:serviceaccount:<ns>:<name>`, and neither does Flux on the reconcile path.

`setImpersonationConfig` is pure string formatting
(`github.com/fluxcd/pkg/runtime@v0.111.0/client/impersonator.go:224-233`):

```go
func (i *Impersonator) setImpersonationConfig(restConfig *rest.Config) {
	name := i.defaultServiceAccount
	if sa := i.serviceAccountName; sa != "" {
		name = sa
	}
	if name != "" {
		username := fmt.Sprintf("system:serviceaccount:%s:%s", i.serviceAccountNamespace, name)
		restConfig.Impersonate = rest.ImpersonationConfig{UserName: username}
	}
}
```

No context, no client, no lookup. The consequence: **RBAC bindings are the entire
contract.** A `RoleBinding` naming a `ServiceAccount` subject that does not exist
still authorizes the impersonated requests.

Upstream considers this by design, and argues it is *more* secure, because if no
ServiceAccount object exists then no Pod can ever hold a token for that identity.
The identity is reachable only through impersonation by the controller. Flux
maintainers declined to add an existence pre-check:
[fluxcd/flux2#3259](https://github.com/fluxcd/flux2/issues/3259) and
[fluxcd/kustomize-controller#682](https://github.com/fluxcd/kustomize-controller/issues/682),
both closed as **not planned**. The reasoning given was that an existence check
fixes only one of several indistinguishable causes of a 403 (missing binding,
typo'd binding, under-privileged role) while requiring cluster-wide `get`/`list`/
`watch` on ServiceAccounts for the controller.

Practical upshot: do not debug by checking whether the ServiceAccount exists. Check
the bindings.

---

## Diagnostics gap: the failure is opaque

Flux has a helper that would detect a missing identity, `CanImpersonate()`, but it
is called **only on the finalizer/delete path**
(`kustomization_controller.go:1137` at v1.8.5, inside `finalize()`). `reconcile()`
never calls it. A missing or unbound identity therefore produces a generic 403 with
condition reason `ReconciliationFailed` and no distinct event.

Because the impersonated client's first API call is discovery, the user-visible
error is:

```
<Kind>/<ns>/<name> dry-run failed (Forbidden): failed to get server groups: unknown
```

None of that string is Flux's own text. Its three parts come from three different
libraries:

| Fragment | Origin |
|---|---|
| `<Kind>/<ns>/<name> dry-run failed` and ` (Forbidden)` | `fluxcd/pkg/ssa` `errors/errors.go:61-72` |
| `failed to get server groups: %w` | controller-runtime `pkg/client/apiutil/restmapper.go:287` |
| `unknown` | client-go `rest/request.go:1343` |

**`(Forbidden)` is prepended by fluxcd/pkg/ssa**, from the reason on the API error
(`github.com/fluxcd/pkg/ssa@v0.74.0/errors/errors.go:61-72`):

```go
	reason := string(apierrors.ReasonForError(e.Unwrap()))
	...
	if reason != "" {
		reason = fmt.Sprintf(" (%s)", reason)
	}

	return fmt.Sprintf("%s dry-run failed%s: %s", utils.FmtUnstructured(e.involvedObject), reason, e.underlyingErr.Error())
```

**`failed to get server groups` is controller-runtime's lazy RESTMapper**, wrapping
the discovery call (`sigs.k8s.io/controller-runtime@v0.24.1/pkg/client/apiutil/restmapper.go:287`):

```go
	apiGroups, maybeResources, _, err := m.client.GroupsAndMaybeResources()
	if err != nil {
		return nil, false, fmt.Errorf("failed to get server groups: %w", err)
	}
```

**`: unknown` is a client-go artifact and carries no information.** `rest.Request`
substitutes the literal string for any response body whose Content-Type is not
`text/*` (`k8s.io/client-go@v0.36.3/rest/request.go:1337-1374`):

```go
	message := "unknown"
	if isTextResponse {
		message = strings.TrimSpace(string(body))
	}
```

```go
func isTextResponse(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	if len(contentType) == 0 {
		return true
	}
	media, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.HasPrefix(media, "text/")
}
```

The API server's 403 body is `application/json`, so `isTextResponse` returns false
and the body is discarded. This path is reached because discovery reads via
`.Raw()`, which returns the transport error verbatim and skips the `Status`
decoding that `Result.Get()` and `Result.Into()` perform
(`k8s.io/client-go@v0.36.3/discovery/discovery_client.go:252-257` and
`rest/request.go:1399-1402`):

```go
	body, err := d.restClient.Get().
		AbsPath("/api").
		SetHeader("Accept", accept).
		Do(context.TODO()).
		ContentType(&responseContentType).
		Raw()
```

```go
// Raw returns the raw result.
func (r Result) Raw() ([]byte, error) {
	return r.body, r.err
}
```

So the API server's real explanation, the `Status.message` naming the user and the
denied path, is thrown away before Flux ever sees it. **Do not interpret
`unknown`.** It is not an authorizer reason, not a resource name, and not a hint
about which grant is missing. To find the real cause, read the API server audit log
(`impersonatedUser.username` and `authorization.k8s.io/reason` on the denied
request) or issue a `SubjectAccessReview` for the impersonated username against
`/api`.

---

## Worked example

Namespace `flux-system` runs the controllers; `example-tenant` holds the Flux
objects and is the namespace the impersonated identity resolves in.

```yaml
---
# 1. Let the controller identity impersonate exactly one ServiceAccount name.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: flux-tenant-impersonator
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    resourceNames: ["flux-tenant-reconciler"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flux-tenant-impersonator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: flux-tenant-impersonator
subjects:
  # The controller's own pod identity, not the impersonated one.
  - kind: ServiceAccount
    name: kustomize-controller
    namespace: flux-system
---
# 2. Give the impersonated identity API discovery, by binding the builtin.
#    A namespaced Role cannot express nonResourceURLs, so this must be a
#    ClusterRoleBinding.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flux-tenant-reconciler-discovery
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:discovery
subjects:
  - kind: ServiceAccount
    name: flux-tenant-reconciler
    namespace: example-tenant
```

The identity still needs its own resource permissions for whatever it applies;
those are ordinary namespaced `Role`/`RoleBinding` grants and are deliberately not
shown here.

### Why bind the builtin instead of a hand-rolled role

Binding `system:discovery` is the non-escalating choice. It is the very same
ClusterRole the bootstrap policy already binds to `system:authenticated`, so
binding it explicitly to one identity grants that identity nothing it would not
already have on a cluster without a deny-capable authorization webhook.

Its definition
(`k8s.io/kubernetes@v1.36.2/plugin/pkg/auth/authorizer/rbac/bootstrappolicy/policy.go:326-339`):

```go
		{
			// a role which provides just enough power to determine if the server is
			// ready and discover API versions for negotiation
			ObjectMeta: metav1.ObjectMeta{Name: "system:discovery"},
			Rules: []rbacv1.PolicyRule{
				rbacv1helpers.NewRule("get").URLs(
					"/livez", "/readyz", "/healthz",
					"/version", "/version/",
					"/openapi", "/openapi/*",
					"/api", "/api/*",
					"/apis", "/apis/*",
				).RuleOrDie(),
			},
		},
```

One rule. Verb `get` only. `.URLs(...)` only, so **no resource rules at all**: it
cannot read a Secret, list a Pod, or touch any object. Writing an equivalent
ClusterRole by hand adds a second thing to maintain and invites drift as upstream
adds discovery paths, with no privilege benefit.

---

## Interaction with WebhookAuthorizer

The `WebhookAuthorizer` CRD this operator ships participates in the API server's
authorizer chain. That has a consequence specific to discovery.

**An explicit deny short-circuits the chain before RBAC is consulted.** The
implicit `system:discovery` binding to `system:authenticated` lives in the RBAC
authorizer, so it never gets a chance to apply. A webhook that denies broadly can
therefore break discovery for an impersonated identity that looks, on paper, to
have every grant it needs. This is the mechanism by which an otherwise correct Flux
setup produces the opaque error above.

A `WebhookAuthorizer` that only ever returns "no opinion" for non-matching
requests, which is the default, does not have this problem; the chain continues to
RBAC. The risk comes from `deniedPrincipals` and from
`impersonationVerbPolicy: Deny`.

If discovery has to be authorized by the webhook itself, grant it via
`nonResourceRules`. See
[`test/e2e/fixtures/webhookauthorizer_flux_discovery.yaml`](../test/e2e/fixtures/webhookauthorizer_flux_discovery.yaml)
for a complete generic example.

### How nonResourceURLs are matched

`nonResourceURLs` matching is implemented by `matchesNonResourceURLRule`
(`internal/webhook/authorization/webhook_authorizer.go:1174-1185`):

```go
func matchesNonResourceURLRule(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == path {
			return true
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(path, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}
```

It supports exact match, the bare `*`, and a trailing `/*` prefix match, which
mirrors Kubernetes RBAC `nonResourceURLs` semantics. Two footguns follow from the
prefix form:

- **A trailing `/*` pattern does not match the parent path.** `/apis/*` trims to the
  prefix `/apis/`, which `/apis` does not have. Listing only `/apis/*` allows
  `/apis/apps/v1` but **not** `/apis` itself, and client-go's discovery reads
  `/apis` first. Always list the parent alongside the wildcard:
  `["/api", "/apis", "/apis/*"]`.
- **It is a prefix match, not a glob.** `/apis/*` does not cover a sibling
  top-level path such as `/openapi/v3`, and there is no `*` expansion in the middle
  of a pattern.

The other matchers on the same object are stricter. `matchesExactOrAll`
(`webhook_authorizer.go:1153-1160`), used for `verbs`, `apiGroups` and
`resourceNames`, is exact-match or a literal `*` with **no prefix or glob
semantics** at all:

```go
func matchesExactOrAll(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}
```

So a partial pattern such as `impersonate*` in `verbs` matches nothing. Enumerate
values, or use the bare `*`.

---

## Kubernetes 1.36 and constrained impersonation

ConstrainedImpersonation (KEP-5284) is beta and enabled by default in 1.36. It
introduces the `impersonate:<mode>` and `impersonate-on:<mode>:<verb>` verbs. See
[Constrained Impersonation](./constrained-impersonation.md) for the typed API this
operator exposes for them, the version compatibility matrix, and the
legacy-fallback escape hatch.

For the purposes of this document, the relevant point is that **discovery behaviour
is unchanged**, because both the legacy and the constrained filter append
`system:authenticated` to the impersonated identity.

Legacy filter, `WithImpersonation`
(`k8s.io/apiserver@v0.36.3/pkg/endpoints/filters/impersonation/impersonation.go:126-144`):

```go
		if username != user.Anonymous {
			...
			addAuthenticated := true
			for _, group := range groups {
				if group == user.AllAuthenticated || group == user.AllUnauthenticated {
					addAuthenticated = false
					break
				}
			}

			if addAuthenticated {
				groups = append(groups, user.AllAuthenticated)
			}
		}
```

Shared mode state, reached from both `WithImpersonation` and
`WithConstrainedImpersonation` (`.../impersonation/mode.go:365-369`):

```go
	if actualUser.Name == user.Anonymous {
		ensureGroup(&actualUser, user.AllUnauthenticated)
	} else if !slices.Contains(actualUser.Groups, user.AllUnauthenticated) {
		ensureGroup(&actualUser, user.AllAuthenticated)
	}
```

`user.AllAuthenticated` is `system:authenticated`, which policy.go:697 binds to
`system:discovery`. So enabling or disabling the feature gate does not change
whether an impersonated ServiceAccount can read discovery.

What the gate *does* change is that the identity grant can be scoped to
impersonation alone. A `serviceaccount`-mode grant restricts what the controller
may do while impersonating, which a blanket legacy `impersonate` does not. Note
that a pre-existing blanket legacy grant wins by fallback and silently defeats the
constraint unless `impersonate` is explicitly restricted.

---

## Checklist

When a Flux object using `spec.serviceAccountName` fails with
`dry-run failed (Forbidden): failed to get server groups: unknown`:

1. Identify the controller's **actual** pod identity, not the chart default, and
   confirm it holds `impersonate` on `serviceaccounts` covering the target name.
2. Confirm the impersonated username is
   `system:serviceaccount:<flux-object-namespace>:<spec.serviceAccountName>`. The
   namespace is the Flux object's own.
3. Confirm the impersonated identity has discovery via a **cluster-scoped** grant.
   A `Role` cannot carry `nonResourceURLs`.
4. Check whether any authorization webhook returns an explicit deny for that
   identity, which bypasses the implicit `system:discovery` binding.
5. Ignore the word `unknown`. Get the real reason from the audit log or a
   `SubjectAccessReview` for `get` on `/api`.
6. Do not bother checking whether the ServiceAccount object exists. It does not
   need to.

# Logging Reference

What the auth-operator logs, at which verbosity, and with which fields. The
[message catalog](#message-catalog) is generated from the logger call sites,
and `go test ./hack/logref` (part of `make test`) fails when it, the level
table, the decision fields or the personal-data table drift from the code.

## Binaries

Every main package in the repository is listed here; `go test ./hack/logref`
fails when one is missing.

| Binary | Where it runs | Logging flags | Components that log |
|--------|---------------|---------------|---------------------|
| `auth-operator controller` | Helm Deployment `<release>-controller-manager` | yes | Startup, controller manager setup, reconcilers, API discovery, capability detection |
| `auth-operator webhook` | Helm Deployment `<release>-webhook-server` | yes | Startup, webhook server setup, authorization webhook (`/authorize`), namespace admission webhooks, CRD validation webhooks |
| `verify-rendered-rbac` | `hack/verify-helm-rbac.sh` in CI (`go run hack/verify-rendered-rbac.go`) | yes | Rendered RBAC verification (one error line on failure) |
| `creator-tracking-benchmark` | `make benchmark-creator-tracking` (`hack/benchmark`) | yes | Creator-tracking benchmark (one error line on failure; results go to report files) |
| `creator-reinvocation-webhook` | e2e test fixture image (`test/e2e/testserver`, build tag `e2e`) | no | Not shipped; logs plain `log.Printf` lines that the creator-tracking e2e suite matches |

`auth-operator` is the only binary in the container image. Libraries such as
controller-runtime and client-go log through the same logger; their messages
are not listed here.

## Flags

All binaries with logging flags share `pkg/logging`, so they behave the same.
A flag given on the command line wins over its environment variable.

| Flag | Environment | Helm value | Default | Meaning |
|------|-------------|------------|---------|---------|
| `--log-format` | `LOG_FORMAT` | `global.logFormat` | `text` | `text` (klog) or `json` (one JSON object per line) |
| `--verbosity`, `-v` | `LOG_VERBOSITY` | `global.logLevel` (number) | `2` for `auth-operator`, `0` for the hack tools | Highest V-level written (0-9) |
| `--log-level` | `LOG_LEVEL` | `global.logLevel` (name) | unset | Named level, mapped to a verbosity (below) |

`--log-level` names map onto verbosities:

| `--log-level` | Verbosity | Writes |
|---------------|-----------|--------|
| `error` | errors only | `error` lines; no `V(0)` lines |
| `warn` | `0` | Same as `info`: logr has no warning level, warnings are `V(0)` lines |
| `info` | `0` | `error` and `V(0)` lines |
| `debug` | `4` | Every message in the catalog |

Setting both `--log-level` and `--verbosity` (or their environment variables)
fails at startup unless they name the same verbosity. In the chart,
`global.logLevel` renders `--verbosity` for a number and `--log-level` for a
name.

Both formats write to stderr. With `json`, every line is JSON:

- klog (client-go) lines go through the same logger.
- Go standard library `log` lines are error lines with logger `stdlib`. That
  includes the `http: TLS handshake error` lines of controller-runtime's
  webhook and metrics servers, which have no `ErrorLog` of their own (this
  repository creates no other `http.Server`).
- OpenTelemetry's internal messages use logger `otel`.

JSON output is never sampled: 1000 identical `authorization decision` calls
write 1000 lines. klog text output is not sampled either.

With `text`, standard library and OpenTelemetry lines keep their plain format,
and with `--log-level=error` client-go's own `V(0)` lines can still appear.

## Levels

Messages are logged with logr. Error lines are always written; `V(n)` lines
are written when the verbosity is at least `n`.

| Level | klog text prefix | JSON `level` | Used for |
|-------|------------------|--------------|----------|
| `error` | `E` | `error` | Failed operations; the line carries the error and, in JSON, a `stacktrace` |
| `V(0)` | `I` | `info` | Startup configuration, warnings, state changes such as pruning, denied authorization decisions |
| `V(1)` | `I` | `debug` | Allowed and no-opinion authorization decisions, admission outcomes, reconcile steps |
| `V(2)` | `I` | `Level(-2)` | Per-request detail (`received SubjectAccessReview`, `/authorize request`), per-object reconcile detail |
| `V(3)` | `I` | `Level(-3)` | Flag dump at startup, namespace admission and reconcile internals |
| `V(4)` | `I` | `Level(-4)` | Most detailed reconcile and namespace admission tracing |

## Line format

Every JSON line has these keys, followed by the key/value pairs of the log
call and of the logger context:

| Key | Type | Meaning |
|-----|------|---------|
| `level` | string | See [Levels](#levels) |
| `ts` | string | RFC 3339 timestamp with sub-second precision |
| `logger` | string | Logger name, e.g. `Authorizer`, `setup`, `stdlib`, `otel` (omitted when unnamed) |
| `msg` | string | Message from the catalog |
| `error` | string | Error text (error lines only; klog text uses `err`) |
| `stacktrace` | string | Go stack trace (error lines only, JSON only) |

Context keys are added by the logger, not the call:

- Reconcilers (controller-runtime): `controller`, `controllerGroup`,
  `controllerKind`, the kind (e.g. `BindDefinition`) as `{"name": ...}`,
  `namespace`, `name`, `reconcileID`.
- CRD validation webhooks (controller-runtime): `webhookGroup`, `webhookKind`,
  the kind as `{"name": ..., "namespace": ...}`, `namespace`, `name`,
  `resource`, `user`, `requestID`.
- Namespace admission webhooks (controller-runtime): `object` as
  `{"name": ...}`, `namespace`, `name`, `resource`, `user`, `requestID`.
- Keys added with `WithValues` in this repository are listed per file in the
  catalog.

## Examples

A denied SubjectAccessReview at `--verbosity=2`, followed by an evaluation
error, in both formats. Stack traces are abbreviated.

Text (`--log-format=text`):

```text
I1113 14:04:37.101751   61910 webhook_authorizer.go:506] "received SubjectAccessReview" logger="Authorizer" namespace="team-a" user="alice" groups=["team-a","system:authenticated"] verb="get" apiGroup="" resource="secrets"
I1113 14:04:37.101828   61910 webhook_authorizer.go:713] "evaluating WebhookAuthorizer" logger="Authorizer" authorizer="deny-wa" index=0 user="alice"
I1113 14:04:37.101846   61910 webhook_authorizer.go:565] "authorization decision" logger="Authorizer" decision="denied" allowed=false reason="Access denied by WebhookAuthorizer deny-wa" user="alice" groups=["team-a","system:authenticated"] authorizer="deny-wa" evaluatedCount=1 skippedCount=0 latency="252.792µs" verb="get" apiGroup="" resource="secrets" namespace="team-a" matchedField="deniedPrincipal" matchedRule=0
I1113 14:04:37.101921   61910 webhook_authorizer.go:135] "/authorize request" logger="Authorizer" remoteAddr="192.0.2.1:1234" method="POST" status=200 latency="332.084µs"
E1113 14:04:37.101927   61910 webhook_authorizer.go:371] "failed to list global WebhookAuthorizers" err="etcdserver: request timed out" logger="Authorizer" user="alice" latency="5.001s"
```

JSON (`--log-format=json`):

```json
{"level":"Level(-2)","ts":"2026-11-13T14:21:52.447822+01:00","logger":"Authorizer","msg":"received SubjectAccessReview","namespace":"team-a","user":"alice","groups":["team-a","system:authenticated"],"verb":"get","apiGroup":"","resource":"secrets"}
{"level":"Level(-2)","ts":"2026-11-13T14:21:52.448562+01:00","logger":"Authorizer","msg":"evaluating WebhookAuthorizer","authorizer":"deny-wa","index":0,"user":"alice"}
{"level":"info","ts":"2026-11-13T14:21:52.448574+01:00","logger":"Authorizer","msg":"authorization decision","decision":"denied","allowed":false,"reason":"Access denied by WebhookAuthorizer deny-wa","user":"alice","groups":["team-a","system:authenticated"],"authorizer":"deny-wa","evaluatedCount":1,"skippedCount":0,"latency":"15.829042ms","verb":"get","apiGroup":"","resource":"secrets","namespace":"team-a","matchedField":"deniedPrincipal","matchedRule":0}
{"level":"Level(-2)","ts":"2026-11-13T14:21:52.448596+01:00","logger":"Authorizer","msg":"/authorize request","remoteAddr":"192.0.2.1:1234","method":"POST","status":200,"latency":"15.852208ms"}
{"level":"error","ts":"2026-11-13T14:21:52.448599+01:00","logger":"Authorizer","msg":"failed to list global WebhookAuthorizers","user":"alice","latency":"5.001s","error":"etcdserver: request timed out","stacktrace":"github.com/telekom/auth-operator/internal/webhook/authorization...."}
```

## Authorization decisions

The webhook server logs one `authorization decision` line per evaluated
SubjectAccessReview (logger `Authorizer`): `denied` at `V(0)`, `allowed` and
`no-opinion` at `V(1)`.

Requests answered before evaluation have no decision line:

| Level | Message | Response |
|-------|---------|----------|
| — | no log line | HTTP 405 Method Not Allowed for a method other than POST |
| — | no log line | HTTP 415 Unsupported Media Type for a Content-Type other than `application/json` |
| `error` | `failed to load /authorize bearer token` | Denied, `unauthorized` |
| `V(1)` | `rejecting unauthenticated SubjectAccessReview request because no bearer token is configured` | Denied, `unauthorized` |
| `V(1)` | `rejecting unauthorized SubjectAccessReview request` | Denied, `unauthorized` |
| `V(0)` | `failed to decode SubjectAccessReview request` | Denied, `invalid request body` |
| `V(1)` | `rejecting malformed SubjectAccessReview` | Denied with the validation reason |
| `V(1)` | `rate limit exceeded, rejecting request` | Denied, `rate limit exceeded` |

The 405 and 415 checks are skipped with `--disable-authorize-request-checks`.

Evaluation errors are error lines whose message is `failed to list global
WebhookAuthorizers`, `failed to list scoped WebhookAuthorizers` or `failed to
evaluate SubjectAccessReview` (shown as `<message>` in the catalog); the
response is denied. `failed to verify live WebhookAuthorizer denies before
bridge allow` is followed by a `no-opinion` decision line.

Errors writing the answer are error lines without a decision change:
`failed to encode SubjectAccessReview response` (HTTP 500),
`failed to write SubjectAccessReview response`, `failed to encode denied
response`, `failed to encode rate-limit response` and `failed to close request
body`.

Other per-request lines of logger `Authorizer`: `allowing unauthenticated
SubjectAccessReview request` (`V(1)`, only with
`--allow-unauthenticated-authorize`), and at `V(2)` `received
SubjectAccessReview`, `evaluating WebhookAuthorizer`, `namespace selector did
not match, skipping`, `skipping namespace-scoped authorizer for non-namespaced
SAR`, `skipping unconfigured WebhookAuthorizer` and the access line
`/authorize request`.

### Authorization decision fields

| Key | Type | Meaning |
|-----|------|---------|
| `decision` | string | `allowed`, `denied` or `no-opinion` |
| `allowed` | bool | SubjectAccessReview `status.allowed` |
| `reason` | string | SubjectAccessReview `status.reason`, e.g. `Access denied by WebhookAuthorizer <name>` |
| `user` | string | `spec.user` |
| `groups` | array of strings | `spec.groups`, first 10 entries, then `...and N more` |
| `authorizer` | string | Deciding WebhookAuthorizer (empty when none matched) |
| `evaluatedCount` | number | WebhookAuthorizers evaluated |
| `skippedCount` | number | WebhookAuthorizers skipped (selector mismatch, not configured) |
| `latency` | string | Evaluation time as a Go duration, e.g. `1.2ms` |
| `verb` | string | Resource or non-resource verb |
| `apiGroup` | string | Resource API group (resource requests only) |
| `resource` | string | Resource (resource requests only) |
| `namespace` | string | Namespace (resource requests only; empty for cluster scope) |
| `path` | string | URL path (non-resource requests only) |
| `matchedField` | string | Field that decided, e.g. `deniedPrincipal` (when set) |
| `matchedRule` | number | Index of the deciding rule (when set) |

SubjectAccessReview `spec.extra` values, `uid` and the request body are not
logged. To keep only denials, run at `--verbosity=0`; to keep every decision,
run at `--verbosity=1` or higher.

## Fields that can hold personal data

These keys can carry user identities, group memberships, namespace names or
client IP addresses. Treat logs that contain them as personal data.
`go test ./hack/logref` fails when a logged key that looks like one of these
is missing here. Free-text values such as `reason`, `error` and `msg` can
also quote a user or namespace.

| Key | Content |
|-----|---------|
| `user` | Requesting user name (authorization decisions, SAR logs, CRD validation webhook context) |
| `username` | Requesting user name (namespace admission webhooks) |
| `groups` | Requesting user's groups (capped at 10) |
| `impersonatedUser` | ServiceAccount identity used for impersonated applies |
| `serviceAccount` | ServiceAccount name |
| `saName` | ServiceAccount name |
| `namespace` | Namespace name, which can name a team or person |
| `saNamespace` | ServiceAccount namespace |
| `targetNamespace` | Target namespace name |
| `bindingNamespace` | Namespace of a generated RoleBinding |
| `explicitNamespace` | Namespace named explicitly in a BindDefinition |
| `objectNamespace` | Namespace of the object that triggered a reconcile |
| `activeNamespaceNames` | Namespace names a BindDefinition selects |
| `path` | Non-resource URL path |
| `remoteAddr` | Client IP address and port of `/authorize` callers (`V(2)`) |

## Never logged

- Bearer tokens, including the `/authorize` token file contents, and
  ServiceAccount tokens.
- Secret data, certificates and private keys.
- SubjectAccessReview and AdmissionReview request bodies, request headers and
  `extra` values.
- Flag values whose names match `token`, `secret`, `password`, `passphrase`,
  `key`, `auth`, `credential`, `private`, `cert`, `bearer`, `api-key` or
  `client-id`: the `V(3)` `flag` line prints `[REDACTED]`.

`go test ./hack/logref` fails if a log key names a token, password,
passphrase, secret, credential, bearer or private value.

## Operational guidance

- **Production**: the default `--verbosity=2` logs every decision and one
  `received SubjectAccessReview` and `/authorize request` line per request.
  Use `1` to keep every authorization decision without per-request detail,
  or `0` (`--log-level=info`) to keep only denials, warnings, errors and state
  changes. `--log-level=error` drops denials too and is not suitable for audit.
- **SIEM**: use `--log-format=json` and select
  `msg == "authorization decision"`. Keep the verbosity at `1` or higher if
  allowed decisions must be audited.
- **Debugging**: raise to `3` or `4` (`--log-level=debug`) to trace reconciles
  and namespace admission; `3` also dumps all flags (redacted). Lower it again
  afterwards, volume grows with the number of objects and requests.

## Message catalog

Generated from the logger call sites. Error lines also carry `error`
(`err` in text); context keys from [Line format](#line-format) are not
repeated. `%s`-style placeholders come from `fmt.Sprintf`; `<name>` marks a
message passed in a variable.

<!-- BEGIN GENERATED LOG CATALOG: go test ./hack/logref -update -->

### Startup

Runs in: `controller, webhook`.

#### `cmd/root.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `command failed` | — |
| V(0) | `app info` | `name`, `version`, `commit` |
| V(0) | `startup flags` | `verbosity`, `logFormat`, `namespace`, `health-probe-bind-address`, `metrics-bind-address` |
| V(3) | `flag` | `name`, `value` |

### Controller manager setup

Runs in: `controller`.

#### `cmd/controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `error shutting down tracing provider` | — |
| error | `timed out waiting for CRDs to be established` | `requiredGVKs` |
| V(0) | `BindDefinition reconciler configured successfully` | — |
| V(0) | `BindDefinition reconciler is disabled` | — |
| V(0) | `RBACPolicy reconciler configured successfully` | — |
| V(0) | `RBACPolicy reconciler is disabled` | — |
| V(0) | `RestrictedBindDefinition reconciler configured successfully` | — |
| V(0) | `RestrictedBindDefinition reconciler is disabled` | — |
| V(0) | `RestrictedRoleDefinition reconciler configured successfully` | — |
| V(0) | `RestrictedRoleDefinition reconciler is disabled` | — |
| V(0) | `RoleDefinition reconciler configured successfully` | — |
| V(0) | `RoleDefinition reconciler is disabled` | — |
| V(0) | `WebhookAuthorizer reconciler configured successfully` | — |
| V(0) | `WebhookAuthorizer reconciler is disabled` | — |
| V(0) | `all required CRDs are established` | — |
| V(0) | `controller configuration` | `enableLeaderElection`, `bindDefinitionConcurrency`, `roleDefinitionConcurrency`, `webhookAuthorizerConcurrency`, `rbacPolicyConcurrency`, `restrictedBindDefinitionConcurrency`, `restrictedRoleDefinitionConcurrency`, `cacheSyncTimeout`, `gracefulShutdownTimeout`, `namespace`, `trackerSyncInterval`, `trackerResyncInterval` |
| V(0) | `creating BindDefinition reconciler` | `concurrency` |
| V(0) | `creating RBACPolicy reconciler` | `concurrency` |
| V(0) | `creating RestrictedBindDefinition reconciler` | `concurrency` |
| V(0) | `creating RestrictedRoleDefinition reconciler` | `concurrency` |
| V(0) | `creating RoleDefinition reconciler` | `concurrency` |
| V(0) | `creating WebhookAuthorizer reconciler` | `concurrency` |
| V(0) | `field indexes configured for cached client` | — |
| V(0) | `starting controller` | — |
| V(0) | `starting manager - waiting for cache sync` | `timeout` |
| V(0) | `tracing enabled` | `endpoint`, `samplingRate` |
| V(0) | `waiting for required CRDs to be established` | `timeout` |
| V(1) | `API server /metrics capability probe unavailable; constrained impersonation support will be inferred from the server version` | `error` |
| V(1) | `API server version lookup unavailable for capability detection` | `error` |

### Webhook server setup

Runs in: `webhook`.

#### `cmd/webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `error shutting down tracing provider` | — |
| V(0) | `/authorize method and Content-Type checks disabled (transitional opt-out)` | — |
| V(0) | `WARNING: emergency namespace authorization disabled: --emergency-namespace-tenant unset` | — |
| V(0) | `all webhooks configured successfully` | — |
| V(0) | `allowing unauthenticated /authorize requests; configure --authorize-auth-token-file for production` | — |
| V(0) | `disabling http/2` | — |
| V(0) | `field indexes configured for cached client` | — |
| V(0) | `rate limiting enabled for /authorize` | `rateLimit`, `burst` |
| V(0) | `registering authorization webhook at /authorize` | — |
| V(0) | `setting up BindDefinition webhook` | — |
| V(0) | `setting up Namespace mutator webhook` | `tdgMigration`, `capiOperatorUpdateBypass`, `strictSANamespaceOwnership`, `emergencyNamespaceTenant`, `emergencyNamespaceCrossTenant` |
| V(0) | `setting up Namespace validator webhook` | `tdgMigration`, `capiOperatorUpdateBypass`, `strictSANamespaceOwnership`, `emergencyNamespaceTenant`, `emergencyNamespaceCrossTenant` |
| V(0) | `setting up RBACPolicy validating webhook` | — |
| V(0) | `setting up RestrictedBindDefinition validating webhook` | — |
| V(0) | `setting up RestrictedRoleDefinition validating webhook` | — |
| V(0) | `setting up RoleDefinition webhook` | — |
| V(0) | `setting up WebhookAuthorizer validating webhook` | — |
| V(0) | `starting manager` | — |
| V(0) | `starting webhook server` | `port`, `certsDir`, `enableHTTP2`, `disableCertRotation`, `namespace`, `bindDefinitionNamespaceSelectorLabelGroups` |
| V(0) | `tracing enabled` | `endpoint`, `samplingRate` |

### Reconcilers

Runs in: `controller`.

#### `internal/controller/authorization/binddefinition_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Delete reconcile failed` | `bindDefinition` |
| error | `Error occurred in reconcileResources` | `bindDefinition` |
| error | `Expected *Namespace` | `got` |
| error | `Failed to add finalizer` | `bindDefinition` |
| error | `Failed to add tracking annotation to external ServiceAccount` | `serviceAccount`, `namespace` |
| error | `Failed to apply BindDefinition status` | `bindDefinition` |
| error | `Failed to apply ServiceAccount` | `bindDefinitionName`, `serviceAccount` |
| error | `Failed to compute desired BindDefinition resource keys` | `bindDefinition` |
| error | `Failed to ensure ClusterRoleBinding` | `bindDefinitionName`, `clusterRoleBindingName` |
| error | `Failed to ensure RoleBinding` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| error | `Failed to fetch BindDefinition` | `bindDefinition` |
| error | `Failed to prune BindDefinition bindings after missing-role-policy=error` | `bindDefinition` |
| error | `Failed to prune stale BindDefinition resources` | `bindDefinition` |
| error | `Failed to update managed ServiceAccount source names` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| error | `Unable to collect namespaces` | `bindDefinitionName` |
| error | `failed to apply BindDefinition status` | `name` |
| error | `failed to collect namespaces for RoleBinding cleanup` | `bindDefinitionName` |
| error | `failed to list BindDefinition resources` | `namespace` |
| V(0) | `Reconciliation blocked by missing-role-policy=error` | `bindDefinition`, `missingCount` |
| V(0) | `Requeuing after deleting RoleBinding before immutable roleRef change` | `bindDefinition`, `requeueAfter` |
| V(0) | `Requeuing with backoff due to missing role references` | `bindDefinition`, `missingCount`, `requeueAfter` |
| V(0) | `Skipping explicitly external ServiceAccount because it does not exist` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(0) | `Some referenced roles do not exist - bindings will be created but may not be effective` | `bindDefinitionName`, `missingRoles` |
| V(0) | `Target binding already exists without this BindDefinition owner` | `bindingKind`, `bindingName`, `bindingNamespace`, `owner`, `ownerUID` |
| V(0) | `Using externally managed ServiceAccount after SSA ownership conflict` | `bindDefinitionName`, `serviceAccount`, `namespace`, `fieldManagers` |
| V(0) | `pruning stale ClusterRoleBinding` | `name`, `bindDefinition` |
| V(0) | `pruning stale RoleBinding` | `namespace`, `name`, `bindDefinition` |
| V(0) | `pruning stale ServiceAccount` | `namespace`, `name`, `bindDefinition` |
| V(1) | `=== Reconcile END ===` | `bindDefinition`, `duration` |
| V(1) | `=== Reconcile START ===` | `bindDefinition`, `namespace` |
| V(1) | `BindDefinition marked for deletion - cleaning up resources` | `bindDefinitionName` |
| V(1) | `BindDefinition marked for deletion, starting delete reconcile` | `bindDefinition`, `deletionTimestamp` |
| V(1) | `BindDefinition not found (deleted), skipping reconcile` | `bindDefinition` |
| V(1) | `ClusterRole not found` | `clusterRole` |
| V(1) | `Delete reconcile completed successfully` | `bindDefinition` |
| V(1) | `Ensured ServiceAccount` | `bindDefinitionName`, `serviceAccount`, `namespace`, `result` |
| V(1) | `Reconcile completed successfully` | `bindDefinition`, `requeueAfter` |
| V(1) | `Role not found` | `role`, `namespace` |
| V(1) | `ServiceAccount is owned by another BindDefinition, adding shared ownership` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(1) | `ServiceAccount reconciliation complete` | `bindDefinitionName`, `generatedSAs`, `externalSAs` |
| V(1) | `Skipping RoleBinding in terminating namespace` | `bindDefinitionName`, `namespace` |
| V(1) | `Skipping ServiceAccount in terminating namespace` | `bindDefinitionName`, `namespace` |
| V(1) | `Skipping pre-existing ServiceAccount (not owned by any BindDefinition)` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(1) | `reconcileDelete completed successfully` | `bindDefinitionName` |
| V(1) | `skipping previously generated ServiceAccount without current ownerRef` | `namespace`, `name`, `bindDefinition` |
| V(1) | `starting reconcileDelete` | `bindDefinition`, `namespace` |
| V(2) | `Active namespaces filtered` | `bindDefinition`, `activeNamespaceCount`, `activeNamespaceNames` |
| V(2) | `Adding finalizer to BindDefinition` | `bindDefinition` |
| V(2) | `BindDefinition fetched successfully` | `bindDefinition`, `generation`, `resourceVersion`, `isDeleting`, `subjectCount`, `clusterRoleRefCount`, `roleBindingCount` |
| V(2) | `Collecting namespaces for BindDefinition` | `bindDefinition` |
| V(2) | `Ensured ClusterRoleBinding` | `bindDefinitionName`, `clusterRoleBindingName`, `result` |
| V(2) | `Ensured RoleBinding` | `bindDefinitionName`, `roleBindingName`, `namespace`, `result` |
| V(2) | `Fetching BindDefinition from API` | `bindDefinition` |
| V(2) | `Marking BindDefinition as Ready and applying status` | `bindDefinition`, `generation`, `missingRoleRefCount` |
| V(2) | `Marking BindDefinition as Reconciling` | `bindDefinition`, `generation` |
| V(2) | `Namespaces collected` | `bindDefinition`, `totalNamespaces` |
| V(2) | `Resource reconciliation completed` | `bindDefinition`, `missingRoleRefCount` |
| V(2) | `RoleBindings reconciliation completed` | `bindDefinitionName` |
| V(2) | `ServiceAccount target namespace not found` | `bindDefinitionName`, `namespace` |
| V(2) | `Starting resource reconciliation` | `bindDefinition`, `subjects`, `clusterRoleRefs`, `roleBindings` |
| V(2) | `Status applied successfully` | `bindDefinition`, `observedGeneration` |
| V(2) | `namespaceToBindDefinitionRequests triggered` | `objectName`, `objectNamespace` |
| V(2) | `processing ClusterRoleBindings for deletion` | `bindDefinitionName`, `clusterRoleRefCount` |
| V(2) | `processing namespace event` | `namespace`, `phase` |
| V(2) | `processing namespace for RoleBinding cleanup` | `bindDefinitionName`, `namespace`, `index` |
| V(2) | `processing namespaces for RoleBinding cleanup` | `bindDefinitionName`, `namespaceCount` |
| V(2) | `processing subjects for deletion` | `bindDefinitionName`, `subjectCount` |
| V(2) | `reconcileResources: ClusterRoleBindings ensured` | `bindDefinition` |
| V(2) | `reconcileResources: Complete` | `bindDefinition`, `crbCount`, `rbCount`, `generatedSACount`, `missingRoleRefCount` |
| V(2) | `reconcileResources: Ensuring ClusterRoleBindings` | `bindDefinition`, `clusterRoleRefCount` |
| V(2) | `reconcileResources: Ensuring RoleBindings` | `bindDefinition`, `roleBindingSpecCount` |
| V(2) | `reconcileResources: Ensuring ServiceAccounts` | `bindDefinition`, `subjectCount` |
| V(2) | `reconcileResources: Role reference validation complete` | `bindDefinition`, `missingCount`, `missingRoles` |
| V(2) | `reconcileResources: RoleBindings ensured` | `bindDefinition` |
| V(2) | `reconcileResources: ServiceAccounts ensured` | `bindDefinition`, `generatedCount`, `externalCount` |
| V(2) | `reconcileResources: Skipping role reference validation (policy=ignore)` | `bindDefinition` |
| V(2) | `reconcileResources: Starting` | `bindDefinition`, `activeNamespaceCount` |
| V(2) | `reconcileResources: Using missing-role policy` | `bindDefinition`, `policy` |
| V(2) | `removing BindDefinition finalizer` | `bindDefinitionName` |
| V(2) | `returning reconciliation requests` | `namespace`, `requestCount`, `totalBindDefinitions` |
| V(3) | `ClusterRoleBinding delete result` | `bindDefinitionName`, `clusterRoleRef`, `result` |
| V(3) | `enqueuing BindDefinition reconciliation` | `namespace`, `bindDefinition` |
| V(3) | `found BindDefinitions` | `namespace`, `bindDefinitionCount` |
| V(3) | `looking up ClusterRoleBinding` | `bindDefinitionName`, `index`, `clusterRoleRef` |
| V(3) | `processing RoleBinding spec` | `bindDefinitionName`, `namespace`, `rbIndex` |
| V(3) | `processing subject` | `bindDefinitionName`, `index`, `kind`, `name`, `namespace` |
| V(3) | `reconcileResources: Validating role references` | `bindDefinition` |
| V(3) | `skipping BindDefinition (no matching namespace routing criteria)` | `namespace`, `bindDefinition` |

#### `internal/controller/authorization/binddefinition_helpers.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Failed to check if ServiceAccount is referenced by other BindDefinitions` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| error | `Failed to delete ClusterRoleBinding` | `bindDefinitionName`, `clusterRoleBindingName` |
| error | `Failed to delete RoleBinding` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| error | `Failed to delete ServiceAccount` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| error | `Failed to get external ServiceAccount during cleanup` | `serviceAccount`, `namespace` |
| error | `Failed to remove tracking annotation from external ServiceAccount` | `serviceAccount`, `namespace` |
| error | `Failed to update metadata on retained ServiceAccount` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| error | `Unable to fetch ClusterRoleBinding from Kubernetes API` | `bindDefinitionName`, `clusterRoleBindingName` |
| error | `Unable to fetch RoleBinding from Kubernetes API` | `bindDefinitionName`, `namespace`, `roleBindingName` |
| error | `Unable to fetch ServiceAccount from Kubernetes API` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| error | `failed to apply Stalled status via SSA` | `bindDefinitionName` |
| error | `failed to apply status (non-fatal)` | `resource` |
| V(1) | `Added referenced-by annotation to external ServiceAccount` | `serviceAccount`, `namespace`, `bindDefinition` |
| V(1) | `Cannot delete ClusterRoleBinding - no OwnerRef` | `bindDefinitionName`, `clusterRoleBindingName` |
| V(1) | `Cannot delete RoleBinding - no OwnerRef` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| V(1) | `Cannot delete ServiceAccount - no OwnerRef` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(1) | `Cleanup ClusterRoleBinding` | `bindDefinitionName`, `clusterRoleBindingName` |
| V(1) | `Cleanup RoleBinding` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| V(1) | `Cleanup ServiceAccount` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(1) | `Invalid external SA reference format, skipping cleanup` | `reference` |
| V(1) | `Removed referenced-by annotation from external ServiceAccount` | `serviceAccount`, `namespace`, `bindDefinition` |
| V(1) | `Skipping update in terminating namespace` | `bindDefinitionName`, `namespace` |
| V(1) | `Successfully deleted ClusterRoleBinding` | `bindDefinitionName`, `clusterRoleBindingName` |
| V(1) | `Successfully deleted RoleBinding` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| V(1) | `Successfully deleted ServiceAccount` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(1) | `marking BindDefinition as stalled` | `bindDefinitionName`, `error` |
| V(2) | `ClusterRoleBinding already deleted` | `bindDefinitionName`, `clusterRoleBindingName` |
| V(2) | `ClusterRoleBinding not found (already deleted)` | `bindDefinitionName`, `clusterRoleBindingName` |
| V(2) | `RoleBinding already deleted during deletion attempt` | `bindDefinitionName`, `roleBindingName`, `namespace` |
| V(2) | `RoleBinding not found (already deleted)` | `bindDefinitionName`, `namespace`, `roleBindingName` |
| V(2) | `ServiceAccount already deleted during deletion attempt` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(2) | `ServiceAccount is referenced by other BindDefinitions - NOT deleting, updating source-names` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(2) | `ServiceAccount not found (already deleted)` | `bindDefinitionName`, `serviceAccount`, `namespace` |
| V(2) | `Updated managed ServiceAccount source-names annotation` | `serviceAccount`, `namespace`, `bindDefinition` |
| V(2) | `Updated metadata on retained ServiceAccount` | `bindDefinitionName`, `serviceAccount` |
| V(3) | `marking BindDefinition as ready` | `bindDefinitionName` |

#### `internal/controller/authorization/client_label_getter.go`

| Level | Message | Keys |
|-------|---------|------|
| V(2) | `failed to get clusterrole labels` | `clusterRole`, `error` |
| V(2) | `failed to get namespace labels` | `namespace`, `error` |
| V(2) | `failed to get role labels` | `namespace`, `role`, `error` |

#### `internal/controller/authorization/constrained_impersonation.go`

| Level | Message | Keys |
|-------|---------|------|
| V(0) | `constrained impersonation grant is inert on this API server` | `mode`, `reason`, `serverVersion` |
| V(1) | `constrained impersonation grant leaves the legacy impersonate fallback reachable` | `mode` |
| V(1) | `constrained impersonation support could not be determined` | `mode`, `reason`, `serverVersion` |

#### `internal/controller/authorization/rbacpolicy_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to apply RBACPolicy status` | `rbacPolicy` |
| error | `failed to apply Stalled status via SSA` | `rbacPolicy` |
| error | `failed to list RestrictedBindDefinitions` | `rbacPolicy` |
| error | `failed to list RestrictedRoleDefinitions` | `rbacPolicy` |
| V(1) | `=== Reconcile END ===` | `rbacPolicy`, `duration` |
| V(1) | `=== Reconcile START ===` | `rbacPolicy` |
| V(1) | `RBACPolicy not found (deleted), skipping` | `rbacPolicy` |
| V(1) | `Reconcile completed successfully` | `rbacPolicy` |
| V(1) | `marking RBACPolicy as stalled` | `rbacPolicy`, `error` |
| V(2) | `bound resource count updated` | `rbacPolicy`, `restrictedBindDefinitions`, `restrictedRoleDefinitions`, `totalBound` |

#### `internal/controller/authorization/restricted_helpers.go`

| Level | Message | Keys |
|-------|---------|------|
| V(0) | `Target binding already exists without this RestrictedBindDefinition owner` | `bindingKind`, `bindingName`, `bindingNamespace`, `owner`, `ownerUID` |
| V(0) | `Target role already exists without this RestrictedRoleDefinition owner` | `roleName`, `targetRole`, `owner`, `ownerUID` |
| V(0) | `Target role is already controlled by a different owner` | `roleName`, `existingOwnerKind`, `existingOwner`, `existingOwnerUID` |
| V(0) | `policy violations detected` | `name`, `violationCount`, `violations` |

#### `internal/controller/authorization/restricted_policy_helper.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to list %ss for policy` | `policy` |
| V(0) | `referenced RBACPolicy is deleting` | `name`, `policyRef` |
| V(0) | `referenced RBACPolicy not found` | `name`, `policyRef` |
| V(2) | `policyRef field index unavailable, falling back to full %s scan` | `policy` |

#### `internal/controller/authorization/restrictedbinddefinition_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Expected *Namespace` | `got` |
| error | `Expected *ServiceAccount` | `got` |
| error | `failed to apply RestrictedBindDefinition status` | `name` |
| error | `failed to apply Stalled status via SSA` | `name` |
| error | `failed to apply status via SSA` | `name` |
| error | `failed to deprovision during deletion` | `name` |
| error | `failed to list RestrictedBindDefinitions by ServiceAccount namespace index` | `namespace` |
| error | `failed to list RestrictedBindDefinitions by ServiceAccount subject index` | `serviceAccount` |
| error | `failed to list RestrictedBindDefinitions by explicit namespace index` | `namespace` |
| error | `failed to list RestrictedBindDefinitions by selector index` | — |
| error | `failed to list RestrictedBindDefinitions for ClusterRole event` | `clusterRole` |
| error | `failed to list RestrictedBindDefinitions for Role event` | `namespace`, `role` |
| error | `failed to list RestrictedBindDefinitions` | — |
| V(0) | `ServiceAccount has this RestrictedBindDefinition controller ownerRef but no generated status record, skipping management` | `serviceAccount`, `namespace`, `ownerName`, `ownerUID` |
| V(0) | `ServiceAccount owned by a different RestrictedBindDefinition, skipping adoption` | `serviceAccount`, `namespace`, `ownerUID`, `currentUID` |
| V(0) | `ServiceAccount owner reference does not match current RestrictedBindDefinition, skipping management` | `serviceAccount`, `namespace`, `ownerName`, `ownerUID`, `currentName`, `currentUID` |
| V(0) | `deprovisioning RestrictedBindDefinition` | `name` |
| V(0) | `pruning stale ClusterRoleBinding` | `name`, `rbd` |
| V(0) | `pruning stale RoleBinding` | `namespace`, `name`, `rbd` |
| V(0) | `pruning stale ServiceAccount` | `namespace`, `name`, `rbd` |
| V(1) | `=== Reconcile END ===` | `restrictedBindDefinition`, `duration` |
| V(1) | `=== Reconcile START ===` | `restrictedBindDefinition` |
| V(1) | `RestrictedBindDefinition marked for deletion` | `name` |
| V(1) | `RestrictedBindDefinition not found (deleted), skipping` | `name` |
| V(1) | `conflict adding finalizer, requeuing` | `name` |
| V(1) | `failed to verify live RestrictedBindDefinition generated ServiceAccount status` | `name`, `serviceAccount`, `namespace`, `error` |
| V(1) | `finalizer removed, deletion complete` | `name` |
| V(1) | `marking RestrictedBindDefinition as stalled` | `name`, `error`, `detail` |
| V(1) | `referenced role not found` | — |
| V(1) | `skipping ServiceAccount adoption: DisableAdoption is true` | `serviceAccount`, `namespace` |
| V(1) | `skipping ServiceAccount with spoofable ownerRef but no generated status record` | `namespace`, `name`, `rbd` |
| V(1) | `skipping generated ServiceAccount: AllowAutoCreate is false` | `serviceAccount`, `namespace` |
| V(1) | `skipping generated ServiceAccount: namespace is not allowed by policy` | `serviceAccount`, `namespace` |
| V(1) | `skipping pre-existing ServiceAccount` | `serviceAccount`, `namespace` |
| V(2) | `SA namespace not found, skipping` | `namespace` |
| V(2) | `field index not available, falling back to full RestrictedBindDefinition scan` | `serviceAccount` |
| V(2) | `field indexes not available, falling back to full RestrictedBindDefinition scan` | — |
| V(2) | `using impersonated apply identity` | `name`, `impersonatedUser`, `policy` |

#### `internal/controller/authorization/restrictedroledefinition_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Expected *Namespace` | `got` |
| error | `failed to apply RestrictedRoleDefinition status` | `name` |
| error | `failed to apply Stalled status via SSA` | `name` |
| error | `failed to apply status via SSA` | `name` |
| error | `failed to list RestrictedRoleDefinitions by target namespace` | `namespace` |
| error | `failed to list RestrictedRoleDefinitions for namespace` | `namespace` |
| error | `failed to list RestrictedRoleDefinitions` | — |
| V(0) | `deprovisioning RestrictedRoleDefinition` | `name` |
| V(0) | `skipping deprovision of target role because it is not owned by this RestrictedRoleDefinition` | `targetRole`, `targetName`, `targetNamespace`, `rrd` |
| V(1) | `=== Reconcile END ===` | `restrictedRoleDefinition`, `duration` |
| V(1) | `=== Reconcile START ===` | `restrictedRoleDefinition` |
| V(1) | `ResourceTracker not started yet - requeuing` | `name` |
| V(1) | `RestrictedRoleDefinition not found (deleted), skipping` | `name` |
| V(1) | `conflict adding finalizer, requeuing` | `name` |
| V(1) | `finalizer removed, deletion complete` | `name` |
| V(1) | `marking RestrictedRoleDefinition as stalled` | `name`, `error`, `detail` |
| V(1) | `role ensured` | `name`, `targetRole`, `targetName` |
| V(2) | `discovery and filtering complete` | `name`, `ruleCount` |
| V(2) | `targetNamespace field index unavailable, falling back to full RestrictedRoleDefinition scan` | `namespace` |
| V(2) | `using impersonated apply identity` | `name`, `impersonatedUser`, `policy` |

#### `internal/controller/authorization/rolebinding_terminator_controller.go`

Context keys added with `WithValues`: `bindDefinitionName`, `roleBinding`.

| Level | Message | Keys |
|-------|---------|------|
| error | `Unable to fetch RoleBinding resource from Kubernetes API` | — |
| error | `failed to add finalizer to RoleBinding` | — |
| error | `failed to check if namespace has resources` | `namespace` |
| error | `failed to clear Namespace termination blocked status` | `namespace` |
| error | `failed to get API resources from ResourceTracker` | `namespace` |
| error | `failed to list resource while checking namespace termination` | `namespace`, `resource` |
| error | `failed to remove finalizer from RoleBinding with invalid BindDefinition owner` | — |
| error | `failed to remove finalizer from RoleBinding` | `roleBindingName`, `roleBinding`, `namespace` |
| error | `failed to remove finalizer from RoleBinding` | — |
| error | `failed to update Namespace status with blocking resources information` | `namespace` |
| error | `failed to verify owning BindDefinition for RoleBinding` | — |
| V(1) | `ResourceTracker not started yet - requeuing reconciliation` | `namespace` |
| V(1) | `added finalizer to RoleBinding` | — |
| V(1) | `blocking resource found` | `namespace`, `resourceType`, `count` |
| V(1) | `removed finalizer from RoleBinding with invalid BindDefinition owner` | `ownerError` |
| V(1) | `removed finalizer from RoleBinding` | — |
| V(1) | `successfully removed finalizer from RoleBinding in terminating namespace` | — |
| V(1) | `terminating namespace has no more resources - proceeding to remove RoleBinding finalizers` | — |
| V(1) | `terminating namespace still has resources - NOT removing RoleBinding finalizer` | `namespace` |
| V(2) | `found blocking resources in namespace` | `namespace`, `blockingResourceCount` |
| V(2) | `found resources in namespace - will NOT remove finalizers` | `namespace`, `gvr`, `itemCount` |
| V(2) | `namespace has no resources - can remove finalizers` | `namespace`, `resourcesChecked`, `resourcesSkipped` |
| V(2) | `reconcileTerminatingNamespaces completed` | — |
| V(2) | `removing finalizer from RoleBinding in terminating namespace` | — |
| V(2) | `returning cached blocking resources` | `namespace`, `cacheAge`, `blockingResourceCount` |
| V(2) | `starting namespace resource check` | `namespace` |
| V(3) | `RoleBinding does not have finalizer` | `roleBindingName` |
| V(3) | `listing resource in namespace` | `namespace`, `gvr` |
| V(3) | `no resources found` | `namespace`, `gvr` |
| V(4) | `skipping cluster-scoped resource` | `namespace`, `resource`, `groupVersion` |
| V(4) | `skipping malformed GroupVersion` | `namespace`, `groupVersion`, `error` |
| V(4) | `skipping resource without list verb` | `namespace`, `resource`, `groupVersion` |
| V(4) | `skipping rolebinding` | `namespace`, `resource`, `groupVersion` |
| V(4) | `skipping subresource` | `namespace`, `resource`, `groupVersion` |

#### `internal/controller/authorization/roledefinition_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Delete reconcile failed` | `roleDefinition` |
| error | `Failed to build constrained impersonation rules` | `roleDefinition` |
| error | `Failed to ensure finalizer` | `roleDefinition` |
| error | `Failed to ensure role` | `roleDefinition` |
| error | `Failed to fetch RoleDefinition` | `roleDefinition` |
| error | `failed to apply final status` | `roleDefinitionName` |
| error | `failed to apply status before requeue` | `roleDefinitionName` |
| error | `failed to clean up invalid aggregateFrom target` | `roleDefinitionName` |
| error | `failed to filter API resources` | `roleDefinitionName` |
| error | `failed to get API resources` | `roleDefinitionName` |
| error | `failed to list RoleDefinition resources` | — |
| error | `invalid RoleDefinition spec` | `roleDefinitionName` |
| error | `invalid stored aggregateFrom selector` | `roleDefinitionName` |
| error | `unable to fetch RoleDefinition` | `roleDefinitionName` |
| V(1) | `=== Reconcile END ===` | `roleDefinition`, `duration` |
| V(1) | `=== Reconcile START ===` | `roleDefinition`, `namespace` |
| V(1) | `Delete reconcile completed successfully` | `roleDefinition` |
| V(1) | `Reconcile completed successfully` | `roleDefinition`, `requeueAfter` |
| V(1) | `ResourceTracker not started yet - requeuing` | `roleDefinitionName` |
| V(1) | `RoleDefinition marked for deletion, starting delete reconcile` | `roleDefinition`, `deletionTimestamp` |
| V(1) | `RoleDefinition not found (deleted), skipping reconcile` | `roleDefinition` |
| V(2) | `Applying final status` | `roleDefinition`, `generation` |
| V(2) | `Building role object` | `roleDefinition` |
| V(2) | `Discovering and filtering resources` | `roleDefinition` |
| V(2) | `Discovery complete` | `roleDefinition`, `ruleCount` |
| V(2) | `Discovery phase returned early` | `roleDefinition`, `error`, `requeueAfter` |
| V(2) | `Ensuring finalizer` | `roleDefinition` |
| V(2) | `Ensuring role` | `roleDefinition`, `ruleCount`, `isAggregating` |
| V(2) | `Fetching RoleDefinition from API` | `roleDefinition` |
| V(2) | `Role ensured successfully` | `roleDefinition` |
| V(2) | `RoleDefinition fetched successfully` | `roleDefinition`, `generation`, `resourceVersion`, `isDeleting`, `targetName` |
| V(2) | `RoleDefinition not found - already deleted` | `roleDefinitionName` |
| V(2) | `RoleDefinition retrieved` | `roleDefinitionName`, `targetRole`, `targetName` |
| V(2) | `Skipping discovery for aggregating ClusterRole` | `roleDefinition`, `selectorCount` |
| V(2) | `resource discovery and filtering completed` | `roleDefinitionName`, `rulesCount` |
| V(2) | `returning reconciliation requests` | `requestCount` |
| V(3) | `enqueuing RoleDefinition reconciliation` | `roleDefinition`, `index` |
| V(3) | `filtering API resources for RoleDefinition` | `roleDefinition`, `apiGroupCount` |
| V(3) | `found RoleDefinitions` | `roleDefinitionCount` |

#### `internal/controller/authorization/roledefinition_helpers.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `Failed to add finalizer` | `roleDefinitionName` |
| error | `Failed to apply ClusterRole via SSA` | `roleDefinitionName`, `roleName` |
| error | `Failed to apply DeleteCondition status` | `roleDefinitionName` |
| error | `Failed to apply Role via SSA` | `roleDefinitionName`, `roleName` |
| error | `Failed to apply status after deletion error` | `roleDefinitionName` |
| error | `Failed to delete role` | `roleDefinitionName`, `roleName` |
| error | `Failed to get role before deletion` | `roleDefinitionName`, `roleName` |
| error | `Failed to remove finalizer` | `roleDefinitionName` |
| error | `failed to apply Stalled status via SSA` | `roleDefinitionName` |
| V(0) | `Skipping cleanup of invalid aggregateFrom target because it is not owned by this RoleDefinition` | `roleDefinitionName`, `clusterRole` |
| V(0) | `Skipping deletion of target role because it is not owned by this RoleDefinition` | `roleDefinitionName`, `roleName`, `targetRole` |
| V(0) | `Target role already exists without this RoleDefinition owner` | `roleName`, `targetRole`, `owner`, `ownerUID` |
| V(0) | `Target role is already controlled by a different owner` | `roleName`, `existingOwnerKind`, `existingOwner`, `existingOwnerUID` |
| V(1) | `Role ensured successfully` | `roleDefinitionName`, `roleName` |
| V(1) | `RoleDefinition deletion completed successfully` | `roleDefinitionName` |
| V(1) | `RoleDefinition marked for deletion - cleaning up resources` | `roleDefinitionName`, `targetRole`, `targetName` |
| V(1) | `marking RoleDefinition as stalled` | `roleDefinitionName`, `error` |
| V(2) | `Adding finalizer to RoleDefinition` | `roleDefinitionName` |
| V(2) | `Attempting to delete role` | `roleDefinitionName`, `roleName` |
| V(2) | `Requeuing RoleDefinition deletion` | `roleDefinitionName` |
| V(2) | `Role disappeared before deletion - removing finalizer` | `roleDefinitionName`, `roleName` |
| V(2) | `Role not found - removing finalizer` | `roleDefinitionName`, `roleName` |

#### `internal/controller/authorization/webhookauthorizer_controller.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to apply Reconciling status via SSA` | `webhookAuthorizer` |
| error | `failed to apply Stalled status via SSA` | `webhookAuthorizer` |
| error | `failed to apply status via SSA` | `webhookAuthorizer` |
| error | `failed to fetch WebhookAuthorizer` | `webhookAuthorizer` |
| error | `failed to refresh active rules metric after WebhookAuthorizer deletion` | `webhookAuthorizer` |
| error | `failed to refresh active rules metric` | `webhookAuthorizer` |
| error | `namespace selector validation failed` | `webhookAuthorizer` |
| error | `transient error during namespace selector validation, will retry` | `webhookAuthorizer` |
| error | `webhook authorizer spec validation failed` | `webhookAuthorizer` |
| V(1) | `=== Reconcile END ===` | `webhookAuthorizer`, `duration` |
| V(1) | `=== Reconcile START ===` | `webhookAuthorizer` |
| V(1) | `WebhookAuthorizer not found (deleted), cleaning up metrics` | `webhookAuthorizer` |
| V(1) | `WebhookAuthorizer reconciled successfully` | `webhookAuthorizer`, `generation`, `requeueAfter` |
| V(1) | `marking WebhookAuthorizer as stalled` | `webhookAuthorizer`, `error` |
| V(2) | `NamespaceSelector is empty, matches all namespaces` | — |
| V(2) | `NamespaceSelector validation` | `matchingNamespaces`, `selector` |

### Authorization webhook (/authorize)

Runs in: `webhook`.

#### `internal/webhook/authorization/webhook_authorizer.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `<message>` | `user`, `latency` |
| error | `failed to close request body` | — |
| error | `failed to encode SubjectAccessReview response` | `latency` |
| error | `failed to encode denied response` | — |
| error | `failed to encode rate-limit response` | — |
| error | `failed to load /authorize bearer token` | — |
| error | `failed to verify live WebhookAuthorizer denies before bridge allow` | — |
| error | `failed to write SubjectAccessReview response` | `latency` |
| V(0) | `authorization decision` | `decision`, `allowed`, `reason`, `user`, `groups`, `authorizer`, `evaluatedCount`, `skippedCount`, `latency`, `verb`, `apiGroup`, `resource`, `namespace`, `path`, `matchedField`, `matchedRule` |
| V(0) | `failed to decode SubjectAccessReview request` | `error`, `latency` |
| V(1) | `allowing unauthenticated SubjectAccessReview request` | — |
| V(1) | `authorization decision` | `decision`, `allowed`, `reason`, `user`, `groups`, `authorizer`, `evaluatedCount`, `skippedCount`, `latency`, `verb`, `apiGroup`, `resource`, `namespace`, `path`, `matchedField`, `matchedRule` |
| V(1) | `rate limit exceeded, rejecting request` | `user`, `groups`, `latency` |
| V(1) | `rejecting malformed SubjectAccessReview` | `reason`, `user`, `latency` |
| V(1) | `rejecting unauthenticated SubjectAccessReview request because no bearer token is configured` | — |
| V(1) | `rejecting unauthorized SubjectAccessReview request` | — |
| V(2) | `/authorize request` | `remoteAddr`, `method`, `status`, `latency` |
| V(2) | `evaluating WebhookAuthorizer` | `authorizer`, `index`, `user` |
| V(2) | `namespace selector did not match, skipping` | `authorizer`, `namespace` |
| V(2) | `received SubjectAccessReview` | `namespace`, `user`, `groups`, `verb`, `apiGroup`, `resource` |
| V(2) | `received SubjectAccessReview` | `user`, `groups`, `detail` |
| V(2) | `received SubjectAccessReview` | `user`, `groups`, `verb`, `path` |
| V(2) | `skipping namespace-scoped authorizer for non-namespaced SAR` | `authorizer` |
| V(2) | `skipping unconfigured WebhookAuthorizer` | `authorizer`, `generation`, `observedGeneration` |

#### `internal/webhook/authorization/binddefinition_bridge.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `authorization bridge group discovery failed` | — |
| error | `authorization bridge resource discovery failed` | `group`, `version`, `resource` |
| error | `authorization bridge role unavailable` | `bindDefinition` |
| error | `failed to select BindDefinitions for authorization bridge` | — |
| error | `failed to verify BindDefinition for authorization bridge` | `bindDefinition` |
| error | `invalid BindDefinition authorization bridge selector` | `bindDefinition` |
| V(1) | `authorization bridge namespace unavailable` | `namespace`, `error` |

#### `internal/webhook/authorization/emergency_authorization.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `emergency namespace authorization failed` | `namespace` |

### Namespace admission webhooks

Runs in: `webhook`.

#### `internal/webhook/authorization/namespace_deletion_protection.go`

| Level | Message | Keys |
|-------|---------|------|
| V(0) | `AUDIT: deletion of protected namespace denied` | `namespace`, `username` |
| V(0) | `AUDIT: deletion of protected system namespace denied` | `namespace`, `username` |
| V(0) | `AUDIT: deletion protection lifted via allow-deletion annotation` | `namespace`, `username` |
| V(0) | `AUDIT: protection label removal permitted via allow-deletion annotation` | `namespace`, `username` |
| V(0) | `AUDIT: removal of deletion-protection labels denied` | `namespace`, `username` |

#### `internal/webhook/authorization/namespace_mutating_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to collect BindDefinition labels` | `namespace` |
| error | `failed to decode namespace` | `namespace` |
| error | `failed to list BindDefinitions` | `namespace` |
| error | `failed to lookup SA namespace labels` | `saNamespace`, `targetNamespace` |
| error | `failed to marshal mutated namespace` | `namespace` |
| V(0) | `AUDIT: webhook bypass granted` | `namespace`, `operation`, `username`, `bypassReason`, `webhook` |
| V(1) | `SA namespace label inheritance - inheriting labels from SA source namespace` | `namespace`, `saNamespace`, `labelCount` |
| V(1) | `SA namespace label inheritance denied - label conflict on target namespace` | `namespace`, `label`, `existingValue`, `inheritedValue` |
| V(1) | `SA namespace label inheritance denied - target has extra tracked key` | `namespace`, `extraKey`, `saNamespace` |
| V(1) | `namespace mutation allowed - explicit namespace binding matched` | `namespace`, `operation`, `username` |
| V(1) | `namespace mutation denied - invalid tracked ownership labels on explicit namespace` | `namespace`, `operation`, `username` |
| V(1) | `namespace mutation denied - invalid tracked ownership labels` | `namespace`, `operation`, `username` |
| V(1) | `namespace mutation denied - no labels matched` | `namespace`, `username` |
| V(1) | `namespace mutation successful` | `namespace`, `labelCount` |
| V(2) | `adding label to namespace` | `namespace`, `label`, `value` |
| V(2) | `checking BindDefinitions for label mutations` | `namespace`, `bindDefinitionCount` |
| V(2) | `mutating namespace with labels` | `namespace`, `labelCount` |
| V(2) | `namespace mutator webhook triggered` | `namespace`, `operation`, `username` |
| V(3) | `checking BindDefinition for user match` | `namespace`, `bindDefinitionName`, `bdIndex` |
| V(3) | `explicit namespace binding matched` | `namespace`, `bindDefinition`, `roleBindingIndex` |
| V(3) | `extracted labels from selector` | `namespace`, `rbIndex`, `selectorIndex`, `labelCount` |
| V(3) | `label already exists - skipping` | `namespace`, `label` |
| V(3) | `processing RoleBinding namespace selectors` | `namespace`, `roleBindingIndex`, `selectorCount` |
| V(3) | `user is ServiceAccount` | `namespace`, `saNamespace`, `saName` |
| V(3) | `user is not ServiceAccount` | `namespace`, `username`, `groupCount` |
| V(3) | `user matched - extracting labels from RoleBindings` | `namespace`, `bindDefinition` |
| V(4) | `explicit namespace did not match request namespace, skipping selectors` | `namespace`, `roleBindingIndex`, `explicitNamespace` |
| V(4) | `operation not CREATE/UPDATE - allowing` | `namespace`, `operation` |
| V(4) | `skipping restricted BindDefinition` | `bindDefinitionName` |
| V(4) | `user not matched in BindDefinition` | `namespace`, `bindDefinitionName` |

#### `internal/webhook/authorization/namespace_validating_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to decode namespace object` | `namespace`, `operation` |
| error | `failed to decode old namespace object` | `namespace`, `operation` |
| error | `failed to list BindDefinitions` | `namespace` |
| error | `failed to lookup SA namespace labels` | `saNamespace`, `targetNamespace` |
| error | `failed to match namespace selector` | `namespace`, `bindDefinition` |
| V(0) | `AUDIT: webhook bypass granted` | `namespace`, `operation`, `username`, `bypassReason`, `webhook` |
| V(1) | `AUDIT: legacy label removal allowed (new owner label exists)` | `namespace`, `removedLabel`, `removedValue` |
| V(1) | `AUDIT: privileged bypass skipped update label checks` | `namespace`, `operation`, `username`, `bypassReason` |
| V(1) | `AUDIT: tenant/thirdparty/addon reclassification allowed` | `namespace`, `oldOwner`, `newOwner` |
| V(1) | `SA namespace label inheritance - authorized via matching SA source namespace labels` | `namespace`, `saNamespace`, `username` |
| V(1) | `namespace operation allowed` | `namespace`, `operation`, `username` |
| V(1) | `namespace operation denied - invalid tracked ownership labels` | `namespace`, `operation`, `username` |
| V(1) | `namespace operation denied` | `namespace`, `operation`, `username`, `reason` |
| V(1) | `namespace update denied - invalid tracked ownership labels` | `namespace`, `operation`, `username` |
| V(2) | `adoption denied: legacy non-platform namespace cannot become platform` | `namespace`, `legacyOwner`, `newOwner` |
| V(2) | `adoption denied: legacy platform namespace cannot become non-platform` | `namespace`, `legacyOwner`, `newOwner` |
| V(2) | `bypass granted - allowing namespace operation` | `namespace`, `operation`, `bypassReason`, `skipUpdateLabelChecks`, `allowProtectedLabelChanges` |
| V(2) | `checking authorization against BindDefinitions` | `namespace`, `bindDefinitionCount` |
| V(2) | `label adoption allowed` | `namespace`, `label`, `newValue` |
| V(2) | `label adoption denied for principal without label-adoption bypass` | `namespace`, `label`, `newValue` |
| V(2) | `label change allowed during reclassification` | `namespace`, `label`, `oldValue`, `newValue` |
| V(2) | `label modification denied` | `namespace`, `label`, `oldValue`, `newValue` |
| V(2) | `namespace validator webhook triggered` | `namespace`, `operation`, `username` |
| V(2) | `user authorized for explicit namespace operation` | `namespace`, `bindDefinition`, `roleBindingIndex`, `username` |
| V(2) | `user authorized for namespace operation` | `namespace`, `bindDefinition`, `username` |
| V(2) | `validating namespace update` | `namespace` |
| V(3) | `checking BindDefinition` | `namespace`, `bindDefinitionName`, `bdIndex`, `subjectCount` |
| V(3) | `namespace labels validated` | `namespace` |
| V(3) | `namespace matched selector` | `namespace`, `bindDefinition`, `roleBindingIndex`, `selectorIndex` |
| V(3) | `parsed user info` | `namespace`, `username`, `isServiceAccount`, `groupCount` |
| V(3) | `unknown operation type - allowing` | `namespace`, `operation` |
| V(3) | `user matched in BindDefinition` | `namespace`, `bindDefinition` |
| V(4) | `explicit namespace did not match request namespace, skipping selectors` | `namespace`, `bindDefinition`, `roleBindingIndex`, `explicitNamespace` |
| V(4) | `skipping restricted BindDefinition` | `bindDefinitionName` |
| V(4) | `user not found in BindDefinition subjects` | `namespace`, `bindDefinitionName` |
| V(4) | `webhook request for non-Namespace resource - ignoring` | `kind` |

### CRD validation webhooks

Runs in: `webhook`.

#### `api/authorization/v1alpha1/binddefinition_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to fetch clusterrole` | `clusterRoleName` |
| error | `failed to fetch role` | `roleName`, `namespace` |
| error | `failed to get namespace` | `namespace` |
| error | `failed to list BindDefinitions` | `targetName` |
| error | `failed to list RestrictedBindDefinitions` | `targetName` |
| error | `failed to list namespaces` | `selector` |
| error | `failed to validate role reference` | `name`, `namespace`, `roleName` |
| V(0) | `clusterrole not found` | `name`, `clusterRoleName`, `policy` |
| V(0) | `namespace not found, skipping role checks` | `name`, `namespace` |
| V(0) | `role not found` | `name`, `roleName`, `namespace`, `policy` |
| V(0) | `validation failed: duplicate targetName` | `name`, `targetName`, `conflictsWith` |
| V(0) | `validation failed: invalid roleBindings` | `name`, `error` |
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

#### `api/authorization/v1alpha1/default_policy_assignment_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to evaluate selected policy assignment` | `selectedPolicy` |
| error | `failed to resolve default policy assignments` | — |

#### `api/authorization/v1alpha1/rbacpolicy_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to list RBACPolicies for defaultAssignment overlap validation` | — |
| error | `failed to list RestrictedBindDefinitions` | — |
| error | `failed to list RestrictedRoleDefinitions` | — |
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

#### `api/authorization/v1alpha1/restrictedbinddefinition_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to get RBACPolicy` | `policyRef` |
| error | `failed to list BindDefinitions` | `targetName` |
| error | `failed to list RestrictedBindDefinitions` | `targetName` |
| error | `transient error fetching RBACPolicy` | `policyRef` |
| error | `transient error listing BindDefinitions` | `targetName` |
| error | `transient error listing RestrictedBindDefinitions` | `targetName` |
| V(0) | `validation failed: duplicate targetName` | `name`, `targetName`, `conflictsWith` |
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

#### `api/authorization/v1alpha1/restrictedroledefinition_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to get RBACPolicy` | `policyRef` |
| error | `failed to list RestrictedRoleDefinitions` | `targetName` |
| error | `failed to list RoleDefinitions` | `targetName` |
| V(0) | `validation failed: duplicate targetName` | `name`, `targetName`, `conflictsWith` |
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

#### `api/authorization/v1alpha1/roledefinition_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to list RestrictedRoleDefinitions` | `targetName` |
| error | `failed to list RoleDefinitions` | `targetName` |
| V(0) | `validation failed: duplicate targetName` | `name`, `targetName`, `conflictsWith` |
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

#### `api/authorization/v1alpha1/webhookauthorizer_webhook.go`

| Level | Message | Keys |
|-------|---------|------|
| V(1) | `validating create` | `name` |
| V(1) | `validating delete` | `name` |
| V(1) | `validating update` | `name` |

### API discovery

Runs in: `controller`.

#### `pkg/discovery/crd.go`

| Level | Message | Keys |
|-------|---------|------|
| V(0) | `CRD is established` | `crd` |
| V(0) | `waiting for CRD to be established` | `crd`, `gvk` |
| V(1) | `CRD has no Established condition yet, retrying...` | `crd` |
| V(1) | `CRD not found, retrying...` | `crd` |
| V(1) | `CRD not yet established, retrying...` | `crd`, `status` |
| V(1) | `error fetching CRD, retrying...` | `crd`, `error` |

#### `pkg/discovery/tracker.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `failed to rescan API resources` | — |
| error | `failed to signal discovery change` | — |
| error | `initial discovery was partial; continuing with usable resources` | — |

### Capability detection

Runs in: `controller`.

#### `pkg/capabilities/constrained_impersonation.go`

| Level | Message | Keys |
|-------|---------|------|
| V(1) | `failed to read API server /metrics for capability detection; falling back to version comparison` | `error` |
| V(1) | `failed to read API server version for capability detection` | `error` |

### Rendered RBAC verification

Runs in: `verify-rendered-rbac`.

#### `hack/verify-rendered-rbac.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `invalid arguments` | `usage` |
| error | `rendered RBAC verification failed` | — |

### Creator-tracking benchmark

Runs in: `creator-tracking-benchmark`.

#### `hack/benchmark/main.go`

| Level | Message | Keys |
|-------|---------|------|
| error | `creator-tracking benchmark failed` | — |

<!-- END GENERATED LOG CATALOG -->

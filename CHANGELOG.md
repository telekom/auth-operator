# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- RestrictedRoleDefinition and RestrictedBindDefinition enforce immutable `spec.policyRef` and `spec.targetName` after creation. To change these fields, recreate the resource with the desired values.

## [0.4.0-rc.13] — Pre-release

### Added

- ServiceAccount namespace label inheritance: when no BindDefinition matches, SAs can create/update namespaces inheriting ownership labels from their source namespace as a last-resort fallback (#202, #213)
- `MaxItems` validation on `RestrictedResources` and `RestrictedVerbs` fields to enforce bounded input sizes (#218)

### Fixed

- WebhookAuthorizer metrics now cleaned up on CR deletion, preventing stale metric series (#215)
- Namespace mutating webhook now registers the UPDATE operation, fixing label inheritance on namespace updates (#216)
- Periodic drift-correction requeue added to WebhookAuthorizer controller to self-heal configuration drift (#214)
- Repeated label key checks in `getLabelsFromNamespaceSelector()` replaced with set-based lookup (#156)
- Stale resource defaults in kustomize base configs (#199)
- Incorrect `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable documentation (#217)
- `--namespace` flag default documentation corrected in README (#222)

### Documentation

- End-user documentation improvements for operator guide (#221)
- Missing BindDefinition status fields added to API reference (#220)
- Documentation drift in `docs/operator-guide.md` — Helm Values section now matches current chart defaults (#199)

### CI

- `govulncheck` and `gosec` pinned to specific versions for reproducible builds (#219)
- `anchore/sbom-action` bumped from 0.23.0 to 0.23.1 (#200)
- `sigstore/cosign-installer` bumped from 4.0.0 to 4.1.0 (#201)
- Release workflow: `helm-release` job now depends on `release` job to prevent upload-before-creation race

## [0.4.0-rc.12] — Pre-release

### Added

- OpenSSF Scorecard workflow for security posture tracking (#77)
- `gosec` static security analysis in CI (#80)
- `dependency-review-action` workflow for supply-chain integrity (#80)
- Copilot reusable prompt for Helm chart changes (#81)
- Package-level `doc.go` documentation for all packages (#82)
- CEL `XValidation` rules for `BindDefinitionSpec`, `RoleDefinitionSpec`, and `WebhookAuthorizerSpec` for server-side schema validation (#50, #111)
- OpenAPI `MaxLength`, `MaxItems` constraints on `Principal`, `BindDefinitionSpec`, `WebhookAuthorizerSpec`, `ClusterBinding`, and `NamespaceBinding` fields (#111)
- WebhookAuthorizer condition types and controller for status management (#116, #123)
- Validating admission webhook for WebhookAuthorizer (#125)
- Informer-based caching and field index for WebhookAuthorizer (#126)
- WebhookAuthorizer integration and E2E tests (#127)
- Prometheus metrics for WebhookAuthorizer handler (#119)
- Structured audit logging for WebhookAuthorizer (#120)
- Breakglass-compatibility label (`t-caas.telekom.com/breakglass-compatible`) to generated ClusterRoles (#118)
- Version-specific filtering for RestrictedAPIs (#117)
- OpenTelemetry tracing support (#124)
- Configurable missing-role-ref validation policy for BindDefinition (#121)
- ClusterRole aggregation labels and `aggregateFrom` for RoleDefinition (#122)
- Parallel reconciliation with configurable concurrency (#128)
- Cache-aware SSA patchhelper to reduce API server load (#165)
- NetworkPolicies in Helm chart (#115)
- Webhook validation for subject kinds and field immutability (#170)
- Rate limiting for `/authorize` endpoint (`authorizeRateLimit`, `authorizeRateBurst`) (#174)
- Metrics authentication and safe leader election defaults (#173)
- Helm `values.schema.json` for strict input validation (#180)
- Multi-persona review prompts and AGENTS.md (#130, #136)
- Test coverage for metrics, cert rotator, cmd, and namespace webhook (#112)

### Changed

- **Breaking:** `BindDefinition` now requires at least one `clusterRoleBindings` or `roleBindings` with a referenced role and at least one `subject` — enforced by CEL validation on create/update (#111)
- **Breaking:** Webhook server defaults to 2 replicas with PDB enabled (#178)
- **Breaking:** Memory limits increased from 128Mi to 256Mi for both controller and webhook (#178)
- `Principal.Groups` `MaxItems` increased from 64 to 256 to accommodate corporate OIDC/LDAP providers (#111)
- `terminationGracePeriodSeconds` increased from 10 to 35 (#178)
- RBAC hardened: split ServiceAccounts, least-privilege ClusterRole (#179)

### Fixed

- Race condition in webhook ready flag using `atomic.Bool` (#76)
- Bare TODO comments now reference tracking issues (#82)
- Cache-backed client in integration test suite for field-indexed queries (#129)
- Error handling and code quality in controller helpers (#169)
- Terminator controller memory leak with cache improvements (#168)
- Legacy single-object `roleBindings` format during unmarshal (#197)
- Google patent license allowed in dependency review; fix GO-2026-4559 (#188)
- Security hardening and documentation improvements (#177)
- Cert rotation TOCTOU race via atomic rename (#178)

### Performance

- Optimized namespace fan-out in BindDefinition controller (#176)

### Refactored

- Extract `Handle()` into focused helpers in webhook handlers (#114)
- Centralize webhook bypass logic and denial messages (#171)
- Remove deprecated `InjectDecoder` and improve code docs (#175)
- Deduplicate namespace resolution in BindDefinition controller (#172)

## [0.4.0-rc.5] — Pre-release

### Added

- Helm chart with additional configuration options
- CRD resource preservation in discovery roles until fully deleted
- EditorConfig and standardized ignore files

### Fixed

- CI release workflows for SBOM attestation and image signature verification

[Unreleased]: https://github.com/telekom/auth-operator/compare/v0.4.0-rc.12...HEAD
[0.4.0-rc.12]: https://github.com/telekom/auth-operator/compare/v0.4.0-rc.5...v0.4.0-rc.12
[0.4.0-rc.5]: https://github.com/telekom/auth-operator/releases/tag/v0.4.0-rc.5

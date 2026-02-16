# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OpenSSF Scorecard workflow for security posture tracking (#77)
- `gosec` static security analysis in CI (#80)
- `dependency-review-action` workflow for supply-chain integrity (#80)
- Copilot reusable prompt for Helm chart changes (#81)
- Package-level `doc.go` documentation for all packages (#82)

### Fixed

- Race condition in webhook ready flag using `atomic.Bool` (#76)
- Bare TODO comments now reference tracking issues (#82)

## [0.4.0-rc.5] — Pre-release

### Added

- Helm chart with additional configuration options
- CRD resource preservation in discovery roles until fully deleted
- EditorConfig and standardized ignore files

### Fixed

- CI release workflows for SBOM attestation and image signature verification

[Unreleased]: https://github.com/telekom/auth-operator/compare/v0.4.0-rc.5...HEAD
[0.4.0-rc.5]: https://github.com/telekom/auth-operator/releases/tag/v0.4.0-rc.5

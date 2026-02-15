<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

## Reporting Security Vulnerabilities

**DO NOT** open a public GitHub issue for security vulnerabilities. Instead, please report security issues directly to:

📧 **[maximilian.rink@telekom.de](mailto:maximilian.rink@telekom.de)**

Please include:
- A clear description of the vulnerability
- Steps to reproduce (if applicable)
- Affected component(s) and version(s)
- Potential impact and severity
- Any suggested fixes (if you have them)

We take all security reports seriously and will respond within 24 hours to acknowledge receipt. We will keep you updated on the investigation and remediation progress.

---

## Security Practices

### Our Commitment

The auth-operator project follows security best practices:

- **Least-Privilege RBAC** — RoleDefinitions and BindDefinitions enforce minimal permissions
- **Webhook Authorization** — Runtime authorization decisions via WebhookAuthorizers
- **Supply Chain Security** — Container images are signed with cosign (keyless/Sigstore), SBOM attestations are attached, and GitHub provenance attestations are generated
- **Dependency Scanning** — govulncheck, Trivy, and go-licenses run on every PR and weekly
- **REUSE Compliance** — All source files carry SPDX license headers

### Supported Versions

We support the latest release with security patches. Older versions receive best-effort fixes.

| Version | Supported |
|---------|-----------|
| Latest  | ✅        |
| < Latest | ⚠️ Best-effort |

### Disclosure Policy

- We aim to acknowledge reports within **24 hours**
- We aim to provide an initial assessment within **72 hours**
- We coordinate disclosure with the reporter and aim for a fix within **30 days**

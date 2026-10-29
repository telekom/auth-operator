<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Temporary emergency namespace admission

Run this matrix only on a disposable cluster with namespace admission enabled.
Install the candidate auth-operator chart and image with
`metrics.auth.enabled=false`. The webhook ServiceAccount must be able to create
SubjectAccessReviews; the controller-manager ServiceAccount must not receive
that permission from the operator chart. This isolates the new review permission
from the optional `system:auth-delegator` metrics binding.

The API server authorization chain must include the temporary-access service.
Use an original OIDC requester token, a separate approver token, and an emergency
escalation whose escalated group has cluster-admin. Do not add the escalation
marker directly to the requester's RBAC. Disable authorization-webhook result
caching in this lab so expiry and revocation checks observe current decisions.

`matrix.py` exports `run_matrix(requester_kubeconfig, admin_kubeconfig)`. Call it
during an independently approved session of at least five minutes. It checks
actual Namespace and ConfigMap create/get/list/update/patch/delete requests,
ordinary and protected tenant namespaces, malformed ownership, other ownership
categories, system namespaces, and deletion confirmation. All requester mutations
except the explicit deletion-confirmation annotation use server-side dry-run.
The administrator creates and cleans up only the test fixtures.

Before approval, after natural expiry, and after explicit session drop, verify
both the marker SubjectAccessReview and an actual resource write are denied.
Self-approval must be denied. The marker review must carry the original
requester's username, UID, groups and extra claims. Preserve the runtime image,
chart settings, session transitions and operation log as separate evidence from
unit tests and CI.

Run `python3 test/emergency-admission/lifecycle.py` with these environment
variables after the cluster and OIDC provider are ready:

- `ADMIN_KUBECONFIG`: administrator kubeconfig for test fixtures and reviews.
- `BREAKGLASS_API_URL`: reachable Breakglass API URL with trusted TLS.
- `REQUESTER_TOKEN_FILE` and `APPROVER_TOKEN_FILE`: separate OIDC token files.
- `BREAKGLASS_NAMESPACE` and `BREAKGLASS_CLUSTER`: installed namespace and target
  ClusterConfig name (defaults: `breakglass-system`, `tenant-a`).
- `REQUESTER_GROUP` and `APPROVER_GROUP`: original requester/approver groups
  (defaults: `ops`, `senior-ops`).
- `NAMESPACE_MATRIX`: path to this directory's `matrix.py`.
- `PERSISTED_MATRIX`: path to this directory's `persisted.py` for actual
  namespace/workload writes and readback, including final absence after deletion.
- `AUTH_NAMESPACE` and `AUTH_RELEASE`: set both to verify that the webhook can
  create reviews and the controller cannot, with metrics authentication disabled.
- `RESULT_DIR`: result directory; otherwise a fresh temporary directory is used.
- `BREAKGLASS_CA_FILE`: optional CA bundle for the Breakglass API.

The runner verifies the original identity through SelfSubjectReview, creates an
isolated escalation, checks pending and self-approval denial, obtains independent
approval, verifies a natural 60-second expiry, then uses a second five-minute
session for the namespace matrix and explicit drop. It records result summaries
without recording tokens. Use fixture identities and a disposable cluster only.

Cleanup revokes the per-run cluster-admin binding first, then deletes its tracked
sessions, escalation and workload fixture. Result summaries remain on disk; the
requester kubeconfig is removed even if the matrix fails.

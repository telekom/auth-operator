#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# The output-delta sample suite includes RBACPolicy objects that intentionally
# exercise apply-time ServiceAccount impersonation. Production manifests keep
# that permission opt-in; this CI helper grants it only for the sample cluster.
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: auth-operator-output-delta-sample-impersonation
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts"]
    verbs: ["impersonate"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: auth-operator-output-delta-sample-impersonation
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: auth-operator-output-delta-sample-impersonation
subjects:
  - kind: ServiceAccount
    name: auth-operator-manager
    namespace: auth-operator-system
EOF

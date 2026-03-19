// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// Package policy provides evaluation logic for RBACPolicy enforcement.
// It validates RestrictedBindDefinitions and RestrictedRoleDefinitions
// against the constraints defined by their referenced RBACPolicy,
// returning structured violations for any non-compliant fields.
package policy

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "time"

// TargetNameField is the field index for efficient lookups by Spec.TargetName.
// This index must be registered with the manager before use.
const TargetNameField = ".spec.targetName"

// maxVersionLength is the upper bound for API version strings (e.g. "v1beta2").
// Shared by RoleDefinition and RestrictedRoleDefinition validation.
const maxVersionLength = 20

// WebhookCacheTimeout is the maximum duration webhook handlers wait for
// cache-backed List or Get calls. Informer-cache reads normally complete in
// microseconds; the timeout is a safety net for cold-cache or degraded
// API-server scenarios. Shared by CRD validation webhooks and authorization
// webhook handlers.
const WebhookCacheTimeout = 5 * time.Second

// roleTargetCollision reports whether two role targets collide, assuming the
// caller has already pre-filtered candidates to those sharing the same spec.targetName
// (e.g. via TargetNameField index). Within that pre-filtered set, ClusterRole
// targets always collide (cluster-scoped names are unique); Role targets only
// collide when targetNamespace also matches.
func roleTargetCollision(targetRole, targetNamespace, existingRole, existingNamespace string) bool {
	if targetRole != existingRole {
		return false
	}

	if targetRole == DefinitionClusterRole {
		return true
	}

	return targetNamespace == existingNamespace
}

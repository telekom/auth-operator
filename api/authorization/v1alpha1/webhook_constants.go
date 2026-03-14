// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import "time"

// TargetNameField is the field index for efficient lookups by Spec.TargetName.
// This index must be registered with the manager before use.
const TargetNameField = ".spec.targetName"

// WebhookCacheTimeout is the maximum duration webhook handlers wait for
// cache-backed List or Get calls. Informer-cache reads normally complete in
// microseconds; the timeout is a safety net for cold-cache or degraded
// API-server scenarios. Shared by CRD validation webhooks and authorization
// webhook handlers.
const WebhookCacheTimeout = 5 * time.Second

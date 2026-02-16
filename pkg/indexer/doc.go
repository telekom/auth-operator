// Package indexer registers controller-runtime field indexes on RoleDefinition
// and BindDefinition resources (by Spec.TargetName) to enable efficient cache
// lookups and duplicate detection in webhooks.
package indexer

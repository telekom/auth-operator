/*
Copyright © 2025 Deutsche Telekom AG.
*/

// Package metrics provides Prometheus metrics for the auth-operator.
// It exposes custom metrics for reconciliation performance, error tracking,
// and operational insights.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// Namespace is the Prometheus metrics namespace for auth-operator.
	Namespace = "auth_operator"
)

var (
	// ReconcileTotal counts the total number of reconciliations per controller.
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "reconcile_total",
			Help:      "Total number of reconciliations per controller",
		},
		[]string{"controller", "result"},
	)

	// ReconcileDuration measures the duration of reconciliations in seconds.
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "reconcile_duration_seconds",
			Help:      "Duration of reconciliations per controller in seconds",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"controller"},
	)

	// ReconcileErrors counts the total number of reconciliation errors per controller.
	ReconcileErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "reconcile_errors_total",
			Help:      "Total number of reconciliation errors per controller",
		},
		[]string{"controller", "error_type"},
	)

	// APIDiscoveryDuration measures the duration of API discovery operations in seconds.
	APIDiscoveryDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "api_discovery_duration_seconds",
			Help:      "Duration of API discovery operations in seconds",
			Buckets:   prometheus.DefBuckets,
		},
	)

	// APIDiscoveryErrors counts the total number of API discovery errors.
	APIDiscoveryErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "api_discovery_errors_total",
			Help:      "Total number of API discovery errors",
		},
	)

	// RBACResourcesDeleted counts the total number of RBAC resources deleted.
	RBACResourcesDeleted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "rbac_resources_deleted_total",
			Help:      "Total number of RBAC resources deleted",
		},
		[]string{"resource_type"},
	)

	// RBACResourcesApplied counts the total number of RBAC resources applied (created or updated)
	// via Server-Side Apply (SSA). SSA merges desired state declaratively, so create and update
	// are a single operation.
	RBACResourcesApplied = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "rbac_resources_applied_total",
			Help:      "Total number of RBAC resources applied (created or updated via SSA)",
		},
		[]string{"resource_type"},
	)

	// RoleRefsMissing tracks the number of BindDefinitions whose referenced
	// Roles or ClusterRoles do not yet exist. The gauge is set to the count of
	// missing references per BindDefinition during each reconciliation.
	// A non-zero value triggers a faster requeue so the condition self-heals
	// once the referenced roles are created.
	RoleRefsMissing = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "role_refs_missing",
			Help:      "Number of missing role references per BindDefinition (0 = all refs valid)",
		},
		[]string{"binddefinition"},
	)

	// NamespacesActive tracks the number of active (non-terminating) namespaces
	// that matched a BindDefinition's namespace selectors during the last
	// reconciliation. Useful for detecting selector misconfiguration or
	// namespace churn.
	NamespacesActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "namespaces_active",
			Help:      "Number of active namespaces matching selectors per BindDefinition",
		},
		[]string{"binddefinition"},
	)

	// ManagedResources tracks the desired/applied count of RBAC resources per
	// source resource (BindDefinition) from the last reconciliation. This reflects
	// the number of resources the controller intends to manage based on the spec,
	// not a live inventory from the cluster. Each reconciliation updates the gauge.
	// Call DeleteManagedResourceSeries on resource deletion to avoid stale series.
	ManagedResources = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "managed_resources",
			Help:      "Desired/applied count of RBAC resources from last reconciliation, by controller, type, and source resource name",
		},
		[]string{"controller", "resource_type", "name"},
	)

	// WebhookRequestsTotal counts the total number of webhook admission requests.
	WebhookRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "webhook_requests_total",
			Help:      "Total number of webhook admission requests",
		},
		[]string{"webhook", "operation", "result"},
	)

	// ServiceAccountSkippedPreExisting counts ServiceAccounts that were
	// not adopted because they already existed without an OwnerReference
	// from the BindDefinition. Useful for auditing pre-existing SA usage.
	ServiceAccountSkippedPreExisting = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "serviceaccount_skipped_preexisting_total",
			Help:      "Total number of pre-existing ServiceAccounts skipped (not adopted) per BindDefinition",
		},
		[]string{"binddefinition"},
	)

	// ExternalSAsReferenced tracks the number of external (pre-existing) ServiceAccounts
	// referenced by each BindDefinition. These SAs are used but not managed by the operator.
	ExternalSAsReferenced = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "external_serviceaccounts_referenced",
			Help:      "Number of external ServiceAccounts referenced per BindDefinition",
		},
		[]string{"binddefinition"},
	)

	// AuthorizerRequestsTotal counts the total number of SubjectAccessReview
	// requests processed by the WebhookAuthorizer, labeled by decision and
	// authorizer name.
	AuthorizerRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "authorizer_requests_total",
			Help:      "Total SubjectAccessReview requests processed by the WebhookAuthorizer",
		},
		[]string{"decision", "authorizer"},
	)

	// AuthorizerRequestDuration measures the end-to-end latency of
	// SubjectAccessReview evaluations in seconds, labeled by decision.
	AuthorizerRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: Namespace,
			Name:      "authorizer_request_duration_seconds",
			Help:      "Duration of SubjectAccessReview evaluations in seconds",
			// Tuned for sub-ms in-memory evaluations (informer cache, not apiserver round-trips).
			Buckets: []float64{0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5},
		},
		[]string{"decision"},
	)

	// AuthorizerActiveRules is a gauge tracking the total number of active
	// WebhookAuthorizer resources observed during the most recent request.
	AuthorizerActiveRules = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: Namespace,
			Name:      "authorizer_active_rules",
			Help:      "Number of active WebhookAuthorizer resources",
		},
	)

	// AuthorizerDeniedPrincipalHitsTotal counts the number of times a request
	// was denied because the subject matched a DeniedPrincipals entry.
	// NOTE: The authorizer label is set to the WebhookAuthorizer CR name.
	// Cardinality is bounded because the expected number of WebhookAuthorizer
	// CRs is small and stable (single-digit, cluster-scoped). If CRs are
	// deleted, call DeleteAuthorizerSeries to prune stale series.
	AuthorizerDeniedPrincipalHitsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: Namespace,
			Name:      "authorizer_denied_principal_hits_total",
			Help:      "Total requests denied due to DeniedPrincipals match",
		},
		[]string{"authorizer"},
	)
)

func init() {
	// Register all metrics with controller-runtime's registry.
	metrics.Registry.MustRegister(
		ReconcileTotal,
		ReconcileDuration,
		ReconcileErrors,
		APIDiscoveryDuration,
		APIDiscoveryErrors,
		RBACResourcesApplied,
		RBACResourcesDeleted,
		RoleRefsMissing,
		NamespacesActive,
		ManagedResources,
		WebhookRequestsTotal,
		ServiceAccountSkippedPreExisting,
		ExternalSAsReferenced,
		AuthorizerRequestsTotal,
		AuthorizerRequestDuration,
		AuthorizerActiveRules,
		AuthorizerDeniedPrincipalHitsTotal,
	)
}

// ReconcileResult constants for labeling reconcile outcomes.
const (
	ResultSuccess   = "success"
	ResultError     = "error"
	ResultRequeue   = "requeue"
	ResultSkipped   = "skipped"
	ResultFinalized = "finalized"
	ResultDegraded  = "degraded"
)

// ErrorType constants for categorizing reconciliation errors.
const (
	ErrorTypeAPI        = "api"
	ErrorTypeValidation = "validation"
	ErrorTypeInternal   = "internal"
)

// ControllerName constants.
const (
	ControllerRoleDefinition        = "RoleDefinition"
	ControllerBindDefinition        = "BindDefinition"
	ControllerRoleBindingTerminator = "RoleBindingTerminator"
)

// ResourceType constants.
const (
	ResourceClusterRole        = "ClusterRole"
	ResourceRole               = "Role"
	ResourceClusterRoleBinding = "ClusterRoleBinding"
	ResourceRoleBinding        = "RoleBinding"
	ResourceServiceAccount     = "ServiceAccount"
)

// WebhookName constants.
const (
	WebhookNamespaceValidator = "namespace_validator"
	WebhookNamespaceMutator   = "namespace_mutator"
)

// WebhookResult constants.
const (
	WebhookResultAllowed = "allowed"
	WebhookResultDenied  = "denied"
	WebhookResultErrored = "errored"
)

// AuthorizerDecision constants for labeling authorizer request outcomes.
const (
	AuthorizerDecisionAllowed = "allowed"
	AuthorizerDecisionDenied  = "denied"
	AuthorizerDecisionError   = "error"
)

// AuthorizerNameNone is the fallback label value when no specific authorizer matched.
const AuthorizerNameNone = "none"

// DeleteManagedResourceSeries removes all ManagedResources gauge series for a
// specific source resource (e.g. a BindDefinition being deleted). This prevents
// stale zero-value series from lingering after the resource is removed.
func DeleteManagedResourceSeries(controller, name string) {
	for _, rt := range []string{ResourceClusterRoleBinding, ResourceRoleBinding, ResourceServiceAccount} {
		ManagedResources.DeleteLabelValues(controller, rt, name)
	}
}

// DeleteAuthorizerSeries removes all metrics series for a deleted
// WebhookAuthorizer CR to prevent stale zero-value series from lingering.
func DeleteAuthorizerSeries(authorizerName string) {
	for _, decision := range []string{AuthorizerDecisionAllowed, AuthorizerDecisionDenied, AuthorizerDecisionError} {
		AuthorizerRequestsTotal.DeleteLabelValues(decision, authorizerName)
	}
	AuthorizerDeniedPrincipalHitsTotal.DeleteLabelValues(authorizerName)
}

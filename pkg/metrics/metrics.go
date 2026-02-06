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
	)
}

// ReconcileResult constants for labeling reconcile outcomes.
const (
	ResultSuccess   = "success"
	ResultError     = "error"
	ResultRequeue   = "requeue"
	ResultSkipped   = "skipped"
	ResultFinalized = "finalized"
)

// ErrorType constants for categorizing reconciliation errors.
const (
	ErrorTypeAPI        = "api"
	ErrorTypeValidation = "validation"
	ErrorTypeConflict   = "conflict"
	ErrorTypeNotFound   = "not_found"
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

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

const (
	apiGroupField       = "apiGroup"
	apiVersionField     = "apiVersion"
	apiVersionV1Alpha1  = "v1alpha1"
	annotationsField    = "annotations"
	benchmarkLabelValue = "creator-tracking"
	booleanTrue         = "true"
	fallbackRunID       = "run"
	kindField           = "kind"
	kindClusterRole     = "ClusterRole"
	labelsField         = "labels"
	metadataField       = "metadata"
	nameField           = "name"

	engineBaseline    = "baseline"
	engineEnvironment = "environment"
	engineMap         = "map"
	kyvernoCommand    = "kyverno"

	modeContributors = "contributors"
	modeCreateOnly   = "create-only"
	modeProtect      = "protect"

	phaseChurn     = "churn"
	phaseCore      = "core"
	phaseCreate    = "create"
	phaseSustained = "sustained"
	phaseWarmup    = "warmup"

	statusComplete = "complete"
	statusFailed   = "failed"
	statusRunning  = "running"

	verbMixed      = "mixed"
	verbUpdate     = "update"
	variantEnabled = "enabled"

	resourceBindDefinition     = "binddefinition"
	resourceClusterRole        = "clusterrole"
	resourceClusterRoleBinding = "clusterrolebinding"
	resourceNamespace          = "namespace"
	resourceNamespaces         = "namespaces"
	resourcePods               = "pods"
	resourceRBACPolicy         = "rbacpolicy"
	resourceRole               = "role"
	resourceRoleBinding        = "rolebinding"
	resourceRoleDefinition     = "roledefinition"
	resourceSecret             = "secret"
	resourceSecrets            = "secrets"
	resourceServiceAccount     = "serviceaccount"
	resourceServiceAccounts    = "serviceaccounts"
	resourceRoles              = "roles"
	isolationRBACGroup         = "rbac-group"
	isolationCRDGroup          = "crd-group"

	kindServiceAccount    = "ServiceAccount"
	defaultEditorIdentity = "creator-bench-000"

	envBenchCPUs        = "BENCH_CPUS"
	evidenceLiveMeminfo = "live /proc/meminfo"

	headerChartVersion      = "chart_version"
	headerErrors429         = "errors_429"
	headerMetricAfterState  = "metric_after_state"
	headerMetricBeforeState = "metric_before_state"
	headerMetricDeltaState  = "metric_delta_state"
	headerPodRestartsBefore = "pod_restarts_before"
	headerPodRestartsAfter  = "pod_restarts_after"
	headerPodRestartsDelta  = "pod_restarts_delta"
	headerWebhookDeltaState = "webhook_delta_state"

	fieldCPUs              = "cpus"
	fieldErrors            = "errors"
	fieldHostCPUModel      = "host_cpu_model"
	fieldHostMemory        = "host_memory"
	fieldKubernetesVersion = "kubernetes_version"
	fieldMemory            = "memory"
	fieldOperatorVersion   = "operator_version"
	fieldPolicyHash        = "policy_hash"
	fieldSamples           = "samples"
	fieldStatus            = "status"
	fieldSuccesses         = "successes"
)

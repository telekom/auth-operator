// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Operation struct {
	Verb          string `json:"verb"`
	LatencyMicros int64  `json:"latency_micros"`
	Error         string `json:"error,omitempty"`
	Status        int    `json:"status,omitempty"`
}
type CellRun struct {
	Cell              Cell            `json:"cell"`
	InputHash         string          `json:"input_hash"`
	Status            string          `json:"status"`
	Operations        []Operation     `json:"operations"`
	Trace             []MutationTrace `json:"trace,omitempty"`
	StartedAt         string          `json:"started_at"`
	Error             string          `json:"error,omitempty"`
	EndedAt           string          `json:"ended_at,omitempty"`
	MetricBefore      Counter         `json:"metric_before"`
	MetricAfter       Counter         `json:"metric_after"`
	Samples           int             `json:"samples"`
	Successes         int             `json:"successes,omitempty"`
	Errors            int             `json:"errors,omitempty"`
	Errors429         int             `json:"errors_429,omitempty"`
	P50Micros         int64           `json:"p50_micros,omitempty"`
	P95Micros         int64           `json:"p95_micros,omitempty"`
	P99Micros         int64           `json:"p99_micros,omitempty"`
	MaxMicros         int64           `json:"max_micros,omitempty"`
	Throughput        float64         `json:"throughput_ops_per_sec,omitempty"`
	RunID             string          `json:"run_id,omitempty"`
	EnvironmentID     string          `json:"environment_id,omitempty"`
	Environment       Environment     `json:"environment,omitempty"`
	WorkloadHash      string          `json:"workload_hash,omitempty"`
	ConfigHash        string          `json:"config_hash,omitempty"`
	MetricBeforeState MetricState     `json:"metric_before_state,omitempty"`
	MetricAfterState  MetricState     `json:"metric_after_state,omitempty"`
	MetricDeltaState  MetricState     `json:"metric_delta_state,omitempty"`
	MetricDelta       Counter         `json:"metric_delta"`
	MetricError       string          `json:"metric_error,omitempty"`
	PodRestartsBefore Counter         `json:"pod_restarts_before"`
	PodRestartsAfter  Counter         `json:"pod_restarts_after"`
	PodRestartsDelta  Counter         `json:"pod_restarts_delta"`
	WebhookBefore     HistogramDelta  `json:"webhook_before"`
	WebhookAfter      HistogramDelta  `json:"webhook_after"`
	WebhookDelta      HistogramDelta  `json:"webhook_delta"`
}

// FetchPodRestarts snapshots container restart counters for the operator pods.
// The counters are supporting evidence only: a missing pod list is recorded as
// unavailable and does not make an otherwise valid benchmark cell fail.
func FetchPodRestarts(ctx context.Context, base *rest.Config) (Counter, error) {
	if base == nil {
		return Counter{State: MetricUnavailable}, fmt.Errorf("pod restarts: nil REST config")
	}
	cl, err := dynamic.NewForConfig(base)
	if err != nil {
		return Counter{State: MetricUnavailable}, fmt.Errorf("pod restarts client: %w", err)
	}
	list, err := cl.Resource(schema.GroupVersionResource{Version: "v1", Resource: resourcePods}).
		Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=auth-operator",
	})
	if err != nil {
		return Counter{State: MetricUnavailable}, fmt.Errorf("list operator pods: %w", err)
	}
	var restarts float64
	found := false
	for _, pod := range list.Items {
		status, ok, statusErr := unstructured.NestedMap(pod.Object, "status")
		if statusErr != nil || !ok {
			continue
		}
		for _, field := range []string{"containerStatuses", "initContainerStatuses"} {
			items, ok, itemsErr := unstructured.NestedSlice(status, field)
			if itemsErr != nil || !ok {
				continue
			}
			for _, item := range items {
				cs, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				value, ok, valueErr := unstructured.NestedInt64(cs, "restartCount")
				if valueErr == nil && ok && value >= 0 {
					restarts += float64(value)
					found = true
				}
			}
		}
	}
	if !found {
		return Counter{State: MetricMissing}, nil
	}
	return Counter{Value: restarts, State: MetricAvailable}, nil
}

type CellJournal struct {
	State             string  `json:"state"`
	RunID             string  `json:"run_id"`
	InputHash         string  `json:"input_hash"`
	Config            options `json:"config"`
	StartedAt         string  `json:"started_at"`
	EndedAt           string  `json:"ended_at,omitempty"`
	Error             string  `json:"error,omitempty"`
	Phase             string  `json:"phase,omitempty"`
	EnvironmentID     string  `json:"environment_id,omitempty"`
	ConfigHash        string  `json:"config_hash,omitempty"`
	WorkloadHash      string  `json:"workload_hash,omitempty"`
	OperationProgress int     `json:"operation_progress,omitempty"`
	Errors            int     `json:"errors,omitempty"`
	Errors429         int     `json:"errors_429,omitempty"`
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func comparisonConfigHash(o options) string {
	return hashBytes(canonical(struct {
		Tier, Mode, Kind, Out, Kubeconfig, RunID string
		Ops, Churn, Identities, Warmup           int
		Concurrency                              []int
		Excluded, Quick, Resume, Report          bool
		Sustained                                time.Duration
	}{o.tier, o.mode, o.kind, o.out, o.kubeconfig, o.runID, o.ops, o.churn, o.identities, o.warmup, o.concurrency, o.excluded, o.quick, o.resume, o.report, o.sustained}))
}

func resumeStartOffset(resume bool, phase, resumePhase string) int {
	// A partial phase is never statistically complete. Replay it from zero
	// instead of mixing a retained prefix with a fresh suffix.
	return 0
}

// validateCompletedResult verifies that an existing phase result belongs to
// the exact phase currently being resumed. A result with a valid status but a
// different cell or input must not be silently skipped or overwritten.
func validateCompletedResult(prior Result, expected Cell, inputHash, environmentID, workloadHash, configHash string) error {
	if err := prior.Validate(); err != nil {
		return fmt.Errorf("invalid completed result: %w", err)
	}
	if prior.Status != statusComplete {
		return fmt.Errorf("completed result has status %q", prior.Status)
	}
	if prior.Cell != expected {
		return fmt.Errorf("completed result cell does not match expected cell")
	}
	if prior.RunID != expected.RunID {
		return fmt.Errorf("completed result run ID does not match expected run")
	}
	if prior.InputHash != inputHash {
		return fmt.Errorf("completed result input hash does not match expected input")
	}
	if prior.EnvironmentID != environmentID {
		return fmt.Errorf("completed result environment ID does not match expected environment")
	}
	if prior.WorkloadHash != workloadHash {
		return fmt.Errorf("completed result workload hash does not match expected workload")
	}
	if prior.ConfigHash != configHash {
		return fmt.Errorf("completed result config hash does not match expected configuration")
	}
	return nil
}

// comparisonEnvironmentID identifies the execution substrate shared by all
// engine variants. Policy and engine-specific versions are retained in each
// result's full Environment, but must not prevent baseline joins.
func comparisonEnvironmentID(e Environment) string {
	e.PolicyHash = ""
	e.KyvernoVersion = ""
	e.KyvernoChart = ""
	e.KyvernoChartSHA = ""
	e.Evidence = nil
	return InputHash(Cell{Engine: engineEnvironment}, MarshalEnvironment(e))
}

type resourceSpec struct {
	gvr        schema.GroupVersionResource
	namespaced bool
	apiVersion string
}

var resourceSpecs = map[string]resourceSpec{
	resourceNamespace: {
		gvr:        schema.GroupVersionResource{Version: "v1", Resource: resourceNamespaces},
		apiVersion: "v1",
	},
	resourceServiceAccount: {
		gvr:        schema.GroupVersionResource{Version: "v1", Resource: resourceServiceAccounts},
		namespaced: true, apiVersion: "v1",
	},
	resourceSecret: {
		gvr:        schema.GroupVersionResource{Version: "v1", Resource: resourceSecrets},
		namespaced: true, apiVersion: "v1",
	},
	resourceRole: {
		gvr:        schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: resourceRoles},
		namespaced: true, apiVersion: rbacv1.SchemeGroupVersion.String(),
	},
	resourceRoleBinding: {
		gvr:        schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "rolebindings"},
		namespaced: true, apiVersion: rbacv1.SchemeGroupVersion.String(),
	},
	resourceClusterRole: {
		gvr:        schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterroles"},
		apiVersion: rbacv1.SchemeGroupVersion.String(),
	},
	resourceClusterRoleBinding: {
		gvr:        schema.GroupVersionResource{Group: rbacv1.GroupName, Version: "v1", Resource: "clusterrolebindings"},
		apiVersion: rbacv1.SchemeGroupVersion.String(),
	},
	resourceRoleDefinition: {
		gvr:        schema.GroupVersionResource{Group: authorizationv1alpha1.GroupVersion.Group, Version: apiVersionV1Alpha1, Resource: "roledefinitions"},
		apiVersion: authorizationv1alpha1.GroupVersion.String(),
	},
	resourceBindDefinition: {
		gvr:        schema.GroupVersionResource{Group: authorizationv1alpha1.GroupVersion.Group, Version: apiVersionV1Alpha1, Resource: "binddefinitions"},
		apiVersion: authorizationv1alpha1.GroupVersion.String(),
	},
	resourceRBACPolicy: {
		gvr:        schema.GroupVersionResource{Group: authorizationv1alpha1.GroupVersion.Group, Version: apiVersionV1Alpha1, Resource: "rbacpolicies"},
		apiVersion: authorizationv1alpha1.GroupVersion.String(),
	},
}

func specFor(k string) (resourceSpec, error) {
	s, ok := resourceSpecs[k]
	if !ok {
		return resourceSpec{}, fmt.Errorf("unsupported benchmark resource %q", k)
	}
	return s, nil
}
func loadConfig(path string) (*rest.Config, error) {
	if path == "" {
		return nil, fmt.Errorf("kubeconfig is required")
	}
	c, e := clientcmd.BuildConfigFromFlags("", path)
	if e != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", e)
	}
	if c.Host == "" {
		return nil, fmt.Errorf("kubeconfig has empty server")
	}
	return c, nil
}
func clientFor(base *rest.Config, identity string) (dynamic.Interface, error) {
	if base == nil {
		return nil, fmt.Errorf("nil REST config")
	}
	c := rest.CopyConfig(base)
	c.Impersonate.UserName = identity
	c.Impersonate.Groups = []string{"system:authenticated"}
	return dynamic.NewForConfig(c)
}
func namespaceFor(runID string) string {
	return "creator-bench-" + strings.ToLower(strings.ReplaceAll(runID, "_", "-"))
}
func ownedLabels(runID string) map[string]interface{} {
	return map[string]interface{}{"t-caas.telekom.com/benchmark": benchmarkLabelValue, "t-caas.telekom.com/benchmark-run": runID}
}
func objectFor(cell Cell, name, namespace string, s resourceSpec) *unstructured.Unstructured {
	runID := cell.RunID
	if runID == "" {
		runID = cell.Variant + "-" + cell.Tier
	}
	labels := ownedLabels(runID)
	labels["t-caas.telekom.com/benchmark-cell"] = cellKey(cell)
	annotations := map[string]interface{}{
		"t-caas.telekom.com/benchmark-run":   runID,
		"t-caas.telekom.com/benchmark-tier":  cell.Tier,
		"t-caas.telekom.com/benchmark-scope": strings.Join(tierScopes[cell.Tier], ","),
	}
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		apiVersionField: s.apiVersion, kindField: cell.Kind,
		metadataField: map[string]interface{}{
			nameField: name, labelsField: labels, annotationsField: annotations,
		},
	}}
	if s.namespaced {
		u.SetNamespace(namespace)
	}
	switch cell.Kind {
	case resourceSecret:
		u.Object["type"] = "Opaque"
		u.Object["stringData"] = map[string]interface{}{"benchmark": booleanTrue}
	case resourceRole, resourceClusterRole:
		u.Object["rules"] = []interface{}{map[string]interface{}{"apiGroups": []interface{}{""}, "resources": []interface{}{resourcePods}, "verbs": []interface{}{"get", "list"}}}
	case resourceRoleBinding:
		u.Object["roleRef"] = map[string]interface{}{apiGroupField: rbacv1.GroupName, kindField: "Role", nameField: dependencyName(cell)}
		u.Object["subjects"] = []interface{}{map[string]interface{}{
			apiGroupField:     rbacv1.GroupName,
			kindField:         kindServiceAccount,
			nameField:         dependencyName(cell),
			resourceNamespace: namespace,
		}}
	case resourceClusterRoleBinding:
		u.Object["roleRef"] = map[string]interface{}{apiGroupField: rbacv1.GroupName, kindField: "ClusterRole", nameField: dependencyName(cell)}
		u.Object["subjects"] = []interface{}{map[string]interface{}{
			apiGroupField:     rbacv1.GroupName,
			kindField:         kindServiceAccount,
			nameField:         dependencyName(cell),
			resourceNamespace: namespace,
		}}
	case resourceRoleDefinition:
		u.Object["spec"] = map[string]interface{}{"targetRole": "ClusterRole", "targetName": "creator-bench-generated-role", "scopeNamespaced": false}
	case resourceBindDefinition:
		u.Object["spec"] = map[string]interface{}{
			"targetName": "creator-bench-generated-binding",
			"subjects": []interface{}{map[string]interface{}{
				apiGroupField: rbacv1.GroupName, kindField: kindServiceAccount,
				nameField: dependencyName(cell), resourceNamespace: namespace,
			}},
			"clusterRoleBindings": map[string]interface{}{
				"clusterRoleRefs": []interface{}{dependencyName(cell)},
			},
		}
	}
	return u
}
func cellKey(cell Cell) string {
	return sanitizeName(cell.Engine + "-" + cell.Tier + "-" + cell.Mode + "-" + cell.Variant)
}

func dependencyName(cell Cell) string {
	c := cell
	c.Phase = phaseCreate
	return deterministicName(c, 0)
}

//nolint:gocyclo // the benchmark lifecycle intentionally keeps phase ordering visible.
func executeBenchmark(ctx context.Context, base *rest.Config, cell Cell, o options, out string) (retErr error) {
	if resource, isolationErr := IsolationResource(o.tier); isolationErr == nil {
		mapped := map[string]string{
			resourceNamespaces:      resourceNamespace,
			resourceServiceAccounts: resourceServiceAccount,
			resourceSecrets:         resourceSecret,
			"rbac-group":            resourceRole,
			"crd-group":             resourceRoleDefinition,
		}
		var ok bool
		cell.Kind, ok = mapped[resource]
		if !ok {
			return fmt.Errorf("unsupported isolation resource %q", resource)
		}
	}
	s, e := specFor(cell.Kind)
	if e != nil {
		return e
	}
	if _, e = TierResources(o.tier); e != nil {
		if _, e = IsolationResource(o.tier); e != nil {
			return e
		}
	}
	ns := namespaceFor(o.runID)
	mix, _ := TierResources(o.tier)
	cleanupKinds := cleanupResourceKinds(mix, cell.Kind)
	if s.namespaced {
		if e := ensureNamespace(ctx, base, ns, o.runID); e != nil {
			return e
		}
	}
	cleanup := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		ownerUIDs, ownerErr := collectDefinitionUIDs(cleanupCtx, base, ns, o.runID, cellKey(cell))
		if ownerErr != nil {
			if retErr == nil {
				retErr = ownerErr
			} else {
				retErr = errors.Join(retErr, ownerErr)
			}
		}
		seen := map[schema.GroupVersionResource]bool{}
		cleanupErrs := []string{}
		for _, kind := range cleanupKinds {
			cs, specErr := specFor(kind)
			if specErr != nil {
				cleanupErrs = append(cleanupErrs, fmt.Errorf("resolve %s resource: %w", kind, specErr).Error())
				continue
			}
			if seen[cs.gvr] {
				continue
			}
			seen[cs.gvr] = true
			if cleanupErr := cleanupOwnedCell(cleanupCtx, base, cs, ns, o.runID, cellKey(cell)); cleanupErr != nil {
				cleanupErrs = append(cleanupErrs, cleanupErr.Error())
			}
		}
		if len(cleanupErrs) > 0 {
			cleanupErr := fmt.Errorf("cleanup: %s", strings.Join(cleanupErrs, "; "))
			if retErr == nil {
				retErr = cleanupErr
			} else {
				retErr = errors.Join(retErr, cleanupErr)
			}
		}
		if dependentErr := cleanupOwnedDependents(cleanupCtx, base, ownerUIDs); dependentErr != nil {
			if retErr == nil {
				retErr = dependentErr
			} else {
				retErr = errors.Join(retErr, dependentErr)
			}
		}
		if containsNamespaced(cleanupKinds) {
			if cleanupErr := deleteOwnedNamespace(cleanupCtx, base, ns, o.runID); cleanupErr != nil {
				if retErr == nil {
					retErr = cleanupErr
				} else {
					retErr = errors.Join(retErr, cleanupErr)
				}
			}
		}
	}
	var finalizeJournal func()
	defer func() {
		cleanup()
		if finalizeJournal != nil {
			finalizeJournal()
		}
	}()
	// Excluded-usernames is a warmup-only probe; measured traffic always has
	// exactly ten identities and therefore remains comparable across cells.
	ids := syntheticIdentities(10)
	inputHash := o.inputHash
	if inputHash == "" {
		inputHash = cellInputHash(cell)
	}
	if inputHash == "" {
		return fmt.Errorf("input hash is empty")
	}
	environment := CollectEnvironment(ctx, OSCommandRunner{}, hostEnvironmentValues())
	if e = environment.ValidateEvidence(); e != nil {
		return fmt.Errorf("environment evidence: %w", e)
	}
	environmentID := comparisonEnvironmentID(environment)
	configHash := comparisonConfigHash(o)
	material, materialErr := cellInputMaterial(cell)
	if materialErr != nil {
		return fmt.Errorf("read benchmark input material: %w", materialErr)
	}
	baseName := sanitizeName(cell.Engine + "-" + cell.Mode)
	if err := WriteEnvironment(filepath.Join(out, "environment-"+baseName+".json"), environment); err != nil {
		return fmt.Errorf("write environment manifest: %w", err)
	}
	if err := WriteInputMaterial(filepath.Join(out, "input-"+baseName+".yaml"), material); err != nil {
		return fmt.Errorf("write input manifest: %w", err)
	}
	workloadHash := hashBytes(canonical(struct {
		Resources                      []string
		Mode                           string
		Ops, Churn, Identities, Warmup int
		Concurrency                    []int
		Sustained                      time.Duration
		Excluded                       bool
	}{mix, cell.Mode, o.ops, o.churn, 10, o.warmup, o.concurrency, o.sustained, o.excluded}))
	journal := filepath.Join(out, "journals", cellFilename(o.runID, cell, "cell")+".journal.json")
	resumePhase := ""
	currentPhase := ""
	currentProgress := 0
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if o.resume {
		if b, readErr := os.ReadFile(journal); readErr == nil {
			var previous CellJournal
			if jsonErr := json.Unmarshal(b, &previous); jsonErr != nil {
				return fmt.Errorf("decode resume journal: %w", jsonErr)
			}
			if previous.RunID != o.runID ||
				previous.InputHash != inputHash ||
				previous.EnvironmentID != environmentID ||
				previous.ConfigHash != configHash ||
				previous.WorkloadHash != workloadHash {
				return fmt.Errorf("resume journal does not match run or input hash")
			}
			if previous.State == statusComplete {
				return nil
			}
			if previous.State != statusRunning && previous.State != statusFailed {
				return fmt.Errorf("resume journal has invalid state %q", previous.State)
			}
			// An interrupted phase is replayed from zero. Its journal offset is
			// not a statistically complete sample and must not be appended to.
			resumePhase = previous.Phase
		}
	}
	if e = writeJournal(journal, CellJournal{
		State: statusRunning, RunID: o.runID, InputHash: inputHash,
		Config: o, EnvironmentID: environmentID, ConfigHash: configHash,
		WorkloadHash: workloadHash, StartedAt: started,
	}); e != nil {
		return fmt.Errorf("write running journal: %w", e)
	}
	finalizeJournal = func() {
		state := journalState(retErr)
		if journalErr := writeJournal(journal, CellJournal{
			State: state, RunID: o.runID, InputHash: inputHash, Config: o,
			EnvironmentID: environmentID, ConfigHash: configHash,
			WorkloadHash: workloadHash, StartedAt: started,
			EndedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Error:   errorString(retErr), Phase: currentPhase,
			OperationProgress: currentProgress,
		}); journalErr != nil && retErr == nil {
			retErr = fmt.Errorf("write final journal: %w", journalErr)
		}
	}
	clients := make([]dynamic.Interface, len(ids))
	for i, identity := range ids {
		clients[i], e = clientFor(base, identity)
		if e != nil {
			return fmt.Errorf("create impersonated client for %q: %w", identity, e)
		}
	}
	metricsClient, e := rest.HTTPClientFor(base)
	if e != nil {
		return fmt.Errorf("create metrics HTTP client: %w", e)
	}
	for _, c := range o.concurrency {
		pc := cell
		pc.Concurrency = c
		pc.RunID = o.runID
		pc.Objects = o.ops
		for _, phase := range []string{phaseWarmup, phaseCreate, phaseChurn, phaseSustained} {
			currentPhase, currentProgress = phase, 0
			pc.Phase = phase
			pc.Sustained = phase == phaseSustained
			completedPath := filepath.Join(out, cellFilename(o.runID, pc, phase))
			if o.resume {
				if b, readErr := os.ReadFile(completedPath); readErr == nil {
					var prior Result
					if jsonErr := json.Unmarshal(b, &prior); jsonErr != nil {
						return fmt.Errorf("decode existing phase result %s: %w", completedPath, jsonErr)
					}
					if validationErr := validateCompletedResult(prior, pc, inputHash, environmentID, workloadHash, configHash); validationErr != nil {
						return fmt.Errorf("refusing existing phase result %s: %w", completedPath, validationErr)
					}
					continue
				} else if !errors.Is(readErr, os.ErrNotExist) {
					return fmt.Errorf("read existing phase result %s: %w", completedPath, readErr)
				}
			}
			if e := writeJournal(journal, CellJournal{
				State: statusRunning, RunID: o.runID, InputHash: inputHash,
				Config: o, EnvironmentID: environmentID, ConfigHash: configHash,
				WorkloadHash: workloadHash, StartedAt: started,
				Phase: phase, OperationProgress: 0,
			}); e != nil {
				return fmt.Errorf("write phase journal: %w", e)
			}
			n := o.warmup
			if phase == phaseCreate {
				n = o.ops
			}
			if phase == phaseChurn {
				if o.ops > int(^uint(0)>>1)/o.churn {
					return fmt.Errorf("churn operation count overflows")
				}
				n = o.ops * o.churn
			}
			if phase == phaseSustained {
				n = 0
			}
			var before MetricsSnapshot
			podBefore := Counter{State: MetricMissing}
			if phase != phaseWarmup {
				before, e = fetchMetrics(ctx, metricsClient, base)
				podBefore, _ = FetchPodRestarts(ctx, base)
				if e != nil {
					run := failedCellRun(pc, inputHash, o.runID, environmentID, environment, workloadHash, configHash, fmt.Errorf("metrics before %s: %w", phase, e))
					run.MetricBeforeState = before.State
					run.MetricBefore = Counter{State: before.State}
					run.MetricDeltaState = MetricUnavailable
					run.MetricDelta = Counter{State: MetricUnavailable}
					run.MetricError = errorString(e)
					run.WebhookDelta = HistogramDelta{State: MetricUnavailable}
					run.PodRestartsBefore = podBefore
					run.PodRestartsDelta = Counter{State: MetricUnavailable}
					if writeErr := writeCellRun(filepath.Join(out, cellFilename(o.runID, pc, phase)), run); writeErr != nil {
						return writeErr
					}
					return runFailure(run)
				}
			}
			duration := time.Duration(0)
			if phase == phaseSustained {
				duration = o.sustained
			}
			startOffset := resumeStartOffset(o.resume, phase, resumePhase)
			currentProgress = startOffset
			run := runMixedPhaseWithOffset(ctx, clients, mix, pc, n, c, ids, ns, duration, startOffset, func(done int) error {
				currentProgress = done
				return writeJournal(journal, CellJournal{
					State: statusRunning, RunID: o.runID, InputHash: inputHash,
					Config: o, EnvironmentID: environmentID, ConfigHash: configHash,
					WorkloadHash: workloadHash, StartedAt: started,
					Phase: phase, OperationProgress: done,
				})
			})
			// Persist a checkpoint before moving to the next phase. Completed
			// result files are used by resume to avoid replaying that phase.
			if checkpointErr := writeJournal(journal, CellJournal{
				State: statusRunning, RunID: o.runID, InputHash: inputHash,
				Config: o, EnvironmentID: environmentID, ConfigHash: configHash,
				WorkloadHash: workloadHash, StartedAt: started,
				Phase: phase, OperationProgress: startOffset + len(run.Operations),
				Errors: run.Errors, Errors429: run.Errors429,
			}); checkpointErr != nil {
				return fmt.Errorf("write operation checkpoint: %w", checkpointErr)
			}
			run.InputHash = inputHash
			run.RunID = o.runID
			run.EnvironmentID = environmentID
			run.Environment = environment
			run.WorkloadHash = workloadHash
			run.ConfigHash = configHash
			if phase != phaseWarmup {
				after, me := fetchMetrics(ctx, metricsClient, base)
				if me != nil {
					run.Status = statusFailed
					run.Error = fmt.Errorf("metrics after %s: %w", phase, me).Error()
					run.MetricBeforeState = before.State
					run.MetricAfterState = after.State
					run.MetricDeltaState = metricDeltaState(before, after)
					run.MetricError = errorString(me)
					if e := writeCellRun(filepath.Join(out, cellFilename(o.runID, pc, phase)), run); e != nil {
						return e
					}
					return runFailure(run)
				}
				run.MetricBeforeState = before.State
				run.MetricAfterState = after.State
				run.MetricBefore = ParseMetricResponse(before.StatusCode, before.Body, APIServerAdmissionDuration+"_count")
				run.MetricAfter = ParseMetricResponse(after.StatusCode, after.Body, APIServerAdmissionDuration+"_count")
				run.MetricDelta = CounterDelta(run.MetricBefore, run.MetricAfter)
				run.MetricDeltaState = run.MetricDelta.State
				labels := map[string]string{"type": "mutating"}
				run.WebhookBefore = ParseHistogramResponse(before, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.WebhookAfter = ParseHistogramResponse(after, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.WebhookDelta = histogramResponseDelta(before, after, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.MetricError = metricDiagnostics(run.MetricBefore, run.MetricAfter, run.MetricDelta, run.WebhookBefore, run.WebhookAfter, run.WebhookDelta)
				if run.MetricBefore.State != MetricAvailable || run.MetricAfter.State != MetricAvailable || run.MetricDelta.State != MetricAvailable {
					run.Status = statusFailed
					run.Error = fmt.Sprintf("metrics delta %s unavailable", phase)
				}
				run.PodRestartsBefore = podBefore
				run.PodRestartsAfter, _ = FetchPodRestarts(ctx, base)
				run.PodRestartsDelta = CounterDelta(run.PodRestartsBefore, run.PodRestartsAfter)
				if run.MetricDelta.State != MetricAvailable || run.WebhookDelta.State != MetricAvailable {
					run.Status = statusFailed
					if run.Error == "" {
						run.Error = fmt.Sprintf("supporting telemetry unavailable for %s", phase)
					}
				}
				if before.State == MetricUnauthorized || after.State == MetricUnauthorized {
					run.Status = statusFailed
					run.Error = "metrics authorization failed"
				}
			}
			if e := writeCellRun(completedPath, run); e != nil {
				return e
			}
			if run.Status != statusComplete || run.Errors > 0 {
				return runFailure(run)
			}
		}
	}
	return nil
}

func collectDefinitionUIDs(ctx context.Context, base *rest.Config, namespace, runID, cell string) ([]types.UID, error) {
	cl, err := dynamic.NewForConfig(base)
	if err != nil {
		return nil, fmt.Errorf("create cleanup client: %w", err)
	}
	return collectDefinitionUIDsWithClient(ctx, cl, namespace, runID, cell)
}

func collectDefinitionUIDsWithClient(ctx context.Context, cl dynamic.Interface, namespace, runID, cell string) ([]types.UID, error) {
	var out []types.UID
	for _, kind := range []string{resourceRoleDefinition, resourceBindDefinition} {
		s, err := specFor(kind)
		if err != nil {
			return nil, fmt.Errorf("resolve %s resource: %w", kind, err)
		}
		var r dynamic.ResourceInterface
		if s.namespaced {
			r = cl.Resource(s.gvr).Namespace(namespace)
		} else {
			r = cl.Resource(s.gvr)
		}
		list, err := r.List(ctx, metav1.ListOptions{LabelSelector: "t-caas.telekom.com/benchmark-run=" + runID})
		if err != nil {
			return nil, fmt.Errorf("list %s resources: %w", kind, err)
		}
		for _, u := range list.Items {
			if u.GetLabels()["t-caas.telekom.com/benchmark"] == benchmarkLabelValue &&
				(cell == "" || u.GetLabels()["t-caas.telekom.com/benchmark-cell"] == cell) && u.GetUID() != "" {
				out = append(out, u.GetUID())
			}
		}
	}
	return out, nil
}

func cleanupOwnedDependents(ctx context.Context, base *rest.Config, owners []types.UID) error {
	if len(owners) == 0 {
		return nil
	}
	cl, err := dynamic.NewForConfig(base)
	if err != nil {
		return err
	}
	return cleanupOwnedDependentsWithClient(ctx, cl, owners)
}

func cleanupOwnedDependentsWithClient(ctx context.Context, cl dynamic.Interface, owners []types.UID) error {
	owned := map[types.UID]bool{}
	for _, uid := range owners {
		owned[uid] = true
	}
	var errs []string
	for _, kind := range []string{resourceServiceAccount, resourceRole, resourceRoleBinding, resourceClusterRole, resourceClusterRoleBinding} {
		s, err := specFor(kind)
		if err != nil {
			return fmt.Errorf("resolve %s resource: %w", kind, err)
		}
		var r dynamic.ResourceInterface
		if s.namespaced {
			r = cl.Resource(s.gvr).Namespace(metav1.NamespaceAll)
		} else {
			r = cl.Resource(s.gvr)
		}
		if err := deleteAndWaitOwnedDependents(ctx, r, owned); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", kind, err).Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup generated dependents: %s", strings.Join(errs, "; "))
	}
	return nil
}

func deleteAndWaitOwnedDependents(ctx context.Context, r dynamic.ResourceInterface, owned map[types.UID]bool) error {
	for {
		list, err := r.List(ctx, metav1.ListOptions{})
		if err != nil {
			return err
		}
		matches := 0
		for _, u := range list.Items {
			match := false
			for _, ref := range u.GetOwnerReferences() {
				if owned[ref.UID] {
					match = true
					break
				}
			}
			if !match {
				continue
			}
			matches++
			if err := r.Delete(ctx, u.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
		if matches == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for generated dependent deletion: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func containsNamespaced(kinds []string) bool {
	for _, kind := range kinds {
		if s, err := specFor(kind); err == nil && s.namespaced {
			return true
		}
	}
	return false
}

func cleanupResourceKinds(mix []string, selected string) []string {
	if len(mix) > 0 {
		return append([]string(nil), mix...)
	}
	return []string{selected}
}

func journalState(err error) string {
	if err != nil {
		return statusFailed
	}
	return statusComplete
}

func cellFilename(runID string, c Cell, phase string) string {
	parts := []string{
		sanitizeName(runID), sanitizeName(c.Engine), sanitizeName(c.Tier),
		sanitizeName(c.Mode), sanitizeName(c.Variant + "-" + phase),
	}
	return fmt.Sprintf("cell-%s-%s-%s-%s-%s-%d.json",
		parts[0], parts[1], parts[2], parts[3], parts[4], c.Concurrency)
}
func failedCellRun(c Cell, inputHash, runID, envID string, env Environment, workloadHash, configHash string, err error) CellRun {
	return CellRun{
		Cell: c, InputHash: inputHash, RunID: runID, EnvironmentID: envID,
		Environment: env, WorkloadHash: workloadHash, ConfigHash: configHash,
		Status: statusFailed, Error: err.Error(),
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
}
func runFailure(r CellRun) error {
	return fmt.Errorf("benchmark phase %s failed: %s", r.Cell.Phase, r.Error)
}
func ensureNamespace(ctx context.Context, base *rest.Config, name, runID string) error {
	cl, e := dynamic.NewForConfig(base)
	if e != nil {
		return e
	}
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		apiVersionField: "v1", kindField: "Namespace",
		metadataField: map[string]interface{}{nameField: name, labelsField: ownedLabels(runID)},
	}}
	r := cl.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	_, e = r.Create(ctx, u, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(e) {
		return e
	}
	existing, getErr := r.Get(ctx, name, metav1.GetOptions{})
	if getErr != nil {
		return getErr
	}
	labels := existing.GetLabels()
	if labels["t-caas.telekom.com/benchmark-run"] != runID || labels["t-caas.telekom.com/benchmark"] != benchmarkLabelValue {
		return fmt.Errorf("refusing to use preexisting namespace %q without exact benchmark ownership", name)
	}
	return nil
}

func writeJournal(path string, journal CellJournal) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	t, err := os.CreateTemp(filepath.Dir(path), ".journal-")
	if err != nil {
		return err
	}
	tmp := t.Name()
	defer func() { _ = os.Remove(tmp) }()
	enc := json.NewEncoder(t)
	enc.SetIndent("", "  ")
	if encodeErr := enc.Encode(journal); encodeErr != nil {
		_ = t.Close()
		return encodeErr
	}
	if closeErr := t.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}

func ValidateResumeExact(path, runID, inputHash, environmentID, configHash string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read journal: %w", err)
	}
	var j CellJournal
	if err := json.Unmarshal(b, &j); err != nil {
		return fmt.Errorf("decode journal: %w", err)
	}
	if j.EnvironmentID != environmentID {
		return fmt.Errorf("journal environment mismatch")
	}
	if j.ConfigHash != configHash {
		return fmt.Errorf("journal config mismatch")
	}
	if j.State != statusComplete || j.RunID != runID || j.InputHash != inputHash {
		return fmt.Errorf("journal run or input mismatch")
	}
	return nil
}

func deleteOwnedNamespace(ctx context.Context, base *rest.Config, name, runID string) error {
	cl, err := dynamic.NewForConfig(base)
	if err != nil {
		return err
	}
	r := cl.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	u, err := r.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	labels := u.GetLabels()
	if labels["t-caas.telekom.com/benchmark-run"] != runID || labels["t-caas.telekom.com/benchmark"] != benchmarkLabelValue {
		return fmt.Errorf("refusing to delete namespace %q without ownership labels", name)
	}
	err = r.Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for {
		_, getErr := r.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			return nil
		}
		if getErr != nil {
			return fmt.Errorf("wait for namespace deletion: %w", getErr)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for namespace deletion: %w", ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func writeCellRun(path string, r CellRun) error {
	if path == "" {
		return fmt.Errorf("output path is required")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return e
	}
	t, e := os.CreateTemp(filepath.Dir(path), ".cell-")
	if e != nil {
		return e
	}
	n := t.Name()
	defer func() { _ = os.Remove(n) }()
	result := Result{
		Cell: r.Cell, InputHash: r.InputHash, RunID: r.RunID, EnvironmentID: r.EnvironmentID,
		Environment: r.Environment, WorkloadHash: r.WorkloadHash, ConfigHash: r.ConfigHash,
		Status: r.Status, Error: r.Error, Samples: r.Samples, Successes: r.Successes,
		Errors: r.Errors, Errors429: r.Errors429, Operations: r.Operations, Trace: r.Trace,
		P50Micros: r.P50Micros, P95Micros: r.P95Micros, P99Micros: r.P99Micros,
		MaxMicros: r.MaxMicros, Throughput: r.Throughput, StartedAt: r.StartedAt, EndedAt: r.EndedAt,
		MetricBefore: r.MetricBefore, MetricAfter: r.MetricAfter, MetricDelta: r.MetricDelta,
		MetricBeforeState: r.MetricBeforeState, MetricAfterState: r.MetricAfterState,
		MetricDeltaState: r.MetricDeltaState, MetricError: r.MetricError,
		WebhookBefore: r.WebhookBefore, WebhookAfter: r.WebhookAfter, WebhookDelta: r.WebhookDelta,
		PodRestartsBefore: r.PodRestartsBefore, PodRestartsAfter: r.PodRestartsAfter,
		PodRestartsDelta: r.PodRestartsDelta,
	}
	x := json.NewEncoder(t)
	x.SetIndent("", "  ")
	if encodeErr := x.Encode(result); encodeErr != nil {
		_ = t.Close()
		return encodeErr
	}
	if closeErr := t.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(n, path)
}
func cleanupCell(ctx context.Context, cl dynamic.Interface, s resourceSpec, namespace string) error {
	var r dynamic.ResourceInterface
	if s.namespaced {
		r = cl.Resource(s.gvr).Namespace(namespace)
	} else {
		r = cl.Resource(s.gvr)
	}
	list, e := r.List(ctx, metav1.ListOptions{LabelSelector: "t-caas.telekom.com/benchmark=" + benchmarkLabelValue})
	if e != nil {
		return e
	}
	var errs []string
	for _, u := range list.Items {
		if e = r.Delete(ctx, u.GetName(), metav1.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
			errs = append(errs, e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}
func cleanupOwnedCell(ctx context.Context, base *rest.Config, s resourceSpec, namespace, runID, cell string) error {
	cl, e := dynamic.NewForConfig(base)
	if e != nil {
		return e
	}
	var r dynamic.ResourceInterface
	if s.namespaced {
		r = cl.Resource(s.gvr).Namespace(namespace)
	} else {
		r = cl.Resource(s.gvr)
	}
	list, e := r.List(ctx, metav1.ListOptions{LabelSelector: "t-caas.telekom.com/benchmark-run=" + runID})
	if e != nil {
		return e
	}
	var errs []string
	for _, u := range list.Items {
		if u.GetLabels()["t-caas.telekom.com/benchmark"] != benchmarkLabelValue {
			continue
		}
		if cell != "" && u.GetLabels()["t-caas.telekom.com/benchmark-cell"] != cell {
			continue
		}
		if e = r.Delete(ctx, u.GetName(), metav1.DeleteOptions{}); e != nil && !apierrors.IsNotFound(e) {
			errs = append(errs, e.Error())
			continue
		}
		if e = waitResourceDeleted(ctx, r, u.GetName()); e != nil {
			errs = append(errs, e.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup: %s", strings.Join(errs, "; "))
	}
	return nil
}

func waitResourceDeleted(ctx context.Context, r dynamic.ResourceInterface, name string) error {
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := r.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("verify deletion of %q: %w", name, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("verify deletion of %q: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

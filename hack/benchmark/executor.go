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
		Excluded, Quick                          bool
		Sustained                                time.Duration
	}{o.tier, o.mode, o.kind, o.out, o.kubeconfig, o.runID, o.ops, o.churn, o.identities, o.warmup, o.concurrency, o.excluded, o.quick, o.sustained}))
}

func resumeStartOffset() int {
	// A partial phase is never statistically complete. Replay it from zero
	// instead of mixing a retained prefix with a fresh suffix.
	return 0
}

// validateResultIdentity verifies that an existing phase result belongs to
// the exact phase currently being resumed. A result with a different cell or
// input must not be silently skipped or overwritten, regardless of whether it
// completed or failed.
func validateResultIdentity(prior Result, expected Cell, inputHash, environmentID, workloadHash, configHash string) error {
	if err := prior.Validate(); err != nil {
		return fmt.Errorf("invalid result: %w", err)
	}
	if prior.Cell != expected {
		return fmt.Errorf("result cell does not match expected cell")
	}
	if prior.RunID != expected.RunID {
		return fmt.Errorf("result run ID does not match expected run")
	}
	if prior.InputHash != inputHash {
		return fmt.Errorf("result input hash does not match expected input")
	}
	if prior.EnvironmentID != environmentID {
		return fmt.Errorf("result environment ID does not match expected environment")
	}
	if prior.WorkloadHash != workloadHash {
		return fmt.Errorf("result workload hash does not match expected workload")
	}
	if prior.ConfigHash != configHash {
		return fmt.Errorf("result config hash does not match expected configuration")
	}
	return nil
}

// validateCompletedResult accepts only an exact, successful result that can be
// skipped during resume.
func validateCompletedResult(prior Result, expected Cell, inputHash, environmentID, workloadHash, configHash string) error {
	if err := validateResultIdentity(prior, expected, inputHash, environmentID, workloadHash, configHash); err != nil {
		return fmt.Errorf("invalid completed result: %w", err)
	}
	if prior.Status != statusComplete {
		return fmt.Errorf("completed result has status %q", prior.Status)
	}
	return nil
}

// validateRetryableResult accepts only an exact failed result. Failed phase
// files are checkpoints to replace after a cell journal proves that the cell
// may be replayed; they must never be mistaken for completed measurements.
func validateRetryableResult(prior Result, expected Cell, inputHash, environmentID, workloadHash, configHash string) error {
	if prior.Status != statusFailed {
		return fmt.Errorf("retryable result has status %q", prior.Status)
	}
	if err := validateResultIdentity(prior, expected, inputHash, environmentID, workloadHash, configHash); err != nil {
		return fmt.Errorf("invalid retryable result: %w", err)
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
	c.Impersonate.Groups = []string{"system:authenticated", benchmarkImpersonationGroup}
	return dynamic.NewForConfig(c)
}
func namespaceFor(runID string) string {
	return "creator-bench-" + strings.ToLower(strings.ReplaceAll(runID, "_", "-"))
}
func ownedLabels(runID string) map[string]interface{} {
	return map[string]interface{}{benchmarkLabelKey: benchmarkLabelValue, "t-caas.telekom.com/benchmark-run": runID}
}

// canonicalKind translates the benchmark's internal resource keys to the
// Kubernetes Kind used in the generated object's type metadata.
func canonicalKind(resource string) string {
	switch resource {
	case resourceNamespace:
		return kindNamespace
	case resourceServiceAccount:
		return kindServiceAccount
	case resourceSecret:
		return kindSecret
	case resourceRole:
		return kindRole
	case resourceRoleBinding:
		return kindRoleBinding
	case resourceClusterRole:
		return kindClusterRole
	case resourceClusterRoleBinding:
		return kindClusterRoleBinding
	case resourceRoleDefinition:
		return kindRoleDefinition
	case resourceBindDefinition:
		return kindBindDefinition
	case resourceRBACPolicy:
		return kindRBACPolicy
	default:
		return resource
	}
}

// subjectFor returns the fields expected by the RBAC Subject API. Service
// accounts are core resources and therefore omit apiGroup; users and groups
// belong to the RBAC API group.
func subjectFor(kind, name, namespace string) map[string]interface{} {
	subject := map[string]interface{}{kindField: kind, nameField: name}
	switch kind {
	case kindServiceAccount:
		subject[resourceNamespace] = namespace
	case "User", "Group":
		subject[apiGroupField] = rbacv1.GroupName
	}
	return subject
}

// metricDeltaCounter combines parsed metric counters with the authenticated
// snapshot states. CounterDelta intentionally returns missing for any
// non-available counter, so apply the more useful unauthorized/unavailable
// snapshot state before persisting the benchmark result.
func metricDeltaCounter(before, after MetricsSnapshot, name string) Counter {
	beforeCounter := ParseMetricResponse(before.StatusCode, before.Body, name)
	afterCounter := ParseMetricResponse(after.StatusCode, after.Body, name)
	delta := CounterDelta(beforeCounter, afterCounter)
	state := metricDeltaState(before, after)
	// FetchMetrics normally sets Snapshot.State, but retain the more specific
	// parser result when callers construct a snapshot from just its status code
	// and body (for example, tests or alternate transport adapters).
	switch {
	case beforeCounter.State == MetricUnauthorized || afterCounter.State == MetricUnauthorized:
		state = MetricUnauthorized
	case beforeCounter.State == MetricUnavailable || afterCounter.State == MetricUnavailable:
		state = MetricUnavailable
	case beforeCounter.State != MetricAvailable || afterCounter.State != MetricAvailable:
		state = MetricMissing
	case beforeCounter.State == MetricAvailable && afterCounter.State == MetricAvailable:
		state = delta.State
	}
	delta.State = state
	if state != MetricAvailable {
		delta.Value = 0
	}
	return delta
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
		"t-caas.telekom.com/benchmark-scope": strings.Join(tierScope(cell.Tier), ","),
		annotationCreator:                    spoofedCreator,
		annotationGroups:                     spoofedGroups,
	}
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		apiVersionField: s.apiVersion, kindField: canonicalKind(cell.Kind),
		metadataField: map[string]interface{}{
			nameField: name, labelsField: labels, annotationsField: annotations,
		},
	}}
	if s.namespaced {
		u.SetNamespace(namespace)
	}
	switch cell.Kind {
	case resourceSecret:
		u.Object[typeField] = "Opaque"
		u.Object["stringData"] = map[string]interface{}{"benchmark": booleanTrue}
	case resourceRole, resourceClusterRole:
		// Keep the generated role within the benchmark runner group's existing
		// permissions. That lets identities create RoleBindings and
		// ClusterRoleBindings without granting the ephemeral group bind or
		// escalate privileges.
		u.Object["rules"] = []interface{}{
			map[string]interface{}{
				"apiGroups": []interface{}{""},
				"resources": []interface{}{resourceServiceAccounts},
				"verbs":     []interface{}{"get"},
			},
		}
	case resourceRoleBinding:
		u.Object["roleRef"] = map[string]interface{}{apiGroupField: rbacv1.GroupName, kindField: kindRole, nameField: dependencyName(cell)}
		u.Object["subjects"] = []interface{}{subjectFor(kindServiceAccount, dependencyName(cell), namespace)}
	case resourceClusterRoleBinding:
		u.Object["roleRef"] = map[string]interface{}{apiGroupField: rbacv1.GroupName, kindField: kindClusterRole, nameField: dependencyName(cell)}
		u.Object["subjects"] = []interface{}{subjectFor(kindServiceAccount, dependencyName(cell), namespace)}
	case resourceRoleDefinition:
		u.Object["spec"] = map[string]interface{}{"targetRole": kindClusterRole, "targetName": "creator-bench-generated-role", "scopeNamespaced": false}
	case resourceBindDefinition:
		u.Object["spec"] = map[string]interface{}{
			"targetName": "creator-bench-generated-binding",
			"subjects":   []interface{}{subjectFor(kindServiceAccount, dependencyName(cell), namespace)},
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

func artifactBaseName(cell Cell) string {
	return sanitizeName(strings.Join([]string{cell.Engine, cell.Tier, cell.Mode, cell.Variant}, "-"))
}

//nolint:gocyclo // the benchmark lifecycle intentionally keeps phase ordering visible.
func executeBenchmark(ctx context.Context, base *rest.Config, cell Cell, o options, out string) (retErr error) {
	if isolationKind, isolationErr := IsolationKind(o.tier); isolationErr == nil {
		cell.Kind = isolationKind
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
	if len(mix) == 0 {
		mix = []string{cell.Kind}
	}
	cleanupKinds := cleanupResourceKinds(mix, cell.Kind)
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
	cleanupOnReturn := true
	var finalizeJournal func()
	defer func() {
		if cleanupOnReturn {
			cleanup()
		}
		if finalizeJournal != nil {
			finalizeJournal()
		}
	}()
	// The excluded-usernames comparison uses a configured non-matching identity.
	// Measured traffic always has exactly ten identities and remains comparable.
	ids := syntheticIdentities()
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
	baseName := artifactBaseName(cell)
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
	}{mix, cell.Mode, o.ops, o.churn, o.identities, o.warmup, o.concurrency, o.sustained, o.excluded}))
	journal := filepath.Join(out, "journals", cellFilename(o.runID, cell, "cell")+".journal.json")
	restartCell := false
	currentPhase := ""
	currentProgress := 0
	started := time.Now().UTC().Format(time.RFC3339Nano)
	if o.resume {
		if b, readErr := readBenchmarkFile(journal); readErr == nil {
			var previous CellJournal
			if jsonErr := json.Unmarshal(b, &previous); jsonErr != nil {
				return fmt.Errorf("decode resume journal: %w", jsonErr)
			}
			if previous.RunID != o.runID ||
				previous.InputHash != inputHash ||
				previous.EnvironmentID != environmentID ||
				previous.ConfigHash != configHash ||
				previous.WorkloadHash != workloadHash {
				return fmt.Errorf("resume journal does not match run ID, input hash, environment ID, config hash, or workload hash")
			}
			if previous.State == statusComplete {
				// Completed cells were already cleaned by their original run. Do
				// not delete the shared workload namespace here: it can contain
				// the retained state of a later interrupted cell.
				cleanupOnReturn = false
				return nil
			}
			if previous.State != statusRunning && previous.State != statusFailed {
				return fmt.Errorf("resume journal has invalid state %q", previous.State)
			}
			// An interrupted phase is replayed from zero. Its journal offset is
			// not a statistically complete sample and must not be appended to.
			// Restart the whole cell so deterministic CREATE names and the
			// state required by later UPDATE phases are both reconstructed.
			restartCell = true
		} else if errors.Is(readErr, os.ErrNotExist) {
			return fmt.Errorf("resume journal is missing: %s", journal)
		} else {
			return fmt.Errorf("read resume journal: %w", readErr)
		}
	}
	if restartCell {
		cleanup()
		if retErr != nil {
			return retErr
		}
		if s.namespaced {
			if e := ensureNamespace(ctx, base, ns, o.runID); e != nil {
				return fmt.Errorf("recreate benchmark namespace: %w", e)
			}
		}
	} else if s.namespaced {
		// A fresh cell creates its namespace only after resume validation. A
		// completed cell returned above without touching the shared namespace,
		// while a missing or mismatched journal failed closed before any create.
		if err := ensureNamespace(ctx, base, ns, o.runID); err != nil {
			return err
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
				if b, readErr := readBenchmarkFile(completedPath); readErr == nil {
					var prior Result
					if jsonErr := json.Unmarshal(b, &prior); jsonErr != nil {
						return fmt.Errorf("decode existing phase result %s: %w", completedPath, jsonErr)
					}
					if prior.Status == statusComplete {
						if validationErr := validateCompletedResult(prior, pc, inputHash, environmentID, workloadHash, configHash); validationErr != nil {
							return fmt.Errorf("refusing existing phase result %s: %w", completedPath, validationErr)
						}
						if !restartCell {
							continue
						}
					} else {
						if validationErr := validateRetryableResult(prior, pc, inputHash, environmentID, workloadHash, configHash); validationErr != nil {
							return fmt.Errorf("refusing failed phase result %s: %w", completedPath, validationErr)
						}
						if !restartCell {
							return fmt.Errorf("refusing failed phase result %s without a retryable cell journal", completedPath)
						}
					}
					// A retryable journal causes every exact prior result to be
					// replaced as the cell is reconstructed from its first phase.
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
			var beforeErr error
			podBefore := Counter{State: MetricMissing}
			if phase != phaseWarmup {
				before, beforeErr = fetchMetrics(ctx, metricsClient, base)
				if before.State == "" {
					before.State = MetricUnavailable
				}
				podBefore, _ = FetchPodRestarts(ctx, base)
			}
			duration := time.Duration(0)
			if phase == phaseSustained {
				duration = o.sustained
			}
			startOffset := resumeStartOffset()
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
				// Client-observed workload results are authoritative. API-server,
				// webhook, and pod-restart snapshots are supporting evidence, so
				// transport/authentication/series gaps are retained in the result
				// without discarding an otherwise successful latency sample.
				after, afterErr := fetchMetrics(ctx, metricsClient, base)
				if after.State == "" {
					after.State = MetricUnavailable
				}
				run.MetricBeforeState = before.State
				run.MetricAfterState = after.State
				run.MetricBefore = ParseMetricResponse(before.StatusCode, before.Body, APIServerAdmissionDuration+"_count")
				run.MetricAfter = ParseMetricResponse(after.StatusCode, after.Body, APIServerAdmissionDuration+"_count")
				run.MetricDelta = metricDeltaCounter(before, after, APIServerAdmissionDuration+"_count")
				run.MetricDeltaState = run.MetricDelta.State
				labels := map[string]string{typeField: metricTypeMutating}
				run.WebhookBefore = ParseHistogramResponse(before, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.WebhookAfter = ParseHistogramResponse(after, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.WebhookDelta = histogramResponseDelta(before, after, WebhookAdmissionDuration+"_sum", WebhookAdmissionDuration+"_count", labels)
				run.MetricError = metricDiagnostics(run.MetricBefore, run.MetricAfter, run.MetricDelta, run.WebhookBefore, run.WebhookAfter, run.WebhookDelta)
				if beforeErr != nil || afterErr != nil {
					fetchErrors := make([]string, 0, 2)
					if beforeErr != nil {
						fetchErrors = append(fetchErrors, fmt.Sprintf("before: %s", beforeErr))
					}
					if afterErr != nil {
						fetchErrors = append(fetchErrors, fmt.Sprintf("after: %s", afterErr))
					}
					if run.MetricError == "" {
						run.MetricError = strings.Join(fetchErrors, "; ")
					} else {
						run.MetricError = strings.Join(append(fetchErrors, run.MetricError), "; ")
					}
				}
				run.PodRestartsBefore = podBefore
				run.PodRestartsAfter, _ = FetchPodRestarts(ctx, base)
				run.PodRestartsDelta = CounterDelta(run.PodRestartsBefore, run.PodRestartsAfter)
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
			if u.GetLabels()[benchmarkLabelKey] == benchmarkLabelValue &&
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
func runFailure(r CellRun) error {
	return fmt.Errorf("benchmark phase %s failed: %s", r.Cell.Phase, r.Error)
}
func ensureNamespace(ctx context.Context, base *rest.Config, name, runID string) error {
	cl, e := dynamic.NewForConfig(base)
	if e != nil {
		return e
	}
	u := &unstructured.Unstructured{Object: map[string]interface{}{
		apiVersionField: "v1", kindField: kindNamespace,
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
	if labels["t-caas.telekom.com/benchmark-run"] != runID || labels[benchmarkLabelKey] != benchmarkLabelValue {
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
	b, err := readBenchmarkFile(path)
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
	if labels["t-caas.telekom.com/benchmark-run"] != runID || labels[benchmarkLabelKey] != benchmarkLabelValue {
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
	return deleteOwnedCollection(ctx, r, "t-caas.telekom.com/benchmark="+benchmarkLabelValue)
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
	selector := []string{
		"t-caas.telekom.com/benchmark-run=" + runID,
		"t-caas.telekom.com/benchmark=" + benchmarkLabelValue,
	}
	if cell != "" {
		selector = append(selector, "t-caas.telekom.com/benchmark-cell="+cell)
	}
	return deleteOwnedCollection(ctx, r, strings.Join(selector, ","))
}

// deleteOwnedCollection uses the API server's collection deletion path so a
// failed benchmark cannot spend its entire cleanup deadline issuing one
// throttled DELETE and follow-up GET for every workload object. The selector
// is exact ownership evidence supplied by the caller. Older API resources may
// not implement collection deletion, so retain a narrowly scoped per-object
// fallback for those resources.
func deleteOwnedCollection(ctx context.Context, r dynamic.ResourceInterface, selector string) error {
	listOptions := metav1.ListOptions{LabelSelector: selector}
	if err := r.DeleteCollection(ctx, metav1.DeleteOptions{}, listOptions); err != nil && !apierrors.IsMethodNotSupported(err) {
		return fmt.Errorf("cleanup: %w", err)
	} else if err != nil {
		list, listErr := r.List(ctx, listOptions)
		if listErr != nil {
			return fmt.Errorf("cleanup: %w", listErr)
		}
		for _, u := range list.Items {
			if deleteErr := r.Delete(ctx, u.GetName(), metav1.DeleteOptions{}); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
				return fmt.Errorf("cleanup: %w", deleteErr)
			}
		}
	}
	for {
		list, err := r.List(ctx, listOptions)
		if err != nil {
			return fmt.Errorf("cleanup: %w", err)
		}
		if len(list.Items) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("cleanup: %w", ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

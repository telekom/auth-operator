/*
Copyright © 2026 Deutsche Telekom AG.
*/

package metrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

func TestMetricRegistration(t *testing.T) {
	// Verify all expected metrics are actually registered with the
	// controller-runtime metrics registry. The init() function registers
	// them via metrics.Registry.MustRegister(), so attempting to
	// re-register should return AlreadyRegisteredError.
	collectors := []struct {
		name      string
		collector prometheus.Collector
	}{
		{"ReconcileTotal", ReconcileTotal},
		{"ReconcileDuration", ReconcileDuration},
		{"ReconcileErrors", ReconcileErrors},
		{"APIDiscoveryDuration", APIDiscoveryDuration},
		{"APIDiscoveryErrors", APIDiscoveryErrors},
		{"RBACResourcesApplied", RBACResourcesApplied},
		{"RBACResourcesDeleted", RBACResourcesDeleted},
		{"RoleRefsMissing", RoleRefsMissing},
		{"NamespacesActive", NamespacesActive},
		{"ManagedResources", ManagedResources},
		{"WebhookRequestsTotal", WebhookRequestsTotal},
		{"ServiceAccountSkippedPreExisting", ServiceAccountSkippedPreExisting},
		{"ExternalSAsReferenced", ExternalSAsReferenced},
	}

	for _, c := range collectors {
		err := crmetrics.Registry.Register(c.collector)
		if err == nil {
			// If registration succeeded, the metric was NOT previously registered;
			// unregister it to avoid side effects, then fail the test.
			crmetrics.Registry.Unregister(c.collector)
			t.Errorf("metric %s should already be registered in controller-runtime registry via init()", c.name)
		} else {
			var regErr prometheus.AlreadyRegisteredError
			if !errors.As(err, &regErr) {
				t.Errorf("metric %s: expected AlreadyRegisteredError, got: %v", c.name, err)
			}
		}
	}
}

func TestReconcileCounterVec(t *testing.T) {
	tests := []struct {
		controller string
		result     string
	}{
		{ControllerRoleDefinition, ResultSuccess},
		{ControllerBindDefinition, ResultError},
		{ControllerRoleBindingTerminator, ResultRequeue},
		{ControllerRoleDefinition, ResultSkipped},
		{ControllerBindDefinition, ResultFinalized},
		{ControllerRoleDefinition, ResultDegraded},
	}

	for _, tt := range tests {
		t.Run(tt.controller+"/"+tt.result, func(t *testing.T) {
			counter, err := ReconcileTotal.GetMetricWithLabelValues(tt.controller, tt.result)
			if err != nil {
				t.Fatalf("failed to get metric: %v", err)
			}

			before := getCounterValue(t, counter)
			counter.Inc()
			after := getCounterValue(t, counter)

			if after != before+1 {
				t.Errorf("expected counter to increment by 1, got delta %f", after-before)
			}
		})
	}
}

func TestReconcileErrorsCounterVec(t *testing.T) {
	tests := []struct {
		controller string
		errorType  string
	}{
		{ControllerRoleDefinition, ErrorTypeAPI},
		{ControllerBindDefinition, ErrorTypeValidation},
		{ControllerRoleBindingTerminator, ErrorTypeInternal},
	}

	for _, tt := range tests {
		t.Run(tt.controller+"/"+tt.errorType, func(t *testing.T) {
			counter, err := ReconcileErrors.GetMetricWithLabelValues(tt.controller, tt.errorType)
			if err != nil {
				t.Fatalf("failed to get metric: %v", err)
			}

			before := getCounterValue(t, counter)
			counter.Inc()
			after := getCounterValue(t, counter)

			if after != before+1 {
				t.Errorf("expected counter to increment by 1, got delta %f", after-before)
			}
		})
	}
}

func TestReconcileDurationHistogram(t *testing.T) {
	observer, err := ReconcileDuration.GetMetricWithLabelValues(ControllerBindDefinition)
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}
	observer.Observe(0.5)
	observer.Observe(1.0)
	observer.Observe(2.5)

	// Verify the histogram actually recorded the observations.
	metric := &dto.Metric{}
	if err := observer.(prometheus.Metric).Write(metric); err != nil {
		t.Fatalf("failed to write metric: %v", err)
	}
	if got := metric.GetHistogram().GetSampleCount(); got < 3 {
		t.Errorf("expected at least 3 samples, got %d", got)
	}
}

func TestAPIDiscoveryMetrics(t *testing.T) {
	// Duration histogram
	APIDiscoveryDuration.Observe(0.1)

	// Error counter
	before := getCounterValue(t, APIDiscoveryErrors)
	APIDiscoveryErrors.Inc()
	after := getCounterValue(t, APIDiscoveryErrors)

	if after != before+1 {
		t.Errorf("expected APIDiscoveryErrors to increment by 1, got delta %f", after-before)
	}
}

func TestRBACResourceCounters(t *testing.T) {
	resourceTypes := []string{
		ResourceClusterRole,
		ResourceRole,
		ResourceClusterRoleBinding,
		ResourceRoleBinding,
		ResourceServiceAccount,
	}

	for _, rt := range resourceTypes {
		t.Run("applied/"+rt, func(t *testing.T) {
			counter, err := RBACResourcesApplied.GetMetricWithLabelValues(rt)
			if err != nil {
				t.Fatalf("failed to get metric: %v", err)
			}
			before := getCounterValue(t, counter)
			counter.Inc()
			after := getCounterValue(t, counter)
			if after != before+1 {
				t.Errorf("expected increment by 1, got delta %f", after-before)
			}
		})

		t.Run("deleted/"+rt, func(t *testing.T) {
			counter, err := RBACResourcesDeleted.GetMetricWithLabelValues(rt)
			if err != nil {
				t.Fatalf("failed to get metric: %v", err)
			}
			before := getCounterValue(t, counter)
			counter.Inc()
			after := getCounterValue(t, counter)
			if after != before+1 {
				t.Errorf("expected increment by 1, got delta %f", after-before)
			}
		})
	}
}

func TestGaugeVecMetrics(t *testing.T) {
	t.Run("RoleRefsMissing", func(t *testing.T) {
		RoleRefsMissing.WithLabelValues("test-bd").Set(3)
		val := getGaugeValue(t, RoleRefsMissing.WithLabelValues("test-bd"))
		if val != 3 {
			t.Errorf("expected 3, got %f", val)
		}
		RoleRefsMissing.WithLabelValues("test-bd").Set(0)
	})

	t.Run("NamespacesActive", func(t *testing.T) {
		NamespacesActive.WithLabelValues("test-bd").Set(5)
		val := getGaugeValue(t, NamespacesActive.WithLabelValues("test-bd"))
		if val != 5 {
			t.Errorf("expected 5, got %f", val)
		}
	})

	t.Run("ExternalSAsReferenced", func(t *testing.T) {
		ExternalSAsReferenced.WithLabelValues("test-bd").Set(2)
		val := getGaugeValue(t, ExternalSAsReferenced.WithLabelValues("test-bd"))
		if val != 2 {
			t.Errorf("expected 2, got %f", val)
		}
	})
}

func TestManagedResourcesGauge(t *testing.T) {
	ManagedResources.WithLabelValues(ControllerBindDefinition, ResourceClusterRoleBinding, "test-bd-1").Set(10)
	ManagedResources.WithLabelValues(ControllerBindDefinition, ResourceRoleBinding, "test-bd-1").Set(5)
	ManagedResources.WithLabelValues(ControllerBindDefinition, ResourceServiceAccount, "test-bd-1").Set(3)

	// Verify all three series have correct exact values.
	expected := map[string]float64{
		ResourceClusterRoleBinding: 10,
		ResourceRoleBinding:        5,
		ResourceServiceAccount:     3,
	}
	for _, rt := range []string{ResourceClusterRoleBinding, ResourceRoleBinding, ResourceServiceAccount} {
		val := getGaugeValue(t, ManagedResources.WithLabelValues(ControllerBindDefinition, rt, "test-bd-1"))
		if val != expected[rt] {
			t.Errorf("expected gauge for %s to be %f, got %f", rt, expected[rt], val)
		}
	}
}

func TestWebhookRequestsCounter(t *testing.T) {
	tests := []struct {
		webhook   string
		operation string
		result    string
	}{
		{WebhookNamespaceValidator, "CREATE", WebhookResultAllowed},
		{WebhookNamespaceValidator, "UPDATE", WebhookResultDenied},
		{WebhookNamespaceMutator, "CREATE", WebhookResultAllowed},
		{WebhookNamespaceMutator, "DELETE", WebhookResultErrored},
	}

	for _, tt := range tests {
		t.Run(tt.webhook+"/"+tt.operation+"/"+tt.result, func(t *testing.T) {
			counter, err := WebhookRequestsTotal.GetMetricWithLabelValues(tt.webhook, tt.operation, tt.result)
			if err != nil {
				t.Fatalf("failed to get metric: %v", err)
			}
			counter.Inc()
		})
	}
}

func TestServiceAccountSkippedCounter(t *testing.T) {
	counter, err := ServiceAccountSkippedPreExisting.GetMetricWithLabelValues("test-bd")
	if err != nil {
		t.Fatalf("failed to get metric: %v", err)
	}

	before := getCounterValue(t, counter)
	counter.Inc()
	after := getCounterValue(t, counter)

	if after != before+1 {
		t.Errorf("expected counter to increment by 1, got delta %f", after-before)
	}
}

func TestDeleteManagedResourceSeries(t *testing.T) {
	controller := ControllerBindDefinition
	name := "test-bd-delete"

	// Set some gauge values
	ManagedResources.WithLabelValues(controller, ResourceClusterRoleBinding, name).Set(5)
	ManagedResources.WithLabelValues(controller, ResourceRoleBinding, name).Set(3)
	ManagedResources.WithLabelValues(controller, ResourceServiceAccount, name).Set(2)

	// Delete the series
	DeleteManagedResourceSeries(controller, name)

	// After deletion, getting fresh metrics should return zero (new series)
	for _, rt := range []string{ResourceClusterRoleBinding, ResourceRoleBinding, ResourceServiceAccount} {
		val := getGaugeValue(t, ManagedResources.WithLabelValues(controller, rt, name))
		if val != 0 {
			t.Errorf("expected gauge for %s to be 0 after deletion, got %f", rt, val)
		}
	}
}

func TestConstants(t *testing.T) {
	// Verify namespace constant
	if Namespace != "auth_operator" {
		t.Errorf("expected namespace %q, got %q", "auth_operator", Namespace)
	}

	// Verify result constants are non-empty
	results := []string{ResultSuccess, ResultError, ResultRequeue, ResultSkipped, ResultFinalized, ResultDegraded}
	for _, r := range results {
		if r == "" {
			t.Error("result constant must not be empty")
		}
	}

	// Verify error type constants are non-empty
	errorTypes := []string{ErrorTypeAPI, ErrorTypeValidation, ErrorTypeInternal}
	for _, et := range errorTypes {
		if et == "" {
			t.Error("error type constant must not be empty")
		}
	}

	// Verify controller name constants are non-empty
	controllers := []string{ControllerRoleDefinition, ControllerBindDefinition, ControllerRoleBindingTerminator}
	for _, c := range controllers {
		if c == "" {
			t.Error("controller constant must not be empty")
		}
	}

	// Verify resource type constants are non-empty
	resources := []string{ResourceClusterRole, ResourceRole, ResourceClusterRoleBinding, ResourceRoleBinding, ResourceServiceAccount}
	for _, r := range resources {
		if r == "" {
			t.Error("resource type constant must not be empty")
		}
	}

	// Verify webhook constants are non-empty
	webhooks := []string{WebhookNamespaceValidator, WebhookNamespaceMutator}
	for _, w := range webhooks {
		if w == "" {
			t.Error("webhook constant must not be empty")
		}
	}

	// Verify webhook result constants are non-empty
	webhookResults := []string{WebhookResultAllowed, WebhookResultDenied, WebhookResultErrored}
	for _, wr := range webhookResults {
		if wr == "" {
			t.Error("webhook result constant must not be empty")
		}
	}
}

// getCounterValue reads the current value from a prometheus.Counter.
func getCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := counter.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("failed to read counter value: %v", err)
	}
	return m.GetCounter().GetValue()
}

// getGaugeValue reads the current value from a prometheus.Gauge.
func getGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := gauge.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("failed to read gauge value: %v", err)
	}
	return m.GetGauge().GetValue()
}

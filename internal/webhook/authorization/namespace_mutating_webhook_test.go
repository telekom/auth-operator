package webhooks_test

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	jsonpatch "github.com/evanphx/json-patch"

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/api/authorization/v1alpha1"
	webhooks "gitlab.devops.telekom.de/cit/t-caas/operators/auth-operator/internal/webhook/authorization"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	crAdmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var admission = struct {
	ApplyPatch func(original, patch []byte) ([]byte, error)
}{
	ApplyPatch: func(original, patchBytes []byte) ([]byte, error) {
		patch, err := jsonpatch.DecodePatch(patchBytes)
		if err != nil {
			return nil, err
		}
		return patch.Apply(original)
	},
}

// General functionality table test
func TestNamespaceMutatorHandle(t *testing.T) {
	// ----------------------------------------------------------------------
	// 1. Setup the scheme for our fake client
	// ----------------------------------------------------------------------
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme)) // For corev1, admissionv1, etc.
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))  // Register your CRD types

	// ----------------------------------------------------------------------
	// 2. Create some sample BindDefinitions that might match certain groups
	// ----------------------------------------------------------------------
	bindDefPlatform := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "platform-namespaced-poweruser",
		},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "bd-platform-ns-poweruser",
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_namespaced_poweruser",
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_cluster_collaborator",
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_cluster_poweruser",
				},
				{
					Kind:      "ServiceAccount",
					Name:      "m2m-sa-t-caas-platform",
					Namespace: "kube-system",
				},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"t-caas-platform-namespaced-poweruser"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"kube-system", "kube-public", "kube-node-lease"},
							},
						},
					},
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "t-caas.telekom.com/owner",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"platform"},
							},
							{
								Key:      "t-caas.telekom.com/owner",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   []string{"tenant", "thirdparty"},
							},
						},
					}},
			},
			},
		},
	}

	// ----------------------------------------------------------------------
	// 3. Initialize a fake client with the BindDefinition objects
	// ----------------------------------------------------------------------
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&bindDefPlatform).
		Build()

	// ----------------------------------------------------------------------
	// 4. Create our NamespaceMutator with the fake client
	// ----------------------------------------------------------------------
	mutator := &webhooks.NamespaceMutator{
		Client: fakeClient,
	}

	dec := crAdmission.NewDecoder(scheme)
	if err := mutator.InjectDecoder(dec); err != nil {
		t.Fatalf("failed to inject decoder: %v", err)
	}

	// ----------------------------------------------------------------------
	// 5. Helper to build an admission Request
	// ----------------------------------------------------------------------
	buildRequest := func(
		operation admissionv1.Operation,
		username string,
		groups []string,
		ns *corev1.Namespace,
		oldNs *corev1.Namespace,
	) crAdmission.Request {
		// Marshal the new namespace for the request
		nsRaw, _ := json.Marshal(ns)
		oldNsRaw, _ := json.Marshal(oldNs)

		return crAdmission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: operation,
				UserInfo: authenticationv1.UserInfo{
					Username: username,
					Groups:   groups,
				},
				Object:    runtime.RawExtension{Raw: nsRaw},
				OldObject: runtime.RawExtension{Raw: oldNsRaw},
			},
		}
	}

	// ----------------------------------------------------------------------
	// 6. Table-driven tests
	// ----------------------------------------------------------------------
	tests := []struct {
		name             string
		operation        admissionv1.Operation
		username         string
		groups           []string
		namespace        *corev1.Namespace
		oldNamespace     *corev1.Namespace
		expectAllowed    bool
		expectLabels     map[string]string
		expectPatch      bool
		expectStatusCode int
	}{
		{
			name:      "Not CREATE or UPDATE => DELETE always allowed with no mutation",
			operation: admissionv1.Delete,
			username:  "t628545",
			groups:    []string{"oidc:s_platform_namespaced_poweruser"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectPatch:   false,
		},
		{
			name:      "kubernetes-admin => CREATE always allowed with no mutation",
			operation: admissionv1.Create,
			username:  "kubernetes-admin",
			groups:    []string{"system:masters"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectPatch:   false,
		},
		{
			name:      "kubernetes-admin => UPDATE always allowed with no mutation",
			operation: admissionv1.Update,
			username:  "kubernetes-admin",
			groups:    []string{"system:masters"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectPatch:   false,
		},
		{
			name:      "User in BindDef specified Group => CREATE should add label from matching BindDefinition",
			operation: admissionv1.Create,
			username:  "t628545",
			groups:    []string{"oidc:s_platform_namespaced_poweruser", "xyzGroup"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: true,
		},
		{
			name:      "User in BindDef specified Group => [NO_LABEL] UPDATE should add label from matching BindDefinition",
			operation: admissionv1.Update,
			username:  "t628545",
			groups:    []string{"oidc:s_platform_namespaced_poweruser", "xyzGroup"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: true,
		},
		{
			name:      "User in BindDef specified Group => [OVERWRITE_LABEL] UPDATE should NOT add label from matching BindDefinition",
			operation: admissionv1.Update,
			username:  "t628545",
			groups:    []string{"oidc:s_platform_namespaced_poweruser", "xyzGroup"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
					Labels: map[string]string{
						"t-caas.telekom.com/owner": "tenant",
					},
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: false,
		},
		{
			name:      "User in BindDef specified ServiceAccount => CREATE should add label from matching BindDefinition",
			operation: admissionv1.Create,
			username:  "system:serviceaccount:kube-system:m2m-sa-t-caas-platform",
			groups:    []string{},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: true,
		},
		{
			name:      "User in BindDef specified ServiceAccount => [NO_LABEL] UPDATE should add label from matching BindDefinition",
			operation: admissionv1.Update,
			username:  "system:serviceaccount:kube-system:m2m-sa-t-caas-platform",
			groups:    []string{},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: true,
		},
		{
			name:      "User in BindDef specified ServiceAccount => [OVERWRITE_LABEL] UPDATE should NOT add label from matching BindDefinition",
			operation: admissionv1.Update,
			username:  "system:serviceaccount:kube-system:m2m-sa-t-caas-platform",
			groups:    []string{},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
					Labels: map[string]string{
						"t-caas.telekom.com/owner": "tenant",
					},
				}},
			expectAllowed: true,
			expectLabels: map[string]string{
				"t-caas.telekom.com/owner": "platform",
			},
			expectPatch: false,
		},
		{
			name:      "No matching group or SA => CREATE denied",
			operation: admissionv1.Create,
			username:  "some-other-user",
			groups:    []string{"unrelated-group"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: false,
			expectPatch:   false,
		},
		{
			name:      "No matching group or SA => UPDATE denied",
			operation: admissionv1.Update,
			username:  "some-other-user",
			groups:    []string{"unrelated-group"},
			namespace: &corev1.Namespace{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "Namespace",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-ns",
				}},
			expectAllowed: false,
			expectPatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildRequest(tt.operation, tt.username, tt.groups, tt.namespace, tt.oldNamespace)

			// Call the mutator
			resp := mutator.Handle(context.Background(), req)

			// Check if allowed / denied
			if tt.expectAllowed && !resp.Allowed {
				t.Errorf("expected Allowed but got Denied: %v", resp.Result.Message)
			}
			if !tt.expectAllowed && resp.Allowed {
				t.Errorf("expected Denied but got Allowed")
			}

			// Check the HTTP status code if an error
			if !tt.expectAllowed && resp.Result.Code != int32(tt.expectStatusCode) && tt.expectStatusCode != 0 {
				t.Errorf("expected status code %d, got %d", tt.expectStatusCode, resp.Result.Code)
			}

			// If we expected a patch, verify that labels were updated
			if tt.expectPatch {
				// Check we got patch operations
				if len(resp.Patches) == 0 {
					t.Errorf("expected patches but got none")
				} else {
					// 1) Convert resp.Patches (a slice of operations) into raw JSON
					patchesJSON, err := json.Marshal(resp.Patches)
					if err != nil {
						t.Errorf("failed to marshal resp.Patches: %v", err)
					}

					// 2) Apply that JSON patch to the original object
					originalBytes, _ := json.Marshal(tt.namespace)
					patched, err := admission.ApplyPatch(originalBytes, patchesJSON)
					if err != nil {
						t.Errorf("failed to apply JSON patch: %v", err)
					}

					// 3) Unmarshal the result to see final mutated namespace
					var patchedNamespace corev1.Namespace
					if err := json.Unmarshal(patched, &patchedNamespace); err != nil {
						t.Errorf("failed to unmarshal patched namespace: %v", err)
					}

					// 4) Confirm that the expected labels are present
					for k, v := range tt.expectLabels {
						gotVal, ok := patchedNamespace.Labels[k]
						if !ok || gotVal != v {
							t.Errorf("expected label %q=%q, got %q", k, v, gotVal)
						}
					}
				}
			} else {
				// If we did NOT expect a patch, ensure no patch ops
				if len(resp.Patches) > 0 {
					t.Errorf("did not expect any patches, but got some: %v", resp.Patches)
				}
			}
		})
	}
}

// Performance test
func TestNamespaceMutatorPerformance(t *testing.T) {
	isCI := os.Getenv("CI")
	if isCI == "true" {
		t.Skip("Skipping performance tests in CI")
	}
	// ----------------------------------------------------------------------
	// 1. Setup the scheme for our fake client
	// ----------------------------------------------------------------------
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme)) // For corev1, admissionv1, etc.
	utilruntime.Must(authzv1alpha1.AddToScheme(scheme))  // Register your CRD types

	// ----------------------------------------------------------------------
	// 2. Create some sample BindDefinitions that might match certain groups
	// ----------------------------------------------------------------------
	bindDefPlatform := authzv1alpha1.BindDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "platform-namespaced-poweruser",
		},
		Spec: authzv1alpha1.BindDefinitionSpec{
			TargetName: "bd-platform-ns-poweruser",
			Subjects: []rbacv1.Subject{
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_namespaced_poweruser",
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_cluster_collaborator",
				},
				{
					APIGroup: "rbac.authorization.k8s.io",
					Kind:     "Group",
					Name:     "oidc:s_platform_cluster_poweruser",
				},
				{
					Kind:      "ServiceAccount",
					Name:      "m2m-sa-t-caas-platform",
					Namespace: "kube-system",
				},
			},
			RoleBindings: []authzv1alpha1.NamespaceBinding{{
				ClusterRoleRefs: []string{"t-caas-platform-namespaced-poweruser"},
				NamespaceSelector: []metav1.LabelSelector{
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "kubernetes.io/metadata.name",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"kube-system", "kube-public", "kube-node-lease"},
							},
						},
					},
					{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "t-caas.telekom.com/owner",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"platform"},
							},
							{
								Key:      "t-caas.telekom.com/owner",
								Operator: metav1.LabelSelectorOpNotIn,
								Values:   []string{"tenant", "thirdparty"},
							},
						},
					},
				},
			}},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(&bindDefPlatform).
		Build()

	mutator := &webhooks.NamespaceMutator{
		Client: fakeClient,
	}
	dec := crAdmission.NewDecoder(scheme)
	if err := mutator.InjectDecoder(dec); err != nil {
		t.Fatalf("failed to inject decoder: %v", err)
	}

	// 2) Define concurrency and total requests
	const concurrency = 100
	const totalRequests = 10000 // Reduced from 1000000 to avoid exhausting local resources during test runs

	// We'll store durations to compute average / percentiles
	durations := make([]time.Duration, 0, totalRequests)

	// We want to avoid data races when appending to durations
	var mu sync.Mutex

	// We'll use a channel as a semaphore for concurrency-limiting
	sem := make(chan struct{}, concurrency)

	// 3) Generate a basic AdmissionRequest builder function
	// We'll always do a "Create" operation for this example
	buildRequest := func(_ int) crAdmission.Request {
		// Example: user in group => we do a request that should be allowed
		ns := &corev1.Namespace{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Namespace",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "perf-ns-test",
			},
		}
		nsRaw, _ := json.Marshal(ns)
		return crAdmission.Request{
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				UserInfo: authenticationv1.UserInfo{
					Username: "t628545",
					Groups:   []string{"oidc:s_platform_namespaced_poweruser"},
				},
				Object: runtime.RawExtension{Raw: nsRaw},
			},
		}
	}

	// 4) Run the test in parallel
	var wg sync.WaitGroup
	wg.Add(totalRequests)

	for i := 0; i < totalRequests; i++ {
		go func(index int) {
			defer wg.Done()

			// Acquire concurrency slot
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build an admission request
			req := buildRequest(index)

			// Measure time
			start := time.Now()
			resp := mutator.Handle(context.Background(), req)
			elapsed := time.Since(start)

			// We might check whether it was allowed or not
			if !resp.Allowed {
				t.Errorf("request %d was unexpectedly denied: %v", index, resp.Result.Message)
			}

			// Record the duration
			mu.Lock()
			durations = append(durations, elapsed)
			mu.Unlock()

		}(i)
	}

	// Wait for all requests to finish
	wg.Wait()

	// 5) Calculate stats
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	avg := total / time.Duration(len(durations))

	// Sort the durations if you want to compute p95, p99, etc.
	// We'll just compute average for brevity here
	t.Logf("Ran %d requests with concurrency=%d", totalRequests, concurrency)
	t.Logf("Average mutator.Handle() latency: %v", avg)
}

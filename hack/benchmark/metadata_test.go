// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

type fakeCommandRunner map[string][]byte

func (f fakeCommandRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name
	for _, arg := range args {
		key += " " + arg
	}
	b, ok := f[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func TestCollectEnvironmentProbesLiveTools(t *testing.T) {
	e := CollectEnvironment(context.Background(), fakeCommandRunner{
		"kind version":                                []byte("kind v0.30.0\n"),
		"go version":                                  []byte("go version go1.26.6 linux/amd64\n"),
		"helm version --short":                        []byte("v3.19.0\n"),
		"kyverno version":                             []byte("v1.19.0\n"),
		"kubectl version -o json":                     []byte(`{"serverVersion":{"gitVersion":"v1.36.1"}}`),
		"kubectl get nodes -o json":                   []byte(`{"items":[{"status":{"nodeInfo":{"kubeletVersion":"v1.36.1"}}}]}`),
		"docker version --format {{.Server.Version}}": []byte("28.0.0\n"),
	}, map[string]string{"BENCH_ARCH": "amd64"})
	if e.KindVersion == "" || e.GoVersion == "" || e.HelmVersion == "" ||
		e.KyvernoVersion == "" || e.KubernetesVersion != "v1.36.1" ||
		e.NodeVersion != "v1.36.1" || e.ContainerRuntime == "" {
		t.Fatalf("missing probes: %#v", e)
	}
}

func TestCollectEnvironmentUsesCapturedPolicyMaterial(t *testing.T) {
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "policy.yaml")
	material := []byte("engine: map\npolicy: captured\n")
	if err := os.WriteFile(p, material, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateBenchmarkArtifactPath(p); err != nil {
		t.Fatalf("captured policy fixture is not private: %v", err)
	}
	e := CollectEnvironment(context.Background(), fakeCommandRunner{
		"kubectl get mutatingwebhookconfigurations -o json": []byte("webhook state"),
	}, map[string]string{"BENCH_POLICY_PATH": p})
	sum := sha256.Sum256(material)
	want := hex.EncodeToString(sum[:])
	if e.PolicyHash != want {
		t.Fatalf("policy hash = %q, want captured material %q", e.PolicyHash, want)
	}
	if e.Evidence[fieldPolicyHash] != "captured per-engine policy inputs" {
		t.Fatalf("policy evidence = %q", e.Evidence[fieldPolicyHash])
	}
}

func TestValidateBenchmarkArtifactPathRejectsUnsafeFiles(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "policy.yaml")
	if err := os.WriteFile(p, []byte("policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) error{
		"relative": func(string) error { return validateBenchmarkArtifactPath("policy.yaml") },
		"world-readable": func(path string) error {
			if err := os.Chmod(path, 0644); err != nil {
				return err
			}
			return validateBenchmarkArtifactPath(path)
		},
		"symlink": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			if err := os.Symlink(filepath.Join(d, "target"), path); err != nil {
				return err
			}
			return validateBenchmarkArtifactPath(path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if name != "relative" {
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("policy"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := mutate(p); err == nil {
				t.Fatalf("accepted unsafe artifact path")
			}
		})
	}
}

func TestCellInputMaterialRejectsUnsafeEnvironmentPath(t *testing.T) {
	t.Setenv("BENCHMARK_INPUT_MATERIAL", filepath.Join(t.TempDir(), "missing.yaml"))
	if _, err := cellInputMaterial(Cell{Engine: "map"}); err == nil {
		t.Fatal("accepted missing caller-controlled input material")
	}
}

func TestEnvironmentDeterministic(t *testing.T) {
	a := EnvironmentFrom(map[string]string{"BENCH_ARCH": "amd64", "BENCH_CPUS": "4"})
	b := EnvironmentFrom(map[string]string{"BENCH_ARCH": "amd64", "BENCH_CPUS": "4"})
	if string(MarshalEnvironment(a)) != string(MarshalEnvironment(b)) {
		t.Fatal("metadata differs")
	}
}
func TestEnvironmentFallback(t *testing.T) {
	if EnvironmentFrom(map[string]string{}).Architecture == "" {
		t.Fatal("architecture missing")
	}
}
func TestWriteEnvironment(t *testing.T) {
	p := filepath.Join(t.TempDir(), "environment.json")
	if e := WriteEnvironment(p, EnvironmentFrom(map[string]string{})); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal(e)
	}
}

func TestWriteInputMaterial(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "input.yaml")
	want := []byte("apiVersion: v1\n")
	if err := WriteInputMaterial(p, want); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("input material = %q, want %q", got, want)
	}
}

func TestValidateEvidenceRequiresLiveHostCapacity(t *testing.T) {
	e := Environment{
		Architecture: "amd64", KubernetesVersion: "v1.36.1", OperatorVersion: "image",
		ChartVersion: "chart", PolicyHash: "hash", HostCPUModel: "cpu", HostMemory: "mem",
		CPUs: "4", Memory: "8 GiB", Evidence: map[string]string{
			"kubernetes_version": "kubectl serverVersion",
			"operator_version":   "kubectl deployment image",
			"chart_version":      "kubectl deployment label",
			"cpus":               "environment override",
			fieldMemory:          evidenceLiveMeminfo,
			fieldHostCPUModel:    "live /proc/cpuinfo",
			fieldHostMemory:      evidenceLiveMeminfo,
		},
	}
	if err := e.ValidateEvidence(); err == nil {
		t.Fatal("accepted host capacity from an environment override")
	}
}

func TestComparisonEnvironmentIDIgnoresEngineSpecificMetadata(t *testing.T) {
	base := Environment{
		Architecture: "amd64", CPUs: "4", Memory: "8Gi", GoVersion: "go1.26",
		KindVersion: "kind v0.30", KubernetesVersion: "v1.36.1", HelmVersion: "v3.19",
		NodeImage: "kindest/node:v1.36.1@sha256:node", NodeVersion: "v1.36.1",
		HostCPUModel: "cpu", HostMemory: "8Gi", ContainerRuntime: "containerd",
		PolicyHash: "native", KyvernoVersion: "v1.19.0", KyvernoChart: "3.9.0",
		KyvernoChartSHA: "chart-a", Evidence: map[string]string{fieldPolicyHash: "native"},
	}
	other := base
	other.PolicyHash = kyvernoCommand
	other.KyvernoVersion = "v1.19.1"
	other.KyvernoChart = "3.9.1"
	other.KyvernoChartSHA = "chart-b"
	other.Evidence = map[string]string{fieldPolicyHash: kyvernoCommand}
	if comparisonEnvironmentID(base) != comparisonEnvironmentID(other) {
		t.Fatal("engine-specific provenance changed comparison identity")
	}
}

func TestComparisonEnvironmentIDIncludesSubstrateMetadata(t *testing.T) {
	base := Environment{
		Architecture: "amd64", CPUs: "4", Memory: "8Gi", GoVersion: "go1.26",
		KindVersion: "kind v0.30", KubernetesVersion: "v1.36.1", HelmVersion: "v3.19",
		NodeImage: "kindest/node:v1.36.1@sha256:node", NodeVersion: "v1.36.1",
		HostCPUModel: "cpu", HostMemory: "8Gi", ContainerRuntime: "containerd",
	}
	for name, mutate := range map[string]func(*Environment){
		"kubernetes": func(e *Environment) { e.KubernetesVersion = "v1.37.0" },
		"node":       func(e *Environment) { e.NodeVersion = "v1.37.0" },
		"host":       func(e *Environment) { e.HostCPUModel = "other cpu" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if comparisonEnvironmentID(base) == comparisonEnvironmentID(changed) {
				t.Fatalf("%s substrate change did not change comparison identity", name)
			}
		})
	}
}

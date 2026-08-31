// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Environment struct {
	Architecture      string            `json:"architecture"`
	CPUs              string            `json:"cpus"`
	Memory            string            `json:"memory"`
	GoVersion         string            `json:"go_version"`
	KindVersion       string            `json:"kind_version"`
	KubernetesVersion string            `json:"kubernetes_version"`
	HelmVersion       string            `json:"helm_version"`
	KyvernoVersion    string            `json:"kyverno_version"`
	KyvernoChart      string            `json:"kyverno_chart,omitempty"`
	KyvernoChartSHA   string            `json:"kyverno_chart_sha256,omitempty"`
	NodeImage         string            `json:"node_image"`
	NodeVersion       string            `json:"node_version,omitempty"`
	OperatorVersion   string            `json:"operator_version,omitempty"`
	ChartVersion      string            `json:"chart_version,omitempty"`
	PolicyHash        string            `json:"policy_hash,omitempty"`
	HostCPUModel      string            `json:"host_cpu_model,omitempty"`
	HostMemory        string            `json:"host_memory,omitempty"`
	ContainerRuntime  string            `json:"container_runtime,omitempty"`
	Evidence          map[string]string `json:"evidence,omitempty"`
}

func EnvironmentFrom(e map[string]string) Environment {
	return Environment{
		Architecture: pick(e, "BENCH_ARCH", runtime.GOARCH), CPUs: e[envBenchCPUs], Memory: e["BENCH_MEMORY"],
		GoVersion: e["BENCH_GO_VERSION"], KindVersion: e["BENCH_KIND_VERSION"],
		KubernetesVersion: e["BENCH_KUBERNETES_VERSION"], HelmVersion: e["BENCH_HELM_VERSION"],
		KyvernoVersion: e["BENCH_KYVERNO_VERSION"], KyvernoChart: e["BENCH_KYVERNO_CHART"],
		KyvernoChartSHA: e["BENCH_KYVERNO_CHART_SHA256"], NodeImage: e["BENCH_NODE_IMAGE"],
		NodeVersion: e["BENCH_NODE_VERSION"], OperatorVersion: e["BENCH_OPERATOR_VERSION"],
		ChartVersion: e["BENCH_CHART_VERSION"], PolicyHash: e["BENCH_POLICY_HASH"],
		HostCPUModel: e["BENCH_HOST_CPU_MODEL"], HostMemory: e["BENCH_HOST_MEMORY"],
		ContainerRuntime: e["BENCH_CONTAINER_RUNTIME"],
	}
}
func pick(m map[string]string, k, d string) string {
	if v := m[k]; v != "" {
		return v
	}
	return d
}
func MarshalEnvironment(e Environment) []byte {
	b, err := json.Marshal(e)
	if err != nil {
		panic(fmt.Sprintf("marshal environment: %v", err))
	}
	return b
}
func HostEnvironment() Environment {
	return EnvironmentFrom(hostEnvironmentValues())
}
func hostEnvironmentValues() map[string]string {
	m := map[string]string{}
	for _, v := range os.Environ() {
		for i := range v {
			if v[i] == '=' {
				m[v[:i]] = v[i+1:]
				break
			}
		}
	}
	return m
}

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type OSCommandRunner struct{}

const linuxCPUInfoProbe = `/^[Mm]odel([[:space:]]+name)?[[:space:]]*:/ {print $2; found=1; exit}` +
	` /^((Hardware)|(Processor))[[:space:]]*:/ {if (!found) hardware=$2}` +
	` /^CPU implementer[[:space:]]*:/ {implementer=$2}` +
	` /^CPU part[[:space:]]*:/ {part=$2}` +
	` END {if (!found) {if (hardware != "") print hardware; else if (implementer != "") {` +
	`printf "ARM implementer %s", implementer; if (part != "") printf ", part %s", part; print ""}}}`

func (OSCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, fmt.Errorf("command path is not allowed: %q", name)
	}
	switch name {
	case "awk", "docker", "getconf", "go", "helm", "kubectl", "kind", kyvernoCommand, "sysctl":
	default:
		return nil, fmt.Errorf("command is not allowlisted: %q", name)
	}
	// #nosec G204 -- executable names are restricted to the fixed allowlist above.
	return exec.CommandContext(ctx, name, args...).Output()
}

// CollectEnvironment gathers observable tool and cluster metadata. Commands are
// bounded and failures are retained as empty fields so a caller can report the
// missing evidence instead of mistaking an env override for live proof.
//
//nolint:gocyclo // the probe sequence mirrors the evidence fields collected.
func CollectEnvironment(parent context.Context, runner CommandRunner, values map[string]string) Environment {
	e := EnvironmentFrom(values)
	e.Evidence = map[string]string{}
	for key, field := range map[string]string{
		envBenchCPUs: fieldCPUs, "BENCH_MEMORY": fieldMemory, "BENCH_HOST_CPU_MODEL": fieldHostCPUModel,
		"BENCH_HOST_MEMORY": fieldHostMemory, "BENCH_OPERATOR_VERSION": fieldOperatorVersion,
		"BENCH_CHART_VERSION": headerChartVersion, "BENCH_POLICY_HASH": fieldPolicyHash,
		"BENCH_KUBERNETES_VERSION": fieldKubernetesVersion, "BENCH_NODE_VERSION": "node_version",
		"BENCH_NODE_IMAGE": "node_image", "BENCH_KYVERNO_CHART": "kyverno_chart",
		"BENCH_KYVERNO_CHART_SHA256": "kyverno_chart_sha256",
	} {
		if values[key] != "" {
			e.Evidence[field] = "environment override"
		}
	}
	probe := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		defer cancel()
		return runner.Run(ctx, name, args...)
	}
	probeVersion := func(name string, args ...string) string {
		b, err := probe(name, args...)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	if e.KindVersion == "" {
		e.KindVersion = probeVersion("kind", "version")
	}
	if e.GoVersion == "" {
		e.GoVersion = probeVersion("go", "version")
		if e.GoVersion != "" {
			e.Evidence["go_version"] = "live go version"
		}
	}
	if e.HelmVersion == "" {
		e.HelmVersion = probeVersion("helm", "version", "--short")
	}
	if e.KyvernoVersion == "" {
		e.KyvernoVersion = probeVersion(kyvernoCommand, "version")
	}
	if e.KubernetesVersion == "" {
		if b, err := probe("kubectl", "version", "-o", "json"); err == nil {
			var v struct {
				ServerVersion struct {
					GitVersion string `json:"gitVersion"`
				} `json:"serverVersion"`
			}
			if json.Unmarshal(b, &v) == nil {
				e.KubernetesVersion = v.ServerVersion.GitVersion
			}
		}
		if e.KubernetesVersion != "" {
			e.Evidence["kubernetes_version"] = "kubectl serverVersion"
		}
	}
	if e.NodeVersion == "" {
		if b, err := probe("kubectl", "get", "nodes", "-o", "json"); err == nil {
			var nodes struct {
				Items []struct {
					Status struct {
						NodeInfo struct {
							KubeletVersion string `json:"kubeletVersion"`
						} `json:"nodeInfo"`
					} `json:"status"`
				} `json:"items"`
			}
			if json.Unmarshal(b, &nodes) == nil && len(nodes.Items) > 0 {
				e.NodeVersion = nodes.Items[0].Status.NodeInfo.KubeletVersion
			}
		}
		if e.NodeVersion != "" {
			e.Evidence["node_version"] = "kubectl node status.nodeInfo.kubeletVersion"
		}
	}
	if e.ContainerRuntime == "" {
		e.ContainerRuntime = probeVersion("docker", "version", "--format", "{{.Server.Version}}")
	}
	if e.HostCPUModel == "" {
		e.HostCPUModel = probeVersion("sysctl", "-n", "machdep.cpu.brand_string")
		if e.HostCPUModel == "" {
			e.HostCPUModel = probeVersion("sysctl", "-n", "hw.model")
		}
		if e.HostCPUModel != "" {
			e.Evidence[fieldHostCPUModel] = "live sysctl"
		}
	}
	if e.HostMemory == "" {
		e.HostMemory = probeVersion("sysctl", "-n", "hw.memsize")
		if e.HostMemory == "" {
			e.HostMemory = probeVersion("sysctl", "-n", "hw.physmem")
		}
		if e.HostMemory != "" {
			e.Evidence[fieldHostMemory] = "live sysctl"
		}
	}
	if e.CPUs == "" {
		e.CPUs = probeVersion("getconf", "_NPROCESSORS_ONLN")
		if e.CPUs != "" {
			e.Evidence[fieldCPUs] = "live getconf"
		}
	}
	if e.Memory == "" {
		e.Memory = probeVersion("awk", `/MemTotal:/ {print $2 " kB"; exit}`, "/proc/meminfo")
		if e.Memory != "" {
			e.Evidence[fieldMemory] = evidenceLiveMeminfo
		}
	}
	if e.HostCPUModel == "" {
		e.HostCPUModel = probeVersion("awk", `/^model name[[:space:]]*:/ {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}`, "/proc/cpuinfo")
		if e.HostCPUModel == "" {
			// Linux arm64 exposes implementation and part identifiers instead of
			// the x86-style model name. Keep this as live /proc/cpuinfo evidence
			// rather than substituting a caller-provided description.
			e.HostCPUModel = probeVersion("awk", "-F:[[:space:]]*", linuxCPUInfoProbe, "/proc/cpuinfo")
		}
		if e.HostCPUModel != "" {
			e.Evidence[fieldHostCPUModel] = evidenceLiveCPUInfo
		}
	}
	if e.HostMemory == "" {
		e.HostMemory = e.Memory
		if e.HostMemory != "" {
			e.Evidence[fieldHostMemory] = evidenceLiveMeminfo
		}
	}
	if e.OperatorVersion == "" || e.ChartVersion == "" {
		if b, err := probe("kubectl", "get", "deployments", "-A", "-l", "app.kubernetes.io/name=auth-operator", "-o", "json"); err == nil {
			var d struct {
				Items []struct {
					Metadata struct {
						Labels map[string]string `json:"labels"`
					} `json:"metadata"`
					Spec struct {
						Template struct {
							Spec struct {
								Containers []struct {
									Image string `json:"image"`
								} `json:"containers"`
							} `json:"spec"`
						} `json:"template"`
					} `json:"spec"`
				} `json:"items"`
			}
			if json.Unmarshal(b, &d) == nil && len(d.Items) > 0 {
				item := d.Items[0]
				if e.OperatorVersion == "" && len(item.Spec.Template.Spec.Containers) > 0 {
					e.OperatorVersion = item.Spec.Template.Spec.Containers[0].Image
					e.Evidence["operator_version"] = "kubectl deployment image"
				}
				if e.ChartVersion == "" {
					e.ChartVersion = item.Metadata.Labels["helm.sh/chart"]
					if e.ChartVersion != "" {
						e.Evidence["chart_version"] = "kubectl deployment label"
					}
				}
			}
		}
	}
	if path := values["BENCH_POLICY_PATH"]; path != "" {
		if b, err := readBenchmarkArtifact(path); err != nil {
			e.Evidence[fieldPolicyHash] = "invalid captured policy material: " + err.Error()
		} else {
			e.PolicyHash = hashBytes(b)
			e.Evidence[fieldPolicyHash] = "captured per-engine policy inputs"
		}
	}
	if e.PolicyHash == "" && values["BENCH_POLICY_PATH"] == "" {
		if b, err := probe("kubectl", "get", "mutatingwebhookconfigurations", "-o", "json"); err == nil {
			e.PolicyHash = hashBytes(b)
			e.Evidence[fieldPolicyHash] = "kubectl mutatingwebhookconfigurations"
		}
	}
	return e
}

// openBenchmarkArtifact only opens private, regular files owned by the current
// user. Comparing the pre-open and opened file identities closes the
// validation/read replacement gap for caller-controlled provenance paths.
func openBenchmarkArtifact(path string) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path must be absolute")
	}
	if filepath.Clean(path) != path {
		return nil, fmt.Errorf("path is not canonical")
	}
	// #nosec G304,G703 -- canonical path and private ownership are checked before opening.
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}
	if err := validateBenchmarkArtifactFileInfo(info); err != nil {
		return nil, err
	}
	if err := validateBenchmarkArtifactParent(filepath.Dir(path)); err != nil {
		return nil, err
	}
	// #nosec G304,G703 -- identity, ownership, type, and mode are checked on the opened descriptor below.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open path: %w", err)
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened path: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, fmt.Errorf("path changed while opening")
	}
	if err := validateBenchmarkArtifactFileInfo(openedInfo); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func validateBenchmarkArtifactFileInfo(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("file mode is %04o, want 0600", info.Mode().Perm())
	}
	if info.Sys() == nil {
		return fmt.Errorf("file ownership is unavailable")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || strconv.FormatUint(uint64(stat.Uid), 10) != strconv.Itoa(os.Getuid()) {
		return fmt.Errorf("file is not owned by the current user")
	}
	return nil
}

func validateBenchmarkArtifactParent(parent string) error {
	if filepath.Clean(parent) != parent {
		return fmt.Errorf("parent is not canonical")
	}
	canonical, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return fmt.Errorf("resolve parent: %w", err)
	}
	if canonical != parent {
		return fmt.Errorf("parent contains a symlink")
	}
	// #nosec G304,G703 -- parent is canonicalized and checked for private ownership below.
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("stat parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("parent is not a directory")
	}
	if parentInfo.Mode().Perm() != 0o700 {
		return fmt.Errorf("parent mode is %04o, want 0700", parentInfo.Mode().Perm())
	}
	if stat, ok := parentInfo.Sys().(*syscall.Stat_t); !ok || strconv.FormatUint(uint64(stat.Uid), 10) != strconv.Itoa(os.Getuid()) {
		return fmt.Errorf("parent is not owned by the current user")
	}
	return nil
}

func validateBenchmarkArtifactPath(path string) error {
	file, err := openBenchmarkArtifact(path)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close validated path: %w", err)
	}
	return nil
}

func readBenchmarkArtifact(path string) ([]byte, error) {
	file, err := openBenchmarkArtifact(path)
	if err != nil {
		return nil, err
	}
	contents, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read validated path: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close validated path: %w", closeErr)
	}
	return contents, nil
}

// readBenchmarkFile makes caller-provided relative paths absolute before
// routing them through the ownership, mode, type, and identity checks above.
func readBenchmarkFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	return readBenchmarkArtifact(absolute)
}
func (e Environment) ValidateEvidence() error {
	if e.Architecture == "" {
		return fmt.Errorf("architecture evidence missing")
	}
	if e.KubernetesVersion == "" {
		return fmt.Errorf("kubernetes version evidence missing")
	}
	if e.OperatorVersion == "" || e.ChartVersion == "" || e.PolicyHash == "" {
		return fmt.Errorf("operator, chart, and policy evidence missing")
	}
	for _, key := range []string{fieldKubernetesVersion, fieldOperatorVersion, headerChartVersion} {
		if strings.EqualFold(e.Evidence[key], "environment override") {
			return fmt.Errorf("%s has no live evidence", key)
		}
	}
	if e.HostCPUModel == "" || e.HostMemory == "" {
		return fmt.Errorf("host CPU and memory evidence missing")
	}
	if e.CPUs == "" || e.Memory == "" {
		return fmt.Errorf("CPU and memory capacity evidence missing")
	}
	for _, key := range []string{fieldCPUs, fieldMemory, fieldHostCPUModel, fieldHostMemory} {
		if e.Evidence[key] == "" || strings.EqualFold(e.Evidence[key], "environment override") {
			return fmt.Errorf("%s has no live evidence", key)
		}
	}
	return nil
}
func WriteEnvironment(path string, e Environment) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".environment-*")
	if err != nil {
		return err
	}
	n := tmp.Name()
	defer func() { _ = os.Remove(n) }()
	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(n, path)
}

func WriteInputMaterial(path string, material []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".input-material-*")
	if err != nil {
		return err
	}
	n := tmp.Name()
	defer func() { _ = os.Remove(n) }()
	if _, err = tmp.Write(material); err != nil {
		_ = tmp.Close()
		return err
	}
	if closeErr := tmp.Close(); closeErr != nil {
		return closeErr
	}
	return os.Rename(n, path)
}

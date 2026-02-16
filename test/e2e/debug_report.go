//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/onsi/ginkgo/v2"
	"github.com/telekom/auth-operator/test/utils"
)

// statusTrue is the status condition value for ready nodes.
const statusTrue = "True"

// DebugReport represents a structured test debug report.
type DebugReport struct {
	Metadata    reportMetadata  `json:"metadata"`
	TestInfo    testInfo        `json:"test_info"`
	ClusterInfo clusterInfo     `json:"cluster_info"`
	Resources   resourceSummary `json:"resources"`
	Errors      []errorEntry    `json:"errors,omitempty"`
	Timing      timingInfo      `json:"timing"`
	Artifacts   []string        `json:"artifacts,omitempty"`
}

type reportMetadata struct {
	GeneratedAt   string `json:"generated_at"`
	RunID         string `json:"run_id"`
	DebugLevel    int    `json:"debug_level"`
	OutputDir     string `json:"output_dir"`
	ClusterName   string `json:"cluster_name"`
	InstallMethod string `json:"install_method"`
}

type testInfo struct {
	SuiteName   string `json:"suite_name"`
	SpecName    string `json:"spec_name"`
	Labels      string `json:"labels"`
	State       string `json:"state"`
	FailMessage string `json:"fail_message,omitempty"`
}

type clusterInfo struct {
	KubernetesVersion string `json:"kubernetes_version"`
	NodeCount         int    `json:"node_count"`
	NodeStatus        string `json:"node_status"`
	APIServerReady    bool   `json:"api_server_ready"`
}

type resourceSummary struct {
	RoleDefinitions       int      `json:"role_definitions"`
	BindDefinitions       int      `json:"bind_definitions"`
	WebhookAuthorizers    int      `json:"webhook_authorizers"`
	GeneratedClusterRoles int      `json:"generated_cluster_roles"`
	GeneratedRoles        int      `json:"generated_roles"`
	OperatorPods          []string `json:"operator_pods"`
	WebhookPods           []string `json:"webhook_pods"`
}

type errorEntry struct {
	Type      string `json:"type"`
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type timingInfo struct {
	StartTime string       `json:"start_time"`
	EndTime   string       `json:"end_time"`
	Duration  string       `json:"duration"`
	SlowSteps []stepTiming `json:"slow_steps,omitempty"`
}

type stepTiming struct {
	Name     string `json:"name"`
	Duration string `json:"duration"`
}

// GenerateDebugReport creates a structured debug report for the current test.
func GenerateDebugReport(report ginkgo.SpecReport, installMethod string) *DebugReport {
	clusterName := os.Getenv("KIND_CLUSTER")
	if clusterName == "" {
		clusterName = "auth-operator-e2e"
	}
	dr := &DebugReport{
		Metadata: reportMetadata{
			GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
			RunID:         os.Getenv("RUN_ID"),
			DebugLevel:    utils.DebugLevel,
			OutputDir:     utils.GetE2EOutputDir(),
			ClusterName:   clusterName,
			InstallMethod: installMethod,
		},
		TestInfo: testInfo{
			SuiteName: "Auth Operator E2E",
			SpecName:  report.FullText(),
			State:     report.State.String(),
		},
		Timing: timingInfo{
			StartTime: report.StartTime.UTC().Format(time.RFC3339),
			EndTime:   report.EndTime.UTC().Format(time.RFC3339),
			Duration:  report.RunTime.String(),
		},
	}

	// Extract labels
	if len(report.Labels()) > 0 {
		dr.TestInfo.Labels = strings.Join(report.Labels(), ", ")
	}

	// Add failure message if failed
	if report.Failed() {
		dr.TestInfo.FailMessage = report.Failure.Message
	}

	// Collect cluster info
	dr.ClusterInfo = collectClusterInfo()

	// Collect resource summary
	dr.Resources = collectResourceSummary()

	// Collect errors from events
	dr.Errors = collectRecentErrors()

	return dr
}

func collectClusterInfo() clusterInfo {
	info := clusterInfo{}

	// Get Kubernetes version
	cmd := exec.CommandContext(context.Background(), "kubectl", "version", "-o", "json")
	output, err := utils.Run(cmd)
	if err == nil {
		var versionInfo map[string]interface{}
		if json.Unmarshal(output, &versionInfo) == nil {
			if serverVersion, ok := versionInfo["serverVersion"].(map[string]interface{}); ok {
				info.KubernetesVersion = fmt.Sprintf("%s.%s", serverVersion["major"], serverVersion["minor"])
			}
		}
	}

	// Get node count and status
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "nodes", "-o", "jsonpath={.items[*].status.conditions[?(@.type=='Ready')].status}")
	output, err = utils.Run(cmd)
	if err == nil {
		statuses := strings.Fields(string(output))
		info.NodeCount = len(statuses)
		allReady := true
		for _, s := range statuses {
			if s != statusTrue {
				allReady = false
				break
			}
		}
		if allReady {
			info.NodeStatus = "Ready"
		} else {
			info.NodeStatus = "NotReady"
		}
	}

	// Check API server
	cmd = exec.CommandContext(context.Background(), "kubectl", "cluster-info")
	_, err = utils.Run(cmd)
	info.APIServerReady = err == nil

	return info
}

func collectResourceSummary() resourceSummary {
	summary := resourceSummary{}

	// Count RoleDefinitions
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "roledefinitions", "-A", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ := utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.RoleDefinitions = len(strings.Fields(string(output)))
	}

	// Count BindDefinitions
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "binddefinitions", "-A", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.BindDefinitions = len(strings.Fields(string(output)))
	}

	// Count WebhookAuthorizers
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "webhookauthorizers", "-A", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.WebhookAuthorizers = len(strings.Fields(string(output)))
	}

	// Count generated ClusterRoles (labeled by auth-operator)
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "clusterroles", "-l", "app.kubernetes.io/managed-by=auth-operator", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.GeneratedClusterRoles = len(strings.Fields(string(output)))
	}

	// Count generated Roles (labeled by auth-operator)
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "roles", "-A", "-l", "app.kubernetes.io/managed-by=auth-operator", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.GeneratedRoles = len(strings.Fields(string(output)))
	}

	// Get operator pod names
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-A", "-l", "control-plane=controller-manager", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.OperatorPods = strings.Fields(string(output))
	}

	// Get webhook pod names
	cmd = exec.CommandContext(context.Background(), "kubectl", "get", "pods", "-A", "-l", "control-plane=webhook-server", "-o", "jsonpath={.items[*].metadata.name}")
	output, _ = utils.Run(cmd)
	if strings.TrimSpace(string(output)) != "" {
		summary.WebhookPods = strings.Fields(string(output))
	}

	return summary
}

func collectRecentErrors() []errorEntry {
	var errors []errorEntry

	// Get warning/error events from last 10 minutes
	cmd := exec.CommandContext(context.Background(), "kubectl", "get", "events", "-A",
		"--field-selector=type!=Normal",
		"-o", "jsonpath={range .items[*]}{.involvedObject.kind}/{.involvedObject.name}|{.message}|{.lastTimestamp}\n{end}")
	output, _ := utils.Run(cmd)

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) >= 2 {
			errors = append(errors, errorEntry{
				Type:     "Event",
				Resource: parts[0],
				Message:  parts[1],
				Timestamp: func() string {
					if len(parts) > 2 {
						return parts[2]
					}
					return ""
				}(),
			})
		}
	}

	// Limit to last 10 errors
	if len(errors) > 10 {
		errors = errors[len(errors)-10:]
	}

	return errors
}

// SaveDebugReport saves the debug report to a JSON file.
func SaveDebugReport(report *DebugReport, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	reportPath := filepath.Join(outputDir, "debug-report.json")
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		return err
	}

	report.Artifacts = append(report.Artifacts, reportPath)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "📄 Debug report saved to: %s\n", reportPath)

	return nil
}

// PrintConciseSummary prints a concise one-screen summary for quick debugging.
func PrintConciseSummary(report *DebugReport) {
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╔══════════════════════════════════════════════════════════════════════════════╗\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║                           E2E TEST DEBUG SUMMARY                             ║\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╠══════════════════════════════════════════════════════════════════════════════╣\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ Test:     %-66s ║\n", truncate(report.TestInfo.SpecName, 66))
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ State:    %-66s ║\n", report.TestInfo.State)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ Duration: %-66s ║\n", report.Timing.Duration)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ Cluster:  %-66s ║\n", report.Metadata.ClusterName)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ Install:  %-66s ║\n", report.Metadata.InstallMethod)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╠══════════════════════════════════════════════════════════════════════════════╣\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ CLUSTER: K8s %-5s │ Nodes: %d (%-8s) │ API: %-5v                      ║\n",
		report.ClusterInfo.KubernetesVersion,
		report.ClusterInfo.NodeCount,
		report.ClusterInfo.NodeStatus,
		report.ClusterInfo.APIServerReady)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╠══════════════════════════════════════════════════════════════════════════════╣\n")
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ RESOURCES: RoleDef:%d │ BindDef:%d │ WebhookAuth:%d │ ClusterRoles:%d │ Roles:%d  ║\n",
		report.Resources.RoleDefinitions,
		report.Resources.BindDefinitions,
		report.Resources.WebhookAuthorizers,
		report.Resources.GeneratedClusterRoles,
		report.Resources.GeneratedRoles)
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ PODS: Controller:[%s] Webhook:[%s]            ║\n",
		truncate(strings.Join(report.Resources.OperatorPods, ","), 20),
		truncate(strings.Join(report.Resources.WebhookPods, ","), 20))
	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╠══════════════════════════════════════════════════════════════════════════════╣\n")

	if len(report.Errors) > 0 {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ RECENT ERRORS (%d):                                                           ║\n", len(report.Errors))
		for i, e := range report.Errors {
			if i >= 3 {
				_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║   ... and %d more (see debug-report.json)                                    ║\n", len(report.Errors)-3)
				break
			}
			_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║   • %-71s ║\n", truncate(e.Message, 71))
		}
	} else {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ ERRORS: None                                                                 ║\n")
	}

	if report.TestInfo.FailMessage != "" {
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╠══════════════════════════════════════════════════════════════════════════════╣\n")
		_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "║ FAILURE: %-67s ║\n", truncate(report.TestInfo.FailMessage, 67))
	}

	_, _ = fmt.Fprintf(ginkgo.GinkgoWriter, "╚══════════════════════════════════════════════════════════════════════════════╝\n\n")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

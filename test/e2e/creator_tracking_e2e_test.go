//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/test/utils"
)

const (
	creatorRelease             = "auth-operator-creator-e2e"
	creatorOperatorNS          = "auth-operator-creator-e2e"
	creatorChartPath           = "chart/auth-operator"
	creatorPolicyName          = creatorRelease + "-creator-tracking"
	contributorPolicyName      = creatorRelease + "-contributor-tracking"
	creatorMigrationRelease    = "creator-api-migration-e2e"
	creatorMigrationPolicyName = "e2e-creator-tracking-api-migration"
	creatorMigrationNS         = "e2e-ct-api-migration"
	creatorMigrationAnnotation = "e2e.t-caas.telekom.com/api-migrated"

	creatorTestNS               = "e2e-creator-tracking"
	creatorPreExistingNS        = "e2e-ct-pre-existing"
	creatorPartialNS            = "e2e-ct-partial"
	creatorForgedCreateNS       = "e2e-ct-forged-create"
	creatorSSANS                = "e2e-ct-ssa"
	creatorReinvokeNS           = "e2e-ct-reinvoke"
	creatorOverflowRestoreNS    = "e2e-ct-overflow-restore"
	creatorOverflowCreateNS     = "e2e-ct-overflow-create"
	creatorExactFitCreateNS     = "e2e-ct-exact-fit-create"
	creatorCreateOnlyNS         = "e2e-ct-create-only"
	creatorCreateOnlyFreshNS    = "e2e-ct-create-only-fresh"
	creatorExcludedNS           = "e2e-ct-excluded-create"
	creatorContributorsNS       = "e2e-ct-contributors"
	creatorContributorLimitNS   = "e2e-ct-contributor-limit"
	creatorContributorRestoreNS = "e2e-ct-contributor-restore"

	creatorRequesterSA = "creator-requester"
	creatorTargetSA    = "creator-target"
	creatorEditorASA   = "creator-editor-a"
	creatorEditorBSA   = "creator-editor-b"
	creatorRoleName    = "e2e-creator-impersonate"
	creatorRoleBinding = "e2e-creator-impersonate"

	creatorBindDefinition = "e2e-creator-binddefinition"
	creatorManagedSA      = "e2e-creator-managed-sa"
	creatorManagedTarget  = "e2e-creator-managed"
	creatorManagedBinding = creatorManagedTarget + "-view-binding"

	createdByAnnotation       = authorizationv1alpha1.AnnotationKeyCreatedBy
	createdByGroupsAnnotation = authorizationv1alpha1.AnnotationKeyCreatedByGroups
	updatedByAnnotation       = authorizationv1alpha1.AnnotationKeyUpdatedBy
	paddingAnnotation         = "e2e.t-caas.telekom.com/padding"
	annotationBudget          = 262144

	creatorPollInterval = 2 * time.Second
	creatorTimeout      = 3 * time.Minute
)

var creatorNamespaces = []string{
	creatorTestNS,
	creatorPreExistingNS,
	creatorPartialNS,
	creatorForgedCreateNS,
	creatorSSANS,
	creatorReinvokeNS,
	creatorOverflowRestoreNS,
	creatorOverflowCreateNS,
	creatorExactFitCreateNS,
	creatorCreateOnlyNS,
	creatorCreateOnlyFreshNS,
	creatorExcludedNS,
	creatorContributorsNS,
	creatorContributorLimitNS,
	creatorContributorRestoreNS,
	creatorMigrationNS,
	creatorOperatorNS,
}

type creatorIdentity struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type creatorWhoAmI struct {
	Status struct {
		UserInfo creatorIdentity `json:"userInfo"`
	} `json:"status"`
}

type creatorManagedField struct {
	Manager    string          `json:"manager"`
	Operation  string          `json:"operation"`
	APIVersion string          `json:"apiVersion"`
	FieldsType string          `json:"fieldsType"`
	FieldsV1   json.RawMessage `json:"fieldsV1"`
}

type creatorObject struct {
	Metadata struct {
		Name            string                `json:"name"`
		UID             string                `json:"uid"`
		ResourceVersion string                `json:"resourceVersion"`
		Generation      int64                 `json:"generation"`
		Annotations     map[string]string     `json:"annotations"`
		Labels          map[string]string     `json:"labels"`
		Finalizers      []string              `json:"finalizers"`
		ManagedFields   []creatorManagedField `json:"managedFields"`
		OwnerReferences []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"ownerReferences"`
	} `json:"metadata"`
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
	Status                       struct {
		ObservedGeneration       int64 `json:"observedGeneration"`
		GeneratedServiceAccounts []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"generatedServiceAccounts"`
		ExternalServiceAccounts []string `json:"externalServiceAccounts"`
		Conditions              []struct {
			Type               string `json:"type"`
			Status             string `json:"status"`
			ObservedGeneration int64  `json:"observedGeneration"`
		} `json:"conditions"`
	} `json:"status"`
}

type creatorEventList struct {
	Items []struct {
		Type    string `json:"type"`
		Reason  string `json:"reason"`
		Message string `json:"message"`
	} `json:"items"`
}

func creatorRun(ctx context.Context, stdin, command string, args ...string) ([]byte, error) {
	cmd := utils.CommandContext(ctx, command, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return utils.Run(cmd)
}

func creatorSensitiveRun(ctx context.Context, operation, command string, args ...string) ([]byte, error) {
	// #nosec G204 -- command and arguments are fixed by this test suite.
	cmd := exec.CommandContext(ctx, command, args...)
	projectDir, err := utils.GetProjectDir()
	if err != nil {
		return nil, fmt.Errorf("%s: resolve project directory: %w", operation, err)
	}
	cmd.Dir = projectDir
	cmd.Env = os.Environ()
	output, err := cmd.Output()
	if err == nil {
		return output, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, fmt.Errorf("%s: %w", operation, ctxErr)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return nil, fmt.Errorf("%s failed with exit code %d: %w", operation, exitErr.ExitCode(), err)
	}
	return nil, fmt.Errorf("%s could not start: %w", operation, err)
}

func creatorSensitiveKubectl(ctx context.Context, operation string, args ...string) ([]byte, error) {
	return creatorSensitiveRun(ctx, operation, "kubectl", args...)
}

func creatorClusterConnection(ctx context.Context) (string, string, error) {
	_ = ctx
	kubeconfigPath, err := creatorPrivateKubeconfig()
	if err != nil {
		return "", "", err
	}
	config, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return "", "", fmt.Errorf("load private kubeconfig: %w", err)
	}
	server, err := creatorKubeconfigServer(config, "private creator tracking")
	if err != nil {
		return "", "", err
	}
	contextConfig := config.Contexts[config.CurrentContext]
	clusterConfig := config.Clusters[contextConfig.Cluster]
	caData := clusterConfig.CertificateAuthorityData
	if server == "" || len(caData) == 0 {
		return "", "", fmt.Errorf("selected cluster server or CA is empty")
	}
	return server, base64.StdEncoding.EncodeToString(caData), nil
}
func creatorKubectl(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	return creatorRun(ctx, stdin, "kubectl", args...)
}

func creatorKubectlAs(
	ctx context.Context,
	kubeconfig, username, stdin string,
	args ...string,
) ([]byte, error) {
	identityArgs := make([]string, 0, len(args)+4)
	if kubeconfig != "" {
		identityArgs = append(identityArgs, "--kubeconfig", kubeconfig)
	}
	if username != "" {
		identityArgs = append(identityArgs, "--as", username)
	}
	identityArgs = append(identityArgs, args...)
	return creatorKubectl(ctx, stdin, identityArgs...)
}

func creatorDecodeObject(raw []byte) (creatorObject, error) {
	var object creatorObject
	if err := json.Unmarshal(raw, &object); err != nil {
		return creatorObject{}, fmt.Errorf("decode Kubernetes object: %w", err)
	}
	return object, nil
}

func creatorNamespaceManifest(name string, annotations, labels map[string]string) (string, error) {
	manifest := map[string]any{
		"apiVersion": "v1",
		"kind":       "Namespace",
		"metadata": map[string]any{
			"name": name,
		},
	}
	metadata := manifest["metadata"].(map[string]any)
	if len(annotations) > 0 {
		metadata["annotations"] = annotations
	}
	if len(labels) > 0 {
		metadata["labels"] = labels
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("encode Namespace %s: %w", name, err)
	}
	return string(raw), nil
}

func creatorCreateNamespace(
	ctx context.Context,
	kubeconfig, username, name string,
	annotations map[string]string,
	dryRun bool,
) (creatorObject, error) {
	manifest, err := creatorNamespaceManifest(name, annotations, nil)
	if err != nil {
		return creatorObject{}, err
	}
	args := []string{"create", "-f", "-", "-o", "json"}
	if dryRun {
		args = append(args, "--dry-run=server")
	}
	output, err := creatorKubectlAs(ctx, kubeconfig, username, manifest, args...)
	if err != nil {
		return creatorObject{}, fmt.Errorf("create Namespace %s: %w", name, err)
	}
	return creatorDecodeObject(output)
}

func creatorPatchNamespace(
	ctx context.Context,
	kubeconfig, username, name string,
	patch map[string]any,
	dryRun bool,
) (creatorObject, error) {
	rawPatch, err := json.Marshal(patch)
	if err != nil {
		return creatorObject{}, fmt.Errorf("encode Namespace %s patch: %w", name, err)
	}
	args := []string{"patch", "namespace", name, "--type=merge", "--patch-file=/dev/stdin", "-o", "json"}
	if dryRun {
		args = append(args, "--dry-run=server")
	}
	output, err := creatorKubectlAs(ctx, kubeconfig, username, string(rawPatch), args...)
	if err != nil {
		return creatorObject{}, fmt.Errorf("patch Namespace %s: %w: %s",
			name, err, strings.TrimSpace(string(output)))
	}
	return creatorDecodeObject(output)
}

func creatorApplyNamespace(
	ctx context.Context,
	name, fieldManager string,
	labels map[string]string,
) (creatorObject, error) {
	manifest, err := creatorNamespaceManifest(name, nil, labels)
	if err != nil {
		return creatorObject{}, err
	}
	output, err := creatorKubectl(ctx, manifest,
		"apply", "--server-side", "--field-manager", fieldManager, "-f", "-", "-o", "json")
	if err != nil {
		return creatorObject{}, fmt.Errorf("server-side apply Namespace %s as %s: %w", name, fieldManager, err)
	}
	return creatorDecodeObject(output)
}

func creatorReadIdentity(
	ctx context.Context,
	kubeconfig, impersonatedUsername string,
) (creatorIdentity, error) {
	output, err := creatorKubectlAs(ctx, kubeconfig, impersonatedUsername, "", "auth", "whoami", "-o", "json")
	if err != nil {
		return creatorIdentity{}, fmt.Errorf("read effective identity: %w", err)
	}
	var response creatorWhoAmI
	if err := json.Unmarshal(output, &response); err != nil {
		return creatorIdentity{}, fmt.Errorf("decode effective identity: %w", err)
	}
	if response.Status.UserInfo.Username == "" {
		return creatorIdentity{}, fmt.Errorf("effective identity has an empty username")
	}
	return response.Status.UserInfo, nil
}

func creatorTokenKubeconfig(ctx context.Context, namespace, serviceAccount string) (string, error) {
	tokenOutput, err := creatorSensitiveKubectl(ctx, "create ServiceAccount token", "create", "token", serviceAccount,
		"-n", namespace, "--duration=60m")
	if err != nil {
		return "", fmt.Errorf("create %s/%s token: %w", namespace, serviceAccount, err)
	}
	token := strings.TrimSpace(string(tokenOutput))
	if token == "" {
		return "", fmt.Errorf("%s/%s token is empty", namespace, serviceAccount)
	}

	server, caData, err := creatorClusterConnection(ctx)
	if err != nil {
		return "", err
	}

	config := map[string]any{
		"apiVersion": "v1",
		"kind":       "Config",
		"clusters": []any{map[string]any{
			"name": "creator-tracking-cluster",
			"cluster": map[string]any{
				"server":                     server,
				"certificate-authority-data": caData,
			},
		}},
		"users": []any{map[string]any{
			"name": "creator-tracking-token",
			"user": map[string]any{"token": token},
		}},
		"contexts": []any{map[string]any{
			"name": "creator-tracking",
			"context": map[string]any{
				"cluster": "creator-tracking-cluster",
				"user":    "creator-tracking-token",
			},
		}},
		"current-context": "creator-tracking",
	}

	runDir, err := creatorPrivateRunDir()
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(runDir, "token-*.kubeconfig")
	if err != nil {
		return "", fmt.Errorf("create token kubeconfig: %w", err)
	}
	path := file.Name()
	remove := true
	defer func() {
		if remove {
			if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
				_, _ = fmt.Fprintf(GinkgoWriter, "remove incomplete token kubeconfig %s: %v\n", path, removeErr)
			}
		}
	}()
	if err := json.NewEncoder(file).Encode(config); err != nil {
		if closeErr := file.Close(); closeErr != nil {
			return "", errors.Join(fmt.Errorf("write token kubeconfig: %w", err),
				fmt.Errorf("close token kubeconfig: %w", closeErr))
		}
		return "", fmt.Errorf("write token kubeconfig: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close token kubeconfig: %w", err)
	}
	remove = false
	return path, nil
}

func creatorEncodeComponent(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "%", "%25"), ",", "%2C")
}

func creatorEncodedComponents(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func creatorSameMembers(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, value := range left {
		counts[value]++
	}
	for _, value := range right {
		counts[value]--
		if counts[value] < 0 {
			return false
		}
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}

func creatorStampError(object creatorObject, identity creatorIdentity) error {
	annotations := object.Metadata.Annotations
	if annotations[createdByAnnotation] != identity.Username {
		return fmt.Errorf("created-by = %q, want %q", annotations[createdByAnnotation], identity.Username)
	}
	expectedGroups := make([]string, 0, len(identity.Groups))
	for _, group := range identity.Groups {
		expectedGroups = append(expectedGroups, creatorEncodeComponent(group))
	}
	actualGroups := creatorEncodedComponents(annotations[createdByGroupsAnnotation])
	if !creatorSameMembers(actualGroups, expectedGroups) {
		return fmt.Errorf("encoded creator groups = %v, want members %v", actualGroups, expectedGroups)
	}
	return nil
}

func creatorExpectStamp(object creatorObject, identity creatorIdentity) {
	ExpectWithOffset(1, creatorStampError(object, identity)).NotTo(HaveOccurred())
}

func creatorExpectNoTracking(object creatorObject) {
	for _, key := range []string{createdByAnnotation, createdByGroupsAnnotation, updatedByAnnotation} {
		_, present := object.Metadata.Annotations[key]
		ExpectWithOffset(1, present).To(BeFalse(), "annotation %s must be absent", key)
	}
}

func creatorServiceAccountUsername(namespace, name string) string {
	return fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)
}

func creatorServiceAccountGroups(namespace string) []string {
	return []string{
		"system:serviceaccounts",
		"system:serviceaccounts:" + namespace,
		"system:authenticated",
	}
}

func creatorApplyManifest(ctx context.Context, manifest string) error {
	output, err := creatorKubectl(ctx, manifest,
		"apply", "--server-side", "--field-manager=creator-tracking-e2e", "-f", "-")
	if err != nil {
		return fmt.Errorf("apply test manifest: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func creatorGetObject(ctx context.Context, resource, name, namespace string) (creatorObject, error) {
	args := []string{"get", resource, name, "-o", "json", "--show-managed-fields=true"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	output, err := creatorKubectl(ctx, "", args...)
	if err != nil {
		return creatorObject{}, fmt.Errorf("get %s/%s: %w", resource, name, err)
	}
	return creatorDecodeObject(output)
}

func creatorResourceAbsent(ctx context.Context, resource, name, namespace string) (bool, error) {
	args := []string{"get", resource, name, "--ignore-not-found", "-o", "name"}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	output, err := creatorKubectl(ctx, "", args...)
	if err != nil {
		message := strings.ToLower(string(output))
		if strings.Contains(message, "notfound") ||
			strings.Contains(message, "not found") ||
			strings.Contains(message, "the server doesn't have a resource type") ||
			strings.Contains(message, "the server could not find the requested resource") {
			return true, nil
		}
		return false, fmt.Errorf("check %s/%s absence: %w", resource, name, err)
	}
	return strings.TrimSpace(string(output)) == "", nil
}

func creatorHelmArgs(mode string) []string {
	args := append([]string{
		"upgrade", "--install", creatorRelease, creatorChartPath,
		"--namespace", creatorOperatorNS,
		"--create-namespace",
	}, imageSetArgs()...)
	args = append(args,
		"--set", "image.pullPolicy=IfNotPresent",
		"--set", "creatorTracking.enabled=true",
		"--set", "creatorTracking.map=auto",
		"--set", "creatorTracking.mode="+mode,
		"--set", "namespaceDeletionProtection.enabled=false",
		"--set", "controller.replicas=1",
		"--set", "webhookServer.replicas=1",
		"--wait", "--timeout", "5m",
	)
	return args
}

func creatorHelmUpgrade(ctx context.Context, mode string) error {
	return creatorHelmUpgradeExcluded(ctx, mode)
}

func creatorHelmUpgradeExcluded(ctx context.Context, mode string, excluded ...string) error {
	commandCtx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	args := creatorHelmArgs(mode)
	if len(excluded) > 0 {
		raw, marshalErr := json.Marshal(excluded)
		if marshalErr != nil {
			return fmt.Errorf("encode excluded usernames: %w", marshalErr)
		}
		args = append(args, "--set-json", "creatorTracking.excludedUsernames="+string(raw))
	}
	output, err := creatorRun(commandCtx, "", "helm", args...)
	if err != nil {
		return fmt.Errorf("install creator tracking in %s mode: %w: %s", mode, err, strings.TrimSpace(string(output)))
	}
	if err := creatorVerifyPolicyAPI(ctx); err != nil {
		return fmt.Errorf("verify creator tracking API in %s mode: %w", mode, err)
	}
	return nil
}

func creatorWaitForPolicy(ctx context.Context, resource, name string) error {
	_, err := creatorKubectl(ctx, "", "get", resource, name, "-o", "name")
	return err
}

func creatorActivationError(ctx context.Context, identity creatorIdentity, attempt uint64) error {
	for _, resource := range []struct {
		kind string
		name string
	}{
		{kind: "mutatingadmissionpolicy", name: creatorPolicyName},
		{kind: "mutatingadmissionpolicybinding", name: creatorPolicyName},
		{kind: "mutatingadmissionpolicy", name: contributorPolicyName},
		{kind: "mutatingadmissionpolicybinding", name: contributorPolicyName},
	} {
		if err := creatorWaitForPolicy(ctx, resource.kind, resource.name); err != nil {
			return err
		}
	}
	name := fmt.Sprintf("e2e-ct-activation-%d", attempt)
	object, err := creatorCreateNamespace(ctx, "", "", name, nil, true)
	if err != nil {
		return err
	}
	if err := creatorStampError(object, identity); err != nil {
		return err
	}
	if _, present := object.Metadata.Annotations[updatedByAnnotation]; present {
		return fmt.Errorf("activation dry-run returned contributor data")
	}
	return nil
}

func creatorBindReadyError(ctx context.Context, generation int64) error {
	object, err := creatorGetObject(ctx, "binddefinition", creatorBindDefinition, "")
	if err != nil {
		return err
	}
	if object.Metadata.Generation != generation {
		return fmt.Errorf("BindDefinition generation = %d, want %d", object.Metadata.Generation, generation)
	}
	if object.Status.ObservedGeneration != generation {
		return fmt.Errorf("BindDefinition observedGeneration = %d, want %d", object.Status.ObservedGeneration, generation)
	}
	for _, condition := range object.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == "True" && condition.ObservedGeneration == generation {
			return nil
		}
	}
	return fmt.Errorf("BindDefinition generation %d is not Ready", generation)
}

func creatorSaveManagedFields(ctx context.Context, resource, name, namespace, filename string) {
	object, err := creatorGetObject(ctx, resource, name, namespace)
	if err != nil {
		return
	}
	raw, err := json.MarshalIndent(object.Metadata.ManagedFields, "", "  ")
	if err != nil {
		return
	}
	saveOutput(filename, append(raw, '\n'))
}

var _ = Describe("Creator Tracking", Serial, Ordered, Label("creator-tracking"), func() {
	var (
		adminIdentity       creatorIdentity
		controllerIdentity  creatorIdentity
		requesterKubeconfig string
		suiteFailed         bool
		activationAttempt   uint64
	)

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			suiteFailed = true
		}
	})

	BeforeAll(func(ctx SpecContext) {
		setSuiteOutputDir("creator-tracking")
		DeferCleanup(func() {
			cleanupErrors := creatorCleanup(suiteFailed || CurrentSpecReport().Failed() || utils.DebugLevel >= 2)
			Expect(cleanupErrors).To(BeEmpty(), creatorFormatErrors(cleanupErrors))
		})

		By("Verifying the private kubeconfig and dedicated Kind cluster")
		Expect(creatorValidateIsolation(ctx)).To(Succeed())

		By("Cleaning exact leftovers before acquiring resources")
		cleanupErrors := creatorCleanup(false)
		Expect(cleanupErrors).To(BeEmpty(), creatorFormatErrors(cleanupErrors))

		expectedAPI, err := creatorExpectedAPI()
		Expect(err).NotTo(HaveOccurred())
		version := creatorExpectedAPIVersionName(expectedAPI)
		By("Checking the expected MutatingAdmissionPolicy API")
		discovery, err := creatorKubectl(ctx, "", "get", "--raw", "/apis/admissionregistration.k8s.io/"+version)
		Expect(err).NotTo(HaveOccurred(), "Kubernetes must serve %s", expectedAPI)
		Expect(string(discovery)).To(ContainSubstring("mutatingadmissionpolicies"))

		By("Reading the effective administrator identity")
		adminIdentity, err = creatorReadIdentity(ctx, "", "")
		Expect(err).NotTo(HaveOccurred())

		By("Creating pre-policy Namespace fixtures")
		_, err = creatorCreateNamespace(ctx, "", "", creatorTestNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		_, err = creatorCreateNamespace(ctx, "", "", creatorPreExistingNS,
			map[string]string{updatedByAnnotation: "forged-before-policy"}, false)
		Expect(err).NotTo(HaveOccurred())
		_, err = creatorCreateNamespace(ctx, "", "", creatorPartialNS,
			map[string]string{createdByAnnotation: "legacy-partial-creator"}, false)
		Expect(err).NotTo(HaveOccurred())
		_, err = creatorCreateNamespace(ctx, "", "", creatorContributorRestoreNS,
			map[string]string{updatedByAnnotation: strings.Repeat("x", 1024)}, false)
		Expect(err).NotTo(HaveOccurred())

		By("Creating the separate requester and target grants")
		Expect(creatorApplyIdentityRBAC(ctx)).To(Succeed())

		By("Building the requester token-only kubeconfig")
		requesterKubeconfig, err = creatorTokenKubeconfig(ctx, creatorTestNS, creatorRequesterSA)
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(creatorRemoveTempFile(requesterKubeconfig)).To(Succeed()) })
		requesterIdentity, err := creatorReadIdentity(ctx, requesterKubeconfig, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(requesterIdentity.Username).To(Equal(creatorServiceAccountUsername(creatorTestNS, creatorRequesterSA)))
		Expect(requesterIdentity.Groups).To(ConsistOf(creatorServiceAccountGroups(creatorTestNS)))

		By("Verifying every impersonated ServiceAccount identity")
		for _, serviceAccount := range []string{creatorTargetSA, creatorEditorASA, creatorEditorBSA} {
			username := creatorServiceAccountUsername(creatorTestNS, serviceAccount)
			identity, identityErr := creatorReadIdentity(ctx, requesterKubeconfig, username)
			Expect(identityErr).NotTo(HaveOccurred())
			Expect(identity.Username).To(Equal(username))
			Expect(identity.Groups).To(ConsistOf(creatorServiceAccountGroups(creatorTestNS)))
		}

		By("Proving the requester cannot act directly or impersonate an unlisted identity")
		for _, args := range [][]string{
			{"create", "namespaces"},
			{"patch", "namespace/" + creatorContributorsNS},
			{"impersonate", "serviceaccounts/unlisted", "-n", creatorTestNS},
		} {
			allowed, canIErr := creatorCanI(ctx, requesterKubeconfig, args...)
			Expect(canIErr).NotTo(HaveOccurred())
			Expect(allowed).To(BeFalse(), "requester unexpectedly passed kubectl auth can-i %v", args)
		}

		By("Installing protect mode with API auto-detection")
		Expect(creatorHelmUpgrade(ctx, "protect")).To(Succeed())
		for _, deployment := range []string{creatorRelease + "-controller-manager", creatorRelease + "-webhook-server"} {
			output, waitErr := creatorKubectl(ctx, "", "wait", "deployment/"+deployment,
				"-n", creatorOperatorNS, "--for=condition=Available", "--timeout=5m")
			Expect(waitErr).NotTo(HaveOccurred(), "%s", string(output))
		}

		By("Verifying the operator controller identity")
		controllerKubeconfig, tokenErr := creatorTokenKubeconfig(ctx, creatorOperatorNS,
			creatorRelease+"-controller-manager")
		Expect(tokenErr).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(creatorRemoveTempFile(controllerKubeconfig)).To(Succeed()) })
		controllerIdentity, err = creatorReadIdentity(ctx, controllerKubeconfig, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(controllerIdentity.Username).To(Equal(
			creatorServiceAccountUsername(creatorOperatorNS, creatorRelease+"-controller-manager")))
		Expect(controllerIdentity.Groups).To(ConsistOf(creatorServiceAccountGroups(creatorOperatorNS)))

		By("Waiting for creator CREATE mutation")
		Eventually(func() error {
			activationAttempt++
			return creatorActivationError(ctx, adminIdentity, activationAttempt)
		}, creatorTimeout, creatorPollInterval).Should(Succeed())

		By("Waiting for the separate updated-by scrub policy")
		Eventually(func() error {
			object, patchErr := creatorPatchNamespace(ctx, "", "", creatorPreExistingNS, map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"e2e.t-caas.telekom.com/scrub": "dry"}},
			}, true)
			if patchErr != nil {
				return patchErr
			}
			if _, present := object.Metadata.Annotations[updatedByAnnotation]; present {
				return fmt.Errorf("protect scrub policy has not removed updated-by")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
	})

	It("overwrites forged creator data on create", func(ctx SpecContext) {
		targetIdentity := creatorIdentity{
			Username: creatorServiceAccountUsername(creatorTestNS, creatorTargetSA),
			Groups:   creatorServiceAccountGroups(creatorTestNS),
		}
		object, err := creatorCreateNamespace(ctx, requesterKubeconfig, targetIdentity.Username,
			creatorForgedCreateNS, map[string]string{
				createdByAnnotation:       "forged-creator",
				createdByGroupsAnnotation: "forged-group",
				updatedByAnnotation:       "forged-editor",
			}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(object, targetIdentity)
		_, updatedPresent := object.Metadata.Annotations[updatedByAnnotation]
		Expect(updatedPresent).To(BeFalse())
	})

	It("restores protected data and handles pre-existing objects", func(ctx SpecContext) {
		targetIdentity := creatorIdentity{
			Username: creatorServiceAccountUsername(creatorTestNS, creatorTargetSA),
			Groups:   creatorServiceAccountGroups(creatorTestNS),
		}
		tampered, err := creatorPatchNamespace(ctx, "", "", creatorForgedCreateNS, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					createdByAnnotation: "tampered", createdByGroupsAnnotation: "tampered",
					updatedByAnnotation: "forged",
				},
				"labels": map[string]any{"e2e.t-caas.telekom.com/touch": "tamper"},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(tampered, targetIdentity)
		_, updatedPresent := tampered.Metadata.Annotations[updatedByAnnotation]
		Expect(updatedPresent).To(BeFalse())

		introduced, err := creatorPatchNamespace(ctx, "", "", creatorPreExistingNS, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					createdByAnnotation: "forged", createdByGroupsAnnotation: "forged",
					updatedByAnnotation: "forged",
				},
				"labels": map[string]any{"e2e.t-caas.telekom.com/touch": "introduced"},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(introduced)
		Expect(introduced.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/touch", "introduced"))

		partial, err := creatorPatchNamespace(ctx, "", "", creatorPartialNS, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					createdByAnnotation: "tampered", createdByGroupsAnnotation: "forged",
				},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(partial.Metadata.Annotations).To(HaveKeyWithValue(createdByAnnotation, "legacy-partial-creator"))
		Expect(partial.Metadata.Annotations).To(HaveKeyWithValue(createdByGroupsAnnotation, ""))
	})

	if os.Getenv("E2E_CREATOR_TRACKING_API_VERSION") == "admissionregistration.k8s.io/v1" {
		It("keeps Helm release and resource identity while moving from beta to stable API", func(ctx SpecContext) {
			runDir, err := creatorPrivateRunDir()
			Expect(err).NotTo(HaveOccurred())
			chartDir, err := os.MkdirTemp(runDir, "helm-api-migration-*")
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { Expect(os.RemoveAll(chartDir)).To(Succeed()) })
			Expect(os.Mkdir(filepath.Join(chartDir, "templates"), 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(`apiVersion: v2
name: creator-api-migration-e2e
version: 0.1.0
`), 0o600)).To(Succeed())

			migrationManifest := func(apiVersion string) string {
				return fmt.Sprintf(`
apiVersion: admissionregistration.k8s.io/%[1]s
kind: MutatingAdmissionPolicy
metadata:
  name: %[2]s
spec:
  failurePolicy: Fail
  reinvocationPolicy: IfNeeded
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["namespaces"]
  matchConditions:
    - name: exact-fixture
      expression: "object.metadata.name == '%[3]s'"
  mutations:
    - patchType: JSONPatch
      jsonPatch:
        expression: >-
          (!has(object.metadata.annotations)
           ? [JSONPatch{op: 'add', path: '/metadata/annotations', value: {}}]
           : [])
          + [JSONPatch{
              op: 'add',
              path: '/metadata/annotations/'
                    + jsonpatch.escapeKey('%[4]s'),
              value: '%[1]s'
            }]
---
apiVersion: admissionregistration.k8s.io/%[1]s
kind: MutatingAdmissionPolicyBinding
metadata:
  name: %[2]s
spec:
  policyName: %[2]s
`, apiVersion, creatorMigrationPolicyName, creatorMigrationNS, creatorMigrationAnnotation)
			}
			writeTemplate := func(apiVersion string) {
				ExpectWithOffset(1, os.WriteFile(filepath.Join(chartDir, "templates", "policy.yaml"),
					[]byte(migrationManifest(apiVersion)), 0o600)).To(Succeed())
			}
			runHelm := func(args ...string) {
				commandCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				args = append(args, "--namespace", creatorOperatorNS)
				output, helmErr := creatorRun(commandCtx, "", "helm", args...)
				ExpectWithOffset(1, helmErr).NotTo(HaveOccurred(), "%s", string(output))
			}
			DeferCleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				var cleanupErrors []error
				output, cleanupErr := creatorRun(cleanupCtx, "", "helm", "uninstall", creatorMigrationRelease,
					"--namespace", creatorOperatorNS, "--ignore-not-found", "--wait", "--timeout", "90s")
				if cleanupErr != nil && !creatorIsAbsentError(output, cleanupErr) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("uninstall migration release: %w", cleanupErr))
				}
				for _, resource := range []string{"mutatingadmissionpolicybinding", "mutatingadmissionpolicy"} {
					if err := creatorDeleteAndWait(creatorExactResource{Kind: resource, Name: creatorMigrationPolicyName}); err != nil {
						cleanupErrors = append(cleanupErrors, fmt.Errorf("delete migration %s: %w", resource, err))
					}
				}
				if err := creatorDeleteAndWait(creatorExactResource{Kind: "namespace", Name: creatorMigrationNS}); err != nil {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("delete migration namespace: %w", err))
				}
				statusOutput, statusErr := creatorRun(cleanupCtx, "", "helm", "status", creatorMigrationRelease, "--namespace", creatorOperatorNS)
				if statusErr == nil || !creatorIsAbsentError(statusOutput, statusErr) {
					cleanupErrors = append(cleanupErrors, fmt.Errorf("migration release remains visible"))
				}
				Expect(cleanupErrors).To(BeEmpty(), creatorFormatErrors(cleanupErrors))
			})
			verifyStoredManifest := func(version string) {
				commandCtx, cancel := context.WithTimeout(ctx, time.Minute)
				defer cancel()
				output, helmErr := creatorRun(commandCtx, "", "helm", "get", "manifest", creatorMigrationRelease,
					"--namespace", creatorOperatorNS)
				ExpectWithOffset(1, helmErr).NotTo(HaveOccurred(), "%s", string(output))
				ExpectWithOffset(1, string(output)).To(ContainSubstring(
					"apiVersion: admissionregistration.k8s.io/" + version))
				if version == "v1" {
					ExpectWithOffset(1, string(output)).NotTo(ContainSubstring("admissionregistration.k8s.io/v1beta1"))
				}
			}
			getUID := func(version, resource string) string {
				path := fmt.Sprintf("/apis/admissionregistration.k8s.io/%s/%s/%s",
					version, resource, creatorMigrationPolicyName)
				output, err := creatorKubectl(ctx, "", "get", "--raw", path)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				object, err := creatorDecodeObject(output)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				return object.Metadata.UID
			}
			verifyMutation := func(want string) {
				EventuallyWithOffset(1, func() error {
					object, createErr := creatorCreateNamespace(ctx, "", "", creatorMigrationNS, nil, true)
					if createErr != nil {
						return createErr
					}
					if object.Metadata.Annotations[creatorMigrationAnnotation] != want {
						return fmt.Errorf("migration annotation = %q, want %q",
							object.Metadata.Annotations[creatorMigrationAnnotation], want)
					}
					return nil
				}, creatorTimeout, creatorPollInterval).Should(Succeed())
			}

			writeTemplate("v1beta1")
			runHelm("install", creatorMigrationRelease, chartDir, "--wait", "--timeout", "90s")
			betaPolicyUID := getUID("v1beta1", "mutatingadmissionpolicies")
			betaBindingUID := getUID("v1beta1", "mutatingadmissionpolicybindings")
			Expect(betaPolicyUID).NotTo(BeEmpty())
			verifyStoredManifest("v1beta1")
			Expect(betaBindingUID).NotTo(BeEmpty())

			verifyMutation("v1beta1")
			writeTemplate("v1")
			runHelm("upgrade", creatorMigrationRelease, chartDir, "--wait", "--timeout", "90s")
			Expect(getUID("v1", "mutatingadmissionpolicies")).To(Equal(betaPolicyUID))
			Expect(getUID("v1", "mutatingadmissionpolicybindings")).To(Equal(betaBindingUID))
			Expect(getUID("v1beta1", "mutatingadmissionpolicies")).To(Equal(betaPolicyUID))
			verifyStoredManifest("v1")
			Expect(getUID("v1beta1", "mutatingadmissionpolicybindings")).To(Equal(betaBindingUID))

			verifyMutation("v1")
			created, createErr := creatorCreateNamespace(ctx, "", "", creatorMigrationNS, nil, false)
			Expect(createErr).NotTo(HaveOccurred())
			creatorExpectStamp(created, adminIdentity)
			Expect(created.Metadata.Annotations).To(HaveKeyWithValue(creatorMigrationAnnotation, "v1"))

			runHelm("uninstall", creatorMigrationRelease, "--wait", "--timeout", "90s")
			for _, resource := range []string{"mutatingadmissionpolicybinding", "mutatingadmissionpolicy"} {
				Expect(creatorDeleteAndWait(creatorExactResource{
					Kind: resource, Name: creatorMigrationPolicyName,
				})).To(Succeed())
			}
		})
	}

	It("supports create-only mode and returns to protect mode", func(ctx SpecContext) {
		created, err := creatorCreateNamespace(ctx, "", "", creatorCreateOnlyNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(created, adminIdentity)
		Expect(creatorHelmUpgrade(ctx, "create-only")).To(Succeed())
		Eventually(func() error {
			object, patchErr := creatorPatchNamespace(ctx, "", "", creatorCreateOnlyNS, map[string]any{
				"metadata": map[string]any{"annotations": map[string]any{
					createdByAnnotation: "dry-run-change", updatedByAnnotation: "dry-run-forged",
				}},
			}, true)
			if patchErr != nil {
				return patchErr
			}
			if object.Metadata.Annotations[createdByAnnotation] != "dry-run-change" {
				return fmt.Errorf("create-only mode still restored creator data")
			}
			if _, present := object.Metadata.Annotations[updatedByAnnotation]; present {
				return fmt.Errorf("create-only scrub policy has not removed updated-by")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())

		fresh, err := creatorCreateNamespace(ctx, "", "", creatorCreateOnlyFreshNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(fresh, adminIdentity)
		_, freshUpdatedBy := fresh.Metadata.Annotations[updatedByAnnotation]
		Expect(freshUpdatedBy).To(BeFalse())

		changed, err := creatorPatchNamespace(ctx, "", "", creatorCreateOnlyNS, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					createdByAnnotation: "changed", createdByGroupsAnnotation: "changed",
					updatedByAnnotation: "forged",
				},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(changed.Metadata.Annotations).To(HaveKeyWithValue(createdByAnnotation, "changed"))
		Expect(changed.Metadata.Annotations).To(HaveKeyWithValue(createdByGroupsAnnotation, "changed"))
		_, updatedPresent := changed.Metadata.Annotations[updatedByAnnotation]
		Expect(updatedPresent).To(BeFalse())

		Expect(creatorHelmUpgrade(ctx, "protect")).To(Succeed())
		Eventually(func() error {
			object, patchErr := creatorPatchNamespace(ctx, "", "", creatorCreateOnlyNS, map[string]any{
				"metadata": map[string]any{"annotations": map[string]any{
					createdByAnnotation: "tampered-again", updatedByAnnotation: "forged-again",
				}},
			}, true)
			if patchErr != nil {
				return patchErr
			}
			if object.Metadata.Annotations[createdByAnnotation] != "changed" {
				return fmt.Errorf("protect mode has not restored the create-only value")
			}
			if _, present := object.Metadata.Annotations[updatedByAnnotation]; present {
				return fmt.Errorf("protect scrub policy has not removed updated-by")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
	})

	It("keeps tracking annotations outside Namespace SSA ownership", func(ctx SpecContext) {
		const (
			firstManager  = "creator-tracking-ssa-one"
			secondManager = "creator-tracking-ssa-two"
		)
		created, err := creatorApplyNamespace(ctx, creatorSSANS, firstManager,
			map[string]string{"e2e.t-caas.telekom.com/ssa-one": "created"})
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(created, adminIdentity)

		sameManager, err := creatorApplyNamespace(ctx, creatorSSANS, firstManager,
			map[string]string{"e2e.t-caas.telekom.com/ssa-one": "updated"})
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(sameManager, adminIdentity)

		newManager, err := creatorApplyNamespace(ctx, creatorSSANS, secondManager,
			map[string]string{"e2e.t-caas.telekom.com/ssa-two": "created"})
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(newManager, adminIdentity)
		managedObject, err := creatorGetObject(ctx, "namespace", creatorSSANS, "")
		Expect(err).NotTo(HaveOccurred())
		Expect(managedObject.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/ssa-one", "updated"))
		Expect(managedObject.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/ssa-two", "created"))
		Expect(creatorValidateManagedFields(managedObject, []creatorExpectedManagedField{
			{
				Manager: firstManager, Operation: "Apply",
				Paths: [][]string{{"f:metadata", "f:labels", "f:e2e.t-caas.telekom.com/ssa-one"}},
			},
			{
				Manager: secondManager, Operation: "Apply",
				Paths: [][]string{{"f:metadata", "f:labels", "f:e2e.t-caas.telekom.com/ssa-two"}},
			},
		})).To(Succeed())
		creatorSaveManagedFields(ctx, "namespace", creatorSSANS, "", "creator-ssa-managed-fields.json")
	})

	It("reinvokes creator tracking after the test webhook", func(ctx SpecContext) {
		fixture, err := creatorCreateNamespace(ctx, "", "", creatorReinvokeNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(fixture, adminIdentity)
		Expect(creatorInstallReinvocationWebhook(ctx)).To(Succeed())

		reinvocationPolicy, err := creatorPolicyReinvocation(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(reinvocationPolicy).To(Equal("IfNeeded"))

		By("Waiting for semantic dry-run activation")
		Eventually(func() error {
			object, patchErr := creatorPatchNamespace(ctx, "", "", creatorReinvokeNS, map[string]any{
				"metadata": map[string]any{"labels": map[string]any{creatorReinvocationTrigger: "true"}},
			}, true)
			if patchErr != nil {
				return patchErr
			}
			if err := creatorStampError(object, adminIdentity); err != nil {
				return err
			}
			if object.Metadata.Annotations[creatorReinvocationMarker] == "" {
				return fmt.Errorf("reinvocation UID marker is missing")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())

		updated, err := creatorPatchNamespace(ctx, "", "", creatorReinvokeNS, map[string]any{
			"metadata": map[string]any{"labels": map[string]any{creatorReinvocationTrigger: "true"}},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(updated, adminIdentity)
		uid := updated.Metadata.Annotations[creatorReinvocationMarker]
		Expect(uid).NotTo(BeEmpty())
		persisted, err := creatorGetObject(ctx, "namespace", creatorReinvokeNS, "")
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(persisted, adminIdentity)
		Expect(persisted.Metadata.Annotations).To(HaveKeyWithValue(creatorReinvocationMarker, uid))

		var webhookLog string
		Eventually(func() (string, error) {
			output, logErr := creatorKubectl(ctx, "", "logs", creatorReinvocationService, "-n", creatorTestNS)
			webhookLog = string(output)
			return webhookLog, logErr
		}, time.Minute, creatorPollInterval).Should(And(
			ContainSubstring("uid="+uid),
			ContainSubstring("removed=created-by,created-by-groups"),
		))
		saveOutput("creator-reinvocation-webhook.log", []byte(webhookLog))

		By("Deleting the fail-closed webhook before its backend")
		Expect(creatorDeleteAndWait(creatorExactResource{
			Kind: "mutatingwebhookconfiguration", Name: creatorReinvocationWebhook,
		})).To(Succeed())
		for _, resource := range []creatorExactResource{
			{Kind: "pod", Name: creatorReinvocationService, Namespace: creatorTestNS},
			{Kind: "service", Name: creatorReinvocationService, Namespace: creatorTestNS},
			{Kind: "secret", Name: creatorReinvocationService, Namespace: creatorTestNS},
		} {
			Expect(creatorDeleteAndWait(resource)).To(Succeed())
		}
	})

	It("keeps tracking on operator-managed ServiceAccounts", func(ctx SpecContext) {
		manifest := fmt.Sprintf(`
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: %[1]s
spec:
  targetName: %[2]s
  subjects:
    - kind: ServiceAccount
      name: %[3]s
      namespace: %[4]s
  clusterRoleBindings:
    clusterRoleRefs: ["view"]
  automountServiceAccountToken: false
`, creatorBindDefinition, creatorManagedTarget, creatorManagedSA, creatorTestNS)
		Expect(creatorApplyManifest(ctx, manifest)).To(Succeed())
		bindDefinition, err := creatorGetObject(ctx, "binddefinition", creatorBindDefinition, "")
		Expect(err).NotTo(HaveOccurred())
		generation := bindDefinition.Metadata.Generation
		Eventually(func() error { return creatorBindReadyError(ctx, generation) },
			creatorTimeout, creatorPollInterval).Should(Succeed())

		assertGenerated := func(wantAutomount bool) {
			current, getErr := creatorGetObject(ctx, "binddefinition", creatorBindDefinition, "")
			ExpectWithOffset(1, getErr).NotTo(HaveOccurred())
			ExpectWithOffset(1, current.Status.ExternalServiceAccounts).To(BeEmpty())
			generated := false
			for _, serviceAccount := range current.Status.GeneratedServiceAccounts {
				generated = generated || serviceAccount.Kind == "ServiceAccount" &&
					serviceAccount.Name == creatorManagedSA && serviceAccount.Namespace == creatorTestNS
			}
			ExpectWithOffset(1, generated).To(BeTrue())
			for _, condition := range current.Status.Conditions {
				ExpectWithOffset(1, condition.Type).NotTo(Equal("ServiceAccountOwnershipTransferred"))
			}

			serviceAccount, saErr := creatorGetObject(ctx, "serviceaccount", creatorManagedSA, creatorTestNS)
			ExpectWithOffset(1, saErr).NotTo(HaveOccurred())
			creatorExpectStamp(serviceAccount, controllerIdentity)
			ExpectWithOffset(1, serviceAccount.AutomountServiceAccountToken).NotTo(BeNil())
			ExpectWithOffset(1, *serviceAccount.AutomountServiceAccountToken).To(Equal(wantAutomount))
			ExpectWithOffset(1, serviceAccount.Metadata.Labels).To(HaveKeyWithValue(
				"app.kubernetes.io/managed-by", "auth-operator"))
			ExpectWithOffset(1, serviceAccount.Metadata.Labels).To(HaveKeyWithValue(
				"app.kubernetes.io/name", "auth-operator"))
			ExpectWithOffset(1, creatorValidateManagedFields(serviceAccount, []creatorExpectedManagedField{
				{
					Manager:   "auth-operator/BindDefinition/" + creatorBindDefinition,
					Operation: "Apply",
					Paths: [][]string{
						{"f:automountServiceAccountToken"},
						{"f:metadata", "f:labels", "f:app.kubernetes.io/managed-by"},
						{"f:metadata", "f:labels", "f:app.kubernetes.io/name"},
					},
				},
				{
					Manager: "auth-operator", Operation: "Update",
					Paths: [][]string{{"f:metadata", "f:annotations", "f:authorization.t-caas.telekom.com/source-names"}},
				},
			})).To(Succeed())
		}
		assertGenerated(false)

		for _, wantAutomount := range []bool{true, false} {
			patch := fmt.Sprintf(`{"spec":{"automountServiceAccountToken":%t}}`, wantAutomount)
			output, patchErr := creatorKubectl(ctx, "", "patch", "binddefinition", creatorBindDefinition,
				"--type=merge", "--patch", patch, "-o", "json")
			Expect(patchErr).NotTo(HaveOccurred())
			patched, decodeErr := creatorDecodeObject(output)
			Expect(decodeErr).NotTo(HaveOccurred())
			Expect(patched.Metadata.Generation).To(BeNumerically(">", generation))
			generation = patched.Metadata.Generation
			Eventually(func() error { return creatorBindReadyError(ctx, generation) },
				creatorTimeout, creatorPollInterval).Should(Succeed())
			assertGenerated(wantAutomount)
		}

		current, err := creatorGetObject(ctx, "binddefinition", creatorBindDefinition, "")
		Expect(err).NotTo(HaveOccurred())
		events, err := creatorKubectl(ctx, "", "get", "events", "-A",
			"--field-selector=involvedObject.kind=BindDefinition,involvedObject.name="+creatorBindDefinition+
				",involvedObject.uid="+current.Metadata.UID, "-o", "json")
		Expect(err).NotTo(HaveOccurred())
		var eventList creatorEventList
		Expect(json.Unmarshal(events, &eventList)).To(Succeed())
		for _, event := range eventList.Items {
			Expect(event.Reason).NotTo(Equal("ServiceAccountOwnershipTransferred"))
			if event.Type == "Warning" {
				Expect(strings.ToLower(event.Reason + " " + event.Message)).NotTo(ContainSubstring("conflict"))
			}
		}
		creatorSaveManagedFields(ctx, "serviceaccount", creatorManagedSA, creatorTestNS,
			"creator-managed-serviceaccount-managed-fields.json")
	})

	It("handles creator annotation budget limits without blocking writes", func(ctx SpecContext) {
		targetIdentity := creatorIdentity{
			Username: creatorServiceAccountUsername(creatorTestNS, creatorTargetSA),
			Groups:   creatorServiceAccountGroups(creatorTestNS),
		}
		creatorBytes := len(createdByAnnotation) + len(targetIdentity.Username) +
			len(createdByGroupsAnnotation) + len(strings.Join(creatorEncodedComponents(strings.Join(targetIdentity.Groups, ",")), ","))
		paddingLength := annotationBudget - creatorBytes - len(paddingAnnotation)
		exact, err := creatorCreateNamespace(ctx, requesterKubeconfig, targetIdentity.Username,
			creatorExactFitCreateNS, map[string]string{paddingAnnotation: strings.Repeat("x", paddingLength)}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(exact, targetIdentity)

		By("Skipping the creator stamp when CREATE has no room")
		paddingLength = annotationBudget - len(paddingAnnotation)
		created, err := creatorCreateNamespace(ctx, "", "", creatorOverflowCreateNS,
			map[string]string{paddingAnnotation: strings.Repeat("x", paddingLength)}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(created)
		Expect(created.Metadata.Annotations[paddingAnnotation]).To(HaveLen(paddingLength))

		By("Removing creator data when restoration has no room")
		tracked, err := creatorCreateNamespace(ctx, requesterKubeconfig, targetIdentity.Username,
			creatorOverflowRestoreNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(tracked, targetIdentity)
		creatorBytes = len(createdByAnnotation) + len(tracked.Metadata.Annotations[createdByAnnotation]) +
			len(createdByGroupsAnnotation) + len(tracked.Metadata.Annotations[createdByGroupsAnnotation])
		paddingLength = annotationBudget - creatorBytes + 1 - len(paddingAnnotation)
		updated, err := creatorPatchNamespace(ctx, "", "", creatorOverflowRestoreNS, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{paddingAnnotation: strings.Repeat("x", paddingLength)},
				"labels":      map[string]any{"e2e.t-caas.telekom.com/budget-update": "accepted"},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(updated)
		Expect(updated.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/budget-update", "accepted"))
	})

	It("honors excluded creators and editors without bypassing restoration", func(ctx SpecContext) {
		excludedCreator := creatorServiceAccountUsername(creatorTestNS, creatorTargetSA)
		Expect(creatorHelmUpgradeExcluded(ctx, "protect", excludedCreator)).To(Succeed())
		Eventually(func() error {
			activated, activationErr := creatorCreateNamespace(ctx, requesterKubeconfig, excludedCreator,
				creatorExcludedNS, nil, true)
			if activationErr != nil {
				return activationErr
			}
			for _, key := range []string{createdByAnnotation, createdByGroupsAnnotation, updatedByAnnotation} {
				if _, present := activated.Metadata.Annotations[key]; present {
					return fmt.Errorf("excluded creator activation still writes %s", key)
				}
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
		created, err := creatorCreateNamespace(ctx, requesterKubeconfig, excludedCreator, creatorExcludedNS, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(created)
		forged, err := creatorPatchNamespace(ctx, requesterKubeconfig, excludedCreator, creatorForgedCreateNS, map[string]any{
			"metadata": map[string]any{"annotations": map[string]any{createdByAnnotation: "forged", createdByGroupsAnnotation: "forged", updatedByAnnotation: "forged"}},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(forged, creatorIdentity{Username: excludedCreator, Groups: creatorServiceAccountGroups(creatorTestNS)})
		Expect(forged.Metadata.Annotations).NotTo(HaveKey(updatedByAnnotation))

		excludedEditor := creatorServiceAccountUsername(creatorTestNS, creatorEditorASA)
		Expect(creatorHelmUpgradeExcluded(ctx, "contributors", excludedEditor)).To(Succeed())
		includedEditor := creatorServiceAccountUsername(creatorTestNS, creatorEditorBSA)
		Eventually(func() error {
			activated, activationErr := creatorPatchNamespace(ctx, requesterKubeconfig, includedEditor,
				creatorForgedCreateNS, map[string]any{
					"metadata": map[string]any{"labels": map[string]any{
						"e2e.t-caas.telekom.com/excluded-editor-activation": "dry",
					}},
				}, true)
			if activationErr != nil {
				return activationErr
			}
			if activated.Metadata.Annotations[updatedByAnnotation] != creatorEncodeComponent(includedEditor) {
				return fmt.Errorf("contributors mode with exclusions is not active")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
		edited, err := creatorPatchNamespace(ctx, requesterKubeconfig, excludedEditor, creatorForgedCreateNS, map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"e2e.t-caas.telekom.com/excluded-editor": "accepted"}},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(edited.Metadata.Annotations).NotTo(HaveKey(updatedByAnnotation))
		Expect(edited.Metadata.Annotations).To(HaveKey(createdByAnnotation))
		Expect(creatorHelmUpgrade(ctx, "protect")).To(Succeed())
	})

	It("encodes and deduplicates a reserved-character effective identity", func(ctx SpecContext) {
		Expect(creatorHelmUpgrade(ctx, "contributors")).To(Succeed())
		encoded := creatorEncodeComponent(creatorReservedUser)
		Eventually(func() error {
			activated, activationErr := creatorPatchNamespace(ctx, requesterKubeconfig, creatorReservedUser,
				creatorForgedCreateNS, map[string]any{
					"metadata": map[string]any{"labels": map[string]any{
						"e2e.t-caas.telekom.com/reserved-activation": "dry",
					}},
				}, true)
			if activationErr != nil {
				return activationErr
			}
			if activated.Metadata.Annotations[updatedByAnnotation] != encoded {
				return fmt.Errorf("contributors mode is not active for the reserved identity")
			}
			return nil
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
		first, err := creatorPatchNamespace(ctx, requesterKubeconfig, creatorReservedUser, creatorForgedCreateNS, map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"e2e.t-caas.telekom.com/reserved": "first"}},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(first.Metadata.Annotations[updatedByAnnotation]).To(Equal(encoded))
		second, err := creatorPatchNamespace(ctx, requesterKubeconfig, creatorReservedUser, creatorForgedCreateNS, map[string]any{
			"metadata": map[string]any{"labels": map[string]any{"e2e.t-caas.telekom.com/reserved": "second"}},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		components := creatorEncodedComponents(second.Metadata.Annotations[updatedByAnnotation])
		Expect(components).To(Equal([]string{encoded}))
		decoded := strings.ReplaceAll(strings.ReplaceAll(components[0], "%2C", ","), "%25", "%")
		Expect(decoded).To(Equal(creatorReservedUser))
	})

	Context("Contributor mode", Ordered, func() {
		var (
			targetIdentity  creatorIdentity
			editorAIdentity creatorIdentity
			editorBIdentity creatorIdentity
		)

		BeforeAll(func(ctx SpecContext) {
			targetIdentity = creatorIdentity{
				Username: creatorServiceAccountUsername(creatorTestNS, creatorTargetSA),
				Groups:   creatorServiceAccountGroups(creatorTestNS),
			}
			editorAIdentity = creatorIdentity{
				Username: creatorServiceAccountUsername(creatorTestNS, creatorEditorASA),
				Groups:   creatorServiceAccountGroups(creatorTestNS),
			}
			editorBIdentity = creatorIdentity{
				Username: creatorServiceAccountUsername(creatorTestNS, creatorEditorBSA),
				Groups:   creatorServiceAccountGroups(creatorTestNS),
			}

			for _, name := range []string{creatorContributorsNS, creatorContributorLimitNS} {
				created, err := creatorCreateNamespace(ctx, requesterKubeconfig, targetIdentity.Username, name, nil, false)
				Expect(err).NotTo(HaveOccurred())
				creatorExpectStamp(created, targetIdentity)
			}
			Expect(creatorHelmUpgrade(ctx, "contributors")).To(Succeed())

			Eventually(func() error {
				object, patchErr := creatorPatchNamespace(ctx, requesterKubeconfig, editorAIdentity.Username,
					creatorContributorsNS, map[string]any{
						"metadata": map[string]any{"labels": map[string]any{
							"e2e.t-caas.telekom.com/contributor-activation": "dry",
						}},
					}, true)
				if patchErr != nil {
					return patchErr
				}
				want := creatorEncodeComponent(editorAIdentity.Username)
				if object.Metadata.Annotations[updatedByAnnotation] != want {
					return fmt.Errorf("contributor activation = %q, want %q",
						object.Metadata.Annotations[updatedByAnnotation], want)
				}
				return creatorStampError(object, targetIdentity)
			}, creatorTimeout, creatorPollInterval).Should(Succeed())
		})

		AfterAll(func(ctx SpecContext) {
			Expect(creatorHelmUpgrade(ctx, "protect")).To(Succeed())
			Eventually(func() error {
				object, err := creatorPatchNamespace(ctx, "", "", creatorContributorsNS, map[string]any{
					"metadata": map[string]any{"labels": map[string]any{
						"e2e.t-caas.telekom.com/protect-activation": "dry",
					}},
				}, true)
				if err != nil {
					return err
				}
				if _, present := object.Metadata.Annotations[updatedByAnnotation]; present {
					return fmt.Errorf("protect mode still returned contributor history")
				}
				return nil
			}, creatorTimeout, creatorPollInterval).Should(Succeed())
		})

		It("records first-edit order and repairs tampering", func(ctx SpecContext) {
			patchAs := func(identity creatorIdentity, value string) creatorObject {
				object, err := creatorPatchNamespace(ctx, requesterKubeconfig, identity.Username,
					creatorContributorsNS, map[string]any{
						"metadata": map[string]any{"labels": map[string]any{
							"e2e.t-caas.telekom.com/contributor-touch": value,
						}},
					}, false)
				ExpectWithOffset(1, err).NotTo(HaveOccurred())
				return object
			}
			first := patchAs(editorBIdentity, "editor-b-one")
			second := patchAs(editorBIdentity, "editor-b-two")
			Expect(second.Metadata.Annotations[updatedByAnnotation]).To(Equal(
				creatorEncodeComponent(editorBIdentity.Username)))

			adminUpdated, err := creatorPatchNamespace(ctx, "", "", creatorContributorsNS, map[string]any{
				"metadata": map[string]any{"labels": map[string]any{
					"e2e.t-caas.telekom.com/contributor-touch": "admin",
				}},
			}, false)
			Expect(err).NotTo(HaveOccurred())
			want := []string{creatorEncodeComponent(editorBIdentity.Username), creatorEncodeComponent(adminIdentity.Username)}
			Expect(creatorEncodedComponents(adminUpdated.Metadata.Annotations[updatedByAnnotation])).To(Equal(want))
			Expect(first.Metadata.Annotations[updatedByAnnotation]).To(Equal(want[0]))

			restored, err := creatorPatchNamespace(ctx, requesterKubeconfig, editorBIdentity.Username,
				creatorContributorsNS, map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]any{updatedByAnnotation: "forged,history"},
						"labels":      map[string]any{"e2e.t-caas.telekom.com/contributor-touch": "tamper"},
					},
				}, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(creatorEncodedComponents(restored.Metadata.Annotations[updatedByAnnotation])).To(Equal(want))
			next, err := creatorPatchNamespace(ctx, "", "", creatorContributorsNS, map[string]any{
				"metadata": map[string]any{"labels": map[string]any{
					"e2e.t-caas.telekom.com/contributor-touch": "after-tamper",
				}},
			}, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(creatorEncodedComponents(next.Metadata.Annotations[updatedByAnnotation])).To(Equal(want))
		})

		It("skips append overflow and removes oversized old history", func(ctx SpecContext) {
			base, err := creatorGetObject(ctx, "namespace", creatorContributorLimitNS, "")
			Expect(err).NotTo(HaveOccurred())
			creatorBytes := len(createdByAnnotation) + len(base.Metadata.Annotations[createdByAnnotation]) +
				len(createdByGroupsAnnotation) + len(base.Metadata.Annotations[createdByGroupsAnnotation])
			firstEditor := creatorEncodeComponent(editorBIdentity.Username)
			paddingLength := annotationBudget - creatorBytes - len(updatedByAnnotation) - len(firstEditor) - len(paddingAnnotation)
			padded, err := creatorPatchNamespace(ctx, requesterKubeconfig, editorBIdentity.Username,
				creatorContributorLimitNS, map[string]any{
					"metadata": map[string]any{
						"annotations": map[string]any{paddingAnnotation: strings.Repeat("x", paddingLength)},
						"labels":      map[string]any{"e2e.t-caas.telekom.com/limit-touch": "editor-b"},
					},
				}, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(padded.Metadata.Annotations[updatedByAnnotation]).To(Equal(firstEditor))
			next, err := creatorPatchNamespace(ctx, "", "", creatorContributorLimitNS, map[string]any{
				"metadata": map[string]any{"labels": map[string]any{"e2e.t-caas.telekom.com/limit-touch": "admin"}},
			}, false)
			Expect(err).NotTo(HaveOccurred())
			Expect(next.Metadata.Annotations[updatedByAnnotation]).To(Equal(firstEditor))

			oldList := strings.Repeat("x", 1024)
			paddingLength = annotationBudget - len(updatedByAnnotation) - len(oldList) + 1 - len(paddingAnnotation)
			overflow, err := creatorPatchNamespace(ctx, "", "", creatorContributorRestoreNS, map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]any{paddingAnnotation: strings.Repeat("x", paddingLength)},
					"labels":      map[string]any{"e2e.t-caas.telekom.com/restore-touch": "accepted"},
				},
			}, false)
			Expect(err).NotTo(HaveOccurred())
			_, present := overflow.Metadata.Annotations[updatedByAnnotation]
			Expect(present).To(BeFalse())
			Expect(overflow.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/restore-touch", "accepted"))
		})
	})
})

var _ = Describe("Creator Tracking Cleanup", Label("creator-tracking-cleanup"), func() {
	It("removes only the exact creator-tracking resources", func(ctx SpecContext) {
		Expect(creatorValidateIsolation(ctx)).To(Succeed())
		cleanupErrors := creatorCleanup(true)
		Expect(cleanupErrors).To(BeEmpty(), creatorFormatErrors(cleanupErrors))
	})
})

var _ = Describe("Creator Tracking Legacy Helm Upgrade", Label("creator-tracking", "creator-tracking-upgrade"), func() {
	It("upgrades the exact origin main chart with reuse-values and preserves the release", func(ctx SpecContext) {
		if os.Getenv("E2E_CREATOR_TRACKING_API_VERSION") != "admissionregistration.k8s.io/v1" {
			Skip("the real old-chart upgrade runs only on the stable MAP API")
		}
		runDir, err := creatorPrivateRunDir()
		Expect(err).NotTo(HaveOccurred())
		extractDir, err := os.MkdirTemp(runDir, "origin-main-chart-*")
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { Expect(os.RemoveAll(extractDir)).To(Succeed()) })

		archivePath := filepath.Join(runDir, "origin-main-auth-operator-chart.tar")
		archive, err := creatorRun(ctx, "", "git", "archive", "origin/main", "chart/auth-operator")
		Expect(err).NotTo(HaveOccurred())
		Expect(os.WriteFile(archivePath, archive, 0o600)).To(Succeed())
		DeferCleanup(func() { Expect(os.Remove(archivePath)).To(Succeed()) })
		output, err := creatorRun(ctx, "", "tar", "-xf", archivePath, "-C", extractDir)
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		oldChart := filepath.Join(extractDir, "chart", "auth-operator")
		Expect(filepath.Join(oldChart, "Chart.yaml")).To(BeAnExistingFile())

		release := fmt.Sprintf("ct-old-%d", time.Now().UnixNano())
		installArgs := append([]string{"install", release, oldChart, "--namespace", creatorOperatorNS,
			"--create-namespace", "--wait", "--timeout", "5m"}, imageSetArgs()...)
		output, err = creatorRun(ctx, "", "helm", installArgs...)
		Expect(err).NotTo(HaveOccurred(), "%s", output)

		history := func() int {
			raw, historyErr := creatorRun(ctx, "", "helm", "history", release,
				"--namespace", creatorOperatorNS, "--output", "json")
			ExpectWithOffset(1, historyErr).NotTo(HaveOccurred(), "%s", raw)
			var entries []map[string]any
			ExpectWithOffset(1, json.Unmarshal(raw, &entries)).To(Succeed())
			ExpectWithOffset(1, entries).NotTo(BeEmpty())
			revision, ok := entries[len(entries)-1]["revision"].(float64)
			ExpectWithOffset(1, ok).To(BeTrue())
			return int(revision)
		}
		before := history()
		Expect(before).To(Equal(1))
		preUpgradeNamespace := release + "-pre-existing"
		preUpgrade, err := creatorCreateNamespace(ctx, "", "", preUpgradeNamespace, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(preUpgrade)

		DeferCleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			var cleanupErrors []error
			output, uninstallErr := creatorRun(cleanupCtx, "", "helm", "uninstall", release, "--namespace", creatorOperatorNS, "--ignore-not-found", "--wait", "--timeout", "90s")
			if uninstallErr != nil && !creatorIsAbsentError(output, uninstallErr) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("helm uninstall: %w", uninstallErr))
			}
			for _, resources := range [][]creatorExactResource{
				creatorAdmissionFrontendsForRelease(release), creatorReleaseBindingResources(release), creatorAdmissionPoliciesForRelease(release),
				creatorReleaseRoleResources(release), creatorReleaseNamespacedResources(release),
				{{Kind: "namespace", Name: preUpgradeNamespace}, {Kind: "namespace", Name: release + "-post-upgrade"}},
			} {
				_, errs := creatorDeletePhase(cleanupCtx, resources, time.Minute)
				cleanupErrors = append(cleanupErrors, errs...)
			}
			verifyResources := append(creatorAdmissionFrontendsForRelease(release), creatorAdmissionPoliciesForRelease(release)...)
			verifyResources = append(verifyResources, creatorReleaseBindingResources(release)...)
			verifyResources = append(verifyResources, creatorReleaseRoleResources(release)...)
			verifyResources = append(verifyResources, creatorReleaseNamespacedResources(release)...)
			verifyResources = append(verifyResources,
				creatorExactResource{Kind: "namespace", Name: preUpgradeNamespace},
				creatorExactResource{Kind: "namespace", Name: release + "-post-upgrade"})
			if absent, _, errs := creatorWaitResourcesAbsent(cleanupCtx, verifyResources); !absent {
				cleanupErrors = append(cleanupErrors, errs...)
			}
			status, statusErr := creatorRun(cleanupCtx, "", "helm", "status", release, "--namespace", creatorOperatorNS)
			if statusErr == nil || !creatorIsAbsentError(status, statusErr) {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("Helm release %s remains visible", release))
			}
			Expect(cleanupErrors).To(BeEmpty(), creatorFormatErrors(cleanupErrors))
		})

		upgradeCtx, cancel := context.WithTimeout(ctx, 6*time.Minute)
		defer cancel()
		output, err = creatorRun(upgradeCtx, "", "helm", "upgrade", release, creatorChartPath,
			"--namespace", creatorOperatorNS, "--reuse-values",
			"--set", "creatorTracking.enabled=true",
			"--set", "creatorTracking.map=auto",
			"--set", "creatorTracking.mode=protect",
			"--wait", "--timeout", "5m")
		Expect(err).NotTo(HaveOccurred(), "%s", output)
		after := history()
		Expect(after).To(Equal(before + 1))
		status, err := creatorRun(ctx, "", "helm", "status", release, "--namespace", creatorOperatorNS)
		Expect(err).NotTo(HaveOccurred(), "%s", status)
		Expect(string(status)).To(ContainSubstring("STATUS: deployed"))

		for _, policy := range creatorAdmissionPoliciesForRelease(release) {
			Eventually(func() error {
				_, policyErr := creatorKubectl(ctx, "", "get", policy.Kind, policy.Name)
				return policyErr
			}, creatorTimeout, creatorPollInterval).Should(Succeed())
		}
		upgradeIdentity, identityErr := creatorReadIdentity(ctx, "", "")
		Expect(identityErr).NotTo(HaveOccurred())
		postUpgradeNamespace := release + "-post-upgrade"
		Eventually(func() error {
			activated, activationErr := creatorCreateNamespace(ctx, "", "", postUpgradeNamespace, nil, true)
			if activationErr != nil {
				return activationErr
			}
			return creatorStampError(activated, upgradeIdentity)
		}, creatorTimeout, creatorPollInterval).Should(Succeed())
		created, err := creatorCreateNamespace(ctx, "", "", postUpgradeNamespace, nil, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectStamp(created, upgradeIdentity)
		patched, err := creatorPatchNamespace(ctx, "", "", preUpgradeNamespace, map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{createdByAnnotation: "forged", createdByGroupsAnnotation: "forged", updatedByAnnotation: "forged"},
				"labels":      map[string]any{"e2e.t-caas.telekom.com/upgrade-touch": "preserved"},
			},
		}, false)
		Expect(err).NotTo(HaveOccurred())
		creatorExpectNoTracking(patched)
		Expect(patched.Metadata.Labels).To(HaveKeyWithValue("e2e.t-caas.telekom.com/upgrade-touch", "preserved"))
	})
})

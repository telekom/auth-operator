// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/telekom/auth-operator/test/utils"
)

var _ = Describe("Restricted CRD E2E", Ordered, ContinueOnFailure, Label("basic", "restricted"), func() {

	BeforeEach(func() {
		By("Waiting for controller-manager and webhook pods to be ready")
		Expect(utils.WaitForDeploymentAvailable("control-plane=controller-manager", operatorNamespace, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=controller-manager", operatorNamespace, deployTimeout)).To(Succeed())
		Expect(utils.WaitForPodsReady("control-plane=webhook-server", operatorNamespace, deployTimeout)).To(Succeed())

		By("Waiting for webhook configurations and service endpoints")
		Expect(utils.WaitForWebhookConfigurations("authorization.t-caas.telekom.com/component=webhook", deployTimeout)).To(Succeed())
		Expect(utils.WaitForServiceEndpoints(webhookService, operatorNamespace, deployTimeout)).To(Succeed())

		By("Waiting for webhook CA bundle and TLS certificate")
		Expect(utils.WaitForWebhookCABundle("authorization.t-caas.telekom.com/component=webhook", deployTimeout)).To(Succeed())
		Expect(utils.WaitForWebhookReady(deployTimeout)).To(Succeed())

		By("Ensuring test namespace exists")
		ensureTestNamespace()
	})

	AfterEach(func() {
		By("Resetting restricted CRD e2e test state")
		cleanupRestrictedCRDTestState()
	})

	AfterAll(func() {
		if CurrentSpecReport().Failed() || utils.DebugLevel >= 2 {
			By("Collecting debug info")
			utils.CollectAndSaveAllDebugInfo("Restricted CRD E2E AfterAll")
			utils.CollectNamespaceDebugInfo(operatorNamespace, "Restricted CRD E2E AfterAll")
			utils.CollectOperatorLogs(operatorNamespace, 200)
		}

		By("Cleaning up restricted CRD test resources")
		cleanupRestrictedCRDTestState()
	})

	Context("RBACPolicy CRD", func() {
		It("should create and reconcile an RBACPolicy", func() {
			By("Applying RBACPolicy")
			applyFixture("rbacpolicy.yaml")

			By("Verifying RBACPolicy was created")
			Eventually(func() error {
				return checkResourceExists("rbacpolicy", "e2e-test-policy", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RBACPolicy status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RBACPolicy spec is correct")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy", // #nosec G204
				"-o", "jsonpath={.spec.appliesTo.namespaceSelector.matchLabels}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("e2e-test"))
		})

		It("should show bound resource count", func() {
			By("Applying RBACPolicy")
			applyFixture("rbacpolicy.yaml")

			By("Waiting for RBACPolicy to be ready")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying initial bound resource count is 0")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy", // #nosec G204
				"-o", "jsonpath={.status.boundResourceCount}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("0"))
		})

		It("should enforce requester default policy assignment at admission and reconciliation", func() {
			By("Creating policies with a requester default assignment")
			policiesYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: e2e-default-assigned-policy
  labels:
    app.kubernetes.io/component: e2e-test
spec:
  appliesTo:
    namespaces:
      - e2e-test-ns
  defaultAssignment:
    groups:
      - oidc:e2e-default-policy-admins
  roleLimits:
    allowClusterRoles: false
    forbiddenVerbs:
      - escalate
      - impersonate
      - bind
    maxRulesPerRole: 200
  bindingLimits:
    allowClusterRoleBindings: false
    clusterRoleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    roleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    targetNamespaceLimits:
      maxTargetNamespaces: 1
  subjectLimits:
    allowedKinds:
      - ServiceAccount
    serviceAccountLimits:
      creation:
        allowAutoCreate: true
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: e2e-default-other-policy
  labels:
    app.kubernetes.io/component: e2e-test
spec:
  appliesTo:
    namespaces:
      - e2e-test-ns
  roleLimits:
    allowClusterRoles: false
    forbiddenVerbs:
      - escalate
      - impersonate
      - bind
    maxRulesPerRole: 200
  bindingLimits:
    allowClusterRoleBindings: false
    clusterRoleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    roleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    targetNamespaceLimits:
      maxTargetNamespaces: 1
  subjectLimits:
    allowedKinds:
      - ServiceAccount
    serviceAccountLimits:
      creation:
        allowAutoCreate: true
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: e2e-default-sa-policy
  labels:
    app.kubernetes.io/component: e2e-test
spec:
  appliesTo:
    namespaces:
      - e2e-test-ns
  defaultAssignment:
    serviceAccounts:
      - name: e2e-default-policy-requester
        namespace: e2e-test-ns
  roleLimits:
    allowClusterRoles: false
    forbiddenVerbs:
      - escalate
      - impersonate
      - bind
    maxRulesPerRole: 200
  bindingLimits:
    allowClusterRoleBindings: false
    clusterRoleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    roleBindingLimits:
      allowedRoleRefs:
        - e2e-default-policy-role
    targetNamespaceLimits:
      maxTargetNamespaces: 1
  subjectLimits:
    allowedKinds:
      - ServiceAccount
    serviceAccountLimits:
      creation:
        allowAutoCreate: true
`
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(policiesYAML)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Creating the role and ServiceAccount used by persisted restricted resources")
			prereqYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: e2e-default-policy-role
  labels:
    app.kubernetes.io/component: e2e-test
rules:
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - get
      - list
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: e2e-default-policy-requester
  namespace: e2e-test-ns
  labels:
    app.kubernetes.io/component: e2e-test
`
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(prereqYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Granting impersonated requesters create and update permission for restricted resources")
			rbacYAML := `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: e2e-default-policy-assignment-create
rules:
  - apiGroups:
      - authorization.t-caas.telekom.com
    resources:
      - restrictedroledefinitions
      - restrictedbinddefinitions
    verbs:
      - get
      - create
      - update
      - patch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: e2e-default-policy-assignment-create
subjects:
  - kind: User
    name: e2e-default-policy-user
  - kind: User
    name: e2e-default-policy-unassigned-user
  - kind: ServiceAccount
    name: e2e-default-policy-requester
    namespace: e2e-test-ns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: e2e-default-policy-assignment-create
`
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(rbacYAML)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				cleanup := utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrole,clusterrolebinding", // #nosec G204
					"e2e-default-policy-assignment-create", "--ignore-not-found=true")
				_, _ = utils.Run(cleanup)
				cleanup = utils.CommandContext(context.Background(), "kubectl", "delete", "clusterrole", // #nosec G204
					"e2e-default-policy-role", "--ignore-not-found=true")
				_, _ = utils.Run(cleanup)
				cleanup = utils.CommandContext(context.Background(), "kubectl", "delete", "serviceaccount", // #nosec G204
					"e2e-default-policy-requester", "-n", testNamespace, "--ignore-not-found=true")
				_, _ = utils.Run(cleanup)
			}()

			restrictedRole := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: e2e-default-policy-dry-run
  labels:
    app.kubernetes.io/component: e2e-test
spec:
  policyRef:
    name: e2e-default-other-policy
  targetRole: Role
  targetName: e2e-default-policy-dry-run
  targetNamespace: e2e-test-ns
  scopeNamespaced: true
`
			By("Rejecting a default-assigned requester that selects a different policy")
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "--dry-run=server", // #nosec G204
				"--as=e2e-default-policy-user",
				"--as-group=oidc:e2e-default-policy-admins",
				"-f", "-")
			cmd.Stdin = strings.NewReader(restrictedRole)
			output, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("e2e-default-assigned-policy"))
			Expect(string(output)).To(ContainSubstring("spec.policyRef.name"))

			By("Allowing the same requester when selecting the assigned policy")
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", "--dry-run=server", // #nosec G204
				"--as=e2e-default-policy-user",
				"--as-group=oidc:e2e-default-policy-admins",
				"-f", "-")
			cmd.Stdin = strings.NewReader(strings.ReplaceAll(restrictedRole, "e2e-default-other-policy", "e2e-default-assigned-policy"))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Persisting a RestrictedRoleDefinition with the assigned group policy")
			persistedRole := strings.ReplaceAll(restrictedRole, "e2e-default-policy-dry-run", "e2e-default-policy-persisted-role")
			persistedRole = strings.ReplaceAll(persistedRole, "e2e-default-other-policy", "e2e-default-assigned-policy")
			persistedRole += `
  restrictedVerbs:
    - escalate
    - impersonate
    - bind
`
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", // #nosec G204
				"--as=e2e-default-policy-user",
				"--as-group=oidc:e2e-default-policy-admins",
				"-f", "-")
			cmd.Stdin = strings.NewReader(persistedRole)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-default-policy-persisted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() error {
				return checkResourceExists("role", "e2e-default-policy-persisted-role", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			wrongPolicyBinding := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: e2e-default-policy-wrong-binding
  labels:
    app.kubernetes.io/component: e2e-test
spec:
  policyRef:
    name: e2e-default-other-policy
  targetName: e2e-default-policy-wrong-binding
  subjects:
    - kind: ServiceAccount
      name: e2e-default-policy-wrong-sa
      namespace: e2e-test-ns
      apiGroup: ""
  roleBindings:
    - namespace: e2e-test-ns
      clusterRoleRefs:
        - e2e-default-policy-role
`
			By("Creating a different-policy RestrictedBindDefinition as an unassigned requester")
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", // #nosec G204
				"--as=e2e-default-policy-unassigned-user",
				"-f", "-")
			cmd.Stdin = strings.NewReader(wrongPolicyBinding)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-default-policy-wrong-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Rejecting mutable updates from a requester assigned to a different default policy")
			cmd = utils.CommandContext(context.Background(), "kubectl", "patch", "restrictedbinddefinition", // #nosec G204
				"e2e-default-policy-wrong-binding",
				"--as=e2e-default-policy-user",
				"--as-group=oidc:e2e-default-policy-admins",
				"--type=merge",
				"-p", `{"spec":{"automountServiceAccountToken":false}}`)
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("e2e-default-assigned-policy"))

			serviceAccountBinding := strings.ReplaceAll(wrongPolicyBinding, "e2e-default-policy-wrong-binding", "e2e-default-policy-sa-binding")
			serviceAccountBinding = strings.ReplaceAll(serviceAccountBinding, "e2e-default-policy-wrong-sa", "e2e-default-policy-sa-created")
			serviceAccountBinding = strings.ReplaceAll(serviceAccountBinding, "e2e-default-other-policy", "e2e-default-sa-policy")

			By("Rejecting a default-assigned ServiceAccount requester that selects a different policy")
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", // #nosec G204
				"--as=system:serviceaccount:e2e-test-ns:e2e-default-policy-requester",
				"-f", "-")
			cmd.Stdin = strings.NewReader(wrongPolicyBinding)
			output, err = utils.Run(cmd)
			Expect(err).To(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("e2e-default-sa-policy"))

			By("Persisting a RestrictedBindDefinition with the ServiceAccount-assigned policy")
			cmd = utils.CommandContext(context.Background(), "kubectl", "apply", // #nosec G204
				"--as=system:serviceaccount:e2e-test-ns:e2e-default-policy-requester",
				"-f", "-")
			cmd.Stdin = strings.NewReader(serviceAccountBinding)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-default-policy-sa-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() error {
				return checkResourceExists("rolebinding", "e2e-default-policy-sa-binding-e2e-default-policy-role-binding", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "e2e-default-policy-sa-created", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("RestrictedBindDefinition CRD", func() {
		It("should create RoleBinding within policy limits", func() {
			By("Applying RBACPolicy first")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Ensuring prerequisite ClusterRole exists")
			applyFixture("roledefinition_clusterrole.yaml")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "e2e-cluster-reader", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Applying RestrictedBindDefinition")
			applyFixture("restrictedbinddefinition.yaml")

			By("Verifying RestrictedBindDefinition was created")
			Eventually(func() error {
				return checkResourceExists("restrictedbinddefinition", "e2e-test-restricted-binding", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RestrictedBindDefinition is policy compliant")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "PolicyCompliant")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RestrictedBindDefinition status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying exact RoleBinding was created in test namespace")
			expectedRoleBinding := "e2e-restricted-binding-e2e-cluster-reader-binding"
			Eventually(func() error {
				return checkResourceExists("rolebinding", expectedRoleBinding, testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			jsonPath := "{.roleRef.kind}/{.roleRef.name} " +
				"{.subjects[0].kind}/{.subjects[0].namespace}/{.subjects[0].name} " +
				"{.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}"
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "rolebinding", // #nosec G204
				expectedRoleBinding, "-n", testNamespace,
				"-o", "jsonpath="+jsonPath)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).To(Equal(
				"ClusterRole/e2e-cluster-reader ServiceAccount/e2e-test-ns/e2e-restricted-sa RestrictedBindDefinition/e2e-test-restricted-binding",
			))

			By("Verifying generated ServiceAccount and status")
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "e2e-restricted-sa", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() string {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "restrictedbinddefinition", // #nosec G204
					"e2e-test-restricted-binding",
					"-o", "jsonpath={.status.generatedServiceAccounts[0].namespace}/{.status.generatedServiceAccounts[0].name}")
				output, err := utils.Run(cmd)
				if err != nil {
					return ""
				}
				return strings.TrimSpace(string(output))
			}, reconcileTimeout, pollingInterval).Should(Equal("e2e-test-ns/e2e-restricted-sa"))

			By("Verifying RBACPolicy bound count increased")
			Eventually(func() bool {
				cmd = utils.CommandContext(context.Background(), "kubectl", "get", "rbacpolicy", "e2e-test-policy", // #nosec G204
					"-o", "jsonpath={.status.boundResourceCount}")
				output, err = utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) != "0"
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
		})

		It("should reject bindings that violate policy", func() {
			By("Applying restrictive RBACPolicy")
			applyFixture("rbacpolicy_restrictive.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-restrictive-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedBindDefinition that violates the policy (CRB not allowed)")
			violatingYAML := `
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: e2e-violating-binding
spec:
  policyRef:
    name: e2e-test-restrictive-policy
  targetName: e2e-violating-binding
  subjects:
    - kind: ServiceAccount
      name: e2e-test-sa
      namespace: e2e-test-ns
      apiGroup: ""
  clusterRoleBindings:
    clusterRoleRefs:
      - admin
  roleBindings:
    - namespace: e2e-test-ns
      clusterRoleRefs:
        - e2e-allowed-reader
`
			cmd := utils.CommandContext(context.Background(), "kubectl", "apply", "-f", "-") // #nosec G204
			cmd.Stdin = strings.NewReader(violatingYAML)
			_, _ = utils.Run(cmd)

			By("Verifying RestrictedBindDefinition shows policy violations")
			// The RBD should be created but show PolicyCompliant=False
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "restrictedbinddefinition", // #nosec G204
					"e2e-violating-binding",
					"-o", "jsonpath={.status.conditions[?(@.type=='PolicyCompliant')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusFalse
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying Ready=False when PolicyCompliant=False (condition correlation)")
			Eventually(func() bool {
				cmd := utils.CommandContext(context.Background(), "kubectl", "get", "restrictedbinddefinition", // #nosec G204
					"e2e-violating-binding",
					"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}")
				output, err := utils.Run(cmd)
				if err != nil {
					return false
				}
				return strings.TrimSpace(string(output)) == statusFalse
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying violating binding did not create RBAC")
			Eventually(func() bool {
				return checkResourceExists("clusterrolebinding", "e2e-violating-binding-admin-binding", "") != nil
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() bool {
				return checkResourceExists("rolebinding", "e2e-violating-binding-e2e-allowed-reader-binding", testNamespace) != nil
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Cleaning up violating binding")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition", // #nosec G204
				"e2e-violating-binding", "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		It("should deprovision bindings when a compliant resource starts violating policy", func() {
			By("Setting up RBACPolicy and prerequisite ClusterRole")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			applyFixture("roledefinition_clusterrole.yaml")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "e2e-cluster-reader", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Applying a compliant RestrictedBindDefinition")
			applyFixture("restrictedbinddefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			expectedRoleBinding := "e2e-restricted-binding-e2e-cluster-reader-binding"
			Eventually(func() error {
				return checkResourceExists("rolebinding", expectedRoleBinding, testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "e2e-restricted-sa", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Patching the RestrictedBindDefinition into a forbidden kube-system target namespace")
			patchJSON := `{"spec":{"roleBindings":[{"namespace":"kube-system","clusterRoleRefs":["e2e-cluster-reader"]}]}}`
			cmd := utils.CommandContext(context.Background(), "kubectl", "patch", "restrictedbinddefinition", // #nosec G204
				"e2e-test-restricted-binding",
				"--type=merge",
				"-p", patchJSON)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Patch failed: %s", string(output))

			By("Verifying policy conditions report the violation")
			Eventually(func() bool {
				return checkResourceConditionStatus(
					"restrictedbinddefinition",
					"e2e-test-restricted-binding",
					"PolicyCompliant",
					statusFalse,
				)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() bool {
				return checkResourceConditionStatus("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready", statusFalse)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying previously generated RoleBinding and ServiceAccount were deprovisioned")
			Eventually(func() error {
				return checkResourceAbsent("rolebinding", expectedRoleBinding, testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceAbsent("serviceaccount", "e2e-restricted-sa", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceAbsent("rolebinding", expectedRoleBinding, "kube-system")
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})

		It("should clean up bindings when RestrictedBindDefinition is deleted", func() {
			By("Setting up RBACPolicy and prerequisite ClusterRole")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			applyFixture("roledefinition_clusterrole.yaml")
			Eventually(func() error {
				return checkResourceExists("clusterrole", "e2e-cluster-reader", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Applying RestrictedBindDefinition")
			applyFixture("restrictedbinddefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedbinddefinition", "e2e-test-restricted-binding", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			expectedRoleBinding := "e2e-restricted-binding-e2e-cluster-reader-binding"

			By("Waiting for generated RoleBinding and ServiceAccount to be created")
			Eventually(func() error {
				return checkResourceExists("rolebinding", expectedRoleBinding, testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceExists("serviceaccount", "e2e-restricted-sa", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Deleting RestrictedBindDefinition")
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition", // #nosec G204
				"e2e-test-restricted-binding", "--timeout=60s")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RestrictedBindDefinition finalizer cleanup to finish")
			Eventually(func() error {
				return checkResourceAbsent("restrictedbinddefinition", "e2e-test-restricted-binding", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Waiting for generated RoleBinding and ServiceAccount to be cleaned up")
			Eventually(func() error {
				return checkResourceAbsent("rolebinding", expectedRoleBinding, testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
			Eventually(func() error {
				return checkResourceAbsent("serviceaccount", "e2e-restricted-sa", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("RestrictedRoleDefinition CRD", func() {
		It("should create a Role within policy limits", func() {
			By("Applying RBACPolicy first")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedRoleDefinition")
			applyFixture("restrictedroledefinition.yaml")

			By("Verifying RestrictedRoleDefinition was created")
			Eventually(func() error {
				return checkResourceExists("restrictedroledefinition", "e2e-test-restricted-role", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying RestrictedRoleDefinition is policy compliant")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "PolicyCompliant")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying RestrictedRoleDefinition status shows Ready")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying Role was created in test namespace")
			Eventually(func() error {
				return checkResourceExists("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Verifying generated Role owner reference")
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "role", // #nosec G204
				"e2e-restricted-reader", "-n", testNamespace,
				"-o", "jsonpath={.metadata.ownerReferences[0].kind}/{.metadata.ownerReferences[0].name}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(strings.TrimSpace(string(output))).To(Equal("RestrictedRoleDefinition/e2e-test-restricted-role"))

			By("Verifying Role excludes restricted APIs (velero.io)")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "role", // #nosec G204
				"e2e-restricted-reader", "-n", testNamespace, "-o", "yaml")
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(ContainSubstring("velero.io"))
			Expect(string(output)).To(ContainSubstring("pods"))
			Expect(string(output)).To(ContainSubstring("get"))

			By("Verifying Role excludes restricted verbs")
			cmd = utils.CommandContext(context.Background(), "kubectl", "get", "role", // #nosec G204
				"e2e-restricted-reader", "-n", testNamespace,
				"-o", `jsonpath={range .rules[*].verbs[*]}{.}{"\n"}{end}`)
			output, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
			roleVerbs := strings.Fields(string(output))
			Expect(roleVerbs).NotTo(ContainElement("escalate"))
			Expect(roleVerbs).NotTo(ContainElement("impersonate"))
			Expect(roleVerbs).NotTo(ContainElement("bind"))
		})

		It("should clean up roles when RestrictedRoleDefinition is deleted", func() {
			By("Setting up RBACPolicy")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying RestrictedRoleDefinition")
			applyFixture("restrictedroledefinition.yaml")
			Eventually(func() error {
				return checkResourceExists("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Deleting RestrictedRoleDefinition")
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "restrictedroledefinition", // #nosec G204
				"e2e-test-restricted-role", "--timeout=60s")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By("Waiting for RestrictedRoleDefinition finalizer cleanup to finish")
			Eventually(func() error {
				return checkResourceAbsent("restrictedroledefinition", "e2e-test-restricted-role", "")
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Waiting for Role to be cleaned up")
			Eventually(func() error {
				return checkResourceAbsent("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})

		It("should deprovision roles when a compliant resource starts violating policy", func() {
			By("Applying RBACPolicy first")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Applying a compliant RestrictedRoleDefinition")
			applyFixture("restrictedroledefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() error {
				return checkResourceExists("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())

			By("Patching the RestrictedRoleDefinition to omit a forbidden verb restriction")
			patchJSON := `{"spec":{"restrictedVerbs":["impersonate","bind"]}}`
			cmd := utils.CommandContext(context.Background(), "kubectl", "patch", "restrictedroledefinition", // #nosec G204
				"e2e-test-restricted-role",
				"--type=merge",
				"-p", patchJSON)
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Patch failed: %s", string(output))

			By("Verifying policy conditions report the violation")
			Eventually(func() bool {
				return checkResourceConditionStatus(
					"restrictedroledefinition",
					"e2e-test-restricted-role",
					"PolicyCompliant",
					statusFalse,
				)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())
			Eventually(func() bool {
				return checkResourceConditionStatus("restrictedroledefinition", "e2e-test-restricted-role", "Ready", statusFalse)
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Verifying the previously generated Role was deprovisioned")
			Eventually(func() error {
				return checkResourceAbsent("role", "e2e-restricted-reader", testNamespace)
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("RBACPolicy Deletion Protection", func() {
		It("should prevent deletion of RBACPolicy with bound resources", func() {
			By("Creating RBACPolicy")
			applyFixture("rbacpolicy.yaml")
			Eventually(func() bool {
				return checkResourceCondition("rbacpolicy", "e2e-test-policy", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Creating RestrictedRoleDefinition that references the policy")
			applyFixture("restrictedroledefinition.yaml")
			Eventually(func() bool {
				return checkResourceCondition("restrictedroledefinition", "e2e-test-restricted-role", "Ready")
			}, reconcileTimeout, pollingInterval).Should(BeTrue())

			By("Attempting to delete RBACPolicy (should be blocked by webhook)")
			cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy", // #nosec G204
				"e2e-test-policy", "--timeout=10s")
			_, err := utils.Run(cmd)
			Expect(err).To(HaveOccurred(), "RBACPolicy deletion should be blocked when bound resources exist")

			By("Cleaning up: delete the RestrictedRoleDefinition first")
			cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "restrictedroledefinition", // #nosec G204
				"e2e-test-restricted-role", "--ignore-not-found=true", "--timeout=60s")
			_, _ = utils.Run(cmd)

			By("Now delete the RBACPolicy (should succeed)")
			Eventually(func() error {
				cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy", // #nosec G204
					"e2e-test-policy", "--timeout=30s")
				_, err := utils.Run(cmd)
				return err
			}, reconcileTimeout, pollingInterval).Should(Succeed())
		})
	})

	Context("New CRDs Installed", func() {
		It("should have RBACPolicy CRD installed", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "crd", // #nosec G204
				"rbacpolicies.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have RestrictedBindDefinition CRD installed", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "crd", // #nosec G204
				"restrictedbinddefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should have RestrictedRoleDefinition CRD installed", func() {
			cmd := utils.CommandContext(context.Background(), "kubectl", "get", "crd", // #nosec G204
				"restrictedroledefinitions.authorization.t-caas.telekom.com")
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

func checkResourceCondition(resourceType, name, conditionType string) bool {
	return checkResourceConditionStatus(resourceType, name, conditionType, statusTrue)
}

func checkResourceConditionStatus(resourceType, name, conditionType, expectedStatus string) bool {
	cmd := utils.CommandContext(context.Background(), "kubectl", "get", resourceType, name, // #nosec G204
		"-o", fmt.Sprintf("jsonpath={.status.conditions[?(@.type=='%s')].status}", conditionType))
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(output)) == expectedStatus
}

func checkResourceAbsent(resourceType, name, namespace string) error {
	if err := checkResourceExists(resourceType, name, namespace); err == nil {
		if namespace != "" {
			return fmt.Errorf("%s %s/%s still exists", resourceType, namespace, name)
		}
		return fmt.Errorf("%s %s still exists", resourceType, name)
	}
	return nil
}

func cleanupRestrictedCRDTestState() {
	// Delete restricted resources first (they reference policies)
	for _, resource := range []string{
		"restrictedbinddefinition",
		"restrictedroledefinition",
	} {
		cmd := utils.CommandContext(context.Background(), "kubectl", "delete", resource, // #nosec G204
			"-l", "app.kubernetes.io/component=e2e-test",
			"--ignore-not-found=true", "--wait=false", "--timeout=30s")
		_, _ = utils.Run(cmd)
		utils.RemoveFinalizersForAll(resource)
	}

	// Delete violating binding if it exists
	cmd := utils.CommandContext(context.Background(), "kubectl", "delete", "restrictedbinddefinition", // #nosec G204
		"e2e-violating-binding", "--ignore-not-found=true", "--wait=false")
	_, _ = utils.Run(cmd)

	// Wait for restricted resources to be cleaned up
	time.Sleep(2 * time.Second)

	// Then delete policies (now that nothing references them)
	cmd = utils.CommandContext(context.Background(), "kubectl", "delete", "rbacpolicy", // #nosec G204
		"-l", "app.kubernetes.io/component=e2e-test",
		"--ignore-not-found=true", "--wait=false", "--timeout=30s")
	_, _ = utils.Run(cmd)
	utils.RemoveFinalizersForAll("rbacpolicy")

	// Clean up managed RBAC resources
	managedByLabel := "app.kubernetes.io/managed-by=auth-operator"
	utils.CleanupResourcesByLabel("role", managedByLabel, testNamespace)
	utils.CleanupResourcesByLabel("rolebinding", managedByLabel, testNamespace)
	utils.CleanupResourcesByLabel("serviceaccount", managedByLabel, testNamespace)
}

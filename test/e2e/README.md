# End-to-End (E2E) Testing Guide

This guide provides comprehensive information about running, debugging, and understanding the auth-operator e2e test suite.

> **📚 Quick Links:**
> - [Quick Reference Card](QUICKREF.md) - Commands and troubleshooting at a glance
> - [Analysis Summary](SUMMARY.md) - Test suite assessment and recommendations
> - [Improvement Guide](IMPROVEMENTS.md) - Detailed code improvement recommendations

## Table of Contents

- [Overview](#overview)
- [Test Architecture](#test-architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Test Suites](#test-suites)
- [Environment Variables](#environment-variables)
- [Debug Options](#debug-options)
- [Cluster Isolation](#cluster-isolation)
- [Test Data & Fixtures](#test-data--fixtures)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)

---

## Overview

The auth-operator e2e tests validate the complete operator lifecycle across different installation methods (Helm, Kustomize, dev overlay) and scenarios (single-node, multi-node HA, complex configurations).

**Key Design Principles:**
- ✅ **Cluster Isolation**: Each test suite runs in its own Kind cluster
- ✅ **Install Method Coverage**: Tests validate Helm, Kustomize, and dev deployments
- ✅ **Comprehensive Artifacts**: Debug data collected on failures
- ✅ **Parallel Safe**: Tests can run concurrently in different clusters

---

## Test Architecture

```
test/e2e/
├── README.md                    # This file
├── e2e_suite_test.go           # Ginkgo test suite setup
├── e2e_test.go                 # Basic setup/prerequisite tests
├── crd_e2e_test.go             # CRD functionality (dev/kustomize)
├── helm_e2e_test.go            # Helm chart installation
├── dev_e2e_test.go             # Dev overlay deployment
├── complex_e2e_test.go         # Complex multi-CRD scenarios
├── integration_e2e_test.go     # Multi-CRD integration tests
├── golden_e2e_test.go          # Golden file comparison tests
├── ha_e2e_test.go              # HA and leader election
├── kustomize_e2e_test.go       # Kustomize overlay validation
├── fixtures/                    # Test manifests (dev/kustomize)
├── testdata/                    # Golden files and test data
├── kind-config-single.yaml     # Single-node cluster config
├── kind-config-multi.yaml      # Multi-node cluster config
└── output/                      # Generated test artifacts
```

### Test Suite Labels

Tests are organized using Ginkgo labels for selective execution:

| Label | Description | Cluster Type |
|-------|-------------|--------------|
| `setup` | Prerequisites check | Any |
| `api` | API version validation | Any |
| `debug` | Debug information collection | Any |
| `helm` | Helm installation tests | Dedicated (auth-operator-e2e-helm) |
| `dev` | Dev/kustomize deployment | Dedicated (auth-operator-e2e-dev) |
| `complex` | Complex multi-CRD scenarios | Dedicated (auth-operator-e2e-complex) |
| `integration` | Integration tests | Dedicated (auth-operator-e2e-integration) |
| `golden` | Golden file comparison | Dedicated (auth-operator-e2e-golden) |
| `ha` | High availability tests | Multi-node (auth-operator-e2e-ha-multi) |
| `leader-election` | Leader election tests | Multi-node (auth-operator-e2e-ha-multi) |
| `kustomize` | Kustomize validation (no cluster) | N/A |

---

## Prerequisites

Before running e2e tests, ensure you have:

- **Docker**: Running and accessible
- **Go**: 1.22 or later
- **kubectl**: Compatible with Kubernetes 1.28+
- **Kind**: v0.20.0 or later
- **Helm**: v3.12.0 or later
- **kustomize**: v5.0.0 or later (optional, can be installed via Make)

**Verify Prerequisites:**
```bash
make test-e2e-quick
```

---

## Quick Start

### Run All Tests (Recommended for CI)

```bash
# Run all test suites in isolated clusters
make test-e2e-full          # Base tests
make test-e2e-helm-full     # Helm tests
make test-e2e-complex       # Complex scenarios
make test-e2e-ha            # HA tests
make test-e2e-dev           # Dev deployment tests
make test-e2e-integration   # Integration tests
make test-e2e-golden        # Golden file tests
```

### Run Individual Test Suites

```bash
# Quick setup validation (no operator deployment)
make test-e2e-quick

# Run specific labeled tests
make test-e2e                    # Base CRD tests
make test-e2e-helm              # Helm installation
make test-e2e-dev               # Dev/kustomize
make test-e2e-complex           # Complex scenarios
```

### Run Against Existing Cluster

```bash
# Skip cluster creation/deletion
export SKIP_E2E_CLEANUP=true
export KIND_CLUSTER=my-existing-cluster
make test-e2e
```

### Debug Failed Tests

```bash
# Keep cluster alive after failure
export SKIP_E2E_CLEANUP=true
make test-e2e-full

# Collect debug info manually
make test-e2e-debug

# Inspect cluster
kubectl get all -A
kubectl get roledefinitions -A
```

---

## Test Suites

### 1. Setup & Prerequisites (`e2e_test.go`)
**Labels:** `setup`, `api`, `debug`  
**Cluster:** Reuses existing  
**Purpose:** Validates prerequisites and provides debug utilities

**Tests:**
- ✓ kubectl, kind, docker availability
- ✓ Kind cluster running
- ✓ CRDs installed
- ✓ Controller deployment
- ✓ API resources available

**Run:**
```bash
make test-e2e-quick
```

---

### 2. CRD Functionality (`crd_e2e_test.go`)
**Labels:** None (default suite)  
**Cluster:** `auth-operator-e2e` (dev/kustomize install)  
**Purpose:** Core CRD functionality tests

**Tests:**
- ✓ RoleDefinition creates ClusterRole/Role
- ✓ BindDefinition creates bindings
- ✓ WebhookAuthorizer configures webhooks
- ✓ Status conditions updated
- ✓ Cleanup and finalizers

**Run:**
```bash
make test-e2e-full
```

---

### 3. Helm Chart Tests (`helm_e2e_test.go`)
**Labels:** `helm`  
**Cluster:** `auth-operator-e2e-helm` (Helm install)  
**Purpose:** Validate Helm chart installation and upgrade

**Tests:**
- ✓ Chart lints without errors
- ✓ Chart templates successfully
- ✓ Installation succeeds
- ✓ All pods running
- ✓ CRD functionality via Helm install
- ✓ Helm upgrade scenarios

**Run:**
```bash
make test-e2e-helm-full
```

---

### 4. Dev Deployment (`dev_e2e_test.go`)
**Labels:** `dev`  
**Cluster:** `auth-operator-e2e-dev` (kustomize/make deploy)  
**Purpose:** Validate standard Kubernetes manifests

**Tests:**
- ✓ Make install/deploy workflow
- ✓ CRD functionality
- ✓ Webhook configuration
- ✓ Cleanup procedures

**Run:**
```bash
make test-e2e-dev
```

---

### 5. Complex Scenarios (`complex_e2e_test.go`)
**Labels:** `complex`  
**Cluster:** `auth-operator-e2e-complex` (Helm install)  
**Purpose:** Test complex multi-CRD interactions

**Tests:**
- ✓ RoleDefinition with all restrictions (APIs, resources, verbs)
- ✓ BindDefinition with multiple roles and namespaces
- ✓ Complex namespace selectors
- ✓ WebhookAuthorizer with all features

**Run:**
```bash
make test-e2e-complex
```

---

### 6. Integration Tests (`integration_e2e_test.go`)
**Labels:** `integration`  
**Cluster:** `auth-operator-e2e-integration` (Helm install)  
**Purpose:** Multi-CRD integration scenarios

**Tests:**
- ✓ Multiple RoleDefinitions with different scopes
- ✓ Cross-namespace bindings
- ✓ Complex role aggregation
- ✓ Webhook authorization flows

**Run:**
```bash
make test-e2e-integration
```

---

### 7. Golden File Tests (`golden_e2e_test.go`)
**Labels:** `golden`  
**Cluster:** `auth-operator-e2e-golden` (Helm install)  
**Purpose:** Validate generated RBAC against expected output

**Tests:**
- ✓ RoleDefinition → ClusterRole structure
- ✓ BindDefinition → ClusterRoleBinding structure
- ✓ Restriction enforcement (APIs, resources, verbs)
- ✓ Namespace selector logic

**Test Data:** `test/e2e/testdata/golden/`

**Run:**
```bash
make test-e2e-golden
```

---

### 8. HA & Leader Election (`ha_e2e_test.go`)
**Labels:** `ha`, `leader-election`  
**Cluster:** `auth-operator-e2e-ha-multi` (multi-node)  
**Purpose:** High availability and leader election

**Tests:**
- ✓ Multiple controller replicas
- ✓ Leader election lease
- ✓ Leader failover
- ✓ Webhook load distribution
- ✓ PodDisruptionBudgets

**Run:**
```bash
make test-e2e-ha
```

---

### 9. Kustomize Validation (`kustomize_e2e_test.go`)
**Labels:** `kustomize`  
**Cluster:** None (build-only tests)  
**Purpose:** Validate kustomize overlays build correctly

**Tests:**
- ✓ Default overlay builds
- ✓ CRD overlay builds
- ✓ RBAC overlay builds
- ✓ Webhook overlay builds
- ✓ Manifest consistency

**Run:**
```bash
go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="kustomize"
```

---

## Environment Variables

### Cluster Configuration

```bash
# Kind cluster name (default: auth-operator-e2e)
export KIND_CLUSTER=my-cluster-name

# Skip cluster creation/deletion (default: false)
export SKIP_CLUSTER_SETUP=true

# Skip cleanup after tests (default: false)
export SKIP_E2E_CLEANUP=true

# Force cluster recreation (default: true)
export E2E_RECREATE_CLUSTER=false

# Tear down operator after tests (default: false)
export E2E_TEARDOWN=true
```

### Image Configuration

```bash
# Operator image to test (default: auth-operator:e2e-test)
export IMG=my-registry/auth-operator:v1.2.3

# Override default e2e image tag
export E2E_IMG=auth-operator:custom-tag
```

### Debug Configuration

```bash
# Debug verbosity level (0-3, default: 1)
# 0 = Errors only
# 1 = Info (default)
# 2 = Debug
# 3 = Trace
export E2E_DEBUG_LEVEL=2

# Disable debug collection on failure (default: collect)
export E2E_DEBUG_ON_FAILURE=false

# Force artifact collection for all specs (default: failures only)
export E2E_COLLECT_ALL_SPECS=true

# Custom output directory for artifacts
export E2E_OUTPUT_DIR=/tmp/e2e-artifacts

# Run identifier for artifact organization (auto-generated if not set)
export RUN_ID=$(date +%s)
```

### Test Execution

```bash
# Run specific test by name
go test -tags e2e ./test/e2e/ -v -ginkgo.v \
  -ginkgo.focus="should create ClusterRole from RoleDefinition"

# Run tests with specific labels
go test -tags e2e ./test/e2e/ -v -ginkgo.v \
  -ginkgo.label-filter="helm && !complex"

# Parallel execution (for independent suites in separate terminals)
make test-e2e-helm & make test-e2e-complex & wait
```

---

## Debug Options

### Debug Levels

| Level | Name | Output | Use Case |
|-------|------|--------|----------|
| 0 | ERROR | Errors only | CI with minimal logs |
| 1 | INFO | Progress + errors | Default, normal runs |
| 2 | DEBUG | Detailed operations | Debugging test logic |
| 3 | TRACE | All operations + API calls | Deep debugging |

**Example:**
```bash
export E2E_DEBUG_LEVEL=3
make test-e2e-full
```

### Artifact Collection

When tests fail (or with `E2E_COLLECT_ALL_SPECS=true`), artifacts are saved to:

```
test/e2e/output/<RUN_ID>/<suite-name>/specs/<status>/<timestamp-test-name>/
├── summary.md                   # Test summary
├── cluster-state.yaml           # All cluster resources
├── controller-logs.txt          # Controller logs
├── webhook-logs.txt             # Webhook logs
├── events.yaml                  # Cluster events
├── describe-pods.txt            # Pod descriptions
├── crds-roledefinitions.yaml   # All RoleDefinitions
├── crds-binddefinitions.yaml   # All BindDefinitions
└── crds-webhookauthorizers.yaml # All WebhookAuthorizers
```

**Manually collect debug info:**
```bash
make test-e2e-debug
# or
kubectl port-forward -n auth-operator-system <pod> 8080:8080
# Access metrics at localhost:8080/metrics
```

### Interactive Debugging

```bash
# 1. Run test with cleanup disabled
export SKIP_E2E_CLEANUP=true
make test-e2e-helm

# 2. Inspect failed state
kubectl get all -n auth-operator-helm
kubectl logs -n auth-operator-helm -l control-plane=controller-manager
kubectl describe roledefinition <name>

# 3. Manually apply test resources
kubectl apply -f test/e2e/fixtures/

# 4. Watch reconciliation
kubectl get roledefinitions -w

# 5. Cleanup when done
make kind-delete
```

---

## Cluster Isolation

Each test suite runs in its own Kind cluster to ensure complete isolation:

| Test Suite | Cluster Name | Install Method | Nodes |
|------------|--------------|----------------|-------|
| Base/CRD | `auth-operator-e2e` | Dev/Kustomize | 1 |
| Helm | `auth-operator-e2e-helm` | Helm | 1 |
| Dev | `auth-operator-e2e-dev` | Kustomize | 1 |
| Complex | `auth-operator-e2e-complex` | Helm | 1 |
| Integration | `auth-operator-e2e-integration` | Helm | 1 |
| Golden | `auth-operator-e2e-golden` | Helm | 1 |
| HA | `auth-operator-e2e-ha-multi` | Helm (HA) | 3 |

**Why Isolation Matters:**
- ✅ Prevents test interference
- ✅ Validates different install methods
- ✅ Allows parallel execution
- ✅ Clean state for each suite
- ✅ Avoids webhook/finalizer conflicts

**Cluster Management:**
```bash
# List all e2e clusters
kind get clusters | grep auth-operator

# Delete all e2e clusters
make kind-delete-all

# Delete specific cluster
kind delete cluster --name auth-operator-e2e-helm
```

---

## Test Data & Fixtures

### Fixtures (`test/e2e/fixtures/`)

Standard Kubernetes manifests for testing basic CRD functionality:
- `roledefinition_*.yaml` - Example RoleDefinitions
- `binddefinition_*.yaml` - Example BindDefinitions
- `webhookauthorizer_*.yaml` - Example WebhookAuthorizers

**Used by:** `crd_e2e_test.go`, `dev_e2e_test.go`

### Testdata (`test/e2e/testdata/`)

```
testdata/
├── golden/                         # Golden file tests
│   ├── README.md                   # Golden test format docs
│   ├── roledefinition-*.yaml      # Input RoleDefinitions
│   └── expected-*.yaml            # Expected generated resources
├── complex/                        # Complex scenario data
│   ├── namespace-*.yaml           # Test namespaces
│   ├── roledefinition-*.yaml      # Complex RoleDefinitions
│   └── binddefinition-*.yaml      # Complex BindDefinitions
└── integration/                    # Integration test data
    └── *.yaml                      # Multi-CRD scenarios
```

### Creating Test Data

**For Golden Tests:**
1. Create input RoleDefinition in `testdata/golden/`
2. Apply to cluster and capture generated output
3. Clean/sanitize output (remove timestamps, UIDs, etc.)
4. Save as `expected-*.yaml`
5. Add test case in `golden_e2e_test.go`

**For Complex Tests:**
1. Create scenario manifests in `testdata/complex/`
2. Add BeforeAll setup in `complex_e2e_test.go`
3. Add test assertions
4. Add cleanup in AfterAll

---

## Troubleshooting

### Common Issues

#### 1. "Cannot connect to kind cluster"

**Symptoms:**
```
Error: Cannot connect to API server
```

**Solutions:**
```bash
# Check Docker is running
docker ps

# Check cluster exists
kind get clusters

# Recreate cluster
make kind-delete
make kind-create

# Check cluster health
kubectl cluster-info
kubectl get nodes
```

---

#### 2. "Image not found in cluster"

**Symptoms:**
```
ErrImagePull or ImagePullBackOff
```

**Solutions:**
```bash
# Rebuild and reload image
make docker-build IMG=auth-operator:e2e-test
make kind-load-image

# Verify image in cluster
docker exec -it auth-operator-e2e-control-plane crictl images | grep auth-operator

# Check pod events
kubectl describe pod -n auth-operator-system -l control-plane=controller-manager
```

---

#### 3. "CRDs not found"

**Symptoms:**
```
Error: the server doesn't have a resource type "roledefinitions"
```

**Solutions:**
```bash
# Install CRDs
make install

# Verify CRDs installed
kubectl get crds | grep authorization.t-caas.telekom.com

# Reinstall if needed
make uninstall
make install
```

---

#### 4. "Webhook connection refused"

**Symptoms:**
```
Error: Internal error occurred: failed calling webhook
```

**Solutions:**
```bash
# Check webhook pods
kubectl get pods -n auth-operator-system -l control-plane=webhook-server

# Check webhook service endpoints
kubectl get endpoints -n auth-operator-system

# Check webhook configuration
kubectl get validatingwebhookconfigurations
kubectl get mutatingwebhookconfigurations

# Restart webhook pods
kubectl delete pod -n auth-operator-system -l control-plane=webhook-server

# Check cert rotation logs
kubectl logs -n auth-operator-system -l control-plane=webhook-server | grep cert
```

---

#### 5. "Test timeout"

**Symptoms:**
```
Timed out after 300s
```

**Solutions:**
```bash
# Increase timeout
go test -tags e2e ./test/e2e/ -timeout 60m

# Check controller logs for errors
kubectl logs -n auth-operator-system -l control-plane=controller-manager --tail=100

# Check for stuck reconciliations
kubectl get roledefinitions -o json | jq '.items[] | {name: .metadata.name, conditions: .status.conditions}'

# Force recreate stuck resources
kubectl delete roledefinition <name> --grace-period=0 --force
```

---

#### 6. "Finalizer blocking deletion"

**Symptoms:**
```
namespace "xxx" is stuck in Terminating
```

**Solutions:**
```bash
# Remove finalizers from all RoleDefinitions
kubectl get roledefinitions -A -o json | \
  jq '.items[] | .metadata.finalizers = []' | \
  kubectl replace -f -

# Manual cleanup script (included in utils)
make test-e2e-cleanup

# Force delete namespace (last resort)
kubectl patch namespace <ns> -p '{"metadata":{"finalizers":[]}}' --type=merge
kubectl delete namespace <ns> --grace-period=0 --force
```

---

### Debug Workflow

```bash
# 1. Enable verbose debugging
export E2E_DEBUG_LEVEL=3
export E2E_DEBUG_ON_FAILURE=true
export E2E_COLLECT_ALL_SPECS=true

# 2. Keep cluster alive on failure
export SKIP_E2E_CLEANUP=true

# 3. Run failing test
make test-e2e-helm

# 4. Collect debug info
make test-e2e-debug

# 5. Inspect artifacts
ls -la test/e2e/output/<RUN_ID>/

# 6. Interactive debugging
kubectl get all -A
kubectl logs -n <namespace> -l control-plane=controller-manager
kubectl describe roledefinition <name>

# 7. Fix and retest
make test-e2e-helm

# 8. Cleanup when done
make kind-delete
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e-base:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'
      
      - name: Run base e2e tests
        run: make test-e2e-full
        env:
          E2E_DEBUG_LEVEL: 1
          E2E_RECREATE_CLUSTER: true
      
      - name: Upload artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: e2e-artifacts
          path: test/e2e/output/

  e2e-helm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - name: Run Helm e2e tests
        run: make test-e2e-helm-full

  e2e-ha:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - name: Run HA e2e tests
        run: make test-e2e-ha
```

### GitLab CI Example

```yaml
stages:
  - test

variables:
  E2E_DEBUG_LEVEL: "1"
  E2E_RECREATE_CLUSTER: "true"

e2e:base:
  stage: test
  image: golang:1.22
  services:
    - docker:dind
  script:
    - make test-e2e-full
  artifacts:
    when: on_failure
    paths:
      - test/e2e/output/
    expire_in: 7 days

e2e:helm:
  stage: test
  image: golang:1.22
  services:
    - docker:dind
  script:
    - make test-e2e-helm-full

e2e:ha:
  stage: test
  image: golang:1.22
  services:
    - docker:dind
  script:
    - make test-e2e-ha
```

---

## Best Practices

### When Writing New Tests

1. **Use appropriate test suite:**
   - Basic CRD tests → `crd_e2e_test.go`
   - Helm-specific → `helm_e2e_test.go`
   - Complex scenarios → `complex_e2e_test.go`
   - Golden comparisons → `golden_e2e_test.go`

2. **Label tests correctly:**
   ```go
   var _ = Describe("My Test", Label("helm", "smoke"), func() {
   ```

3. **Use dedicated cluster:**
   - Ensure `setSuiteOutputDir()` called in BeforeAll
   - Use unique namespace for test resources
   - Clean up in AfterAll

4. **Collect artifacts:**
   ```go
   AfterEach(func() {
       if CurrentSpecReport().Failed() {
           utils.CollectAndSaveAllDebugInfo("My Test Context")
       }
   })
   ```

5. **Use utilities:**
   ```go
   utils.WaitForDeploymentAvailable("label", "namespace", timeout)
   utils.WaitForPodsReady("label", "namespace", timeout)
   utils.CollectOperatorLogs("namespace", 100)
   ```

6. **Document test data:**
   - Add README.md in testdata subdirectories
   - Comment complex YAML scenarios
   - Explain expected behavior

---

## Performance Tips

### Faster Local Development

```bash
# Skip cluster recreation between runs
export E2E_RECREATE_CLUSTER=false
export SKIP_E2E_CLEANUP=true

# Reuse built image
export IMG=auth-operator:e2e-test

# Run specific test
go test -tags e2e ./test/e2e/ -v -ginkgo.focus="my specific test"

# Skip slow tests
go test -tags e2e ./test/e2e/ -v -ginkgo.skip="slow|integration"
```

### Parallel Execution

```bash
# Run multiple suites in parallel (in separate terminals)
# Each uses its own cluster
make test-e2e-helm &
make test-e2e-complex &
make test-e2e-integration &
wait

# Or use GNU parallel
parallel ::: \
  "make test-e2e-helm" \
  "make test-e2e-complex" \
  "make test-e2e-integration"
```

---

## Getting Help

- **Issues:** Check [Troubleshooting](#troubleshooting) section
- **Questions:** Open a GitLab issue
- **Debug:** Use `E2E_DEBUG_LEVEL=3` and check artifacts
- **CI Failures:** Download artifacts from CI pipeline

**Quick Commands:**
```bash
# Health check
make test-e2e-quick

# Full test run
make test-e2e-full test-e2e-helm-full test-e2e-complex

# Debug failed test
export SKIP_E2E_CLEANUP=true
export E2E_DEBUG_LEVEL=3
make test-e2e-<suite>

# Cleanup everything
make kind-delete-all
make test-e2e-cleanup
```

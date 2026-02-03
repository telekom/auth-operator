# E2E Test Quick Reference Card

> **One page, all the commands you need.**

---

## 🚀 Running Tests

```bash
# ═══════════════════════════════════════════════════════════════════════════════
# QUICK START - Choose one based on what you're testing
# ═══════════════════════════════════════════════════════════════════════════════

make test-e2e-quick          # Health check only (30s)
make test-e2e-full           # Base CRD tests - kustomize install
make test-e2e-helm-full      # Helm chart tests - helm install  
make test-e2e-dev            # Dev overlay tests - make deploy
make test-e2e-complex        # Multi-CRD scenarios
make test-e2e-ha             # HA & leader election (multi-node)
make test-e2e-integration    # Cross-CRD integration
make test-e2e-golden         # Golden file validation

# ═══════════════════════════════════════════════════════════════════════════════
# DEBUG A FAILING TEST
# ═══════════════════════════════════════════════════════════════════════════════

export SKIP_E2E_CLEANUP=true     # Keep cluster alive
export E2E_DEBUG_LEVEL=3         # Maximum verbosity
make test-e2e-helm               # Run failing test
# → inspect: kubectl get all -A
# → logs:    kubectl logs -n auth-operator-helm -l control-plane=controller-manager
```

---

## 🎯 Cluster Isolation Matrix

| Test Suite | Cluster Name | Install Method | Nodes |
|------------|--------------|----------------|-------|
| **base** | `auth-operator-e2e` | Kustomize | 1 |
| **helm** | `auth-operator-e2e-helm` | Helm | 1 |
| **dev** | `auth-operator-e2e-dev` | Kustomize | 1 |
| **complex** | `auth-operator-e2e-complex` | Helm | 1 |
| **integration** | `auth-operator-e2e-integration` | Helm | 1 |
| **golden** | `auth-operator-e2e-golden` | Helm | 1 |
| **ha** | `auth-operator-e2e-ha-multi` | Helm (HA) | 3 |

> ⚠️ **Each suite MUST run in its own cluster** to avoid cross-contamination

---

## 🔧 Environment Variables

```bash
# ─────────────────────────────────────────────────────────────────────────────
# CLUSTER CONTROL
# ─────────────────────────────────────────────────────────────────────────────
SKIP_E2E_CLEANUP=true       # Keep cluster after tests (debug mode)
E2E_RECREATE_CLUSTER=false  # Reuse existing cluster (faster iteration)
KIND_CLUSTER=my-cluster     # Override cluster name

# ─────────────────────────────────────────────────────────────────────────────
# DEBUG SETTINGS  
# ─────────────────────────────────────────────────────────────────────────────
E2E_DEBUG_LEVEL=2           # 0=error 1=info 2=debug 3=trace
E2E_DEBUG_ON_FAILURE=true   # Auto-collect on failure (default: true)
E2E_COLLECT_ALL_SPECS=true  # Collect for ALL tests, not just failures
E2E_OUTPUT_DIR=/tmp/e2e     # Custom artifact output directory

# ─────────────────────────────────────────────────────────────────────────────
# IMAGE SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
IMG=myregistry/auth-operator:v1.2.3   # Custom operator image
```

---

## 📊 Debug Levels Explained

| Level | Name | What You Get | When to Use |
|-------|------|--------------|-------------|
| `0` | ERROR | Failures only | CI pipelines, minimal noise |
| `1` | INFO | Progress + failures | **Default**, normal runs |
| `2` | DEBUG | Detailed operations | Debugging test logic |
| `3` | TRACE | Everything + API calls | Deep investigation |

---

## 🏷️ Test Labels

```bash
# Run specific test types
go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="LABEL"

# Combine labels
-ginkgo.label-filter="helm && !complex"    # Helm but not complex
-ginkgo.label-filter="ha || leader-election" # HA or leader election
```

| Label | Purpose | Requires Cluster? |
|-------|---------|-------------------|
| `setup` | Prerequisites check | Yes |
| `helm` | Helm chart installation | Yes |
| `dev` | Dev/kustomize deployment | Yes |
| `complex` | Multi-CRD combinations | Yes |
| `integration` | Cross-CRD scenarios | Yes |
| `golden` | Expected output validation | Yes |
| `ha` | High availability | Yes (multi-node) |
| `leader-election` | Leader election | Yes (multi-node) |
| `kustomize` | Overlay build validation | **No** (build only) |

---

## 🐛 Troubleshooting Cheat Sheet

### ❌ Image not found / ImagePullBackOff
```bash
make docker-build IMG=auth-operator:e2e-test
make kind-load-image
docker exec -it auth-operator-e2e-control-plane crictl images | grep auth
```

### ❌ CRDs not found
```bash
make install
kubectl get crds | grep authorization.t-caas.telekom.com
```

### ❌ Webhook connection refused
```bash
kubectl get pods -A -l control-plane=webhook-server
kubectl get endpoints -A | grep webhook
kubectl logs -n auth-operator-system -l control-plane=webhook-server --tail=50
```

### ❌ Test timeout / reconcile stuck
```bash
kubectl logs -n auth-operator-system -l control-plane=controller-manager --tail=100
kubectl get roledefinitions -A -o wide
kubectl get events -A --sort-by=.lastTimestamp | tail -20
```

### ❌ Namespace stuck terminating (finalizers)
```bash
# Remove finalizers from all CRs
kubectl get roledefinitions -A -o json | \
  jq '.items[] | .metadata.finalizers = []' | \
  kubectl replace -f -

# Or use cleanup utility
make test-e2e-cleanup
```

### ❌ Cluster not responding
```bash
kind get clusters
kubectl cluster-info
make kind-delete KIND_CLUSTER_NAME=auth-operator-e2e
make kind-create KIND_CLUSTER_NAME=auth-operator-e2e
```

---

## 📁 Artifact Locations

```
test/e2e/output/<RUN_ID>/<suite>/
├── specs/
│   ├── passed/
│   │   └── <timestamp>-<test-name>/
│   │       └── summary.md
│   └── failed/
│       └── <timestamp>-<test-name>/
│           ├── summary.md
│           ├── debug-report.json     # ← NEW: Structured JSON report
│           ├── cluster-state.yaml
│           ├── controller-logs.txt
│           ├── webhook-logs.txt
│           └── events.yaml
```

---

## 💡 Pro Tips

```bash
# Parallel execution (separate terminals)
make test-e2e-helm &
make test-e2e-complex &
make test-e2e-integration &
wait

# Run single test by name
go test -tags e2e ./test/e2e/ -v -ginkgo.focus="should create ClusterRole"

# Skip slow tests during development
go test -tags e2e ./test/e2e/ -v -ginkgo.skip="ha|integration|golden"

# List all kind clusters
kind get clusters | grep auth-operator

# Delete ALL e2e clusters
make kind-delete-all
```

## Cleanup

```bash
# Delete all e2e clusters
make kind-delete-all

# Full cleanup
make test-e2e-cleanup
```

## Artifacts

Collected on failure at:
```
test/e2e/output/<RUN_ID>/<suite>/specs/<status>/<test-name>/
├── summary.md
├── cluster-state.yaml
├── controller-logs.txt
├── webhook-logs.txt
├── events.yaml
└── crds-*.yaml
```

## Useful Commands

```bash
# List clusters
kind get clusters

# Get cluster logs
kubectl logs -n <ns> -l control-plane=controller-manager --tail=100

# Watch reconciliation
kubectl get roledefinitions -w

# Debug specific test
go test -tags e2e ./test/e2e/ -v -ginkgo.focus="should create ClusterRole"

# Check webhook config
kubectl get validatingwebhookconfigurations
kubectl describe validatingwebhookconfigurations auth-operator-validating-webhook

# Force delete stuck namespace
kubectl patch namespace <ns> -p '{"metadata":{"finalizers":[]}}' --type=merge
```

## New Utilities (if implemented)

```go
// Cleanup
CleanupForHelmTests(namespace, release)
CleanupForDevTests(namespace, clusterRoles)

// Progress
progress := NewTestProgress("Setup", 5)
done := progress.Step("Building image")
buildImage()
done()
progress.Complete()

// Simple progress
sp := NewSimpleProgress("Waiting for pods")
waitForPods()
sp.Done()
```

## Documentation

- **Full Guide**: [test/e2e/README.md](README.md)
- **Improvements**: [test/e2e/IMPROVEMENTS.md](IMPROVEMENTS.md)
- **Summary**: [test/e2e/SUMMARY.md](SUMMARY.md)
- **Main README**: [README.md](../../README.md)

## Quick Test Workflow

```bash
# 1. Run quick check
make test-e2e-quick

# 2. Run full suite
make test-e2e-full

# 3. On failure, debug
export SKIP_E2E_CLEANUP=true
export E2E_DEBUG_LEVEL=3
make test-e2e-full

# 4. Inspect
kubectl get all -A
ls -la test/e2e/output/

# 5. Fix and retest
make test-e2e-full

# 6. Cleanup
make kind-delete-all
```

## CI/CD Example

```yaml
e2e-tests:
  script:
    - make test-e2e-full
    - make test-e2e-helm-full
  artifacts:
    when: on_failure
    paths:
      - test/e2e/output/
```

---

**Need help?** Check the [Full Documentation](README.md) or open an issue.

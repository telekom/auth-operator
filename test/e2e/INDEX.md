# Auth Operator E2E Test Documentation Index

Welcome to the auth-operator e2e test documentation!

---

## 🏗️ Test Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              E2E TEST ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                         CLUSTER ISOLATION LAYER                                  │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐ │
│  │ auth-operator │  │ auth-operator │  │ auth-operator │  │ auth-operator-e2e-ha │ │
│  │   -e2e-helm   │  │   -e2e-dev    │  │  -e2e-complex │  │       -multi         │ │
│  │               │  │               │  │               │  │    (3 nodes)         │ │
│  │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐         │ │
│  │  │  Helm   │  │  │  │Kustomize│  │  │  │  Helm   │  │  │  │  Helm   │         │ │
│  │  │ Install │  │  │  │ Deploy  │  │  │  │ Install │  │  │  │  HA     │         │ │
│  │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘         │ │
│  └───────────────┘  └───────────────┘  └───────────────┘  └───────────────────────┘ │
│                                                                                      │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐ │
│  │                            SHARED UTILITIES                                      │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │ │
│  │  │cleanup.go│  │progress. │  │debug_    │  │suite_    │  │leak_detector.go  │   │ │
│  │  │          │  │   go     │  │report.go │  │config.go │  │                  │   │ │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘   │ │
│  └─────────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Documentation Files

| Document | Purpose | When to Use |
|----------|---------|-------------|
| **[README.md](README.md)** | Complete guide | First time setup, comprehensive reference |
| **[QUICKREF.md](QUICKREF.md)** | Cheat sheet | Quick commands, troubleshooting |

---

## 🗂️ File Organization

```
test/e2e/
│
├── 📄 Documentation
│   ├── README.md           # Complete testing guide
│   ├── QUICKREF.md         # One-page cheat sheet
│   ├── SUMMARY.md          # Test suite assessment
│   ├── IMPROVEMENTS.md     # Enhancement recommendations
│   └── INDEX.md            # This file
│
├── 🧪 Test Suites (one cluster each)
│   ├── e2e_suite_test.go   # Ginkgo suite setup + BeforeSuite/AfterSuite
│   ├── e2e_test.go         # [setup] Prerequisites & debug utilities
│   ├── helm_e2e_test.go    # [helm] Helm chart installation tests
│   ├── dev_e2e_test.go     # [dev] Kustomize/make deploy tests
│   ├── crd_e2e_test.go     # [default] Core CRD functionality
│   ├── complex_e2e_test.go # [complex] Multi-CRD combinations
│   ├── integration_e2e_test.go # [integration] Cross-CRD scenarios
│   ├── golden_e2e_test.go  # [golden] Expected output validation
│   ├── ha_e2e_test.go      # [ha] High availability tests
│   └── kustomize_e2e_test.go # [kustomize] Build-only validation
│
├── 🔧 Utilities
│   ├── cleanup.go          # Centralized cleanup functions
│   ├── progress.go         # Test progress tracking
│   ├── debug_report.go     # Structured debug reports (JSON)
│   ├── suite_config.go     # Test suite configuration
│   └── leak_detector.go    # Resource leak detection
│
├── 📦 Test Data
│   ├── fixtures/           # Basic test manifests
│   ├── testdata/
│   │   ├── golden/         # Expected output files
│   │   ├── complex/        # Complex scenario data
│   │   └── integration/    # Integration test data
│   └── test/               # Additional test helpers
│
├── ⚙️ Configuration
│   ├── kind-config-single.yaml  # Single-node cluster
│   └── kind-config-multi.yaml   # Multi-node cluster (HA)
│
└── 📂 Output (generated)
    └── output/<RUN_ID>/    # Test artifacts
```

---

## 🏷️ Test Labels → Cluster Mapping

Each label corresponds to a dedicated Kind cluster:

| Label | Cluster Name | Install Method | Purpose |
|-------|--------------|----------------|---------|
| `setup` | `auth-operator-e2e` | Dev | Prerequisites |
| `helm` | `auth-operator-e2e-helm` | Helm | Chart validation |
| `dev` | `auth-operator-e2e-dev` | Kustomize | Manifest validation |
| `complex` | `auth-operator-e2e-complex` | Helm | Multi-CRD scenarios |
| `integration` | `auth-operator-e2e-integration` | Helm | Cross-CRD tests |
| `golden` | `auth-operator-e2e-golden` | Helm | Output comparison |
| `ha` | `auth-operator-e2e-ha-multi` | Helm (HA) | High availability |
| `kustomize` | *None* | *Build only* | Overlay validation |

---

## 🚀 New Utilities (Optional Enhancements)

### [cleanup.go](cleanup.go)
**Centralized cleanup utilities**
- Reduces code duplication
- Provides consistent cleanup across tests
- Convenient wrapper functions

**Usage:**
```go
CleanupForHelmTests(namespace, release)
CleanupForDevTests(namespace, clusterRoles)
```

---

### [progress.go](progress.go)
**Test progress tracking**
- Step-by-step progress indicators
- Time estimates
- Slowest step identification

**Usage:**
```go
progress := NewTestProgress("Setup", 5)
done := progress.Step("Building image")
buildImage()
done()
progress.Complete()
```

---

### [debug_report.go](debug_report.go)
**Structured JSON debug reports**
- Concise summary output
- Machine-readable JSON
- Resource counts and error aggregation

**Usage:**
```go
report := GenerateDebugReport(CurrentSpecReport(), "helm")
PrintConciseSummary(report)
SaveDebugReport(report, outputDir)
```

---

### [suite_config.go](suite_config.go)
**Test suite configuration**
- Cluster isolation enforcement
- Install method mapping
- Configuration validation

**Usage:**
```go
config, _ := GetSuiteConfig("helm")
ValidateClusterIsolation(config)
PrintSuiteConfig(config)
```

---

## 📁 Test Files
- `helm_e2e_test.go` - Helm chart tests
- `dev_e2e_test.go` - Dev/kustomize deployment
- `complex_e2e_test.go` - Complex scenarios
- `integration_e2e_test.go` - Integration tests
- `golden_e2e_test.go` - Golden file comparison
- `ha_e2e_test.go` - HA and leader election
- `kustomize_e2e_test.go` - Kustomize validation

### Test Data
- `fixtures/` - Basic test manifests
- `testdata/` - Golden files and complex scenarios
- `kind-config-*.yaml` - Kind cluster configurations

---

## 🎯 Getting Started

### For First-Time Users
1. Read [README.md](README.md) sections:
   - Prerequisites
   - Quick Start
   - Test Suites
2. Run `make test-e2e-quick` to verify setup
3. Run `make test-e2e-full` for full test
4. Keep [QUICKREF.md](QUICKREF.md) handy

### For Test Developers
1. Read [README.md](README.md) sections:
   - Test Architecture
   - Test Data & Fixtures
   - Best Practices
2. Review [helm_example_refactored_test.go](helm_example_refactored_test.go)
3. Check [IMPROVEMENTS.md](IMPROVEMENTS.md) for patterns

### For Troubleshooting
1. Check [QUICKREF.md](QUICKREF.md) "Common Issues"
2. Read [README.md](README.md) "Troubleshooting" section
3. Set `E2E_DEBUG_LEVEL=3` and collect artifacts

### For CI/CD Integration
1. Read [README.md](README.md) "CI/CD Integration" section
2. Use examples as templates
3. Ensure artifact collection on failure

---

## 🔍 Quick Command Reference

```bash
# Health check
make test-e2e-quick

# Run specific suite
make test-e2e-helm-full

# Debug mode
export E2E_DEBUG_LEVEL=3
export SKIP_E2E_CLEANUP=true
make test-e2e-helm

# Cleanup
make kind-delete-all
```

See [QUICKREF.md](QUICKREF.md) for complete command reference.

---

## 📊 Test Suite Quality

**Overall Score: 8/10** ✅

**Strengths:**
- ✅ Complete cluster isolation
- ✅ Comprehensive test coverage
- ✅ Good debug capabilities
- ✅ Well-organized test structure

**Improvements Made:**
- ✅ Comprehensive documentation
- ✅ Cleanup utilities created
- ✅ Progress tracking utilities
- ✅ Example refactored test

See [SUMMARY.md](SUMMARY.md) for detailed analysis.

---

## 🛠️ Recommended Improvements

### High Priority ✅ DONE
1. ✅ Create comprehensive documentation (this guide)
2. ✅ Create cleanup utilities
3. ✅ Create progress tracking utilities

### Medium Priority ⏳ OPTIONAL
1. Refactor existing tests to use new utilities
2. Add structured logging to debug output
3. Integrate progress tracking in long-running tests

### Low Priority 💡 FUTURE
1. Add resource leak detection
2. Collect performance metrics
3. Automated golden file generation

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for implementation details.

---

## 📞 Getting Help

### Documentation
- **Comprehensive**: [README.md](README.md)
- **Quick**: [QUICKREF.md](QUICKREF.md)
- **Analysis**: [SUMMARY.md](SUMMARY.md)
- **Improvements**: [IMPROVEMENTS.md](IMPROVEMENTS.md)

### Debugging
1. Enable debug mode: `export E2E_DEBUG_LEVEL=3`
2. Keep cluster: `export SKIP_E2E_CLEANUP=true`
3. Check artifacts: `test/e2e/output/<RUN_ID>/`
4. Review [Troubleshooting](README.md#troubleshooting)

### Issues
- Check [Common Issues](README.md#troubleshooting)
- Review [QUICKREF.md](QUICKREF.md)
- Open GitLab issue with debug artifacts

---

## 📈 Test Execution Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Prerequisites Check (make test-e2e-quick)               │
│    ✓ Docker, kubectl, kind, helm                           │
│    ✓ Kind cluster exists and is accessible                 │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Setup Phase (BeforeAll)                                 │
│    • Create dedicated Kind cluster                          │
│    • Build and load operator image                          │
│    • Deploy operator (Helm/Kustomize/Dev)                   │
│    • Wait for pods ready                                    │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Test Execution                                           │
│    • Run test specs                                         │
│    • Collect artifacts on failure                           │
│    • Validate expected behavior                             │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Cleanup Phase (AfterAll)                                │
│    • Collect final debug info                               │
│    • Remove CRDs and finalizers                             │
│    • Uninstall operator                                     │
│    • Delete cluster (unless SKIP_E2E_CLEANUP=true)          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎓 Learning Path

### Beginner
1. Read [Quick Start](README.md#quick-start)
2. Run `make test-e2e-quick`
3. Review [QUICKREF.md](QUICKREF.md)

### Intermediate
1. Run full test suite
2. Review test structure in README
3. Understand cluster isolation
4. Practice debugging failed tests

### Advanced
1. Read [IMPROVEMENTS.md](IMPROVEMENTS.md)
2. Review utility code
3. Refactor tests using new patterns
4. Contribute improvements

---

## 📝 Contributing

When adding new tests:

1. **Choose appropriate file:**
   - Basic CRD → `crd_e2e_test.go`
   - Helm-specific → `helm_e2e_test.go`
   - Complex scenarios → `complex_e2e_test.go`

2. **Use correct labels:**
   ```go
   var _ = Describe("My Test", Label("helm", "smoke"), func() {
   ```

3. **Use utilities:**
   ```go
   CleanupForHelmTests(namespace, release)
   progress := NewTestProgress("Setup", steps)
   ```

4. **Document test data:**
   - Add README in testdata subdirectories
   - Comment complex scenarios
   - Explain expected behavior

See [Best Practices](README.md#best-practices) for more details.

---

## 🔗 Related Documentation

- [Main README](../../README.md) - Auth operator overview
- [API Reference](../../docs/api-reference/) - CRD API documentation
- [Makefile](../../Makefile) - Build and test targets

---

**Last Updated:** January 2026  
**Version:** 1.0  
**Status:** ✅ Complete and Maintained

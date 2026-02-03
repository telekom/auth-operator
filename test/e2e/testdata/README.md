# Test Data Structure

This directory contains test data for e2e tests organized by test suite and purpose.

## Directory Structure

```
testdata/
├── README.md                    # This file
├── golden/                      # Golden file test data
│   ├── README.md                # Golden test documentation
│   ├── roledefinition-clusterrole-input.yaml
│   ├── expected-clusterrole.yaml
│   └── ...
├── complex/                     # Complex scenario data
│   ├── namespace-test.yaml
│   ├── namespace-team-alpha.yaml
│   ├── namespace-team-beta.yaml
│   ├── roledefinition-all-restrictions.yaml
│   └── binddefinition-*.yaml
└── integration/                 # Integration test data
    └── ...
```

## Golden Test Format

Golden tests validate that the operator generates correct RBAC resources from CRD inputs.

### Purpose
- Verify RoleDefinitions generate correct ClusterRoles/Roles
- Verify BindDefinitions generate correct bindings
- Ensure restricted APIs, resources, and verbs are properly filtered
- Validate namespace selector logic

### Structure

Each golden test has two parts:
1. **Input** - The CRD that the operator processes
2. **Expected** - The cleaned/expected output resource

### Creating Golden Test Data

#### 1. Create Input CRD

```yaml
# roledefinition-example-input.yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: test-cluster-reader
  namespace: test-namespace
spec:
  targetRole: ClusterRole
  targetName: generated-cluster-reader
  scopeNamespaced: false
  restrictedVerbs:
    - create
    - update
    - delete
    - patch
  restrictedApis:
    - name: apps
      versions:
        - groupVersion: apps/v1
```

#### 2. Apply and Capture Output

```bash
# Apply the RoleDefinition
kubectl apply -f roledefinition-example-input.yaml

# Wait for reconciliation
sleep 10

# Get generated ClusterRole
kubectl get clusterrole generated-cluster-reader -o yaml > temp-output.yaml
```

#### 3. Clean the Output

Remove dynamic/non-deterministic fields:
- `metadata.creationTimestamp`
- `metadata.generation`
- `metadata.resourceVersion`
- `metadata.uid`
- `metadata.managedFields`
- Any other runtime-generated fields

Keep only:
- `apiVersion`
- `kind`
- `metadata.name`
- `metadata.labels` (relevant ones)
- `metadata.annotations` (relevant ones)
- `rules` (the actual RBAC rules)

#### 4. Save as Expected Output

```yaml
# expected-clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: generated-cluster-reader
  labels:
    app.kubernetes.io/created-by: auth-operator
    app.kubernetes.io/name: roledefinition
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list", "watch"]
  # Note: No create/update/delete/patch verbs (filtered by restrictedVerbs)
  # Note: No apps/* resources (filtered by restrictedApis)
```

#### 5. Add Test Case

In `golden_e2e_test.go`:

```go
It("should generate correct ClusterRole for example scenario", func() {
    By("Applying RoleDefinition input")
    inputPath := filepath.Join(testdataPath, "roledefinition-example-input.yaml")
    cmd := exec.Command("kubectl", "apply", "-f", inputPath)
    _, err := utils.Run(cmd)
    Expect(err).NotTo(HaveOccurred())
    
    By("Waiting for ClusterRole to be generated")
    Eventually(func() error {
        cmd := exec.Command("kubectl", "get", "clusterrole", "generated-cluster-reader")
        _, err := utils.Run(cmd)
        return err
    }, reconcileTimeout, pollingInterval).Should(Succeed())
    
    By("Comparing generated output with expected")
    // Compare logic here
})
```

### Golden Test Checklist

When creating golden tests:
- ✓ Input file clearly shows test scenario
- ✓ Expected output is cleaned of runtime fields
- ✓ Test validates specific feature (restrictions, selectors, etc.)
- ✓ Comments explain what is being tested
- ✓ File names are descriptive

---

## Complex Test Scenarios

Complex tests validate multiple CRDs working together in realistic scenarios.

### Purpose
- Test multi-CRD interactions
- Validate namespace selectors
- Test complex restriction combinations
- Verify cross-namespace bindings

### Structure

Each complex scenario is a collection of related manifests:

```
complex/<scenario-name>/
├── 01-namespaces.yaml       # Namespace setup
├── 02-roledefinitions.yaml  # RoleDefinitions for scenario
├── 03-binddefinitions.yaml  # BindDefinitions
└── 04-webhooks.yaml         # WebhookAuthorizers (if needed)
```

Numbering ensures correct application order.

### Example: Multi-Tenant Scenario

#### 01-namespaces.yaml
```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-alpha
  labels:
    team: alpha
    env: dev
    tenant: true
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-beta
  labels:
    team: beta
    env: dev
    tenant: true
```

#### 02-roledefinitions.yaml
```yaml
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: tenant-developer
spec:
  targetRole: Role
  targetName: developer
  scopeNamespaced: true
  restrictedVerbs:
    - delete
    - deletecollection
  restrictedResources:
    - secrets
    - serviceaccounts
```

#### 03-binddefinitions.yaml
```yaml
---
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: alpha-developers
spec:
  roleRefs:
    - name: developer
      kind: Role
  subjects:
    - kind: Group
      name: alpha-developers
      apiGroup: rbac.authorization.k8s.io
  namespaceSelector:
    matchLabels:
      team: alpha
```

### Creating Complex Test Data

1. **Design scenario** - What combination are you testing?
2. **Create namespace setup** - Define test namespaces with appropriate labels
3. **Create CRDs** - RoleDefinitions, BindDefinitions, WebhookAuthorizers
4. **Number files** - Use 01-, 02-, 03- prefix for order
5. **Add documentation** - Comment complex logic in YAML
6. **Add test** - Create test case in `complex_e2e_test.go`

---

## Integration Test Data

Integration tests validate end-to-end workflows with multiple CRDs.

### Purpose
- Test complete authorization workflows
- Validate CRD chaining and dependencies
- Test realistic multi-step scenarios

### Structure

Similar to complex tests but focused on integration flows:

```
integration/<workflow-name>/
├── setup-*.yaml
├── step1-*.yaml
├── step2-*.yaml
└── teardown-*.yaml
```

---

## Fixtures

The `fixtures/` directory (outside testdata) contains basic test manifests for simple CRD functionality tests.

### Purpose
- Basic CRD creation tests
- Simple validation scenarios
- Quick smoke tests

### Structure

```
fixtures/
├── roledefinition_clusterrole.yaml
├── roledefinition_role.yaml
├── binddefinition_clusterrolebinding.yaml
└── webhookauthorizer_basic.yaml
```

---

## Best Practices

### File Naming
- Use descriptive names: `roledefinition-restricted-apis.yaml`
- Use prefixes for ordering: `01-namespaces.yaml`
- Include test purpose in name: `binddefinition-namespace-selector.yaml`

### YAML Structure
- Add comments explaining non-obvious configurations
- Use consistent indentation (2 spaces)
- Include metadata.name that describes purpose
- Add labels that indicate test scenario

### Documentation
- Document complex scenarios
- Explain expected behavior
- Note any special requirements
- Link to related test cases

### Maintenance
- Keep test data in sync with API changes
- Update golden files when output format changes
- Remove obsolete test data
- Validate test data still works after refactoring

---

## Troubleshooting

### Golden Tests Failing

1. **Check if CRD changed** - API version or spec structure
2. **Verify operator logic** - Did reconciliation logic change?
3. **Update expected output** - Regenerate golden files if intentional change
4. **Check for flakes** - Timing issues in test execution

### Complex Tests Failing

1. **Check resource order** - Are resources applied in correct sequence?
2. **Verify namespace labels** - Do selectors match?
3. **Check finalizers** - Are resources stuck during deletion?
4. **Review logs** - Check operator logs for reconciliation errors

### Creating New Test Data

1. **Start simple** - Create basic scenario first
2. **Test incrementally** - Add complexity one step at a time
3. **Validate manually** - Apply manifests manually before adding test
4. **Document assumptions** - Note any prerequisites or dependencies

---

## Examples

### Minimal Golden Test

Input: RoleDefinition with restricted verbs
Expected: ClusterRole without restricted verbs in rules

### Complex Scenario

Multiple namespaces with labels
→ RoleDefinition creating Roles
→ BindDefinition with namespace selector
→ Verify Roles created only in matching namespaces
→ Verify RoleBindings created in correct namespaces

### Integration Test

Create RoleDefinition (admin)
→ Create BindDefinition (bind to group)
→ Create WebhookAuthorizer (authorize group)
→ Verify complete authorization chain
→ Test actual authorization with simulated requests

---

## Contributing

When adding new test data:

1. Follow the structure guidelines above
2. Add documentation in comments
3. Create corresponding test case
4. Update this README if adding new patterns
5. Ensure test data is committed with tests

---

## Related Documentation

- [E2E Test Guide](../README.md) - Complete e2e testing documentation
- [Golden Test Example](golden/README.md) - Detailed golden test guide
- [Test Suite](../) - Test implementation files

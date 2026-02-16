You are reviewing a pull request for the auth-operator project. Check for:

## Code Quality
- [ ] All auto-generated files are up to date (`make manifests generate helm docs`)
- [ ] No edits to auto-generated files (CRDs, DeepCopy, RBAC)
- [ ] `go mod tidy` has been run
- [ ] Imports use standard aliases (`authorizationv1alpha1`, `ctrl`, `rbacv1`, `metav1`)
- [ ] Errors wrapped with `%w` not `%v`
- [ ] Standard library constants used (`http.MethodGet`, not `"GET"`)

## Testing
- [ ] New/modified code has unit tests (>70% coverage target)
- [ ] Controller tests use envtest
- [ ] Table-driven tests for validation logic
- [ ] All tests pass: `make test`

## Security & Compliance
- [ ] SPDX headers present on all new files
- [ ] No secrets or credentials in code
- [ ] RBAC markers are minimal (least privilege)
- [ ] govulncheck clean

## Documentation
- [ ] API docs updated if CRD fields changed
- [ ] Operator guide updated if behavior changed
- [ ] Helm chart values documented if new config added

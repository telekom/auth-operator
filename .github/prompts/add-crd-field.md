You are adding a new field to an existing CRD in this Kubebuilder v4 project.

## Steps

1. Add the field to the appropriate `*_types.go` file in `api/authorization/v1alpha1/`
2. Add kubebuilder validation markers (`+kubebuilder:validation:*`, `+optional`)
3. Run `make manifests generate` to regenerate CRDs and DeepCopy
4. Update the webhook validation in the corresponding `*_webhook.go` file
5. Add the field to the controller reconciliation logic
6. Update status conditions if the field affects reconciliation
7. Run `make docs` to regenerate API reference documentation
8. Run `make helm` to sync CRDs to the Helm chart
9. Add unit tests for the new field (validation, reconciliation, edge cases)
10. Update `docs/` with the new field documentation
11. Verify with `make lint test`

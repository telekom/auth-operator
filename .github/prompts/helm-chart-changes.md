<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Helm Chart Changes

Use this prompt when modifying the auth-operator Helm chart.

## Chart structure

```
chart/auth-operator/
├── Chart.yaml            # Chart metadata and version
├── values.yaml           # Default values
├── kustomization.yaml    # Kustomize overlay for CRDs
├── README.md             # Chart documentation (auto-generated)
├── crds/                 # CRD manifests (copied from config/crd/)
└── templates/            # Helm templates
```

## Checklist for chart changes

1. **values.yaml** — add new values with sensible defaults and a YAML comment
2. **templates/** — use `{{ include "auth-operator.fullname" . }}` for names,
   follow existing label/annotation helpers
3. **CRD sync** — if a CRD changed, run `make manifests` then copy the output
   into `chart/auth-operator/crds/`
4. **Chart.yaml** — bump `version` (chart version) for every chart change;
   bump `appVersion` only on operator releases
5. **README.md** — regenerate with `helm-docs` if value descriptions changed
6. **Lint & test** — run:
   ```bash
   helm lint chart/auth-operator
   helm template auth-operator chart/auth-operator --debug
   make helm-chart-test        # runs ct lint + ct install in CI-like mode
   ```
7. **RBAC** — if the operator needs new permissions, update both
   `config/rbac/` (kubebuilder markers) and the chart's RBAC templates
8. **Upgrade path** — ensure `helm upgrade` from the previous release works;
   avoid removing values without a deprecation cycle

## Naming conventions

- Template helpers live in `templates/_helpers.tpl`
- Use `auth-operator.labels` / `auth-operator.selectorLabels` includes
- ConfigMap/Secret names must be scoped with `{{ .Release.Name }}`

## Testing

- `make helm-chart-test` runs chart-testing (`ct`) with schema validation
- The CI workflow `.github/workflows/helm-chart-test.yml` installs the chart
  into a kind cluster — make sure it passes before merging

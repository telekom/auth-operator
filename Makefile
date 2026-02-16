#!make

## Export tool versions
include versions.env

# Image URL to use all building/pushing image targets
PROJECT_NAME = "auth-operator"
APP ?= auth-operator
IMG ?= $(APP):latest
NAMESPACE ?= auth-operator-system

# E2E run identifier and deterministic kind cluster name
RUN_ID ?= $(shell date +%s)
KIND_CLUSTER_NAME ?= auth-operator-e2e
SKIP_E2E_CLEANUP ?= false
E2E_RECREATE_CLUSTER ?= true
E2E_TEARDOWN ?= false
export RUN_ID
export KIND_CLUSTER_NAME
export E2E_TEARDOWN
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
# Keep in sync with KIND_K8S_VERSION for consistency between envtest and kind-based E2E tests.
ENVTEST_K8S_VERSION = 1.34.1

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Extract Go version from go.mod (single source of truth)
GO_VERSION := $(shell grep -E '^go [0-9]+\.[0-9]+' go.mod | awk '{print $$2}' | cut -d. -f1,2)

# CONTAINER_TOOL defines the container tool to be used for building images.
# Be aware that the target commands are only tested with Docker which is
# scaffolded by default. However, you might want to replace it to use other
# tools. (i.e. podman)
CONTAINER_TOOL ?= docker

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) crd paths="./api/..." output:crd:artifacts:config=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=manager-role webhook paths="{./api/...,./internal/...}"

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, DeepCopyObject, and ApplyConfiguration implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONTROLLER_GEN) applyconfiguration:headerFile="hack/boilerplate.go.txt" paths="./api/..." output:applyconfiguration:dir=./api/authorization/v1alpha1/applyconfiguration

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test -race $$(go list ./... | grep -v /e2e) -coverprofile cover.out

##@ E2E Testing

# Kind cluster configuration
KIND_K8S_VERSION ?= v1.34.3
E2E_IMG ?= auth-operator:e2e-test
KIND_CONFIG_SINGLE ?= test/e2e/kind-config-single.yaml
KIND_CONFIG_MULTI ?= test/e2e/kind-config-multi.yaml

.PHONY: kind-create
kind-create: ## Create a single-node kind cluster for e2e testing.
	@if [ "$(E2E_RECREATE_CLUSTER)" = "true" ]; then \
		kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || true; \
	fi
	@echo "Creating single-node kind cluster '$(KIND_CLUSTER_NAME)'..."; \
	kind create cluster --name $(KIND_CLUSTER_NAME) --config $(KIND_CONFIG_SINGLE) --image kindest/node:$(KIND_K8S_VERSION) --wait 5m
	@kubectl cluster-info --context kind-$(KIND_CLUSTER_NAME)

.PHONY: kind-create-multi
kind-create-multi: ## Create a multi-node kind cluster for HA testing.
	@if [ "$(E2E_RECREATE_CLUSTER)" = "true" ]; then \
		kind delete cluster --name $(KIND_CLUSTER_NAME)-multi 2>/dev/null || true; \
	fi
	@echo "Creating multi-node kind cluster '$(KIND_CLUSTER_NAME)-multi'..."; \
	kind create cluster --name $(KIND_CLUSTER_NAME)-multi --config $(KIND_CONFIG_MULTI) --image kindest/node:$(KIND_K8S_VERSION) --wait 8m
	@kubectl cluster-info --context kind-$(KIND_CLUSTER_NAME)-multi
	@kubectl get nodes -o wide

.PHONY: kind-delete
kind-delete: ## Delete the kind cluster(s).
	kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || true
	kind delete cluster --name $(KIND_CLUSTER_NAME)-multi 2>/dev/null || true

.PHONY: kind-delete-all
kind-delete-all: ## Delete all deterministic e2e kind clusters.
	@for c in auth-operator-e2e auth-operator-e2e-dev auth-operator-e2e-helm auth-operator-e2e-complex auth-operator-e2e-integration auth-operator-e2e-golden auth-operator-e2e-ha auth-operator-e2e-all; do \
		kind delete cluster --name $$c 2>/dev/null || true; \
		kind delete cluster --name $$c-multi 2>/dev/null || true; \
	done

.PHONY: kind-load-image
kind-load-image: docker-build ## Build and load the operator image into kind cluster.
	$(CONTAINER_TOOL) tag ${IMG} $(E2E_IMG)
	kind load docker-image $(E2E_IMG) --name $(KIND_CLUSTER_NAME)

.PHONY: kind-load-image-multi
kind-load-image-multi: docker-build ## Build and load the operator image into multi-node kind cluster.
	$(CONTAINER_TOOL) tag ${IMG} $(E2E_IMG)
	kind load docker-image $(E2E_IMG) --name $(KIND_CLUSTER_NAME)-multi

.PHONY: test-e2e-setup
test-e2e-setup: kind-create kind-load-image install ## Set up the e2e test environment (create cluster, build, deploy with dev overlay).
	$(MAKE) deploy OVERLAY=dev IMG=$(E2E_IMG)
	@echo "E2E test environment ready!"
	@echo "  Cluster: $(KIND_CLUSTER_NAME)"
	@echo "  Image: $(E2E_IMG)"
	@echo "  Overlay: dev (debug logging enabled)"

.PHONY: test-e2e-setup-multi
test-e2e-setup-multi: kind-create-multi kind-load-image-multi install ## Set up multi-node e2e test environment.
	$(MAKE) deploy OVERLAY=dev IMG=$(E2E_IMG)
	@echo "Multi-node E2E test environment ready!"
	@echo "  Cluster: $(KIND_CLUSTER_NAME)-multi"
	@echo "  Image: $(E2E_IMG)"
	@echo "  Overlay: dev (debug logging enabled)"

.PHONY: test-e2e
test-e2e: ## Run base e2e tests against existing kind cluster.
	KIND_CLUSTER=$(KIND_CLUSTER_NAME) IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="!helm && !complex && !integration && !golden && !ha && !leader-election && !dev" -timeout 30m

.PHONY: test-e2e-full
test-e2e-full: ## Run full e2e test suite (fresh cluster each run, configurable cleanup).
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; \
	$(MAKE) test-e2e-setup KIND_CLUSTER_NAME=auth-operator-e2e; \
	if $(MAKE) test-e2e KIND_CLUSTER_NAME=auth-operator-e2e; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; exit 1; \
	fi

.PHONY: test-e2e-full-chain
test-e2e-full-chain: ## Run full e2e test suite with popular CRDs installed (fresh cluster each run).
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e; \
	KIND_CLUSTER_NAME=auth-operator-e2e bash hack/ci/setup-kind-crds.sh; \
	$(MAKE) kind-load-image KIND_CLUSTER_NAME=auth-operator-e2e; \
	$(MAKE) install KIND_CLUSTER_NAME=auth-operator-e2e; \
	$(MAKE) deploy OVERLAY=dev IMG=$(E2E_IMG) KIND_CLUSTER_NAME=auth-operator-e2e; \
	if $(MAKE) test-e2e KIND_CLUSTER_NAME=auth-operator-e2e; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e; fi; exit 1; \
	fi

.PHONY: test-e2e-quick
test-e2e-quick: ## Run e2e tests with setup label only (prerequisites check).
	KIND_CLUSTER=$(KIND_CLUSTER_NAME) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="setup" -timeout 5m

.PHONY: test-e2e-debug
test-e2e-debug: ## Run e2e debug tests (prints cluster state).
	KIND_CLUSTER=$(KIND_CLUSTER_NAME) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="debug" -timeout 5m

.PHONY: test-e2e-cleanup
test-e2e-cleanup: ## Clean up e2e test resources.
	kubectl delete -k test/e2e/fixtures --ignore-not-found=true || true
	kubectl delete ns e2e-test-ns e2e-helm-test-ns e2e-ha-test-ns dev-e2e-test-ns auth-operator-golden-test auth-operator-integration-test integration-ns-alpha integration-ns-beta integration-ns-gamma --ignore-not-found=true || true
	$(MAKE) kind-delete-all

.PHONY: test-e2e-helm
test-e2e-helm: kind-create kind-load-image ## Run Helm e2e tests (installs via Helm chart).
	KIND_CLUSTER=$(KIND_CLUSTER_NAME) IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="helm" -timeout 30m

.PHONY: test-e2e-dev
test-e2e-dev: ## Run dev e2e tests (kustomize deploy) on a dedicated cluster.
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-dev; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e-dev; \
	if KIND_CLUSTER=auth-operator-e2e-dev IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="dev" -timeout 45m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-dev; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-dev; fi; exit 1; \
	fi

.PHONY: test-e2e-integration
test-e2e-integration: ## Run integration e2e tests on a dedicated cluster.
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-integration; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e-integration; \
	if KIND_CLUSTER=auth-operator-e2e-integration IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="integration" -timeout 60m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-integration; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-integration; fi; exit 1; \
	fi

.PHONY: test-e2e-golden
test-e2e-golden: ## Run golden e2e tests on a dedicated cluster.
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-golden; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e-golden; \
	if KIND_CLUSTER=auth-operator-e2e-golden IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="golden" -timeout 60m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-golden; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-golden; fi; exit 1; \
	fi

.PHONY: test-e2e-helm-full
test-e2e-helm-full: ## Run full Helm e2e test suite (fresh cluster each run, configurable cleanup).
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-helm; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e-helm; \
	$(MAKE) kind-load-image KIND_CLUSTER_NAME=auth-operator-e2e-helm; \
	if $(MAKE) test-e2e-helm KIND_CLUSTER_NAME=auth-operator-e2e-helm; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-helm; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-helm; fi; exit 1; \
	fi

.PHONY: test-e2e-complex
test-e2e-complex: ## Run complex e2e tests (Helm-based, isolated, fresh cluster each run, configurable cleanup).
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-complex; fi; \
	$(MAKE) kind-create KIND_CLUSTER_NAME=auth-operator-e2e-complex; \
	$(MAKE) kind-load-image KIND_CLUSTER_NAME=auth-operator-e2e-complex; \
	if KIND_CLUSTER=auth-operator-e2e-complex IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="complex" -timeout 45m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-complex; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-complex; fi; exit 1; \
	fi

.PHONY: test-e2e-ha
test-e2e-ha: ## Run HA and leader election e2e tests on multi-node cluster.
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-ha; fi; \
	$(MAKE) test-e2e-setup-multi KIND_CLUSTER_NAME=auth-operator-e2e-ha; \
	if KIND_CLUSTER=auth-operator-e2e-ha-multi IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="ha || leader-election" -timeout 45m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-ha; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-ha; fi; exit 1; \
	fi

.PHONY: test-e2e-all
test-e2e-all: ## Run non-Helm/non-complex e2e tests on multi-node cluster.
	@set -e; \
	if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-all; fi; \
	$(MAKE) test-e2e-setup-multi KIND_CLUSTER_NAME=auth-operator-e2e-all; \
	if KIND_CLUSTER=auth-operator-e2e-all-multi IMG=$(E2E_IMG) go test -tags e2e ./test/e2e/ -v -ginkgo.v -ginkgo.label-filter="!helm && !complex" -timeout 60m; then \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-all; fi; \
	else \
		if [ "$(SKIP_E2E_CLEANUP)" != "true" ]; then $(MAKE) kind-delete KIND_CLUSTER_NAME=auth-operator-e2e-all; fi; exit 1; \
	fi

.PHONY: test-e2e-output
test-e2e-output: ## Show the e2e test output directory.
	@echo "E2E test output directory: test/e2e/output"
	@ls -la test/e2e/output 2>/dev/null || echo "No output files yet. Run e2e tests first."

.PHONY: test-e2e-clean-output
test-e2e-clean-output: ## Clean the e2e test output directory.
	rm -rf test/e2e/output/*

.PHONY: test-e2e-collect-artifacts
test-e2e-collect-artifacts: ## Collect e2e test artifacts (logs, resources).
	@mkdir -p test/e2e/output
	@echo "Collecting cluster state..."
	kubectl cluster-info dump --output-directory=test/e2e/output/cluster-dump || true
	kubectl get all -A -o wide > test/e2e/output/all-resources.txt 2>&1 || true
	kubectl get events -A --sort-by='.lastTimestamp' > test/e2e/output/events.txt 2>&1 || true
	@echo "Collecting operator logs..."
	@for ns in auth-operator-system auth-operator-helm auth-operator-ha; do \
		if kubectl get ns "$$ns" >/dev/null 2>&1; then \
			kubectl logs -n "$$ns" -l control-plane=controller-manager --tail=1000 > "test/e2e/output/$${ns}-controller-logs.txt" 2>&1 || true; \
			kubectl logs -n "$$ns" -l app.kubernetes.io/component=webhook --tail=1000 > "test/e2e/output/$${ns}-webhook-logs.txt" 2>&1 || true; \
		fi; \
	done
	@echo "Collecting CRDs..."
	kubectl get roledefinitions,binddefinitions,webhookauthorizers -A -o yaml > test/e2e/output/crds.yaml 2>&1 || true
	@echo "Artifacts collected in test/e2e/output/"

##@ Linting

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter.
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes.
	$(GOLANGCI_LINT) run --fix

.PHONY: lint-strict
lint-strict: golangci-lint ## Run golangci-lint with strict settings (as in CI).
	$(GOLANGCI_LINT) run --timeout 10m --issues-exit-code 1

.PHONY: vulncheck
vulncheck: ## Run govulncheck to check for known vulnerabilities.
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

.PHONY: verify
verify: lint-strict vet test vulncheck ## Run all verification checks (lint, vet, test, vulncheck).
	@echo "All verification checks passed!"

.PHONY: ci-checks
ci-checks: verify helm-lint ## Run all CI checks locally before pushing.
	@echo "Checking go.mod is tidy..."
	@go mod tidy
	@git diff --exit-code go.mod go.sum || (echo "ERROR: go.mod/go.sum not tidy" && exit 1)
	@echo "Checking generated code is up to date..."
	@$(MAKE) generate manifests
	@git diff --exit-code || (echo "ERROR: Generated code out of date" && exit 1)
	@echo "Linting YAML files..."
	@command -v yamllint >/dev/null 2>&1 && yamllint -c .yamllint.yml . || echo "yamllint not installed, skipping"
	@echo "All CI checks passed!"

.PHONY: helm-lint
helm-lint: ## Lint Helm chart.
	@command -v helm >/dev/null 2>&1 || (echo "helm not installed, skipping helm-lint" && exit 0)
	helm lint chart/auth-operator --strict

##@ Build

.PHONY: build
build: manifests generate fmt vet ## Build manager binary.
	go build -o bin/manager main.go

.PHONY: run-ctrl
run-ctrl: manifests generate fmt vet ## Run controllers from your host.
	go run ./main.go controller --namespace $(NAMESPACE)

.PHONY: run-wh
run-wh: manifests generate fmt vet ## Run webhooks from your host.
	go run ./main.go webhook --namespace $(NAMESPACE)


# If you wish to build the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/develop-images/build_enhancements/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) go build -o auth-operator main.go
	$(CONTAINER_TOOL) build --build-arg BINARY_SOURCE_PATH=auth-operator -t ${IMG} --load .
	rm -f auth-operator

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	$(CONTAINER_TOOL) push ${IMG}


.PHONY: helm
helm: manifests kustomize ## Generate the complete Helm chart
	rm -f chart/auth-operator/crds/*
	$(KUSTOMIZE) build config/crd -o chart/auth-operator/crds
	pushd "chart/auth-operator" && \
	$(KUSTOMIZE) build . -o crds && \
	for file in crds/apiextensions.k8s.io_v1_customresourcedefinition_*; do \
		mv "$$file" "crds/$${file#crds/apiextensions.k8s.io_v1_customresourcedefinition_}"; \
	done && \
	popd



# PLATFORMS defines the target platforms for the manager image be built to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - be able to use docker buildx. More info: https://docs.docker.com/build/buildx/
# - have enabled BuildKit. More info: https://docs.docker.com/develop/develop-images/build_enhancements/
# - be able to push the image to your registry (i.e. if you do not set a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To adequately provide solutions that are compatible with multiple platforms, you should consider using this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- $(CONTAINER_TOOL) buildx create --name auth-operator-builder
	$(CONTAINER_TOOL) buildx use auth-operator-builder
	- $(CONTAINER_TOOL) buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- $(CONTAINER_TOOL) buildx rm auth-operator-builder
	rm Dockerfile.cross

.PHONY: build-installer
build-installer: manifests generate kustomize ## Generate a consolidated YAML with CRDs and deployment.
	mkdir -p dist
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default > dist/install.yaml

.PHONY: export-images
export-images: drawio ## Export PNG images from a Draw.io diagram.
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/overall-architecture.png --format png --page-index=0
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/generator.png --format png --page-index=1
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/binder.png --format png --page-index=2
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/idp.png --format png --page-index=3
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/authorizer.png --format png --page-index=4
	drawio --export docs/drawio/auth-operator.drawio --output docs/images/advertiser.png --format png --page-index=5

.PHONY: docs
docs: crd-ref-docs ## Generate markdown API reference into docs directory.
	${LOCALBIN}/crd-ref-docs --source-path=api --config=docs/crd-ref-docs-config.yaml --renderer=markdown --output-mode=single --output-path=docs/generated/api-reference.md


##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

# OVERLAY can be 'dev' or 'production' (default: dev)
OVERLAY ?= dev

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller using overlay (OVERLAY=dev|production, default: dev).
	cd config/overlays/$(OVERLAY) && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/overlays/$(OVERLAY) | $(KUBECTL) apply -f -

.PHONY: deploy-dev
deploy-dev: ## Deploy controller with dev overlay (debug logging enabled).
	$(MAKE) deploy OVERLAY=dev

.PHONY: deploy-production
deploy-production: ## Deploy controller with production overlay (optimized for production).
	$(MAKE) deploy OVERLAY=production

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/overlays/$(OVERLAY) | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY tilt:
tilt:
	CONTROLLERGEN_BIN=$(CONTROLLER_GEN) CLUSTER_NAME=kind-$(PROJECT_NAME) tilt up

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUBECTL ?= kubectl
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint
CRD_REF_DOCS = $(LOCALBIN)/crd-ref-docs
MOCKGEN ?= $(LOCALBIN)/mockgen

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: envtest
envtest: $(ENVTEST) ## Download setup-envtest locally if necessary.
$(ENVTEST): $(LOCALBIN)
	$(call go-install-tool,$(ENVTEST),sigs.k8s.io/controller-runtime/tools/setup-envtest,$(ENVTEST_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,${GOLANGCI_LINT_VERSION})

.PHONY: crd-ref-docs
crd-ref-docs: $(CRD_REF_DOCS) ## Download crd-ref-docs locally if necessary.
$(CRD_REF_DOCS): $(LOCALBIN)
	$(call go-install-tool,$(CRD_REF_DOCS),github.com/elastic/crd-ref-docs,${CRD_REF_DOCS_VERSION})

.PHONY: drawio
drawio: ## Download Draw.io locally if necessary.
	echo "Can't check if you downloaded Draw.io. If not please install it manually."

.PHONY: mockgen
mockgen: $(MOCKGEN) ## Download mockgen locally if necessary.
$(MOCKGEN): $(LOCALBIN)
	$(call go-install-tool,$(MOCKGEN),go.uber.org/mock/mockgen,$(MOCKGEN_VERSION))

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary (ideally with version)
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f $(1) ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
}
endef

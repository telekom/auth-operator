# authn-authz-operator
This operator serves as the T-CaaS specific authentication (`authN`) and authorization (`authZ`) implementation. The need for this operator arises from the requirement to manage `authN` and `authZ` for multiple cluster consumers in a single cluster. The operator API reference can be found in the `docs/reference` directory, specifically for [authorization](https://gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/docs/reference/authorization.t-caas.telekom.com.md) API group and for [authentication](https://gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/docs/reference/authentication.t-caas.telekom.com.md) API group. In case the API reference is out of date or you are making changes to the API groups, run `make docs` locally and commit the documentation changes into the repository.

## Getting started
To contribute clone the repository with `SSH` or `HTTPS`. Please make use of the `Makefile` as most common actions that you would like to repeat multiple times are encapsulated in it. The repository structure is the default kubebuilder scaffold for multi-group projects with few additions. Please refer to the snippet below for a brief explanation:
```
.
├── api                                                         # Go APIs being reconciled into the cluster, separated by group
│   ├── authentication
│   │   └── v1alpha1
│   └── authorization
│       └── v1alpha1
├── bin                                                         # Static binaries downloaded or built via Makefile
├── cmd
│   └── main.go                                                 # The main Go function bootstrapping a Manager
├── config                                                      # Different configs that can be used for quick testing of the operator locally
│   ├── certmanager
│   ├── crd
│   ├── default
│   ├── manager
│   ├── prometheus
│   ├── rbac
│   ├── samples                                                 # Sample custom resources that can be used for quick testing of the operator locally
│   └── webhook
├── Dockerfile                                                  # Main Dockerfile for building the operator container image
├── docs                                                        # Docs repository containing API reference, diagrams and images
│   ├── drawio
│   ├── images
│   ├── reference
│   └── config.yaml
├── go.mod
├── go.sum
├── hack
│   └── boilerplate.go.txt
├── helm                                                        # Operator Helm packaging that gets pushed to Artifactory/Harbor
│   ├── Chart.yaml
│   ├── crds
│   ├── templates
│   └── values.yaml
├── internal
│   └── controller                                              # Controllers for both API groups with respective reconcile functions
│       ├── authentication
│       └── authorization
├── Makefile                                                    # Makefile containing useful repeatable actions
├── pkg
│   ├── client                                                  # OIDC client implementations
│   └── conditions                                              # Common conditions getter/setter implementation
├── test
│   ├── e2e
│   └── utils
└── vendor                                                      # Vendor dependencies
```


## Architecture
Architecture diagrams and images can be found in `docs/` directory under `docs/drawio` and `docs/images`. 

## Generator (RoleDefinition)
The `generator` component acts as a 

## Binder (BindDefinition)
The `binder` component acts as a 

## OIDC client (AuthProvider)
The `oidc-client` component acts as a

***

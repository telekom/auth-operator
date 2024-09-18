# API Reference

## Packages
- [authorization.t-caas.telekom.com/v1alpha1](#authorizationt-caastelekomcomv1alpha1)


## authorization.t-caas.telekom.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the authorization v1alpha1 API group

### Resource Types
- [BindDefinition](#binddefinition)
- [RoleDefinition](#roledefinition)



#### BindDefinition



BindDefinition is the Schema for the binddefinitions API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `BindDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BindDefinitionSpec](#binddefinitionspec)_ |  |  |  |
| `status` _[BindDefinitionStatus](#binddefinitionstatus)_ |  |  |  |


#### BindDefinitionSpec



BindDefinitionSpec defines the desired state of BindDefinition



_Appears in:_
- [BindDefinition](#binddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `foo` _string_ | Foo is an example field of BindDefinition. Edit binddefinition_types.go to remove/update |  |  |


#### BindDefinitionStatus



BindDefinitionStatus defines the observed state of BindDefinition



_Appears in:_
- [BindDefinition](#binddefinition)









#### RoleDefinition



RoleDefinition is the Schema for the roledefinitions API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RoleDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RoleDefinitionSpec](#roledefinitionspec)_ |  |  |  |
| `status` _[RoleDefinitionStatus](#roledefinitionstatus)_ |  |  |  |


#### RoleDefinitionSpec



RoleDefinitionSpec defines the desired state of RoleDefinition



_Appears in:_
- [RoleDefinition](#roledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRole` _string_ | The target role that will be reconciled. This can be a ClusterRole or a namespaced Role |  | Enum: [ClusterRole Role] <br />Required: {} <br /> |
| `targetName` _string_ | The name of the target role. This can be any name that accurately describes the ClusterRole/Role |  | MinLength: 5 <br />Required: {} <br /> |
| `targetNamespace` _string_ | The target namespace for the Role. This value is necessary when the "TargetRole" is "Role" |  | Optional: {} <br /> |
| `scopeNamespaced` _boolean_ | The scope controls whether the API resource is namespaced or not. This can also be checked by<br />running `kubectl api-resources --namespaced=true/false` |  | Required: {} <br /> |
| `restrictedApis` _[APIGroup](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#apigroup-v1-meta) array_ | The restricted APIs field holds all API groups which will *NOT* be reconciled into the "TargetRole"<br />The RBAC operator discovers all API groups available and removes those which are defined by "RestrictedAPIs" |  | Optional: {} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#apiresource-v1-meta) array_ | The restricted resources field holds all resources which will *NOT* be reconciled into the "TargetRole"<br />The RBAC operator discovers all API resources available and removes those which are defined by "RestrictedResources" |  | Optional: {} <br /> |
| `restrictedVerbs` _string array_ | The restricted verbs field holds all verbs which will *NOT* be reconciled into the "TargetRole"<br />The RBAC operator discovers all resource verbs available and removes those which are defined by "RestrictedVerbs" |  | Optional: {} <br /> |


#### RoleDefinitionStatus



RoleDefinitionStatus defines the observed state of RoleDefinition



_Appears in:_
- [RoleDefinition](#roledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `roleReconciled` _boolean_ | Not extremely important as most status updates are driven by Conditions<br />We read the JSONPath from this status field to signify completed reconciliation |  | Optional: {} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | Conditions defines current service state of the Role definition<br />All conditions should evaluate to true to signify successful reconciliation |  | Optional: {} <br /> |



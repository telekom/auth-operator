# API Reference

## Packages
- [authorization.t-caas.telekom.com/v1alpha1](#authorizationt-caastelekomcomv1alpha1)


## authorization.t-caas.telekom.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the authorization v1alpha1 API group

### Resource Types
- [BindDefinition](#binddefinition)
- [RoleDefinition](#roledefinition)
- [WebhookAuthorizer](#webhookauthorizer)



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
| `targetName` _string_ | Name that will be prefixed to the concatenated string which is the name of the binding. Follows format "targetName-clusterrole/role-binding" where clusterrole/role is the in-cluster existing ClusterRole or Role. |  | Required: {} <br /> |
| `subjects` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#subject-v1-rbac) array_ | List of subjects that will be bound to a target ClusterRole/Role. Can be "User", "Group" or "ServiceAccount". |  | Required: {} <br /> |
| `clusterRoleBindings` _[ClusterBinding](#clusterbinding)_ | List of ClusterRoles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying this field are ClusterRoleBindings. |  | Optional: {} <br /> |
| `roleBindings` _[NamespaceBinding](#namespacebinding)_ | List of ClusterRoles/Roles to which subjects will be bound to. The list is a RoleRef which means we have to specify t he full rbacv1.RoleRef schema. The result of specifying the field are RoleBindings. |  | Optional: {} <br /> |


#### BindDefinitionStatus



BindDefinitionStatus defines the observed state of BindDefinition



_Appears in:_
- [BindDefinition](#binddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `bindReconciled` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify completed reconciliation. |  | Optional: {} <br /> |
| `generatedServiceAccounts` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#subject-v1-rbac) array_ | If the BindDefinition points to a subject of "Kind: ServiceAccount" and the service account is not present. The controller will reconcile it automatically. |  | Optional: {} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | Conditions defines current service state of the Bind definition. All conditions should evaluate to true to signify successful reconciliation. |  | Optional: {} <br /> |


#### ClusterBinding







_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _[RoleRef](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#roleref-v1-rbac) array_ | ClusterRole references adhering to the rbacv1.RoleRef schema. |  | Optional: {} <br /> |








#### NamespaceBinding







_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _[RoleRef](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#roleref-v1-rbac) array_ | ClusterRole references adhering to the rbacv1.RoleRef schema. |  | Optional: {} <br /> |
| `roleRefs` _[RoleRef](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#roleref-v1-rbac) array_ | Role references adhering to the rbacv1.RoleRef schema. |  | Optional: {} <br /> |
| `namespace` _string_ | Namespace of the the Role that should be bound to the subjects. |  | Optional: {} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#labelselector-v1-meta) array_ | NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s. |  | Required: {} <br /> |


#### Principal







_Appears in:_
- [WebhookAuthorizerSpec](#webhookauthorizerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `user` _string_ | User is the requesting user in SubjectAccessReview request. |  | Optional: {} <br /> |
| `groups` _string array_ | Groups is the requesting user groups in SubjectAccessReview request. |  | Optional: {} <br /> |


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
| `roleReconciled` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify completed reconciliation. |  | Optional: {} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | Conditions defines current service state of the Role definition. All conditions should evaluate to true to signify successful reconciliation. |  | Optional: {} <br /> |


#### WebhookAuthorizer



WebhookAuthorizer is the Schema for the webhookauthorizers API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `WebhookAuthorizer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[WebhookAuthorizerSpec](#webhookauthorizerspec)_ |  |  |  |
| `status` _[WebhookAuthorizerStatus](#webhookauthorizerstatus)_ |  |  |  |


#### WebhookAuthorizerSpec



WebhookAuthorizerSpec defines the desired state of WebhookAuthorizer



_Appears in:_
- [WebhookAuthorizer](#webhookauthorizer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroup` _string_ | APIGroup is the group of the API that should be allowed. |  | Required: {} <br /> |
| `apiVersion` _string_ | APIVersion is the version of the API that should be allowed. |  | Required: {} <br /> |
| `resource` _string_ | Resource is the resource of the API that should be allowed. Resource can be a RegEx pattern to match multiple resources. |  | Required: {} <br /> |
| `verbs` _string array_ | Verbs is a list of verbs that should be allowed. |  | Required: {} <br /> |
| `allowedPrincipals` _[Principal](#principal) array_ | AllowedPrincipals is a slice of principals this authorizer should allow. |  | Optional: {} <br /> |
| `deniedPrincipals` _[Principal](#principal) array_ | DeniedPrincipals is a slice of principals this authorizer should deny. |  | Optional: {} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#labelselector-v1-meta)_ | NamespaceSelector is a label selector to match namespaces that should allow the specified API calls. |  | Optional: {} <br /> |


#### WebhookAuthorizerStatus



WebhookAuthorizerStatus defines the observed state of WebhookAuthorizer



_Appears in:_
- [WebhookAuthorizer](#webhookauthorizer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `authorizerConfigured` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify webhook authorizer as configured. |  | Optional: {} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.3/#condition-v1-meta) array_ | Conditions defines current service state of the Webhook authorizer. All conditions should evaluate to true to signify successful configuration. |  | Optional: {} <br /> |



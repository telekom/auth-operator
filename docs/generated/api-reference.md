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



BindDefinition is the Schema for the binddefinitions API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `BindDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[BindDefinitionSpec](#binddefinitionspec)_ |  |  |  |
| `status` _[BindDefinitionStatus](#binddefinitionstatus)_ |  |  |  |


#### BindDefinitionSpec



BindDefinitionSpec defines the desired state of BindDefinition.



_Appears in:_
- [BindDefinition](#binddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetName` _string_ | Name that will be prefixed to the concatenated string which is the name of the binding. Follows format "targetName-clusterrole/role-binding" where clusterrole/role is the in-cluster existing ClusterRole or Role. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `subjects` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#subject-v1-rbac) array_ | List of subjects that will be bound to a target ClusterRole/Role. Can be "User", "Group" or "ServiceAccount". |  | Required: \{\} <br /> |
| `clusterRoleBindings` _[ClusterBinding](#clusterbinding)_ | List of ClusterRoles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying this field are ClusterRoleBindings. |  | Optional: \{\} <br /> |
| `roleBindings` _[NamespaceBinding](#namespacebinding) array_ | List of ClusterRoles/Roles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying the field are RoleBindings. |  | Optional: \{\} <br /> |
| `automountServiceAccountToken` _boolean_ | AutomountServiceAccountToken controls whether to automount API credentials for ServiceAccounts<br />created by this BindDefinition. Defaults to true for backward compatibility with Kubernetes<br />native ServiceAccount behavior. Set to false to improve security by preventing automatic<br />token mounting.<br />Only applies when Subjects contain ServiceAccount entries that need to be auto-created. | true | Optional: \{\} <br /> |


#### BindDefinitionStatus



BindDefinitionStatus defines the observed state of BindDefinition.



_Appears in:_
- [BindDefinition](#binddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource.<br />This is used by kstatus to determine if the resource is current. |  | Optional: \{\} <br /> |
| `bindReconciled` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify completed reconciliation. |  | Optional: \{\} <br /> |
| `generatedServiceAccounts` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#subject-v1-rbac) array_ | If the BindDefinition points to a subject of "Kind: ServiceAccount" and the service account is not present. The controller will reconcile it automatically. |  | Optional: \{\} <br /> |
| `missingRoleRefs` _string array_ | MissingRoleRefs lists role references that could not be resolved during the<br />last reconciliation. Format: "ClusterRole/<name>" or "Role/<namespace>/<name>".<br />Empty when all referenced roles exist. |  | Optional: \{\} <br /> |
| `externalServiceAccounts` _string array_ | ExternalServiceAccounts lists ServiceAccounts referenced by this BindDefinition<br />that already existed and are not owned by any BindDefinition. These SAs are used<br />in bindings but not managed (created/deleted) by the controller.<br />Format: "<namespace>/<name>". |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Bind definition. All conditions should evaluate to true to signify successful reconciliation. |  | Optional: \{\} <br /> |




#### ClusterBinding



ClusterBinding defines cluster-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | Optional: \{\} <br /> |


#### NamespaceBinding



NamespaceBinding defines namespace-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | Optional: \{\} <br /> |
| `roleRefs` _string array_ | RoleRefs references a specific Role that has to exist in the target namespaces |  | Optional: \{\} <br /> |
| `namespace` _string_ | Namespace of the Role that should be bound to the subjects. |  | Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta) array_ | NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s. |  | Optional: \{\} <br /> |


#### Principal



Principal represents a requesting user or service account identity.



_Appears in:_
- [WebhookAuthorizerSpec](#webhookauthorizerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `user` _string_ | User is the requesting user in SubjectAccessReview request. |  | Optional: \{\} <br /> |
| `groups` _string array_ | Groups is the requesting user groups in SubjectAccessReview request. |  | Optional: \{\} <br /> |
| `namespace` _string_ | Namespace is the requesting user namespace in case the requesting user is a ServiceAccount. |  | Optional: \{\} <br /> |


#### RoleDefinition



RoleDefinition is the Schema for the roledefinitions API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RoleDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RoleDefinitionSpec](#roledefinitionspec)_ |  |  |  |
| `status` _[RoleDefinitionStatus](#roledefinitionstatus)_ |  |  |  |


#### RoleDefinitionSpec



RoleDefinitionSpec defines the desired state of RoleDefinition.



_Appears in:_
- [RoleDefinition](#roledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `targetRole` _string_ | TargetRole is the role type that will be reconciled. This can be a ClusterRole or a namespaced Role. |  | Enum: [ClusterRole Role] <br />Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name of the target role. This can be any name that accurately describes the ClusterRole/Role.<br />Must be a valid Kubernetes name (max 63 characters for most resources). |  | MaxLength: 63 <br />MinLength: 5 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `targetNamespace` _string_ | TargetNamespace is the target namespace for the Role. Required when "TargetRole" is "Role". |  | Optional: \{\} <br /> |
| `scopeNamespaced` _boolean_ | ScopeNamespaced controls whether the API resource is namespaced or not. This can also be checked by<br />running `kubectl api-resources --namespaced=true/false`. |  | Required: \{\} <br /> |
| `restrictedApis` _[APIGroup](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apigroup-v1-meta) array_ | RestrictedAPIs holds all API groups which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all API groups available and removes those which are defined here.<br />When Versions is empty (versions: []), all versions of that group are restricted.<br />When Versions is specified, only those API versions are excluded from resource discovery.<br />Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource exists in<br />a non-restricted version of the same group, it will still appear in the generated role. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apiresource-v1-meta) array_ | RestrictedResources holds all resources which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all API resources available and removes those listed here. |  | Optional: \{\} <br /> |
| `restrictedVerbs` _string array_ | RestrictedVerbs holds all verbs which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all resource verbs available and removes those listed here. |  | Optional: \{\} <br /> |


#### RoleDefinitionStatus



RoleDefinitionStatus defines the observed state of RoleDefinition.



_Appears in:_
- [RoleDefinition](#roledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource.<br />This is used by kstatus to determine if the resource is current. |  | Optional: \{\} <br /> |
| `roleReconciled` _boolean_ | RoleReconciled indicates whether the target role has been successfully reconciled. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Role definition. All conditions should evaluate to true to signify successful reconciliation. |  | Optional: \{\} <br /> |




#### WebhookAuthorizer



WebhookAuthorizer is the Schema for the webhookauthorizers API.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `WebhookAuthorizer` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[WebhookAuthorizerSpec](#webhookauthorizerspec)_ |  |  |  |
| `status` _[WebhookAuthorizerStatus](#webhookauthorizerstatus)_ |  |  |  |


#### WebhookAuthorizerSpec



WebhookAuthorizerSpec defines the desired state of WebhookAuthorizer.



_Appears in:_
- [WebhookAuthorizer](#webhookauthorizer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `resourceRules` _[ResourceRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#resourcerule-v1-authorization) array_ | Resources which will be used to evaluate the SubjectAccessReviewSpec.ResourceAttributes |  | Optional: \{\} <br /> |
| `nonResourceRules` _[NonResourceRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#nonresourcerule-v1-authorization) array_ | Resources which will be used to evaluate the SubjectAccessReviewSpec.NonResourceAttributes |  | Optional: \{\} <br /> |
| `allowedPrincipals` _[Principal](#principal) array_ | AllowedPrincipals is a slice of principals this authorizer should allow. |  | Optional: \{\} <br /> |
| `deniedPrincipals` _[Principal](#principal) array_ | DeniedPrincipals is a slice of principals this authorizer should deny. |  | Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | NamespaceSelector is a label selector to match namespaces that should allow the specified API calls. |  | Optional: \{\} <br /> |


#### WebhookAuthorizerStatus



WebhookAuthorizerStatus defines the observed state of WebhookAuthorizer.



_Appears in:_
- [WebhookAuthorizer](#webhookauthorizer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource.<br />This is used by kstatus to determine if the resource is current. |  | Optional: \{\} <br /> |
| `authorizerConfigured` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify webhook authorizer as configured. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Webhook authorizer. All conditions should evaluate to true to signify successful configuration. |  | Optional: \{\} <br /> |



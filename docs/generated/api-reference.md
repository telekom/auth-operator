# API Reference

## Packages
- [authorization.t-caas.telekom.com/v1alpha1](#authorizationt-caastelekomcomv1alpha1)


## authorization.t-caas.telekom.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the authorization v1alpha1 API group

### Resource Types
- [BindDefinition](#binddefinition)
- [RBACPolicy](#rbacpolicy)
- [RestrictedBindDefinition](#restrictedbinddefinition)
- [RestrictedRoleDefinition](#restrictedroledefinition)
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
| `targetName` _string_ | Name that will be prefixed to the concatenated string which is the name of the binding. Follows format "targetName-clusterrole/role-binding" where clusterrole/role is the in-cluster existing ClusterRole or Role.<br />This field is immutable after creation; changing it would orphan existing bindings and service accounts. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `subjects` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#subject-v1-rbac) array_ | List of subjects that will be bound to a target ClusterRole/Role. Can be "User", "Group" or "ServiceAccount". |  | MaxItems: 256 <br />Required: \{\} <br /> |
| `clusterRoleBindings` _[ClusterBinding](#clusterbinding)_ | List of ClusterRoles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying this field are ClusterRoleBindings. |  | Optional: \{\} <br /> |
| `roleBindings` _[NamespaceBinding](#namespacebinding) array_ | List of ClusterRoles/Roles to which subjects will be bound to. The list is a RoleRef which means we have to specify the full rbacv1.RoleRef schema. The result of specifying the field are RoleBindings. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `automountServiceAccountToken` _boolean_ | AutomountServiceAccountToken controls whether to automount API credentials for ServiceAccounts<br />created by this BindDefinition. Defaults to true for backward compatibility with Kubernetes<br />native ServiceAccount behavior.<br />Security: When enabled (default), pods using ServiceAccounts created by this BindDefinition<br />receive a projected token that grants access to the Kubernetes API with the permissions<br />defined by the associated ClusterRoleBindings/RoleBindings. Set to false for workloads that<br />do not require in-cluster API access to follow the principle of least privilege.<br />Only applies when Subjects contain ServiceAccount entries that need to be auto-created. | true | Optional: \{\} <br /> |


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




#### BindingLimits



BindingLimits defines constraints on role bindings created by restricted definitions.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowClusterRoleBindings` _boolean_ | AllowClusterRoleBindings controls whether ClusterRoleBindings may be created.<br />Default is false (deny by default). | false | Optional: \{\} <br /> |
| `clusterRoleBindingLimits` _[RoleRefLimits](#rolereflimits)_ | ClusterRoleBindingLimits constrains which ClusterRoles may be referenced in CRBs. |  | Optional: \{\} <br /> |
| `roleBindingLimits` _[RoleRefLimits](#rolereflimits)_ | RoleBindingLimits constrains which ClusterRoles/Roles may be referenced in RBs. |  | Optional: \{\} <br /> |
| `targetNamespaceLimits` _[NamespaceLimits](#namespacelimits)_ | TargetNamespaceLimits constrains which namespaces may be targeted. |  | Optional: \{\} <br /> |


#### ClusterBinding



ClusterBinding defines cluster-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)
- [RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | MaxItems: 64 <br />Optional: \{\} <br /> |




#### NameMatchLimits



NameMatchLimits defines name-based allow/deny patterns for subjects.



_Appears in:_
- [SubjectLimits](#subjectlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNames` _string array_ | AllowedNames is a list of allowed subject names. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `forbiddenNames` _string array_ | ForbiddenNames is a list of forbidden subject names. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `allowedPrefixes` _string array_ | AllowedPrefixes is a list of allowed name prefixes. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `forbiddenPrefixes` _string array_ | ForbiddenPrefixes is a list of forbidden name prefixes. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `allowedSuffixes` _string array_ | AllowedSuffixes is a list of allowed name suffixes. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `forbiddenSuffixes` _string array_ | ForbiddenSuffixes is a list of forbidden name suffixes. |  | MaxItems: 64 <br />Optional: \{\} <br /> |


#### NamespaceBinding



NamespaceBinding defines namespace-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)
- [RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `roleRefs` _string array_ | RoleRefs references a specific Role that has to exist in the target namespaces |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `namespace` _string_ | Namespace of the Role that should be bound to the subjects. |  | Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta) array_ | NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s. |  | MaxItems: 16 <br />Optional: \{\} <br /> |


#### NamespaceLimits



NamespaceLimits controls which namespaces can be targeted by bindings.



_Appears in:_
- [BindingLimits](#bindinglimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedNamespaceSelector selects allowed namespaces by label. |  | Optional: \{\} <br /> |
| `forbiddenNamespaces` _string array_ | ForbiddenNamespaces is a list of namespace names that may not be targeted. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `forbiddenNamespacePrefixes` _string array_ | ForbiddenNamespacePrefixes is a list of namespace name prefixes that may not be targeted. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `maxTargetNamespaces` _integer_ | MaxTargetNamespaces limits the number of target namespaces per binding. |  | Minimum: 0 <br />Optional: \{\} <br /> |


#### PolicyScope



PolicyScope defines which namespaces this policy governs.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | NamespaceSelector selects namespaces by label selector. |  | Optional: \{\} <br /> |
| `namespaces` _string array_ | Namespaces is an explicit list of namespace names. |  | MaxItems: 256 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br /> |


#### Principal



Principal represents a requesting user or service account identity.



_Appears in:_
- [WebhookAuthorizerSpec](#webhookauthorizerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `user` _string_ | User is the requesting user in SubjectAccessReview request. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `groups` _string array_ | Groups is the requesting user groups in SubjectAccessReview request. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `namespace` _string_ | Namespace is the requesting user namespace in case the requesting user is a ServiceAccount. |  | MaxLength: 253 <br />Optional: \{\} <br /> |


#### RBACPolicy



RBACPolicy is the Schema for the rbacpolicies API.
It defines RBAC guardrails that RestrictedBindDefinitions and
RestrictedRoleDefinitions must comply with.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RBACPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RBACPolicySpec](#rbacpolicyspec)_ |  |  |  |
| `status` _[RBACPolicyStatus](#rbacpolicystatus)_ |  |  |  |


#### RBACPolicyReference



RBACPolicyReference is a reference to an RBACPolicy that governs a restricted resource.



_Appears in:_
- [RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)
- [RestrictedRoleDefinitionSpec](#restrictedroledefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the RBACPolicy. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |


#### RBACPolicySpec



RBACPolicySpec defines the desired state of RBACPolicy.



_Appears in:_
- [RBACPolicy](#rbacpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `appliesTo` _[PolicyScope](#policyscope)_ | AppliesTo defines the namespace scope this policy governs. |  | Required: \{\} <br /> |
| `bindingLimits` _[BindingLimits](#bindinglimits)_ | BindingLimits constrains role bindings that may be created. |  | Optional: \{\} <br /> |
| `roleLimits` _[RoleLimits](#rolelimits)_ | RoleLimits constrains roles that may be generated. |  | Optional: \{\} <br /> |
| `subjectLimits` _[SubjectLimits](#subjectlimits)_ | SubjectLimits constrains the subjects a tenant may use. |  | Optional: \{\} <br /> |


#### RBACPolicyStatus



RBACPolicyStatus defines the observed state of RBACPolicy.



_Appears in:_
- [RBACPolicy](#rbacpolicy)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource. |  | Optional: \{\} <br /> |
| `boundResourceCount` _integer_ | BoundResourceCount is the number of RestrictedBindDefinitions and<br />RestrictedRoleDefinitions currently referencing this policy. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the RBACPolicy. |  | Optional: \{\} <br /> |




#### ResourceVerbRule



ResourceVerbRule specifies a forbidden combination of resource, API group, and verbs.



_Appears in:_
- [RoleLimits](#rolelimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `resource` _string_ | Resource is the resource name (e.g., "pods", "secrets"). |  | MinLength: 1 <br />Required: \{\} <br /> |
| `apiGroup` _string_ | APIGroup is the API group of the resource. Empty string means core group. |  | Optional: \{\} <br /> |
| `verbs` _string array_ | Verbs are the verbs forbidden on this resource. |  | MinItems: 1 <br />Required: \{\} <br /> |


#### RestrictedBindDefinition



RestrictedBindDefinition is the Schema for the restrictedbinddefinitions API.
It is similar to BindDefinition but requires a policy reference and enforces
RBAC guardrails defined by the referenced RBACPolicy.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RestrictedBindDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)_ |  |  |  |
| `status` _[RestrictedBindDefinitionStatus](#restrictedbinddefinitionstatus)_ |  |  |  |


#### RestrictedBindDefinitionSpec



RestrictedBindDefinitionSpec defines the desired state of RestrictedBindDefinition.



_Appears in:_
- [RestrictedBindDefinition](#restrictedbinddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[RBACPolicyReference](#rbacpolicyreference)_ | PolicyRef references the RBACPolicy that governs this binding. |  | Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name prefix for generated bindings. Follows format<br />"targetName-clusterrole/role-binding".<br />This field is immutable after creation. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `subjects` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#subject-v1-rbac) array_ | Subjects lists the subjects that will be bound to the target ClusterRole/Role.<br />Can be "User", "Group" or "ServiceAccount". |  | MaxItems: 256 <br />Required: \{\} <br /> |
| `clusterRoleBindings` _[ClusterBinding](#clusterbinding)_ | ClusterRoleBindings defines cluster-scoped role bindings. |  | Optional: \{\} <br /> |
| `roleBindings` _[NamespaceBinding](#namespacebinding) array_ | RoleBindings defines namespace-scoped role bindings. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `automountServiceAccountToken` _boolean_ | AutomountServiceAccountToken controls whether to automount API credentials<br />for ServiceAccounts created by this RestrictedBindDefinition. | true | Optional: \{\} <br /> |


#### RestrictedBindDefinitionStatus



RestrictedBindDefinitionStatus defines the observed state of RestrictedBindDefinition.



_Appears in:_
- [RestrictedBindDefinition](#restrictedbinddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource. |  | Optional: \{\} <br /> |
| `bindReconciled` _boolean_ | BindReconciled indicates whether bindings have been successfully reconciled. |  | Optional: \{\} <br /> |
| `generatedServiceAccounts` _[Subject](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#subject-v1-rbac) array_ | GeneratedServiceAccounts lists ServiceAccounts that were auto-created. |  | Optional: \{\} <br /> |
| `missingRoleRefs` _string array_ | MissingRoleRefs lists role references that could not be resolved.<br />Format: "ClusterRole/<name>" or "Role/<namespace>/<name>". |  | Optional: \{\} <br /> |
| `externalServiceAccounts` _string array_ | ExternalServiceAccounts lists ServiceAccounts referenced by this RestrictedBindDefinition<br />that were not created by the controller.<br />Format: "<namespace>/<name>". |  | Optional: \{\} <br /> |
| `policyViolations` _string array_ | PolicyViolations lists policy violations detected during the last reconciliation.<br />Empty when all checks pass. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state. |  | Optional: \{\} <br /> |




#### RestrictedRoleDefinition



RestrictedRoleDefinition is the Schema for the restrictedroledefinitions API.
It is similar to RoleDefinition but requires a policy reference and enforces
RBAC guardrails defined by the referenced RBACPolicy.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RestrictedRoleDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RestrictedRoleDefinitionSpec](#restrictedroledefinitionspec)_ |  |  |  |
| `status` _[RestrictedRoleDefinitionStatus](#restrictedroledefinitionstatus)_ |  |  |  |


#### RestrictedRoleDefinitionSpec



RestrictedRoleDefinitionSpec defines the desired state of RestrictedRoleDefinition.



_Appears in:_
- [RestrictedRoleDefinition](#restrictedroledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[RBACPolicyReference](#rbacpolicyreference)_ | PolicyRef references the RBACPolicy that governs this role definition. |  | Required: \{\} <br /> |
| `targetRole` _string_ | TargetRole is the role type that will be reconciled: ClusterRole or Role.<br />This field is immutable after creation. |  | Enum: [ClusterRole Role] <br />Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name of the target role.<br />This field is immutable after creation. |  | MaxLength: 63 <br />MinLength: 5 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `targetNamespace` _string_ | TargetNamespace is the target namespace for the Role.<br />Required when "TargetRole" is "Role". |  | Optional: \{\} <br /> |
| `scopeNamespaced` _boolean_ | ScopeNamespaced controls whether the API resource filter includes<br />namespaced or cluster-scoped resources. |  | Required: \{\} <br /> |
| `restrictedApis` _[APIGroup](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apigroup-v1-meta) array_ | RestrictedAPIs holds API groups which will NOT be included in the generated role. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apiresource-v1-meta) array_ | RestrictedResources holds resources which will NOT be included in the generated role. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `restrictedVerbs` _string array_ | RestrictedVerbs holds verbs which will NOT be included in the generated role. |  | MaxItems: 16 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: ^([a-z]+\|\*)$ <br /> |


#### RestrictedRoleDefinitionStatus



RestrictedRoleDefinitionStatus defines the observed state of RestrictedRoleDefinition.



_Appears in:_
- [RestrictedRoleDefinition](#restrictedroledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource. |  | Optional: \{\} <br /> |
| `roleReconciled` _boolean_ | RoleReconciled indicates whether the target role has been successfully reconciled. |  | Optional: \{\} <br /> |
| `policyViolations` _string array_ | PolicyViolations lists policy violations detected during the last reconciliation. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state. |  | Optional: \{\} <br /> |




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
| `targetRole` _string_ | TargetRole is the role type that will be reconciled. This can be a ClusterRole or a namespaced Role.<br />This field is immutable after creation; changing it would orphan the generated role and its bindings. |  | Enum: [ClusterRole Role] <br />Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name of the target role. This can be any name that accurately describes the ClusterRole/Role.<br />Must be a valid Kubernetes name (max 63 characters for most resources).<br />This field is immutable after creation; changing it would orphan the generated role and its bindings. |  | MaxLength: 63 <br />MinLength: 5 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
| `targetNamespace` _string_ | TargetNamespace is the target namespace for the Role. Required when "TargetRole" is "Role". |  | Optional: \{\} <br /> |
| `scopeNamespaced` _boolean_ | ScopeNamespaced controls whether the API resource is namespaced or not. This can also be checked by<br />running `kubectl api-resources --namespaced=true/false`. |  | Required: \{\} <br /> |
| `restrictedApis` _[APIGroup](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apigroup-v1-meta) array_ | RestrictedAPIs holds all API groups which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all API groups available and removes those which are defined here.<br />When Versions is empty (versions: []), all versions of that group are restricted.<br />When Versions is specified, only those API versions are excluded from resource discovery.<br />Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource exists in<br />a non-restricted version of the same group, it will still appear in the generated role. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apiresource-v1-meta) array_ | RestrictedResources holds all resources which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all API resources available and removes those listed here. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `restrictedVerbs` _string array_ | RestrictedVerbs holds all verbs which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all resource verbs available and removes those listed here. |  | MaxItems: 16 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: ^([a-z]+\|\*)$ <br /> |
| `breakglassAllowed` _boolean_ | BreakglassAllowed marks generated ClusterRoles as eligible for temporary<br />privilege escalation via k8s-breakglass. The generated ClusterRole always<br />receives the label t-caas.telekom.com/breakglass-compatible set to "true"<br />or "false" based on this field's value.<br />Only applicable when TargetRole is ClusterRole. Defaults to false. | false | Optional: \{\} <br /> |
| `aggregationLabels` _object (keys:string, values:string)_ | AggregationLabels are additional labels applied to the generated ClusterRole so that<br />it participates in Kubernetes' built-in ClusterRole aggregation mechanism.<br />For example, setting `rbac.authorization.k8s.io/aggregate-to-view: "true"` causes the<br />generated ClusterRole's rules to be aggregated into the default "view" ClusterRole.<br />Only applicable when targetRole is ClusterRole. |  | Optional: \{\} <br /> |
| `aggregateFrom` _[AggregationRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#aggregationrule-v1-rbac)_ | AggregateFrom generates an aggregating ClusterRole that uses label selectors<br />to compose rules from other ClusterRoles, instead of specifying rules directly.<br />When set, the controller skips API discovery and filtering; the generated ClusterRole<br />carries an aggregationRule and its rules[] are managed by the RBAC aggregation controller.<br />Mutually exclusive with RestrictedAPIs, RestrictedResources, and RestrictedVerbs.<br />Only applicable when targetRole is ClusterRole. |  | Optional: \{\} <br /> |


#### RoleDefinitionStatus



RoleDefinitionStatus defines the observed state of RoleDefinition.



_Appears in:_
- [RoleDefinition](#roledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource.<br />This is used by kstatus to determine if the resource is current. |  | Optional: \{\} <br /> |
| `roleReconciled` _boolean_ | RoleReconciled indicates whether the target role has been successfully reconciled. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Role definition. All conditions should evaluate to true to signify successful reconciliation. |  | Optional: \{\} <br /> |




#### RoleLimits



RoleLimits defines constraints on roles created by RestrictedRoleDefinitions.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowClusterRoles` _boolean_ | AllowClusterRoles controls whether ClusterRoles may be generated.<br />Default is false (deny by default). | false | Optional: \{\} <br /> |
| `forbiddenVerbs` _string array_ | ForbiddenVerbs is a list of verbs that must not appear in generated roles. |  | MaxItems: 16 <br />Optional: \{\} <br /> |
| `forbiddenResources` _string array_ | ForbiddenResources is a list of resources that must not appear in generated roles. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `forbiddenAPIGroups` _string array_ | ForbiddenAPIGroups is a list of API groups that must not appear in generated roles. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `forbiddenResourceVerbs` _[ResourceVerbRule](#resourceverbrule) array_ | ForbiddenResourceVerbs is a list of specific resource+verb combinations that are forbidden. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `maxRulesPerRole` _integer_ | MaxRulesPerRole limits the number of rules in a single generated role. |  | Minimum: 1 <br />Optional: \{\} <br /> |


#### RoleRefLimits



RoleRefLimits controls which role references are allowed or forbidden.



_Appears in:_
- [BindingLimits](#bindinglimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedRoleRefs` _string array_ | AllowedRoleRefs is a list of allowed role names. Supports simple wildcards:<br />"prefix*" and "*suffix". An empty list means no role refs are allowed (default-deny). |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `allowedRoleRefSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedRoleRefSelector selects allowed roles by label. |  | Optional: \{\} <br /> |
| `forbiddenRoleRefs` _string array_ | ForbiddenRoleRefs is a list of explicitly forbidden role names.<br />Takes precedence over AllowedRoleRefs. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `forbiddenRoleRefSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | ForbiddenRoleRefSelector selects forbidden roles by label. |  | Optional: \{\} <br /> |


#### SACreationConfig



SACreationConfig controls ServiceAccount auto-creation behaviour.



_Appears in:_
- [ServiceAccountLimits](#serviceaccountlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowAutoCreate` _boolean_ | AllowAutoCreate controls whether ServiceAccounts may be auto-created. | false | Optional: \{\} <br /> |
| `allowedCreationNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedCreationNamespaceSelector selects namespaces where SA creation is allowed. |  | Optional: \{\} <br /> |
| `allowedCreationNamespaces` _string array_ | AllowedCreationNamespaces is an explicit list of namespaces where SA creation is allowed. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `automountServiceAccountToken` _boolean_ | AutomountServiceAccountToken controls automount for auto-created SAs. |  | Optional: \{\} <br /> |
| `disableAdoption` _boolean_ | DisableAdoption prevents adoption of pre-existing ServiceAccounts. | false | Optional: \{\} <br /> |




#### ServiceAccountLimits



ServiceAccountLimits defines constraints on ServiceAccount subjects.



_Appears in:_
- [SubjectLimits](#subjectlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedNamespaceSelector selects namespaces whose SAs may be referenced. |  | Optional: \{\} <br /> |
| `forbiddenNamespaces` _string array_ | ForbiddenNamespaces is a list of namespaces whose SAs may not be referenced. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `forbiddenNamespacePrefixes` _string array_ | ForbiddenNamespacePrefixes is a list of namespace prefixes to deny. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `creation` _[SACreationConfig](#sacreationconfig)_ | Creation constrains ServiceAccount auto-creation behaviour. |  | Optional: \{\} <br /> |


#### SubjectLimits



SubjectLimits defines constraints on the subjects a tenant may use.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedKinds` _string array_ | AllowedKinds controls which subject kinds are allowed.<br />Valid values: "User", "Group", "ServiceAccount".<br />An empty list means no subject kinds are allowed (default-deny). |  | MaxItems: 3 <br />Optional: \{\} <br /> |
| `forbiddenKinds` _string array_ | ForbiddenKinds lists subject kinds that are explicitly forbidden.<br />Takes precedence over AllowedKinds. |  | MaxItems: 3 <br />Optional: \{\} <br /> |
| `userLimits` _[NameMatchLimits](#namematchlimits)_ | UserLimits constrains User subject names. |  | Optional: \{\} <br /> |
| `groupLimits` _[NameMatchLimits](#namematchlimits)_ | GroupLimits constrains Group subject names. |  | Optional: \{\} <br /> |
| `serviceAccountLimits` _[ServiceAccountLimits](#serviceaccountlimits)_ | ServiceAccountLimits constrains ServiceAccount subjects. |  | Optional: \{\} <br /> |




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
| `resourceRules` _[ResourceRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#resourcerule-v1-authorization) array_ | Resources which will be used to evaluate the SubjectAccessReviewSpec.ResourceAttributes |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `nonResourceRules` _[NonResourceRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#nonresourcerule-v1-authorization) array_ | Resources which will be used to evaluate the SubjectAccessReviewSpec.NonResourceAttributes |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `allowedPrincipals` _[Principal](#principal) array_ | AllowedPrincipals is a slice of principals this authorizer should allow. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `deniedPrincipals` _[Principal](#principal) array_ | DeniedPrincipals is a slice of principals this authorizer should deny. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
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





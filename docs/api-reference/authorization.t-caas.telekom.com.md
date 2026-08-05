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
Write access is intended for platform-admin or trusted-admin workflows
because generated bindings affect real Kubernetes RBAC.
Use RestrictedBindDefinition under an RBACPolicy for delegated workflows.





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
| `targetName` _string_ | Name that will be prefixed to the concatenated string which is the name of the binding. Follows format "targetName-clusterrole-role-binding" where clusterrole/role is the in-cluster existing ClusterRole or Role.<br />This field is immutable after creation; changing it would orphan existing bindings and service accounts.<br />MaxLength=253 is the full Kubernetes object name limit. Unlike RestrictedBindDefinition,<br />BindDefinition uses the referenced role name (not a fixed suffix) when constructing binding names,<br />so callers are responsible for ensuring the combined name stays within Kubernetes limits. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
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
| `clusterRoleBindingLimits` _[RoleRefLimits](#rolereflimits)_ | ClusterRoleBindingLimits constrains which ClusterRoles may be referenced<br />from ClusterRoleBindings or RoleBindings. |  | Optional: \{\} <br /> |
| `roleBindingLimits` _[RoleRefLimits](#rolereflimits)_ | RoleBindingLimits constrains which namespaced Roles may be referenced in RoleBindings. |  | Optional: \{\} <br /> |
| `targetNamespaceLimits` _[NamespaceLimits](#namespacelimits)_ | TargetNamespaceLimits constrains which namespaces may be targeted. |  | Optional: \{\} <br /> |


#### ClusterBinding



ClusterBinding defines cluster-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)
- [RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |


#### ConstrainedImpersonationLimits



ConstrainedImpersonationLimits constrains Kubernetes constrained impersonation
(KEP-5284) grants that RestrictedRoleDefinitions may declare.

This complements RoleLimits.ForbiddenVerbs and
RoleLimits.ForbiddenResourceVerbs, which can also match generated
`impersonate:<mode>` / `impersonate-on:<mode>:<verb>` verbs directly. The
dedicated block exists because the generated verbs are synthesised by the
operator rather than authored by the tenant, so a verb-string denylist alone is
easy to bypass by choosing a different mode.



_Appears in:_
- [RoleLimits](#rolelimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowed` _boolean_ | Allowed enables constrained impersonation grants under this policy.<br />Defaults to false (deny by default). | false | Optional: \{\} <br /> |
| `allowedModes` _[ImpersonationMode](#impersonationmode) array_ | AllowedModes restricts which impersonation modes may be used. An empty list<br />with allowed=true permits every mode. |  | Enum: [user-info serviceaccount arbitrary-node associated-node] <br />MaxItems: 4 <br />Optional: \{\} <br /> |
| `allowedIdentityResources` _[ImpersonationIdentityResource](#impersonationidentityresource) array_ | AllowedIdentityResources restricts which identity resources may be granted.<br />An empty list with allowed=true permits every identity resource. |  | Enum: [users groups uids userextras serviceaccounts nodes] <br />MaxItems: 6 <br />Optional: \{\} <br /> |
| `identityNameLimits` _[NameMatchLimits](#namematchlimits)_ | IdentityNameLimits constrains the identity names (resourceNames) a tenant may<br />list in identity rules, using the same allow/deny prefix and suffix semantics<br />as subject limits. |  | Optional: \{\} <br /> |
| `forbiddenActionVerbs` _string array_ | ForbiddenActionVerbs lists underlying request verbs that must not appear in<br />action rules. Entries are the bare verbs (e.g. "delete"), not the<br />`impersonate-on:<mode>:` encoded form. |  | MaxItems: 32 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbidLegacyFallback` _boolean_ | ForbidLegacyFallback requires that the RestrictedRoleDefinition also excludes<br />the legacy bare "impersonate" verb via restrictedVerbs. This closes knob #8 of<br />the KEP integration surface: a pre-existing blanket `impersonate` grant wins by<br />fallback and silently defeats every constraint expressed here. | false | Optional: \{\} <br /> |
| `maxIdentityNames` _integer_ | MaxIdentityNames limits how many identity names a single grant may allowlist<br />across all identity rules. Nil means unlimited. |  | Minimum: 1 <br />Optional: \{\} <br /> |


#### ConstrainedImpersonationSpec



ConstrainedImpersonationSpec is the first-class, typed expression of a
Kubernetes constrained impersonation (KEP-5284) grant. The operator translates
it into the exact RBAC PolicyRules the apiserver expects, so operators do not
need to hand-write magic verb strings such as "impersonate-on:user-info:list".

IMPORTANT — grants union, they do not correlate. The effective permission is
the full cross product of every granted identity and every granted action. It
is not possible to express "userA only for pods AND userB only for secrets" in
a single grant; use two separate RoleDefinitions bound to different subjects.



_Appears in:_
- [RestrictedRoleDefinitionSpec](#restrictedroledefinitionspec)
- [RoleDefinitionSpec](#roledefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `mode` _[ImpersonationMode](#impersonationmode)_ | Mode selects the constrained impersonation mode the generated verbs target. |  | Enum: [user-info serviceaccount arbitrary-node associated-node] <br />Required: \{\} <br /> |
| `identities` _[ImpersonationIdentityRule](#impersonationidentityrule) array_ | Identities are the identity allowlist rules. They generate cluster-scoped<br />PolicyRules in the authentication.k8s.io API group with the<br />`impersonate:<mode>` verb. |  | MaxItems: 32 <br />MinItems: 1 <br />Required: \{\} <br /> |
| `actions` _[ImpersonationActionRule](#impersonationactionrule) array_ | Actions are the action rules describing which requests may be made while<br />impersonating. They generate PolicyRules with `impersonate-on:<mode>:<verb>`<br />verbs against the target resources.<br />An empty Actions list produces an identity-only grant, which by itself<br />authorizes nothing: the apiserver runs the action check FIRST and falls back<br />to legacy impersonation when it fails. Admission emits a warning in that case. |  | MaxItems: 32 <br />Optional: \{\} <br /> |


#### DefaultPolicyAssignment



DefaultPolicyAssignment defines identities that must use this policy by default
when creating RestrictedBindDefinition/RestrictedRoleDefinition resources.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `groups` _string array_ | Groups lists requester group names for which this policy is the default. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `serviceAccounts` _[SARef](#saref) array_ | ServiceAccounts lists requester ServiceAccounts for which this policy is the default. |  | MaxItems: 128 <br />Optional: \{\} <br /> |


#### ImpersonationActionRule



ImpersonationActionRule grants permission to perform specific verbs on specific
target resources *while* impersonating in the declared mode. Each rule becomes
one RBAC PolicyRule carrying `impersonate-on:<mode>:<verb>` verbs against the
target request's own API group, resource and namespace — there is no group
override, so apiGroups/resources describe the impersonated request's target.



_Appears in:_
- [ConstrainedImpersonationSpec](#constrainedimpersonationspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiGroups` _string array_ | APIGroups are the target API groups. Use "" for the core group and "*" for<br />all groups. |  | MaxItems: 32 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 253 <br /> |
| `resources` _string array_ | Resources are the target resources, optionally with a subresource<br />("pods/log"). Use "*" for all resources. |  | MaxItems: 64 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |
| `resourceNames` _string array_ | ResourceNames optionally restricts the target resource names. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |
| `verbs` _string array_ | Verbs are the *underlying* request verbs, e.g. ["get", "list", "watch"].<br />The operator rewrites each entry to `impersonate-on:<mode>:<verb>`; do not<br />pre-encode the prefix here.<br />The apiserver has no prefix wildcard for action verbs: "*" is accepted by<br />RBAC as a full wildcard, but "impersonate-on:<mode>:*" is not a thing.<br />Passing "*" therefore emits the bare "*" verb, which grants every verb<br />including plain (non-impersonated) access, so it is rejected by validation. |  | MaxItems: 32 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: `^[a-z][a-z0-9]*$` <br /> |


#### ImpersonationConfig



ImpersonationConfig controls apply-time impersonation for
RestrictedBindDefinition and RestrictedRoleDefinition reconciliation.
RBACPolicy write access is a cluster trust boundary: a policy author can choose
any identity here, and admission only validates structural correctness. The
impersonated identity's own Kubernetes RBAC is the authoritative permission
check during apply operations.

### The header-mixing trap (KEP-5284)

The apiserver selects the `serviceaccount` and node constrained-impersonation
modes only when the Impersonate-User header is the ONLY impersonation header
set. Sending Impersonate-Uid, Impersonate-Group or Impersonate-Extra-* alongside
a `system:serviceaccount:...` or `system:node:...` username silently skips those
modes, falls through to `user-info` (which refuses node and ServiceAccount
usernames) and finally to legacy impersonation. Admission therefore rejects
combining ServiceAccountRef with UID, Groups or Extra.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `enabled` _boolean_ | Enabled enables impersonation during restricted resource apply operations. | false | Optional: \{\} <br /> |
| `serviceAccountRef` _[SARef](#saref)_ | ServiceAccountRef is the ServiceAccount identity used for impersonated apply<br />operations, rendered as system:serviceaccount:<namespace>:<name>. Exactly one<br />of ServiceAccountRef or UserName is required when enabled is true.<br />Mutually exclusive with UID, Groups and Extra — see the header-mixing trap in<br />the type documentation. |  | Optional: \{\} <br /> |
| `userName` _string_ | UserName is a raw impersonated username, used instead of ServiceAccountRef<br />when the apply identity is not a ServiceAccount. Combined with UID, Groups and<br />Extra this expresses the full `user-info` constrained-impersonation identity.<br />A `system:node:<name>` username is rejected: node impersonation forces<br />Groups=[system:nodes] and is not a meaningful apply identity for this operator. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `uid` _string_ | UID is the impersonated UID, sent as the Impersonate-Uid header. Requires<br />UserName and is checked by the apiserver against<br />authentication.k8s.io/uids with the `impersonate:user-info` verb. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `groups` _string array_ | Groups are the impersonated groups, sent as repeated Impersonate-Group<br />headers. Requires UserName. "system:masters" is rejected because constrained<br />impersonation hard-denies it.<br />Note: at four or more groups the apiserver first attempts a single wildcard<br />("*") group authorization check before falling back to per-group checks. |  | MaxItems: 32 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |
| `extra` _[ImpersonationExtra](#impersonationextra) array_ | Extra are the impersonated extra values, sent as Impersonate-Extra-<key><br />headers. Requires UserName. |  | MaxItems: 16 <br />Optional: \{\} <br /> |
| `mode` _[ImpersonationMode](#impersonationmode)_ | Mode records which constrained-impersonation mode the configured identity is<br />expected to select. It is advisory: the apiserver derives the mode from the<br />username and header set, it cannot be chosen by the client. Admission verifies<br />that the configured identity actually selects the declared mode, turning a<br />silent legacy fallback into an admission error. |  | Enum: [user-info serviceaccount arbitrary-node associated-node] <br />Optional: \{\} <br /> |


#### ImpersonationExtra



ImpersonationExtra is a single Impersonate-Extra-<key> entry used for
apply-time impersonation.



_Appears in:_
- [ImpersonationConfig](#impersonationconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `key` _string_ | Key is the extra key. It must be a lowercase, domain-prefixed path, matching<br />the apiserver's constrained-impersonation validateExtra() rules. |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `values` _string array_ | Values are the extra values for Key. At least one non-empty value is required;<br />the apiserver denies empty value lists and empty-string values. |  | MaxItems: 32 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |


#### ImpersonationIdentityResource

_Underlying type:_ _string_

ImpersonationIdentityResource is the resource in the authentication.k8s.io API
group that an identity rule grants against.

_Validation:_
- Enum: [users groups uids userextras serviceaccounts nodes]

_Appears in:_
- [ConstrainedImpersonationLimits](#constrainedimpersonationlimits)
- [ImpersonationIdentityRule](#impersonationidentityrule)

| Field | Description |
| --- | --- |
| `users` | ImpersonationResourceUsers matches a generic Impersonate-User value.<br /> |
| `groups` | ImpersonationResourceGroups matches each Impersonate-Group value.<br /> |
| `uids` | ImpersonationResourceUIDs matches the Impersonate-Uid value.<br /> |
| `userextras` | ImpersonationResourceUserExtras matches Impersonate-Extra-<key> values. The<br />extra key becomes the RBAC subresource, i.e. "userextras/<key>".<br /> |
| `serviceaccounts` | ImpersonationResourceServiceAccounts matches an Impersonate-User value of the<br />form system:serviceaccount:<ns>:<name>. This is the only identity resource<br />that may be granted from a namespaced Role.<br /> |
| `nodes` | ImpersonationResourceNodes matches an Impersonate-User value of the form<br />system:node:<name>.<br /> |


#### ImpersonationIdentityRule



ImpersonationIdentityRule grants permission to assume a specific class of
identity while impersonating. Each rule becomes one RBAC PolicyRule in the
authentication.k8s.io API group carrying the `impersonate:<mode>` verb.

Identity rules for users, groups, uids, userextras and nodes are cluster-scoped
and therefore require a ClusterRole target. Only serviceaccounts identity rules
may be expressed from a namespaced Role.



_Appears in:_
- [ConstrainedImpersonationSpec](#constrainedimpersonationspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `resource` _[ImpersonationIdentityResource](#impersonationidentityresource)_ | Resource is the identity resource this rule grants against. |  | Enum: [users groups uids userextras serviceaccounts nodes] <br />Required: \{\} <br /> |
| `extraKey` _string_ | ExtraKey is the domain-prefixed extra key when Resource is "userextras".<br />It becomes the RBAC subresource, producing resources: ["userextras/<key>"].<br />Must be lowercase and a valid domain-prefixed path, matching the apiserver's<br />own validateExtra() checks. Required for userextras, forbidden otherwise. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `names` _string array_ | Names is the allowlist written to the PolicyRule's resourceNames. Values are<br />usernames, group names, UIDs, ServiceAccount names, node names or extra<br />values depending on Resource. "*" grants every name for this resource.<br />Leave empty only for the associated-node mode, where the apiserver performs<br />the node association check itself and the rule intentionally carries no<br />resourceNames. For every other mode an empty Names list would grant<br />unrestricted impersonation and is rejected. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |


#### ImpersonationMode

_Underlying type:_ _string_

ImpersonationMode selects one of the constrained impersonation modes defined by
KEP-5284. The mode is derived by the apiserver from the Impersonate-User header
value; this field declares which mode the generated RBAC grant targets.

_Validation:_
- Enum: [user-info serviceaccount arbitrary-node associated-node]

_Appears in:_
- [ConstrainedImpersonationLimits](#constrainedimpersonationlimits)
- [ConstrainedImpersonationSpec](#constrainedimpersonationspec)
- [ImpersonationConfig](#impersonationconfig)
- [ParsedImpersonationVerb](#parsedimpersonationverb)

| Field | Description |
| --- | --- |
| `associated-node` | ImpersonationModeAssociatedNode allows a requesting ServiceAccount to<br />impersonate only the node it is scheduled on. Identity rules take no names.<br /> |
| `arbitrary-node` | ImpersonationModeArbitraryNode allows impersonating any system:node:<name>.<br /> |
| `serviceaccount` | ImpersonationModeServiceAccount allows impersonating system:serviceaccount:<ns>:<name>.<br /> |
| `user-info` | ImpersonationModeUserInfo allows impersonating any non-node, non-ServiceAccount<br />identity, including uid, groups and extra values.<br /> |


#### ImpersonationVerbPolicy

_Underlying type:_ _string_

ImpersonationVerbPolicy selects how an authorizer handles constrained
impersonation verbs.

KEP-5284 explicitly warns that "a permissive webhook that allows unknown verbs
silently grants constrained impersonation". Because Kubernetes RBAC treats
verbs: ["*"] as matching every verb — including `impersonate:user-info` — any
pre-existing wildcard allow rule becomes an unintended impersonation grant when
the feature gate is enabled.

_Validation:_
- Enum: [RequireExplicitVerb AllowWildcard Deny]

_Appears in:_
- [WebhookAuthorizerSpec](#webhookauthorizerspec)

| Field | Description |
| --- | --- |
| `RequireExplicitVerb` | ImpersonationVerbPolicyRequireExplicitVerb (the default) means a constrained<br />impersonation verb only matches a rule that lists it literally. A rule with<br />verbs: ["*"] does NOT match `impersonate:user-info`. This is fail-safe and<br />keeps existing wildcard rules from silently widening.<br /> |
| `AllowWildcard` | ImpersonationVerbPolicyAllowWildcard restores plain Kubernetes RBAC<br />semantics, where verbs: ["*"] matches constrained impersonation verbs too.<br />Only use this on authorizers whose rules are known to be narrow.<br /> |
| `Deny` | ImpersonationVerbPolicyDeny makes this authorizer return an explicit deny for<br />any request carrying a constrained impersonation verb that matches its rules,<br />regardless of the allowed principals. Use it as a cluster-wide kill switch for<br />constrained impersonation.<br />Rule matching uses plain RBAC semantics, so verbs: ["*"] DOES match every<br />impersonation verb here. This differs from RequireExplicitVerb on purpose:<br />ignoring "*" is fail-safe when granting but fail-open when denying, and a kill<br />switch written as verbs: ["*"] must not silently match nothing.<br /> |




#### NameMatchLimits



NameMatchLimits defines name-based allow/deny patterns for subjects.



_Appears in:_
- [ConstrainedImpersonationLimits](#constrainedimpersonationlimits)
- [SubjectLimits](#subjectlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNames` _string array_ | AllowedNames is a list of allowed subject names. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenNames` _string array_ | ForbiddenNames is a list of forbidden subject names. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `allowedPrefixes` _string array_ | AllowedPrefixes is a list of allowed name prefixes. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenPrefixes` _string array_ | ForbiddenPrefixes is a list of forbidden name prefixes. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `allowedSuffixes` _string array_ | AllowedSuffixes is a list of allowed name suffixes. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenSuffixes` _string array_ | ForbiddenSuffixes is a list of forbidden name suffixes. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |


#### NamespaceBinding



NamespaceBinding defines namespace-scoped role bindings.



_Appears in:_
- [BindDefinitionSpec](#binddefinitionspec)
- [RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `clusterRoleRefs` _string array_ | ClusterRoleRefs references an existing ClusterRole |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |
| `roleRefs` _string array_ | RoleRefs references a specific Role that has to exist in the target namespaces |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |
| `namespace` _string_ | Namespace of the Role that should be bound to the subjects. |  | Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta) array_ | NamespaceSelector is a label selector which will match namespaces that should have the RoleBinding/s. |  | MaxItems: 16 <br />Optional: \{\} <br /> |


#### NamespaceLimits



NamespaceLimits controls which namespaces can be targeted by bindings.



_Appears in:_
- [BindingLimits](#bindinglimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedNamespaceSelector selects allowed namespaces by label. |  | Optional: \{\} <br /> |
| `forbiddenNamespaces` _string array_ | ForbiddenNamespaces is a list of namespace names that may not be targeted. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenNamespacePrefixes` _string array_ | ForbiddenNamespacePrefixes is a list of namespace name prefixes that may not be targeted. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `maxTargetNamespaces` _integer_ | MaxTargetNamespaces limits the number of target namespaces per binding. |  | Minimum: 0 <br />Optional: \{\} <br /> |




#### PolicyScope



PolicyScope defines which namespaces this policy governs.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | NamespaceSelector selects namespaces by label selector. |  | Optional: \{\} <br /> |
| `namespaces` _string array_ | Namespaces is an explicit list of namespace names. Use "*" to make the<br />policy explicitly cluster-wide; this is required for cluster-scoped<br />generated resources such as ClusterRoles and ClusterRoleBindings. |  | MaxItems: 256 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br /> |


#### Principal



Principal represents a requesting user or service account identity.



_Appears in:_
- [WebhookAuthorizerSpec](#webhookauthorizerspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `user` _string_ | User is the requesting user in SubjectAccessReview request. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `groups` _string array_ | Groups is the requesting user groups in SubjectAccessReview request. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `namespace` _string_ | Namespace scopes User to a Kubernetes ServiceAccount namespace. When set,<br />User may be either the short ServiceAccount name or the full<br />system:serviceaccount:<namespace>:<name> username. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `uid` _string_ | UID matches SubjectAccessReview spec.uid, the UID of the authenticated<br />requester. Matching on UID pins a principal to one specific identity instance<br />even when usernames are reused, which matters for constrained impersonation<br />because the requester's UID is part of the impersonation authorization check. |  | MaxLength: 253 <br />Optional: \{\} <br /> |
| `extra` _[PrincipalExtraMatch](#principalextramatch) array_ | Extra matches SubjectAccessReview spec.extra entries. All listed matchers must<br />match (AND) for the principal to match. This makes attributes such as<br />authentication.kubernetes.io/node-name — the value the associated-node<br />impersonation mode is keyed on — usable in authorization decisions. |  | MaxItems: 16 <br />Optional: \{\} <br /> |


#### PrincipalExtraMatch



PrincipalExtraMatch matches a single SubjectAccessReview spec.extra entry.
The apiserver populates spec.extra from the authenticated requester's extra
values, including impersonation-related keys such as
authentication.kubernetes.io/node-name.



_Appears in:_
- [Principal](#principal)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `key` _string_ | Key is the extra key to match, e.g. "authentication.kubernetes.io/node-name". |  | MaxLength: 253 <br />MinLength: 1 <br />Required: \{\} <br /> |
| `values` _string array_ | Values are the accepted values for Key. The principal matches when at least<br />one of the request's values for Key is listed here. Use ["*"] to require only<br />that the key is present with any non-empty value. |  | MaxItems: 64 <br />MinItems: 1 <br />Required: \{\} <br />items:MaxLength: 253 <br />items:MinLength: 1 <br /> |


#### RBACPolicy



RBACPolicy is the Schema for the rbacpolicies API.
It defines RBAC guardrails that RestrictedBindDefinitions and
RestrictedRoleDefinitions must comply with.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RBACPolicy` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RBACPolicySpec](#rbacpolicyspec)_ |  |  | Required: \{\} <br /> |
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
| `appliesTo` _[PolicyScope](#policyscope)_ | AppliesTo defines the namespace scope this policy governs.<br />Static Namespaces entries and NamespaceSelector are enforced at evaluation time;<br />selector-based scope checks require a LabelGetter so namespace labels can be<br />resolved during controller reconciliation. |  | Required: \{\} <br /> |
| `bindingLimits` _[BindingLimits](#bindinglimits)_ | BindingLimits constrains role bindings that may be created. |  | Optional: \{\} <br /> |
| `roleLimits` _[RoleLimits](#rolelimits)_ | RoleLimits constrains roles that may be generated. |  | Optional: \{\} <br /> |
| `subjectLimits` _[SubjectLimits](#subjectlimits)_ | SubjectLimits constrains the subjects a tenant may use. |  | Optional: \{\} <br /> |
| `defaultAssignment` _[DefaultPolicyAssignment](#defaultpolicyassignment)_ | DefaultAssignment defines requester identities that must use this policy by default<br />when creating restricted resources. |  | Optional: \{\} <br /> |
| `impersonation` _[ImpersonationConfig](#impersonationconfig)_ | Impersonation configures ServiceAccount impersonation for restricted resource<br />apply operations governed by this policy. |  | Optional: \{\} <br /> |


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


#### RestrictedAPIGroup



RestrictedAPIGroup defines an API group restriction with optional verb-level filtering.
When Verbs is empty, the entire API group is blocked (all verbs restricted).
When Verbs is specified, only the listed verbs are restricted across all resources in the group,
and the remaining verbs are still allowed.



_Appears in:_
- [RestrictedRoleDefinitionSpec](#restrictedroledefinitionspec)
- [RoleDefinitionSpec](#roledefinitionspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name is the name of the API group (e.g., "storage.k8s.io", "velero.io"). |  | Required: \{\} <br /> |
| `versions` _[GroupVersionForDiscovery](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#groupversionfordiscovery-v1-meta) array_ | Versions restricts only the specified API versions within this group.<br />When empty, all versions of the group are affected. |  | Optional: \{\} <br /> |
| `verbs` _string array_ | Verbs restricts only the specified verbs across all resources in this API group.<br />When empty, the entire API group is fully blocked (existing behavior).<br />When specified, only the listed verbs are removed from the generated role for resources<br />in this group — remaining verbs are still allowed.<br />This enables per-API-group read-only restrictions without enumerating every resource.<br />A verb value of "*" restricts all discovered verbs in this API group.<br />Kubernetes constrained impersonation (KEP-5284) verbs are accepted here too,<br />i.e. "impersonate:<mode>" and "impersonate-on:<mode>:<verb>", plus the legacy<br />bare "impersonate" verb. Because every mode x verb combination is a separate<br />entry, MaxItems is 64 rather than the historical 16. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: `^([a-z]+\|\*\|impersonate:(user-info\|serviceaccount\|arbitrary-node\|associated-node)\|impersonate-on:(user-info\|serviceaccount\|arbitrary-node\|associated-node):[a-z]+)$` <br /> |


#### RestrictedBindDefinition



RestrictedBindDefinition is the Schema for the restrictedbinddefinitions API.
It is similar to BindDefinition but requires a policy reference and enforces
RBAC guardrails defined by the referenced RBACPolicy.





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authorization.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `RestrictedBindDefinition` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[RestrictedBindDefinitionSpec](#restrictedbinddefinitionspec)_ |  |  | Required: \{\} <br /> |
| `status` _[RestrictedBindDefinitionStatus](#restrictedbinddefinitionstatus)_ |  |  |  |


#### RestrictedBindDefinitionSpec



RestrictedBindDefinitionSpec defines the desired state of RestrictedBindDefinition.



_Appears in:_
- [RestrictedBindDefinition](#restrictedbinddefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[RBACPolicyReference](#rbacpolicyreference)_ | PolicyRef references the RBACPolicy that governs this binding.<br />This field is immutable after creation. |  | Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name prefix for generated bindings. Generated binding<br />names are derived from this value and suffixed with the binding kind, for<br />example "targetName-clusterrolebinding" or "targetName-rolebinding".<br />This field is immutable after creation.<br />MaxLength=200 (not 253) to leave headroom for the longest suffix<br />("-clusterrolebinding" = 20 chars), keeping generated names within the<br />Kubernetes 253-character object name limit. |  | MaxLength: 200 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` <br />Required: \{\} <br /> |
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
| `skippedServiceAccounts` _string array_ | SkippedServiceAccounts lists ServiceAccount subjects that could not be<br />created or bound during the last reconciliation.<br />Format: "<namespace>/<name>: <reason>". |  | Optional: \{\} <br /> |
| `policyViolations` _string array_ | PolicyViolations lists policy violations detected during the last reconciliation.<br />Format: "<fieldPath>: <message>" when a field path is available.<br />Empty when all checks pass. |  | Optional: \{\} <br /> |
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
| `spec` _[RestrictedRoleDefinitionSpec](#restrictedroledefinitionspec)_ |  |  | Required: \{\} <br /> |
| `status` _[RestrictedRoleDefinitionStatus](#restrictedroledefinitionstatus)_ |  |  |  |


#### RestrictedRoleDefinitionSpec



RestrictedRoleDefinitionSpec defines the desired state of RestrictedRoleDefinition.



_Appears in:_
- [RestrictedRoleDefinition](#restrictedroledefinition)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `policyRef` _[RBACPolicyReference](#rbacpolicyreference)_ | PolicyRef references the RBACPolicy that governs this role definition.<br />This field is immutable after creation. |  | Required: \{\} <br /> |
| `targetRole` _string_ | TargetRole is the role type that will be reconciled: ClusterRole or Role.<br />This field is immutable after creation. |  | Enum: [ClusterRole Role] <br />Required: \{\} <br /> |
| `targetName` _string_ | TargetName is the name of the target role.<br />This field is immutable after creation. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([a-z0-9\-]\{0,61\}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]\{0,61\}[a-z0-9])?)*$` <br />Required: \{\} <br /> |
| `targetNamespace` _string_ | TargetNamespace is the target namespace for the Role.<br />Required when "TargetRole" is "Role". |  | MaxLength: 63 <br />Optional: \{\} <br />Pattern: `^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$` <br /> |
| `scopeNamespaced` _boolean_ | ScopeNamespaced controls whether the API resource filter includes<br />namespaced or cluster-scoped resources. |  | Required: \{\} <br /> |
| `restrictedApis` _[RestrictedAPIGroup](#restrictedapigroup) array_ | RestrictedAPIs defines API group-level restrictions for the generated role.<br />Each entry can either fully block an API group or restrict only certain verbs:<br />  - When Verbs is empty or omitted, the entire API group is fully blocked<br />    (no resources from that group appear in the generated role).<br />  - When Verbs is specified, only those verbs are removed for resources in<br />    the group — the remaining verbs are still allowed (partial restriction).<br />Version filtering narrows which API versions are affected:<br />  - When Versions is empty, all versions of the group are affected.<br />  - When Versions is specified, only those API versions are restricted.<br />Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource<br />exists in a non-restricted version of the same group, it will still appear<br />in the generated role. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apiresource-v1-meta) array_ | RestrictedResources holds resources which will NOT be included in the generated role. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `restrictedVerbs` _string array_ | RestrictedVerbs holds verbs which will NOT be included in the generated role.<br />Kubernetes constrained impersonation (KEP-5284) verbs are accepted here too,<br />i.e. "impersonate:<mode>" and "impersonate-on:<mode>:<verb>", plus the legacy<br />bare "impersonate" verb. Because every mode x verb combination is a separate<br />entry, MaxItems is 64 rather than the historical 16. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: `^([a-z]+\|\*\|impersonate:(user-info\|serviceaccount\|arbitrary-node\|associated-node)\|impersonate-on:(user-info\|serviceaccount\|arbitrary-node\|associated-node):[a-z]+)$` <br /> |
| `constrainedImpersonation` _[ConstrainedImpersonationSpec](#constrainedimpersonationspec)_ | ConstrainedImpersonation declares a Kubernetes constrained impersonation<br />(KEP-5284) grant using a typed API instead of hand-written magic verb strings.<br />The controller appends the generated PolicyRules to the discovery-derived rules<br />of the generated role.<br />Unlike RoleDefinition, the grant is additionally checked against the governing<br />RBACPolicy: roleLimits.forbiddenVerbs and roleLimits.forbiddenResourceVerbs can<br />forbid `impersonate:*`-style grants, and<br />roleLimits.constrainedImpersonation can restrict the allowed modes, identity<br />resources and identity names. |  | Optional: \{\} <br /> |


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
Write access is intended for platform-admin or trusted-admin workflows
because generated Roles and ClusterRoles affect real Kubernetes RBAC.
Use RestrictedRoleDefinition under an RBACPolicy for delegated workflows.





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
| `targetName` _string_ | TargetName is the name of the target role. This can be any valid Kubernetes<br />RFC 1123 subdomain name for the generated ClusterRole/Role.<br />This field is immutable after creation; changing it would orphan the generated role and its bindings. |  | MaxLength: 253 <br />MinLength: 1 <br />Pattern: `^[a-z0-9]([a-z0-9\-]\{0,61\}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]\{0,61\}[a-z0-9])?)*$` <br />Required: \{\} <br /> |
| `targetNamespace` _string_ | TargetNamespace is the target namespace for the Role. Required when "TargetRole" is "Role". |  | MaxLength: 63 <br />Optional: \{\} <br />Pattern: `^([a-z0-9]([-a-z0-9]*[a-z0-9])?)?$` <br /> |
| `scopeNamespaced` _boolean_ | ScopeNamespaced controls whether the API resource is namespaced or not. This can also be checked by<br />running `kubectl api-resources --namespaced=true/false`. |  | Required: \{\} <br /> |
| `restrictedApis` _[RestrictedAPIGroup](#restrictedapigroup) array_ | RestrictedAPIs defines API group-level restrictions for the generated role.<br />Each entry can either fully block an API group or restrict only certain verbs:<br />  - When Verbs is empty or omitted, the entire API group is fully blocked<br />    (no resources from that group appear in the generated role).<br />  - When Verbs is specified, only those verbs are removed for resources in<br />    the group — the remaining verbs are still allowed (partial restriction).<br />Version filtering narrows which API versions are affected:<br />  - When Versions is empty, all versions of the group are affected.<br />  - When Versions is specified, only those API versions are restricted.<br />Note: Kubernetes RBAC PolicyRules are version-agnostic. If the same resource<br />exists in a non-restricted version of the same group, it will still appear<br />in the generated role. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `restrictedResources` _[APIResource](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#apiresource-v1-meta) array_ | RestrictedResources holds all resources which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all API resources available and removes those listed here. |  | MaxItems: 128 <br />Optional: \{\} <br /> |
| `restrictedVerbs` _string array_ | RestrictedVerbs holds all verbs which will *NOT* be reconciled into the "TargetRole".<br />The RBAC operator discovers all resource verbs available and removes those listed here.<br />A value of "*" restricts all discovered verbs.<br />Kubernetes constrained impersonation (KEP-5284) verbs are accepted here too,<br />i.e. "impersonate:<mode>" and "impersonate-on:<mode>:<verb>", plus the legacy<br />bare "impersonate" verb. Because every mode x verb combination is a separate<br />entry, MaxItems is 64 rather than the historical 16. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MaxLength: 63 <br />items:MinLength: 1 <br />items:Pattern: `^([a-z]+\|\*\|impersonate:(user-info\|serviceaccount\|arbitrary-node\|associated-node)\|impersonate-on:(user-info\|serviceaccount\|arbitrary-node\|associated-node):[a-z]+)$` <br /> |
| `breakglassAllowed` _boolean_ | BreakglassAllowed marks generated ClusterRoles as eligible for temporary<br />privilege escalation via k8s-breakglass. The generated ClusterRole always<br />receives the label t-caas.telekom.com/breakglass-compatible set to "true"<br />or "false" based on this field's value.<br />Only applicable when TargetRole is ClusterRole. Defaults to false. | false | Optional: \{\} <br /> |
| `metricsAccessAllowed` _boolean_ | MetricsAccessAllowed adds get access to the /metrics non-resource URL<br />on generated ClusterRoles. Only applicable when TargetRole is ClusterRole<br />and get is not restricted by RestrictedVerbs. Defaults to false. | false | Optional: \{\} <br /> |
| `aggregationLabels` _object (keys:string, values:string)_ | AggregationLabels are additional labels applied to the generated ClusterRole.<br />Kubernetes RBAC aggregation labels such as rbac.authorization.k8s.io/aggregate-to-view<br />are rejected because generated roles must not feed built-in or externally managed<br />aggregating ClusterRoles. Only applicable when targetRole is ClusterRole. |  | Optional: \{\} <br /> |
| `aggregateFrom` _[AggregationRule](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#aggregationrule-v1-rbac)_ | AggregateFrom generates an aggregating ClusterRole that uses label selectors<br />to compose rules from other ClusterRoles, instead of specifying rules directly.<br />When set, the controller skips API discovery and filtering; the generated ClusterRole<br />carries an aggregationRule and its rules[] are managed by the RBAC aggregation controller.<br />Selectors must use explicit matchLabels for t-caas.telekom.com/rbac-fragment="true"<br />and t-caas.telekom.com/aggregate-scope to avoid selecting system or unrelated ClusterRoles.<br />Mutually exclusive with RestrictedAPIs, RestrictedResources, and RestrictedVerbs.<br />Only applicable when targetRole is ClusterRole. |  | Optional: \{\} <br /> |
| `constrainedImpersonation` _[ConstrainedImpersonationSpec](#constrainedimpersonationspec)_ | ConstrainedImpersonation declares a Kubernetes constrained impersonation<br />(KEP-5284) grant using a typed API instead of hand-written magic verb<br />strings. The controller appends the generated PolicyRules — identity rules in<br />the authentication.k8s.io API group with `impersonate:<mode>` verbs, and<br />action rules with `impersonate-on:<mode>:<verb>` verbs — to the discovery<br />derived rules of the target role.<br />The feature requires the ConstrainedImpersonation kube-apiserver feature gate<br />(alpha 1.35 off-by-default, beta 1.36 on-by-default). On an older apiserver<br />the generated grants are simply never matched, so the change fails safe.<br />Mutually exclusive with AggregateFrom, whose rules are owned by the<br />Kubernetes aggregation controller. |  | Optional: \{\} <br /> |


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
| `forbiddenVerbs` _string array_ | ForbiddenVerbs is a list of verbs that must not appear in generated roles.<br />Constrained impersonation verbs may be listed here, either fully spelled out<br />("impersonate:user-info") or as a wildcard pattern ("impersonate:*",<br />"impersonate-on:*"). MaxItems is 64 because each constrained impersonation<br />mode x verb combination is a separate verb string. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenResources` _string array_ | ForbiddenResources is a list of resources that must not appear in generated roles. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenAPIGroups` _string array_ | ForbiddenAPIGroups is a list of API groups that must not appear in generated roles.<br />Use an empty string for the core API group. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `forbiddenResourceVerbs` _[ResourceVerbRule](#resourceverbrule) array_ | ForbiddenResourceVerbs is a list of specific resource+verb combinations that are forbidden. |  | MaxItems: 64 <br />Optional: \{\} <br /> |
| `maxRulesPerRole` _integer_ | MaxRulesPerRole limits the number of rules in a single generated role. |  | Minimum: 1 <br />Optional: \{\} <br /> |
| `constrainedImpersonation` _[ConstrainedImpersonationLimits](#constrainedimpersonationlimits)_ | ConstrainedImpersonation constrains Kubernetes constrained impersonation<br />(KEP-5284) grants declared by RestrictedRoleDefinitions governed by this<br />policy. When omitted, constrained impersonation grants are forbidden entirely<br />(deny by default) — a RestrictedRoleDefinition that sets<br />spec.constrainedImpersonation is reported as non-compliant. |  | Optional: \{\} <br /> |


#### RoleRefLimits



RoleRefLimits controls which role references are allowed or forbidden.



_Appears in:_
- [BindingLimits](#bindinglimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedRoleRefs` _string array_ | AllowedRoleRefs is a list of allowed role names. Supports simple wildcards:<br />"prefix*" and "*suffix". An empty list means no role refs are allowed (default-deny). |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `allowedRoleRefSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedRoleRefSelector selects allowed roles by label. |  | Optional: \{\} <br /> |
| `forbiddenRoleRefs` _string array_ | ForbiddenRoleRefs is a list of explicitly forbidden role names.<br />Takes precedence over AllowedRoleRefs. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenRoleRefSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | ForbiddenRoleRefSelector selects forbidden roles by label. |  | Optional: \{\} <br /> |


#### SACreationConfig



SACreationConfig controls ServiceAccount auto-creation behaviour.



_Appears in:_
- [ServiceAccountLimits](#serviceaccountlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowAutoCreate` _boolean_ | AllowAutoCreate controls whether ServiceAccounts may be auto-created. | false | Optional: \{\} <br /> |
| `allowedCreationNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedCreationNamespaceSelector selects namespaces where SA creation is allowed. |  | Optional: \{\} <br /> |
| `allowedCreationNamespaces` _string array_ | AllowedCreationNamespaces is an explicit list of namespaces where SA creation is allowed. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `automountServiceAccountToken` _boolean_ | AutomountServiceAccountToken controls automount for auto-created SAs. |  | Optional: \{\} <br /> |
| `disableAdoption` _boolean_ | DisableAdoption records that pre-existing ServiceAccounts must stay external<br />unless they are already owned by the same RestrictedBindDefinition. Unowned<br />ServiceAccounts and ServiceAccounts owned by another RestrictedBindDefinition<br />are always treated as external subjects and are never adopted or modified. | false | Optional: \{\} <br /> |


#### SARef



SARef is a reference to a specific ServiceAccount.



_Appears in:_
- [DefaultPolicyAssignment](#defaultpolicyassignment)
- [ImpersonationConfig](#impersonationconfig)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ | Name of the ServiceAccount. |  | MinLength: 1 <br />Required: \{\} <br /> |
| `namespace` _string_ | Namespace of the ServiceAccount. |  | Optional: \{\} <br /> |


#### ServiceAccountLimits



ServiceAccountLimits defines constraints on ServiceAccount subjects.



_Appears in:_
- [SubjectLimits](#subjectlimits)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedNamespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | AllowedNamespaceSelector selects namespaces whose SAs may be referenced. |  | Optional: \{\} <br /> |
| `forbiddenNamespaces` _string array_ | ForbiddenNamespaces is a list of namespaces whose SAs may not be referenced. |  | MaxItems: 128 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenNamespacePrefixes` _string array_ | ForbiddenNamespacePrefixes is a list of namespace prefixes to deny. |  | MaxItems: 64 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `creation` _[SACreationConfig](#sacreationconfig)_ | Creation constrains ServiceAccount auto-creation behaviour. |  | Optional: \{\} <br /> |


#### SubjectLimits



SubjectLimits defines constraints on the subjects a tenant may use.



_Appears in:_
- [RBACPolicySpec](#rbacpolicyspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `allowedKinds` _string array_ | AllowedKinds controls which subject kinds are allowed.<br />Valid values: "User", "Group", "ServiceAccount".<br />An empty list means no subject kinds are allowed (default-deny). |  | MaxItems: 3 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
| `forbiddenKinds` _string array_ | ForbiddenKinds lists subject kinds that are explicitly forbidden.<br />Takes precedence over AllowedKinds. |  | MaxItems: 3 <br />Optional: \{\} <br />items:MinLength: 1 <br /> |
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
| `deniedPrincipals` _[Principal](#principal) array_ | DeniedPrincipals is a slice of principals this authorizer should deny<br />when the request also matches ResourceRules or NonResourceRules. |  | MaxItems: 256 <br />Optional: \{\} <br /> |
| `namespaceSelector` _[LabelSelector](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#labelselector-v1-meta)_ | NamespaceSelector is a label selector to match namespaces that should allow the specified API calls. |  | Optional: \{\} <br /> |
| `impersonationVerbPolicy` _[ImpersonationVerbPolicy](#impersonationverbpolicy)_ | ImpersonationVerbPolicy controls how this authorizer treats Kubernetes<br />constrained impersonation (KEP-5284) verbs — `impersonate:<mode>` and<br />`impersonate-on:<mode>:<verb>` — in resourceRules[].verbs.<br />Defaults to "RequireExplicitVerb", which is a deliberate hardening: a<br />pre-existing rule with verbs: ["*"] would otherwise silently start granting<br />constrained impersonation the moment the feature gate is on. See the<br />ImpersonationVerbPolicy type documentation for the full rationale. | RequireExplicitVerb | Enum: [RequireExplicitVerb AllowWildcard Deny] <br />Optional: \{\} <br /> |


#### WebhookAuthorizerStatus



WebhookAuthorizerStatus defines the observed state of WebhookAuthorizer.



_Appears in:_
- [WebhookAuthorizer](#webhookauthorizer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `observedGeneration` _integer_ | ObservedGeneration is the last observed generation of the resource.<br />This is used by kstatus to determine if the resource is current. |  | Optional: \{\} <br /> |
| `authorizerConfigured` _boolean_ | Not extremely important as most status updates are driven by Conditions. We read the JSONPath from this status field to signify webhook authorizer as configured. |  | Optional: \{\} <br /> |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Webhook authorizer. All conditions should evaluate to true to signify successful configuration. |  | Optional: \{\} <br /> |

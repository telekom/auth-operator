<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Proposal: Restricted CRDs with Decoupled Policy Limits

## Summary

Add restricted CRD variants (`RestrictedRoleDefinition`, `RestrictedBindDefinition`) for tenant use, with policy limits managed separately by platform administrators via a new policy CRD. The design prevents privilege escalation by enforcing strict boundaries on what tenants can create.

### Naming Alternatives

The policy CRD is currently called `RBACPolicy`, but alternatives worth considering:

| Name | Pros | Cons |
|------|------|------|
| `RBACPolicy` | Clear purpose | Generic, might conflict with other projects |
| `TenantRBACConstraint` | Explicit tenant focus | Verbose |
| `RBACBoundary` | Describes function well | Less intuitive |
| `AuthorizationScope` | Matches K8s terminology | Too generic |
| `RBACGuardrail` | Platform engineering term | Non-standard |
| `BindingConstraint` | Matches restricted binding | Doesn't cover RoleDefinition |
| `RBACTenantPolicy` | Clear scope | Still verbose |

**Current choice**: `RBACPolicy` (subject to change based on feedback)

## Table of Contents

<!-- TOC generated manually — update when sections change -->

- [Goals](#goals)
- [Non-Goals](#non-goals)
- [Motivation](#motivation)
- [Detailed Design](#detailed-design)
  - [RBACPolicy CRD](#rbacpolicy-crd)
  - [RestrictedRoleDefinition CRD](#restrictedroledefinition-crd)
  - [RestrictedBindDefinition CRD](#restrictedbinddefinition-crd)
  - [Privilege Escalation Prevention](#privilege-escalation-prevention)
  - [Continuous Enforcement](#continuous-enforcement)
- [Controller Design](#controller-design)
- [Webhook Design](#webhook-design)
- [Integration with Existing CRDs](#integration-with-existing-crds)
- [Security Considerations](#security-considerations)
- [Implementation Plan](#implementation-plan)
- [Go Type Definitions](#go-type-definitions)
- [Appendix: Naming Alternatives](#naming-alternatives)

> **Note on Go type definitions:** The Go types in this proposal are
> intentionally skeletal. During implementation, fields will be added as
> the YAML specification is finalized. The YAML specification sections are
> the authoritative reference; discrepancies between YAML examples and Go
> types will be resolved in the implementation PRs.

## Goals

1. **Self-service RBAC** for tenants within guardrails
2. **Prevent privilege escalation** - no backdoors
3. **Decoupled policy management** - admins define limits, tenants consume
4. **Namespace isolation** - tenants can only target namespaces they're allowed to
5. **Continuous enforcement** - validate on every reconcile, deprovision on violation
6. **Explicit policy binding** - resources explicitly reference their governing policy
7. **Full audit trail** - track who created/modified resources

## Design Principles

### Selector Semantics (Standard Kubernetes)

All selectors in this proposal follow **standard Kubernetes conventions**:

| Selector Type | Syntax | Supported Operators |
|--------------|--------|---------------------|
| `matchLabels` | `key: value` | Exact match only |
| `matchExpressions` | `key`, `operator`, `values` | `In`, `NotIn`, `Exists`, `DoesNotExist` |

**No regex support.** For name-based matching (namespaces, users, groups, SAs), use simple wildcards:

| Pattern | Example | Matches |
|---------|---------|---------|
| `prefix*` | `kube-*` | `kube-system`, `kube-public` |
| `*suffix` | `*-admin` | `team-a-admin`, `cluster-admin` |
| `*` | `*` | Any value |
| `exact` | `default` | Only `default` |

**Why no regex?**
- Matches standard K8s API behavior
- Simpler validation and predictable performance
- Better UX for platform users (no regex expertise needed)
- Easier to audit and understand policies

### Universal Selector Support

**ALL namespace-related fields** support the full K8s LabelSelector API (`matchLabels` AND `matchExpressions`):

| Field Pattern | Selector Field | List Field |
|---------------|----------------|------------|
| Target namespaces | `targetNamespaceSelector` | `targetNamespaces` |
| Allowed namespaces | `allowedNamespaceSelector` | `allowedNamespaces` |
| SA creation namespaces | `allowedCreationNamespaceSelector` | `allowedCreationNamespaces` |
| Source namespaces (mirroring) | `allowedSourceNamespaceSelector` | `allowedSourceNamespaces` |

Both can be specified - they're combined with **OR** logic (match either selector or explicit list).

**Selector syntax (identical to standard K8s):**

```yaml
# Full LabelSelector support
namespaceSelector:
  # Exact match (AND logic between labels)
  matchLabels:
    tenant: team-a
    environment: production
  
  # Expression-based (AND logic between expressions)
  matchExpressions:
    - key: environment
      operator: In
      values: [dev, staging, prod]
    - key: deprecated
      operator: DoesNotExist
    - key: tier
      operator: NotIn
      values: [legacy]
```

| Operator | Description | Example |
|----------|-------------|---------|
| `In` | Label value in set | `environment In [dev, staging]` |
| `NotIn` | Label value not in set | `tier NotIn [legacy]` |
| `Exists` | Label key exists (any value) | `tenant Exists` |
| `DoesNotExist` | Label key does not exist | `deprecated DoesNotExist` |

**ClusterRole/Role selection** also supports the full selector API on `metadata.labels`:

| Field | Matches On | Example Use Case |
|-------|------------|------------------|
| `allowedRoleRefSelector` | ClusterRole/Role labels | Allow binding to all roles labeled `tenant-bindable: "true"` |
| `forbiddenRoleRefSelector` | ClusterRole/Role labels | Forbid all roles labeled `privileged: "true"` |

```yaml
# Example: Platform admin labels ClusterRoles for tenant access
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-developer
  labels:
    rbac.t-caas.telekom.com/tenant-bindable: "true"
    rbac.t-caas.telekom.com/scope: "standard"
rules: [...]
---
# RBACPolicy allows binding to labeled ClusterRoles
bindingLimits:
  roleBindingLimits:
    allowedRoleRefSelector:
      matchLabels:
        rbac.t-caas.telekom.com/tenant-bindable: "true"
      matchExpressions:
        - key: rbac.t-caas.telekom.com/scope
          operator: In
          values: [read-only, standard, developer]
```

### Mirroring Always Generates Roles (Never ClusterRoles)

When mirroring permissions across namespaces, the operator **always generates namespace-scoped Roles**, never ClusterRoles. This is a fundamental security boundary:

| Input | Source | Output | Why |
|-------|--------|--------|-----|
| `roleRef.kind: ClusterRole` | Existing ClusterRole | **Role** in each target namespace | ClusterRole rules are copied into namespace-scoped Roles |
| `roleRef.kind: Role` | Role from source namespace | **Role** in each target namespace | Role rules are copied into new Roles in target namespaces |

**Why not CRBs or reuse the original ClusterRole?**
- **Blast radius** - ClusterRoleBindings grant cluster-wide access; mirrored Roles are scoped to specific namespaces
- **Auditability** - Each namespace has its own Role, making it clear what permissions exist where
- **Policy enforcement** - Easier to validate and revoke per-namespace
- **Impersonation compatibility** - The impersonated SA only needs `roles` permissions, not `clusterroles`

### Independent Configuration: Role Generation vs Binding

Role generation (mirroring) and binding creation are **independently configured** but follow the **same policy constraints**:

```
┌─────────────────────────────────────────────────────────────────┐
│  RestrictedRoleDefinition (Role Generation)                     │
│  - Generates Roles in target namespaces                        │
│  - Follows roleLimits from RBACPolicy                          │
│  - Follows targetNamespaceLimits from RBACPolicy               │
│  - Does NOT create bindings                                    │
└─────────────────────────────────────────────────────────────────┘
                              +
┌─────────────────────────────────────────────────────────────────┐
│  RestrictedBindDefinition (Binding Creation)                    │
│  - Creates RoleBindings/ClusterRoleBindings                    │
│  - References existing Roles/ClusterRoles (or generated ones)  │
│  - Follows bindingLimits from RBACPolicy                       │
│  - Follows subjectLimits from RBACPolicy                       │
└─────────────────────────────────────────────────────────────────┘
```

**Composition patterns:**
1. **Role + Binding together**: RestrictedRoleDefinition generates Roles, RestrictedBindDefinition references them
2. **Binding only**: RestrictedBindDefinition references existing ClusterRoles/Roles
3. **Role only**: RestrictedRoleDefinition generates Roles for other consumers (e.g., platform-managed bindings)

## Architecture

### Separation of Concerns

| CRD | Managed By | Purpose |
|-----|------------|---------|
| `RBACPolicy` | Platform Admins | Define cluster-wide or namespace-scoped limits |
| `RestrictedBindDefinition` | Tenants | Create bindings within policy limits (explicit policy ref) |
| `RestrictedRoleDefinition` | Tenants | Create roles within policy limits (explicit policy ref) |

### Policy Binding Model

```
┌─────────────────────────────────────────────────────────────────┐
│                     RBACPolicy                                   │
│  (cluster-scoped, managed by platform admins)                   │
│                                                                  │
│  - Defines all limits (bindings, roles, subjects, namespaces)   │
│  - Specifies which namespaces/labels it governs                 │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ rbacPolicyRef
                              │
┌─────────────────────────────┴───────────────────────────────────┐
│  RestrictedBindDefinition / RestrictedRoleDefinition            │
│  (namespace-scoped, managed by tenants)                         │
│                                                                  │
│  - Explicit reference to governing RBACPolicy                   │
│  - Policy ref enforcement via Kyverno/webhook                   │
│  - Audit metadata (creator, timestamp)                          │
└─────────────────────────────────────────────────────────────────┘
```

## RBACPolicy Specification

Platform admins configure comprehensive limits:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: tenant-team-a-policy
spec:
  # Which namespaces this policy applies to (where RestrictedBD/RD can be created)
  # Uses standard Kubernetes LabelSelector - NO regex support
  # Supported: matchLabels (exact match), matchExpressions (In, NotIn, Exists, DoesNotExist)
  appliesTo:
    namespaceSelector:
      matchLabels:
        tenant: team-a
    # Explicit namespace list (combined with selector using OR/union semantics)
    # A namespace matches if it matches EITHER the selector OR is in this list
    namespaces:
      - team-a-dev
      - team-a-staging

  # ============================================
  # BINDING LIMITS
  # ============================================
  bindingLimits:
    # Completely disable ClusterRoleBindings for this tenant
    allowClusterRoleBindings: false
    
    # If ClusterRoleBindings are allowed, restrict them
    clusterRoleBindingLimits:
      # Only allow binding to these specific ClusterRoles (by name)
      allowedRoleRefs:
        - view
        - edit
      
      # Allow binding to ClusterRoles matching this selector (by labels)
      # Standard K8s LabelSelector on ClusterRole metadata.labels
      allowedRoleRefSelector:
        matchLabels:
          rbac.t-caas.telekom.com/tenant-bindable: "true"
        matchExpressions:
          - key: rbac.t-caas.telekom.com/scope
            operator: In
            values: [read-only, standard]
      
      # Never allow these (even if in allowedRoleRefs or matching selector)
      forbiddenRoleRefs:
        - cluster-admin
        - admin
        - "system:*"
      
      # Forbid ClusterRoles matching this selector (takes precedence)
      forbiddenRoleRefSelector:
        matchLabels:
          rbac.t-caas.telekom.com/privileged: "true"
        matchExpressions:
          - key: rbac.t-caas.telekom.com/scope
            operator: In
            values: [admin, system]
      
      # Restrict what resources can be bound at cluster scope
      forbiddenClusterScopeResources:
        - secrets
        - nodes
        - persistentvolumes
      # Restrict verbs at cluster scope
      forbiddenClusterScopeVerbs:
        - "*"
        - delete
        - deletecollection

    # RoleBinding limits (namespace-scoped)
    roleBindingLimits:
      # Role refs that cannot be bound (by name)
      forbiddenRoleRefs:
        - cluster-admin
        - admin
        - "system:*"
      
      # Forbid roles matching this selector (takes precedence)
      forbiddenRoleRefSelector:
        matchLabels:
          rbac.t-caas.telekom.com/privileged: "true"
      
      # Allowed role refs by name (if set, only these are allowed)
      allowedRoleRefs:
        - view
        - edit
        - custom-tenant-role
      
      # Allow roles matching this selector (OR with allowedRoleRefs)
      allowedRoleRefSelector:
        matchLabels:
          rbac.t-caas.telekom.com/tenant-bindable: "true"

    # ============================================
    # TARGET NAMESPACE RESTRICTIONS
    # ============================================
    targetNamespaceLimits:
      # Tenants can ONLY target namespaces matching this selector
      # (prevents targeting kube-system, other tenants, etc.)
      # Standard K8s LabelSelector (NO regex)
      allowedNamespaceSelector:
        matchLabels:
          tenant: team-a
        matchExpressions:
          - key: environment
            operator: In
            values: [dev, staging, prod]
      
      # Explicit deny list (takes precedence over selector)
      forbiddenNamespaces:
        - kube-system
        - kube-public
        - kube-node-lease
        - cert-manager
        - istio-system
      
      # Forbidden namespace prefixes (simple wildcard, NO regex)
      # Simple prefix match: "kube-*" matches "kube-system", "kube-public"
      forbiddenNamespacePrefixes:
        - "kube-*"
        - "istio-*"
        - "team-b-*"  # Other tenant's namespaces
      
      # Max namespaces a single RestrictedBD can target
      maxTargetNamespaces: 10

  # ============================================
  # ROLE DEFINITION LIMITS
  # ============================================
  roleLimits:
    # Completely disable ClusterRole creation
    allowClusterRoles: false
    
    # Forbidden verbs (prevents wildcard escalation)
    forbiddenVerbs:
      - "*"
      - impersonate
      - escalate
      - bind
    
    # Forbidden resources (sensitive resources)
    forbiddenResources:
      - secrets
      - nodes
      - persistentvolumes
      - clusterroles
      - clusterrolebindings
      - roles
      - rolebindings
      - validatingwebhookconfigurations
      - mutatingwebhookconfigurations
    
    # Forbidden API groups
    forbiddenAPIGroups:
      - "admissionregistration.k8s.io"
      - "certificates.k8s.io"
      - "authorization.k8s.io"
    
    # Forbidden resource/verb combinations
    forbiddenResourceVerbs:
      - resource: pods
        verbs: [delete, deletecollection]
      - resource: deployments
        apiGroup: apps
        verbs: [delete]
    
    # Max rules per role (complexity limit)
    maxRulesPerRole: 20

  # ============================================
  # SUBJECT RESTRICTIONS (Granular)
  # ============================================
  subjectLimits:
    # ----------------------------------------
    # Kind-level controls
    # ----------------------------------------
    # Completely disable certain subject kinds
    # (e.g., tenants can only use ServiceAccounts, not Users/Groups)
    # Use EITHER allowedKinds (whitelist) OR forbiddenKinds (blacklist) - MUTUALLY EXCLUSIVE
    allowedKinds:
      - ServiceAccount
    # Note: When allowedKinds is set, forbiddenKinds must NOT be set
    # Example using forbiddenKinds instead (commented out):
    # forbiddenKinds:
    #   - User
    #   - Group
    # ----------------------------------------
    # User restrictions
    # ----------------------------------------
    userLimits:
      # Allow only specific users (if set, only these are allowed)
      allowedUsers:
        - "team-a-admin@company.com"
        - "team-a-ci@company.com"
      
      # Forbidden user prefixes (simple wildcard, NO regex)
      forbiddenPrefixes:
        - "system:*"     # All system users
      
      # Forbidden user suffixes
      forbiddenSuffixes:
        - "*@external.com"  # External users
      
      # Forbidden exact names
      forbiddenNames:
        - "admin"
      
      # Allowed user prefixes (if set, users must match at least one)
      allowedPrefixes:
        - "team-a-*"
        - "svc-team-a-*"
    
    # ----------------------------------------
    # Group restrictions  
    # ----------------------------------------
    groupLimits:
      # Allow only specific groups (if set, only these are allowed)
      allowedGroups:
        - "team-a-developers"
        - "team-a-admins"
      
      # Forbidden groups (always rejected)
      forbiddenGroups:
        - "system:masters"
        - "system:cluster-admins"
        - "cluster-admin"
      
      # Forbidden group prefixes (simple wildcard, NO regex)
      forbiddenPrefixes:
        - "system:*"    # All system groups
        - "team-b-*"   # Other tenant's groups
      
      # Forbidden group suffixes
      forbiddenSuffixes:
        - "*-admin"    # Admin groups
      
      # Allowed group prefixes (if set, groups must match at least one)
      allowedPrefixes:
        - "team-a-*"
    
    # ----------------------------------------
    # ServiceAccount restrictions (per-namespace)
    # ----------------------------------------
    serviceAccountLimits:
      # Global: allowed SA namespaces (label selector)
      allowedNamespaceSelector:
        matchLabels:
          tenant: team-a
      
      # Global: explicit allowed namespaces (uses UnifiedSelector)
      allowedNamespaces:
        names:
          - team-a-dev
          - team-a-staging
          - team-a-prod
      
      # Global: forbidden SA namespaces (uses UnifiedSelector)
      forbiddenNamespaces:
        names:
          - kube-system
          - kube-public
          - default
      
      # Forbidden namespace prefixes (simple wildcard, NO regex)
      forbiddenNamespacePrefixes:
        - "kube-*"
        - "team-b-*"
      
      # Forbidden ServiceAccounts (simple wildcards: prefix*, *suffix)
      forbiddenServiceAccounts:
        - namespace: "*"
          name: "default"           # No default SA in any namespace
        - namespace: "team-a-*"
          name: "*-privileged"      # No *-privileged SAs in tenant namespaces
      
      # Allowed ServiceAccounts (if set, only these are allowed)
      # Simple wildcards only: "*" (any), "prefix*", "*suffix"
      allowedServiceAccounts:
        - namespace: team-a-dev
          name: "*"                 # Any SA in team-a-dev
        - namespace: team-a-staging
          name: "app-*"             # Only app-* SAs in staging
      
      # ----------------------------------------
      # ServiceAccount Creation Controls
      # ----------------------------------------
      creation:
        # Allow RestrictedBindDefinition to auto-create SAs
        allowAutoCreate: true
        
        # Namespaces where SA creation is allowed (standard K8s LabelSelector)
        # Must also satisfy allowedNamespaces/allowedNamespaceSelector above
        allowedCreationNamespaceSelector:
          matchLabels:
            tenant: team-a
            sa-creation-allowed: "true"
          matchExpressions:
            - key: environment
              operator: In
              values: [dev, staging]  # No SA creation in prod
        
        # Explicit namespace list (OR with selector above)
        allowedCreationNamespaces:
          - team-a-dev
          - team-a-staging
        
        # Force automountServiceAccountToken value on all managed SAs
        # (overrides RestrictedBindDefinition.spec.automountServiceAccountToken)
        automountServiceAccountToken: false  # Secure default: no token mounting
        
        # Prevent SA adoption (always treat pre-existing SAs as external)
        disableAdoption: false
      
      # ----------------------------------------
      # Per-namespace SA rules (most specific wins)
      # ----------------------------------------
      namespaceRules:
        # In production, only allow specific SAs
        - namespaceSelector:
            matchLabels:
              environment: production
          allowedServiceAccounts:
            - name: "app-service"
            - name: "app-worker"
          forbiddenServiceAccounts:
            - name: "debug-*"
            - name: "*-dev"
        
        # In development, allow any SA from the tenant
        - namespaceSelector:
            matchLabels:
              environment: development
          allowedServiceAccounts:
            - name: "*"
        
        # Specific namespace overrides
        - namespaces:
            - team-a-ci
          allowedServiceAccounts:
            - name: "ci-runner"
            - name: "ci-deployer"
    
    # ----------------------------------------
    # Complex subject validation rules
    # ----------------------------------------
    # For scenarios that don't fit the above limits.
    # Uses simple prefix/suffix matching for subject names (NO regex)
    # Annotation value matching uses "*" as a sentinel meaning "any non-empty value"
    customRules:
      # Rule 1: CI service accounts can only be bound in CI namespace
      - name: ci-sa-restriction
        description: "CI SAs can only be used in CI namespaces"
        match:
          subjects:
            - kind: ServiceAccount
              namePrefix: "ci-"  # Matches ci-runner, ci-deployer, etc.
        require:
          # The RestrictedBD must be in a CI namespace
          sourceNamespaceSelector:
            matchLabels:
              purpose: ci
          # Target namespaces must also be CI-related
          targetNamespaceLabels:
            purpose: ci
      
      # Rule 2: Admin groups require approval annotation
      - name: admin-group-approval
        description: "Admin groups require explicit approval"
        match:
          subjects:
            - kind: Group
              nameSuffix: "-admins"  # Matches team-a-admins, platform-admins, etc.
        require:
          annotations:
            authorization.t-caas.telekom.com/approved-by: "*"  # Must exist (non-empty)
      
      # Rule 3: Cross-namespace SA binding restrictions
      - name: cross-namespace-sa
        description: "Cross-namespace SA bindings require same tenant label"
        match:
          # When SA namespace differs from RestrictedBD namespace
          crossNamespaceServiceAccount: true
        require:
          # Both namespaces must have same tenant label
          namespaceLabelsMatch:
            - tenant

  # ============================================
  # ESCALATION PREVENTION
  # ============================================
  escalationPrevention:
    # Require that the creating user has all permissions they're granting
    # (standard K8s RBAC escalation prevention)
    enforceRBACEscalationPrevention: true
    
    # Don't allow granting more permissions than the policy allows
    # even if the user technically has those permissions
    strictPolicyEnforcement: true
    
    # Audit all policy violations (even if allowed by RBAC)
    auditViolations: true

  # ============================================
  # IMPERSONATION ENFORCEMENT
  # ============================================
  # When enabled, the operator impersonates a specific ServiceAccount when
  # applying RBAC resources. This provides defense-in-depth by limiting
  # effective permissions to exactly what the impersonated SA allows,
  # regardless of the operator's own permissions.
  impersonation:
    # Enable impersonation-based enforcement
    enabled: true
    
    # ServiceAccount to impersonate when applying resources for this policy
    # The operator must have 'impersonate' permission for this SA
    serviceAccountRef:
      # SA name - can use template variables: {{.Namespace}}, {{.TenantLabel}}
      name: "rbac-applier"
      # SA namespace - typically the tenant's admin namespace
      namespace: "team-a-system"
    
    # Auto-create the impersonation SA if it doesn't exist
    # The SA will be created with no permissions - platform admin must grant separately
    autoCreateServiceAccount: false
    
    # If autoCreateServiceAccount is true, optionally bind the SA to a ClusterRole
    # This allows the policy to define exactly what permissions the tenant has
    autoBindToRole:
      kind: ClusterRole
      name: tenant-rbac-manager  # Pre-defined by platform admin
    
    # Alternative: Per-namespace impersonation
    # Use a different SA per namespace (SA must exist in target namespace)
    perNamespace:
      enabled: false
      # Template for SA name in each target namespace
      serviceAccountNameTemplate: "rbac-applier"
    
    # Fail-safe behavior when impersonation SA doesn't exist or lacks permissions
    onImpersonationFailure: Deny  # or: AllowWithAudit
```

## RestrictedBindDefinition

Tenants create bindings with explicit policy reference. Extends the BindDefinition concept to a **namespaced** scope with policy governance and support for **multiple roleRefs**.

> **Note:** Unlike BindDefinition (which is cluster-scoped), RestrictedBindDefinition is
> **namespace-scoped** to enforce tenant boundaries. The `spec.subjects` and
> `spec.roleBindings` fields follow a similar structure but are adapted for
> namespaced restrictions (e.g., `namespaceSelector` uses a list of `LabelSelector`
> objects, such as `[]metav1.LabelSelector`, rather than a single `LabelSelector`).

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: my-app-developers
  namespace: team-a-dev
spec:
  # REQUIRED: Explicit reference to governing policy
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  # Name prefix for generated bindings
  targetName: my-app-devs
  
  subjects:
    - kind: Group
      name: team-a-developers
    - kind: ServiceAccount
      name: my-app           # Auto-created if doesn't exist
      namespace: team-a-dev
  
  # ServiceAccount creation settings (same as BindDefinition)
  # Default: true for backward compatibility
  automountServiceAccountToken: false  # Recommended: disable token auto-mount
  
  # ClusterRoleBindings (cluster-scoped) - if allowed by policy
  clusterRoleBindings:
    clusterRoleRefs:
      - view  # Multiple ClusterRoles supported
  
  # RoleBindings (namespace-scoped)
  roleBindings:
    - clusterRoleRefs:
        - edit
      namespaceSelector:
        matchLabels:
          tenant: team-a
    - roleRefs:
        - app-role  # Reference Roles in target namespaces
      namespaceSelector:
        matchLabels:
          app: my-app
          tenant: team-a

status:
  # ServiceAccounts created by this RestrictedBindDefinition
  generatedServiceAccounts:
    - kind: ServiceAccount
      name: my-app
      namespace: team-a-dev
  
  # Pre-existing SAs used but not managed (won't be deleted)
  externalServiceAccounts:
    - "team-a-dev/pre-existing-sa"
  
  # Audit information (set by webhook/controller)
  audit:
    createdBy: "user:john.doe@company.com"
    createdAt: "2026-02-08T10:30:00Z"
    lastModifiedBy: "user:jane.smith@company.com"
    lastModifiedAt: "2026-02-08T14:15:00Z"
  
  # Policy compliance
  policyCompliance:
    compliant: true
    lastChecked: "2026-02-08T14:20:00Z"
    appliedPolicy: tenant-team-a-policy
    policyGeneration: 5  # Track policy version for drift detection
  
  conditions:
    - type: PolicyCompliant
      status: "True"
      reason: AllChecksPass
    - type: Ready
      status: "True"
      reason: BindingsCreated
      message: "Created 3 RoleBindings"
  
  resolvedNamespaces:
    - team-a-dev
    - team-a-staging
```

## RestrictedRoleDefinition

**RestrictedRoleDefinition always generates namespace-scoped Roles**, never ClusterRoles. This is a fundamental security boundary - tenants cannot create cluster-wide permissions.

Two modes:
1. **Inline rules** - Define permissions directly
2. **Source reference** - Copy rules from existing ClusterRole or Role (mirroring)

### Inline Rules Mode

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: my-app-role
  namespace: team-a-dev
spec:
  # REQUIRED: Explicit reference to governing policy
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  # Define rules inline (no sourceRef)
  rules:
    - apiGroups: ["apps"]
      resources: ["deployments", "statefulsets"]
      verbs: ["get", "list", "watch", "create", "update", "patch"]
      # No "delete" - would be forbidden by policy
    
    - apiGroups: [""]
      resources: ["configmaps", "services"]
      verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  
  # Target namespaces where Roles will be created
  targetNamespaces:
    selector:
      matchLabels:
        tenant: team-a

status:
  audit:
    createdBy: "user:john.doe@company.com"
    createdAt: "2026-02-08T10:30:00Z"
  
  policyCompliance:
    compliant: true
    lastChecked: "2026-02-08T14:20:00Z"
    appliedPolicy: tenant-team-a-policy
    policyGeneration: 5
  
  # Track generated Roles
  generatedRoles:
    - namespace: team-a-dev
      name: my-app-role
    - namespace: team-a-staging
      name: my-app-role
```

### Source Reference Mode (Mirroring)

Copy rules from an existing ClusterRole or Role into namespace-scoped Roles.

#### Mirror ClusterRole → Roles

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: operator-role-mirror
  namespace: team-a-operators
spec:
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  # Source: existing ClusterRole (rules will be copied into Roles)
  sourceRef:
    kind: ClusterRole
    name: my-operator-cluster-role
  
  targetNamespaces:
    selector:
      matchLabels:
        managed-by: my-operator
        tenant: team-a

status:
  generatedRoles:
    - namespace: team-a-app1
      name: operator-role-mirror
    - namespace: team-a-app2
      name: operator-role-mirror
```

#### Mirror Role → Roles

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: shared-developer-role-mirror
  namespace: team-a-dev
spec:
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  sourceRef:
    kind: Role
    name: shared-developer-role
    namespace: team-a-shared
  
  targetNamespaces:
    selector:
      matchLabels:
        tenant: team-a
        environment: development
```

## Bindings (RestrictedBindDefinition)

Create bindings referencing existing or generated Roles. **Separate from role generation.**

Matches the existing BindDefinition structure - supports **multiple roleRefs** in a single RestrictedBindDefinition:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: team-a-developer-access
  namespace: team-a-dev
spec:
  # REQUIRED: Explicit reference to governing policy
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  # Name prefix for generated bindings
  # Format: "{targetName}-{roleName}-binding"
  targetName: team-a-devs
  
  # Subjects to bind (same as BindDefinition)
  subjects:
    - kind: Group
      name: team-a-developers
    - kind: ServiceAccount
      name: ci-runner
      namespace: team-a-ci
  
  # ClusterRoleBindings (cluster-scoped)
  # Each clusterRoleRef creates a ClusterRoleBinding
  clusterRoleBindings:
    clusterRoleRefs:
      - view           # Built-in K8s ClusterRole
      - pod-reader     # Custom ClusterRole
  
  # RoleBindings (namespace-scoped)
  # Multiple entries, each with its own target namespaces
  roleBindings:
    # Entry 1: Bind ClusterRoles as RoleBindings in specific namespaces
    - clusterRoleRefs:
        - edit         # Built-in K8s ClusterRole
        - custom-edit  # Custom ClusterRole
      namespaceSelector:
        matchLabels:
          tenant: team-a
          environment: development
    
    # Entry 2: Bind namespace-scoped Roles
    - roleRefs:
        - app-deployer              # Role must exist in target namespaces
        - operator-role-mirror      # Role generated by RestrictedRoleDefinition
      namespaceSelector:
        matchLabels:
          tenant: team-a
    
    # Entry 3: Explicit namespace list
    - clusterRoleRefs:
        - secret-reader
      namespace: team-a-secrets  # Single namespace

status:
  # Track what was created
  createdBindings:
    clusterRoleBindings:
      - team-a-devs-view-binding
      - team-a-devs-pod-reader-binding
    roleBindings:
      - namespace: team-a-dev
        names:
          - team-a-devs-edit-binding
          - team-a-devs-app-deployer-binding
      - namespace: team-a-staging
        names:
          - team-a-devs-edit-binding
  
  audit:
    createdBy: "user:john.doe@company.com"
    createdAt: "2026-02-08T10:30:00Z"
  
  policyCompliance:
    compliant: true
    appliedPolicy: tenant-team-a-policy
```

### Single Role Binding (Simple Case)

For simple use cases, you can bind a single role:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: developers-view
  namespace: team-a-dev
spec:
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  targetName: devs
  
  subjects:
    - kind: Group
      name: team-a-developers
  
  # Simple: single ClusterRole as RoleBindings
  roleBindings:
    - clusterRoleRefs:
        - view
      namespaceSelector:
        matchLabels:
          tenant: team-a
```

### Policy Validation for Multiple RoleRefs

Each roleRef in the list is validated independently against RBACPolicy:

```
RestrictedBindDefinition.roleBindings[0].clusterRoleRefs = [edit, admin]
                                                              │      │
                                                              ▼      ▼
RBACPolicy.bindingLimits.allowedRoleRefs = [view, edit]    ✓ OK   ✗ REJECT
```

If **any** roleRef fails validation, the entire RestrictedBindDefinition is rejected.

### ServiceAccount Handling

RestrictedBindDefinition follows the **same SA handling as BindDefinition**:

#### Auto-Creation of ServiceAccounts

When a subject references a ServiceAccount that doesn't exist, the controller **creates it automatically**:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: app-binding
  namespace: team-a-dev
spec:
  rbacPolicyRef:
    name: tenant-team-a-policy
  
  targetName: app
  
  subjects:
    - kind: ServiceAccount
      name: my-new-app      # Will be auto-created if it doesn't exist
      namespace: team-a-dev
  
  # Control token mounting (default: true for compatibility)
  automountServiceAccountToken: false  # Recommended for security
  
  roleBindings:
    - clusterRoleRefs: [view]
      namespace: team-a-dev

status:
  # Tracks auto-created SAs
  generatedServiceAccounts:
    - kind: ServiceAccount
      name: my-new-app
      namespace: team-a-dev
```

**Policy validation for SA creation:**
- SA namespace must match `subjectLimits.serviceAccountLimits.allowedNamespaces` or `allowedNamespaceSelector`
- SA name must not match `forbiddenServiceAccounts` patterns

#### Pre-Existing (External) ServiceAccounts

When referencing a SA that already exists but **isn't owned by any BindDefinition**:

```yaml
status:
  # Tracked but NOT adopted (no ownerRef added)
  externalServiceAccounts:
    - "team-a-dev/pre-existing-sa"
```

**Behavior:**
- The SA is used for bindings but NOT managed (won't be deleted when RestrictedBindDefinition is deleted)
- No ownerReference is added to the SA
- A tracking annotation is added for observability

#### Multiple RestrictedBindDefinitions for Same SA

When multiple RestrictedBindDefinitions reference the **same ServiceAccount**:

```
┌───────────────────────────────────┐     ┌───────────────────────────────────┐
│  RestrictedBindDefinition/app-a   │     │  RestrictedBindDefinition/app-b   │
│  subjects:                        │     │  subjects:                        │
│    - kind: ServiceAccount         │     │    - kind: ServiceAccount         │
│      name: shared-sa              │     │      name: shared-sa              │
│      namespace: team-a-dev        │     │      namespace: team-a-dev        │
└───────────────────────────────────┘     └───────────────────────────────────┘
                    │                                     │
                    └──────────────┬──────────────────────┘
                                   ▼
              ┌─────────────────────────────────────────────┐
              │  ServiceAccount/shared-sa                   │
              │  ownerReferences:                           │
              │    - kind: RestrictedBindDefinition         │
              │      name: app-a  # First creator          │
              │    - kind: RestrictedBindDefinition         │
              │      name: app-b  # Added via SSA          │
              └─────────────────────────────────────────────┘
```

**Shared ownership behavior:**
1. **First RestrictedBindDefinition** creates the SA with its ownerReference
2. **Subsequent RestrictedBindDefinitions** add their ownerReference via SSA (shared ownership, `controller=false`)
3. **SA is deleted only when ALL owning RestrictedBindDefinitions are deleted**
4. **Event emitted** when shared ownership is detected

#### Mixed BindDefinition and RestrictedBindDefinition

When both BindDefinition and RestrictedBindDefinition reference the same SA:

| Scenario | First Owner | Second Reference | Behavior |
|----------|-------------|------------------|----------|
| BD creates SA | BindDefinition | RestrictedBindDefinition | RBD uses SA, adds shared ownerRef |
| RBD creates SA | RestrictedBindDefinition | BindDefinition | BD uses SA, adds shared ownerRef |
| External SA | (none) | Both BD and RBD | Both use SA, neither adopts it |

**Impersonation interaction:**
- When impersonation is enabled, SA creation is done **as the impersonated SA**
- The impersonated SA must have `serviceaccounts` create permission in the target namespace
- This prevents tenants from creating SAs in namespaces they shouldn't access

```yaml
# With impersonation enabled, the operator impersonates the policy's SA
# when creating the ServiceAccount:
#
# POST /api/v1/namespaces/team-a-dev/serviceaccounts
# Impersonate-User: system:serviceaccount:team-a-system:team-a-rbac-applier
```

### Policy Limits for Role Generation (Mirroring)

The `RBACPolicy` includes specific limits for `RestrictedRoleDefinition` (role generation/mirroring):

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: tenant-team-a-policy
spec:
  # ... other limits ...
  
  # ============================================
  # MIRRORING LIMITS
  # ============================================
  mirroringLimits:
    # Allow mirroring at all
    allowMirroring: true
    
    # Limit which source namespaces can be referenced for Role mirroring
    # (prevents tenants from mirroring admin roles from privileged namespaces)
    allowedSourceNamespaceSelector:
      matchLabels:
        tenant: team-a
    
    # Explicit list of allowed source namespaces
    allowedSourceNamespaces:
      - team-a-shared
      - team-a-templates
    
    # Forbidden source namespaces (always takes precedence)
    forbiddenSourceNamespaces:
      - kube-system
      - kube-public
      - default
    
    # Forbidden source namespace prefixes (bare prefix, matches "prefix*")
    forbiddenSourcePrefixes:
      - "kube-"
      - "team-b-"  # Other tenant's namespaces
    
    # Restrict which roles can be mirrored (by name prefix/suffix)
    allowedRolePrefixes:
      - "team-a-"
      - "shared-"
    
    forbiddenRoleSuffixes:
      - "-admin"
      - "-privileged"
    
    # Maximum number of target namespaces per RestrictedRoleDefinition
    maxMirrorTargets: 20
    
    # Content validation for mirrored roles
    # (validates the actual Role content, not just the reference)
    validateMirroredContent: true
    
    # If validateMirroredContent is true, these limits apply to the role being mirrored
    mirroredContentLimits:
      forbiddenVerbs:
        - "*"
        - impersonate
        - escalate
        - bind
      forbiddenResources:
        - secrets
        - nodes
      forbiddenAPIGroups:
        - "admissionregistration.k8s.io"
```

### How Role Generation Works

1. Tenant creates `RestrictedRoleDefinition` with `sourceRef` (or inline `rules`)
2. Controller validates:
   - Source namespace matches `allowedSourceNamespaceSelector` / `allowedSourceNamespaces`
   - Source namespace not in `forbiddenSourceNamespaces` / prefixes
   - Role/ClusterRole name matches allowed prefixes (if set)
   - Role/ClusterRole name not in forbidden suffixes
3. If `validateMirroredContent: true`:
   - Fetch the actual Role/ClusterRole content
   - Validate its rules against `mirroredContentLimits` (inherits `roleLimits`)
   - Reject if source contains forbidden verbs/resources/apiGroups
4. For each target namespace:
   - Validate against standard `targetNamespaceLimits`
   - **Create a new Role** (copying rules from source)
   - Track generated Role in status
5. Watch for changes to source Role/ClusterRole and re-sync

**Key point**: Even if `sourceRef.kind: ClusterRole`, the **output is always namespace-scoped Roles**.

## Continuous Enforcement & Deprovisioning

Policy compliance is enforced at **two levels**:

### 1. Admission-Time Validation

The webhook validates on CREATE/UPDATE:
- Reject non-compliant resources immediately
- Provide clear error messages
- Record audit information (creator, timestamp)

### 2. Reconcile-Time Validation

The controller re-validates on **every reconcile cycle**:

```go
func (r *RestrictedBindDefinitionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // 1. Fetch RestrictedBindDefinition
    rbd := &authorizationv1alpha1.RestrictedBindDefinition{}
    if err := r.Get(ctx, req.NamespacedName, rbd); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }
    
    // 2. Fetch referenced RBACPolicy
    policy := &authorizationv1alpha1.RBACPolicy{}
    if err := r.Get(ctx, types.NamespacedName{Name: rbd.Spec.RBACPolicyRef.Name}, policy); err != nil {
        return r.handlePolicyNotFound(ctx, rbd, err)
    }
    
    // 3. Validate against current policy (policy may have changed)
    violations := r.validateAgainstPolicy(ctx, rbd, policy)
    
    // 4. Handle violations - DEPROVISION
    if len(violations) > 0 {
        return r.handleViolations(ctx, rbd, policy, violations)
    }
    
    // 5. Policy compliant - provision/update bindings
    return r.reconcileBindings(ctx, rbd, policy)
}
```

### Violation Handling & Deprovisioning

When violations are detected during reconcile:

```yaml
# Violation detected - bindings are REMOVED
status:
  policyCompliance:
    compliant: false
    lastChecked: "2026-02-08T15:00:00Z"
    appliedPolicy: tenant-team-a-policy
    policyGeneration: 6
    violations:
      - type: ForbiddenRoleRef
        message: "Role 'admin' is now forbidden by policy"
        detectedAt: "2026-02-08T15:00:00Z"
      - type: ForbiddenNamespace
        message: "Namespace 'team-a-legacy' no longer matches policy selector"
        detectedAt: "2026-02-08T15:00:00Z"
  
  conditions:
    - type: PolicyCompliant
      status: "False"
      reason: ViolationsDetected
      message: "2 policy violations detected, bindings deprovisioned"
    
    - type: Ready
      status: "False"
      reason: Deprovisioned
      message: "Bindings removed due to policy violation"
  
  # Track what was deprovisioned
  deprovisionedBindings:
    - name: my-app-developers-team-a-dev
      namespace: team-a-dev
      deprovisionedAt: "2026-02-08T15:00:05Z"
      reason: "ForbiddenRoleRef: admin"
```

### Deprovisioning Behavior Options

Configurable via RBACPolicy:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: tenant-team-a-policy
spec:
  # ... limits ...
  
  enforcement:
    # What to do when violations are detected during reconcile
    onViolation: Deprovision  # or: Warn, Block
    
    # Options:
    # - Deprovision: Remove all managed bindings/roles immediately
    # - Warn: Keep bindings but set status to non-compliant (grace period)
    # - Block: Keep existing bindings but prevent new ones
    
    # Grace period before deprovisioning (for Warn mode)
    gracePeriod: 24h
    
    # Notify on violation
    notifications:
      # Create Kubernetes Event
      createEvent: true
      # Emit metric
      emitMetric: true
```

### Triggers for Re-Validation

The controller re-validates when:

1. **RestrictedBD/RD changes** - standard reconcile
2. **RBACPolicy changes** - watch policies, re-reconcile all affected resources
3. **Namespace label changes** - namespace selector may now include/exclude namespaces
4. **Referenced Role changes** - for mirrored roles with content validation
5. **Periodic re-sync** - configurable interval (default: 1 hour)

```go
// Watch RBACPolicy and trigger reconcile for all RestrictedBDs using it
func (r *RestrictedBindDefinitionReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&authorizationv1alpha1.RestrictedBindDefinition{}).
        // Re-reconcile when policy changes
        Watches(
            &authorizationv1alpha1.RBACPolicy{},
            handler.EnqueueRequestsFromMapFunc(r.findRestrictedBDsForPolicy),
        ).
        // Re-reconcile when namespace labels change
        Watches(
            &corev1.Namespace{},
            handler.EnqueueRequestsFromMapFunc(r.findRestrictedBDsForNamespace),
        ).
        Complete(r)
}
```

## Policy Reference Enforcement

### Why Explicit Policy Reference?

The `rbacPolicyRef` field ensures:
1. **Explicit binding** - No ambiguity about which policy governs a resource
2. **Audit trail** - Clear lineage from resource to policy
3. **Multi-tenancy** - Different tenants can use different policies in same namespace
4. **Policy lifecycle** - Detect and handle policy deletion

### Enforcing Correct Policy Reference

Tenants could try to reference a more permissive policy. Enforcement options:

#### Option 1: Kyverno Policy (Recommended for existing Kyverno users)

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: enforce-rbac-policy-ref
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    # Rule 1: Validate rbacPolicyRef matches namespace tenant label
    - name: validate-policy-ref-by-tenant
      match:
        any:
          - resources:
              kinds:
                - RestrictedBindDefinition
                - RestrictedRoleDefinition
      validate:
        message: "rbacPolicyRef must match the tenant policy: tenant-{{request.namespace | split('-') | [0]}}-policy"
        pattern:
          spec:
            rbacPolicyRef:
              name: "tenant-{{request.namespace | split('-') | [0]}}-policy"
    
    # Rule 2: Validate rbacPolicyRef matches namespace label
    - name: validate-policy-ref-by-label
      match:
        any:
          - resources:
              kinds:
                - RestrictedBindDefinition
                - RestrictedRoleDefinition
      context:
        - name: nsLabels
          apiCall:
            urlPath: "/api/v1/namespaces/{{request.namespace}}"
            jmesPath: "metadata.labels"
      validate:
        message: "rbacPolicyRef must match namespace's 'rbac-policy' label"
        deny:
          conditions:
            any:
              - key: "{{ request.object.spec.rbacPolicyRef.name }}"
                operator: NotEquals
                value: "{{ nsLabels.\"authorization.t-caas.telekom.com/rbac-policy\" }}"
```

#### Option 2: Built-in Admission Webhook

```go
func (v *RestrictedBindDefinitionValidator) ValidateCreate(ctx context.Context, obj client.Object) (admission.Warnings, error) {
    rbd := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
    
    // Get namespace
    ns := &corev1.Namespace{}
    if err := v.Client.Get(ctx, types.NamespacedName{Name: rbd.Namespace}, ns); err != nil {
        return nil, fmt.Errorf("getting namespace %q: %w", rbd.Namespace, err)
    }
    
    // Check namespace label for required policy
    requiredPolicy := ns.Labels["authorization.t-caas.telekom.com/rbac-policy"]
    if requiredPolicy == "" {
        return nil, fmt.Errorf("namespace %q missing label 'authorization.t-caas.telekom.com/rbac-policy'", rbd.Namespace)
    }
    
    // Validate rbacPolicyRef matches
    if rbd.Spec.RBACPolicyRef.Name != requiredPolicy {
        return nil, fmt.Errorf("rbacPolicyRef must be %q (per namespace label), got %q", 
            requiredPolicy, rbd.Spec.RBACPolicyRef.Name)
    }
    
    // Continue with policy validation...
    return v.validateAgainstPolicy(ctx, rbd)
}
```

### Namespace Labeling for Policy Assignment

Platform admins assign policies to namespaces via labels:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: team-a-dev
  labels:
    tenant: team-a
    environment: development
    # Required: specifies which RBACPolicy governs this namespace
    authorization.t-caas.telekom.com/rbac-policy: tenant-team-a-policy
```

### Recording Audit Information

Audit trail is implemented via two complementary mechanisms:

1. **Mutating webhook** (`admission.Handler`): Sets metadata annotations on the
   resource to durably record who created/modified it. This requires an
   `admission.Handler` implementation (not `admission.Validator`) because
   `UserInfo` is only available from the `admission.Request`, and because the
   webhook must mutate the object to persist annotations.

2. **Controller reconciliation**: Copies durable annotation data into
   `.status.audit` for convenient read access and long-term visibility.

```go
// RestrictedBindDefinitionMutator implements admission.Handler to access
// the admission.Request (including UserInfo) and set metadata annotations.
type RestrictedBindDefinitionMutator struct {
    Client  client.Client
    decoder admission.Decoder
}

func (m *RestrictedBindDefinitionMutator) Handle(ctx context.Context,
    req admission.Request) admission.Response {
    rbd := &authorizationv1alpha1.RestrictedBindDefinition{}
    if err := m.decoder.Decode(req, rbd); err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }

    // Access user info directly from the admission request
    userInfo := req.UserInfo

    // Set durable metadata annotations on the object
    if rbd.Annotations == nil {
        rbd.Annotations = make(map[string]string)
    }

    now := time.Now().UTC().Format(time.RFC3339)
    if req.Operation == admissionv1.Create {
        rbd.Annotations["authorization.t-caas.telekom.com/created-by"] = userInfo.Username
        rbd.Annotations["authorization.t-caas.telekom.com/created-at"] = now
    }
    rbd.Annotations["authorization.t-caas.telekom.com/last-modified-by"] = userInfo.Username
    rbd.Annotations["authorization.t-caas.telekom.com/last-modified-at"] = now

    marshaledRBD, err := json.Marshal(rbd)
    if err != nil {
        return admission.Errored(http.StatusInternalServerError, err)
    }
    return admission.PatchResponseFromRaw(req.Object.Raw, marshaledRBD)
}
```

> **Design note:** The `admission.Validator` interface used by existing webhooks
> (e.g., `*_webhook.go`) does not provide access to `admission.Request` or
> `UserInfo`. For audit recording, a separate mutating webhook using
> `admission.Handler` is required. The validating webhook continues to perform
> policy checks independently. `AuditAnnotations` on admission responses only
> appear in API server audit logs and are **not** stored on the resource — hence
> metadata annotations are used for durable audit trail.


### 2. Development Team Self-Service

Allow specific groups with guardrails:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: dev-team-policy
spec:
  subjectLimits:
    allowedKinds:
      - Group
      - ServiceAccount
    
    groupLimits:
      # Allow groups starting with team-a- (simple prefix, NO regex)
      allowedPrefixes:
        - "team-a-"
      forbiddenGroups:
        - "team-a-admins"  # Admins handled separately
    
    serviceAccountLimits:
      allowedNamespaceSelector:
        matchLabels:
          tenant: team-a
```

### 3. Operator Cross-Namespace Permissions

Mirror operator SA permissions to managed namespaces:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy  
metadata:
  name: operator-policy
spec:
  subjectLimits:
    serviceAccountLimits:
      # Operator SAs can be referenced cross-namespace within tenant
      customRules:
        - name: operator-cross-ns
          match:
            subjects:
              - kind: ServiceAccount
                # Allow SAs ending with -operator (simple suffix, NO regex)
                nameSuffix: "-operator"
          require:
            namespaceLabelsMatch:
              - tenant
```

### 4. Compliance with Audit Trail

Centralized policy with approval workflow integration:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: compliance-policy
spec:
  subjectLimits:
    customRules:
      # Any group containing 'admin' in the name requires approval annotation
      - name: admin-approval-required
        match:
          subjects:
            - kind: Group
              # Match groups with admin prefix or suffix (simple wildcards, NO regex)
              namePrefix: "admin-"
            - kind: Group
              nameSuffix: "-admin"
            - kind: Group
              nameSuffix: "-admins"
        require:
          annotations:
            compliance.company.com/approved-by: "*"  # Any non-empty value
            compliance.company.com/ticket: "TICKET-*"  # Simple prefix match
  
  escalationPrevention:
    auditViolations: true
```

### 5. Impersonation-Based Least Privilege

Use impersonation to ensure the operator can only apply what a tenant-specific SA allows:

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: strict-tenant-policy
spec:
  appliesTo:
    namespaceSelector:
      matchLabels:
        tenant: team-a
  
  # Impersonation provides defense-in-depth
  # Even if operator has cluster-admin, it will only apply
  # what the impersonated SA is allowed to do
  impersonation:
    enabled: true
    serviceAccountRef:
      name: team-a-rbac-applier
      namespace: team-a-system
    # Fail closed if SA doesn't exist
    onImpersonationFailure: Deny
  
  # Policy limits still apply (double enforcement)
  bindingLimits:
    allowClusterRoleBindings: false
  
  roleLimits:
    forbiddenVerbs: ["*", "impersonate", "escalate", "bind"]
    forbiddenResources: [secrets, nodes]
```

The impersonation SA only needs permissions for what tenants can create:

```yaml
# Pre-created by platform admin
apiVersion: v1
kind: ServiceAccount
metadata:
  name: team-a-rbac-applier
  namespace: team-a-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-rbac-applier
rules:
  # Can only create/manage RoleBindings in tenant namespaces
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["rolebindings"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # Can only create/manage Roles in tenant namespaces
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # No ClusterRole/ClusterRoleBinding permissions - blocked at impersonation level
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: team-a-rbac-applier
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: tenant-rbac-applier
subjects:
  - kind: ServiceAccount
    name: team-a-rbac-applier
    namespace: team-a-system
```

This provides **three layers of protection**:
1. **Policy limits** - RBACPolicy forbids dangerous patterns
2. **RBAC escalation prevention** - User can't grant more than they have
3. **Impersonation limits** - Operator can't apply more than impersonated SA allows

### BindDefinition → ServiceAccount → RBACPolicy Workflow

The impersonation model integrates naturally with existing BindDefinitions. Platform admins
use a standard BindDefinition to provision ServiceAccounts with bounded permissions, then
reference those SAs in RBACPolicy for impersonation-based enforcement:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Platform Admin creates BindDefinition (manages permissions for tenant SA) │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  BindDefinition creates:                                                    │
│    - ServiceAccount: team-a-rbac-applier                                   │
│    - RoleBinding: grants limited RBAC permissions                          │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  RBACPolicy references SA via impersonation.serviceAccountRef              │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Tenant creates RestrictedBindDefinition (references RBACPolicy)           │
│    → Operator impersonates tenant SA when applying → limited blast radius  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Complete workflow example:**

```yaml
# Step 1: Platform admin creates BindDefinition for tenant's applier SA
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: BindDefinition
metadata:
  name: team-a-rbac-applier-permissions
  namespace: platform-system
spec:
  # Create the ServiceAccount in tenant's system namespace
  serviceAccountRef:
    name: team-a-rbac-applier
    namespace: team-a-system
    create: true

  # Grant limited RBAC permissions via RoleBindings in each tenant namespace
  bindingType: RoleBinding
  roleRef:
    kind: ClusterRole
    name: tenant-rbac-applier  # Pre-defined ClusterRole with limited permissions

  # Only apply in tenant's namespaces
  targetNamespaces:
    selector:
      matchLabels:
        tenant: team-a
---
# Step 2: The ClusterRole that defines max permissions for tenant
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tenant-rbac-applier
rules:
  # Can only manage Roles/RoleBindings (no ClusterRole/ClusterRoleBinding)
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings"]
    verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
  # Cannot manage: secrets, nodes, clusterroles, etc.
---
# Step 3: RBACPolicy references the SA for impersonation
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: team-a-policy
spec:
  appliesTo:
    namespaceSelector:
      matchLabels:
        tenant: team-a

  # Impersonate the SA provisioned by BindDefinition
  impersonation:
    enabled: true
    serviceAccountRef:
      name: team-a-rbac-applier
      namespace: team-a-system
    onImpersonationFailure: Deny

  # Additional policy limits (defense in depth)
  bindingLimits:
    allowClusterRoleBindings: false

  roleLimits:
    allowClusterRoles: false
---
# Step 4: Tenant creates RestrictedBindDefinition (references the policy)
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedBindDefinition
metadata:
  name: team-a-app-binding
  namespace: team-a-dev
spec:
  rbacPolicyRef:
    name: team-a-policy

  targetName: team-a-app
  
  # When operator reconciles this, it impersonates team-a-rbac-applier
  # If the SA lacks permissions, the apply fails → tenant can't escalate
  subjects:
    - kind: ServiceAccount
      name: my-app
      namespace: team-a-dev
  
  roleBindings:
    - clusterRoleRefs:
        - view
      namespace: team-a-dev
```

**Benefits of this workflow:**
- **Single source of truth** - BindDefinition manages what each tenant SA can do
- **Composable** - Reuse existing BindDefinition patterns for SA provisioning
- **Auditable** - Both BindDefinition and RBACPolicy are tracked resources
- **Self-contained** - Tenant doesn't need to know about impersonation internals

## Conflict Handling with RoleDefinition/BindDefinition

Restricted* CRDs coexist with existing RoleDefinition and BindDefinition resources. This section defines how conflicts are detected and resolved.

### Conflict Types

| Conflict Type | Example | Resolution |
|---------------|---------|------------|
| **Name collision** | `RestrictedRoleDefinition` generates Role `app-role`, existing `RoleDefinition` also creates `app-role` | **Reject** - RestrictedRoleDefinition fails validation |
| **Binding overlap** | Both target the same namespace with same `roleRef` | **Allow** - Multiple bindings to same role are valid K8s |
| **Subject conflict** | `RestrictedBindDefinition` binds group that `BindDefinition` already bound | **Allow** - Additive (K8s RBAC is additive) |
| **Permission escalation** | `RestrictedRoleDefinition` tries to reference Role owned by `RoleDefinition` | **Validate** - Must pass mirroringLimits |

### Ownership Model

Resources are tracked using standard Kubernetes owner references and field manager annotations:

```yaml
# Role generated by RestrictedRoleDefinition
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: operator-role-mirror
  namespace: team-a-app1
  ownerReferences:
    - apiVersion: authorization.t-caas.telekom.com/v1alpha1
      kind: RestrictedRoleDefinition
      name: operator-role-mirror
      controller: true
  annotations:
    # Field manager for SSA conflict detection
    authorization.t-caas.telekom.com/managed-by: RestrictedRoleDefinition/team-a-operators/operator-role-mirror
```

### Conflict Detection Rules

1. **Before generating a Role**, check if it already exists:
   - If owned by **this** RestrictedRoleDefinition → update via SSA
   - If owned by **another** RestrictedRoleDefinition → **reject** (name collision)
   - If owned by **RoleDefinition** → **reject** (cannot take ownership)
   - If owned by **nothing** (orphan) → **configurable**: adopt or reject

2. **Before creating a RoleBinding**, check if it conflicts:
   - Same `subjects[]` + `roleRef` + namespace → **idempotent** (no conflict)
   - Different `subjects[]` but same name → **reject** (name collision)

### Configuration for Conflict Handling

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: tenant-team-a-policy
spec:
  # ... other limits ...
  
  conflictHandling:
    # What to do when generated Role name collides with existing Role
    onRoleConflict: Reject  # Reject | AdoptOrphan
    
    # What to do when binding name collides
    onBindingConflict: Reject  # Reject | Merge
    
    # Prevent Restricted* resources from referencing Roles/ClusterRoles
    # managed by non-restricted RoleDefinitions
    blockCrossOwnerReference: true
```

### Impersonation × Conflict Interaction

When impersonation is enabled, conflicts are resolved **as the impersonated SA**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Tenant creates RestrictedRoleDefinition                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Controller checks for conflicts (as operator SA)                           │
│    - Name collision? → Reject before impersonation                         │
│    - Ownership conflict? → Reject before impersonation                     │
└─────────────────────────────────────────────────────────────────────────────┘
                              │ No conflicts
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  Controller impersonates tenant SA                                          │
│    - Apply Role via SSA (impersonated)                                     │
│    - If SA lacks 'roles' permission → apply fails (not privilege escalation)│
│    - Conflict with existing Role? → SSA rejects (field manager conflict)   │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key behaviors:**

1. **Conflict checks happen before impersonation** - The operator (with full permissions) validates ownership and naming before switching to impersonated context

2. **SSA field manager prevents silent overwrites** - If a Role field is managed by `RoleDefinition`, SSA will reject RestrictedRoleDefinition trying to change it

3. **Impersonated SA determines final apply success** - Even if policy allows and no conflicts, the impersonated SA must have permissions

### Example: RoleDefinition + RestrictedRoleDefinition Coexistence

Platform admin creates base roles via RoleDefinition:

```yaml
# Platform-managed base role (RoleDefinition)
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RoleDefinition
metadata:
  name: platform-base-role
spec:
  rules:
    - apiGroups: [""]
      resources: ["pods", "services"]
      verbs: ["get", "list", "watch"]
  targetNamespaces:
    selector:
      matchLabels:
        platform.t-caas.telekom.com/managed: "true"
```

Tenant extends with RestrictedRoleDefinition (different name, additive permissions):

```yaml
# Tenant-managed extension (RestrictedRoleDefinition)
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RestrictedRoleDefinition
metadata:
  name: tenant-app-role  # Different name - no conflict
  namespace: team-a-dev
spec:
  rbacPolicyRef:
    name: tenant-team-a-policy
  rules:
    - apiGroups: ["apps"]
      resources: ["deployments"]
      verbs: ["get", "list", "watch", "create", "update", "patch"]
  targetNamespaces:
    names:
      - team-a-dev
```

Both Roles exist in `team-a-dev` namespace - K8s RBAC is additive.

## Multi-Tenancy Enforcement

The policy enforcement can be implemented through multiple mechanisms, each with trade-offs:

### Option 1: Built-in Admission Webhooks (Recommended)

Ship validating admission webhooks as part of the auth-operator:

```yaml
# Auto-generated webhook configuration
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: auth-operator-restricted-resources
webhooks:
  - name: restricted-binddefinition.auth-operator.t-caas.telekom.com
    admissionReviewVersions: [v1]
    rules:
      - operations: [CREATE, UPDATE]
        apiGroups: [authorization.t-caas.telekom.com]
        apiVersions: [v1alpha1]
        resources: [restrictedbinddefinitions, restrictedroledefinitions]
    clientConfig:
      service:
        name: auth-operator-webhook
        namespace: kube-system
        path: /validate-restricted
    failurePolicy: Fail
    sideEffects: None
```

**Advantages:**
- Self-contained solution - no external dependencies
- Fast validation at admission time
- Consistent behavior across clusters
- Tight integration with RBACPolicy CRDs
- Atomic transaction: validate → reconcile
- Detailed error messages tailored to policy violations

**Disadvantages:**
- Webhook availability affects cluster operations
- Additional complexity in operator code

### Option 2: Kyverno Policies

Use Kyverno for policy enforcement if already deployed:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: restrict-rbac-policy
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    # Prevent forbidden ClusterRole references in ClusterRoleBindings
    - name: forbid-dangerous-cluster-roles
      match:
        any:
          - resources:
              kinds:
                - RestrictedBindDefinition
      validate:
        message: "Cannot bind to cluster-admin or system:* ClusterRoles"
        foreach:
          - list: "request.object.spec.clusterRoleBindings.clusterRoleRefs || `[]`"
            deny:
              conditions:
                any:
                  - key: "{{ element }}"
                    operator: Equals
                    value: "cluster-admin"
                  - key: "{{ element }}"
                    operator: AnyIn
                    value: "system:*"

    # Prevent forbidden ClusterRole references in RoleBindings
    - name: forbid-dangerous-role-binding-refs
      match:
        any:
          - resources:
              kinds:
                - RestrictedBindDefinition
      validate:
        message: "Cannot bind to cluster-admin or system:* ClusterRoles via RoleBindings"
        foreach:
          - list: "request.object.spec.roleBindings[].clusterRoleRefs[]"
            deny:
              conditions:
                any:
                  - key: "{{ element }}"
                    operator: Equals
                    value: "cluster-admin"
                  - key: "{{ element }}"
                    operator: AnyIn
                    value: "system:*"

    # Ensure rbacPolicyRef is set and matches the tenant's assigned policy
    - name: enforce-policy-ref
      match:
        any:
          - resources:
              kinds:
                - RestrictedBindDefinition
              namespaces:
                - "team-*-*"
      validate:
        message: "rbacPolicyRef must reference the tenant's assigned RBACPolicy"
        pattern:
          spec:
            rbacPolicyRef:
              name: "tenant-*"
```

**Advantages:**
- Leverages existing policy infrastructure
- GitOps-friendly policy management
- Rich policy language (CEL, JMESPath)
- Central policy visibility across teams
- Can apply to multiple resource types

**Disadvantages:**
- External dependency (Kyverno must be installed)
- Potential policy drift from RBACPolicy CRDs
- Two sources of truth for policy
- Limited integration with operator status reporting

### Option 3: Hybrid Approach

Combine built-in webhooks for core validation with Kyverno for tenant-specific customizations:

```
┌─────────────────────────────────────────────────────────────┐
│                    Admission Flow                           │
│                                                             │
│  RestrictedBindDefinition ──► Kyverno (Tenant Policy)       │
│         │                            │                      │
│         │                            ▼                      │
│         │                     Tenant-specific rules         │
│         │                     (naming, quotas, custom)      │
│         │                            │                      │
│         ▼                            ▼                      │
│  auth-operator webhook ◄──────────────┘                     │
│         │                                                   │
│         ▼                                                   │
│  RBACPolicy enforcement (core escalation prevention)        │
│         │                                                   │
│         ▼                                                   │
│  Allowed / Denied                                           │
└─────────────────────────────────────────────────────────────┘
```

**Division of Responsibility:**
| Concern | Enforcement |
|---------|-------------|
| Escalation prevention | auth-operator webhook |
| RBACPolicy limits | auth-operator webhook |
| Role content validation | auth-operator webhook |
| Tenant naming conventions | Kyverno |
| Resource quotas per tenant | Kyverno |
| Custom tenant restrictions | Kyverno |
| Audit logging | Both (complementary) |

### Option 4: Controller-Only Enforcement (Not Recommended)

Validate only during reconciliation (no admission webhook):

**Why this is problematic:**
- Invalid resources are accepted, then fail later
- Poor user experience (delayed error feedback)
- Resources persist in "invalid" state
- Potential security window between create and reconcile
- Hard to explain failures to users

### Recommendation

**Use Option 1 (Built-in Webhooks) as the default** with optional Kyverno integration:

1. **Core Protection**: Built-in webhooks handle all escalation prevention and RBACPolicy enforcement
2. **Immediate Feedback**: Users get validation errors at `kubectl apply` time
3. **No Dependencies**: Works out-of-box without Kyverno
4. **Kyverno Optional**: Platform teams can add Kyverno policies for:
   - Tenant-specific naming conventions
   - Custom restrictions per team
   - Integration with other cluster policies
   - Resource quotas and limits

### Webhook Implementation Details

> **Architecture note:** The webhook design separates concerns across three components:
>
> 1. **Validating webhook** (`admission.Validator`): Performs static policy-compliance
>    checks against the referenced `RBACPolicy`. This is the same pattern used by
>    existing webhooks (e.g., `*_webhook.go`). It does NOT perform escalation
>    prevention because `admission.Validator` does not expose `admission.Request`
>    or `UserInfo`.
>
> 2. **Mutating webhook** (`admission.Handler`): A separate mutating webhook used
>    ONLY for audit recording (setting creator/modifier annotations). It must not
>    reject requests on its own.
>
> 3. **Controller reconciliation**: Performs RBAC escalation prevention via
>    `SubjectAccessReview` (where impersonation context is available), and copies
>    durable annotation data into `.status.audit`.

```go
// RestrictedBindDefinitionValidator implements admission.Validator and is
// responsible only for policy-compliance checks against the referenced
// RBACPolicy. Escalation prevention is handled in the controller via
// SubjectAccessReview, not in this webhook.
type RestrictedBindDefinitionValidator struct {
    Client client.Client
}

// ValidateCreate validates a new RestrictedBindDefinition against its
// referenced RBACPolicy. It does not perform RBAC escalation checks.
func (v *RestrictedBindDefinitionValidator) ValidateCreate(ctx context.Context, obj client.Object) (admission.Warnings, error) {
    rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
    if !ok {
        return nil, fmt.Errorf("expected RestrictedBindDefinition, got %T", obj)
    }

    // 1. Read explicit policy reference from the RestrictedBindDefinition
    if rbd.Spec.RBACPolicyRef.Name == "" {
        return nil, fmt.Errorf("rbacPolicyRef.name is required")
    }

    // 2. Fetch the referenced RBACPolicy
    policy := &authorizationv1alpha1.RBACPolicy{}
    if err := v.Client.Get(ctx, client.ObjectKey{Name: rbd.Spec.RBACPolicyRef.Name}, policy); err != nil {
        return nil, fmt.Errorf("referenced RBACPolicy %q not found: %w", rbd.Spec.RBACPolicyRef.Name, err)
    }

    // 3. Verify the policy applies to this namespace (appliesTo check)
    if !v.policyAppliesToNamespace(policy, rbd.Namespace) {
        return nil, fmt.Errorf("RBACPolicy %q does not apply to namespace %q", policy.Name, rbd.Namespace)
    }

    // 4. Validate against policy limits (no escalation checks here)
    if err := v.validateBindingType(rbd, policy); err != nil {
        return nil, err
    }
    if err := v.validateRoleRef(rbd, policy); err != nil {
        return nil, err
    }
    if err := v.validateTargetNamespaces(ctx, rbd, policy); err != nil {
        return nil, err
    }
    if err := v.validateSubjects(rbd, policy); err != nil {
        return nil, err
    }

    // NOTE: Escalation prevention is handled in the controller using
    // SubjectAccessReview; the validating webhook only enforces static policy.
    return nil, nil
}

// ValidateUpdate reuses the same validation logic as create.
func (v *RestrictedBindDefinitionValidator) ValidateUpdate(ctx context.Context, oldObj, newObj client.Object) (admission.Warnings, error) {
    return v.ValidateCreate(ctx, newObj)
}

// ValidateDelete currently does not enforce additional checks.
func (v *RestrictedBindDefinitionValidator) ValidateDelete(_ context.Context, _ client.Object) (admission.Warnings, error) {
    return nil, nil
}
```

> **Escalation prevention in the controller:** During reconciliation, the
> controller performs `SubjectAccessReview` checks on behalf of the user who
> created/updated the binding (recorded in metadata annotations by the mutating
> webhook). This ensures users cannot grant permissions they don't have, while
> keeping the validating webhook simple and stateless.

## Unified Selector Model

All allow/forbid lists support a consistent selector model combining explicit values, simple wildcards (NO regex), and label selectors:

### Selector Type Definition

```go
// UnifiedSelector provides flexible matching for any resource type.
// Uses simple wildcards (prefix*, *suffix) — NO regex support.
//
// This type is used throughout the RBACPolicy spec for allow/forbid fields
// (e.g., allowedNamespaces, forbiddenNamespaces, etc.).
type UnifiedSelector struct {
    // Explicit list of allowed/forbidden values (exact match)
    Names []string `json:"names,omitempty"`
    
    // Prefix wildcard patterns, specified with a trailing "*" (e.g., "team-a-*"
    // matches "team-a-dev", "team-a-prod"). Values MUST include the "*" suffix;
    // there is no implicit wildcarding.
    Prefixes []string `json:"prefixes,omitempty"`
    
    // Suffix wildcard patterns, specified with a leading "*" (e.g., "*-admin"
    // matches "team-a-admin", "cluster-admin"). Values MUST include the leading
    // "*"; there is no implicit wildcarding.
    Suffixes []string `json:"suffixes,omitempty"`
    
    // Label selector for matching against resource labels
    // (e.g., namespace labels, role labels if annotated)
    // Uses standard Kubernetes LabelSelector (matchLabels, matchExpressions)
    LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}
```

### Go Type Definitions

> **Note:** The types below provide the complete proposed Go type definitions
> for all three CRDs. They reference the `UnifiedSelector` type above for
> all allow/forbid fields, ensuring a consistent API shape across the proposal.
> Nested types referenced by `RBACPolicySpec` are fully defined.
>
> Existing types like `ClusterBinding` and `NamespaceBinding` from
> `binddefinition_types.go` are reused where applicable. Each CRD includes its
> corresponding `*List` type and `init()` registration with `SchemeBuilder`,
> following the codebase pattern established in `binddefinition_types.go`.

```go
// Note: In real Go source files, add the appropriate SPDX license header comments here.

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=rbacpolicies,scope=Cluster,shortName=rbacpol
// +kubebuilder:subresource:status

// RBACPolicy defines cluster-wide or namespace-scoped RBAC limits for tenants.
type RBACPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RBACPolicySpec   `json:"spec,omitempty"`
	Status            RBACPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RBACPolicyList contains a list of RBACPolicy.
type RBACPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RBACPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RBACPolicy{}, &RBACPolicyList{})
}

// RBACPolicySpec defines the desired state of RBACPolicy.
type RBACPolicySpec struct {
	// AppliesTo defines which namespaces this policy governs.
	// +kubebuilder:validation:Required
	AppliesTo PolicyScope `json:"appliesTo"`

	// BindingLimits constrains what bindings tenants may create.
	// +kubebuilder:validation:Optional
	BindingLimits *BindingLimits `json:"bindingLimits,omitempty"`

	// RoleLimits constrains what roles/rules tenants may define.
	// +kubebuilder:validation:Optional
	RoleLimits *RoleLimits `json:"roleLimits,omitempty"`

	// SubjectLimits constrains which subjects may be bound.
	// +kubebuilder:validation:Optional
	SubjectLimits *SubjectLimits `json:"subjectLimits,omitempty"`

	// EscalationPrevention configures privilege escalation checks.
	// +kubebuilder:validation:Optional
	EscalationPrevention *EscalationPrevention `json:"escalationPrevention,omitempty"`

	// Impersonation configures impersonation-based enforcement.
	// +kubebuilder:validation:Optional
	Impersonation *ImpersonationConfig `json:"impersonation,omitempty"`

	// MirroringLimits constrains RestrictedRoleDefinition mirroring.
	// +kubebuilder:validation:Optional
	MirroringLimits *MirroringLimits `json:"mirroringLimits,omitempty"`

	// Enforcement configures violation handling behavior.
	// +kubebuilder:validation:Optional
	Enforcement *EnforcementConfig `json:"enforcement,omitempty"`

	// ConflictHandling configures how naming conflicts are resolved.
	// +kubebuilder:validation:Optional
	ConflictHandling *ConflictHandlingConfig `json:"conflictHandling,omitempty"`
}

// PolicyScope defines which namespaces the RBACPolicy governs.
type PolicyScope struct {
	// NamespaceSelector selects namespaces by label (standard K8s LabelSelector).
	// +kubebuilder:validation:Optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// Namespaces is an explicit list of namespace names (OR with selector).
	// +kubebuilder:validation:Optional
	Namespaces []string `json:"namespaces,omitempty"`
}

// BindingLimits constrains what bindings tenants may create.
type BindingLimits struct {
	// AllowClusterRoleBindings controls whether CRBs are permitted at all.
	// +kubebuilder:default=true
	AllowClusterRoleBindings bool `json:"allowClusterRoleBindings,omitempty"`

	// ClusterRoleBindingLimits restricts CRB creation details.
	// +kubebuilder:validation:Optional
	ClusterRoleBindingLimits *RoleRefLimits `json:"clusterRoleBindingLimits,omitempty"`

	// RoleBindingLimits restricts RoleBinding creation details.
	// +kubebuilder:validation:Optional
	RoleBindingLimits *RoleRefLimits `json:"roleBindingLimits,omitempty"`

	// TargetNamespaceLimits restricts which namespaces bindings may target.
	// +kubebuilder:validation:Optional
	TargetNamespaceLimits *NamespaceLimits `json:"targetNamespaceLimits,omitempty"`
}

// RoleRefLimits constrains which Roles/ClusterRoles may be referenced.
type RoleRefLimits struct {
	AllowedRoleRefs         []string              `json:"allowedRoleRefs,omitempty"`
	AllowedRoleRefSelector  *metav1.LabelSelector `json:"allowedRoleRefSelector,omitempty"`
	ForbiddenRoleRefs       []string              `json:"forbiddenRoleRefs,omitempty"`
	ForbiddenRoleRefSelector *metav1.LabelSelector `json:"forbiddenRoleRefSelector,omitempty"`
}

// NamespaceLimits constrains which namespaces may be targeted.
type NamespaceLimits struct {
	AllowedNamespaceSelector  *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`
	ForbiddenNamespaces       []string              `json:"forbiddenNamespaces,omitempty"`
	ForbiddenNamespacePrefixes []string             `json:"forbiddenNamespacePrefixes,omitempty"`
	MaxTargetNamespaces       *int32                `json:"maxTargetNamespaces,omitempty"`
}

// RoleLimits constrains what roles and rules tenants may define.
type RoleLimits struct {
	AllowClusterRoles   bool                    `json:"allowClusterRoles,omitempty"`
	ForbiddenVerbs      []string                `json:"forbiddenVerbs,omitempty"`
	ForbiddenResources  []string                `json:"forbiddenResources,omitempty"`
	ForbiddenAPIGroups  []string                `json:"forbiddenAPIGroups,omitempty"`
	ForbiddenResourceVerbs []ResourceVerbRule   `json:"forbiddenResourceVerbs,omitempty"`
	MaxRulesPerRole     *int32                  `json:"maxRulesPerRole,omitempty"`
}

// ResourceVerbRule forbids specific resource + verb combinations.
type ResourceVerbRule struct {
	Resource string   `json:"resource"`
	APIGroup string   `json:"apiGroup,omitempty"`
	Verbs    []string `json:"verbs"`
}

// SubjectLimits constrains which subjects may be bound.
type SubjectLimits struct {
	// AllowedKinds restricts subject kinds (e.g., ["ServiceAccount"]).
	// Mutually exclusive with ForbiddenKinds.
	AllowedKinds   []string `json:"allowedKinds,omitempty"`
	ForbiddenKinds []string `json:"forbiddenKinds,omitempty"`

	UserLimits           *NameMatchLimits       `json:"userLimits,omitempty"`
	GroupLimits          *NameMatchLimits       `json:"groupLimits,omitempty"`
	ServiceAccountLimits *ServiceAccountLimits  `json:"serviceAccountLimits,omitempty"`
	CustomRules          []CustomSubjectRule    `json:"customRules,omitempty"`
}

// NameMatchLimits provides allow/forbid by name, prefix, and suffix.
type NameMatchLimits struct {
	AllowedNames      []string `json:"allowedNames,omitempty"`
	ForbiddenNames    []string `json:"forbiddenNames,omitempty"`
	AllowedPrefixes   []string `json:"allowedPrefixes,omitempty"`
	ForbiddenPrefixes []string `json:"forbiddenPrefixes,omitempty"`
	AllowedSuffixes   []string `json:"allowedSuffixes,omitempty"`
	ForbiddenSuffixes []string `json:"forbiddenSuffixes,omitempty"`
}

// ServiceAccountLimits constrains SA subjects.
type ServiceAccountLimits struct {
	AllowedNamespaceSelector *metav1.LabelSelector `json:"allowedNamespaceSelector,omitempty"`
	AllowedNamespaces        *UnifiedSelector      `json:"allowedNamespaces,omitempty"`
	ForbiddenNamespaces      *UnifiedSelector      `json:"forbiddenNamespaces,omitempty"`
	ForbiddenNamespacePrefixes []string            `json:"forbiddenNamespacePrefixes,omitempty"`
	Creation                 *SACreationConfig     `json:"creation,omitempty"`
	NamespaceRules           []NamespaceRule       `json:"namespaceRules,omitempty"`
}

// SACreationConfig controls auto-creation of ServiceAccounts.
type SACreationConfig struct {
	AllowAutoCreate                bool                  `json:"allowAutoCreate,omitempty"`
	AllowedCreationNamespaceSelector *metav1.LabelSelector `json:"allowedCreationNamespaceSelector,omitempty"`
	AllowedCreationNamespaces      []string              `json:"allowedCreationNamespaces,omitempty"`
	AutomountServiceAccountToken   *bool                 `json:"automountServiceAccountToken,omitempty"`
	DisableAdoption                bool                  `json:"disableAdoption,omitempty"`
}

// NamespaceRule defines per-namespace SA restrictions.
type NamespaceRule struct {
	NamespaceSelector       *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
	Namespaces              []string              `json:"namespaces,omitempty"`
	AllowedServiceAccounts  []SARef               `json:"allowedServiceAccounts,omitempty"`
	ForbiddenServiceAccounts []SARef              `json:"forbiddenServiceAccounts,omitempty"`
}

// SARef references a ServiceAccount by name (supports simple wildcards).
type SARef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// CustomSubjectRule defines complex match/require validation rules.
type CustomSubjectRule struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Match and Require fields are intentionally left flexible for the proposal;
	// detailed struct definitions will be finalized during implementation.
}

// EscalationPrevention configures privilege escalation checks.
type EscalationPrevention struct {
	EnforceRBACEscalationPrevention bool `json:"enforceRBACEscalationPrevention,omitempty"`
	StrictPolicyEnforcement         bool `json:"strictPolicyEnforcement,omitempty"`
	AuditViolations                 bool `json:"auditViolations,omitempty"`
}

// ImpersonationConfig controls impersonation-based enforcement.
type ImpersonationConfig struct {
	Enabled                 bool              `json:"enabled,omitempty"`
	ServiceAccountRef       SARef             `json:"serviceAccountRef,omitempty"`
	AutoCreateServiceAccount bool             `json:"autoCreateServiceAccount,omitempty"`
	PerNamespace            *PerNamespaceConfig `json:"perNamespace,omitempty"`

	// OnImpersonationFailure controls fail-safe behavior.
	// Supported values: "Deny", "AllowWithAudit".
	// +kubebuilder:default=Deny
	// +kubebuilder:validation:Enum=Deny;AllowWithAudit
	OnImpersonationFailure string `json:"onImpersonationFailure,omitempty"`
}

// PerNamespaceConfig enables per-namespace impersonation SAs.
type PerNamespaceConfig struct {
	Enabled                    bool   `json:"enabled,omitempty"`
	ServiceAccountNameTemplate string `json:"serviceAccountNameTemplate,omitempty"`
}

// MirroringLimits constrains RestrictedRoleDefinition mirroring.
type MirroringLimits struct {
	AllowMirroring              bool                  `json:"allowMirroring,omitempty"`
	AllowedSourceNamespaceSelector *metav1.LabelSelector `json:"allowedSourceNamespaceSelector,omitempty"`
	AllowedSourceNamespaces     []string              `json:"allowedSourceNamespaces,omitempty"`
	ForbiddenSourceNamespaces   []string              `json:"forbiddenSourceNamespaces,omitempty"`
	ForbiddenSourcePrefixes     []string              `json:"forbiddenSourcePrefixes,omitempty"`
	AllowedRolePrefixes         []string              `json:"allowedRolePrefixes,omitempty"`
	ForbiddenRoleSuffixes       []string              `json:"forbiddenRoleSuffixes,omitempty"`
	MaxMirrorTargets            *int32                `json:"maxMirrorTargets,omitempty"`
	ValidateMirroredContent     bool                  `json:"validateMirroredContent,omitempty"`
}

// EnforcementConfig configures violation handling.
type EnforcementConfig struct {
	// OnViolation defines behavior when violations are detected.
	// Supported values: "Deprovision", "Warn", "Block".
	// +kubebuilder:default=Deprovision
	// +kubebuilder:validation:Enum=Deprovision;Warn;Block
	OnViolation string `json:"onViolation,omitempty"`

	GracePeriod *metav1.Duration `json:"gracePeriod,omitempty"`
}

// ConflictHandlingConfig configures naming conflict resolution.
type ConflictHandlingConfig struct {
	OnRoleConflict           string `json:"onRoleConflict,omitempty"`
	OnBindingConflict        string `json:"onBindingConflict,omitempty"`
	BlockCrossOwnerReference bool   `json:"blockCrossOwnerReference,omitempty"`
}

// RBACPolicyStatus defines the observed state of RBACPolicy.
type RBACPolicyStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}
```

```go
// Note: In real Go source files, add the appropriate SPDX license header comments here.

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=restrictedbinddefinitions,scope=Namespaced,shortName=rbinddef
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Ready",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="Policy",type="string",JSONPath=".spec.policyRef.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status

// RestrictedBindDefinition creates bindings within policy limits.
type RestrictedBindDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RestrictedBindDefinitionSpec   `json:"spec,omitempty"`
	Status            RestrictedBindDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RestrictedBindDefinitionList contains a list of RestrictedBindDefinition.
type RestrictedBindDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RestrictedBindDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RestrictedBindDefinition{}, &RestrictedBindDefinitionList{})
}

// RestrictedBindDefinitionSpec defines the desired state.
type RestrictedBindDefinitionSpec struct {
	// RBACPolicyRef is the explicit reference to the governing RBACPolicy.
	// +kubebuilder:validation:Required
	RBACPolicyRef RBACPolicyReference `json:"rbacPolicyRef"`

	// TargetName is a name prefix for generated bindings.
	TargetName string `json:"targetName,omitempty"`

	// Subjects lists the subjects to bind.
	Subjects []rbacv1.Subject `json:"subjects,omitempty"`

	// AutomountServiceAccountToken controls token mounting for managed SAs.
	// +kubebuilder:default=true
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`

	// ClusterRoleBindings defines cluster-scoped bindings.
	// Reuses ClusterBinding from existing BindDefinition types.
	ClusterRoleBindings *ClusterBinding `json:"clusterRoleBindings,omitempty"`

	// RoleBindings defines namespace-scoped bindings.
	// Reuses NamespaceBinding from existing BindDefinition types.
	RoleBindings []NamespaceBinding `json:"roleBindings,omitempty"`
}

// RBACPolicyReference is a reference to an RBACPolicy by name.
type RBACPolicyReference struct {
	// Name of the cluster-scoped RBACPolicy.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
}
```

```go
// Note: In real Go source files, add the appropriate SPDX license header comments here.

// +kubebuilder:object:root=true
// +kubebuilder:resource:path=restrictedroledefinitions,scope=Namespaced,shortName=rroledef
// +kubebuilder:subresource:status

// RestrictedRoleDefinition creates roles within policy limits.
type RestrictedRoleDefinition struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RestrictedRoleDefinitionSpec   `json:"spec,omitempty"`
	Status            RestrictedRoleDefinitionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RestrictedRoleDefinitionList contains a list of RestrictedRoleDefinition.
type RestrictedRoleDefinitionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RestrictedRoleDefinition `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RestrictedRoleDefinition{}, &RestrictedRoleDefinitionList{})
}

// RestrictedRoleDefinitionSpec defines the desired state.
type RestrictedRoleDefinitionSpec struct {
	// RBACPolicyRef is the explicit reference to the governing RBACPolicy.
	// +kubebuilder:validation:Required
	RBACPolicyRef RBACPolicyReference `json:"rbacPolicyRef"`

	// Rules defines inline RBAC rules (mutually exclusive with SourceRef).
	Rules []rbacv1.PolicyRule `json:"rules,omitempty"`

	// SourceRef mirrors rules from an existing Role or ClusterRole.
	SourceRef *SourceReference `json:"sourceRef,omitempty"`

	// TargetNamespaces selects where Roles will be generated.
	TargetNamespaces NamespaceTarget `json:"targetNamespaces,omitempty"`
}

// SourceReference points to an existing Role or ClusterRole for mirroring.
type SourceReference struct {
	Kind      string `json:"kind"`      // "Role" or "ClusterRole"
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"` // Required for Kind=Role
}

// NamespaceTarget selects namespaces by selector and/or explicit list.
type NamespaceTarget struct {
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
	Names    []string              `json:"names,omitempty"`
}
```

### Example: Namespace Selection with All Methods

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: comprehensive-example
spec:
  bindingLimits:
    targetNamespaceLimits:
      # Method 1: Explicit allowed namespaces (exact match)
      allowedNamespaces:
        names:
          - team-a-dev
          - team-a-staging
          - team-a-prod
    
      # Method 2: Prefix-based (simple wildcard, NO regex)
      # Matches: team-a-dev, team-a-staging, team-a-anything
      allowedNamespacePrefixes:
        - "team-a-*"
    
      # Method 3: Suffix-based (simple wildcard, NO regex)
      # Matches: team-a-dev, team-b-dev
      allowedNamespaceSuffixes:
        - "*-dev"
    
      # Method 4: Label selector (preferred for dynamic environments)
      # Standard K8s LabelSelector - most flexible option
      allowedNamespaceSelector:
        matchLabels:
          tenant: team-a
        matchExpressions:
          - key: environment
            operator: In
            values: [dev, staging, prod]
          - key: deprecated
            operator: DoesNotExist
    
      # Forbidden always takes precedence
      forbiddenNamespaces:
        names:
          - kube-system
          - kube-public
      forbiddenNamespacePrefixes:
        - "kube-*"
        - "istio-*"
      forbiddenNamespaceSelector:
        matchLabels:
          protected: "true"
```

### Example: Subject Selection with Label Selectors

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: subject-selector-example
spec:
  subjectLimits:
    serviceAccountLimits:
      # Select SAs by their namespace labels
      allowedNamespaceSelector:
        matchLabels:
          tenant: team-a
        matchExpressions:
          - key: environment
            operator: In
            values: [dev, staging]
      
      # Select SAs by their own labels (if ServiceAccounts are labeled)
      allowedServiceAccountSelector:
        matchLabels:
          purpose: application
        matchExpressions:
          - key: risk-level
            operator: NotIn
            values: [high, critical]
      
      # Select SAs by name prefix (simple wildcard, NO regex)
      allowedServiceAccountPrefixes:
        - "app-"
        - "svc-"
      
      # Forbid privileged SA names
      forbiddenServiceAccountPrefixes:
        - "admin-"
        - "root-"
```

### Example: Role Reference Selection

```yaml
apiVersion: authorization.t-caas.telekom.com/v1alpha1
kind: RBACPolicy
metadata:
  name: role-selector-example
spec:
  bindingLimits:
    roleBindingLimits:
      # Allow roles by name prefix (simple wildcard, NO regex)
      allowedRoleRefPrefixes:
        - "team-a-"
        - "shared-"
      
      # Forbid roles by suffix (simple wildcard, NO regex)
      forbiddenRoleRefSuffixes:
        - "-admin"
        - "-superuser"
      
      # Forbid roles with specific labels (if ClusterRoles are labeled)
      forbiddenRoleRefSelector:
        matchExpressions:
          - key: authorization.t-caas.telekom.com/privilege-level
            operator: In
            values: [admin, superuser]
          - key: rbac.authorization.k8s.io/aggregate-to-admin
            operator: Exists
```

### Selector Evaluation Order

When multiple selection methods are specified:

1. **Forbidden always wins** — if any forbidden selector matches, reject immediately
2. **At least one allowed selector must match** — OR (union) logic between different allowed selector types
3. **Within a selector type, OR logic** — matching any name, prefix, or suffix in the list is sufficient

```
Evaluation:
  # Step 1: Forbidden selectors (any match → REJECT immediately)
  IF matches(forbiddenNames) OR matches(forbiddenPrefixes) OR matches(forbiddenSuffixes) OR matches(forbiddenLabelSelector):
    REJECT with error "value is explicitly forbidden by policy"
  
  # Step 2: Default-deny MUST short-circuit when the policy omits this dimension.
  # If the resource requires this dimension but the policy defines no allowed
  # selectors at all, reject with an explicit "no policy defined" style error
  # so operators can distinguish it from "value not allowed".
  IF (no allowed selectors are defined) AND (resource requires this dimension):
    REJECT with error "dimension <name> has no allowed values configured in RBACPolicy"
  
  # Step 3: Allowed selectors (any match → ALLOW, i.e., union/OR)
  IF matches(allowedNames) OR matches(allowedPrefixes) OR matches(allowedSuffixes) OR matches(allowedLabelSelector):
    ALLOW
  
  # Step 4: Allowed selectors are defined but none matched for this resource → REJECT
  # This represents "value not allowed by policy", not "no policy defined".
  REJECT with error "value does not match any allowed selector in policy"
```

## Implementation Notes

- `RBACPolicy` should be cluster-scoped (managing multiple namespaces)
- Multiple policies can match — most restrictive wins across policies (deny-by-default when policies conflict)
- Consider policy inheritance (base policy + tenant-specific overrides)
- Integration with k8s-breakglass for temporary policy bypass with approval
- Support dry-run mode for testing policies before enforcement
- Metrics for policy violations and blocked escalation attempts
- **Continuous enforcement**: Re-validate on every reconcile, deprovision on violation
- **Audit trail**: Record creator/modifier in annotations, copy to status
- **Watch dependencies**: Policy changes, namespace label changes, referenced role changes
- **Label selector caching**: Cache resolved selectors for performance

## Related

- [k8s-breakglass](https://github.com/telekom/k8s-breakglass) - Temporary privilege escalation system
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) - Native RBAC documentation
- [Kyverno](https://kyverno.io/) - Kubernetes native policy engine
- [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) - Alternative policy enforcement

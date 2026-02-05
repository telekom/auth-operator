<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# T-CaaS Platform Integration

This document describes how the auth-operator is used within the T-CaaS (Telekom Container as a Service) platform. It covers the specific RBAC model, cluster participants, group naming conventions, and role mappings used in T-CaaS environments.

> **Note:** This document is specific to T-CaaS deployments. For general auth-operator usage, see the main [README](../README.md).

## Table of Contents

- [Cluster Participants](#cluster-participants)
  - [Owners](#owners)
  - [Non-owners](#non-owners)
  - [Participants Toggle](#participants-toggle)
- [Group Naming Convention](#group-naming-convention)
- [Role Mappings](#role-mappings)
  - [Platform Team](#platform-team)
  - [Tenant](#tenant)
  - [Third Parties](#third-parties)
  - [Onboarding Team](#onboarding-team)
  - [First Line Support](#first-line-support)

---

## Cluster Participants

T-CaaS platform recognizes several cluster participants organized in two categories. The first category is `owners` and the second category is `non-owners`. The `owners` category relates to those cluster participants that `own` Kubernetes API resources - `Pods`, `ConfigMaps`, `Secrets`, `Deployments`, `StatefulSets`, `Services`, etc. The `non-owners` category relates to those cluster participants that do not own any Kubernetes API resources. Instead, `non-owners` are organized by the `owners` participants to help with configuration or other actions inside the cluster on the objects owned by the `owners` category. As new `owners` and `non-owners` are recognized, the corresponding role mappings should be updated to reflect the correct situation of ownership or non-ownership of resources within the Kubernetes API.

### Owners

1. **Platform team** is the first `owner` of resources in the Kubernetes API. The platform team is the provider of the T-CaaS platform for its customers. The platform team owns namespaces prefixed with `kube-*` and namespaces which contain the label `t-caas.telekom.com/owner: platform`, as well as the majority of non-namespaced cluster-scoped resources. The ownership is exclusive in order to facilitate the proper functionality of the T-CaaS platform. The platform team has 3 distinctive roles through which members of the team are managed. These 3 roles are applicable to all clusters, in all sites, in all environments. Further role mappings are explained in more detail in the next chapter.

2. **Tenant** is the second `owner` of resources in the Kubernetes API. The tenant is the primary user of the T-CaaS platform through which they deliver NT and IT services. The tenant cannot be the `owner` of namespaces prefixed with `kube-*` and namespaces which contain the label `t-caas.telekom.com/owner: platform` or namespaces which contain the label `t-caas.telekom.com/owner: thirdparty`. Instead, the tenant is given rights to create namespaces and resources within those namespaces. The tenant also has rights to create some non-namespaced resources deemed safe by the platform team. The naming convention of tenant owned resources (both namespaced and non-namespaced) is exclusively determined by the tenant. To control access to namespaced resources for the tenant, on each namespace `create/update/delete` request to the Kubernetes API, the platform team will inject the proper labels into the namespace indicating the ownership and propagating RBAC to downstream resources. The labels that indicate tenant ownership are `t-caas.telekom.com/owner: tenant` and `t-caas.telekom.com/tenant: $tenantName`, where `$tenantName` is the name of that specific tenant. These labels cannot be overwritten by any of the cluster participants and are subject to a `ValidatingWebhook` which will check for validity of the request on namespace `create/update/delete` requests to the Kubernetes API. The tenant has 3 distinctive roles which are tenant-scoped, environment-scoped and cluster-scoped. Further role mappings are explained in more detail in the next chapter.

3. **Third parties** is the third `owner` of resources in the Kubernetes API. Third parties are the secondary users of the T-CaaS platform through which they deliver managed services to the tenant or to the platform team. Third parties cannot be the `owner` of namespaces prefixed with `kube-*` and namespaces which contain the label `t-caas.telekom.com/owner: platform` or namespaces which contain the label `t-caas.telekom.com/owner: tenant`. Instead, third parties are given rights to create namespaces and resources within those namespaces. Third parties also have rights to create some non-namespaced resources deemed safe by the platform team. The naming convention of third party owned resources (both namespaced and non-namespaced) is exclusively determined by the third party. To control access to namespaced resources for third parties, on each namespace `create/update/delete` request to the Kubernetes API, the platform team will inject the proper labels into the namespace indicating the ownership and propagating RBAC to downstream resources. The labels that indicate third party ownership are `t-caas.telekom.com/owner: thirdparty` and `t-caas.telekom.com/tenant: $thirdpartyName`, where `$thirdpartyName` is the name of that specific third party. These labels cannot be overwritten by any of the cluster participants and are subject to a `ValidatingWebhook` which will check for validity of the request on namespace `create/update/delete` requests to the Kubernetes API. Each third party team has 3 distinctive roles through which members of the team are managed. These 3 roles are applicable to all clusters, in all sites, in all environments. Further role mappings are explained in more detail in the next chapter.

Inside the cluster, there can be a single platform team, a single tenant and multiple third parties.

### Non-owners

1. **Onboarding team** is the first `non-owner` of resources in the Kubernetes API. The onboarding team provides network plumbing support to the platform team, tenant and third parties inside the cluster, as well as consulting and support services to the tenant and third parties relating to their service deployments. The onboarding team does not own any namespaces inside the cluster and thus has restricted access to all of them. The onboarding team also has rights to configure specific parts of the T-CaaS platform to satisfy tenant and third party needs. The onboarding team has 3 distinctive roles through which members of the team are managed. These 3 roles are applicable to all clusters, in all sites, in all environments. Further role mappings are explained in more detail in the next chapter.

2. **First line support** is the second `non-owner` of resources in the Kubernetes API. The first-line support team provides incident response services and can do very basic troubleshooting to resolve well-known issues on the platform. This team has the lowest privileges of all teams as they serve as the first responders, usually unable to resolve complex issues requiring elevated privileges. The first-line support team has 3 distinctive roles through which members of the team are managed. These 3 roles are applicable to all clusters, in all sites, in all environments. Further role mappings are explained in more detail in the next chapter.

Inside the cluster, there can be a single onboarding team, and a single first-line support team.

### Participants Toggle

It is important to note that not all cluster participants are part of the cluster by default. By default, only `ClusterRoles/Roles` and `ClusterRoleBindings/RoleBindings` for the platform team and for the tenant are created. These two cluster participants are always present in the T-CaaS Kubernetes cluster because the platform team provides the T-CaaS service, while the tenant is the ordering customer which requests a new instance from the T-CaaS platform team. Other cluster participants - third parties, onboarding and first-line support can be included or excluded from a cluster by toggling tenant settings on the `t-caas.telekom.com/v1alpha1` API group.

```yaml
apiVersion: t-caas.telekom.com/v1alpha1
kind: TCaasTenant
metadata:
  name: sample-tenant
  labels:
    t-caas.telekom.com/tenant-name: sample-tenant
spec:
  ...
  supportedBy:
    firstlineSupport: false
    onboardingSupport: true
    thirdPartySupport: true
    thirdPartyComponents:
      - istio
      - monitoring
  ...
```

The example above shows that any clusters which are owned by the tenant `sample-tenant` will have RBAC created for the onboarding team and for third parties - specifically third party teams supporting Istio service mesh and a custom monitoring stack. The example above is also a global tenant-wide setting. Which means it is applicable to *all* clusters owned by this tenant. However, we can provide per-cluster overrides to enable or disable a certain cluster participant via the `TCaasCluster` kind.

```yaml
apiVersion: t-caas.telekom.com/v1alpha1
kind: TCaasCluster
metadata:
  name: sample-cluster
  namespace: c-sample-namespace
spec:
  environment: test
  location: hrzagt5
  tenant:
    ref:
      name: sample-tenant
    overrides:
      supportedBy:
        firstlineSupport: true
        onboardingSupport: false
        thirdPartySupport: true
        thirdPartyComponents:
          - security
  ...
```

The example above shows that we have disabled onboarding teams RBAC in this specific cluster, and we have enabled RBAC for first-line support team. We have also overriden which third-party teams are granted access. This toggle allows for tenants to have globally uniform clusters which have the same cluster participants on all of them, and allows for being more specific - that is, granting access to certain cluster participants only on specific clusters.

---

## Group Naming Convention

The various IDP backend systems T-CaaS platform uses or will use should adhere to a common naming convention for IDP groups. The naming convention should stay the same across multiple IDPs, except using a prefix for multi-IDP authentication in a single cluster. Currently, there are 3 conventions that are employed in group naming and each of them applies to a different cluster participant.

| Global | Per-environment | Per-cluster |
| ------ | --------------- | ----------- |
| "$participantName"-"$permissionScope"-"$role" | "$participantName"-"$environment"-"$permissionScope"-"$role" | "$clusterName"-"$participantName"-"$siteLocation"-"$environment"-"$permissionScope"-"$role" |

Reading the naming convention in the above format may seem very abstract. However, let's take some example input values and construct groups names. The example values are the following:

```yaml
clusterName: 5gcore
participantName: sddata
siteLocation: hrzagt5
clusterEnv: prod
permissionScope: cluster
role: admin
```

| Global | Per-environment | Per-cluster |
| ------ | --------------- | ----------- |
| sddata-cluster-admin | sddata-prod-cluster-admin | 5gcore-sddata-hrzagt5-prod-cluster-admin |

These three formats will follow *some* cluster participants - namely **tenants**. Each tenant will be given a single global bundle of groups which will cover the whole tenant. This means that assignment to that group is applicable across environments and across clusters. Each tenant will be given a per-environment (test, ref, prod) bundle of groups which will cover the environment-specific accesses. It may be the case that a tenant wants a particular set of people to access production clusters, and another particular set of people to access test clusters. Thirdly, each tenant will be given a per-cluster bundle of groups which will be specific to that cluster only. Allowing the tenant to apply maximum granularity in assigning permissions to its team members.

Some other groups may not have this necessity - namely the platform team, the onboarding team, third-party teams and the first-line support team. These teams will only have `Global` mappings as their teams provide support to multiple cluster consumers across numerous clusters. It would be extremely unpractical and tedious to juggle membership per cluster for a platform team which **must** support all clusters. The same is true for onboarding, third-party teams and first-line support - as they gain access to a cluster by toggling the participant in the `TCaasTenant` specification or by providing overrides in the `TCaasCluster`. If you are unaware of this topic, please refer to the chapter above this one. Otherwise, proceed to role mappings and their respective permissions in the next chapter.

---

## Role Mappings

Role mappings are a way to uniquely identify the permission scope and may vary depending on the cluster participant. For some role mappings, you will see a total of 4 roles, but 2 of these roles are assigned through the same group-role mapping. The roles in question are `*-namespaced-reader` and `*-namespaced-reader-restricted`. These roles are assignable through group suffixed with `*-reader` because they are related to cluster participants of type `owners` where the `*-namespaced-reader` is a direct mapping to `owning` namespaces and `*-namespaced-reader-restricted` is a direct mapping to `non-owning` namespaces. These role mappings are subject to change and could be changed if new security circumstances arise.

### Platform Team

| Role | Description | Allowed verbs | Restricted API groups | Restricted API resources |
| ---- | ----------- | ------------- | --------------------- | ------------------------ |
| platform-poweruser | Can execute all verbs on resources. | create, delete, deletecollection, patch, update, get, list, watch | | |
| platform-collaborator | Can execute edit verbs on resources. | patch, update, get, list, watch | | |
| platform-reader | Can execute read verbs on resources. | get, list, watch | | |
| platform-reader-restricted | Can execute read verbs on resources in non-owned namespaces and a subset of cluster-scoped resources, except on restricted API groups and restricted API resources. This role is attached to tenant namespaces and third party namespaces. | get, list, watch | | secrets, pods/exec, pods/proxy, pods/attach, pods/portforward |

### Tenant

| Role | Description | Allowed verbs | Restricted API groups | Restricted API resources |
| ---- | ----------- | ------------- | --------------------- | ------------------------ |
| tenant-poweruser | Can execute all verbs on resources, except on restricted API groups and restricted API resources. | create, delete, deletecollection, patch, update, get, list, watch | authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, cert-manager.io/v1, crd.projectcalico.org/v1, node.k8s.io/v1, trident.netapp.io/v1 | nodes, nodes/proxy |
| tenant-collaborator | Can execute edit verbs on resources, except on restricted API groups and restricted API resources. | patch, update, get, list, watch | authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, cert-manager.io/v1, crd.projectcalico.org/v1, node.k8s.io/v1, trident.netapp.io/v1 | nodes, nodes/proxy |
| tenant-reader | Can execute read verbs on resources, except on restricted API groups and restricted API resources. | get, list, watch | | nodes/proxy |
| tenant-reader-restricted | Can execute read verbs on resources in non-owned namespaces and a subset of cluster-scoped resources, except on restricted API groups and restricted API resources. This role is attached to platform namespaces and third party namespaces. | get, list, watch | | secrets, pods/attach, pods/binding, pods/ephemeralcontainers, pods/eviction, pods/exec, pods/log, pods/portforward, pods/proxy, serviceaccounts/token, services/proxy |

### Third Parties

| Role | Description | Allowed verbs | Restricted API groups | Restricted API resources |
| ---- | ----------- | ------------- | --------------------- | ------------------------ |
| third-party-poweruser | Can execute all verbs on resources, except on restricted API groups and restricted API resources. | create, delete, deletecollection, patch, update, get, list, watch | authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, cert-manager.io/v1, crd.projectcalico.org/v1, node.k8s.io/v1, trident.netapp.io/v1 | nodes, nodes/proxy |
| third-party-collaborator | Can execute edit verbs on resources, except on restricted API groups and restricted API resources. | patch, update, get, list, watch | authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, cert-manager.io/v1, crd.projectcalico.org/v1, node.k8s.io/v1, trident.netapp.io/v1 | nodes, nodes/proxy |
| third-party-reader | Can execute read verbs on resources, except on restricted API groups and restricted API resources. | get, list, watch | | nodes/proxy |
| third-party-reader-restricted | Can execute read verbs on resources in non-owned namespaces and a subset of cluster-scoped resources, except on restricted API groups and restricted API resources. This role is attached to platform namespaces and tenant namespaces. | get, list, watch | | secrets, pods/attach, pods/binding, pods/ephemeralcontainers, pods/eviction, pods/exec, pods/log, pods/portforward, pods/proxy, serviceaccounts/token, services/proxy |

### Onboarding Team

| Role | Description | Allowed verbs | Restricted API groups | Restricted API resources |
| ---- | ----------- | ------------- | --------------------- | ------------------------ |
| onboarding-poweruser | Can execute all verbs on resources, except on restricted API groups and restricted API resources. | create, delete, deletecollection, patch, update, get, list, watch | acme.cert-manager.io/v1, admissionregistration.k8s.io/v1, apiextensions.k8s.io/v1, apiregistration.k8s.io/v1, authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, autoscaling/v2, batch/v1, cert-manager.io/v1, certificates.k8s.io/v1, coordination.k8s.io/v1, crd.projectcalico.org/v1, events.k8s.io/v1, flowcontrol.apiserver.k8s.io/v1, node.k8s.io/v1, policy/v1, rbac.authorization.k8s.io/v1, scheduling.k8s.io/v1, snapshot.storage.k8s.io/v1, storage.k8s.io/v1, trident.netapp.io/v1, velero.io/v1 | namespaces, namespaces/finalize, nodes, nodes/proxy, secrets, pods/attach, pods/ephemeralcontainers, pods/exec, pods/portforward, pods/proxy |
| onboarding-collaborator | Can execute edit verbs on resources, except on restricted API groups and restricted API resources. | patch, update, get, list, watch | acme.cert-manager.io/v1, admissionregistration.k8s.io/v1, apiextensions.k8s.io/v1, apiregistration.k8s.io/v1, authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, autoscaling/v2, batch/v1, cert-manager.io/v1, certificates.k8s.io/v1, coordination.k8s.io/v1, crd.projectcalico.org/v1, events.k8s.io/v1, flowcontrol.apiserver.k8s.io/v1, node.k8s.io/v1, policy/v1, rbac.authorization.k8s.io/v1, scheduling.k8s.io/v1, snapshot.storage.k8s.io/v1, storage.k8s.io/v1, trident.netapp.io/v1, velero.io/v1 | namespaces, namespaces/finalize, nodes, nodes/proxy, secrets, pods/attach, pods/ephemeralcontainers, pods/exec, pods/portforward, pods/proxy |
| onboarding-reader | Can execute read verbs on resources, except on restricted API groups and restricted API resources. | get, list, watch | | nodes/proxy, secrets, pods/attach, pods/ephemeralcontainers, pods/exec, pods/portforward, pods/proxy |

### First Line Support

| Role | Description | Allowed verbs | Restricted API groups | Restricted API resources |
| ---- | ----------- | ------------- | --------------------- | ------------------------ |
| first-line-poweruser | Can execute all verbs on resources, except on restricted API groups and restricted API resources. | create, delete, deletecollection, patch, update, get, list, watch | acme.cert-manager.io/v1, admissionregistration.k8s.io/v1, apiextensions.k8s.io/v1, apiregistration.k8s.io/v1, authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, autoscaling/v2, batch/v1, cert-manager.io/v1, certificates.k8s.io/v1, coordination.k8s.io/v1, crd.projectcalico.org/v1, events.k8s.io/v1, flowcontrol.apiserver.k8s.io/v1, node.k8s.io/v1, policy/v1, rbac.authorization.k8s.io/v1, scheduling.k8s.io/v1, snapshot.storage.k8s.io/v1, storage.k8s.io/v1, trident.netapp.io/v1, velero.io/v1 | namespaces, namespaces/finalize, nodes, nodes/proxy, secrets, pods/attach, pods/binding, pods/ephemeralcontainers, pods/eviction, pods/exec, pods/log, pods/portforward, pods/proxy, serviceaccounts/token, services/proxy |
| first-line-collaborator | Can execute edit verbs on resources, except on restricted API groups and restricted API resources. | patch, update, get, list, watch | acme.cert-manager.io/v1, admissionregistration.k8s.io/v1, apiextensions.k8s.io/v1, apiregistration.k8s.io/v1, authentication.t-caas.telekom.com/v1alpha1, authorization.t-caas.telekom.com/v1alpha1, autoscaling/v2, batch/v1, cert-manager.io/v1, certificates.k8s.io/v1, coordination.k8s.io/v1, crd.projectcalico.org/v1, events.k8s.io/v1, flowcontrol.apiserver.k8s.io/v1, node.k8s.io/v1, policy/v1, rbac.authorization.k8s.io/v1, scheduling.k8s.io/v1, snapshot.storage.k8s.io/v1, storage.k8s.io/v1, trident.netapp.io/v1, velero.io/v1 | namespaces, namespaces/finalize, nodes, nodes/proxy, secrets, pods/attach, pods/binding, pods/ephemeralcontainers, pods/eviction, pods/exec, pods/log, pods/portforward, pods/proxy, serviceaccounts/token, services/proxy |
| first-line-reader | Can execute read verbs on resources, except on restricted API groups and restricted API resources. | get, list, watch | | nodes/proxy, secrets, pods/attach, pods/binding, pods/ephemeralcontainers, pods/eviction, pods/exec, pods/log, pods/portforward, pods/proxy, serviceaccounts/token, services/proxy |

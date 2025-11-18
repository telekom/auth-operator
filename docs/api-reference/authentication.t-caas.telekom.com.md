# API Reference

## Packages
- [authentication.t-caas.telekom.com/v1alpha1](#authenticationt-caastelekomcomv1alpha1)


## authentication.t-caas.telekom.com/v1alpha1

Package v1alpha1 contains API Schema definitions for the authentication v1alpha1 API group

### Resource Types
- [AuthProvider](#authprovider)



#### AuthProvider



AuthProvider is the Schema for the authproviders API





| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `apiVersion` _string_ | `authentication.t-caas.telekom.com/v1alpha1` | | |
| `kind` _string_ | `AuthProvider` | | |
| `metadata` _[ObjectMeta](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta)_ | Refer to Kubernetes API documentation for fields of `metadata`. |  |  |
| `spec` _[AuthProviderSpec](#authproviderspec)_ |  |  |  |
| `status` _[AuthProviderStatus](#authproviderstatus)_ |  |  |  |


#### AuthProviderSpec



AuthProviderSpec defines the desired state of AuthProvider



_Appears in:_
- [AuthProvider](#authprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `authBackend` _[BackendURL](#backendurl)_ |  |  |  |
| `refreshBackend` _[BackendURL](#backendurl)_ |  |  |  |
| `tenant` _[ClusterConsumer](#clusterconsumer)_ |  |  |  |
| `thirdParty` _[ClusterConsumer](#clusterconsumer) array_ |  |  |  |


#### AuthProviderStatus



AuthProviderStatus defines the observed state of AuthProvider



_Appears in:_
- [AuthProvider](#authprovider)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `status` _string_ |  |  |  |
| `conditions` _[Condition](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#condition-v1-meta) array_ | Conditions defines current service state of the Auth provider<br />All conditions should evaluate to true to signify successful reconciliation |  | Optional: \{\} <br /> |


#### BackendURL







_Appears in:_
- [AuthProviderSpec](#authproviderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `host` _string_ |  |  |  |
| `port` _integer_ |  |  |  |
| `path` _string_ |  |  |  |


#### ClusterConsumer







_Appears in:_
- [AuthProviderSpec](#authproviderspec)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  |  |
| `owners` _string array_ |  |  |  |
| `members` _[OIDCMember](#oidcmember) array_ |  |  |  |
| `groups` _[OIDCGroup](#oidcgroup) array_ |  |  |  |








#### OIDCGroup







_Appears in:_
- [ClusterConsumer](#clusterconsumer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `groupType` _string_ |  |  |  |
| `parentGroup` _string_ |  |  |  |
| `groupNames` _string array_ |  |  |  |


#### OIDCMember







_Appears in:_
- [ClusterConsumer](#clusterconsumer)

| Field | Description | Default | Validation |
| --- | --- | --- | --- |
| `name` _string_ |  |  |  |
| `groupNames` _string array_ |  |  |  |



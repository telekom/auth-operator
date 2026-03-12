package webhooks

import (
	"context"
	"fmt"
	"strings"
	"time"

	authzv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// webhookListTimeout is the maximum duration webhook handlers wait for
// cache-backed List or Get calls. Informer-cache reads normally complete in
// microseconds; the timeout is a safety net for cold-cache or degraded
// API-server scenarios.
const webhookListTimeout = 5 * time.Second

// trackedOwnershipKeys defines the ownership label keys used for SA namespace
// label inheritance, label extraction, and extra-key detection.
var trackedOwnershipKeys = []string{
	authzv1alpha1.LabelKeyOwner,
	authzv1alpha1.LabelKeyTenant,
	authzv1alpha1.LabelKeyThirdParty,
}

/*
BYPASS ACCOUNT SECURITY MODEL

The webhook bypass mechanism allows specific trusted system accounts to perform
namespace operations without going through the full validation/mutation process.
This is necessary for critical cluster operations while maintaining security.

SECURITY CONSIDERATIONS:
1. All bypass decisions are logged at Info level with "AUDIT: webhook bypass granted"
   for security monitoring and forensic analysis.
2. Bypass accounts are hardcoded to prevent runtime modification attacks.
3. Each bypass is scoped as narrowly as possible (e.g., specific operation types,
   specific namespaces).

BYPASS CATEGORIES:

1. kubernetes-admin:
   - Full bypass for all operations
   - This is the cluster administrator account
   - Rationale: Admin needs unrestricted access for cluster management

2. Trident Operator (storage):
   - Account: system:serviceaccount:t-caas-storage:trident-operator
   - Scope: UPDATE operations on t-caas-storage namespace only
   - Rationale: Storage provisioner needs to update its own namespace

3. CAPI Operator Manager:
   - Account: system:serviceaccount:capi-operator-system:capi-operator-manager
   - Scope: UPDATE operations only
   - Rationale: Cluster API manager needs to manage cluster resources

4. TDG Migration Mode (temporary, enabled via flag):
   - helm-controller: For Flux Helm releases
   - kustomize-controller: For Flux Kustomizations
   - schiff-tenant/schiff-system m2m-sa: For migration automation
   - trident-system trident-operator: For storage migration
   - Rationale: Temporary bypasses during platform migration

MODIFYING BYPASS ACCOUNTS:
- Any changes to bypass accounts should be reviewed by security team
- Consider adding new accounts to TDG migration mode if temporary
- Always scope bypasses as narrowly as possible
- Ensure audit logging captures all bypass decisions.
*/

// Common service account constants.
const (
	kubernetesAdmin            = "kubernetes-admin"
	tridentOperatorStorageSA   = "system:serviceaccount:t-caas-storage:trident-operator"
	tridentOperatorSystemSA    = "system:serviceaccount:trident-system:trident-operator"
	helmControllerSA           = "system:serviceaccount:flux-system:helm-controller"
	kustomizeControllerSA      = "system:serviceaccount:flux-system:kustomize-controller"
	schiffTenantM2MSA          = "system:serviceaccount:schiff-tenant:m2m-sa"
	schiffSystemM2MSA          = "system:serviceaccount:schiff-system:m2m-sa"
	capiOperatorManagerSAConst = "system:serviceaccount:capi-operator-system:capi-operator-manager"

	// Namespace names for special cases.
	tridentStorageNamespace = "t-caas-storage"
	tridentSystemNamespace  = "trident-system"
)

// ServiceAccountInfo holds parsed service account information.
type ServiceAccountInfo struct {
	Namespace        string
	Name             string
	IsServiceAccount bool
}

// ParseServiceAccount parses a username to extract service account info.
// Format: system:serviceaccount:<namespace>:<name>.
func ParseServiceAccount(username string) ServiceAccountInfo {
	parts := strings.Split(username, ":")
	if len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
		return ServiceAccountInfo{
			Namespace:        parts[2],
			Name:             parts[3],
			IsServiceAccount: true,
		}
	}
	return ServiceAccountInfo{IsServiceAccount: false}
}

// BypassCheckResult represents the result of a bypass check.
type BypassCheckResult struct {
	ShouldBypass bool
	Reason       string
}

// CheckBypass checks if a request should bypass the namespace webhook (both mutator and validator).
// Returns true if the user is a known system account that should be allowed without processing.
func CheckBypass(username string, operation admissionv1.Operation, namespace string, tdgMigration bool) BypassCheckResult {
	// Allow kubernetes-admin without processing.
	if username == kubernetesAdmin {
		return BypassCheckResult{ShouldBypass: true, Reason: "kubernetes-admin"}
	}

	// Allow trident-operator for its own namespace
	if username == tridentOperatorStorageSA && operation == admissionv1.Update && namespace == tridentStorageNamespace {
		return BypassCheckResult{ShouldBypass: true, Reason: "trident-operator for t-caas-storage"}
	}

	// Allow capi-operator-manager for updates
	if username == capiOperatorManagerSAConst && operation == admissionv1.Update {
		return BypassCheckResult{ShouldBypass: true, Reason: "capi-operator-manager"}
	}

	// TDG migration specific bypasses
	if tdgMigration {
		switch username {
		case helmControllerSA:
			return BypassCheckResult{ShouldBypass: true, Reason: "helm-controller (tdgMigration)"}
		case kustomizeControllerSA:
			return BypassCheckResult{ShouldBypass: true, Reason: "kustomize-controller (tdgMigration)"}
		case schiffTenantM2MSA:
			return BypassCheckResult{ShouldBypass: true, Reason: "schiff-tenant m2m-sa (tdgMigration)"}
		case schiffSystemM2MSA:
			return BypassCheckResult{ShouldBypass: true, Reason: "schiff-system m2m-sa (tdgMigration)"}
		case capiOperatorManagerSAConst:
			return BypassCheckResult{ShouldBypass: true, Reason: "capi-operator-manager (tdgMigration)"}
		case tridentOperatorSystemSA:
			if operation == admissionv1.Update && namespace == tridentSystemNamespace {
				return BypassCheckResult{ShouldBypass: true, Reason: "trident-operator for trident-system (tdgMigration)"}
			}
		}
	}

	return BypassCheckResult{ShouldBypass: false}
}

// MatchesSubjects checks if the user (via groups or service account) matches any of the subjects.
func MatchesSubjects(userGroups []string, saInfo ServiceAccountInfo, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		if subject.Kind == "Group" {
			for _, userGroup := range userGroups {
				if subject.Name == userGroup {
					return true
				}
			}
		} else if subject.Kind == "ServiceAccount" && saInfo.IsServiceAccount {
			if subject.Namespace == saInfo.Namespace && subject.Name == saInfo.Name {
				return true
			}
		}
	}
	return false
}

// IsRestrictedBindDefinition checks if a BindDefinition should be skipped based on its name.
func IsRestrictedBindDefinition(name string) bool {
	return strings.HasSuffix(name, "-namespaced-reader-restricted")
}

// GetSANamespaceTrackedLabels looks up the namespace where the ServiceAccount resides
// and returns the tracked ownership labels (owner, tenant, thirdparty) found on it.
// It validates that the label set is a valid ownership combination:
//   - The owner label must always be present.
//   - For tenant/thirdparty owners, the corresponding identifying label must also be present.
//
// Returns an empty map if the SA is not a ServiceAccount, the namespace has no tracked
// labels, or the label set is incomplete. Returns a non-nil error only for transient
// API failures (non-NotFound errors) so the caller can return admission.Errored.
func GetSANamespaceTrackedLabels(ctx context.Context, c client.Client, saInfo ServiceAccountInfo) (map[string]string, error) {
	if !saInfo.IsServiceAccount {
		return map[string]string{}, nil
	}

	saNamespace := &corev1.Namespace{}
	if err := c.Get(ctx, types.NamespacedName{Name: saInfo.Namespace}, saNamespace); err != nil {
		if apierrors.IsNotFound(err) {
			return map[string]string{}, nil
		}
		return map[string]string{}, fmt.Errorf("unable to get SA namespace %q: %w", saInfo.Namespace, err)
	}

	result := map[string]string{}
	for _, key := range trackedOwnershipKeys {
		if val, ok := saNamespace.Labels[key]; ok {
			result[key] = val
		}
	}

	// Require at minimum the owner label with a non-empty value.
	ownerVal, hasOwner := result[authzv1alpha1.LabelKeyOwner]
	if !hasOwner || ownerVal == "" {
		return map[string]string{}, nil
	}

	// Enforce a valid and non-ambiguous ownership combination:
	//   - owner=platform    => only owner; no tenant/thirdparty labels
	//   - owner=tenant      => owner + tenant; no thirdparty label
	//   - owner=thirdparty  => owner + thirdparty; no tenant label
	// Any other combination is treated as invalid and results in no tracked labels.
	switch ownerVal {
	case authzv1alpha1.OwnerPlatform:
		if _, ok := result[authzv1alpha1.LabelKeyTenant]; ok {
			return map[string]string{}, nil
		}
		if _, ok := result[authzv1alpha1.LabelKeyThirdParty]; ok {
			return map[string]string{}, nil
		}
	case authzv1alpha1.OwnerTenant:
		tenantVal, hasTenant := result[authzv1alpha1.LabelKeyTenant]
		if !hasTenant || tenantVal == "" {
			return map[string]string{}, nil
		}
		if _, ok := result[authzv1alpha1.LabelKeyThirdParty]; ok {
			return map[string]string{}, nil
		}
	case authzv1alpha1.OwnerThirdParty:
		tpVal, hasTP := result[authzv1alpha1.LabelKeyThirdParty]
		if !hasTP || tpVal == "" {
			return map[string]string{}, nil
		}
		if _, ok := result[authzv1alpha1.LabelKeyTenant]; ok {
			return map[string]string{}, nil
		}
	default:
		// Unknown owner values are not considered valid tracked ownership.
		return map[string]string{}, nil
	}

	return result, nil
}

// FindExtraTrackedKey returns the first tracked ownership label key that exists
// on targetLabels but is absent from inherited. Returns "" if no extra keys exist.
func FindExtraTrackedKey(targetLabels, inherited map[string]string) string {
	for _, key := range trackedOwnershipKeys {
		if _, onTarget := targetLabels[key]; onTarget {
			if _, onSA := inherited[key]; !onSA {
				return key
			}
		}
	}
	return ""
}

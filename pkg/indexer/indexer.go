/*
Copyright © 2026 Deutsche Telekom AG.
*/
package indexer

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/helpers"
)

const (
	// RoleDefinitionTargetNameField is the field index for RoleDefinition.Spec.TargetName.
	RoleDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// RoleDefinitionTargetRoleField is the field index for RoleDefinition.Spec.TargetRole.
	RoleDefinitionTargetRoleField = authorizationv1alpha1.TargetRoleField

	// RoleDefinitionTargetNamespaceField is the field index for RoleDefinition.Spec.TargetNamespace.
	RoleDefinitionTargetNamespaceField = authorizationv1alpha1.TargetNamespaceField

	// BindDefinitionTargetNameField is the field index for BindDefinition.Spec.TargetName.
	BindDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// WebhookAuthorizerHasNamespaceSelectorField indexes WebhookAuthorizer
	// resources by whether they define a non-empty namespace selector.
	// This allows the webhook handler to efficiently filter authorizers that
	// need namespace matching versus those that apply globally.
	WebhookAuthorizerHasNamespaceSelectorField = ".spec.hasNamespaceSelector"

	// BindDefinitionHasRoleBindingsField indexes only BindDefinitions that define
	// at least one RoleBinding (i.e. namespace-scoped bindings). Used by the
	// namespace validating webhook to skip cluster-only BindDefinitions and avoid
	// a full O(N) scan on every namespace admission call.
	BindDefinitionHasRoleBindingsField = ".spec.hasRoleBindings"

	// BindDefinitionHasRoleBindingsTrue is the index value for BindDefinitions
	// that have at least one RoleBinding entry.
	BindDefinitionHasRoleBindingsTrue = "true"

	// RestrictedBindDefinitionPolicyRefField indexes RestrictedBindDefinition
	// by the referenced RBACPolicy name for efficient reverse lookups.
	RestrictedBindDefinitionPolicyRefField = authorizationv1alpha1.PolicyRefField

	// RestrictedRoleDefinitionPolicyRefField indexes RestrictedRoleDefinition
	// by the referenced RBACPolicy name for efficient reverse lookups.
	RestrictedRoleDefinitionPolicyRefField = authorizationv1alpha1.PolicyRefField

	// RestrictedBindDefinitionTargetNameField indexes RestrictedBindDefinition
	// by TargetName for duplicate detection in webhook validation.
	RestrictedBindDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// RestrictedBindDefinitionRoleBindingNamespaceField indexes
	// RestrictedBindDefinition resources by explicit roleBinding namespace
	// values to reduce namespace fanout scans on namespace events.
	RestrictedBindDefinitionRoleBindingNamespaceField = ".spec.roleBindings.namespace"

	// RestrictedBindDefinitionHasNamespaceSelectorField indexes
	// RestrictedBindDefinition resources by whether any roleBinding includes a
	// namespaceSelector entry.
	RestrictedBindDefinitionHasNamespaceSelectorField = ".spec.hasNamespaceSelector"

	// RestrictedBindDefinitionOwnerRefField indexes RoleBinding,
	// ClusterRoleBinding, and ServiceAccount resources by RestrictedBindDefinition
	// owner name for efficient deprovision cleanup.
	RestrictedBindDefinitionOwnerRefField = ".metadata.ownerReferences.restrictedbinddefinition"

	// RestrictedRoleDefinitionTargetNameField indexes RestrictedRoleDefinition
	// by TargetName for duplicate detection in webhook validation.
	RestrictedRoleDefinitionTargetNameField = authorizationv1alpha1.TargetNameField

	// RestrictedRoleDefinitionTargetRoleField indexes RestrictedRoleDefinition
	// by TargetRole for duplicate detection in webhook validation.
	RestrictedRoleDefinitionTargetRoleField = authorizationv1alpha1.TargetRoleField

	// RestrictedRoleDefinitionTargetNamespaceField indexes RestrictedRoleDefinition
	// by TargetNamespace for duplicate detection in webhook validation.
	RestrictedRoleDefinitionTargetNamespaceField = authorizationv1alpha1.TargetNamespaceField

	// RBACPolicyHasDefaultAssignmentField indexes RBACPolicy resources by whether
	// defaultAssignment is configured.
	RBACPolicyHasDefaultAssignmentField = authorizationv1alpha1.HasDefaultAssignmentField
)

// SetupBaseIndexes registers field indexes for legacy controller/webhook types.
// This should be called before starting the manager.
func SetupBaseIndexes(ctx context.Context, mgr manager.Manager) error {
	// Index RoleDefinition by Spec.TargetName for duplicate detection in webhook validation
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RoleDefinition{},
		RoleDefinitionTargetNameField,
		RoleDefinitionTargetNameFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RoleDefinition.Spec.TargetName: %w", err)
	}

	// Index RoleDefinition by Spec.TargetRole for scoped duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RoleDefinition{},
		RoleDefinitionTargetRoleField,
		RoleDefinitionTargetRoleFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RoleDefinition.Spec.TargetRole: %w", err)
	}

	// Index RoleDefinition by Spec.TargetNamespace for scoped duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RoleDefinition{},
		RoleDefinitionTargetNamespaceField,
		RoleDefinitionTargetNamespaceFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RoleDefinition.Spec.TargetNamespace: %w", err)
	}

	// Index BindDefinition by Spec.TargetName for duplicate detection in webhook validation
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.BindDefinition{},
		BindDefinitionTargetNameField,
		func(obj client.Object) []string {
			bd, ok := obj.(*authorizationv1alpha1.BindDefinition)
			if !ok || bd.Spec.TargetName == "" {
				return nil
			}
			return []string{bd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for BindDefinition.Spec.TargetName: %w", err)
	}

	// Index WebhookAuthorizer by whether a namespace selector is set.
	// This enables the webhook handler to efficiently query only those
	// authorizers that require namespace matching, avoiding full scans
	// on every SubjectAccessReview evaluation.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.WebhookAuthorizer{},
		WebhookAuthorizerHasNamespaceSelectorField,
		WebhookAuthorizerHasNamespaceSelectorFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for WebhookAuthorizer.Spec.HasNamespaceSelector: %w", err)
	}

	// Index BindDefinitions that have at least one RoleBinding.
	// This allows the namespace validating webhook to skip cluster-only
	// BindDefinitions and limit the in-memory selector scan to candidates
	// that can actually produce namespace-scoped bindings.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.BindDefinition{},
		BindDefinitionHasRoleBindingsField,
		BindDefinitionHasRoleBindingsFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for BindDefinitions with RoleBindings: %w", err)
	}

	return nil
}

// SetupRestrictedIndexes registers field indexes for RBACPolicy and restricted CRDs.
// This should be called only when those CRDs are installed and used by the manager.
func SetupRestrictedIndexes(ctx context.Context, mgr manager.Manager) error {
	// Index RestrictedBindDefinition by PolicyRef.Name for reverse lookups from RBACPolicy.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionPolicyRefField,
		RestrictedBindDefinitionPolicyRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.PolicyRef.Name: %w", err)
	}

	// Index RestrictedBindDefinition by TargetName for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionTargetNameField,
		func(obj client.Object) []string {
			rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
			if !ok || rbd.Spec.TargetName == "" {
				return nil
			}
			return []string{rbd.Spec.TargetName}
		},
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.TargetName: %w", err)
	}

	// Index RestrictedBindDefinition by explicit RoleBinding namespace.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionRoleBindingNamespaceField,
		RestrictedBindDefinitionRoleBindingNamespaceFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.RoleBindings.Namespace: %w", err)
	}

	// Index RestrictedBindDefinition by whether namespace selectors are present.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedBindDefinition{},
		RestrictedBindDefinitionHasNamespaceSelectorField,
		RestrictedBindDefinitionHasNamespaceSelectorFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedBindDefinition.Spec.HasNamespaceSelector: %w", err)
	}

	// Index RestrictedRoleDefinition by PolicyRef.Name for reverse lookups from RBACPolicy.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionPolicyRefField,
		RestrictedRoleDefinitionPolicyRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.PolicyRef.Name: %w", err)
	}

	// Index RestrictedRoleDefinition by TargetName for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionTargetNameField,
		RestrictedRoleDefinitionTargetNameFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.TargetName: %w", err)
	}

	// Index RestrictedRoleDefinition by TargetRole for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionTargetRoleField,
		RestrictedRoleDefinitionTargetRoleFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.TargetRole: %w", err)
	}

	// Index RestrictedRoleDefinition by TargetNamespace for duplicate detection.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RestrictedRoleDefinition{},
		RestrictedRoleDefinitionTargetNamespaceField,
		RestrictedRoleDefinitionTargetNamespaceFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RestrictedRoleDefinition.Spec.TargetNamespace: %w", err)
	}

	// Index RBACPolicy by whether defaultAssignment is set.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&authorizationv1alpha1.RBACPolicy{},
		RBACPolicyHasDefaultAssignmentField,
		RBACPolicyHasDefaultAssignmentFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RBACPolicy.Spec.DefaultAssignment presence: %w", err)
	}

	return nil
}

// SetupIndexes registers all field indexes shared by controllers and webhooks.
// This should be called before starting the manager.
func SetupIndexes(ctx context.Context, mgr manager.Manager) error {
	if err := SetupBaseIndexes(ctx, mgr); err != nil {
		return err
	}
	return SetupRestrictedIndexes(ctx, mgr)
}

// SetupControllerIndexes registers controller-only field indexes on the
// manager's cache for efficient reconciliation lookups.
//
// These indexes intentionally exclude webhook managers because they would start
// additional informers for RBAC binding types, requiring broader permissions
// than admission webhooks otherwise need.
func SetupControllerIndexes(ctx context.Context, mgr manager.Manager, includeRestricted bool) error {
	if err := SetupBaseIndexes(ctx, mgr); err != nil {
		return err
	}
	if !includeRestricted {
		return nil
	}
	if err := SetupRestrictedIndexes(ctx, mgr); err != nil {
		return err
	}

	// Index ClusterRoleBinding by RestrictedBindDefinition owner name.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&rbacv1.ClusterRoleBinding{},
		RestrictedBindDefinitionOwnerRefField,
		RestrictedBindDefinitionOwnerRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for ClusterRoleBinding RestrictedBindDefinition owner references: %w", err)
	}

	// Index RoleBinding by RestrictedBindDefinition owner name.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&rbacv1.RoleBinding{},
		RestrictedBindDefinitionOwnerRefField,
		RestrictedBindDefinitionOwnerRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for RoleBinding RestrictedBindDefinition owner references: %w", err)
	}

	// Index ServiceAccount by RestrictedBindDefinition owner name.
	if err := mgr.GetFieldIndexer().IndexField(
		ctx,
		&corev1.ServiceAccount{},
		RestrictedBindDefinitionOwnerRefField,
		RestrictedBindDefinitionOwnerRefFunc,
	); err != nil {
		return fmt.Errorf("failed to create index for ServiceAccount RestrictedBindDefinition owner references: %w", err)
	}

	return nil
}

// WebhookAuthorizerHasNamespaceSelectorFunc extracts the index value for
// the hasNamespaceSelector field. Exported for testing and fake client setup.
func WebhookAuthorizerHasNamespaceSelectorFunc(obj client.Object) []string {
	wa, ok := obj.(*authorizationv1alpha1.WebhookAuthorizer)
	if !ok {
		return nil
	}
	if helpers.IsLabelSelectorEmpty(&wa.Spec.NamespaceSelector) {
		return []string{"false"}
	}
	return []string{"true"}
}

// BindDefinitionHasRoleBindingsFunc emits the true index value for
// BindDefinitions that have RoleBindings. BindDefinitions without RoleBindings
// are intentionally absent from the index.
func BindDefinitionHasRoleBindingsFunc(obj client.Object) []string {
	bd, ok := obj.(*authorizationv1alpha1.BindDefinition)
	if !ok {
		return nil
	}
	if len(bd.Spec.RoleBindings) > 0 {
		return []string{BindDefinitionHasRoleBindingsTrue}
	}
	return nil
}

// RoleDefinitionTargetNameFunc extracts the RoleDefinition target name.
func RoleDefinitionTargetNameFunc(obj client.Object) []string {
	rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
	if !ok || rd.Spec.TargetName == "" {
		return nil
	}
	return []string{rd.Spec.TargetName}
}

// RoleDefinitionTargetRoleFunc extracts the RoleDefinition target role kind.
func RoleDefinitionTargetRoleFunc(obj client.Object) []string {
	rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
	if !ok || rd.Spec.TargetRole == "" {
		return nil
	}
	return []string{rd.Spec.TargetRole}
}

// RoleDefinitionTargetNamespaceFunc extracts the RoleDefinition target namespace.
func RoleDefinitionTargetNamespaceFunc(obj client.Object) []string {
	rd, ok := obj.(*authorizationv1alpha1.RoleDefinition)
	if !ok || rd.Spec.TargetNamespace == "" {
		return nil
	}
	return []string{rd.Spec.TargetNamespace}
}

// RestrictedBindDefinitionPolicyRefFunc extracts the RBACPolicy name from a
// RestrictedBindDefinition for field indexing. Exported for testing and fake client setup.
func RestrictedBindDefinitionPolicyRefFunc(obj client.Object) []string {
	rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
	if !ok || rbd.Spec.PolicyRef.Name == "" {
		return nil
	}
	return []string{rbd.Spec.PolicyRef.Name}
}

// RestrictedBindDefinitionRoleBindingNamespaceFunc extracts explicit
// roleBinding namespace values from RestrictedBindDefinition for field indexing.
func RestrictedBindDefinitionRoleBindingNamespaceFunc(obj client.Object) []string {
	rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
	if !ok {
		return nil
	}

	namespaceSet := make(map[string]struct{})
	for _, rb := range rbd.Spec.RoleBindings {
		if rb.Namespace == "" {
			continue
		}
		namespaceSet[rb.Namespace] = struct{}{}
	}

	namespaces := make([]string, 0, len(namespaceSet))
	for ns := range namespaceSet {
		namespaces = append(namespaces, ns)
	}
	return namespaces
}

// RestrictedBindDefinitionHasNamespaceSelectorFunc extracts whether a
// RestrictedBindDefinition has any namespace selectors in role bindings.
func RestrictedBindDefinitionHasNamespaceSelectorFunc(obj client.Object) []string {
	rbd, ok := obj.(*authorizationv1alpha1.RestrictedBindDefinition)
	if !ok {
		return nil
	}

	for _, rb := range rbd.Spec.RoleBindings {
		if len(rb.NamespaceSelector) > 0 {
			return []string{"true"}
		}
	}

	return []string{"false"}
}

// RestrictedBindDefinitionOwnerRefFunc extracts RestrictedBindDefinition owner
// reference names from generated child objects.
func RestrictedBindDefinitionOwnerRefFunc(obj client.Object) []string {
	switch typed := obj.(type) {
	case *rbacv1.ClusterRoleBinding:
		return restrictedBindDefinitionOwnerNames(typed.OwnerReferences)
	case *rbacv1.RoleBinding:
		return restrictedBindDefinitionOwnerNames(typed.OwnerReferences)
	case *corev1.ServiceAccount:
		return restrictedBindDefinitionOwnerNames(typed.OwnerReferences)
	default:
		return nil
	}
}

func restrictedBindDefinitionOwnerNames(ownerRefs []metav1.OwnerReference) []string {
	names := make([]string, 0, len(ownerRefs))
	for _, ownerRef := range ownerRefs {
		if ownerRef.Kind != "RestrictedBindDefinition" {
			continue
		}
		if ownerRef.APIVersion != authorizationv1alpha1.GroupVersion.String() {
			continue
		}
		names = append(names, ownerRef.Name)
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// RestrictedRoleDefinitionPolicyRefFunc extracts the RBACPolicy name from a
// RestrictedRoleDefinition for field indexing. Exported for testing and fake client setup.
func RestrictedRoleDefinitionPolicyRefFunc(obj client.Object) []string {
	rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
	if !ok || rrd.Spec.PolicyRef.Name == "" {
		return nil
	}
	return []string{rrd.Spec.PolicyRef.Name}
}

// RestrictedRoleDefinitionTargetNameFunc extracts the RestrictedRoleDefinition target name.
func RestrictedRoleDefinitionTargetNameFunc(obj client.Object) []string {
	rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
	if !ok || rrd.Spec.TargetName == "" {
		return nil
	}
	return []string{rrd.Spec.TargetName}
}

// RestrictedRoleDefinitionTargetRoleFunc extracts the RestrictedRoleDefinition target role kind.
func RestrictedRoleDefinitionTargetRoleFunc(obj client.Object) []string {
	rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
	if !ok || rrd.Spec.TargetRole == "" {
		return nil
	}
	return []string{rrd.Spec.TargetRole}
}

// RestrictedRoleDefinitionTargetNamespaceFunc extracts the RestrictedRoleDefinition target namespace.
func RestrictedRoleDefinitionTargetNamespaceFunc(obj client.Object) []string {
	rrd, ok := obj.(*authorizationv1alpha1.RestrictedRoleDefinition)
	if !ok || rrd.Spec.TargetNamespace == "" {
		return nil
	}
	return []string{rrd.Spec.TargetNamespace}
}

// RBACPolicyHasDefaultAssignmentFunc extracts whether an RBACPolicy has
// defaultAssignment configured for field indexing.
func RBACPolicyHasDefaultAssignmentFunc(obj client.Object) []string {
	policy, ok := obj.(*authorizationv1alpha1.RBACPolicy)
	if !ok {
		return nil
	}
	if policy.Spec.DefaultAssignment == nil {
		return []string{"false"}
	}
	return []string{"true"}
}

package webhooks

import (
	"context"
	"fmt"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	"github.com/telekom/auth-operator/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// hardProtectedNamespaces are Kubernetes system namespaces that are never
// deletable while deletion protection is enabled. The AnnotationKeyAllowDeletion
// escape hatch does NOT apply to them; the only way to delete one is to disable
// the feature entirely (--namespace-deletion-protection=false).
//
// Kept in sync with the ValidatingAdmissionPolicy in
// chart/auth-operator/templates/namespace-deletion-protection-vap.yaml.
var hardProtectedNamespaces = map[string]struct{}{
	"kube-system":     {},
	"kube-public":     {},
	"kube-node-lease": {},
	"default":         {},
}

// isHardProtectedNamespace reports whether the namespace name is in the
// built-in hard-protection set or the operator-configured extra list.
func isHardProtectedNamespace(name string, extra []string) bool {
	if _, ok := hardProtectedNamespaces[name]; ok {
		return true
	}
	for _, n := range extra {
		if n == name {
			return true
		}
	}
	return false
}

// isDeletionProtected reports whether the namespace is deletion-protected by
// its labels: platform-owned namespaces are protected implicitly, legacy
// platform namespaces are protected while TDG migration is active, and any
// other namespace can opt in via the deletion-protection label.
func isDeletionProtected(ns *corev1.Namespace, tdgMigration bool) bool {
	if ns.Labels[authorizationv1alpha1.LabelKeyOwner] == authorizationv1alpha1.OwnerPlatform {
		return true
	}
	if tdgMigration {
		if legacy := ns.Labels[legacyOwnerLabel]; legacy == authorizationv1alpha1.OwnerPlatform || legacy == "schiff" {
			return true
		}
	}
	return ns.Labels[authorizationv1alpha1.LabelKeyDeletionProtection] == authorizationv1alpha1.DeletionProtectionEnabled
}

// allowsDeletion reports whether the namespace carries the allow-deletion
// escape-hatch annotation.
func allowsDeletion(ns *corev1.Namespace) bool {
	return ns.Annotations[authorizationv1alpha1.AnnotationKeyAllowDeletion] == authorizationv1alpha1.AllowDeletionTrue
}

// checkDeletionProtection enforces namespace deletion protection for DELETE
// requests. It returns a non-nil response when the request must be denied (or
// errored); nil means the namespace is not protected or has been explicitly
// unlocked, and normal admission flow (bypass, BindDefinition authorization)
// continues.
//
// It MUST run before CheckBypass: deletion protection intentionally has no
// admin or automation bypass, so even kubernetes-admin/system:masters must set
// the allow-deletion annotation first.
func (v *NamespaceValidator) checkDeletionProtection(ctx context.Context, req admission.Request) *admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-validator")

	if isHardProtectedNamespace(req.Name, v.ExtraProtectedNamespaces) {
		logger.Info("AUDIT: deletion of protected system namespace denied",
			"namespace", req.Name, "username", req.UserInfo.Username)
		metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
		resp := admission.Denied(fmt.Sprintf(DenialSystemNamespaceDeletionFmt, req.Name))
		return &resp
	}

	ns, _, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		return errResp
	}

	if !isDeletionProtected(&ns, v.TDGMigration) {
		return nil
	}

	if allowsDeletion(&ns) {
		logger.Info("AUDIT: deletion protection lifted via allow-deletion annotation",
			"namespace", req.Name, "username", req.UserInfo.Username)
		return nil
	}

	logger.Info("AUDIT: deletion of protected namespace denied",
		"namespace", req.Name, "username", req.UserInfo.Username)
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
	resp := admission.Denied(fmt.Sprintf(DenialProtectedNamespaceDeletionFmt, req.Name, authorizationv1alpha1.AnnotationKeyAllowDeletion))
	return &resp
}

// checkProtectionDowngrade enforces deletion protection for UPDATE requests:
// stripping the protection labels from a protected namespace requires the same
// allow-deletion annotation as deleting it, so protection cannot be sidestepped
// by removing the label first and deleting afterwards.
//
// Like checkDeletionProtection, it MUST run before CheckBypass.
func (v *NamespaceValidator) checkProtectionDowngrade(ctx context.Context, req admission.Request) *admission.Response {
	logger := logf.FromContext(ctx).WithName("namespace-validator")

	ns, oldNs, errResp := v.decodeNamespaces(logger, req)
	if errResp != nil {
		return errResp
	}

	if !isDeletionProtected(&oldNs, v.TDGMigration) || isDeletionProtected(&ns, v.TDGMigration) {
		return nil
	}

	if allowsDeletion(&ns) {
		logger.Info("AUDIT: protection label removal permitted via allow-deletion annotation",
			"namespace", req.Name, "username", req.UserInfo.Username)
		return nil
	}

	logger.Info("AUDIT: removal of deletion-protection labels denied",
		"namespace", req.Name, "username", req.UserInfo.Username)
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookNamespaceValidator, string(req.Operation), metrics.WebhookResultDenied).Inc()
	resp := admission.Denied(fmt.Sprintf(DenialProtectionRemovalFmt, req.Name, authorizationv1alpha1.AnnotationKeyAllowDeletion))
	return &resp
}

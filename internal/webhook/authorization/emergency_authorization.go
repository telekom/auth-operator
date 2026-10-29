// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package webhooks

import (
	"context"

	authorizationv1alpha1 "github.com/telekom/auth-operator/api/authorization/v1alpha1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// emergencyTenantAuthorization checks a dedicated permission with the original
// request identity. A live authorization webhook can supply that permission for
// an approved emergency session without changing admission's user information.
// It is not a deletion-protection bypass and cannot transfer namespace ownership.
func emergencyTenantAuthorization(ctx context.Context, c client.Client, req admission.Request, ns *corev1.Namespace) bool {
	if c == nil || req.UserInfo.Username == "" || !ValidTrackedOwnershipLabels(ns.Labels) ||
		ns.Labels[authorizationv1alpha1.LabelKeyOwner] != authorizationv1alpha1.OwnerTenant {
		return false
	}
	switch ns.Name {
	case "default", "kube-system", "kube-public", "kube-node-lease":
		return false
	}
	if protected, exists := ns.Labels[authorizationv1alpha1.LabelKeyProtected]; exists && protected != ns.Labels[authorizationv1alpha1.LabelKeyTenant] {
		return false
	}
	review := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: req.UserInfo.Username, UID: req.UserInfo.UID, Groups: req.UserInfo.Groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Group: "breakglass.t-caas.telekom.com", Resource: "escalationguards", Name: "platform-emergency", Verb: "use",
		},
	}}
	if req.UserInfo.Extra != nil {
		review.Spec.Extra = make(map[string]authorizationv1.ExtraValue, len(req.UserInfo.Extra))
		for key, values := range req.UserInfo.Extra {
			review.Spec.Extra[key] = authorizationv1.ExtraValue(values)
		}
	}
	reviewCtx, cancel := context.WithTimeout(ctx, authorizationv1alpha1.WebhookCacheTimeout)
	defer cancel()
	if err := c.Create(reviewCtx, review); err != nil {
		log.FromContext(ctx).Error(err, "emergency namespace authorization failed", "namespace", ns.Name)
		return false
	}
	return review.Status.Allowed && !review.Status.Denied && review.Status.EvaluationError == ""
}

package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	authzv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	authzv1alpha1 "gitlab.devops.telekom.de/cit/t-caas/operators/authn-authz-operator/api/authorization/v1alpha1"
)

type Authorizer struct {
	Client client.Client
	Log    logr.Logger
}

func (wa *Authorizer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	var sar authzv1.SubjectAccessReview

	if err := json.NewDecoder(r.Body).Decode(&sar); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	wa.Log.Info("Received SubjectAccessReview", "Namespace", sar.Spec.ResourceAttributes.Namespace, "User", sar.Spec.User, "Groups", sar.Spec.Groups, "Verb", sar.Spec.ResourceAttributes.Verb, "API", sar.Spec.ResourceAttributes.Group, "Resource", sar.Spec.ResourceAttributes.Resource)

	var webhookAuthorizers authzv1alpha1.WebhookAuthorizerList
	if err := wa.Client.List(ctx, &webhookAuthorizers); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	verdict, reason := wa.evaluateSAR(ctx, &sar, &webhookAuthorizers)

	response := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1beta1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: verdict,
			Reason:  reason,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (wa *Authorizer) evaluateSAR(ctx context.Context, sar *authzv1.SubjectAccessReview, waList *authzv1alpha1.WebhookAuthorizerList) (bool, string) {
	for _, webhookAuthorizer := range waList.Items {
		if !isLabelSelectorEmpty(&webhookAuthorizer.Spec.NamespaceSelector) && sar.Spec.ResourceAttributes.Namespace != "" {
			if !wa.namespaceMatches(ctx, sar.Spec.ResourceAttributes.Namespace, &webhookAuthorizer.Spec.NamespaceSelector) {
				continue
			}
		}

		// Check DeniedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.DeniedPrincipals) {
			return false, fmt.Sprintf("Access denied by WebhookAuthorizer %s", webhookAuthorizer.Name)
		}

		// Check AllowedPrincipals.
		if wa.principalMatches(sar.Spec.User, sar.Spec.Groups, webhookAuthorizer.Spec.AllowedPrincipals) {
			// Check ResourceRules.
			if sar.Spec.ResourceAttributes != nil && wa.resourceRulesMatch(webhookAuthorizer.Spec.ResourceRules, sar.Spec.ResourceAttributes) {
				return true, fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name)
			}
			// Check NonResourceRules.
			if sar.Spec.NonResourceAttributes != nil && wa.nonResourceRulesMatch(webhookAuthorizer.Spec.NonResourceRules, sar.Spec.NonResourceAttributes) {
				return true, fmt.Sprintf("Access granted by WebhookAuthorizer %s", webhookAuthorizer.Name)
			}
		}
	}
	return false, "Access denied: no matching rules"
}

func isLabelSelectorEmpty(selector *metav1.LabelSelector) bool {
	return selector == nil || (len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0)
}

// namespaceMatches checks if the namespace matches the selector.
func (wa *Authorizer) namespaceMatches(ctx context.Context, namespace string, selector *metav1.LabelSelector) bool {
	if namespace == "" {
		return false
	}
	var ns corev1.Namespace
	err := wa.Client.Get(ctx, types.NamespacedName{Name: namespace}, &ns)
	if err != nil {
		wa.Log.Error(err, "Failed to get namespace", "namespace", namespace)
		return false
	}
	labelSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		wa.Log.Error(err, "Invalid label selector")
		return false
	}
	return labelSelector.Matches(labels.Set(ns.Labels))
}

// principalMatches checks if the user or groups match the principals.
func (wa *Authorizer) principalMatches(user string, groups []string, principals []authzv1alpha1.Principal) bool {
	for _, principal := range principals {
		if principal.User != "" && principal.User == user {
			return true
		}
		if len(principal.Groups) > 0 && intersects(groups, principal.Groups) {
			return true
		}
		if principal.Namespace != "" && isServiceAccountInNamespace(user, principal.User, principal.Namespace) {
			return true
		}
	}
	return false
}

// intersects checks if two slices have any common elements.
func intersects(slice1, slice2 []string) bool {
	for _, s1 := range slice1 {
		for _, s2 := range slice2 {
			if s1 == s2 {
				return true
			}
		}
	}
	return false
}

// resourceRulesMatch checks if the resource attributes match any of the resource rules.
func (wa *Authorizer) resourceRulesMatch(rules []authzv1.ResourceRule, attr *authzv1.ResourceAttributes) bool {
	for _, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.APIGroups, attr.Group) &&
			matchesRule(rule.Resources, attr.Resource) {
			return true
		}
	}
	return false
}

// nonResourceRulesMatch checks if the non-resource attributes match any of the non-resource rules.
func (wa *Authorizer) nonResourceRulesMatch(rules []authzv1.NonResourceRule, attr *authzv1.NonResourceAttributes) bool {
	for _, rule := range rules {
		if matchesRule(rule.Verbs, attr.Verb) &&
			matchesRule(rule.NonResourceURLs, attr.Path) {
			return true
		}
	}
	return false
}

// matchesRule checks if a value matches any pattern in the list.
func matchesRule(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == value {
			return true
		}
	}
	return false
}

// isServiceAccountInNamespace checks if the user is a service account in the specified namespace.
func isServiceAccountInNamespace(user, saUser, namespace string) bool {
	// Format: system:serviceaccount:<namespace>:<serviceaccount>
	parts := strings.Split(user, ":")
	return len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" && parts[2] == namespace && parts[3] == saUser
}

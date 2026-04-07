// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/telekom/auth-operator/pkg/policy"
)

// clientLabelGetter implements policy.LabelGetter using a controller-runtime client.
type clientLabelGetter struct {
	reader client.Reader
}

// newLabelGetter creates a LabelGetter backed by the given client.
func newLabelGetter(reader client.Reader) policy.LabelGetter {
	return &clientLabelGetter{reader: reader}
}

// GetNamespaceLabels returns the labels for the given namespace.
func (g *clientLabelGetter) GetNamespaceLabels(ctx context.Context, name string) (map[string]string, bool) {
	ns := &corev1.Namespace{}
	if err := g.reader.Get(ctx, types.NamespacedName{Name: name}, ns); err != nil {
		if !apierrors.IsNotFound(err) {
			log.FromContext(ctx).V(2).Info("failed to get namespace labels", "namespace", name, "error", err)
		}
		return nil, false
	}
	return ns.Labels, true
}

// GetClusterRoleLabels returns the labels for the given ClusterRole.
func (g *clientLabelGetter) GetClusterRoleLabels(ctx context.Context, name string) (map[string]string, bool) {
	cr := &rbacv1.ClusterRole{}
	if err := g.reader.Get(ctx, types.NamespacedName{Name: name}, cr); err != nil {
		if !apierrors.IsNotFound(err) {
			log.FromContext(ctx).V(2).Info("failed to get clusterrole labels", "clusterRole", name, "error", err)
		}
		return nil, false
	}
	return cr.Labels, true
}

// GetRoleLabels returns the labels for the given Role in the specified namespace.
func (g *clientLabelGetter) GetRoleLabels(ctx context.Context, namespace, name string) (map[string]string, bool) {
	role := &rbacv1.Role{}
	if err := g.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, role); err != nil {
		if !apierrors.IsNotFound(err) {
			log.FromContext(ctx).V(2).Info("failed to get role labels", "namespace", namespace, "role", name, "error", err)
		}
		return nil, false
	}
	return role.Labels, true
}

// ListNamespacesBySelector returns the names of all namespaces matching the given label selector.
func (g *clientLabelGetter) ListNamespacesBySelector(ctx context.Context, selector *metav1.LabelSelector) ([]string, error) {
	sel, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return nil, fmt.Errorf("parse namespace selector: %w", err)
	}
	nsList := &corev1.NamespaceList{}
	if err := g.reader.List(ctx, nsList, client.MatchingLabelsSelector{Selector: sel}); err != nil {
		return nil, fmt.Errorf("list namespaces by selector: %w", err)
	}
	names := make([]string, 0, len(nsList.Items))
	for i := range nsList.Items {
		names = append(names, nsList.Items[i].Name)
	}
	return names, nil
}

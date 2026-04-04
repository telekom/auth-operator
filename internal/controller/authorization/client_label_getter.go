// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

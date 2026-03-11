// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/auth-operator/pkg/policy"
)

// clientLabelGetter implements policy.LabelGetter using a controller-runtime client.
type clientLabelGetter struct {
	ctx    context.Context
	reader client.Reader
}

// newLabelGetter creates a LabelGetter backed by the given client.
func newLabelGetter(ctx context.Context, reader client.Reader) policy.LabelGetter {
	return &clientLabelGetter{ctx: ctx, reader: reader}
}

// GetNamespaceLabels returns the labels for the given namespace.
func (g *clientLabelGetter) GetNamespaceLabels(name string) (map[string]string, bool) {
	ns := &corev1.Namespace{}
	if err := g.reader.Get(g.ctx, types.NamespacedName{Name: name}, ns); err != nil {
		return nil, false
	}
	return ns.Labels, true
}

// GetClusterRoleLabels returns the labels for the given ClusterRole.
func (g *clientLabelGetter) GetClusterRoleLabels(name string) (map[string]string, bool) {
	cr := &rbacv1.ClusterRole{}
	if err := g.reader.Get(g.ctx, types.NamespacedName{Name: name}, cr); err != nil {
		return nil, false
	}
	return cr.Labels, true
}

// GetRoleLabels returns the labels for the given Role in the specified namespace.
func (g *clientLabelGetter) GetRoleLabels(namespace, name string) (map[string]string, bool) {
	role := &rbacv1.Role{}
	if err := g.reader.Get(g.ctx, types.NamespacedName{Namespace: namespace, Name: name}, role); err != nil {
		return nil, false
	}
	return role.Labels, true
}

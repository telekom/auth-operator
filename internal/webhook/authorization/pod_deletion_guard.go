package webhooks

import (
	"context"
	"fmt"
	"time"

	"github.com/telekom/auth-operator/pkg/metrics"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// PodDeletionGuard is the optional node-scoped pod deletion guard for
// delegated identities. Every Pod DELETE that reaches it is allowed only when
// the target ConfigMap names the Pod's node and the requesting user; anything
// else, including a missing or unreadable ConfigMap, is denied (fail closed).
//
// The handler does not decide who is guarded: the ValidatingWebhookConfiguration
// scopes it with matchConditions, which the API server evaluates before calling
// the webhook. Requests of other identities never reach it, so a missing
// ConfigMap or an unavailable webhook cannot block controllers, the kubelet or
// the garbage collector.
type PodDeletionGuard struct {
	// Reader reads the target ConfigMap. Use a live (uncached) reader so that
	// revocations apply immediately and an unreadable target denies.
	Reader client.Reader
	// Decoder decodes the Pod in the request's oldObject.
	Decoder admission.Decoder
	// ConfigMap is the target ConfigMap.
	ConfigMap types.NamespacedName
	// NodeKey is the data key holding the node name.
	NodeKey string
	// UserKey is the data key holding the username allowed to delete on that node.
	UserKey string
}

// Handle implements admission.Handler.
func (g *PodDeletionGuard) Handle(ctx context.Context, req admission.Request) admission.Response {
	start := time.Now()
	allowed, reason, podNode, targetNode := g.decide(ctx, req)
	result := metrics.WebhookResultDenied
	if allowed {
		result = metrics.WebhookResultAllowed
	}
	metrics.WebhookRequestsTotal.WithLabelValues(metrics.WebhookPodDeletionGuard, string(req.Operation), result).Inc()

	// Same fields as the authorization decision log, plus the node scope.
	logf.FromContext(ctx).WithName("pod-deletion-guard").Info("pod deletion guard decision",
		"decision", result,
		"allowed", allowed,
		"reason", reason,
		"user", req.UserInfo.Username,
		"groups", cappedGroups(req.UserInfo.Groups),
		"verb", "delete",
		"apiGroup", req.Resource.Group,
		"resource", req.Resource.Resource,
		"namespace", req.Namespace,
		"name", req.Name,
		"node", podNode,
		"targetNode", targetNode,
		"targetConfigMap", g.ConfigMap.String(),
		"latency", time.Since(start).String(),
	)
	if allowed {
		return admission.Allowed(reason)
	}
	return admission.Denied(reason)
}

// decide returns the decision, its reason, the Pod's node and the target node.
func (g *PodDeletionGuard) decide(ctx context.Context, req admission.Request) (allowed bool, reason, podNode, targetNode string) {
	if req.Operation != admissionv1.Delete || req.Resource.Group != "" || req.Resource.Resource != "pods" || req.SubResource != "" {
		return false, fmt.Sprintf("pod deletion guard only handles pod DELETE, got %s %s/%s", req.Operation, req.Resource.Resource, req.SubResource), "", ""
	}
	pod := &corev1.Pod{}
	if err := g.Decoder.DecodeRaw(req.OldObject, pod); err != nil {
		return false, fmt.Sprintf("pod deletion guard: cannot decode the pod: %v", err), "", ""
	}
	podNode = pod.Spec.NodeName

	cm := &corev1.ConfigMap{}
	if err := g.Reader.Get(ctx, g.ConfigMap, cm); err != nil {
		if apierrors.IsNotFound(err) {
			return false, fmt.Sprintf("pod deletion guard: target ConfigMap %s not found; denied (fail closed)", g.ConfigMap), podNode, ""
		}
		return false, fmt.Sprintf("pod deletion guard: cannot read target ConfigMap %s; denied (fail closed): %v", g.ConfigMap, err), podNode, ""
	}
	targetNode = cm.Data[g.NodeKey]
	targetUser := cm.Data[g.UserKey]
	switch {
	case targetNode == "":
		return false, fmt.Sprintf("pod deletion guard: no target node set in ConfigMap %s data.%s", g.ConfigMap, g.NodeKey), podNode, targetNode
	case targetUser != req.UserInfo.Username:
		return false, fmt.Sprintf("pod deletion guard: the target in ConfigMap %s belongs to another user (data.%s); set your own target", g.ConfigMap, g.UserKey), podNode, targetNode
	case podNode != targetNode:
		return false, fmt.Sprintf("pod deletion guard: pod %s/%s is on node %q, not on the target node %q", req.Namespace, req.Name, podNode, targetNode), podNode, targetNode
	}
	return true, fmt.Sprintf("pod is on the target node %q of %s", targetNode, req.UserInfo.Username), podNode, targetNode
}

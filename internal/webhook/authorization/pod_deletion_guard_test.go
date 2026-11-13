package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var guardTarget = types.NamespacedName{Namespace: "kube-system", Name: "pod-guard-target"}

func guardConfigMap(data map[string]string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: guardTarget.Namespace, Name: guardTarget.Name},
		Data:       data,
	}
}

func guardPodDelete(t *testing.T, user, node string) admission.Request {
	t.Helper()
	raw, err := json.Marshal(&corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web-0"},
		Spec:       corev1.PodSpec{NodeName: node},
	})
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Operation: admissionv1.Delete,
		Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
		Namespace: "app",
		Name:      "web-0",
		UserInfo:  authenticationv1.UserInfo{Username: user, Groups: []string{"delegated"}},
		OldObject: runtime.RawExtension{Raw: raw},
	}}
}

func newGuard(reader client.Reader) *PodDeletionGuard {
	return &PodDeletionGuard{
		Reader:    reader,
		Decoder:   admission.NewDecoder(clientgoscheme.Scheme),
		ConfigMap: guardTarget,
		NodeKey:   "node",
		UserKey:   "user",
	}
}

func TestPodDeletionGuard(t *testing.T) {
	target := guardConfigMap(map[string]string{"node": "node-a", "user": "alice"})
	tests := []struct {
		name        string
		objects     []client.Object
		getErr      error
		req         func(*testing.T) admission.Request
		wantAllowed bool
		wantReason  string
	}{
		{name: "allows the target user on the target node", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "node-a") }, wantAllowed: true},
		{name: "denies a pod on another node", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "node-b") }, wantReason: `not on the target node "node-a"`},
		{name: "denies an unscheduled pod", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "") }, wantReason: "not on the target node"},
		{name: "denies another user", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "bob", "node-a") }, wantReason: "belongs to another user"},
		{name: "denies when no target node is set", objects: []client.Object{guardConfigMap(map[string]string{"user": "alice"})},
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "") }, wantReason: "no target node set"},
		{name: "denies when the ConfigMap is missing",
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "node-a") }, wantReason: "not found; denied (fail closed)"},
		{name: "denies when the ConfigMap is unreadable", objects: []client.Object{target}, getErr: errors.New("Get \"https://10.0.0.1/api/v1\": forbidden: system:serviceaccount:x:y"),
			req: func(t *testing.T) admission.Request { t.Helper(); return guardPodDelete(t, "alice", "node-a") }, wantReason: "cannot read target ConfigMap"},
		{name: "denies an undecodable pod", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request {
				t.Helper()
				r := guardPodDelete(t, "alice", "node-a")
				r.OldObject.Raw = []byte("{")
				return r
			}, wantReason: "cannot decode the pod"},
		{name: "denies other operations", objects: []client.Object{target},
			req: func(t *testing.T) admission.Request {
				t.Helper()
				r := guardPodDelete(t, "alice", "node-a")
				r.Operation = admissionv1.Create
				r.SubResource = "eviction"
				return r
			}, wantReason: "only handles pod DELETE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithObjects(tt.objects...)
			if tt.getErr != nil {
				builder = builder.WithInterceptorFuncs(interceptor.Funcs{
					Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
						return tt.getErr
					},
				})
			}
			resp := newGuard(builder.Build()).Handle(context.Background(), tt.req(t))
			if resp.Allowed != tt.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (%s)", resp.Allowed, tt.wantAllowed, resp.Result.Message)
			}
			if !tt.wantAllowed && !strings.Contains(resp.Result.Message, tt.wantReason) {
				t.Fatalf("message %q does not contain %q", resp.Result.Message, tt.wantReason)
			}
			if tt.getErr != nil && strings.Contains(resp.Result.Message, tt.getErr.Error()) {
				t.Fatalf("message %q leaks the read error", resp.Result.Message)
			}
		})
	}
}

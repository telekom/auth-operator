// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
)

// Preserve main's trailing-edge CRD refresh regressions through the library adapter.
func TestResourceTrackerCollectsAfterThrottledCRDStatusEvents(t *testing.T) {
	for _, mode := range []string{"burst", "closed", "error", "overlapping"} {
		t.Run(mode, func(t *testing.T) {
			testCRDStatusRefresh(t, mode)
		})
	}
}

func testCRDStatusRefresh(t *testing.T, mode string) {
	t.Helper()
	server := newDiscoveryTestServer(t)
	defer server.Close()
	events := make(chan watch.Event, 2)
	sent := make(chan struct{}, 2)
	ready := make(chan struct{})
	var blockCollection atomic.Bool
	collectionRead := make(chan struct{})
	releaseCollection := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCollection) }) }
	watchServer := newCRDWatchTestServer(server, events, sent,
		interceptCRDDiscovery(server, ready, &blockCollection, collectionRead, releaseCollection))
	defer watchServer.Close()
	defer release()

	config := server.Config()
	config.Host = watchServer.URL
	testScheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	tracker := NewResourceTracker(testScheme, config)
	signal := make(chan struct{}, 1)
	tracker.AddSignalFunc(finalCRDDiscoverySignal(tracker, signal))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- tracker.Start(ctx) }()
	defer stopCRDTestTracker(t, cancel, release, done)
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("CRD watch never became ready")
	}
	waitForCRDWatchStartup(ctx, t, tracker, server)
	activeCollection := make(chan error, 1)
	if mode == "overlapping" {
		blockCollection.Store(true)
		go func() {
			_, err := tracker.collectAPIResources(ctx)
			activeCollection <- err
		}()
		select {
		case <-collectionRead:
		case <-time.After(3 * time.Second):
			t.Fatal("overlapping collection did not read the old discovery snapshot")
		}
	}
	crd := &apiextensionsv1.CustomResourceDefinition{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{Name: "widgets.example.com"},
	}
	events <- watch.Event{Type: watch.Modified, Object: crd}
	<-sent
	server.coreWatch.Store(true)
	establishedCRD := crd.DeepCopy()
	establishedCRD.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{
		{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue},
	}
	events <- watch.Event{Type: watch.Modified, Object: establishedCRD}
	<-sent
	finishCRDStatusEvents(t, mode, events, release, activeCollection)
	refreshTimeout := 3 * time.Second
	if mode == "closed" || mode == "error" {
		// The pending refresh must survive termination, not wait for the 1s reconnect.
		refreshTimeout = 750 * time.Millisecond
	}
	select {
	case <-signal:
	case <-time.After(refreshTimeout):
		t.Fatal("CRD status events never refreshed discovery or signaled")
	}
	snapshot, err := tracker.GetAPIResources()
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range snapshot["v1"] {
		if resource.Name == "pods" && slices.Contains(resource.Verbs, verbWatch) {
			return
		}
	}
	t.Fatal("discovery cache does not contain the final discovery update")
}

func waitForCRDWatchStartup(ctx context.Context, t *testing.T, tracker *ResourceTracker, server *discoveryTestServer) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	// Start performs two initial collections and a debounced watch-establishment refresh.
	// Drain that refresh before changing discovery, so it cannot mask dropped CRD events.
	for server.RequestCount("/api/v1") < 3 {
		select {
		case <-deadline.C:
			t.Fatal("watch-establishment discovery never completed")
		case <-ticker.C:
		}
	}
	if _, err := tracker.collectAPIResources(ctx); err != nil {
		t.Fatal(err)
	}
}

func interceptCRDDiscovery(
	server *discoveryTestServer, ready chan struct{}, block *atomic.Bool, read chan struct{}, release <-chan struct{},
) func(http.ResponseWriter, *http.Request) bool {
	var readyOnce sync.Once
	return func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("watch") == "true" {
			readyOnce.Do(func() { close(ready) })
			return false
		}
		if r.URL.Path != "/api/v1" || !block.CompareAndSwap(true, false) {
			return false
		}
		response := httptest.NewRecorder()
		server.handle(response, r)
		close(read)
		select {
		case <-release:
			_, _ = w.Write(response.Body.Bytes())
		case <-r.Context().Done():
		}
		return true
	}
}

func finalCRDDiscoverySignal(tracker *ResourceTracker, signal chan<- struct{}) signalFunc {
	return func() error {
		snapshot, err := tracker.GetAPIResources()
		if err == nil {
			for _, resource := range snapshot["v1"] {
				if resource.Name == "pods" && slices.Contains(resource.Verbs, verbWatch) {
					select {
					case signal <- struct{}{}:
					default:
					}
				}
			}
		}
		return nil
	}
}

func stopCRDTestTracker(t *testing.T, cancel context.CancelFunc, release func(), done <-chan error) {
	t.Helper()
	cancel()
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("tracker stopped with error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("tracker did not stop after cancellation")
	}
}

func finishCRDStatusEvents(t *testing.T, mode string, events chan watch.Event, release func(), activeCollection <-chan error) {
	t.Helper()
	switch mode {
	case "closed":
		close(events)
	case "error":
		events <- watch.Event{Type: watch.Error, Object: &metav1.Status{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
			Status:   metav1.StatusFailure, Reason: metav1.StatusReasonExpired, Code: http.StatusGone,
		}}
	case "overlapping":
		// Hold the older snapshot past the library's 100ms debounce deadline.
		<-time.After(200 * time.Millisecond)
		release()
		select {
		case err := <-activeCollection:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("overlapping collection did not finish")
		}
	}
}

func newCRDWatchTestServer(server *discoveryTestServer, events <-chan watch.Event, sent chan<- struct{}, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	server.t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if intercept(w, r) {
			return
		}
		if r.URL.Query().Get("watch") != "true" {
			switch r.URL.Path {
			case "/apis":
				version := metav1.GroupVersionForDiscovery{GroupVersion: "apiextensions.k8s.io/v1", Version: "v1"}
				server.encode(w, metav1.APIGroupList{
					TypeMeta: metav1.TypeMeta{Kind: "APIGroupList"},
					Groups:   []metav1.APIGroup{{Name: "apiextensions.k8s.io", Versions: []metav1.GroupVersionForDiscovery{version}, PreferredVersion: version}},
				})
			case "/apis/apiextensions.k8s.io/v1":
				server.encode(w, metav1.APIResourceList{
					TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList"},
					GroupVersion: "apiextensions.k8s.io/v1",
					APIResources: []metav1.APIResource{{Name: "customresourcedefinitions", Kind: "CustomResourceDefinition"}},
				})
			case "/apis/apiextensions.k8s.io/v1/customresourcedefinitions":
				server.encode(w, apiextensionsv1.CustomResourceDefinitionList{
					TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinitionList"},
				})
			default:
				server.handle(w, r)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case event, ok := <-events:
				if !ok {
					return
				}
				server.encode(w, metav1.WatchEvent{Type: string(event.Type), Object: runtime.RawExtension{Object: event.Object}})
				w.(http.Flusher).Flush()
				sent <- struct{}{}
			case <-r.Context().Done():
				return
			}
		}
	}))
}

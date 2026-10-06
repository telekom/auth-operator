package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

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
	var blockCollection atomic.Bool
	collectionRead := make(chan struct{})
	releaseCollection := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCollection) }) }
	defer release()
	watchServer := newCRDWatchTestServer(server, events, sent, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/api/v1" || !blockCollection.CompareAndSwap(true, false) {
			return false
		}
		response := httptest.NewRecorder()
		server.handle(response, r)
		close(collectionRead)
		select {
		case <-releaseCollection:
			_, _ = w.Write(response.Body.Bytes())
		case <-r.Context().Done():
		}
		return true
	})
	defer watchServer.Close()

	config := server.Config()
	config.Host = watchServer.URL
	testScheme := runtime.NewScheme()
	if err := apiextensionsv1.AddToScheme(testScheme); err != nil {
		t.Fatal(err)
	}
	tracker := NewResourceTracker(testScheme, config)
	tracker.rateLimit.Interval = 100 * time.Millisecond
	if changed, err := tracker.collectAPIResources(context.Background()); err != nil || !changed {
		t.Fatalf("initial discovery = (%v, %v)", changed, err)
	}
	signal := make(chan struct{}, 2)
	tracker.AddSignalFunc(func() error {
		signal <- struct{}{}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	ready := make(chan struct{})
	go func() {
		defer close(done)
		tracker.watchAPIResources(ctx, ready)
	}()
	select {
	case <-ready:
	case <-done:
		t.Fatal("CRD watch failed to start")
	case <-time.After(3 * time.Second):
		t.Fatal("CRD watch never became ready")
	}
	tracker.rateLimit.Do(func() {})
	activeCollection := make(chan error, 1)
	if mode == "overlapping" {
		blockCollection.Store(true)
		go func() {
			_, err := tracker.collectAPIResources(context.Background())
			activeCollection <- err
		}()
		select {
		case <-collectionRead:
		case <-time.After(3 * time.Second):
			t.Fatal("overlapping collection did not read the old discovery snapshot")
		}
	}
	crd := &apiextensionsv1.CustomResourceDefinition{
		TypeMeta: metav1.TypeMeta{APIVersion: "apiextensions.k8s.io/v1", Kind: "CustomResourceDefinition"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "widgets.example.com",
		},
	}
	events <- watch.Event{Type: watch.Modified, Object: crd}
	<-sent
	server.established.Store(true)
	establishedCRD := crd.DeepCopy()
	establishedCRD.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{
		{Type: apiextensionsv1.Established, Status: apiextensionsv1.ConditionTrue},
	}
	events <- watch.Event{Type: watch.Modified, Object: establishedCRD}
	<-sent
	finishCRDStatusEvents(t, mode, events, tracker.rateLimit.Interval, release, activeCollection)
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("throttled CRD status events never refreshed discovery or signaled")
	}
	assertEstablishedResourceCached(t, tracker)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("CRD watch did not stop after cancellation")
	}
	want := 2 // initial snapshot plus one coalesced refresh
	if mode == "overlapping" {
		want++
	}
	if got := server.RequestCount("/api/v1"); got != want {
		t.Fatalf("discovery requests = %d, want %d", got, want)
	}
}

func finishCRDStatusEvents(t *testing.T, mode string, events chan watch.Event, interval time.Duration, release func(), activeCollection <-chan error) {
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
		// Keep the older discovery snapshot active past the pending timer.
		<-time.After(2 * interval)
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

func assertEstablishedResourceCached(t *testing.T, tracker *ResourceTracker) {
	t.Helper()
	tracker.cacheMu.RLock()
	defer tracker.cacheMu.RUnlock()
	for _, resource := range tracker.cache["v1"] {
		if resource.Name == "widgets" {
			return
		}
	}
	t.Fatal("discovery cache does not contain the finally established resource")
}

func newCRDWatchTestServer(server *discoveryTestServer, events <-chan watch.Event, sent chan<- struct{}, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	server.t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("watch") != "true" {
			if intercept(w, r) {
				return
			}
			if r.URL.Path == "/apis" {
				version := metav1.GroupVersionForDiscovery{GroupVersion: "apiextensions.k8s.io/v1", Version: "v1"}
				server.encode(w, metav1.APIGroupList{
					TypeMeta: metav1.TypeMeta{Kind: "APIGroupList"},
					Groups:   []metav1.APIGroup{{Name: "apiextensions.k8s.io", Versions: []metav1.GroupVersionForDiscovery{version}, PreferredVersion: version}},
				})
				return
			}
			if r.URL.Path == "/apis/apiextensions.k8s.io/v1" {
				server.encode(w, metav1.APIResourceList{
					TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList"},
					GroupVersion: "apiextensions.k8s.io/v1",
					APIResources: []metav1.APIResource{{Name: "customresourcedefinitions", Kind: "CustomResourceDefinition"}},
				})
				return
			}
			server.handle(w, r)
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

func TestResourceTrackerCollectionSignalsOnlyOnChanges(t *testing.T) {
	server := newDiscoveryTestServer(t)
	defer server.Close()

	tracker := NewResourceTracker(kubescheme.Scheme, server.Config())

	changed, err := tracker.collectAPIResources(context.Background())
	if err != nil {
		t.Fatalf("initial collection: %v", err)
	}
	if !changed {
		t.Fatal("initial collection should report a change")
	}

	changed, err = tracker.collectAPIResources(context.Background())
	if err != nil {
		t.Fatalf("unchanged collection: %v", err)
	}
	if changed {
		t.Fatal("unchanged collection should not report a change")
	}
	if got := server.RequestCount("/api/v1"); got != 2 {
		t.Fatalf("core discovery requests = %d, want one per collection (2)", got)
	}
	if got := countAPIResources(tracker.cache); got != 2 {
		t.Fatalf("cached core resources = %d, want 2 without duplicates", got)
	}
}

func TestResourceTrackerKeepsUsableCacheAfterEmptyDiscovery(t *testing.T) {
	server := newDiscoveryTestServer(t)
	defer server.Close()

	tracker := NewResourceTracker(kubescheme.Scheme, server.Config())
	if changed, err := tracker.collectAPIResources(context.Background()); err != nil || !changed {
		t.Fatalf("initial collection = (%v, %v), want (true, nil)", changed, err)
	}

	server.SetEmpty(true)
	changed, err := tracker.collectAPIResources(context.Background())
	if err != nil {
		t.Fatalf("empty refresh: %v", err)
	}
	if changed {
		t.Fatal("empty refresh should not report a change")
	}
	if got := countAPIResources(tracker.cache); got == 0 {
		t.Fatal("empty refresh replaced the usable cache")
	}
}

func TestResourceTrackerFailsWithoutUsableInitialDiscovery(t *testing.T) {
	server := newDiscoveryTestServer(t)
	defer server.Close()
	server.SetEmpty(true)

	tracker := NewResourceTracker(kubescheme.Scheme, server.Config())
	changed, err := tracker.collectAPIResources(context.Background())
	if err == nil {
		t.Fatal("empty initial collection should fail")
	}
	if changed {
		t.Fatal("failed initial collection should not report a change")
	}
	if got := countAPIResources(tracker.cache); got != 0 {
		t.Fatalf("empty initial collection populated %d resources", got)
	}
}

func TestResourceTrackerReportsUnchangedOnDiscoveryHTTPError(t *testing.T) {
	server := newDiscoveryTestServer(t)
	defer server.Close()
	server.SetError(true)

	tracker := NewResourceTracker(kubescheme.Scheme, server.Config())
	changed, err := tracker.collectAPIResources(context.Background())
	if err == nil {
		t.Fatal("discovery HTTP error should fail")
	}
	if changed {
		t.Fatal("discovery HTTP error should not report a change")
	}
}

func TestAPIResourcesByGroupVersionEqualsChangedResource(t *testing.T) {
	base := APIResourcesByGroupVersion{
		"v1": {{Name: "pods", Kind: "Pod", Verbs: []string{"get", "list"}}},
	}
	changed := APIResourcesByGroupVersion{
		"v1": {{Name: "pods", Kind: "Pod", Verbs: []string{"get", "list", "watch"}}},
	}
	if base.Equals(changed) {
		t.Fatal("Equals returned true for changed resource verbs")
	}
}

func TestResourceTrackerSignalRegistrationConcurrent(t *testing.T) {
	tracker := NewResourceTracker(nil, nil)
	const workers = 8
	const registrations = 100

	var wg sync.WaitGroup
	wg.Add(workers * 2)
	for range workers {
		go func() {
			defer wg.Done()
			for range registrations {
				tracker.AddSignalFunc(func() error { return nil })
			}
		}()
	}
	for range workers {
		go func() {
			defer wg.Done()
			for range registrations {
				_ = tracker.signalFuncsSnapshot()
			}
		}()
	}
	wg.Wait()

	callbackCalled := make(chan struct{})
	tracker.AddSignalFunc(func() error {
		tracker.AddSignalFunc(func() error { return nil })
		close(callbackCalled)
		return nil
	})
	for _, callback := range tracker.signalFuncsSnapshot() {
		if err := callback(); err != nil {
			t.Fatalf("callback: %v", err)
		}
	}
	select {
	case <-callbackCalled:
	default:
		t.Fatal("callback was not invoked")
	}
}

type discoveryTestServer struct {
	*httptest.Server
	t           *testing.T
	empty       atomic.Bool
	err         atomic.Bool
	established atomic.Bool
	mu          sync.Mutex
	requests    map[string]int
}

func newDiscoveryTestServer(t *testing.T) *discoveryTestServer {
	t.Helper()
	server := &discoveryTestServer{t: t, requests: make(map[string]int)}
	server.Server = httptest.NewServer(http.HandlerFunc(server.handle))
	return server
}

func (s *discoveryTestServer) Config() *rest.Config {
	return &rest.Config{
		Host:    s.URL,
		APIPath: "/api",
		ContentConfig: rest.ContentConfig{
			GroupVersion:         &schema.GroupVersion{Version: "v1"},
			NegotiatedSerializer: kubescheme.Codecs.WithoutConversion(),
		},
	}
}

func (s *discoveryTestServer) SetEmpty(empty bool) {
	s.empty.Store(empty)
}

func (s *discoveryTestServer) SetError(err bool) {
	s.err.Store(err)
}

func (s *discoveryTestServer) RequestCount(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[path]
}

func (s *discoveryTestServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests[r.URL.Path]++
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch r.URL.Path {
	case "/api":
		s.encode(w, metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
	case "/apis":
		s.encode(w, metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList"}})
	case "/api/v1":
		if s.err.Load() {
			http.Error(w, "discovery failure", http.StatusInternalServerError)
			return
		}
		resources := []metav1.APIResource{}
		if !s.empty.Load() {
			resources = append(resources, metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: []string{"get", "list"}})
		}
		if s.established.Load() {
			resources = append(resources, metav1.APIResource{Name: "widgets", Kind: "Widget", Namespaced: true, Verbs: []string{"get", "list"}})
		}
		s.encode(w, metav1.APIResourceList{
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList"},
			GroupVersion: "v1",
			APIResources: resources,
		})
	default:
		http.NotFound(w, r)
	}
}

func (s *discoveryTestServer) encode(w http.ResponseWriter, value any) {
	s.t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.t.Errorf("encode discovery response: %v", err)
	}
}

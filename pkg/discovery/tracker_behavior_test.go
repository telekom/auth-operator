package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	kubescheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
)

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
	snapshot, err := tracker.GetAPIResources()
	if err != nil {
		t.Fatal(err)
	}
	if got := countAPIResources(snapshot); got != 2 {
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
	snapshot, err := tracker.GetAPIResources()
	if err != nil {
		t.Fatal(err)
	}
	if got := countAPIResources(snapshot); got == 0 {
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
	snapshot, _ := tracker.GetAPIResources()
	if got := countAPIResources(snapshot); got != 0 {
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

func TestResourceTrackerPartialDiscoveryRetainsFailedGroup(t *testing.T) {
	server := newDiscoveryTestServer(t)
	defer server.Close()
	server.customGroup.Store(true)
	tracker := NewResourceTracker(kubescheme.Scheme, server.Config())
	if _, err := tracker.collectAPIResources(context.Background()); err != nil {
		t.Fatal(err)
	}
	server.groupError.Store(true)
	server.coreWatch.Store(true)
	changed, err := tracker.collectAPIResources(context.Background())
	var partial *discovery.ErrGroupDiscoveryFailed
	if !changed || !errors.As(err, &partial) {
		t.Fatalf("partial refresh = (%v, %v), want a changed snapshot and wrapped discovery error", changed, err)
	}
	snapshot, err := tracker.GetAPIResources()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot["coverage.example.com/v1"]) != 2 {
		t.Fatal("failed group was removed or its synthetic resources were duplicated")
	}
	for i := range snapshot["v1"] {
		if snapshot["v1"][i].Name == "pods" {
			if !slices.Contains(snapshot["v1"][i].Verbs, verbWatch) {
				t.Fatal("healthy core group was not refreshed")
			}
			snapshot["v1"][i].Verbs[0] = "modified-copy"
		}
	}
	fresh, err := tracker.GetAPIResources()
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range fresh["v1"] {
		if slices.Contains(resource.Verbs, "modified-copy") {
			t.Fatal("nested snapshot mutation changed the shared cache")
		}
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
	customGroup atomic.Bool
	groupError  atomic.Bool
	coreWatch   atomic.Bool
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
		groups := metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList"}}
		if s.customGroup.Load() {
			version := metav1.GroupVersionForDiscovery{GroupVersion: "coverage.example.com/v1", Version: "v1"}
			groups.Groups = []metav1.APIGroup{{Name: "coverage.example.com",
				Versions: []metav1.GroupVersionForDiscovery{version}, PreferredVersion: version}}
		}
		s.encode(w, groups)
	case "/api/v1":
		if s.err.Load() {
			http.Error(w, "discovery failure", http.StatusInternalServerError)
			return
		}
		resources := []metav1.APIResource{}
		if !s.empty.Load() {
			verbs := metav1.Verbs{"get", "list"}
			if s.coreWatch.Load() {
				verbs = append(verbs, verbWatch)
			}
			resources = append(resources, metav1.APIResource{Name: "pods", Kind: "Pod", Namespaced: true, Verbs: verbs})
		}
		s.encode(w, metav1.APIResourceList{
			TypeMeta:     metav1.TypeMeta{Kind: "APIResourceList"},
			GroupVersion: "v1",
			APIResources: resources,
		})
	case "/apis/coverage.example.com/v1":
		if s.groupError.Load() {
			http.Error(w, "group discovery failure", http.StatusInternalServerError)
			return
		}
		s.encode(w, metav1.APIResourceList{
			TypeMeta: metav1.TypeMeta{Kind: "APIResourceList"}, GroupVersion: "coverage.example.com/v1",
			APIResources: []metav1.APIResource{{Name: "widgets", Kind: "Widget", Verbs: metav1.Verbs{"get", "list"}}},
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

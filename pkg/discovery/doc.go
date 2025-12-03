// Package discovery provides functionality to track and cache the available API resources
// in the Kubernetes cluster.
// It collects API resources through the Kubernetes Discovery API both periodically and
// triggered by CRD events and maintains an up-to-date cache that can be queried by other components.
package discovery

package discovery

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CRDWaiter provides functionality to wait for CRDs to become available and established.
type CRDWaiter struct {
	client client.Client
	log    logr.Logger
}

// NewCRDWaiter creates a new CRDWaiter.
func NewCRDWaiter(c client.Client, log logr.Logger) *CRDWaiter {
	return &CRDWaiter{
		client: c,
		log:    log.WithName("crd-waiter"),
	}
}

// WaitForCRDs waits for all specified CRDs to be established.
// It returns an error if the context is cancelled or times out.
func (w *CRDWaiter) WaitForCRDs(ctx context.Context, gvks []schema.GroupVersionKind, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, gvk := range gvks {
		crdName := crdNameFromGVK(gvk)
		w.log.Info("waiting for CRD to be established", "crd", crdName, "gvk", gvk.String())

		if err := w.waitForCRD(ctx, crdName); err != nil {
			return fmt.Errorf("failed waiting for CRD %s: %w", crdName, err)
		}
		w.log.Info("CRD is established", "crd", crdName)
	}

	return nil
}

// waitForCRD waits for a single CRD to be established.
func (w *CRDWaiter) waitForCRD(ctx context.Context, crdName string) error {
	backoff := wait.Backoff{
		Duration: 500 * time.Millisecond,
		Factor:   1.5,
		Jitter:   0.1,
		Steps:    30, // ~2.5 minutes with this backoff
		Cap:      10 * time.Second,
	}

	return wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		crd := &apiextensionsv1.CustomResourceDefinition{}
		err := w.client.Get(ctx, types.NamespacedName{Name: crdName}, crd)
		if err != nil {
			if apierrors.IsNotFound(err) {
				w.log.V(1).Info("CRD not found, retrying...", "crd", crdName)
				return false, nil // Retry
			}
			// Transient error, retry
			w.log.V(1).Info("error fetching CRD, retrying...", "crd", crdName, "error", err.Error())
			return false, nil
		}

		// Check if CRD is established
		for _, condition := range crd.Status.Conditions {
			if condition.Type == apiextensionsv1.Established {
				if condition.Status == apiextensionsv1.ConditionTrue {
					return true, nil // Done
				}
				w.log.V(1).Info("CRD not yet established, retrying...", "crd", crdName, "status", condition.Status)
				return false, nil // Retry
			}
		}

		w.log.V(1).Info("CRD has no Established condition yet, retrying...", "crd", crdName)
		return false, nil // Retry
	})
}

// crdNameFromGVK constructs the CRD name from a GroupVersionKind
// CRD names follow the pattern: <plural>.<group>
// For example: roledefinitions.authorization.t-caas.telekom.com.
func crdNameFromGVK(gvk schema.GroupVersionKind) string {
	// Convert Kind to lowercase plural form (simple heuristic)
	plural := pluralize(gvk.Kind)
	return fmt.Sprintf("%s.%s", plural, gvk.Group)
}

// pluralize converts a Kind to its lowercase plural form
// This is a simple heuristic that works for most Kubernetes resource kinds.
func pluralize(kind string) string {
	lower := toLower(kind)
	// Handle common cases
	switch {
	case endsWith(lower, "s"):
		return lower + "es"
	case endsWith(lower, "y"):
		// Vowel + y: just add 's' (e.g., gateway -> gateways, key -> keys)
		// Consonant + y: replace with 'ies' (e.g., policy -> policies)
		if len(lower) >= 2 && isVowel(lower[len(lower)-2]) {
			return lower + "s"
		}
		return lower[:len(lower)-1] + "ies"
	default:
		return lower + "s"
	}
}

func isVowel(c byte) bool {
	return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

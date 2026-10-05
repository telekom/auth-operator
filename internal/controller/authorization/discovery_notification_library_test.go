// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package authorization

import (
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestDiscoveryNotificationsCoalesce(t *testing.T) {
	events := make(chan event.TypedGenericEvent[client.Object], 100)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range cap(events) + 1 {
			if err := notifyDiscoveryChange(events); err != nil {
				t.Errorf("notify discovery change: %v", err)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full controller queue blocked tracker shutdown")
	}
	if len(events) != cap(events) {
		t.Fatal("pending controller notifications were lost")
	}
}

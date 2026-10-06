// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"math"
	"testing"
)

func TestValidateSharedRateLimitBounds(t *testing.T) {
	for _, limit := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 1e9 + 1} {
		if err := validateRateLimitFlags(limit, 1); err == nil {
			t.Errorf("unsupported rate %v was accepted", limit)
		}
	}
	if err := validateRateLimitFlags(1e9, 1); err != nil {
		t.Fatalf("maximum supported rate was rejected: %v", err)
	}
}

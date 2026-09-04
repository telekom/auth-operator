//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdmissionReviewBodyLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		size       int
		wantStatus int
	}{
		{name: "exact limit is read", size: maxReviewBytes, wantStatus: http.StatusBadRequest},
		{name: "over limit is rejected", size: maxReviewBytes + 1, wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/mutate",
				bytes.NewReader(bytes.Repeat([]byte{'x'}, test.size)))
			response := httptest.NewRecorder()

			(&server{fixture: "fixture"}).ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package utils

import "testing"

func TestCountWebhookCABundles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		configs  int
		webhooks int
		bundles  int
		wantErr  bool
	}{
		{
			name: "empty list",
			input: `{
				"items": []
			}`,
		},
		{
			name: "single populated validating webhook",
			input: `{
				"items": [
					{
						"webhooks": [
							{
								"clientConfig": {
									"caBundle": "Y2E="
								}
							}
						]
					}
				]
			}`,
			configs:  1,
			webhooks: 1,
			bundles:  1,
		},
		{
			name: "single empty webhook",
			input: `{
				"items": [
					{
						"webhooks": [
							{
								"clientConfig": {
									"caBundle": ""
								}
							}
						]
					}
				]
			}`,
			configs:  1,
			webhooks: 1,
		},
		{
			name: "multiple configurations and mixed bundles",
			input: `{
				"items": [
					{
						"webhooks": [
							{
								"clientConfig": {
									"caBundle": "Y2E="
								}
							},
							{
								"clientConfig": {
									"caBundle": " "
								}
							}
						]
					},
					{
						"webhooks": [
							{
								"clientConfig": {
									"caBundle": "Y2Ey"
								}
							}
						]
					}
				]
			}`,
			configs:  2,
			webhooks: 3,
			bundles:  2,
		},
		{
			name:    "invalid json",
			input:   `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			configs, webhooks, bundles, err := countWebhookCABundles([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if configs != tt.configs || webhooks != tt.webhooks || bundles != tt.bundles {
				t.Fatalf("counts = (%d, %d, %d), want (%d, %d, %d)",
					configs, webhooks, bundles, tt.configs, tt.webhooks, tt.bundles)
			}
		})
	}
}

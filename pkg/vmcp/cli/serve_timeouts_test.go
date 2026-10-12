// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/toolhive/pkg/vmcp/config"
)

func TestBackendInitTimeoutFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "returns zero for nil config",
			cfg:  nil,
			want: 0,
		},
		{
			name: "uses health check timeout when configured",
			cfg: &config.Config{
				Operational: &config.OperationalConfig{
					Timeouts: &config.TimeoutConfig{
						Default: config.Duration(60 * time.Second),
					},
					FailureHandling: &config.FailureHandlingConfig{
						HealthCheckTimeout: config.Duration(10 * time.Second),
					},
				},
			},
			want: 10 * time.Second,
		},
		{
			name: "falls back to default timeout",
			cfg: &config.Config{
				Operational: &config.OperationalConfig{
					Timeouts: &config.TimeoutConfig{
						Default: config.Duration(45 * time.Second),
					},
				},
			},
			want: 45 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := backendInitTimeoutFromConfig(tt.cfg)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBackendRequestTimeoutsFromConfig(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Operational: &config.OperationalConfig{
			Timeouts: &config.TimeoutConfig{
				Default: config.Duration(60 * time.Second),
				PerWorkload: map[string]config.Duration{
					"cilium-flows-mcp": config.Duration(125 * time.Second),
				},
			},
		},
	}

	defaultTimeout, perWorkload := backendRequestTimeoutsFromConfig(cfg)

	assert.Equal(t, 60*time.Second, defaultTimeout)
	assert.Equal(t, map[string]time.Duration{
		"cilium-flows-mcp": 125 * time.Second,
	}, perWorkload)
}

func TestServerWriteTimeoutFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		want time.Duration
	}{
		{
			name: "returns zero without timeout configuration",
			cfg:  nil,
			want: 0,
		},
		{
			name: "adds response margin to default timeout",
			cfg: &config.Config{Operational: &config.OperationalConfig{
				Timeouts: &config.TimeoutConfig{Default: config.Duration(125 * time.Second)},
			}},
			want: 130 * time.Second,
		},
		{
			name: "uses the largest per-workload timeout",
			cfg: &config.Config{Operational: &config.OperationalConfig{
				Timeouts: &config.TimeoutConfig{
					Default: config.Duration(60 * time.Second),
					PerWorkload: map[string]config.Duration{
						"elastic-mcp": config.Duration(125 * time.Second),
					},
				},
			}},
			want: 130 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, serverWriteTimeoutFromConfig(tt.cfg))
		})
	}
}

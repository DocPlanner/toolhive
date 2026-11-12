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

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/auth"
	"github.com/stacklok/toolhive/pkg/vmcp/auth/strategies"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
)

func TestRequestTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		opts        []Option
		workload    string
		wantTimeout time.Duration
	}{
		{name: "no option uses 90 s", workload: "a", wantTimeout: defaultBackendRequestTimeout},
		{
			name:        "default applies to unlisted workload",
			opts:        []Option{WithRequestTimeouts(2*time.Minute, map[string]time.Duration{"b": time.Minute})},
			workload:    "a",
			wantTimeout: 2 * time.Minute,
		},
		{
			name:        "per-workload wins over default",
			opts:        []Option{WithRequestTimeouts(2*time.Minute, map[string]time.Duration{"a": 5 * time.Minute})},
			workload:    "a",
			wantTimeout: 5 * time.Minute,
		},
		{
			name:        "non-positive values fall back to 90 s",
			opts:        []Option{WithRequestTimeouts(0, map[string]time.Duration{"a": -time.Second})},
			workload:    "a",
			wantTimeout: defaultBackendRequestTimeout,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bc, err := NewHTTPBackendClient(auth.NewDefaultOutgoingAuthRegistry(), tt.opts...)
			require.NoError(t, err)
			assert.Equal(t, tt.wantTimeout, bc.(*httpBackendClient).requestTimeout(tt.workload))
		})
	}
}

// TestWithRequestTimeouts_CutsSlowBackendCall checks that the per-workload timeout
// reaches the streamable-HTTP client: a backend that never answers fails the call
// after the configured timeout, not after the 90 s default.
func TestWithRequestTimeouts_CutsSlowBackendCall(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() {
		close(release)
		ts.Close()
	})

	registry := auth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, registry.RegisterStrategy(authtypes.StrategyTypeUnauthenticated, &strategies.UnauthenticatedStrategy{}))
	bc, err := NewHTTPBackendClient(registry,
		WithRequestTimeouts(time.Hour, map[string]time.Duration{"slow": 200 * time.Millisecond}))
	require.NoError(t, err)

	target := &vmcp.BackendTarget{
		WorkloadID:    "slow",
		WorkloadName:  "slow",
		BaseURL:       ts.URL,
		TransportType: "streamable-http",
	}

	start := time.Now()
	_, err = bc.CallTool(t.Context(), target, "any", nil, nil)
	require.Error(t, err)
	assert.Less(t, time.Since(start), 10*time.Second, "call must end at the per-workload timeout")
}

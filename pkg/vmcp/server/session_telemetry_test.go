// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
)

func TestMonitorSessionCardinality(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	sessionManager := transportsession.NewManager(time.Minute, transportsession.NewStreamableSession)
	t.Cleanup(func() { _ = sessionManager.Stop() })
	require.NoError(t, sessionManager.AddWithID("11111111-1111-1111-1111-111111111111"))
	require.NoError(t, sessionManager.AddWithID("22222222-2222-2222-2222-222222222222"))

	srv := &Server{sessionManager: sessionManager}
	for _, id := range []string{"sdk-session-1", "sdk-session-2", "sdk-session-3"} {
		srv.activeClientSessions.begin(id)
		srv.activeClientSessions.commit(&fakeSDKSession{id: id})
	}
	srv.inFlightRegistrations.Add(1)

	require.NoError(t, monitorSessionCardinality(meterProvider, srv))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	gauges := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if g, ok := m.Data.(metricdata.Gauge[int64]); ok && len(g.DataPoints) > 0 {
				gauges[m.Name] = g.DataPoints[len(g.DataPoints)-1].Value
			}
		}
	}
	assert.Equal(t, map[string]int64{
		"toolhive_vmcp_active_transport_sessions":      2,
		"toolhive_vmcp_active_sdk_sessions":            3,
		"toolhive_vmcp_inflight_session_registrations": 1,
	}, gauges)
}

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

func findMetric(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func gaugeValue(m *metricdata.Metrics) int64 {
	if m == nil {
		return 0
	}
	gauge, ok := m.Data.(metricdata.Gauge[int64])
	if !ok {
		return 0
	}
	var latest int64
	for _, dp := range gauge.DataPoints {
		latest = dp.Value
	}
	return latest
}

func TestMonitorSessionCardinality(t *testing.T) {
	t.Parallel()

	reader := sdkmetric.NewManualReader()
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	sessionManager := transportsession.NewManager(time.Minute, transportsession.NewStreamableSession)
	t.Cleanup(func() {
		_ = sessionManager.Stop()
	})

	require.NoError(t, sessionManager.AddWithID("11111111-1111-1111-1111-111111111111"))
	require.NoError(t, sessionManager.AddWithID("22222222-2222-2222-2222-222222222222"))

	srv := &Server{
		sessionManager: sessionManager,
	}
	srv.activeClientSessions.Store("sdk-session-1", &hydrationTestSession{sessionID: "sdk-session-1"})
	srv.activeClientSessions.Store("sdk-session-2", &hydrationTestSession{sessionID: "sdk-session-2"})
	srv.activeClientSessions.Store("sdk-session-3", &hydrationTestSession{sessionID: "sdk-session-3"})
	srv.inFlightRegistrations.Store("registering-session-1", newSessionRegistrationState())

	require.NoError(t, monitorSessionCardinality(meterProvider, srv))

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	assert.Equal(t, int64(2), gaugeValue(findMetric(rm, "toolhive_vmcp_active_transport_sessions")))
	assert.Equal(t, int64(3), gaugeValue(findMetric(rm, "toolhive_vmcp_active_sdk_sessions")))
	assert.Equal(t, int64(1), gaugeValue(findMetric(rm, "toolhive_vmcp_inflight_session_registrations")))
}

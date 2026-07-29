// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

// instrumentationName is the OTEL instrumentation scope for vMCP server metrics.
const instrumentationName = "github.com/stacklok/toolhive/pkg/vmcp"

// monitorSessionCardinality registers observable gauges for the main vMCP
// session layers so operators can distinguish transport/session churn from
// live SDK-session growth and post-initialize registration backlog.
func monitorSessionCardinality(
	meterProvider metric.MeterProvider,
	srv *Server,
) error {
	meter := meterProvider.Meter(instrumentationName)

	activeTransportSessions, err := meter.Int64ObservableGauge(
		"toolhive_vmcp_active_transport_sessions",
		metric.WithDescription("Number of active transport-layer MCP sessions tracked by the vMCP"),
	)
	if err != nil {
		return fmt.Errorf("failed to create active transport sessions gauge: %w", err)
	}

	activeSDKSessions, err := meter.Int64ObservableGauge(
		"toolhive_vmcp_active_sdk_sessions",
		metric.WithDescription("Number of live SDK client sessions currently registered on this vMCP replica"),
	)
	if err != nil {
		return fmt.Errorf("failed to create active SDK sessions gauge: %w", err)
	}

	inFlightRegistrations, err := meter.Int64ObservableGauge(
		"toolhive_vmcp_inflight_session_registrations",
		metric.WithDescription("Number of session registrations currently executing the post-initialize capability injection hook"),
	)
	if err != nil {
		return fmt.Errorf("failed to create in-flight session registrations gauge: %w", err)
	}

	_, err = meter.RegisterCallback(
		func(_ context.Context, observer metric.Observer) error {
			observer.ObserveInt64(activeTransportSessions, int64(srv.sessionManager.Count()))
			observer.ObserveInt64(activeSDKSessions, srv.activeClientSessionCount())
			observer.ObserveInt64(inFlightRegistrations, srv.inFlightRegistrationCount())
			return nil
		},
		activeTransportSessions,
		activeSDKSessions,
		inFlightRegistrations,
	)
	if err != nil {
		return fmt.Errorf("failed to register session cardinality callback: %w", err)
	}

	return nil
}

func (s *Server) activeClientSessionCount() int64 {
	var count int64
	s.activeClientSessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func (s *Server) inFlightRegistrationCount() int64 {
	var count int64
	s.inFlightRegistrations.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

type registrationContextKey struct{}

// registrationContextRecorder records the context CreateSession receives and then
// fails, so handleSessionRegistrationImpl stops before it needs a core. Methods
// not overridden here are never called by the code under test.
type registrationContextRecorder struct {
	SessionManager

	ctxErr      error
	deadline    time.Time
	hasDeadline bool
	subject     string
	value       any
	inFlight    int64
	srv         *Server
}

var errStopRegistration = errors.New("stop after CreateSession")

func (r *registrationContextRecorder) CreateSession(ctx context.Context, _ string) (vmcpsession.MultiSession, error) {
	r.ctxErr = ctx.Err()
	r.deadline, r.hasDeadline = ctx.Deadline()
	if identity, ok := auth.IdentityFromContext(ctx); ok {
		r.subject = identity.Subject
	}
	r.value = ctx.Value(registrationContextKey{})
	r.inFlight = r.srv.inFlightRegistrations.Load()
	return nil, errStopRegistration
}

func (*registrationContextRecorder) Terminate(string) (bool, error) { return false, nil }

func TestHandleSessionRegistrationImpl_DetachedBoundedContext(t *testing.T) {
	t.Parallel()

	rec := &registrationContextRecorder{}
	srv := &Server{vmcpSessionMgr: rec}
	rec.srv = srv

	ctx := auth.WithIdentity(context.Background(), &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{Subject: "subject-123"},
	})
	ctx = context.WithValue(ctx, registrationContextKey{}, "kept")
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	err := srv.handleSessionRegistrationImpl(canceledCtx, &fakeSDKSession{id: "session-123"})
	require.ErrorIs(t, err, errStopRegistration)

	assert.NoError(t, rec.ctxErr, "request cancellation must not reach session creation")
	assert.Equal(t, "subject-123", rec.subject, "identity must survive the detach")
	assert.Equal(t, "kept", rec.value, "request values must survive the detach")
	require.True(t, rec.hasDeadline, "detached context must be bounded")
	remaining := time.Until(rec.deadline)
	assert.Greater(t, remaining, defaultSessionRegistrationTimeout-5*time.Second)
	assert.LessOrEqual(t, remaining, defaultSessionRegistrationTimeout)

	assert.Equal(t, int64(1), rec.inFlight, "registration counts as in flight while it runs")
	assert.Equal(t, int64(0), srv.inFlightRegistrations.Load(), "in-flight count drops when it returns")
}

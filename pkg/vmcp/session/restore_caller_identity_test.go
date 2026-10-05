// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/vmcp"
	internalbk "github.com/stacklok/toolhive/pkg/vmcp/session/internal/backend"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

type restoreIdentityRecorder struct {
	mu         sync.Mutex
	connector  *auth.Identity
	requestCtx *auth.Identity
}

func (r *restoreIdentityRecorder) connect(
	ctx context.Context, _ *vmcp.BackendTarget, identity *auth.Identity, _ string,
) (internalbk.Session, *vmcp.CapabilityList, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.connector = identity
	r.requestCtx, _ = auth.IdentityFromContext(ctx)
	return &mockConnectedBackend{sessID: "backend-session"}, &vmcp.CapabilityList{}, nil
}

func (r *restoreIdentityRecorder) seen() (*auth.Identity, *auth.Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connector, r.requestCtx
}

func restoreTestBackends() []*vmcp.Backend {
	return []*vmcp.Backend{{ID: "memory"}}
}

func callerIdentity(subject, token string) *auth.Identity {
	return &auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: subject}, Token: token}
}

func storedBoundSession(t *testing.T, factory MultiSessionFactory) map[string]string {
	t.Helper()
	original, err := factory.MakeSessionWithID(
		t.Context(), uuid.New().String(), callerIdentity("alice", "token-at-create"), restoreTestBackends(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = original.Close() })
	return original.GetMetadata()
}

func creatorOf(t *testing.T, sess sessiontypes.MultiSession) *auth.Identity {
	t.Helper()
	provider, ok := sess.(sessiontypes.CreatorIdentityProvider)
	require.True(t, ok)
	return provider.CreatorIdentity()
}

func TestRestoreSession_UsesTheOwnersLiveIdentity(t *testing.T) {
	t.Parallel()

	recorder := &restoreIdentityRecorder{}
	factory := newSessionFactoryWithConnector(recorder.connect)
	stored := storedBoundSession(t, factory)

	owner := callerIdentity("alice", "token-at-restore")
	restored, err := factory.RestoreSession(
		auth.WithIdentity(t.Context(), owner), uuid.New().String(), stored, restoreTestBackends(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	connectorIdentity, requestIdentity := recorder.seen()
	assert.Same(t, owner, connectorIdentity)
	assert.Same(t, owner, requestIdentity)
	assert.Equal(t, "token-at-restore", creatorOf(t, restored).Token)
}

func TestRestoreSession_IgnoresAnotherSubjectsIdentity(t *testing.T) {
	t.Parallel()

	recorder := &restoreIdentityRecorder{}
	factory := newSessionFactoryWithConnector(recorder.connect)
	stored := storedBoundSession(t, factory)

	restored, err := factory.RestoreSession(
		auth.WithIdentity(t.Context(), callerIdentity("mallory", "mallory-token")),
		uuid.New().String(), stored, restoreTestBackends(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	connectorIdentity, requestIdentity := recorder.seen()
	require.NotNil(t, connectorIdentity)
	assert.Equal(t, "alice", connectorIdentity.Subject)
	assert.Empty(t, connectorIdentity.Token)
	assert.Nil(t, requestIdentity)
	assert.Empty(t, creatorOf(t, restored).Token)
}

func TestRestoreSession_WithoutCallerKeepsTheStoredSubject(t *testing.T) {
	t.Parallel()

	recorder := &restoreIdentityRecorder{}
	factory := newSessionFactoryWithConnector(recorder.connect)
	stored := storedBoundSession(t, factory)

	restored, err := factory.RestoreSession(t.Context(), uuid.New().String(), stored, restoreTestBackends())
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	connectorIdentity, requestIdentity := recorder.seen()
	require.NotNil(t, connectorIdentity)
	assert.Equal(t, "alice", connectorIdentity.Subject)
	assert.Empty(t, connectorIdentity.Token)
	assert.Nil(t, requestIdentity)
}

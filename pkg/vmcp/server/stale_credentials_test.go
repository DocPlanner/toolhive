// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

// credentialTestSession only implements what the refresh path reads.
type credentialTestSession struct {
	sessiontypes.MultiSession
	metadata map[string]string
	identity *auth.Identity
}

func (s *credentialTestSession) GetMetadata() map[string]string {
	cloned := make(map[string]string, len(s.metadata))
	for k, v := range s.metadata {
		cloned[k] = v
	}
	return cloned
}

func (s *credentialTestSession) CreatorIdentity() *auth.Identity { return s.identity }

func (*credentialTestSession) Close() error { return nil }

// credentialTestManager hands out one rebuilt session and records how the
// server ends or rolls back the refresh.
type credentialTestManager struct {
	SessionManager

	mu           sync.Mutex
	current      sessiontypes.MultiSession
	rebuilt      sessiontypes.MultiSession
	terminateErr error
	refreshes    int
	terminated   []string
	rolledBack   bool
	tools        []mcpserver.ServerTool
}

func (m *credentialTestManager) GetMultiSession(string) (vmcpsession.MultiSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current, m.current != nil
}

func (m *credentialTestManager) RefreshSession(context.Context, string) (vmcpsession.MultiSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshes++
	m.current = m.rebuilt
	return m.rebuilt, nil
}

func (m *credentialTestManager) Terminate(sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.terminateErr != nil {
		return false, m.terminateErr
	}
	m.terminated = append(m.terminated, sessionID)
	m.current = nil
	return false, nil
}

func (m *credentialTestManager) ReplaceSession(
	_ context.Context, _ string, current, replacement vmcpsession.MultiSession,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current != m.rebuilt {
		return errors.New("unexpected rollback source")
	}
	m.rolledBack = true
	m.current = replacement
	return nil
}

func (m *credentialTestManager) GetAdaptedTools(string) ([]mcpserver.ServerTool, error) {
	return m.tools, nil
}

func (*credentialTestManager) GetAdaptedResources(string) ([]mcpserver.ServerResource, error) {
	return nil, nil
}

const (
	credentialTestSessionID = "credential-test-session"
	credentialTestSubject   = "user-1"
	// credentialTestBackend rejects stored credentials that have gone stale.
	credentialTestBackend = "stale-backend"
	// credentialTestForbidding rejected the credentials from the start.
	credentialTestForbidding = "forbids-user"
)

func newCredentialTestServer(
	t *testing.T, previous, rebuilt map[string]string, identity *auth.Identity,
) (*Server, *credentialTestManager, *hydrationTestSession) {
	t.Helper()

	mgr := &credentialTestManager{
		current: &credentialTestSession{metadata: previous, identity: identity},
		rebuilt: &credentialTestSession{metadata: rebuilt, identity: identity},
		tools:   []mcpserver.ServerTool{{Tool: mcp.NewTool("rebuilt-tool")}},
	}
	clientSession := &hydrationTestSession{
		sessionID: credentialTestSessionID,
		ch:        make(chan mcp.JSONRPCNotification, 4),
		tools:     map[string]mcpserver.ServerTool{"previous-tool": {Tool: mcp.NewTool("previous-tool")}},
	}
	srv := &Server{
		vmcpSessionMgr: mgr,
		mcpServer:      mcpserver.NewMCPServer("stale-credentials-test", "1.0.0"),
	}
	require.NoError(t, srv.mcpServer.RegisterSession(context.Background(), clientSession))
	srv.activeClientSessions.Store(credentialTestSessionID, clientSession)
	return srv, mgr, clientSession
}

func sdkSessionRegistered(srv *Server) bool {
	err := srv.mcpServer.SendNotificationToSpecificClient(credentialTestSessionID, "notifications/test", nil)
	return !errors.Is(err, mcpserver.ErrSessionNotFound)
}

func TestRefreshSessionCapabilities_EndsSessionOnStaleCredentials(t *testing.T) {
	t.Parallel()

	// A session restored from storage: its owner is known, its token is not.
	restored := &auth.Identity{PrincipalInfo: auth.PrincipalInfo{Subject: credentialTestSubject}}

	tests := []struct {
		name     string
		previous map[string]string
		rebuilt  map[string]string
		wantEnd  bool
	}{
		{
			name: "backend rejects credentials it accepted at creation",
			previous: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:            credentialTestSubject,
				vmcpsession.MetadataKeyBackendIDs:                 credentialTestBackend,
				vmcpsession.MetadataKeyCreationRejectedBackendIDs: credentialTestForbidding,
			},
			rebuilt: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:            credentialTestSubject,
				vmcpsession.MetadataKeyCreationRejectedBackendIDs: credentialTestForbidding,
				vmcpsession.MetadataKeyRejectedBackendIDs:         credentialTestForbidding + "," + credentialTestBackend,
			},
			wantEnd: true,
		},
		{
			name: "session created before the creation-time list existed",
			previous: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject,
			},
			rebuilt: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:    credentialTestSubject,
				vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestBackend,
			},
			wantEnd: true,
		},
		{
			name: "backend already rejected the credentials at creation",
			previous: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:            credentialTestSubject,
				vmcpsession.MetadataKeyCreationRejectedBackendIDs: credentialTestForbidding,
			},
			rebuilt: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:    credentialTestSubject,
				vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestForbidding,
			},
			wantEnd: false,
		},
		{
			name: "anonymous-mode session whose backend needs a token",
			previous: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:            "anonymous",
				vmcpsession.MetadataKeyCreationRejectedBackendIDs: credentialTestBackend,
			},
			rebuilt: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:    "anonymous",
				vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestBackend,
			},
			wantEnd: false,
		},
		{
			name:     "session without a subject",
			previous: map[string]string{},
			rebuilt:  map[string]string{vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestBackend},
			wantEnd:  false,
		},
		{
			name:     "rebuild without rejections",
			previous: map[string]string{vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject},
			rebuilt:  map[string]string{vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject},
			wantEnd:  false,
		},
		{
			name: "rebuild without rejections of a session that had some at creation",
			previous: map[string]string{
				vmcpsession.MetadataKeyIdentitySubject:            credentialTestSubject,
				vmcpsession.MetadataKeyCreationRejectedBackendIDs: credentialTestForbidding,
			},
			rebuilt: map[string]string{vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject},
			wantEnd: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv, mgr, clientSession := newCredentialTestServer(t, tt.previous, tt.rebuilt, restored)

			ended, err := srv.refreshSessionCapabilities(context.Background(), credentialTestSessionID, clientSession)
			require.NoError(t, err)
			assert.Equal(t, tt.wantEnd, ended)

			_, stillActive := srv.activeClientSessions.Load(credentialTestSessionID)
			if tt.wantEnd {
				assert.Equal(t, []string{credentialTestSessionID}, mgr.terminated)
				assert.False(t, stillActive, "an ended session must not stay registered for refreshes")
				assert.False(t, sdkSessionRegistered(srv), "an ended session must be unregistered from the SDK server")
				assert.Contains(t, clientSession.tools, "previous-tool", "an ended session must not get the rebuilt tools")
				return
			}
			assert.Empty(t, mgr.terminated)
			assert.True(t, stillActive)
			assert.True(t, sdkSessionRegistered(srv))
			assert.Contains(t, clientSession.tools, "rebuilt-tool")
		})
	}
}

func TestRefreshSessionCapabilities_RollsBackWhenEndingFails(t *testing.T) {
	t.Parallel()

	srv, mgr, clientSession := newCredentialTestServer(t,
		map[string]string{vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject},
		map[string]string{
			vmcpsession.MetadataKeyIdentitySubject:    credentialTestSubject,
			vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestBackend,
		},
		nil)
	mgr.terminateErr = errors.New("storage unavailable")

	ended, err := srv.refreshSessionCapabilities(context.Background(), credentialTestSessionID, clientSession)
	require.ErrorContains(t, err, "storage unavailable")
	assert.False(t, ended)
	assert.True(t, mgr.rolledBack, "the rebuilt session must be replaced by the previous one")
	_, stillActive := srv.activeClientSessions.Load(credentialTestSessionID)
	assert.True(t, stillActive, "a session that could not be ended stays registered and is retried")
	assert.Contains(t, clientSession.tools, "previous-tool")
}

func TestRunBackendRefresh_DoesNotRetryAnEndedSession(t *testing.T) {
	t.Parallel()

	srv, mgr, _ := newCredentialTestServer(t,
		map[string]string{
			vmcpsession.MetadataKeyIdentitySubject: credentialTestSubject,
			vmcpsession.MetadataKeyBackendIDs:      "kept-backend",
		},
		map[string]string{
			vmcpsession.MetadataKeyIdentitySubject:    credentialTestSubject,
			vmcpsession.MetadataKeyBackendIDs:         "kept-backend",
			vmcpsession.MetadataKeyRejectedBackendIDs: credentialTestBackend,
		},
		nil)

	srv.runBackendRefresh(credentialTestBackend, refreshSessionsLackingBackend)
	assert.Equal(t, 1, mgr.refreshes)
	assert.Equal(t, []string{credentialTestSessionID}, mgr.terminated)

	// The next reconcile pass finds nothing left to rebuild.
	srv.runBackendRefresh(credentialTestBackend, refreshSessionsLackingBackend)
	assert.Equal(t, 1, mgr.refreshes)
}

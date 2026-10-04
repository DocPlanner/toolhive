// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
	sessionmocks "github.com/stacklok/toolhive/pkg/vmcp/session/types/mocks"
)

const (
	deadOwnerURL = "http://10.1.2.7:4483/mcp"
	thisPodURL   = "http://10.9.9.9:4483/mcp"
)

type ownerClaimTestManager struct {
	*hydrationTestManager
	session     vmcpsession.MultiSession
	claimCtxErr error
	claimedKey  string
	claimedURL  string
}

func (m *ownerClaimTestManager) GetMultiSession(context.Context, string) (vmcpsession.MultiSession, bool) {
	return m.session, true
}

func (m *ownerClaimTestManager) SetSessionMetadataValue(
	ctx context.Context,
	_ string,
	_ vmcpsession.MultiSession,
	key string,
	value string,
) error {
	m.claimCtxErr = ctx.Err()
	m.claimedKey = key
	m.claimedURL = value
	return ctx.Err()
}

func TestOwnerForwardingMiddleware_ClaimsOwnershipAfterClientGaveUp(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	restored := sessionmocks.NewMockMultiSession(ctrl)
	restored.EXPECT().GetMetadata().Return(map[string]string{
		sessiontypes.MetadataKeyOwnerURL: deadOwnerURL,
	}).AnyTimes()

	manager := &ownerClaimTestManager{hydrationTestManager: &hydrationTestManager{}, session: restored}
	srv := &Server{
		sessionDataStorage: &forwardingTestStorage{
			metadata: map[string]map[string]string{
				"session-dead-owner": {
					sessiontypes.MetadataKeyOwnerURL: deadOwnerURL,
				},
			},
		},
		sessionOwnerURL: thisPodURL,
		vmcpSessionMgr:  manager,
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp 10.1.2.7:4483: i/o timeout")
			}),
		},
	}

	handler := srv.ownerForwardingMiddleware(srv.claimOrphanedSessionMiddleware(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil).WithContext(ctx)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-dead-owner")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	require.NoError(t, manager.claimCtxErr)
	assert.Equal(t, sessiontypes.MetadataKeyOwnerURL, manager.claimedKey)
	assert.Equal(t, thisPodURL, manager.claimedURL)
}

func TestNewOwnerForwardTransport_FailsFastWhenOwnerIsUnreachable(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: newOwnerForwardTransport()}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://192.0.2.1:4483/mcp", nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	require.Error(t, err)
	assert.Less(t, time.Since(start), ownerForwardDialTimeout+3*time.Second)
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessionfactorymocks "github.com/stacklok/toolhive/pkg/vmcp/session/mocks"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

const (
	takeoverTestLocalOwner = "http://10.9.9.9:4483/mcp"
	takeoverTestDeadOwner  = "http://10.1.2.7:4483/mcp"
)

type ownerMetadataSession struct {
	sessiontypes.MultiSession
	metadata map[string]string
}

func (s *ownerMetadataSession) GetMetadata() map[string]string {
	return s.metadata
}

type ownerTestManager struct {
	hydrationTestManager
	session      vmcpsession.MultiSession
	onGet        func()
	getCalls     int
	claimCalls   int
	claimCtxErr  error
	claimedOwner string
}

func (m *ownerTestManager) CreateSession(context.Context, string) (vmcpsession.MultiSession, error) {
	return m.session, nil
}

func (m *ownerTestManager) GetMultiSession(string) (vmcpsession.MultiSession, bool) {
	m.mu.Lock()
	m.getCalls++
	onGet := m.onGet
	m.mu.Unlock()
	if onGet != nil {
		onGet()
	}
	return m.session, m.session != nil
}

func (m *ownerTestManager) SetSessionMetadataValue(
	ctx context.Context,
	_ string,
	_ vmcpsession.MultiSession,
	key string,
	value string,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.claimCalls++
	m.claimCtxErr = ctx.Err()
	if key == sessiontypes.MetadataKeyOwnerURL {
		m.claimedOwner = value
	}
	return nil
}

func deadOwnerTransport() *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp 10.1.2.7:4483: connect: connection refused")
		}),
	}
}

func deadOwnerStorage(sessionID string) *forwardingTestStorage {
	return &forwardingTestStorage{
		metadata: map[string]map[string]string{
			sessionID: {sessiontypes.MetadataKeyOwnerURL: takeoverTestDeadOwner},
		},
	}
}

func TestOwnerForwarding_EarlyListOnNonOwnerIsForwardedToPlaceholderOwner(t *testing.T) {
	t.Parallel()

	const ownerURL = "http://10.1.2.3:4483/mcp"

	storage, err := transportsession.NewLocalSessionDataStorage(time.Minute)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storage.Close() })

	ctrl := gomock.NewController(t)
	ownerMgr, cleanup, err := sessionmanager.New(
		storage,
		&sessionmanager.FactoryConfig{
			Base:     sessionfactorymocks.NewMockMultiSessionFactory(ctrl),
			OwnerURL: ownerURL,
		},
		vmcp.NewImmutableRegistry(nil),
		nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup(context.Background()) })

	sessionID := ownerMgr.Generate()
	require.NotEmpty(t, sessionID)

	for _, body := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/list","params":{}}`,
	} {
		var forwardedTo string
		nonOwner := &Server{
			sessionDataStorage: storage,
			sessionOwnerURL:    takeoverTestLocalOwner,
			ownerForwardClient: &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					forwardedTo = req.URL.String()
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     http.Header{"Content-Type": []string{"application/json"}},
						Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":2,"result":{}}`)),
					}, nil
				}),
			},
		}

		nextCalled := false
		handler := nonOwner.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			nextCalled = true
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set(mcpserver.HeaderKeySessionID, sessionID)
		recorder := httptest.NewRecorder()

		handler.ServeHTTP(recorder, req)

		assert.False(t, nextCalled, body)
		assert.Equal(t, ownerURL, forwardedTo, body)
		assert.Equal(t, http.StatusOK, recorder.Code, body)
	}
}

func TestOwnerForwardingMiddleware_DeadOwnerDeleteAndGETSkipRestore(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodDelete, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			mgr := &ownerTestManager{
				session: &ownerMetadataSession{metadata: map[string]string{
					sessiontypes.MetadataKeyOwnerURL: takeoverTestDeadOwner,
				}},
			}
			srv := &Server{
				sessionDataStorage: deadOwnerStorage("session-dead"),
				sessionOwnerURL:    takeoverTestLocalOwner,
				ownerForwardClient: deadOwnerTransport(),
				vmcpSessionMgr:     mgr,
			}

			nextCalled := false
			handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/mcp", nil)
			req.Header.Set(mcpserver.HeaderKeySessionID, "session-dead")
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, req)

			assert.True(t, nextCalled)
			assert.Zero(t, mgr.getCalls)
			assert.Zero(t, mgr.claimCalls)
		})
	}
}

func TestOwnerForwardingMiddleware_DeleteForwardSurvivesCallerAbort(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var forwardedCtxErr error
	forwardedCalled := false
	srv := &Server{
		sessionDataStorage: &forwardingTestStorage{
			metadata: map[string]map[string]string{
				"session-delete-abort": {sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.8:4483/mcp"},
			},
		},
		sessionOwnerURL: takeoverTestLocalOwner,
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				cancel()
				forwardedCalled = true
				forwardedCtxErr = req.Context().Err()
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		},
		vmcpSessionMgr: &ownerTestManager{},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil).WithContext(ctx)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-delete-abort")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.True(t, forwardedCalled)
	require.NoError(t, forwardedCtxErr)
	assert.False(t, nextCalled)
}

func TestOwnerForwardingMiddleware_TerminatedRecordIsNotForwarded(t *testing.T) {
	t.Parallel()

	forwarded := false
	srv := &Server{
		sessionDataStorage: &forwardingTestStorage{
			metadata: map[string]map[string]string{
				"session-terminated": {
					sessiontypes.MetadataKeyOwnerURL:     takeoverTestDeadOwner,
					sessionmanager.MetadataKeyTerminated: sessionmanager.MetadataValTrue,
				},
			},
		},
		sessionOwnerURL: takeoverTestLocalOwner,
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				forwarded = true
				return nil, errors.New("unexpected forward")
			}),
		},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`),
	)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-terminated")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.False(t, forwarded)
	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestOwnerForwardingMiddleware_DeadOwnerClaimSurvivesCallerCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := &ownerTestManager{
		session: &ownerMetadataSession{metadata: map[string]string{
			sessiontypes.MetadataKeyOwnerURL: takeoverTestDeadOwner,
		}},
		onGet: cancel,
	}
	srv := &Server{
		sessionDataStorage: deadOwnerStorage("session-claim"),
		sessionOwnerURL:    takeoverTestLocalOwner,
		ownerForwardClient: deadOwnerTransport(),
		vmcpSessionMgr:     mgr,
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{}}}`),
	).WithContext(ctx)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-claim")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.True(t, nextCalled)
	assert.Equal(t, 1, mgr.getCalls)
	assert.Equal(t, 1, mgr.claimCalls)
	assert.NoError(t, mgr.claimCtxErr)
	assert.Equal(t, takeoverTestLocalOwner, mgr.claimedOwner)
}

func TestOwnerForwardingMiddleware_CallerAbortDoesNotTakeOver(t *testing.T) {
	t.Parallel()

	assertCallerAbortDoesNotTakeOver(
		t,
		http.MethodPost,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"slow","arguments":{}}}`,
		false,
	)
}

func assertCallerAbortDoesNotTakeOver(t *testing.T, method, body string, wantNext bool) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	mgr := &ownerTestManager{
		session: &ownerMetadataSession{metadata: map[string]string{
			sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.8:4483/mcp",
		}},
	}
	srv := &Server{
		sessionDataStorage: &forwardingTestStorage{
			metadata: map[string]map[string]string{
				"session-abort": {sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.8:4483/mcp"},
			},
		},
		sessionOwnerURL: takeoverTestLocalOwner,
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				cancel()
				return nil, req.Context().Err()
			}),
		},
		vmcpSessionMgr: mgr,
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(method, "/mcp", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-abort")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, wantNext, nextCalled)
	assert.Zero(t, mgr.getCalls)
	assert.Zero(t, mgr.claimCalls)
}

func TestNewOwnerForwardClient_BoundsDialTime(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://192.0.2.1:4483/mcp", nil)
	require.NoError(t, err)

	start := time.Now()
	resp, err := newOwnerForwardClient().Do(req)
	elapsed := time.Since(start)
	if resp != nil {
		_ = resp.Body.Close()
	}

	require.Error(t, err)
	assert.Less(t, elapsed, 6*time.Second)
}

func TestHandleSessionRegistrationImpl_OwnerMetadataWrite(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		metadata   map[string]string
		wantWrites int
	}{
		{
			name:       "skips write when placeholder owner was carried",
			metadata:   map[string]string{sessiontypes.MetadataKeyOwnerURL: takeoverTestLocalOwner},
			wantWrites: 0,
		},
		{
			name:       "writes owner when missing",
			metadata:   map[string]string{},
			wantWrites: 1,
		},
		{
			name:       "writes owner when a different owner is stored",
			metadata:   map[string]string{sessiontypes.MetadataKeyOwnerURL: takeoverTestDeadOwner},
			wantWrites: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mgr := &ownerTestManager{session: &ownerMetadataSession{metadata: tc.metadata}}
			srv := &Server{vmcpSessionMgr: mgr, sessionOwnerURL: takeoverTestLocalOwner}
			session := &registrationContextTestSession{
				sessionID: "session-register",
				ch:        make(chan mcp.JSONRPCNotification, 1),
			}

			require.NoError(t, srv.handleSessionRegistrationImpl(context.Background(), session))
			assert.Equal(t, tc.wantWrites, mgr.claimCalls)
		})
	}
}

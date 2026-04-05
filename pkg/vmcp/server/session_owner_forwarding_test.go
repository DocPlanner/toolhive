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

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

type forwardingTestStorage struct {
	metadata map[string]map[string]string
}

func (s *forwardingTestStorage) Upsert(context.Context, string, map[string]string) error {
	return nil
}

func (s *forwardingTestStorage) Load(_ context.Context, id string) (map[string]string, error) {
	metadata, ok := s.metadata[id]
	if !ok {
		return nil, transportsession.ErrSessionNotFound
	}
	cloned := make(map[string]string, len(metadata))
	for k, v := range metadata {
		cloned[k] = v
	}
	return cloned, nil
}

func (s *forwardingTestStorage) Create(context.Context, string, map[string]string) (bool, error) {
	return true, nil
}

func (s *forwardingTestStorage) Delete(context.Context, string) error {
	return nil
}

func (s *forwardingTestStorage) Close() error {
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestOwnerForwardingMiddleware_ForwardsSessionGETToOwner(t *testing.T) {
	t.Parallel()

	storage := &forwardingTestStorage{
		metadata: map[string]map[string]string{
			"session-get": {
				sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.3:4483/mcp",
			},
		},
	}

	var forwarded *http.Request
	srv := &Server{
		sessionDataStorage: storage,
		sessionOwnerURL:    "http://10.9.9.9:4483/mcp",
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				forwarded = req.Clone(req.Context())
				return &http.Response{
					StatusCode: http.StatusAccepted,
					Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
					Body:       io.NopCloser(strings.NewReader("data: ping\n\n")),
				}, nil
			}),
		},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-get")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	require.NotNil(t, forwarded)
	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusAccepted, recorder.Code)
	assert.Equal(t, "http://10.1.2.3:4483/mcp", forwarded.URL.String())
	assert.Equal(t, sessionOwnerForwardedValue, forwarded.Header.Get(sessionOwnerForwardedHeader))
	assert.Equal(t, "data: ping\n\n", recorder.Body.String())
}

func TestOwnerForwardingMiddleware_ForwardsMethodlessClientResponse(t *testing.T) {
	t.Parallel()

	storage := &forwardingTestStorage{
		metadata: map[string]map[string]string{
			"session-response": {
				sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.4:4483/mcp",
			},
		},
	}

	var forwardedBody string
	srv := &Server{
		sessionDataStorage: storage,
		sessionOwnerURL:    "http://10.9.9.9:4483/mcp",
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				forwardedBody = string(body)
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			}),
		},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`),
	)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-response")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.False(t, nextCalled)
	assert.Equal(t, http.StatusNoContent, recorder.Code)
	assert.JSONEq(t, `{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`, forwardedBody)
}

func TestOwnerForwardingMiddleware_FallsBackLocallyWhenOwnerUnavailable(t *testing.T) {
	t.Parallel()

	storage := &forwardingTestStorage{
		metadata: map[string]map[string]string{
			"session-dead-owner": {
				sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.7:4483/mcp",
			},
		},
	}

	srv := &Server{
		sessionDataStorage: storage,
		sessionOwnerURL:    "http://10.9.9.9:4483/mcp",
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("dial tcp 10.1.2.7: connect: connection refused")
			}),
		},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-dead-owner")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.True(t, nextCalled)
	assert.Equal(t, http.StatusAccepted, recorder.Code)
}

func TestOwnerForwardingMiddleware_SkipsRequestsOwnedLocally(t *testing.T) {
	t.Parallel()

	storage := &forwardingTestStorage{
		metadata: map[string]map[string]string{
			"session-local": {
				sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.5:4483/mcp",
			},
		},
	}

	forwarded := false
	srv := &Server{
		sessionDataStorage: storage,
		sessionOwnerURL:    "http://10.9.9.9:4483/mcp",
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				forwarded = true
				return nil, nil
			}),
		},
	}
	srv.activeClientSessions.Store("session-local", &hydrationTestSession{sessionID: "session-local"})

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-local")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.True(t, nextCalled)
	assert.False(t, forwarded)
	assert.Equal(t, http.StatusCreated, recorder.Code)
}

func TestOwnerForwardingMiddleware_DoesNotForwardRegularToolRequests(t *testing.T) {
	t.Parallel()

	storage := &forwardingTestStorage{
		metadata: map[string]map[string]string{
			"session-tools": {
				sessiontypes.MetadataKeyOwnerURL: "http://10.1.2.6:4483/mcp",
			},
		},
	}

	forwarded := false
	srv := &Server{
		sessionDataStorage: storage,
		sessionOwnerURL:    "http://10.9.9.9:4483/mcp",
		ownerForwardClient: &http.Client{
			Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				forwarded = true
				return nil, nil
			}),
		},
	}

	nextCalled := false
	handler := srv.ownerForwardingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(
		http.MethodPost,
		"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`),
	)
	req.Header.Set(mcpserver.HeaderKeySessionID, "session-tools")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.True(t, nextCalled)
	assert.False(t, forwarded)
	assert.Equal(t, http.StatusOK, recorder.Code)
}

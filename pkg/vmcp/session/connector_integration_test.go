// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	mcpmcp "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpauth "github.com/stacklok/toolhive/pkg/vmcp/auth"
	"github.com/stacklok/toolhive/pkg/vmcp/auth/strategies"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
	internalbk "github.com/stacklok/toolhive/pkg/vmcp/session/internal/backend"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
)

// startInProcessMCPServer creates a real in-process MCP server over
// streamable-HTTP and returns its base URL. The server is shut down when the
// test ends via t.Cleanup.
//
// The server exposes:
//   - tool "echo": returns the "input" argument as text content
//   - resource "test://data": returns the static text "hello"
//   - prompt "greet": returns a greeting message
func startInProcessMCPServer(t *testing.T) string {
	t.Helper()

	mcpSrv := mcpserver.NewMCPServer("integration-test-backend", "1.0.0")

	mcpSrv.AddTool(
		mcpmcp.NewTool("echo",
			mcpmcp.WithDescription("Echoes the input back"),
			mcpmcp.WithString("input", mcpmcp.Required()),
		),
		func(_ context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
			args, _ := req.Params.Arguments.(map[string]any)
			input, _ := args["input"].(string)
			return &mcpmcp.CallToolResult{
				Content: []mcpmcp.Content{mcpmcp.NewTextContent(input)},
			}, nil
		},
	)

	mcpSrv.AddResource(
		mcpmcp.Resource{
			URI:      "test://data",
			Name:     "Test Data",
			MIMEType: "text/plain",
		},
		func(_ context.Context, _ mcpmcp.ReadResourceRequest) ([]mcpmcp.ResourceContents, error) {
			return []mcpmcp.ResourceContents{
				mcpmcp.TextResourceContents{URI: "test://data", MIMEType: "text/plain", Text: "hello"},
			}, nil
		},
	)

	mcpSrv.AddPrompt(
		mcpmcp.NewPrompt("greet",
			mcpmcp.WithPromptDescription("Returns a greeting"),
		),
		func(_ context.Context, _ mcpmcp.GetPromptRequest) (*mcpmcp.GetPromptResult, error) {
			return &mcpmcp.GetPromptResult{
				Messages: []mcpmcp.PromptMessage{
					{Role: "user", Content: mcpmcp.NewTextContent("Hello!")},
				},
			}, nil
		},
	)

	streamableSrv := mcpserver.NewStreamableHTTPServer(mcpSrv)
	mux := http.NewServeMux()
	mux.Handle("/mcp", streamableSrv)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts.URL + "/mcp"
}

func startSlowInProcessMCPServer(t *testing.T, delay time.Duration) string {
	t.Helper()

	mcpSrv := mcpserver.NewMCPServer("slow-integration-test-backend", "1.0.0")
	mcpSrv.AddTool(
		mcpmcp.NewTool("slow_echo"),
		func(ctx context.Context, _ mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
			select {
			case <-time.After(delay):
				return &mcpmcp.CallToolResult{
					Content: []mcpmcp.Content{mcpmcp.NewTextContent("done")},
				}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	)

	streamableSrv := mcpserver.NewStreamableHTTPServer(mcpSrv)
	mux := http.NewServeMux()
	mux.Handle("/mcp", streamableSrv)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp"
}

// startSessionFailureMCPServer injects one HTTP failure before a tool reaches
// the MCP server. It records Initialize handshakes and successful executions so
// tests can distinguish safe session recovery from unsafe generic retries.
func startSessionFailureMCPServer(t *testing.T, failureStatus int) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	return startSessionFailureMCPServerWithResponse(t, func(w http.ResponseWriter, _ []byte) {
		http.Error(w, http.StatusText(failureStatus), failureStatus)
	})
}

// startSessionFailureMCPServerWithResponse starts a streamable-HTTP MCP server
// whose first tools/call is answered by failFirst instead of being executed.
// failFirst receives the raw JSON-RPC request body so it can echo the request ID.
func startSessionFailureMCPServerWithResponse(
	t *testing.T,
	failFirst func(w http.ResponseWriter, body []byte),
) (string, *atomic.Int32, *atomic.Int32) {
	t.Helper()

	var initializeCount atomic.Int32
	var executionCount atomic.Int32
	var failNext atomic.Bool
	failNext.Store(true)

	mcpSrv := mcpserver.NewMCPServer("session-failure-backend", "1.0.0")
	mcpSrv.AddTool(
		mcpmcp.NewTool("echo", mcpmcp.WithString("input", mcpmcp.Required())),
		func(_ context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
			executionCount.Add(1)
			args, _ := req.Params.Arguments.(map[string]any)
			input, _ := args["input"].(string)
			return &mcpmcp.CallToolResult{
				Content: []mcpmcp.Content{mcpmcp.NewTextContent(input)},
			}, nil
		},
	)

	streamableSrv := mcpserver.NewStreamableHTTPServer(mcpSrv)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var request struct {
			Method string `json:"method"`
		}
		if err := json.Unmarshal(body, &request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if request.Method == string(mcpmcp.MethodInitialize) {
			initializeCount.Add(1)
		}
		if request.Method == "tools/call" && failNext.CompareAndSwap(true, false) {
			failFirst(w, body)
			return
		}
		streamableSrv.ServeHTTP(w, r)
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", handler)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts.URL + "/mcp", &initializeCount, &executionCount
}

// newUnauthenticatedRegistry returns a minimal OutgoingAuthRegistry that
// uses the unauthenticated (no-op) strategy — suitable for tests where the
// backend MCP server does not require auth.
func newUnauthenticatedRegistry(t *testing.T) vmcpauth.OutgoingAuthRegistry {
	t.Helper()
	reg := vmcpauth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, reg.RegisterStrategy(authtypes.StrategyTypeUnauthenticated, strategies.NewUnauthenticatedStrategy()))
	return reg
}

// ---------------------------------------------------------------------------
// Integration tests — exercise the real HTTP connector
// ---------------------------------------------------------------------------

func TestSessionFactory_Integration_CapabilityDiscovery(t *testing.T) {
	t.Parallel()

	baseURL := startInProcessMCPServer(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	require.NotNil(t, sess)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	// The real MCP Initialize + ListTools/Resources/Prompts handshake must
	// have discovered all three capabilities.
	require.Len(t, sess.Tools(), 1)
	assert.Equal(t, "echo", sess.Tools()[0].Name)

	require.Len(t, sess.Resources(), 1)
	assert.Equal(t, "test://data", sess.Resources()[0].URI)

	require.Len(t, sess.Prompts(), 1)
	assert.Equal(t, "greet", sess.Prompts()[0].Name)
}

func TestSessionFactory_Integration_CallTool(t *testing.T) {
	t.Parallel()

	baseURL := startInProcessMCPServer(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.CallTool(context.Background(), nil, "echo", map[string]any{"input": "hello world"}, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Content, 1)
	assert.Equal(t, "hello world", result.Content[0].Text)
}

func TestSessionFactory_Integration_PerWorkloadRequestTimeout(t *testing.T) {
	t.Parallel()

	baseURL := startSlowInProcessMCPServer(t, 100*time.Millisecond)
	backend := &vmcp.Backend{
		ID:            "slow-backend",
		Name:          "slow-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(
		newUnauthenticatedRegistry(t),
		WithBackendRequestTimeouts(25*time.Millisecond, map[string]time.Duration{
			"slow-backend": 250 * time.Millisecond,
		}),
	)
	sess, err := factory.MakeSessionWithID(
		context.Background(),
		uuid.New().String(),
		nil,
		[]*vmcp.Backend{backend},
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.CallTool(context.Background(), nil, "slow_echo", nil, nil)
	require.NoError(t, err)
	require.Len(t, result.Content, 1)
	assert.Equal(t, "done", result.Content[0].Text)
}

func TestSessionFactory_Integration_ReconnectsExpiredBackendSession(t *testing.T) {
	t.Parallel()

	baseURL, initializeCount, executionCount := startSessionFailureMCPServer(t, http.StatusNotFound)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.CallTool(context.Background(), nil, "echo", map[string]any{"input": "recovered"}, nil)
	require.NoError(t, err)
	require.Len(t, result.Content, 1)
	assert.Equal(t, "recovered", result.Content[0].Text)
	assert.EqualValues(t, 2, initializeCount.Load(), "expired session must be reinitialized once")
	assert.EqualValues(t, 1, executionCount.Load(), "the rejected request must execute exactly once after recovery")
}

// TypeScript SDK servers answer a request that lost its Mcp-Session-Id with an
// HTTP 400 and this exact body; the vMCP client must treat it like a 404.
func TestSessionFactory_Integration_ReconnectsOnSessionlessBadRequest(t *testing.T) {
	t.Parallel()

	baseURL, initializeCount, executionCount := startSessionFailureMCPServerWithResponse(t,
		func(w http.ResponseWriter, _ []byte) {
			http.Error(w, "Bad Request: Not an initialization request and no valid session ID provided.", http.StatusBadRequest)
		})
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.CallTool(context.Background(), nil, "echo", map[string]any{"input": "recovered"}, nil)
	require.NoError(t, err)
	require.Len(t, result.Content, 1)
	assert.Equal(t, "recovered", result.Content[0].Text)
	assert.EqualValues(t, 2, initializeCount.Load(), "sessionless rejection must trigger one reinitialization")
	assert.EqualValues(t, 1, executionCount.Load(), "the rejected request must execute exactly once after recovery")
}

// go-sdk servers open a fresh session for a sessionless request and reject the
// method with a JSON-RPC error; the vMCP client must recover from that as well.
func TestSessionFactory_Integration_ReconnectsOnInvalidDuringInitializationError(t *testing.T) {
	t.Parallel()

	baseURL, initializeCount, executionCount := startSessionFailureMCPServerWithResponse(t,
		func(w http.ResponseWriter, body []byte) {
			var req struct {
				ID json.RawMessage `json:"id"`
			}
			require.NoError(t, json.Unmarshal(body, &req))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w,
				`{"jsonrpc":"2.0","id":%s,"error":{"code":-32600,"message":"method \"tools/call\" is invalid during session initialization"}}`,
				req.ID)
		})
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.CallTool(context.Background(), nil, "echo", map[string]any{"input": "recovered"}, nil)
	require.NoError(t, err)
	require.Len(t, result.Content, 1)
	assert.Equal(t, "recovered", result.Content[0].Text)
	assert.EqualValues(t, 2, initializeCount.Load(), "initialization-state rejection must trigger one reinitialization")
	assert.EqualValues(t, 1, executionCount.Load(), "the rejected request must execute exactly once after recovery")
}

func TestSessionFactory_Integration_DoesNotRetryAmbiguousBackendFailure(t *testing.T) {
	t.Parallel()

	baseURL, initializeCount, executionCount := startSessionFailureMCPServer(t, http.StatusInternalServerError)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	_, err = sess.CallTool(context.Background(), nil, "echo", map[string]any{"input": "do not retry"}, nil)
	require.Error(t, err)
	assert.EqualValues(t, 1, initializeCount.Load(), "ambiguous failures must not reconnect")
	assert.EqualValues(t, 0, executionCount.Load(), "ambiguous failures must not retry the operation")
}

func TestSessionFactory_Integration_ReadResource(t *testing.T) {
	t.Parallel()

	baseURL := startInProcessMCPServer(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.ReadResource(context.Background(), nil, "test://data")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.Contents)
	assert.Equal(t, "hello", result.Contents[0].Text)
}

func TestSessionFactory_Integration_GetPrompt(t *testing.T) {
	t.Parallel()

	baseURL := startInProcessMCPServer(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	result, err := sess.GetPrompt(context.Background(), nil, "greet", nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Messages preserve individual roles and content structure
	require.Len(t, result.Messages, 1)
	assert.Equal(t, "user", result.Messages[0].Role)
	assert.Equal(t, vmcp.ContentTypeText, result.Messages[0].Content.Type)
	assert.Equal(t, "Hello!", result.Messages[0].Content.Text)
}

func TestSessionFactory_Integration_MultipleBackends(t *testing.T) {
	t.Parallel()

	// Start two independent backends — each has its own "echo" tool.
	// The factory must route each call to the correct backend after resolving
	// the capability-name conflict (alphabetically-earlier backend wins).
	url1 := startInProcessMCPServer(t)
	url2 := startInProcessMCPServer(t)

	backends := []*vmcp.Backend{
		{ID: "backend-b", Name: "backend-b", BaseURL: url2, TransportType: "streamable-http"},
		{ID: "backend-a", Name: "backend-a", BaseURL: url1, TransportType: "streamable-http"},
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, backends)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	// Both backends expose "echo"; "backend-a" sorts first and must win.
	require.Len(t, sess.Tools(), 1, "conflicting tool names collapse to one")
	assert.Equal(t, "backend-a", sess.Tools()[0].BackendID)
}

// ---------------------------------------------------------------------------
// Identity-binding integration tests — CallerRejection for ReadResource / GetPrompt
// ---------------------------------------------------------------------------

// TestTokenBinding_CallerRejection verifies that the hijack-prevention decorator
// is applied to all three protected methods (CallTool, ReadResource, GetPrompt):
// each rejects a wrong caller (ErrUnauthorizedCaller) and a nil caller
// (ErrNilCaller) before any backend routing occurs.
//
// The identity binding is derived from Claims["iss"] and Claims["sub"] per the
// new #5306 model (no HMAC secret required).
func TestIdentityBinding_CallerRejection(t *testing.T) {
	t.Parallel()

	// Both alice and bob need valid Claims so the binding decorator can extract
	// their (iss, sub) pairs. alice creates the session; bob is the wrong caller.
	alice := &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{
			Subject: "alice",
			Claims: map[string]any{
				"iss": "https://idp.example",
				"sub": "alice",
			},
		},
	}
	wrongCaller := &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{
			Subject: "bob",
			Claims: map[string]any{
				"iss": "https://idp.example",
				"sub": "bob",
			},
		},
	}

	// No backend connector needed: auth validation fires before any routing.
	connector := func(_ context.Context, _ *vmcp.BackendTarget, _ *auth.Identity, _ string) (internalbk.Session, *vmcp.CapabilityList, error) {
		return nil, nil, nil
	}
	factory := newSessionFactoryWithConnector(connector)
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), alice, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })

	callFns := []struct {
		name string
		call func(caller *auth.Identity) error
	}{
		{"CallTool", func(caller *auth.Identity) error {
			_, err := sess.CallTool(context.Background(), caller, "echo", map[string]any{"input": "test"}, nil)
			return err
		}},
		{"ReadResource", func(caller *auth.Identity) error {
			_, err := sess.ReadResource(context.Background(), caller, "test://data")
			return err
		}},
		{"GetPrompt", func(caller *auth.Identity) error {
			_, err := sess.GetPrompt(context.Background(), caller, "greet", nil)
			return err
		}},
	}

	for _, fn := range callFns {
		t.Run(fn.name+"/wrong caller", func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, fn.call(wrongCaller), sessiontypes.ErrUnauthorizedCaller)
		})
		t.Run(fn.name+"/nil caller", func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, fn.call(nil), sessiontypes.ErrNilCaller)
		})
	}
}

// TestTokenBinding_ReadResource_And_GetPrompt_WithRealBackend verifies that a
// bound session accepts ReadResource and GetPrompt calls from the correct caller
// when a real backend is connected.
func TestIdentityBinding_ReadResource_And_GetPrompt_WithRealBackend(t *testing.T) {
	t.Parallel()

	baseURL := startInProcessMCPServer(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	// Identity with Claims so binding.Format(iss, sub) succeeds and the session
	// is bound to the caller identity.
	identity := &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{
			Subject: "alice",
			Claims: map[string]any{
				"iss": "https://idp.example",
				"sub": "alice",
			},
		},
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), identity, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sess.Close()) })

	t.Run("allows ReadResource with correct caller", func(t *testing.T) {
		t.Parallel()
		result, err := sess.ReadResource(context.Background(), identity, "test://data")
		require.NoError(t, err)
		require.NotNil(t, result)
		require.NotEmpty(t, result.Contents)
		assert.Equal(t, "hello", result.Contents[0].Text)
	})

	t.Run("allows GetPrompt with correct caller", func(t *testing.T) {
		t.Parallel()
		result, err := sess.GetPrompt(context.Background(), identity, "greet", nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Messages, 1)
		assert.Equal(t, "user", result.Messages[0].Role)
		assert.Equal(t, "Hello!", result.Messages[0].Content.Text)
	})
}

// TestTokenBinding_RestoreSession_RoundTrip verifies the full
// store-then-restore flow across a real factory-created session:
//
//  1. Create a session via the factory (writes MetadataKeyIdentityBinding to metadata).
//  2. Extract the persisted binding.
//  3. Restore the session via RestoreSession using the persisted metadata.
//  4. Confirm the restored decorator accepts the original caller and rejects others.
func TestIdentityBinding_RestoreSession_RoundTrip(t *testing.T) {
	t.Parallel()

	identity := &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{
			Subject: "alice",
			Claims: map[string]any{
				"iss": "https://idp.example",
				"sub": "alice",
			},
		},
	}

	connector := func(_ context.Context, _ *vmcp.BackendTarget, _ *auth.Identity, _ string) (internalbk.Session, *vmcp.CapabilityList, error) {
		return nil, nil, nil
	}
	factory := newSessionFactoryWithConnector(connector)
	sess, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), identity, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })

	// Extract persisted values — these simulate what would be read back from Redis.
	meta := sess.GetMetadata()
	storedBinding := meta[MetadataKeyIdentityBinding]
	require.NotEmpty(t, storedBinding, "factory must write MetadataKeyIdentityBinding to metadata")

	// Simulate "Pod B": restore the session from persisted metadata.
	restored, err := factory.RestoreSession(context.Background(), uuid.New().String(), meta, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	ctx := context.Background()

	// Original caller is accepted.
	_, err = restored.CallTool(ctx, identity, "any-tool", nil, nil)
	// ErrToolNotFound is expected (no backends), not an auth error.
	require.NotErrorIs(t, err, sessiontypes.ErrUnauthorizedCaller)
	require.NotErrorIs(t, err, sessiontypes.ErrNilCaller)

	// A different caller is rejected at the auth layer.
	wrongCaller := &auth.Identity{
		PrincipalInfo: auth.PrincipalInfo{
			Subject: "eve",
			Claims: map[string]any{
				"iss": "https://idp.example",
				"sub": "eve",
			},
		},
	}
	_, err = restored.CallTool(ctx, wrongCaller, "any-tool", nil, nil)
	require.ErrorIs(t, err, sessiontypes.ErrUnauthorizedCaller)

	// Nil caller is rejected at the auth layer.
	_, err = restored.CallTool(ctx, nil, "any-tool", nil, nil)
	require.ErrorIs(t, err, sessiontypes.ErrNilCaller)
}

// startInProcessMCPServerWithHeaderCapture starts an in-process MCP server and
// returns the base URL along with a function that returns all Mcp-Session-Id
// header values received by the server from clients.
func startInProcessMCPServerWithHeaderCapture(t *testing.T) (string, func() []string) {
	t.Helper()

	mcpSrv := mcpserver.NewMCPServer("integration-test-backend", "1.0.0")
	mcpSrv.AddTool(
		mcpmcp.NewTool("echo", mcpmcp.WithDescription("echo"), mcpmcp.WithString("input", mcpmcp.Required())),
		func(_ context.Context, req mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error) {
			args, _ := req.Params.Arguments.(map[string]any)
			input, _ := args["input"].(string)
			return &mcpmcp.CallToolResult{Content: []mcpmcp.Content{mcpmcp.NewTextContent(input)}}, nil
		},
	)

	streamableSrv := mcpserver.NewStreamableHTTPServer(mcpSrv)

	var mu sync.Mutex
	var capturedIDs []string

	mux := http.NewServeMux()
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get("Mcp-Session-Id"); id != "" {
			mu.Lock()
			capturedIDs = append(capturedIDs, id)
			mu.Unlock()
		}
		streamableSrv.ServeHTTP(w, r)
	}))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts.URL + "/mcp", func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(capturedIDs))
		copy(out, capturedIDs)
		return out
	}
}

// TestSessionFactory_Integration_RestoreSession_SendsStoredSessionHintToBackend
// verifies that RestoreSession passes the stored backend session ID as the
// Mcp-Session-Id hint in the Initialize request so the backend can resume
// rather than create a new session.
func TestSessionFactory_Integration_RestoreSession_SendsStoredSessionHintToBackend(t *testing.T) {
	t.Parallel()

	baseURL, capturedIDs := startInProcessMCPServerWithHeaderCapture(t)
	backend := &vmcp.Backend{
		ID:            "integration-backend",
		Name:          "integration-backend",
		BaseURL:       baseURL,
		TransportType: "streamable-http",
	}

	factory := NewSessionFactory(newUnauthenticatedRegistry(t))

	// Create the original session — the backend assigns a session ID over
	// streamable-HTTP and we store it in metadata.
	orig, err := factory.MakeSessionWithID(context.Background(), uuid.New().String(), nil, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { _ = orig.Close() })

	storedMeta := orig.GetMetadata()
	storedBackendSessionID := storedMeta[MetadataKeyBackendSessionPrefix+"integration-backend"]
	require.NotEmpty(t, storedBackendSessionID, "streamable-HTTP backend must assign a session ID on Initialize")

	// RestoreSession: the factory must send the stored session ID as Mcp-Session-Id.
	restored, err := factory.RestoreSession(context.Background(), uuid.New().String(), storedMeta, []*vmcp.Backend{backend})
	require.NoError(t, err)
	t.Cleanup(func() { _ = restored.Close() })

	// The server must have received the stored ID as a hint in the Initialize request.
	assert.Contains(t, capturedIDs(), storedBackendSessionID,
		"RestoreSession must send the stored backend session ID as Mcp-Session-Id hint")
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive/pkg/auth"
	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpauth "github.com/stacklok/toolhive/pkg/vmcp/auth"
	"github.com/stacklok/toolhive/pkg/vmcp/auth/strategies"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
)

// These tests model two vMCP replicas ("pods") that share one session store, as two
// pods share Redis in production. A session is initialized on pod A by alice. A later
// request with the same Mcp-Session-Id lands on pod B, which has never seen the
// session in memory.
//
// The question under test: does a GET (the Streamable HTTP SSE listen stream) on
// pod B re-run phase-2 session creation (OnRegisterSession -> CreateSession) and
// overwrite the identity binding in the shared store? POST tools/call is the control:
// it lazily restores the session from the store and enforces the stored binding.
//
// The shared store is one in-process DataStorage instance (the interface the Redis
// store implements), and requests go straight to Handler.ServeHTTP, so the test needs
// no network listeners.

const (
	crossPodUserHeader = "X-Test-User"
	crossPodIssuer     = "https://idp.example"
)

// countingFactory wraps a MultiSessionFactory and counts phase-2 creations
// (MakeSessionWithID) and cross-pod restores (RestoreSession).
type countingFactory struct {
	base     vmcpsession.MultiSessionFactory
	makes    atomic.Int32
	restores atomic.Int32
}

func (f *countingFactory) MakeSessionWithID(
	ctx context.Context, id string, identity *auth.Identity, backends []*vmcp.Backend,
) (vmcpsession.MultiSession, error) {
	f.makes.Add(1)
	return f.base.MakeSessionWithID(ctx, id, identity, backends)
}

func (f *countingFactory) RestoreSession(
	ctx context.Context, id string, storedMetadata map[string]string, allBackends []*vmcp.Backend,
) (vmcpsession.MultiSession, error) {
	f.restores.Add(1)
	return f.base.RestoreSession(ctx, id, storedMetadata, allBackends)
}

// headerIdentityMiddleware stands in for the real auth middleware: it puts an
// authenticated identity (iss + sub claims, the binding source) into the request
// context, taken from the X-Test-User header.
func headerIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user := r.Header.Get(crossPodUserHeader); user != "" {
			id := &auth.Identity{PrincipalInfo: auth.PrincipalInfo{
				Subject: user,
				Claims:  map[string]any{"iss": crossPodIssuer, "sub": user},
			}}
			r = r.WithContext(auth.WithIdentity(r.Context(), id))
		}
		next.ServeHTTP(w, r)
	})
}

type crossPod struct {
	handler http.Handler
	factory *countingFactory
}

// startCrossPod builds one Serve-path vMCP replica whose vMCP session manager uses
// the shared store, and returns the full shared Handler (auth middleware included).
func startCrossPod(t *testing.T, shared transportsession.DataStorage) *crossPod {
	t.Helper()
	authReg := vmcpauth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, authReg.RegisterStrategy(authtypes.StrategyTypeUnauthenticated, strategies.NewUnauthenticatedStrategy()))
	factory := &countingFactory{base: vmcpsession.NewSessionFactory(authReg)}
	registry := vmcp.NewImmutableRegistry([]vmcp.Backend{})
	fc := &fakeCore{tools: []vmcp.Tool{{Name: "echo", Description: "echo"}}}

	srv, err := Serve(context.Background(), fc, &ServerConfig{
		SessionTTL:           time.Hour,
		SessionManagerConfig: &sessionmanager.FactoryConfig{Base: factory},
		BackendRegistry:      registry,
		AuthMiddleware:       headerIdentityMiddleware,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop(context.Background()) })

	// Replace the per-process session manager and session data storage with ones on
	// the shared store, as Serve wires both on the same store in production. The SDK
	// hooks read srv.vmcpSessionMgr and srv.sessionDataStorage at call time, and
	// Handler (built below) passes the manager to mcp-go as the SessionIdManager, so
	// every path uses the shared store. Closing the shared store twice (here via
	// srv.Stop and in the test) is safe.
	mgr, cleanup, err := sessionmanager.New(shared, &sessionmanager.FactoryConfig{Base: factory}, registry)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cleanup(context.Background()) })
	srv.vmcpSessionMgr = mgr
	_ = srv.sessionDataStorage.Close()
	srv.sessionDataStorage = shared

	handler, err := srv.Handler(context.Background())
	require.NoError(t, err)
	return &crossPod{handler: handler, factory: factory}
}

// storedBinding reads the identity binding for sessionID straight from the shared store.
func storedBinding(t *testing.T, shared transportsession.DataStorage, sessionID string) string {
	t.Helper()
	meta, err := shared.Load(context.Background(), sessionID)
	require.NoError(t, err)
	return meta[vmcpsession.MetadataKeyIdentityBinding]
}

func newCrossPodRequest(ctx context.Context, method, user, sessionID, body string) *http.Request {
	req := httptest.NewRequestWithContext(ctx, method, "/mcp", strings.NewReader(body))
	req.Header.Set("Accept", "application/json, text/event-stream")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.Header.Set(crossPodUserHeader, user)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	return req
}

// initSession runs initialize on pod as user and waits until phase-2 has bound it.
func initSession(t *testing.T, shared transportsession.DataStorage, pod *crossPod, user string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	pod.handler.ServeHTTP(rec, newCrossPodRequest(context.Background(), http.MethodPost, user, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",`+
			`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	sessionID := rec.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)
	require.Eventually(t, func() bool { return storedBinding(t, shared, sessionID) != "" },
		2*time.Second, 10*time.Millisecond, "phase-2 must write the identity binding")
	return sessionID
}

// sseWriter is a goroutine-safe streaming ResponseWriter. It signals headerWritten
// on the first WriteHeader so the test can wait for the SSE stream to open.
type sseWriter struct {
	mu            sync.Mutex
	header        http.Header
	code          int
	once          sync.Once
	headerWritten chan struct{}
}

func newSSEWriter() *sseWriter {
	return &sseWriter{header: http.Header{}, headerWritten: make(chan struct{})}
}

func (w *sseWriter) Header() http.Header { return w.header }

func (w *sseWriter) WriteHeader(code int) {
	w.mu.Lock()
	if w.code == 0 {
		w.code = code
	}
	w.mu.Unlock()
	w.once.Do(func() { close(w.headerWritten) })
}

func (w *sseWriter) Write(b []byte) (int, error) {
	w.WriteHeader(http.StatusOK)
	return len(b), nil
}

func (*sseWriter) Flush() {}

func (w *sseWriter) status() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.code
}

// openSSE opens the GET listen stream on pod and returns the status code once the
// response headers are written. mcp-go runs RegisterSession (and so the
// OnRegisterSession hook) synchronously before it writes the SSE headers, so the
// hook has finished when this returns. The stream is closed before returning.
func openSSE(t *testing.T, pod *crossPod, user, sessionID string) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := newSSEWriter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pod.handler.ServeHTTP(w, newCrossPodRequest(ctx, http.MethodGet, user, sessionID, ""))
	}()
	select {
	case <-w.headerWritten:
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GET did not write response headers")
	}
	cancel()
	<-done
	return w.status()
}

func callEcho(t *testing.T, pod *crossPod, user, sessionID string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	pod.handler.ServeHTTP(rec, newCrossPodRequest(context.Background(), http.MethodPost, user, sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	return rec.Body.String()
}

// TestCrossPodSessionRebind asserts the SECURE expectation for each case. A case
// that fails demonstrates the bug on the code under test. On the fork the GET cases
// pass because of attachToBoundSession; upstream stops the re-bind only from
// v0.40.0 (#5729). Once the fork is on v0.40 or later, drop the guard if this test
// still passes without it.
func TestCrossPodSessionRebind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		caller string // identity on pod B
		viaGET bool   // GET listen stream (true) or POST tools/call (false) on pod B
	}{
		{name: "GET on pod B, same identity", caller: "alice", viaGET: true},
		{name: "GET on pod B, different identity", caller: "eve", viaGET: true},
		{name: "POST tools/call on pod B, same identity", caller: "alice", viaGET: false},
		{name: "POST tools/call on pod B, different identity", caller: "eve", viaGET: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shared, err := transportsession.NewLocalSessionDataStorage(time.Hour)
			require.NoError(t, err)
			t.Cleanup(func() { _ = shared.Close() })
			podA := startCrossPod(t, shared)
			podB := startCrossPod(t, shared)

			sessionID := initSession(t, shared, podA, "alice")
			aliceBinding := storedBinding(t, shared, sessionID)
			require.Equal(t, int32(1), podA.factory.makes.Load())

			if tc.viaGET {
				status := openSSE(t, podB, tc.caller, sessionID)
				t.Logf("GET on pod B as %s -> HTTP %d; pod B MakeSessionWithID=%d RestoreSession=%d; "+
					"binding before=%q after=%q", tc.caller, status, podB.factory.makes.Load(),
					podB.factory.restores.Load(), aliceBinding, storedBinding(t, shared, sessionID))

				// A GET for an existing session must not run phase-2 creation again.
				assert.Equal(t, int32(0), podB.factory.makes.Load(),
					"GET on pod B must not call CreateSession/MakeSessionWithID for an existing session")
				// The stored binding must still be alice's.
				assert.Equal(t, aliceBinding, storedBinding(t, shared, sessionID),
					"GET on pod B must not overwrite the identity binding in the shared store")

				if tc.caller != "alice" {
					// After eve's GET, alice must still own her session on pod B. This is
					// checked first: a rejected call terminates the session (fail-closed
					// terminateOnBindingFailure), which is intended and not under test.
					body := callEcho(t, podB, "alice", sessionID)
					t.Logf("alice tools/call on pod B after eve's GET -> %s", body)
					assert.Contains(t, body, `"ok"`, "alice must keep her session after eve's GET")
					// And eve must not be able to use alice's session.
					body = callEcho(t, podB, "eve", sessionID)
					t.Logf("eve tools/call on pod B after GET -> %s", body)
					assert.Contains(t, body, "Unauthorized",
						"eve must not be able to call tools on alice's session after a GET")
				}
				return
			}

			body := callEcho(t, podB, tc.caller, sessionID)
			t.Logf("tools/call on pod B as %s -> %s; pod B MakeSessionWithID=%d RestoreSession=%d",
				tc.caller, body, podB.factory.makes.Load(), podB.factory.restores.Load())
			assert.Equal(t, int32(0), podB.factory.makes.Load(),
				"POST on pod B must restore the session, not create it again")
			if tc.caller == "alice" {
				assert.Contains(t, body, `"ok"`, "the owner must be able to call tools on pod B")
				assert.Equal(t, aliceBinding, storedBinding(t, shared, sessionID))
			} else {
				assert.Contains(t, body, "Unauthorized", "a different identity must be rejected on pod B")
			}
		})
	}
}

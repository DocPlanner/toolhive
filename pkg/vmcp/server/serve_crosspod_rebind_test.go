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
	"github.com/stacklok/toolhive/pkg/vmcp/health"
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
	crossPodUserHeader  = "X-Test-User"
	crossPodIssuer      = "https://idp.example"
	crossPodResourceURI = "file:///doc.txt"
)

// countingFactory wraps a MultiSessionFactory and counts phase-2 creations
// (MakeSessionWithID) and cross-pod restores (RestoreSession). When gate is set,
// MakeSessionWithID blocks until it is closed, which holds the session record as an
// unbound placeholder.
type countingFactory struct {
	base     vmcpsession.MultiSessionFactory
	gate     chan struct{}
	makes    atomic.Int32
	restores atomic.Int32
}

func (f *countingFactory) MakeSessionWithID(
	ctx context.Context, id string, identity *auth.Identity, backends []*vmcp.Backend,
) (vmcpsession.MultiSession, error) {
	f.makes.Add(1)
	if f.gate != nil {
		<-f.gate
	}
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
	core    *fakeCore
}

// startCrossPod builds one Serve-path vMCP replica whose vMCP session manager uses
// the shared store, and returns the full shared Handler (auth middleware included).
// A non-nil gate blocks the replica's phase-2 creation until it is closed.
func startCrossPod(t *testing.T, shared transportsession.DataStorage, gate chan struct{}) *crossPod {
	t.Helper()
	authReg := vmcpauth.NewDefaultOutgoingAuthRegistry()
	require.NoError(t, authReg.RegisterStrategy(authtypes.StrategyTypeUnauthenticated, strategies.NewUnauthenticatedStrategy()))
	factory := &countingFactory{base: vmcpsession.NewSessionFactory(authReg), gate: gate}
	registry := vmcp.NewImmutableRegistry([]vmcp.Backend{})
	fc := &fakeCore{
		tools:     []vmcp.Tool{{Name: "echo", Description: "echo"}},
		resources: []vmcp.Resource{{URI: crossPodResourceURI, Name: "doc"}},
	}

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
	return &crossPod{handler: handler, factory: factory, core: fc}
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
func openSSE(t *testing.T, pod *crossPod, user, sessionID string, extraHeaders ...string) int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := newSSEWriter()
	req := newCrossPodRequest(ctx, http.MethodGet, user, sessionID, "")
	for i := 0; i+1 < len(extraHeaders); i += 2 {
		req.Header.Set(extraHeaders[i], extraHeaders[i+1])
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pod.handler.ServeHTTP(w, req)
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
	return crossPodRPC(t, pod, user, sessionID, "tools/call", `{"name":"echo","arguments":{}}`)
}

// crossPodRPC sends one JSON-RPC request on pod and returns the response body.
func crossPodRPC(t *testing.T, pod *crossPod, user, sessionID, method, params string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	pod.handler.ServeHTTP(rec, newCrossPodRequest(context.Background(), http.MethodPost, user, sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"`+method+`","params":`+params+`}`))
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
			podA := startCrossPod(t, shared, nil)
			podB := startCrossPod(t, shared, nil)

			sessionID := initSession(t, shared, podA, "alice")
			aliceBinding := storedBinding(t, shared, sessionID)
			require.Equal(t, int32(1), podA.factory.makes.Load())

			if tc.viaGET {
				status := openSSE(t, podB, tc.caller, sessionID)
				t.Logf("GET on pod B as %s -> HTTP %d; pod B MakeSessionWithID=%d RestoreSession=%d; "+
					"binding before=%q after=%q", tc.caller, status, podB.factory.makes.Load(),
					podB.factory.restores.Load(), aliceBinding, storedBinding(t, shared, sessionID))

				// mcp-go answers a GET with 200 whatever its registration hook does, so
				// only an HTTP-level check can refuse a different caller.
				if tc.caller == "alice" {
					assert.Equal(t, http.StatusOK, status, "the owner's GET on pod B must open the stream")
				} else {
					assert.Equal(t, http.StatusForbidden, status, "a different identity's GET on pod B must be refused")
				}
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

// TestCrossPodGETDuringRegistration covers the window before the session has a
// binding: alice's initialize on pod A is still registering (phase-2 creation is
// blocked) when eve sends a GET with the session ID to pod B. Only the session's own
// initialize may create the session, so pod B must not run phase-2 creation for
// eve's GET; it waits for alice's binding and then rejects eve.
func TestCrossPodGETDuringRegistration(t *testing.T) {
	t.Parallel()

	shared, err := transportsession.NewLocalSessionDataStorage(time.Hour)
	require.NoError(t, err)
	t.Cleanup(func() { _ = shared.Close() })
	gate := make(chan struct{})
	podA := startCrossPod(t, shared, gate)
	podB := startCrossPod(t, shared, nil)

	// alice's initialize on pod A. mcp-go writes the response headers (with the
	// session ID) before it runs the registration hook, which then blocks in the gate.
	initW := newSSEWriter()
	initDone := make(chan struct{})
	go func() {
		defer close(initDone)
		podA.handler.ServeHTTP(initW, newCrossPodRequest(context.Background(), http.MethodPost, "alice", "",
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",`+
				`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
	}()
	select {
	case <-initW.headerWritten:
	case <-time.After(5 * time.Second):
		t.Fatal("initialize did not write response headers")
	}
	sessionID := initW.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)
	require.Eventually(t, func() bool { return podA.factory.makes.Load() == 1 },
		2*time.Second, 5*time.Millisecond, "alice's registration must be blocked in phase-2 creation")
	require.Empty(t, storedBinding(t, shared, sessionID), "the session must not be bound yet")

	// eve's GET on pod B while alice's registration is pending.
	getCtx, cancelGET := context.WithCancel(context.Background())
	getW := newSSEWriter()
	getDone := make(chan struct{})
	go func() {
		defer close(getDone)
		podB.handler.ServeHTTP(getW, newCrossPodRequest(getCtx, http.MethodGet, "eve", sessionID, ""))
	}()

	// Give eve's GET time to reach the registration hook, then let alice's
	// registration finish.
	time.Sleep(200 * time.Millisecond)
	close(gate)
	select {
	case <-initDone:
	case <-time.After(5 * time.Second):
		t.Fatal("alice's registration did not finish")
	}
	select {
	case <-getW.headerWritten:
	case <-getDone:
	case <-time.After(5 * time.Second):
		t.Fatal("GET did not write response headers")
	}
	cancelGET()
	<-getDone

	assert.Equal(t, http.StatusForbidden, getW.status(), "eve's GET must be refused once alice's binding is written")
	assert.Equal(t, int32(0), podB.factory.makes.Load(),
		"a GET on pod B must not call CreateSession/MakeSessionWithID")
	binding := storedBinding(t, shared, sessionID)
	alice := &auth.Identity{PrincipalInfo: auth.PrincipalInfo{
		Subject: "alice", Claims: map[string]any{"iss": crossPodIssuer, "sub": "alice"},
	}}
	assert.NoError(t, vmcpsession.ValidateCaller(binding, alice), "the session must be bound to alice")

	body := callEcho(t, podB, "alice", sessionID)
	assert.Contains(t, body, `"ok"`, "alice must own her session after eve's GET")
	body = callEcho(t, podB, "eve", sessionID)
	assert.Contains(t, body, "Unauthorized", "eve must not be able to use alice's session")
}

// TestCrossPodRehydration covers a session initialized on pod A and used on pod B,
// which never ran the registration for it: pod B restores the session from the
// shared store and fills the per-session tool and resource stores from the core,
// without creating the session again.
func TestCrossPodRehydration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		params string
		want   string
	}{
		{name: "tools/list", method: "tools/list", params: `{}`, want: `"name":"echo"`},
		{name: "tools/call", method: "tools/call", params: `{"name":"echo","arguments":{}}`, want: `"text":"ok"`},
		{name: "resources/list", method: "resources/list", params: `{}`, want: `"uri":"` + crossPodResourceURI + `"`},
		{
			name: "resources/read", method: "resources/read",
			params: `{"uri":"` + crossPodResourceURI + `"}`, want: `"text":"resource-body"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			shared, err := transportsession.NewLocalSessionDataStorage(time.Hour)
			require.NoError(t, err)
			t.Cleanup(func() { _ = shared.Close() })
			podA := startCrossPod(t, shared, nil)
			podB := startCrossPod(t, shared, nil)

			sessionID := initSession(t, shared, podA, "alice")
			binding := storedBinding(t, shared, sessionID)

			body := crossPodRPC(t, podB, "alice", sessionID, tc.method, tc.params)
			assert.Contains(t, body, tc.want, "pod B must serve %s for a session from pod A", tc.method)
			assert.NotContains(t, body, `"error"`)
			assert.Equal(t, int32(0), podB.factory.makes.Load(), "pod B must not create the session again")
			assert.Equal(t, binding, storedBinding(t, shared, sessionID), "the stored binding must not change")
		})
	}
}

// TestListenStreamGuard covers the HTTP-level check of GET listen streams. mcp-go
// answers a GET with 200 even when the registration hook rejects it, keeps the
// GET's session object for later requests on that pod, and on the pod that holds
// the session in memory runs no hook at all, so the check must refuse the request
// before mcp-go sees it.
func TestListenStreamGuard(t *testing.T) {
	t.Parallel()

	newPods := func(t *testing.T) (transportsession.DataStorage, *crossPod, *crossPod) {
		t.Helper()
		shared, err := transportsession.NewLocalSessionDataStorage(time.Hour)
		require.NoError(t, err)
		t.Cleanup(func() { _ = shared.Close() })
		return shared, startCrossPod(t, shared, nil), startCrossPod(t, shared, nil)
	}

	t.Run("GET on the owner pod", func(t *testing.T) {
		t.Parallel()
		shared, podA, _ := newPods(t)
		sessionID := initSession(t, shared, podA, "bob")

		assert.Equal(t, http.StatusForbidden, openSSE(t, podA, "eve", sessionID),
			"eve's GET on the pod that holds bob's session must be refused")
		assert.Equal(t, http.StatusForbidden,
			openSSE(t, podA, "eve", sessionID, health.ProbeHeader, health.ProbeHeaderValue),
			"the probe header must not skip the listen-stream check")
		assert.Equal(t, http.StatusOK, openSSE(t, podA, "bob", sessionID),
			"bob's GET on his own session must open the stream")
		assert.Contains(t, callEcho(t, podA, "bob", sessionID), `"ok"`)
	})

	t.Run("GET held open on another pod", func(t *testing.T) {
		t.Parallel()
		shared, podA, podB := newPods(t)
		sessionID := initSession(t, shared, podA, "alice")

		// eve's GET on pod B, kept open while alice uses pod B.
		ctx, cancel := context.WithCancel(context.Background())
		w := newSSEWriter()
		done := make(chan struct{})
		go func() {
			defer close(done)
			podB.handler.ServeHTTP(w, newCrossPodRequest(ctx, http.MethodGet, "eve", sessionID, ""))
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		select {
		case <-w.headerWritten:
		case <-time.After(5 * time.Second):
			t.Fatal("GET did not write response headers")
		}
		assert.Equal(t, http.StatusForbidden, w.status(), "eve's GET on pod B must be refused")

		body := callEcho(t, podB, "alice", sessionID)
		assert.Contains(t, body, `"ok"`, "alice must be able to use her session on pod B")
		assert.Equal(t, "alice", podB.core.lastCallSubject.Load(), "alice's call must run with her own identity")
	})

	t.Run("GET without a session ID", func(t *testing.T) {
		t.Parallel()
		_, podA, _ := newPods(t)
		assert.Equal(t, http.StatusBadRequest, openSSE(t, podA, "alice", ""))
	})

	t.Run("GET for an unknown session", func(t *testing.T) {
		t.Parallel()
		_, podA, _ := newPods(t)
		assert.Equal(t, http.StatusNotFound, openSSE(t, podA, "alice", "unknown-session"))
	})
}

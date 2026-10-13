// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"sync"

	"github.com/mark3labs/mcp-go/server"
)

// clientSessionSet tracks the SDK sessions registered on this replica. It feeds
// the session cardinality gauges and selects the sessions a capability refresh
// clears (serve_refresh.go).
//
// A registration runs for up to defaultSessionRegistrationTimeout, and mcp-go
// can unregister the session meanwhile (a DELETE, the end of a GET, the idle
// sweep). So a registration is begun when the hook starts and committed when it
// succeeds, and remove cancels a registration still in progress: a session that
// was unregistered before its registration finished is never added. The zero
// value is ready to use.
type clientSessionSet struct {
	mu      sync.Mutex
	pending map[string]struct{}
	active  map[string]server.ClientSession
}

// begin records that the registration of sessionID has started.
func (c *clientSessionSet) begin(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pending == nil {
		c.pending = make(map[string]struct{})
	}
	c.pending[sessionID] = struct{}{}
}

// commit adds session if its registration is still in progress (begin was
// called and remove was not), and ends the registration.
func (c *clientSessionSet) commit(session server.ClientSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sessionID := session.SessionID()
	if _, ok := c.pending[sessionID]; !ok {
		return
	}
	delete(c.pending, sessionID)
	if c.active == nil {
		c.active = make(map[string]server.ClientSession)
	}
	c.active[sessionID] = session
}

// abort ends a registration that failed, without adding the session.
func (c *clientSessionSet) abort(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, sessionID)
}

// remove drops sessionID and cancels its registration if one is in progress.
func (c *clientSessionSet) remove(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.pending, sessionID)
	delete(c.active, sessionID)
}

// count returns the number of registered sessions.
func (c *clientSessionSet) count() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int64(len(c.active))
}

// snapshot returns the registered sessions.
func (c *clientSessionSet) snapshot() []server.ClientSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	sessions := make([]server.ClientSession, 0, len(c.active))
	for _, session := range c.active {
		sessions = append(sessions, session)
	}
	return sessions
}

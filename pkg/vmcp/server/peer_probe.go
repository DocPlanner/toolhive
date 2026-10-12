// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"log/slog"
	"net/http"

	mcpparser "github.com/stacklok/toolhive/pkg/mcp"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
)

// peerProbeKey marks the context of a request that carries the inter-vMCP
// health probe header (health.ProbeHeader), which a peer vMCP's health checker
// sets on the wire (healthProbePropagatingRoundTripper in pkg/vmcp/client).
//
// The key is private to this package on purpose. The header is set by the
// client, so any authenticated caller can send it. It must never set the
// healthcontext marker: that marker makes the outgoing auth strategies (token
// exchange, XAA) use the vMCP's own service credentials instead of the caller's
// identity. Only handleSessionRegistration and the lazy-injection hooks read
// this key, to skip session work for a probe.
type peerProbeKey struct{}

// peerProbeMethods are the MCP methods a peer probe may send: the handshake and
// the capability lists that the health checker's ListCapabilities runs. A probe
// never calls a tool, reads a resource or gets a prompt.
var peerProbeMethods = map[string]bool{
	"initialize":                true,
	"notifications/initialized": true,
	"ping":                      true,
	"tools/list":                true,
	"resources/list":            true,
	"resources/templates/list":  true,
	"prompts/list":              true,
}

// peerProbeBody is the JSON-RPC error returned for a probe-marked request that
// is not part of the probe handshake.
var peerProbeBody = []byte(
	`{"jsonrpc":"2.0","id":"server-error","error":` +
		`{"code":-32600,"message":"Forbidden: health probes may only initialize and list capabilities"}}`,
)

// peerProbeMiddleware marks the request context with peerProbeKey when the
// request carries the probe header. A probe-marked POST whose MCP method is not
// in peerProbeMethods (or cannot be parsed) is rejected with 403. GET and DELETE
// pass: the listen-stream guard checks every GET, and the probe client's Close
// sends a DELETE. Runs after authentication.
func peerProbeMiddleware(next http.Handler) http.Handler {
	return mcpparser.ParsingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !health.HasProbeHeader(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodPost {
			parsed := mcpparser.GetParsedMCPRequest(r.Context())
			if parsed == nil || !peerProbeMethods[parsed.Method] {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				if _, err := w.Write(peerProbeBody); err != nil {
					slog.Debug("failed to write probe refusal", "error", err)
				}
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerProbeKey{}, true)))
	}))
}

// isPeerProbe reports whether ctx belongs to a request marked by peerProbeMiddleware.
func isPeerProbe(ctx context.Context) bool {
	marked, _ := ctx.Value(peerProbeKey{}).(bool)
	return marked
}

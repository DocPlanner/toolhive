// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	mcptransport "github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/stacklok/toolhive/pkg/auth"
	"github.com/stacklok/toolhive/pkg/versions"
	"github.com/stacklok/toolhive/pkg/vmcp"
	vmcpauth "github.com/stacklok/toolhive/pkg/vmcp/auth"
	authtypes "github.com/stacklok/toolhive/pkg/vmcp/auth/types"
	"github.com/stacklok/toolhive/pkg/vmcp/conversion"
)

const (
	// maxBackendResponseSize caps each HTTP response body for streamable-HTTP
	// backends to prevent memory exhaustion. Not applied to SSE transports —
	// see createMCPClient for the rationale.
	maxBackendResponseSize = 100 * 1024 * 1024 // 100 MB

	// defaultBackendRequestTimeout is the wall-clock deadline for individual
	// streamable-HTTP requests. Applied at both the http.Client and SDK layers
	// (defense-in-depth). Not used for SSE, whose stream lifetime is unbounded.
	defaultBackendRequestTimeout = 30 * time.Second
)

// httpRoundTripperFunc adapts a plain function to http.RoundTripper.
type httpRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f httpRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// authRoundTripper adds pre-resolved authentication to outgoing backend requests.
type authRoundTripper struct {
	base         http.RoundTripper
	authStrategy vmcpauth.Strategy
	authConfig   *authtypes.BackendAuthStrategy
	target       *vmcp.BackendTarget
}

func (a *authRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	reqClone := req.Clone(req.Context())
	if err := a.authStrategy.Authenticate(reqClone.Context(), reqClone, a.authConfig); err != nil {
		return nil, fmt.Errorf("authentication failed for backend %s: %w", a.target.WorkloadID, err)
	}
	return a.base.RoundTrip(reqClone)
}

// identityRoundTripper propagates the caller's identity to outgoing backend requests.
type identityRoundTripper struct {
	base     http.RoundTripper
	identity *auth.Identity
}

func (i *identityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if i.identity != nil {
		ctx := auth.WithIdentity(req.Context(), i.identity)
		req = req.Clone(ctx)
	}
	return i.base.RoundTrip(req)
}

// Compile-time assertion: mcpSession must implement Session.
var _ Session = (*mcpSession)(nil)

// mcpSession wraps a persistent mark3labs MCP client for one backend.
// It is created once per backend during MakeSession and closed when the session ends.
type mcpSession struct {
	mu               sync.RWMutex
	client           *mcpclient.Client
	target           *vmcp.BackendTarget // bound at creation; used for capability name translation
	backendSessionID string              // backend-assigned session ID (may be empty)
	generation       uint64
	closed           bool
	reconnect        func(context.Context) (*mcpclient.Client, string, error)
}

// SessionID returns the backend-assigned session ID.
func (c *mcpSession) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.backendSessionID
}

// Close closes the underlying MCP client transport.
func (c *mcpSession) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.client.Close()
}

// backendSessionLostMarkers are lower-cased substrings of backend replies that
// mean the backend no longer knows our session even though the transport did not
// surface a plain 404:
//   - "no valid session id": HTTP 400 from TypeScript SDK servers when a request
//     arrives without Mcp-Session-Id;
//   - "invalid during session initialization": go-sdk servers open a fresh
//     session for a sessionless request and reject any non-initialize method;
//   - "invalid session id" / "session not found" / "session terminated": mcp-go
//     and ToolHive proxies describing a session they no longer hold.
//
// All of these are returned before the backend executes the operation, so a
// single reinitialize-and-retry is safe.
var backendSessionLostMarkers = []string{
	"no valid session id",
	"invalid during session initialization",
	"invalid session id",
	"session not found",
	"session terminated",
}

// errBackendSessionIDLost is returned before a request is sent when the
// streamable-HTTP transport has dropped the session ID the backend issued.
// mark3labs/mcp-go clears the ID after any 404, so the next request would go out
// without Mcp-Session-Id and be rejected as a non-initialize call. It wraps
// ErrSessionTerminated so the recovery path treats it as a definitive loss.
var errBackendSessionIDLost = fmt.Errorf(
	"backend session ID dropped by transport: %w", mcptransport.ErrSessionTerminated)

// isBackendSessionLostError reports whether err means the backend session is
// definitively gone and the operation was not executed.
func isBackendSessionLostError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mcptransport.ErrSessionTerminated) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range backendSessionLostMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// callWithSessionRecovery retries an operation only after a definitive MCP
// session-lost response (see isBackendSessionLostError). Such responses are
// returned before the backend executes the operation, unlike ambiguous network
// or 5xx errors, which are never retried.
func callWithSessionRecovery[T any](
	ctx context.Context,
	c *mcpSession,
	operation func(*mcpclient.Client) (T, error),
) (T, error) {
	result, generation, err := callSession(ctx, c, operation)
	if err == nil || c.reconnect == nil || !isBackendSessionLostError(err) {
		return result, err
	}

	slog.Info("backend session lost; reinitializing before retry",
		"backendID", c.target.WorkloadID, "error", err)

	if reconnectErr := c.reconnectIfCurrent(ctx, generation); reconnectErr != nil {
		var zero T
		return zero, fmt.Errorf("backend session expired and reinitialization failed: %w", reconnectErr)
	}

	result, _, err = callSession(ctx, c, operation)
	return result, err
}

func callSession[T any](
	ctx context.Context,
	c *mcpSession,
	operation func(*mcpclient.Client) (T, error),
) (T, uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		var zero T
		return zero, c.generation, fmt.Errorf("backend session is closed")
	}
	if c.transportLostSessionID() {
		var zero T
		return zero, c.generation, errBackendSessionIDLost
	}
	result, err := operation(c.client)
	return result, c.generation, err
}

// transportLostSessionID reports whether the streamable-HTTP transport no longer
// carries the session ID the backend issued at initialize. Callers must hold
// c.mu. Sending in that state is pointless: the backend would reject the
// sessionless request, so the caller reinitializes first instead.
func (c *mcpSession) transportLostSessionID() bool {
	if c.backendSessionID == "" || c.reconnect == nil || c.client == nil {
		return false
	}
	sh, ok := c.client.GetTransport().(*mcptransport.StreamableHTTP)
	if !ok {
		return false
	}
	return sh.GetSessionId() == ""
}

// reconnectIfCurrent serializes reinitialization. Concurrent callers that
// observed the same expired generation reuse the first caller's new client.
func (c *mcpSession) reconnectIfCurrent(ctx context.Context, observedGeneration uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("backend session is closed")
	}
	if c.generation != observedGeneration {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	newClient, sessionID, err := c.reconnect(ctx)
	if err != nil {
		return err
	}
	oldClient := c.client
	c.client = newClient
	c.backendSessionID = sessionID
	c.generation++
	if closeErr := oldClient.Close(); closeErr != nil {
		slog.Warn("failed to close expired backend session", "backendID", c.target.WorkloadID, "error", closeErr)
	}
	slog.Info("reinitialized expired backend session", "backendID", c.target.WorkloadID)
	return nil
}

// CallTool invokes a named tool on this backend.
func (c *mcpSession) CallTool(
	ctx context.Context,
	toolName string,
	arguments map[string]any,
	meta map[string]any,
) (*vmcp.ToolCallResult, error) {
	backendName := c.target.GetBackendCapabilityName(toolName)
	if backendName != toolName {
		slog.Debug("Translating tool name", "clientName", toolName, "backendName", backendName)
	}

	result, err := callWithSessionRecovery(ctx, c, func(client *mcpclient.Client) (*mcp.CallToolResult, error) {
		return client.CallTool(ctx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      backendName,
				Arguments: arguments,
				Meta:      conversion.ToMCPMeta(meta),
			},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("tool %q call failed on backend %s: %w", toolName, c.target.WorkloadID, err)
	}

	contentArray := conversion.ConvertMCPContents(result.Content)

	structuredContent := conversion.ToolResultStructuredContent(
		result.StructuredContent,
		contentArray,
		c.target.OutputSchema != nil,
	)

	return &vmcp.ToolCallResult{
		Content:           contentArray,
		StructuredContent: structuredContent,
		IsError:           result.IsError,
		Meta:              conversion.FromMCPMeta(result.Meta),
	}, nil
}

// ReadResource reads a resource from this backend.
func (c *mcpSession) ReadResource(
	ctx context.Context,
	uri string,
) (*vmcp.ResourceReadResult, error) {
	backendURI := c.target.GetBackendCapabilityName(uri)
	if backendURI != uri {
		slog.Debug("Translating resource URI", "clientURI", uri, "backendURI", backendURI)
	}

	result, err := callWithSessionRecovery(ctx, c, func(client *mcpclient.Client) (*mcp.ReadResourceResult, error) {
		return client.ReadResource(ctx, mcp.ReadResourceRequest{
			Params: mcp.ReadResourceParams{URI: backendURI},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("resource %q read failed on backend %s: %w", uri, c.target.WorkloadID, err)
	}

	return &vmcp.ResourceReadResult{
		Contents: conversion.ConvertMCPResourceContents(result.Contents),
		Meta:     conversion.FromMCPMeta(result.Meta),
	}, nil
}

// GetPrompt retrieves a prompt from this backend.
func (c *mcpSession) GetPrompt(
	ctx context.Context,
	name string,
	arguments map[string]any,
) (*vmcp.PromptGetResult, error) {
	backendName := c.target.GetBackendCapabilityName(name)
	if backendName != name {
		slog.Debug("Translating prompt name", "clientName", name, "backendName", backendName)
	}

	stringArgs := conversion.ConvertPromptArguments(arguments)

	result, err := callWithSessionRecovery(ctx, c, func(client *mcpclient.Client) (*mcp.GetPromptResult, error) {
		return client.GetPrompt(ctx, mcp.GetPromptRequest{
			Params: mcp.GetPromptParams{
				Name:      backendName,
				Arguments: stringArgs,
			},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("prompt %q get failed on backend %s: %w", name, c.target.WorkloadID, err)
	}

	return &vmcp.PromptGetResult{
		Messages:    conversion.ConvertMCPPromptMessages(result.Messages),
		Description: result.Description,
		Meta:        conversion.FromMCPMeta(result.Meta),
	}, nil
}

// NewHTTPConnector returns a function that creates an HTTP-based (streamable-HTTP
// or SSE) persistent backend Session for each backend.
//
// registry provides the authentication strategy for outgoing backend requests.
// Pass a registry configured with the "unauthenticated" strategy to disable auth.
//
// onCapabilityChange is an optional callback invoked (in a separate goroutine)
// when the backend sends a tools/list_changed or resources/list_changed
// notification. Pass nil to ignore capability change notifications.
//
// defaultRequestTimeout applies to streamable-HTTP backends. Entries in
// perWorkloadRequestTimeouts override it by BackendTarget.WorkloadID. Invalid
// or absent values retain the built-in timeout.
func NewHTTPConnector(
	registry vmcpauth.OutgoingAuthRegistry,
	onCapabilityChange func(backendID string),
	defaultRequestTimeout time.Duration,
	perWorkloadRequestTimeouts map[string]time.Duration,
) func(
	ctx context.Context,
	target *vmcp.BackendTarget,
	identity *auth.Identity,
) (Session, *vmcp.CapabilityList, error) {
	return func(
		ctx context.Context,
		target *vmcp.BackendTarget,
		identity *auth.Identity,
	) (Session, *vmcp.CapabilityList, error) {
		requestTimeout := requestTimeoutForWorkload(
			target.WorkloadID,
			defaultRequestTimeout,
			perWorkloadRequestTimeouts,
		)
		c, caps, backendSessionID, err := connectMCPClient(
			ctx, target, identity, registry, requestTimeout,
		)
		if err != nil {
			return nil, nil, err
		}
		registerCapabilityChangeNotifications(c, target, onCapabilityChange)

		var reconnect func(context.Context) (*mcpclient.Client, string, error)
		if _, ok := c.GetTransport().(*mcptransport.StreamableHTTP); ok {
			reconnect = func(reconnectCtx context.Context) (*mcpclient.Client, string, error) {
				newClient, _, sessionID, reconnectErr := connectMCPClient(
					reconnectCtx, target, identity, registry, requestTimeout,
				)
				if reconnectErr == nil {
					registerCapabilityChangeNotifications(newClient, target, onCapabilityChange)
				}
				return newClient, sessionID, reconnectErr
			}
		}

		return &mcpSession{
			client:           c,
			target:           target,
			backendSessionID: backendSessionID,
			reconnect:        reconnect,
		}, caps, nil
	}
}

func registerCapabilityChangeNotifications(
	c *mcpclient.Client,
	target *vmcp.BackendTarget,
	onCapabilityChange func(backendID string),
) {
	if onCapabilityChange == nil {
		return
	}
	backendID := target.WorkloadID
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == "notifications/tools/list_changed" ||
			n.Method == "notifications/resources/list_changed" {
			go onCapabilityChange(backendID)
		}
	})
}

func connectMCPClient(
	ctx context.Context,
	target *vmcp.BackendTarget,
	identity *auth.Identity,
	registry vmcpauth.OutgoingAuthRegistry,
	requestTimeout time.Duration,
) (*mcpclient.Client, *vmcp.CapabilityList, string, error) {
	c, err := createMCPClient(target, identity, registry, requestTimeout)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to create MCP client for backend %s: %w", target.WorkloadID, err)
	}

	caps, err := initAndQueryCapabilities(ctx, c, target)
	if err != nil {
		_ = c.Close()
		return nil, nil, "", fmt.Errorf("failed to initialise backend %s: %w", target.WorkloadID, err)
	}

	// Streamable-HTTP servers assign the session ID during Initialize. SSE
	// transports do not assign one, so the value remains empty.
	var backendSessionID string
	if sh, ok := c.GetTransport().(*mcptransport.StreamableHTTP); ok {
		backendSessionID = sh.GetSessionId()
	}
	return c, caps, backendSessionID, nil
}

// createMCPClient builds and starts a mark3labs MCP client for target.
// The transport is started with context.Background() so its lifetime is bound
// to client.Close(), not to any caller-supplied init context.
func createMCPClient(
	target *vmcp.BackendTarget,
	identity *auth.Identity,
	registry vmcpauth.OutgoingAuthRegistry,
	requestTimeout time.Duration,
) (*mcpclient.Client, error) {
	// Resolve and validate the auth strategy once at client creation time.
	strategyName := authtypes.StrategyTypeUnauthenticated
	if target.AuthConfig != nil {
		strategyName = target.AuthConfig.Type
	}
	strategy, err := registry.GetStrategy(strategyName)
	if err != nil {
		return nil, fmt.Errorf("auth strategy %q not found: %w", strategyName, err)
	}
	if err := strategy.Validate(target.AuthConfig); err != nil {
		return nil, fmt.Errorf("invalid auth config for backend %s: %w", target.WorkloadID, err)
	}

	slog.Debug("Applied authentication strategy", "strategy", strategy.Name(), "backendID", target.WorkloadID)

	// Build shared transport chain: auth → identity propagation.
	// The per-transport sections below may add a size-limiting wrapper on top.
	base := http.RoundTripper(http.DefaultTransport)
	base = &authRoundTripper{
		base:         base,
		authStrategy: strategy,
		authConfig:   target.AuthConfig,
		target:       target,
	}
	base = &identityRoundTripper{base: base, identity: identity}

	var c *mcpclient.Client
	switch target.TransportType {
	case "streamable-http", "streamable":
		// "streamable" is a legacy alias for "streamable-http".
		//
		// For streamable-HTTP, each MCP call is a single bounded HTTP
		// request/response pair, so a per-response body size limit is safe and
		// correct. http.Client.Timeout provides a hard wall-clock deadline;
		// WithHTTPTimeout additionally wraps each SDK request in a
		// context.WithTimeout so the mark3labs transport surfaces a descriptive
		// error before the stdlib deadline fires. Both are set to
		// requestTimeout: defense-in-depth.
		sizeLimited := httpRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := base.RoundTrip(req)
			if err != nil {
				return nil, err
			}
			resp.Body = struct {
				io.Reader
				io.Closer
			}{
				Reader: io.LimitReader(resp.Body, maxBackendResponseSize),
				Closer: resp.Body,
			}
			return resp, nil
		})
		httpClient := &http.Client{
			Transport: sizeLimited,
			Timeout:   requestTimeout,
		}
		c, err = mcpclient.NewStreamableHttpClient(
			target.BaseURL,
			mcptransport.WithHTTPTimeout(requestTimeout),
			mcptransport.WithHTTPBasicClient(httpClient),
		)
	case "sse":
		// For SSE, the entire session is delivered as one long-lived HTTP
		// response body. Applying io.LimitReader to that body would silently
		// terminate the connection after maxBackendResponseSize cumulative bytes
		// — not per-event — which is wrong. Individual event size is bounded by
		// the backend; operation deadlines are enforced via context cancellation.
		//
		// http.Client.Timeout is also omitted: it caps the full round-trip
		// including body reads, which would kill the stream after the timeout.
		httpClient := &http.Client{Transport: base}
		c, err = mcpclient.NewSSEMCPClient(
			target.BaseURL,
			mcptransport.WithHTTPClient(httpClient),
		)
	default:
		return nil, fmt.Errorf("%w: %s (supported: streamable-http, sse)",
			vmcp.ErrUnsupportedTransport, target.TransportType)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create %s client: %w", target.TransportType, err)
	}

	// Start the transport with context.Background() so that the transport's
	// lifetime is scoped to the session (terminated by client.Close()) rather
	// than to the per-backend init timeout context. The init timeout context
	// is used only for the Initialize handshake and capability queries in
	// initAndQueryCapabilities, both of which have bounded duration.
	// Without this, the SSE transport would tear down its persistent read
	// goroutine when the init goroutine's defer-cancel fires after init completes.
	if err := c.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to start client: %w", err)
	}

	return c, nil
}

func requestTimeoutForWorkload(
	workloadID string,
	defaultTimeout time.Duration,
	perWorkloadTimeouts map[string]time.Duration,
) time.Duration {
	if timeout := perWorkloadTimeouts[workloadID]; timeout > 0 {
		return timeout
	}
	if defaultTimeout > 0 {
		return defaultTimeout
	}
	return defaultBackendRequestTimeout
}

// initAndQueryCapabilities runs the MCP Initialize handshake then discovers
// all capabilities (tools, resources, prompts) from the backend.
func initAndQueryCapabilities(
	ctx context.Context,
	c *mcpclient.Client,
	target *vmcp.BackendTarget,
) (*vmcp.CapabilityList, error) {
	result, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "toolhive-vmcp",
				Version: versions.Version,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize failed: %w", err)
	}

	serverCaps := result.Capabilities
	caps := &vmcp.CapabilityList{}

	if serverCaps.Tools != nil {
		toolsResult, listErr := c.ListTools(ctx, mcp.ListToolsRequest{})
		if listErr != nil {
			return nil, fmt.Errorf("list tools failed: %w", listErr)
		}
		for _, t := range toolsResult.Tools {
			caps.Tools = append(caps.Tools, vmcp.Tool{
				Name:         t.Name,
				Description:  t.Description,
				InputSchema:  conversion.ConvertToolInputSchema(t.InputSchema),
				OutputSchema: conversion.ConvertToolOutputSchema(t.OutputSchema),
				Annotations:  conversion.ConvertToolAnnotations(t.Annotations),
				BackendID:    target.WorkloadID,
			})
		}
	}

	if serverCaps.Resources != nil {
		resResult, listErr := c.ListResources(ctx, mcp.ListResourcesRequest{})
		if listErr != nil {
			return nil, fmt.Errorf("list resources failed: %w", listErr)
		}
		for _, r := range resResult.Resources {
			caps.Resources = append(caps.Resources, vmcp.Resource{
				URI:         r.URI,
				Name:        r.Name,
				Description: r.Description,
				MimeType:    r.MIMEType,
				BackendID:   target.WorkloadID,
			})
		}
	}

	if serverCaps.Prompts != nil {
		promptsResult, listErr := c.ListPrompts(ctx, mcp.ListPromptsRequest{})
		if listErr != nil {
			return nil, fmt.Errorf("list prompts failed: %w", listErr)
		}
		for _, p := range promptsResult.Prompts {
			args := make([]vmcp.PromptArgument, len(p.Arguments))
			for j, a := range p.Arguments {
				args[j] = vmcp.PromptArgument{
					Name:        a.Name,
					Description: a.Description,
					Required:    a.Required,
				}
			}
			caps.Prompts = append(caps.Prompts, vmcp.Prompt{
				Name:        p.Name,
				Description: p.Description,
				Arguments:   args,
				BackendID:   target.WorkloadID,
			})
		}
	}

	slog.Debug("Backend capabilities",
		"backendID", target.WorkloadID,
		"tools", len(caps.Tools),
		"resources", len(caps.Resources),
		"prompts", len(caps.Prompts),
	)

	return caps, nil
}

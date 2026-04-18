// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package server implements the Virtual MCP Server that aggregates
// multiple backend MCP servers into a unified interface.
//
// The server exposes aggregated capabilities (tools, resources, prompts)
// and routes incoming MCP protocol requests to appropriate backend workloads.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/stacklok/toolhive/pkg/audit"
	"github.com/stacklok/toolhive/pkg/auth"
	asrunner "github.com/stacklok/toolhive/pkg/authserver/runner"
	mcpparser "github.com/stacklok/toolhive/pkg/mcp"
	"github.com/stacklok/toolhive/pkg/recovery"
	"github.com/stacklok/toolhive/pkg/telemetry"
	transportmiddleware "github.com/stacklok/toolhive/pkg/transport/middleware"
	transportsession "github.com/stacklok/toolhive/pkg/transport/session"
	"github.com/stacklok/toolhive/pkg/vmcp"
	"github.com/stacklok/toolhive/pkg/vmcp/composer"
	vmcpconfig "github.com/stacklok/toolhive/pkg/vmcp/config"
	"github.com/stacklok/toolhive/pkg/vmcp/discovery"
	"github.com/stacklok/toolhive/pkg/vmcp/health"
	"github.com/stacklok/toolhive/pkg/vmcp/optimizer"
	"github.com/stacklok/toolhive/pkg/vmcp/router"
	"github.com/stacklok/toolhive/pkg/vmcp/server/adapter"
	"github.com/stacklok/toolhive/pkg/vmcp/server/sessionmanager"
	vmcpsession "github.com/stacklok/toolhive/pkg/vmcp/session"
	sessiontypes "github.com/stacklok/toolhive/pkg/vmcp/session/types"
	vmcpstatus "github.com/stacklok/toolhive/pkg/vmcp/status"
)

const (
	// defaultReadHeaderTimeout prevents slowloris attacks by limiting time to read request headers.
	defaultReadHeaderTimeout = 10 * time.Second

	// defaultReadTimeout is the maximum duration for reading the entire request, including body.
	defaultReadTimeout = 30 * time.Second

	// defaultWriteTimeout is the server-level write deadline set on http.Server.WriteTimeout.
	// It protects all routes (health, metrics, well-known, etc.) from slow-write clients.
	// For qualifying SSE (GET) connections, transportmiddleware.WriteTimeout clears this
	// per-request via http.ResponseController.SetWriteDeadline(time.Time{}) (golang/go#16100).
	defaultWriteTimeout = 30 * time.Second

	// defaultIdleTimeout is the maximum amount of time to wait for the next request when keep-alive's are enabled.
	defaultIdleTimeout = 120 * time.Second

	// defaultMaxHeaderBytes is the maximum size of request headers in bytes (1 MB).
	defaultMaxHeaderBytes = 1 << 20

	// defaultShutdownTimeout is the maximum time to wait for graceful shutdown.
	defaultShutdownTimeout = 10 * time.Second

	// defaultHeartbeatInterval sends SSE heartbeat pings on GET connections.
	// Prevents proxies/load balancers from closing idle SSE connections.
	defaultHeartbeatInterval = 30 * time.Second

	// defaultSessionTTL is the default session time-to-live duration.
	// Sessions that are inactive for this duration will be automatically cleaned up.
	defaultSessionTTL = 30 * time.Minute

	// defaultSessionRefreshTimeout bounds how long a live session refresh may take.
	defaultSessionRefreshTimeout = 45 * time.Second

	// defaultSessionRegistrationTimeout bounds how long post-initialize session
	// registration may take when opening backend connections and injecting
	// session-scoped capabilities.
	defaultSessionRegistrationTimeout = 45 * time.Second

	// defaultSessionRegistrationWaitTimeout bounds how long an early
	// session-scoped request will wait for post-initialize registration to
	// finish before falling back to best-effort hydration.
	defaultSessionRegistrationWaitTimeout = 10 * time.Second

	// defaultSessionRegistrationGracePeriod gives the OnRegisterSession hook a
	// brief chance to publish its in-flight marker after initialize returns the
	// session ID to the client.
	defaultSessionRegistrationGracePeriod = 500 * time.Millisecond

	// defaultSessionRegistrationPollInterval is the cadence used while waiting
	// for an in-flight registration marker to appear.
	defaultSessionRegistrationPollInterval = 25 * time.Millisecond

	// defaultSessionHydrationTimeout bounds best-effort repair of pod-local SDK
	// session state when a valid session ID lands on a different vMCP replica.
	defaultSessionHydrationTimeout = 10 * time.Second

	// defaultSessionOwnerLookupTimeout bounds loading owner metadata from the
	// shared session metadata storage when deciding whether a request must be
	// forwarded back to the owning replica.
	defaultSessionOwnerLookupTimeout = 5 * time.Second

	// defaultSessionCloseGracePeriod delays closing the replaced session so
	// in-flight handlers that already captured it can drain gracefully.
	defaultSessionCloseGracePeriod = 2 * time.Second

	sessionOwnerForwardedHeader = "X-ToolHive-Session-Forwarded"
	sessionOwnerForwardedValue  = "1"
)

var errSessionOwnerUnavailable = errors.New("session owner unavailable")

//go:generate mockgen -destination=mocks/mock_watcher.go -package=mocks -source=server.go Watcher

// Watcher is the interface for Kubernetes backend watcher integration.
// Used in dynamic mode (outgoingAuth.source: discovered) to gate readiness
// on controller-runtime cache sync before serving requests.
type Watcher interface {
	// WaitForCacheSync waits for the Kubernetes informer caches to sync.
	// Returns true if caches synced successfully, false on timeout or error.
	WaitForCacheSync(ctx context.Context) bool
}

// Config holds the Virtual MCP Server configuration.
type Config struct {
	// Name is the server name exposed in MCP protocol
	Name string

	// Version is the server version
	Version string

	// GroupRef is the name of the MCPGroup containing backend workloads.
	// Used for operational visibility in status endpoint and logging.
	GroupRef string

	// Host is the bind address (default: "127.0.0.1")
	Host string

	// Port is the bind port (default: 4483)
	Port int

	// EndpointPath is the MCP endpoint path (default: "/mcp")
	EndpointPath string

	// SessionTTL is the session time-to-live duration (default: 30 minutes)
	// Sessions inactive for this duration will be automatically cleaned up
	SessionTTL time.Duration

	// AuthMiddleware is the optional authentication middleware to apply to MCP routes.
	// If nil, no authentication is required.
	// This should be a composed middleware chain (e.g., TokenValidator + MCP parser).
	AuthMiddleware func(http.Handler) http.Handler

	// AuthzMiddleware is the optional authorization middleware to apply AFTER discovery.
	// Split from AuthMiddleware so authz can access discovered tool annotations
	// injected by the annotation enrichment middleware.
	// If nil, no authorization is performed.
	AuthzMiddleware func(http.Handler) http.Handler

	// AuthInfoHandler is the optional handler for /.well-known/oauth-protected-resource endpoint.
	// Exposes OIDC discovery information about the protected resource.
	AuthInfoHandler http.Handler

	// AuthServer is the optional embedded authorization server.
	// When non-nil, the routes returned by Routes() are registered on the mux
	// alongside the protected resource metadata endpoint.
	AuthServer *asrunner.EmbeddedAuthServer

	// TelemetryProvider is the optional telemetry provider.
	// If nil, no telemetry is recorded.
	TelemetryProvider *telemetry.Provider

	// AuditConfig is the optional audit configuration.
	// If nil, no audit logging is performed.
	// Component should be set to "vmcp-server" to distinguish vMCP audit logs.
	AuditConfig *audit.Config

	// HealthMonitorConfig is the optional health monitoring configuration.
	// If nil, health monitoring is disabled.
	HealthMonitorConfig *health.MonitorConfig

	// StatusReportingInterval is the interval for reporting status updates.
	// If zero, defaults to 30 seconds.
	// Lower values provide faster status updates but increase API server load.
	StatusReportingInterval time.Duration

	// Watcher is the optional Kubernetes backend watcher for dynamic mode.
	// Only set when running in K8s with outgoingAuth.source: discovered.
	// Used for /readyz endpoint to gate readiness on cache sync.
	Watcher Watcher

	// OptimizerFactory builds an optimizer from a list of tools.
	// If not set, the optimizer is disabled.
	OptimizerFactory func(context.Context, []server.ServerTool) (optimizer.Optimizer, error)

	// OptimizerConfig holds the parsed optimizer search parameters (typed values).
	// When non-nil, Start() creates the search store, wires the OptimizerFactory,
	// and registers the store cleanup in shutdownFuncs.
	// A nil value disables the optimizer.
	OptimizerConfig *optimizer.Config

	// StatusReporter enables vMCP runtime to report operational status.
	// In Kubernetes mode: Updates VirtualMCPServer.Status (requires RBAC)
	// In CLI mode: NoOpReporter (no persistent status)
	// If nil, status reporting is disabled.
	StatusReporter vmcpstatus.Reporter

	// SessionOwnerAdvertiseURL is the pod-local HTTP endpoint used by sibling
	// replicas to forward live-session traffic (SSE listen/delete and methodless
	// client replies) back to the pod that owns the SDK session state.
	SessionOwnerAdvertiseURL string
	// SessionFactory creates MultiSessions for session management.
	// Required; must not be nil.
	SessionFactory vmcpsession.MultiSessionFactory

	// SessionStorage configures the session storage backend.
	// When nil or provider is "memory", local in-process storage is used.
	// When provider is "redis", a Redis-backed store is created for cross-pod
	// session persistence; the Redis password is read from the
	// THV_SESSION_REDIS_PASSWORD environment variable.
	SessionStorage *vmcpconfig.SessionStorageConfig
}

// Server is the Virtual MCP Server that aggregates multiple backends.
type Server struct {
	config *Config

	// MCP protocol server (mark3labs/mcp-go)
	mcpServer *server.MCPServer

	// HTTP server for Streamable HTTP transport
	httpServer *http.Server

	// Network listener (tracks actual bound port when using port 0)
	listener   net.Listener
	listenerMu sync.RWMutex

	// Router for forwarding requests to backends
	router router.Router

	// Backend client for making requests to backends
	backendClient vmcp.BackendClient

	// Handler factory for creating MCP request handlers
	handlerFactory *adapter.DefaultHandlerFactory

	// Discovery manager for lazy per-user capability discovery
	discoveryMgr discovery.Manager

	// Backend registry for capability discovery
	// For static mode (CLI), this is an immutable registry created from initial backends.
	// For dynamic mode (K8s), this is a DynamicRegistry updated by the operator.
	backendRegistry vmcp.BackendRegistry

	// Session manager for tracking MCP protocol sessions
	// This is ToolHive's session.Manager (pkg/transport/session) - the same component
	// used by streamable proxy for MCP session tracking. It handles:
	//   - Session storage and retrieval
	//   - TTL-based cleanup of inactive sessions
	//   - Session lifecycle management
	sessionManager *transportsession.Manager

	// sessionDataStorage is the pluggable key-value backend for session metadata.
	// Currently always LocalSessionDataStorage (in-memory, single-process).
	// Redis-backed storage for multi-pod deployments is not yet wired.
	sessionDataStorage transportsession.DataStorage

	// sessionOwnerURL is the canonical pod-local URL advertised to sibling
	// replicas for owner-aware forwarding of live-session traffic.
	sessionOwnerURL string

	// ownerForwardClient is used to proxy live-session traffic back to the pod
	// that owns the SDK session state.
	ownerForwardClient *http.Client

	// Capability adapter for converting aggregator types to SDK types
	capabilityAdapter *adapter.CapabilityAdapter

	// vmcpSessionMgr manages session-scoped backend client lifecycle.
	vmcpSessionMgr SessionManager

	// Ready channel signals when the server is ready to accept connections.
	// Closed once the listener is created and serving.
	ready     chan struct{}
	readyOnce sync.Once

	// healthMonitor performs periodic health checks on backends.
	// Nil if health monitoring is disabled.
	// Protected by healthMonitorMu: RLock for reads (getter methods, HTTP handlers),
	// Lock for writes (initialization, disabling on start failure).
	healthMonitor   *health.Monitor
	healthMonitorMu sync.RWMutex

	// statusReporter enables vMCP to report operational status to control plane.
	// Nil if status reporting is disabled.
	statusReporter vmcpstatus.Reporter

	// shutdownFuncs contains cleanup functions to run during Stop().
	// Populated during Start() initialization before blocking; no mutex needed
	// since Stop() is only called after Start()'s select returns.
	shutdownFuncs []func(context.Context) error

	// activeClientSessions stores initialized SDK sessions by session ID so
	// live refresh can replace per-session tools/resources directly.
	activeClientSessions sync.Map

	// inFlightRegistrations tracks sessions currently executing the
	// post-initialize registration hook so early session-scoped requests can
	// wait briefly instead of racing a still-empty SDK session.
	inFlightRegistrations sync.Map

	// refreshMu serializes session refresh work triggered by health transitions.
	refreshMu sync.Mutex
}

// buildSessionDataStorage constructs the DataStorage backend from cfg.
// When cfg.SessionStorage is nil or provider is "memory" (or empty), local in-process
// storage is used. When provider is "redis", a Redis-backed store is created
// using the address, DB, and key prefix from cfg.SessionStorage; the password
// is read from the THV_SESSION_REDIS_PASSWORD environment variable.
// Any other provider value is a misconfiguration and returns an error.
func buildSessionDataStorage(ctx context.Context, cfg *Config) (transportsession.DataStorage, error) {
	// Default to in-process storage when session storage is not configured,
	// or when the provider is explicitly "memory" or left empty.
	if cfg.SessionStorage == nil ||
		cfg.SessionStorage.Provider == "" ||
		strings.EqualFold(cfg.SessionStorage.Provider, "memory") {
		return transportsession.NewLocalSessionDataStorage(cfg.SessionTTL)
	}
	if cfg.SessionStorage.Provider != "redis" {
		return nil, fmt.Errorf("unsupported session storage provider %q (supported: \"memory\", \"redis\")",
			cfg.SessionStorage.Provider)
	}
	keyPrefix := cfg.SessionStorage.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "thv:vmcp:session:"
	}
	redisCfg := transportsession.RedisConfig{
		Addr:      cfg.SessionStorage.Address,
		Username:  os.Getenv(vmcpconfig.RedisUsernameEnvVar),
		Password:  os.Getenv(vmcpconfig.RedisPasswordEnvVar),
		DB:        int(cfg.SessionStorage.DB),
		KeyPrefix: keyPrefix,
	}
	slog.Info("using Redis session storage",
		"address", cfg.SessionStorage.Address,
		"db", cfg.SessionStorage.DB,
		"key_prefix", keyPrefix,
	)
	return transportsession.NewRedisSessionDataStorage(ctx, redisCfg, cfg.SessionTTL)
}

type sessionRegistrationState struct {
	done chan struct{}
	once sync.Once
}

func newSessionRegistrationState() *sessionRegistrationState {
	return &sessionRegistrationState{done: make(chan struct{})}
}

func (s *sessionRegistrationState) close() {
	s.once.Do(func() {
		close(s.done)
	})
}

// New creates a new Virtual MCP Server instance.
//
// The backendRegistry parameter provides the list of available backends:
// - For static mode (CLI), pass an immutable registry created from initial backends
// - For dynamic mode (K8s), pass a DynamicRegistry that will be updated by the operator
//
//nolint:gocyclo // Complexity from hook logic is acceptable
func New(
	ctx context.Context,
	cfg *Config,
	rt router.Router,
	backendClient vmcp.BackendClient,
	discoveryMgr discovery.Manager,
	backendRegistry vmcp.BackendRegistry,
	workflowDefs map[string]*composer.WorkflowDefinition,
) (*Server, error) {
	// Apply defaults
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	// Note: Port 0 means "let OS assign random port" - intentionally no default applied here.
	// CLI provides default via flag (4483), so Port is only 0 in tests for dynamic port assignment.
	if cfg.EndpointPath == "" {
		cfg.EndpointPath = "/mcp"
	}
	if cfg.Name == "" {
		cfg.Name = "toolhive-vmcp"
	}
	if cfg.Version == "" {
		cfg.Version = "0.1.0"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	sessionOwnerURL, err := normalizeSessionOwnerURL(cfg.SessionOwnerAdvertiseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid session owner advertise URL: %w", err)
	}

	// Create hooks for SDK integration
	hooks := &server.Hooks{}

	// Create mark3labs MCP server
	mcpServer := server.NewMCPServer(
		cfg.Name,
		cfg.Version,
		server.WithToolCapabilities(true), // Session-scoped capability updates send list_changed notifications
		server.WithResourceCapabilities(false, true), // Session-scoped resources may be refreshed live
		server.WithLogging(),
		server.WithHooks(hooks),
	)

	// Create SDK elicitation adapter for workflow engine
	// This wraps the mark3labs SDK to provide elicitation functionality to the composer
	sdkElicitationRequester := newSDKElicitationAdapter(mcpServer)

	// Create elicitation handler for workflow engine
	// This provides SDK-agnostic elicitation with security validation
	elicitationHandler := composer.NewDefaultElicitationHandler(sdkElicitationRequester)

	// Decorate backend client with telemetry if provider is configured
	// This must happen BEFORE creating the workflow engine so that workflow
	// backend calls are instrumented when they occur during workflow execution.
	if cfg.TelemetryProvider != nil {
		var err error
		// Get initial backends list from registry for telemetry setup
		initialBackends := backendRegistry.List(ctx)
		backendClient, err = monitorBackends(
			ctx,
			cfg.TelemetryProvider.MeterProvider(),
			cfg.TelemetryProvider.TracerProvider(),
			initialBackends,
			backendClient,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to monitor backends: %w", err)
		}
	}

	// Create workflow auditor if audit config is provided
	var workflowAuditor *audit.WorkflowAuditor
	if cfg.AuditConfig != nil {
		if err := cfg.AuditConfig.Validate(); err != nil {
			return nil, fmt.Errorf("invalid audit configuration: %w", err)
		}
		var err error
		workflowAuditor, err = audit.NewWorkflowAuditor(cfg.AuditConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create workflow auditor: %w", err)
		}
		slog.Info("workflow audit logging enabled")
	}

	// Create workflow engine (composer) for executing composite tools
	// The composer orchestrates multi-step workflows across backends
	// Use in-memory state store with 5-minute cleanup interval and 1-hour max age for completed workflows
	stateStore := composer.NewInMemoryStateStore(5*time.Minute, 1*time.Hour)
	workflowComposer := composer.NewWorkflowEngine(rt, backendClient, elicitationHandler, stateStore, workflowAuditor, nil)

	// composerFactory builds a per-session workflow engine at session registration
	// time, binding composite tool routing to the session's own routing table and
	// tool list. This removes composite tools' dependency on the discovery middleware
	// injecting DiscoveredCapabilities into the request context.
	sessionComposerFactory := func(sessionRT *vmcp.RoutingTable, sessionTools []vmcp.Tool) composer.Composer {
		return composer.NewWorkflowEngine(
			router.NewSessionRouter(sessionRT), backendClient, elicitationHandler, stateStore, workflowAuditor,
			sessionTools,
		)
	}

	// Validate workflows (fail fast on invalid definitions)
	workflowDefs, err = validateWorkflows(workflowComposer, workflowDefs)
	if err != nil {
		return nil, fmt.Errorf("workflow validation failed: %w", err)
	}

	// Create session manager using StreamableSession as the transport-layer placeholder.
	// StreamableSession is a lightweight implementation of transportsession.Session that
	// handles disconnect tracking, TTL, and metadata for Streamable HTTP connections.
	// It intentionally carries no vmcp-specific state — backend connections, routing
	// tables, tool lists, and token binding all live in the separate sessionmanager.Manager,
	// keyed by the same session ID.
	sessionManager := transportsession.NewManager(cfg.SessionTTL, transportsession.NewStreamableSession)

	sessionDataStorage, err := buildSessionDataStorage(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create session data storage: %w", err)
	}
	// Close sessionDataStorage if New() returns an error after this point so the
	// background cleanup goroutine does not leak.
	closeStorageOnErr := true
	defer func() {
		if closeStorageOnErr {
			_ = sessionDataStorage.Close()
		}
	}()

	// Create handler factory (used by adapter and for future dynamic registration)
	handlerFactory := adapter.NewDefaultHandlerFactory(rt, backendClient)

	// Create capability adapter (single source of truth for converting aggregator types to SDK types)
	capabilityAdapter := adapter.NewCapabilityAdapter(handlerFactory)

	// Create health monitor if configured
	var healthMon *health.Monitor
	if cfg.HealthMonitorConfig != nil {
		// Get initial backends list from registry for health monitoring setup
		initialBackends := backendRegistry.List(ctx)
		healthMon, err = health.NewMonitor(backendClient, initialBackends, *cfg.HealthMonitorConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create health monitor: %w", err)
		}
		slog.Info("health monitoring enabled",
			"check_interval", cfg.HealthMonitorConfig.CheckInterval,
			"unhealthy_threshold", cfg.HealthMonitorConfig.UnhealthyThreshold,
			"timeout", cfg.HealthMonitorConfig.Timeout,
			"degraded_threshold", cfg.HealthMonitorConfig.DegradedThreshold)
	} else {
		slog.Info("health monitoring disabled")
	}

	// Pass the whole factory config so the session manager constructs everything
	// it needs (optimizer wiring, composite tool layers, telemetry instruments).
	sessMgrCfg := &sessionmanager.FactoryConfig{
		Base:              cfg.SessionFactory,
		SessionTTL:        cfg.SessionTTL,
		WorkflowDefs:      workflowDefs,
		ComposerFactory:   sessionComposerFactory,
		OptimizerConfig:   cfg.OptimizerConfig,
		OptimizerFactory:  cfg.OptimizerFactory,
		TelemetryProvider: cfg.TelemetryProvider,
	}
	vmcpSessMgr, optimizerCleanup, err := sessionmanager.New(sessionDataStorage, sessMgrCfg, backendRegistry, healthMon)
	if err != nil {
		return nil, err
	}

	// Create Server instance
	srv := &Server{
		config:             cfg,
		mcpServer:          mcpServer,
		router:             rt,
		backendClient:      backendClient,
		handlerFactory:     handlerFactory,
		discoveryMgr:       discoveryMgr,
		backendRegistry:    backendRegistry,
		sessionManager:     sessionManager,
		sessionDataStorage: sessionDataStorage,
		sessionOwnerURL:    sessionOwnerURL,
		ownerForwardClient: &http.Client{Transport: http.DefaultTransport},
		capabilityAdapter:  capabilityAdapter,
		ready:              make(chan struct{}),
		healthMonitor:      healthMon,
		statusReporter:     cfg.StatusReporter,
		vmcpSessionMgr:     vmcpSessMgr,
	}

	if cfg.TelemetryProvider != nil {
		if err := monitorSessionCardinality(cfg.TelemetryProvider.MeterProvider(), srv); err != nil {
			return nil, fmt.Errorf("failed to monitor session cardinality: %w", err)
		}
	}

	if optimizerCleanup != nil {
		srv.shutdownFuncs = append(srv.shutdownFuncs, optimizerCleanup)
	}

	if healthMon != nil {
		healthMon.AddOnStatusChange(srv.handleBackendStatusChange)
	}

	// Late-bind capability-change notifications: when a backend sends
	// tools/list_changed the server refreshes all sessions that contain it.
	if reg, ok := cfg.SessionFactory.(vmcpsession.CapabilityChangeRegistrar); ok {
		reg.SetOnCapabilityChange(srv.handleBackendCapabilityChange)
	}

	// Repair session-scoped SDK state for valid sessions that arrive on a
	// different replica than the one that originally registered them.
	hooks.AddOnRequestInitialization(func(ctx context.Context, id any, message any) error {
		return srv.handleSessionRequestInitialization(ctx, id, message)
	})

	// Register OnRegisterSession hook to inject capabilities after SDK registers session.
	// See handleSessionRegistration for implementation details.
	hooks.AddOnRegisterSession(func(ctx context.Context, session server.ClientSession) {
		srv.handleSessionRegistration(ctx, session)
	})
	hooks.AddOnUnregisterSession(func(_ context.Context, session server.ClientSession) {
		srv.activeClientSessions.Delete(session.SessionID())
	})

	// Disarm the close-on-error guard: Server is fully constructed.
	closeStorageOnErr = false
	return srv, nil
}

// Handler builds and returns the MCP HTTP handler without starting a listener.
// This enables embedding the vmcp server inside another HTTP server or framework.
//
// The returned handler includes all routes (health, metrics, well-known, MCP)
// and the full middleware chain (recovery, header validation, auth, audit,
// discovery, backend enrichment, MCP parsing, telemetry).
//
// Each call builds a fresh handler. The method is safe to call multiple times.
// All returned handlers share the same underlying MCPServer and SessionManager,
// so callers should not serve concurrent traffic through multiple handlers.
func (s *Server) Handler(_ context.Context) (http.Handler, error) {
	// Create Streamable HTTP server with ToolHive session management
	streamableServer := server.NewStreamableHTTPServer(
		s.mcpServer,
		server.WithEndpointPath(s.config.EndpointPath),
		server.WithSessionIdManager(s.vmcpSessionMgr),
		server.WithHeartbeatInterval(defaultHeartbeatInterval),
		server.WithSessionIdleTTL(s.config.SessionTTL),
	)

	// Create HTTP mux with separated authenticated and unauthenticated routes
	mux := http.NewServeMux()

	// Unauthenticated health endpoints
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ping", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReadiness)
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/api/backends/health", s.handleBackendHealth)

	// Optional Prometheus metrics endpoint (unauthenticated)
	if s.config.TelemetryProvider != nil {
		if prometheusHandler := s.config.TelemetryProvider.PrometheusHandler(); prometheusHandler != nil {
			mux.Handle("/metrics", prometheusHandler)
			slog.Info("prometheus metrics endpoint enabled at /metrics")
		} else {
			slog.Warn("prometheus metrics endpoint is not enabled, but telemetry provider is configured")
		}
	}

	// RFC 9728 protected resource metadata.
	// Always register a .well-known handler so OAuth discovery requests get a
	// clean response (404 JSON when auth is off) instead of falling through to
	// the MCP handler, which rejects GETs with a 406 JSON-RPC error that
	// breaks Claude Code's OAuth error parsing.
	wellKnownHandler := auth.NewWellKnownHandler(s.config.AuthInfoHandler)
	mux.Handle("/.well-known/", wellKnownHandler)
	if s.config.AuthInfoHandler != nil {
		slog.Debug("RFC 9728 OAuth protected resource metadata enabled")
	}

	// Register embedded auth server routes if configured
	if s.config.AuthServer != nil {
		s.config.AuthServer.RegisterHandlers(mux)
		slog.Debug("embedded authorization server routes registered")
	}

	// MCP endpoint - apply middleware chain (wrapping order, execution happens in reverse):
	// Code wraps: auth+parser → audit → discovery → annotation-enrichment →
	//   authz → backend-enrichment → MCP-parsing → telemetry
	// Execution order: recovery → header-val → auth+parser → audit →
	//   discovery → annotation-enrichment → authz → backend-enrichment →
	//   MCP-parsing → telemetry → handler

	var mcpHandler http.Handler = streamableServer

	if s.config.TelemetryProvider != nil {
		mcpHandler = s.config.TelemetryProvider.Middleware(s.config.Name, "streamable-http")(mcpHandler)
		slog.Info("telemetry middleware enabled for MCP endpoints")
	}

	// Apply MCP parsing middleware to extract JSON-RPC method from request body.
	// This runs before telemetry so that recordMetrics can label metrics with the
	// actual mcp_method (e.g. "tools/call", "initialize") instead of "unknown".
	// Note: ParsingMiddleware is also composed inside the auth middleware (for audit/authz).
	// The second application here is a no-op because the context already holds a
	// ParsedMCPRequest; it exists only so the telemetry layer works correctly even
	// when auth middleware is nil.
	mcpHandler = mcpparser.ParsingMiddleware(mcpHandler)

	// Apply backend enrichment middleware if audit is configured
	// This runs after discovery populates the routing table, so it can extract backend names
	if s.config.AuditConfig != nil {
		mcpHandler = s.backendEnrichmentMiddleware(mcpHandler)
		slog.Info("backend enrichment middleware enabled for audit events")
	}

	// Apply authorization middleware if configured (runs AFTER discovery in execution).
	// Wrapping it here (before discovery wrap) means discovery runs first, then authz.
	if s.config.AuthzMiddleware != nil {
		mcpHandler = s.config.AuthzMiddleware(mcpHandler)
		slog.Info("authorization middleware enabled for MCP endpoints (post-discovery)")
	}

	// Apply annotation enrichment middleware (runs after discovery, before authz in execution).
	// Reads tool annotations from discovered capabilities and injects them into the
	// request context so the authz middleware can make annotation-aware decisions.
	if s.config.AuthzMiddleware != nil {
		mcpHandler = AnnotationEnrichmentMiddleware(mcpHandler)
		slog.Info("annotation enrichment middleware enabled for MCP endpoints")
	}

	// Apply discovery middleware (runs after audit/auth middleware)
	// Discovery middleware performs per-request capability aggregation with user context.
	// vmcpSessionMgr (MultiSessionGetter) is used to retrieve the fully-formed MultiSession
	// for subsequent requests so the routing table can be injected into context.
	// The backend registry provides a dynamic backend list (supports DynamicRegistry for K8s).
	// The health monitor enables filtering based on current health status (respects circuit breaker).
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	var healthStatusProvider health.StatusProvider
	if healthMon != nil {
		healthStatusProvider = healthMon
	}
	mcpHandler = discovery.Middleware(
		s.discoveryMgr, s.backendRegistry, s.vmcpSessionMgr, healthStatusProvider,
		discovery.WithSessionScopedRouting(),
	)(mcpHandler)
	slog.Info("discovery middleware enabled for lazy per-user capability discovery")

	// Apply audit middleware if configured (runs after auth, before discovery)
	if s.config.AuditConfig != nil {
		if err := s.config.AuditConfig.Validate(); err != nil {
			return nil, fmt.Errorf("invalid audit configuration: %w", err)
		}
		auditor, err := audit.NewAuditorWithTransport(
			s.config.AuditConfig,
			"streamable-http", // vMCP uses streamable HTTP transport
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create auditor: %w", err)
		}
		mcpHandler = auditor.Middleware(mcpHandler)
		slog.Info("audit middleware enabled for MCP endpoints")
	}

	// Apply authentication middleware if configured (runs first in chain)
	if s.config.AuthMiddleware != nil {
		mcpHandler = s.config.AuthMiddleware(mcpHandler)
		slog.Info("authentication middleware enabled for MCP endpoints")
	}

	// Restore the health-check marker from the wire so receiving spokes can
	// serve inter-vMCP health probes without opening full session-scoped
	// backend connections.
	mcpHandler = healthProbeContextMiddleware(mcpHandler)

	// Forward the sticky-only live-session paths (listen/delete and client
	// replies to server-initiated requests) back to the replica that owns the
	// SDK session state. Regular tool/resource requests stay local and rely on
	// session rehydration instead.
	mcpHandler = s.ownerForwardingMiddleware(mcpHandler)

	// Apply Accept header validation (rejects GET requests without Accept: text/event-stream)
	mcpHandler = headerValidatingMiddleware(mcpHandler)

	// Clear the write deadline for qualifying SSE connections (GET +
	// Accept: text/event-stream + MCP endpoint path) so the server-level
	// WriteTimeout does not kill long-lived SSE streams (see golang/go#16100).
	// Non-qualifying requests are left untouched; http.Server.WriteTimeout
	// (defaultWriteTimeout) remains in effect for them.
	mcpHandler = transportmiddleware.WriteTimeout(s.config.EndpointPath)(mcpHandler)

	// Apply recovery middleware as outermost (catches panics from all inner middleware)
	mcpHandler = recovery.Middleware(mcpHandler)
	slog.Info("recovery middleware enabled for MCP endpoints")

	mux.Handle("/", mcpHandler)

	return mux, nil
}

// Start starts the Virtual MCP Server and begins serving requests.
//
//nolint:gocyclo // Complexity from health monitoring and startup orchestration is acceptable
func (s *Server) Start(ctx context.Context) error {
	// Build the HTTP handler (middleware chain, routes, mux)
	handler, err := s.Handler(ctx)
	if err != nil {
		return fmt.Errorf("failed to build handler: %w", err)
	}

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
		MaxHeaderBytes:    defaultMaxHeaderBytes,
	}

	// Create listener (allows port 0 to bind to random available port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}

	s.listenerMu.Lock()
	s.listener = listener
	s.listenerMu.Unlock()

	actualAddr := listener.Addr().String()
	slog.Info("starting Virtual MCP Server", "address", actualAddr, "endpoint", s.config.EndpointPath)
	slog.Info("health endpoints available",
		"health", actualAddr+"/health",
		"ping", actualAddr+"/ping",
		"status", actualAddr+"/status",
		"backends_health", actualAddr+"/api/backends/health")

	// Start server in background
	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Signal that the server is ready (listener created and serving started)
	s.readyOnce.Do(func() {
		close(s.ready)
	})

	// Start health monitor if configured
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon != nil {
		if err := healthMon.Start(ctx); err != nil {
			// Log error and disable health monitoring - treat as if it wasn't configured
			// This ensures getter methods correctly report monitoring as disabled
			slog.Warn("failed to start health monitor, disabling health monitoring", "error", err)
			s.healthMonitorMu.Lock()
			s.healthMonitor = nil
			s.healthMonitorMu.Unlock()
		} else {
			slog.Info("health monitor started")
		}
	}

	// Start status reporter if configured
	if s.statusReporter != nil {
		shutdown, err := s.statusReporter.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start status reporter: %w", err)
		}
		s.shutdownFuncs = append(s.shutdownFuncs, shutdown)

		// Create internal context for status reporting goroutine lifecycle
		// This ensures the goroutine is cleaned up on all exit paths
		statusReportingCtx, statusReportingCancel := context.WithCancel(ctx)

		// Prepare status reporting config
		statusConfig := DefaultStatusReportingConfig()
		statusConfig.Reporter = s.statusReporter
		if s.config.StatusReportingInterval > 0 {
			statusConfig.Interval = s.config.StatusReportingInterval
		}

		// Start periodic status reporting in background
		go s.periodicStatusReporting(statusReportingCtx, statusConfig)

		// Append cancel function to shutdownFuncs for cleanup
		// Done after starting goroutine to avoid race if Stop() is called immediately
		s.shutdownFuncs = append(s.shutdownFuncs, func(context.Context) error {
			statusReportingCancel()
			return nil
		})
	}

	// Wait for either context cancellation or server error
	select {
	case <-ctx.Done():
		slog.Info("context cancelled, shutting down server")
		return s.Stop(context.Background())
	case err := <-errCh:
		// HTTP server error - log and tear down cleanly
		slog.Error("hTTP server error", "error", err)
		if stopErr := s.Stop(context.Background()); stopErr != nil {
			// Combine errors if Stop() also fails
			return fmt.Errorf("server error: %w; stop error: %v", err, stopErr)
		}
		return err
	}
}

// Stop gracefully stops the Virtual MCP Server.
func (s *Server) Stop(ctx context.Context) error {
	slog.Info("stopping Virtual MCP Server")

	var errs []error

	// Stop HTTP server (this internally closes the listener)
	if s.httpServer != nil {
		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(ctx, defaultShutdownTimeout)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, fmt.Errorf("failed to shutdown HTTP server: %w", err))
		}
	}

	// Clear listener reference (already closed by httpServer.Shutdown)
	s.listenerMu.Lock()
	s.listener = nil
	s.listenerMu.Unlock()

	// Stop health monitor to clean up health check goroutines
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon != nil {
		if err := healthMon.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop health monitor: %w", err))
		}
	}

	// Run shutdown functions (e.g., status reporter cleanup, future components)
	for _, shutdown := range s.shutdownFuncs {
		if err := shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to execute shutdown function: %w", err))
		}
	}

	// Stop session manager after HTTP server shutdown
	if s.sessionManager != nil {
		if err := s.sessionManager.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("failed to stop session manager: %w", err))
		}
	}

	// Stop discovery manager to clean up background goroutines
	if s.discoveryMgr != nil {
		s.discoveryMgr.Stop()
	}

	// Close session data storage last: HTTP server is down (no new in-flight requests),
	// all other components have stopped (no further restore or liveness checks).
	if s.sessionDataStorage != nil {
		if err := s.sessionDataStorage.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close session data storage: %w", err))
		}
	}

	if len(errs) > 0 {
		slog.Error("errors during shutdown", "errors", errs)
		return errors.Join(errs...)
	}

	slog.Info("virtual MCP Server stopped")
	return nil
}

// Address returns the server's actual listen address.
// If the server is started with port 0, this returns the actual bound port.
func (s *Server) Address() string {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()

	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// handleHealth handles /health and /ping HTTP requests.
// Returns 200 OK if the server is running and able to respond.
//
// Security Note: This endpoint is unauthenticated and intentionally minimal.
// It only confirms the HTTP server is responding. No version information,
// session counts, or operational metrics are exposed to prevent information
// disclosure in multi-tenant scenarios.
//
// For operational monitoring, implement an authenticated /metrics endpoint
// that requires proper authorization.
func (*Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	response := map[string]string{
		"status": "ok",
	}

	w.Header().Set("Content-Type", "application/json")
	// Always send 200 OK - even if JSON encoding fails below, the server is responding
	w.WriteHeader(http.StatusOK)

	// Encode response. If this fails (extremely unlikely for simple map[string]string),
	// the 200 OK status has already been sent above.
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode health response", "error", err)
	}
}

// handleReadiness handles /readyz HTTP requests for Kubernetes readiness probes.
//
// In dynamic mode (K8s with outgoingAuth.source: discovered), this endpoint gates
// readiness on the controller-runtime manager's cache sync status. The pod will
// not be marked ready until the manager has populated its cache with current
// backend information from the MCPGroup.
//
// In static mode (CLI or K8s with inline backends), this always returns 200 OK
// since there's no cache to sync.
//
// Design Pattern:
// This follows the same readiness gating pattern used by cert-manager and ArgoCD:
// - /health: Always returns 200 if server is responding (liveness probe)
// - /readyz: Returns 503 until caches synced, then 200 (readiness probe)
//
// K8s Configuration:
//
//	readinessProbe:
//	  httpGet:
//	    path: /readyz
//	    port: 4483
//	  initialDelaySeconds: 5
//	  periodSeconds: 5
//	  timeoutSeconds: 5
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	// Static mode: always ready (no watcher, no cache to sync)
	if s.config.Watcher == nil {
		response := map[string]string{
			"status": "ready",
			"mode":   "static",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode readiness response", "error", err)
		}
		return
	}

	// Dynamic mode: gate readiness on cache sync
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if !s.config.Watcher.WaitForCacheSync(ctx) {
		// Cache not synced yet - return 503 Service Unavailable
		response := map[string]string{
			"status": "not_ready",
			"mode":   "dynamic",
			"reason": "cache_sync_pending",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to encode readiness response", "error", err)
		}
		return
	}

	// Cache synced - ready to serve requests
	response := map[string]string{
		"status": "ready",
		"mode":   "dynamic",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode readiness response", "error", err)
	}
}

// SessionManager returns the session manager instance.
// This is useful for testing and monitoring.
func (s *Server) SessionManager() *transportsession.Manager {
	return s.sessionManager
}

// Ready returns a channel that is closed when the server is ready to accept connections.
// This is useful for testing and synchronization.
func (s *Server) Ready() <-chan struct{} {
	return s.ready
}

// setSessionResourcesDirect sets resources directly on the session via the SessionWithResources
// interface, analogous to setSessionToolsDirect for resources.
func setSessionResourcesDirect(session server.ClientSession, resources []server.ServerResource) error {
	sessionWithResources, ok := session.(server.SessionWithResources)
	if !ok {
		return fmt.Errorf("session does not support per-session resources")
	}

	existing := sessionWithResources.GetSessionResources()
	resourceMap := make(map[string]server.ServerResource, len(existing)+len(resources))
	for k, v := range existing {
		resourceMap[k] = v
	}
	for _, res := range resources {
		resourceMap[res.Resource.URI] = res
	}
	sessionWithResources.SetSessionResources(resourceMap)
	return nil
}

// replaceSessionResourcesDirect replaces the session-specific resource set.
// Returns true when the visible resource URIs changed.
func replaceSessionResourcesDirect(session server.ClientSession, resources []server.ServerResource) (bool, error) {
	sessionWithResources, ok := session.(server.SessionWithResources)
	if !ok {
		return false, fmt.Errorf("session does not support per-session resources")
	}

	existing := sessionWithResources.GetSessionResources()
	newResources := make(map[string]server.ServerResource, len(resources))
	for _, res := range resources {
		newResources[res.Resource.URI] = res
	}

	changed := len(existing) != len(newResources)
	if !changed {
		for uri := range existing {
			if _, ok := newResources[uri]; !ok {
				changed = true
				break
			}
		}
	}

	sessionWithResources.SetSessionResources(newResources)
	return changed, nil
}

// setSessionToolsDirect sets tools directly on the session via the SessionWithTools
// interface, bypassing MCPServer.AddSessionTools. This avoids sending notifications
// through the session's notification channel, which would accumulate as stale
// messages during session registration (the notification goroutine from the
// initialize request has already exited at that point).
func setSessionToolsDirect(session server.ClientSession, tools []server.ServerTool) error {
	sessionWithTools, ok := session.(server.SessionWithTools)
	if !ok {
		return fmt.Errorf("session does not support per-session tools")
	}

	// Merge with any existing tools (preserves tools set by earlier calls)
	existing := sessionWithTools.GetSessionTools()
	toolMap := make(map[string]server.ServerTool, len(existing)+len(tools))
	for k, v := range existing {
		toolMap[k] = v
	}
	for _, tool := range tools {
		toolMap[tool.Tool.Name] = tool
	}
	sessionWithTools.SetSessionTools(toolMap)
	return nil
}

// replaceSessionToolsDirect replaces the session-specific tool set.
// Returns true when the visible tool names changed.
func replaceSessionToolsDirect(session server.ClientSession, tools []server.ServerTool) (bool, error) {
	sessionWithTools, ok := session.(server.SessionWithTools)
	if !ok {
		return false, fmt.Errorf("session does not support per-session tools")
	}

	existing := sessionWithTools.GetSessionTools()
	newTools := make(map[string]server.ServerTool, len(tools))
	for _, tool := range tools {
		newTools[tool.Tool.Name] = tool
	}

	changed := len(existing) != len(newTools)
	if !changed {
		for name := range existing {
			if _, ok := newTools[name]; !ok {
				changed = true
				break
			}
		}
	}

	sessionWithTools.SetSessionTools(newTools)
	return changed, nil
}

// handleSessionRegistration processes a new MCP session registration.
// It fires AFTER the session is registered in the SDK.
func (s *Server) handleSessionRegistration(
	ctx context.Context,
	session server.ClientSession,
) {
	registration := s.beginSessionRegistration(session.SessionID())
	defer s.finishSessionRegistration(session.SessionID(), registration)

	// Error is logged and handled within handleSessionRegistrationImpl.
	// The session is terminated on failure; no further action needed here.
	if err := s.handleSessionRegistrationImpl(ctx, session); err != nil {
		return
	}
	s.activeClientSessions.Store(session.SessionID(), session)
}

// handleSessionRegistrationImpl handles session registration.
//
// It is invoked from handleSessionRegistration and:
//  1. Creates a MultiSession with real backend HTTP connections via CreateSession().
//  2. Retrieves SDK-format tools and resources with session-scoped routing handlers.
//  3. Registers backend tools, composite tools, and resources with the SDK for the session.
//
// Tool and resource calls are routed directly through the session's backend connections
// rather than through the global router and discovery middleware.
// Composite tool executors use the shared backend client and router.
//
// # Current capability surface
//
//   - Optimizer mode: when configured, all tools (backend + composite) are
//     indexed into the optimizer and only find_tool/call_tool are exposed,
//     using session-scoped tool handlers.
//
//   - Prompts: not supported until the SDK adds AddSessionPrompts.
func (s *Server) handleSessionRegistrationImpl(ctx context.Context, session server.ClientSession) (retErr error) {
	// The SDK invokes this hook with the original request context. For
	// initialize over streamable HTTP, the response has already been written by
	// the time registration runs, so a fast client-side close can cancel the
	// request context while backend initialization is still in progress. Detach
	// from request cancellation, but preserve request-scoped values such as
	// identity and session, then bound the work with a server-side timeout.
	registrationCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		defaultSessionRegistrationTimeout,
	)
	defer cancel()
	ctx = registrationCtx

	sessionID := session.SessionID()
	slog.Debug("creating session-scoped backends", "session_id", sessionID)

	if health.IsHealthCheck(ctx) {
		// Health probes validate connectivity, not tool completeness.
		// Discovery is intentionally skipped for probes to avoid slow
		// backends inflating probe response time. If cached capabilities
		// happen to be available in the context they are injected;
		// otherwise the session remains empty, which is fine — the hub's
		// health checker only inspects timing and errors.
		if err := s.injectHealthCheckCapabilities(ctx, session, true, true); err != nil {
			slog.Debug("health probe registered without capabilities (discovery skipped)",
				"session_id", sessionID)
		} else {
			slog.Debug("health probe registered with cached capabilities",
				"session_id", sessionID,
				"tool_count", sessionToolCount(session),
				"resource_count", sessionResourceCount(session))
		}
		return nil
	}

	// Defer cleanup: if any error occurs, terminate the session and log failures.
	defer func() {
		if retErr != nil {
			if _, termErr := s.vmcpSessionMgr.Terminate(sessionID); termErr != nil {
				slog.Warn("failed to clean up session after error",
					"session_id", sessionID,
					"error", termErr,
					"original_error", retErr)
			}
		}
	}()

	// NOTE: the initialize response (including the Mcp-Session-Id header) has
	// already been sent to the client before this hook fires. Any error below
	// terminates the session internally, but the client holds a session ID that
	// will appear to have no tools (tool calls will return "not found" from the
	// SDK). This is an architectural constraint of the two-phase pattern — there
	// is no way to retract the session ID after it has been sent.
	//
	// NOTE: there is a brief race window between the client receiving the session
	// ID and this hook completing. A client that pipelines a tools/call immediately
	// after initialize may receive a "tool not found" error before AddSessionTools
	// completes. Conforming MCP clients call tools/list before tools/call, so this
	// window is expected to be harmless in practice.
	multiSession, retErr := s.vmcpSessionMgr.CreateSession(ctx, sessionID)
	if retErr != nil {
		slog.Error("failed to create session-scoped backends",
			"session_id", sessionID,
			"error", retErr)
		return retErr
	}
	if s.sessionOwnerURL != "" {
		if retErr = s.vmcpSessionMgr.SetSessionMetadataValue(
			ctx,
			sessionID,
			multiSession,
			sessiontypes.MetadataKeyOwnerURL,
			s.sessionOwnerURL,
		); retErr != nil {
			slog.Error("failed to persist session owner metadata",
				"session_id", sessionID,
				"owner_url", s.sessionOwnerURL,
				"error", retErr)
			return retErr
		}
	}

	// Uniform registration — same code path regardless of which decorators are active.
	// session.Tools() returns the final decorated tool list.
	adaptedTools, retErr := s.vmcpSessionMgr.GetAdaptedTools(sessionID)
	if retErr != nil {
		slog.Error("failed to get session-scoped tools",
			"session_id", sessionID,
			"error", retErr)
		return retErr
	}

	adaptedResources, retErr := s.vmcpSessionMgr.GetAdaptedResources(sessionID)
	if retErr != nil {
		slog.Error("failed to get session-scoped resources",
			"session_id", sessionID,
			"error", retErr)
		return retErr
	}

	if len(adaptedResources) > 0 {
		if err := setSessionResourcesDirect(session, adaptedResources); err != nil {
			slog.Error("failed to add session resources", "session_id", sessionID, "error", err)
			return err
		}
	}

	if len(adaptedTools) > 0 {
		if err := setSessionToolsDirect(session, adaptedTools); err != nil {
			slog.Error("failed to add session tools", "session_id", sessionID, "error", err)
			return err
		}
	}

	slog.Info("session capabilities injected",
		"session_id", sessionID,
		"tool_count", len(adaptedTools))
	return nil
}

func (s *Server) handleSessionRequestInitialization(
	ctx context.Context,
	_ any,
	message any,
) error {
	method, err := parseRequestMethod(message)
	if err != nil {
		slog.Debug("failed to parse MCP method during session hydration", "error", err)
		return nil
	}

	needsTools, needsResources := requestHydrationNeeds(method)
	if !needsTools && !needsResources {
		return nil
	}

	session := server.ClientSessionFromContext(ctx)
	if session == nil || session.SessionID() == "" {
		return nil
	}

	needsTools = needsTools && sessionToolCount(session) == 0
	needsResources = needsResources && sessionResourceCount(session) == 0
	if !needsTools && !needsResources {
		return nil
	}

	if health.IsHealthCheck(ctx) {
		// Best-effort injection: if cached capabilities are available in the
		// context they are injected; otherwise the request proceeds with an
		// empty list. This is safe because health probes only validate
		// connectivity and timing — the hub's health checker discards the
		// actual tool/resource list.
		if err := s.injectHealthCheckCapabilities(ctx, session, needsTools, needsResources); err != nil {
			slog.Debug("health probe request proceeding without capabilities (discovery skipped)",
				"session_id", session.SessionID(),
				"method", method)
		}
		return nil
	}

	if err := s.waitForSessionRegistration(ctx, session.SessionID()); err != nil {
		slog.Debug("session registration wait finished without full readiness",
			"session_id", session.SessionID(),
			"method", method,
			"error", err)
	}

	hydrationCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultSessionHydrationTimeout)
	defer cancel()

	if err := s.rehydrateSessionCapabilities(hydrationCtx, session, needsTools, needsResources); err != nil {
		slog.Warn("failed to rehydrate session-scoped capabilities",
			"session_id", session.SessionID(),
			"method", method,
			"error", err)
	}

	return nil
}

func (s *Server) injectHealthCheckCapabilities(
	ctx context.Context,
	session server.ClientSession,
	needsTools bool,
	needsResources bool,
) error {
	capabilities, ok := discovery.DiscoveredCapabilitiesFromContext(ctx)
	if !ok || capabilities == nil {
		return fmt.Errorf("discovered capabilities unavailable for health probe")
	}
	if s.capabilityAdapter == nil {
		return fmt.Errorf("capability adapter is not configured")
	}

	if needsResources {
		adaptedResources := s.capabilityAdapter.ToSDKResources(capabilities.Resources)
		if len(adaptedResources) > 0 {
			if err := setSessionResourcesDirect(session, adaptedResources); err != nil {
				return err
			}
		}
	}

	if needsTools {
		adaptedTools, err := s.capabilityAdapter.ToSDKTools(capabilities.Tools)
		if err != nil {
			return err
		}
		if len(adaptedTools) > 0 {
			if err := setSessionToolsDirect(session, adaptedTools); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Server) beginSessionRegistration(sessionID string) *sessionRegistrationState {
	if sessionID == "" {
		return nil
	}

	state := newSessionRegistrationState()
	actual, loaded := s.inFlightRegistrations.LoadOrStore(sessionID, state)
	if loaded {
		if existing, ok := actual.(*sessionRegistrationState); ok {
			return existing
		}
		return nil
	}
	return state
}

func (s *Server) finishSessionRegistration(sessionID string, state *sessionRegistrationState) {
	if sessionID == "" || state == nil {
		return
	}

	state.close()
	s.inFlightRegistrations.CompareAndDelete(sessionID, state)
}

func (s *Server) lookupSessionRegistration(sessionID string) *sessionRegistrationState {
	if sessionID == "" {
		return nil
	}

	value, ok := s.inFlightRegistrations.Load(sessionID)
	if !ok {
		return nil
	}
	state, ok := value.(*sessionRegistrationState)
	if !ok {
		return nil
	}
	return state
}

func (s *Server) waitForSessionRegistration(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	if _, ok := s.vmcpSessionMgr.GetMultiSession(sessionID); ok {
		return nil
	}

	registration := s.lookupSessionRegistration(sessionID)
	if registration == nil {
		isTerminated, err := s.vmcpSessionMgr.Validate(sessionID)
		if err != nil || isTerminated {
			return nil
		}

		graceCtx, cancel := context.WithTimeout(ctx, defaultSessionRegistrationGracePeriod)
		defer cancel()

		registration, err = s.waitForRegistrationMarker(graceCtx, sessionID)
		if err != nil || registration == nil {
			return err
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, defaultSessionRegistrationWaitTimeout)
	defer cancel()

	select {
	case <-registration.done:
		return nil
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func (s *Server) waitForRegistrationMarker(
	ctx context.Context,
	sessionID string,
) (*sessionRegistrationState, error) {
	registration := s.lookupSessionRegistration(sessionID)
	if registration != nil {
		return registration, nil
	}

	ticker := time.NewTicker(defaultSessionRegistrationPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			registration = s.lookupSessionRegistration(sessionID)
			if registration != nil {
				return registration, nil
			}
		}
	}
}

func requestHydrationNeeds(method mcp.MCPMethod) (bool, bool) {
	switch method {
	case mcp.MethodToolsList, mcp.MethodToolsCall:
		return true, false
	case mcp.MethodResourcesList, mcp.MethodResourcesRead, mcp.MethodResourcesTemplatesList:
		return false, true
	default:
		return false, false
	}
}

func parseRequestMethod(message any) (mcp.MCPMethod, error) {
	var raw json.RawMessage

	switch msg := message.(type) {
	case json.RawMessage:
		raw = msg
	case []byte:
		raw = json.RawMessage(msg)
	default:
		return "", fmt.Errorf("unexpected request hook message type %T", message)
	}

	var envelope struct {
		Method mcp.MCPMethod `json:"method"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", err
	}

	return envelope.Method, nil
}

func healthProbeContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !health.HasProbeHeader(r) {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(health.WithHealthCheckMarker(r.Context())))
	})
}

func (s *Server) rehydrateSessionCapabilities(
	ctx context.Context,
	session server.ClientSession,
	hydrateTools bool,
	hydrateResources bool,
) error {
	sessionID := session.SessionID()

	if _, ok := s.vmcpSessionMgr.GetMultiSession(sessionID); !ok {
		return fmt.Errorf("session %q not found", sessionID)
	}

	if hydrateResources {
		adaptedResources, err := s.vmcpSessionMgr.GetAdaptedResources(sessionID)
		if err != nil {
			return fmt.Errorf("get adapted resources: %w", err)
		}
		if _, err := replaceSessionResourcesDirect(session, adaptedResources); err != nil {
			return fmt.Errorf("replace session resources: %w", err)
		}
	}

	if hydrateTools {
		adaptedTools, err := s.vmcpSessionMgr.GetAdaptedTools(sessionID)
		if err != nil {
			return fmt.Errorf("get adapted tools: %w", err)
		}
		if _, err := replaceSessionToolsDirect(session, adaptedTools); err != nil {
			return fmt.Errorf("replace session tools: %w", err)
		}
	}

	return nil
}

func (s *Server) ownerForwardingMiddleware(next http.Handler) http.Handler {
	if s.sessionDataStorage == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded, err := s.tryForwardSessionRequest(w, r)
		if err != nil {
			if errors.Is(err, errSessionOwnerUnavailable) {
				s.handleOwnerUnavailable(r)
			}
			slog.Warn("failed to forward live session request to owner",
				"method", r.Method,
				"path", r.URL.Path,
				"error", err)
			if !forwarded {
				next.ServeHTTP(w, r)
			}
			return
		}
		if forwarded {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleOwnerUnavailable restores an orphaned session and claims ownership
// so subsequent requests route directly to this pod.
func (s *Server) handleOwnerUnavailable(r *http.Request) {
	if s.sessionOwnerURL == "" || s.vmcpSessionMgr == nil {
		return
	}
	sessionID := r.Header.Get(server.HeaderKeySessionID)
	if sessionID == "" {
		return
	}

	ms, ok := s.vmcpSessionMgr.GetMultiSession(sessionID)
	if !ok || ms == nil {
		return
	}

	currentOwner := ms.GetMetadata()[sessiontypes.MetadataKeyOwnerURL]
	if currentOwner == s.sessionOwnerURL {
		return
	}

	if err := s.vmcpSessionMgr.SetSessionMetadataValue(
		r.Context(), sessionID, ms,
		sessiontypes.MetadataKeyOwnerURL,
		s.sessionOwnerURL,
	); err != nil {
		slog.Warn("failed to claim session ownership after restore",
			"session_id", sessionID, "error", err)
		return
	}

	slog.Info("session ownership claimed after pod loss",
		"session_id", sessionID,
		"previous_owner", currentOwner,
		"new_owner", s.sessionOwnerURL)
}

func (s *Server) tryForwardSessionRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if s.sessionOwnerURL == "" {
		return false, nil
	}
	if r.Header.Get(sessionOwnerForwardedHeader) == sessionOwnerForwardedValue {
		return false, nil
	}

	sessionID := r.Header.Get(server.HeaderKeySessionID)
	if sessionID == "" {
		return false, nil
	}

	shouldForward, err := shouldForwardToSessionOwner(r)
	if err != nil {
		return false, err
	}
	if !shouldForward {
		return false, nil
	}

	if _, ok := s.activeClientSessions.Load(sessionID); ok {
		return false, nil
	}

	ownerURL, err := s.loadSessionOwnerURL(r.Context(), sessionID)
	if err != nil {
		return false, fmt.Errorf("load session owner URL for %q: %w", sessionID, err)
	}
	if ownerURL == "" || ownerURL == s.sessionOwnerURL {
		return false, nil
	}

	if err := s.forwardRequestToSessionOwner(w, r, ownerURL); err != nil {
		if errors.Is(err, errSessionOwnerUnavailable) {
			return false, err
		}
		return true, err
	}
	return true, nil
}

func shouldForwardToSessionOwner(r *http.Request) (bool, error) {
	switch r.Method {
	case http.MethodGet, http.MethodDelete:
		return true, nil
	case http.MethodPost:
		envelope, err := parseForwardableEnvelope(r)
		if err != nil {
			return false, nil
		}
		if isSessionScopedClientResponse(envelope) {
			return true, nil
		}
		return envelope.Method == mcp.MethodSetLogLevel || envelope.Method == mcp.MethodNotificationElicitationComplete, nil
	default:
		return false, nil
	}
}

type forwardableEnvelope struct {
	Method mcp.MCPMethod   `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

func parseForwardableEnvelope(r *http.Request) (forwardableEnvelope, error) {
	var envelope forwardableEnvelope

	if r.Body == nil {
		return envelope, io.EOF
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return envelope, err
	}

	if closeErr := r.Body.Close(); closeErr != nil {
		slog.Debug("failed to close request body after peek", "error", closeErr)
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return envelope, io.EOF
	}

	if err := json.Unmarshal(body, &envelope); err != nil {
		return envelope, err
	}

	return envelope, nil
}

func isSessionScopedClientResponse(envelope forwardableEnvelope) bool {
	return envelope.Method == "" &&
		len(envelope.ID) > 0 &&
		(len(envelope.Result) > 0 || len(envelope.Error) > 0)
}

func (s *Server) loadSessionOwnerURL(ctx context.Context, sessionID string) (string, error) {
	loadCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultSessionOwnerLookupTimeout)
	defer cancel()

	metadata, err := s.sessionDataStorage.Load(loadCtx, sessionID)
	if err != nil {
		return "", err
	}

	ownerURL, err := normalizeSessionOwnerURL(metadata[sessiontypes.MetadataKeyOwnerURL])
	if err != nil {
		return "", fmt.Errorf("normalize stored owner URL: %w", err)
	}
	return ownerURL, nil
}

func (s *Server) forwardRequestToSessionOwner(
	w http.ResponseWriter,
	r *http.Request,
	ownerURL string,
) error {
	targetReq, err := cloneRequestForOwner(r, ownerURL)
	if err != nil {
		return err
	}

	client := s.ownerForwardClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(targetReq)
	if err != nil {
		return fmt.Errorf("%w: %w", errSessionOwnerUnavailable, err)
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	writer := io.Writer(w)
	if flusher, ok := w.(http.Flusher); ok {
		writer = &flushingWriter{writer: w, flusher: flusher}
	}
	if _, err := io.Copy(writer, resp.Body); err != nil {
		return err
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return nil
}

func cloneRequestForOwner(r *http.Request, ownerURL string) (*http.Request, error) {
	targetURL, err := normalizeOwnerURLForRequest(ownerURL)
	if err != nil {
		return nil, err
	}

	outReq := r.Clone(r.Context())
	outReq.URL = targetURL
	outReq.URL.RawQuery = r.URL.RawQuery
	outReq.Host = targetURL.Host
	outReq.RequestURI = ""
	outReq.Header = r.Header.Clone()
	outReq.Header.Set(sessionOwnerForwardedHeader, sessionOwnerForwardedValue)
	return outReq, nil
}

func normalizeSessionOwnerURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}

	normalizedURL, err := normalizeOwnerURLForRequest(raw)
	if err != nil {
		return "", err
	}
	return normalizedURL.String(), nil
}

func normalizeOwnerURLForRequest(raw string) (*url.URL, error) {
	targetURL, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if !targetURL.IsAbs() || targetURL.Host == "" {
		return nil, fmt.Errorf("owner URL %q must be absolute", raw)
	}
	if targetURL.Path == "" {
		targetURL.Path = "/"
	}
	return targetURL, nil
}

type flushingWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w *flushingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.flusher.Flush()
	}
	return n, err
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func sessionToolCount(session server.ClientSession) int {
	sessionWithTools, ok := session.(server.SessionWithTools)
	if !ok {
		return 0
	}
	return len(sessionWithTools.GetSessionTools())
}

func sessionResourceCount(session server.ClientSession) int {
	sessionWithResources, ok := session.(server.SessionWithResources)
	if !ok {
		return 0
	}
	return len(sessionWithResources.GetSessionResources())
}

func (s *Server) handleBackendStatusChange(event health.StatusChangeEvent) {
	previousEligible := health.IsStatusEligibleForExposure(event.PreviousStatus)
	currentEligible := health.IsStatusEligibleForExposure(event.Status)
	if previousEligible == currentEligible {
		return
	}

	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	targets := s.targetSessionsForRefresh(event, currentEligible)
	if len(targets) == 0 {
		return
	}

	slog.Info("refreshing active sessions after backend exposure change",
		"backend_id", event.BackendID,
		"backend_name", event.BackendName,
		"previous_status", event.PreviousStatus,
		"status", event.Status,
		"session_count", len(targets))

	for _, target := range targets {
		refreshCtx, cancel := context.WithTimeout(context.Background(), defaultSessionRefreshTimeout)
		if err := s.refreshSessionCapabilities(refreshCtx, target.sessionID, target.session); err != nil {
			slog.Warn("failed to refresh session capabilities",
				"session_id", target.sessionID,
				"backend_id", event.BackendID,
				"error", err)
		}
		cancel()
	}
}

// handleBackendCapabilityChange is called (asynchronously) when a backend
// sends a tools/list_changed or resources/list_changed notification via the
// persistent MCP session. It refreshes every hub session that includes the
// backend so clients see the updated tool/resource list.
func (s *Server) handleBackendCapabilityChange(backendID string) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	// backendEligible=true: the backend's tool list changed but it is still
	// reachable, so refresh ALL sessions (same as a backend recovering).
	targets := s.targetSessionsForRefresh(
		health.StatusChangeEvent{BackendID: backendID},
		true,
	)
	if len(targets) == 0 {
		return
	}

	slog.Info("refreshing sessions after backend capability change notification",
		"backend_id", backendID,
		"session_count", len(targets))

	for _, target := range targets {
		refreshCtx, cancel := context.WithTimeout(context.Background(), defaultSessionRefreshTimeout)
		if err := s.refreshSessionCapabilities(refreshCtx, target.sessionID, target.session); err != nil {
			slog.Warn("failed to refresh session after capability change",
				"session_id", target.sessionID,
				"backend_id", backendID,
				"error", err)
		}
		cancel()
	}
}

type refreshTarget struct {
	sessionID string
	session   server.ClientSession
}

func (s *Server) targetSessionsForRefresh(
	event health.StatusChangeEvent,
	backendEligible bool,
) []refreshTarget {
	targets := make([]refreshTarget, 0)
	s.activeClientSessions.Range(func(key, value any) bool {
		sessionID, ok := key.(string)
		if !ok {
			return true
		}
		clientSession, ok := value.(server.ClientSession)
		if !ok {
			return true
		}
		if !backendEligible {
			multiSess, exists := s.vmcpSessionMgr.GetMultiSession(sessionID)
			if !exists {
				return true
			}
			if !sessionContainsBackend(multiSess, event.BackendID) {
				return true
			}
		}
		targets = append(targets, refreshTarget{
			sessionID: sessionID,
			session:   clientSession,
		})
		return true
	})
	return targets
}

func sessionContainsBackend(sess sessiontypes.MultiSession, backendID string) bool {
	metadata := sess.GetMetadata()
	if len(metadata) == 0 {
		return false
	}

	backendIDs := metadata[vmcpsession.MetadataKeyBackendIDs]
	if backendIDs == "" {
		return false
	}

	for _, current := range strings.Split(backendIDs, ",") {
		if current == backendID {
			return true
		}
	}
	return false
}

func (s *Server) refreshSessionCapabilities(
	ctx context.Context,
	sessionID string,
	clientSession server.ClientSession,
) error {
	previous, ok := s.vmcpSessionMgr.GetMultiSession(sessionID)
	if !ok {
		return fmt.Errorf("session %q not found", sessionID)
	}

	refreshed, err := s.vmcpSessionMgr.RefreshSession(ctx, sessionID)
	if err != nil {
		return err
	}

	rollback := func(refreshErr error) error {
		if storeErr := s.vmcpSessionMgr.ReplaceSession(context.Background(), sessionID, refreshed, previous); storeErr != nil {
			return fmt.Errorf("%w (rollback failed: %v)", refreshErr, storeErr)
		}

		go func(rebuilt sessiontypes.MultiSession) {
			time.Sleep(defaultSessionCloseGracePeriod)
			if closeErr := rebuilt.Close(); closeErr != nil {
				slog.Warn("failed to close rolled back refreshed session",
					"session_id", sessionID,
					"error", closeErr)
			}
		}(refreshed)

		return refreshErr
	}

	adaptedTools, err := s.vmcpSessionMgr.GetAdaptedTools(sessionID)
	if err != nil {
		return rollback(err)
	}
	adaptedResources, err := s.vmcpSessionMgr.GetAdaptedResources(sessionID)
	if err != nil {
		return rollback(err)
	}

	resourcesChanged, err := replaceSessionResourcesDirect(clientSession, adaptedResources)
	if err != nil {
		return rollback(err)
	}
	toolsChanged, err := replaceSessionToolsDirect(clientSession, adaptedTools)
	if err != nil {
		return rollback(err)
	}

	if resourcesChanged {
		if err := s.mcpServer.SendNotificationToSpecificClient(sessionID, "notifications/resources/list_changed", nil); err != nil {
			slog.Debug("failed to send session resource refresh notification",
				"session_id", sessionID,
				"error", err)
		}
	}
	if toolsChanged {
		if err := s.mcpServer.SendNotificationToSpecificClient(sessionID, "notifications/tools/list_changed", nil); err != nil {
			slog.Debug("failed to send session tool refresh notification",
				"session_id", sessionID,
				"error", err)
		}
	}

	go func(previous sessiontypes.MultiSession) {
		time.Sleep(defaultSessionCloseGracePeriod)
		if err := previous.Close(); err != nil {
			slog.Warn("failed to close replaced session",
				"session_id", sessionID,
				"error", err)
		}
	}(previous)

	slog.Info("refreshed session capabilities",
		"session_id", sessionID,
		"tool_count", len(adaptedTools),
		"resource_count", len(adaptedResources),
		"tools_changed", toolsChanged,
		"resources_changed", resourcesChanged)

	return nil
}

// validateWorkflows validates workflow definitions, returning only the valid ones.
//
// This function:
//  1. Validates each workflow definition (cycle detection, tool references, etc.)
//  2. Returns error on first validation failure (fail-fast)
//
// Failing fast on invalid workflows provides immediate user feedback and prevents
// security issues (resource exhaustion from cycles, information disclosure from errors).
func validateWorkflows(
	validator composer.Composer,
	workflowDefs map[string]*composer.WorkflowDefinition,
) (map[string]*composer.WorkflowDefinition, error) {
	if len(workflowDefs) == 0 {
		return nil, nil
	}

	validDefs := make(map[string]*composer.WorkflowDefinition, len(workflowDefs))

	for name, def := range workflowDefs {
		if err := validator.ValidateWorkflow(context.Background(), def); err != nil {
			return nil, fmt.Errorf("invalid workflow definition '%s': %w", name, err)
		}

		validDefs[name] = def
		slog.Debug("validated workflow definition", "name", name)
	}

	if len(validDefs) > 0 {
		slog.Info("loaded valid composite tool workflows", "count", len(validDefs))
	}

	return validDefs, nil
}

// GetBackendHealthStatus returns the health status of a specific backend.
// Returns error if health monitoring is disabled or backend not found.
func (s *Server) GetBackendHealthStatus(backendID string) (vmcp.BackendHealthStatus, error) {
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon == nil {
		return vmcp.BackendUnknown, fmt.Errorf("health monitoring is disabled")
	}
	return healthMon.GetBackendStatus(backendID)
}

// GetBackendHealthState returns the full health state of a specific backend.
// Returns error if health monitoring is disabled or backend not found.
func (s *Server) GetBackendHealthState(backendID string) (*health.State, error) {
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon == nil {
		return nil, fmt.Errorf("health monitoring is disabled")
	}
	return healthMon.GetBackendState(backendID)
}

// GetAllBackendHealthStates returns the health states of all backends.
// Returns empty map if health monitoring is disabled.
func (s *Server) GetAllBackendHealthStates() map[string]*health.State {
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon == nil {
		return make(map[string]*health.State)
	}
	return healthMon.GetAllBackendStates()
}

// GetHealthSummary returns a summary of backend health across all backends.
// Returns zero-valued summary if health monitoring is disabled.
func (s *Server) GetHealthSummary() health.Summary {
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	if healthMon == nil {
		return health.Summary{}
	}
	return healthMon.GetHealthSummary()
}

// BackendHealthResponse represents the health status response for all backends.
type BackendHealthResponse struct {
	// MonitoringEnabled indicates if health monitoring is active.
	MonitoringEnabled bool `json:"monitoring_enabled"`

	// Summary provides aggregate health statistics.
	// Only populated if MonitoringEnabled is true.
	Summary *health.Summary `json:"summary,omitempty"`

	// Backends contains the detailed health state of each backend.
	// Only populated if MonitoringEnabled is true.
	Backends map[string]*health.State `json:"backends,omitempty"`
}

// handleBackendHealth handles /api/backends/health HTTP requests.
// Returns 200 OK with backend health information.
//
// Security Note: This endpoint is unauthenticated and may expose backend topology.
// Consider applying authentication middleware if operating in multi-tenant mode.
func (s *Server) handleBackendHealth(w http.ResponseWriter, _ *http.Request) {
	s.healthMonitorMu.RLock()
	healthMon := s.healthMonitor
	s.healthMonitorMu.RUnlock()

	response := BackendHealthResponse{
		MonitoringEnabled: healthMon != nil,
	}

	if healthMon != nil {
		summary := s.GetHealthSummary()
		response.Summary = &summary
		response.Backends = s.GetAllBackendHealthStates()
	}

	// Encode response before writing headers to ensure encoding succeeds
	data, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to encode backend health response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(data); err != nil {
		slog.Error("failed to write backend health response", "error", err)
	}
}

// notAcceptableBody is the JSON-RPC error returned when a GET request is missing
// the Accept: text/event-stream header required by the Streamable HTTP transport.
var notAcceptableBody = []byte(
	`{"jsonrpc":"2.0","id":"server-error","error":` +
		`{"code":-32600,"message":"Not Acceptable: Client must accept text/event-stream"}}`,
)

// headerValidatingMiddleware rejects GET requests that do not include
// Accept: text/event-stream, as required by the MCP Streamable HTTP transport spec.
func headerValidatingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet &&
			!strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotAcceptable)
			if _, err := w.Write(notAcceptableBody); err != nil {
				slog.Error("failed to write not-acceptable response", "error", err)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
}

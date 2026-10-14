# DocPlanner fork of ToolHive

`dp-stable` is DocPlanner's release branch: upstream `stacklok/toolhive` tags merged in, plus the
fork patches we carry. Upstream releases are brought in with a merge commit
(`Merge upstream vX.Y.Z into dp-stable`), never a rebase.

Merge base: upstream **v0.32.0** (`ecb9a8d84`), merged in `38edac4e3` (PAIINFRA-228).

## Changes that live only in a merge commit

Some fork behaviour was re-applied by hand while resolving an upstream merge, so it exists in no
standalone commit. Replaying the fork's commits onto a fresh upstream tag (instead of merging) would
silently lose it. Port these explicitly.

### `74e7a003a` — Merge upstream v0.23.1

Upstream moved the vMCP server wiring from `cmd/vmcp/app/commands.go` to `pkg/vmcp/cli`. The fork's
changes to the old file were re-applied in the new package:

| Behaviour | Where it lives now | Original commit |
|---|---|---|
| Backend init timeout from `failureHandling.healthCheckTimeout`, falling back to `timeouts.default` | `pkg/vmcp/cli/serve_timeouts.go` (`backendInitTimeoutFromConfig`) | `5feb1b1c9` |
| Backend request timeouts (`timeouts.default` / `timeouts.perWorkload`) and the HTTP write timeout derived from them | `pkg/vmcp/cli/serve_timeouts.go` (`backendRequestTimeoutsFromConfig`, `serverWriteTimeoutFromConfig`) | `3533730ce` |
| Session TTL passed to the server | `pkg/vmcp/cli/serve.go` (`SessionTTL`) | `d104dfc9f` |

Tests: `pkg/vmcp/cli/serve_timeouts_test.go`.

The same merge also carried a groupRef transition shim (string-form `MCPServer.spec.groupRef`,
optional `VirtualMCPServer.spec.groupRef`). It was removed in `d0a48cbe3`; nothing to port.

### Merge upstream v0.28.3

Upstream moved the auth-server and session Redis clients onto toolhive-core's `redis` package and
renamed `address` to `addr`. Fork behaviour re-applied while resolving:

| Behaviour | Where it lives now | Original commit |
|---|---|---|
| Upstream-token writes use WATCH/MULTI instead of Lua (Dragonfly), with upstream's #5092 index-TTL rules | `pkg/authserver/storage/redis.go` (`queueUpstreamIndexTTL`) | `907d7040d` |
| Session Redis ACL username from `sessionStorage.usernameRef` passed to the toolhive-core client | `pkg/runner/runner.go`, `pkg/vmcp/server/server.go` (`buildSessionDataStorage`, re-ported in `bafe4d46a`) | `8d09330f5` |
| Redis credential env injected once, after `resourceOverrides` (upstream's password-only builder removed) | `cmd/thv-operator/controllers/mcpserver_controller.go` (`buildSessionRedisCredentialEnvVars`) | `8d09330f5` |
| `TOOLHIVE_PROXY_SESSION_TTL` is the fallback when RunConfig `session_ttl` is unset | `pkg/runner/runner.go`, proxy constructors | `d104dfc9f` |
| vMCP `--session-ttl` flag wins over the config-file `sessionTTL` | `pkg/vmcp/cli/serve_timeouts.go` (`sessionTTLFromConfig`) | `d104dfc9f` |

### Merge upstream v0.29.3

Upstream replaced HMAC token/subject session binding with an `(iss, sub)` identity binding
(#5306/#5378). The fork's subject binding (`e492cbfad`) is dropped; the binding is upstream's.
Fork behaviour re-applied on top (the vMCP session rows were dropped or re-ported in the v0.32.0
merge, see below):

| Behaviour | Where it lives now | Original commit |
|---|---|---|
| DCR without `scope` defaults to the server's supported scopes | `pkg/authserver/server/registration/dcr.go` | `16c2fba5e` |
| Digest-pinned image pulls go through the Docker daemon (upstream #5978, after v0.29.3) | `pkg/container/images/registry.go` | `09c117c56` |

`VMCP_SESSION_HMAC_SECRET` is no longer used (upstream logs and ignores it). Sessions stored with the
old token-hash key are invalidated on read, so clients re-initialize once after the upgrade.

## Fork behaviour re-ported after the v0.32.0 merge

In v0.32.0 every vMCP caller goes through `server.Serve`: tool, resource and prompt calls go
through the core with a new backend client per call, and any pod restores a session from Redis
(#5650). The merge commit `38edac4e3` resolved every conflict to upstream's behaviour; the fork
behaviour still needed came back in standalone commits on top of it (plan:
`docs/fork/v0.32-merge-plan.md`, PAIINFRA-227, DocPlanner/toolhive#21). Unlike the sections
above, a replay keeps these, as long as each commit is replayed.

| Behaviour | Where it lives now | Commit | Original commit |
|---|---|---|---|
| Session Redis ACL username, `WithSessionIdleTTL`, HTTP write timeout and backend init timeout wired on the Serve path; mcp-go's idle sweep clears only this pod's SDK state (`sessionIDManagerResolver`) and `Stop` stops it | `pkg/vmcp/server/server.go` (`buildSessionDataStorage`, `Handler`), `pkg/vmcp/cli/serve.go`, `pkg/vmcp/server/derive.go` | `bafe4d46a`, `7f57d1f6f` | `8d09330f5`, `d104dfc9f`, `3533730ce`, `5feb1b1c9` |
| Session registration runs on a detached context (request values kept, 45 s timeout) | `pkg/vmcp/server/server.go` (`handleSessionRegistrationImpl`) | `0d62ea671` | `596f6ccf8` |
| Session-cardinality gauges (transport sessions, SDK sessions, in-flight registrations) | `pkg/vmcp/server/session_telemetry.go`, `client_sessions.go` | `0d62ea671`, `f387a57f2` | `560c1d023` |
| New sessions connect only to backends eligible for exposure | `pkg/vmcp/server/sessionmanager/session_manager.go` (`FactoryConfig.HealthStatusProvider`) | `ee875852d` | `currentEligibleBackends` |
| `timeouts.default` / `timeouts.perWorkload` applied to each backend call (keyed by `WorkloadID`, 90 s fallback); the HTTP write timeout covers the longest of them, fallback included | `pkg/vmcp/client/client.go` (`WithRequestTimeouts`, `DefaultBackendRequestTimeout`), `pkg/vmcp/cli/serve_timeouts.go` (`serverWriteTimeoutFromConfig`) | `4cf28e14c`, `703e8e849` | `3533730ce` |
| `Terminate` closes the node-local cached session; idle sweep closes cached sessions after the session TTL; `Close` runs outside the cache lock | `pkg/vmcp/server/sessionmanager/session_manager.go`, `pkg/cache/validating_cache.go` (`Remove`, `EvictIdle`) | `036974570`, `51de52641` | `596f6ccf8`, `c9ab3ccbc` |
| A call that arrives before the registration wrote the identity binding waits (one store read per step, 25 ms doubling to 500 ms, 10 s) instead of failing | `pkg/vmcp/server/serve_handlers.go` (`waitForRegisteredSession`, `waitWhileRegistrationPending`) | `c94881448`, `7d04b4957` | `d6a23fcda` |
| Health probes between vMCPs neither create sessions nor list capabilities. The probe header sets a package-private context key, never the `healthcontext` marker (which switches outgoing auth to the vMCP's service credentials), and a probe may only initialize, ping and list (else 403) | `pkg/vmcp/server/peer_probe.go` (`peerProbeMiddleware`) | `37d40cf78`, `43623c120` | `46dd7a465` |
| Resources filled on a pod that did not register the session | `pkg/vmcp/server/server.go` (`lazyInjectSessionResources`), `serve.go` hooks | `536c603b4` | `d6a23fcda` |
| Backend health or registry change clears the sessions' tool and resource stores and sends `list_changed` (15 s debounce, 60 s cooldown) | `pkg/vmcp/server/serve_refresh.go`, `refresh_scheduler.go` | `c4984e59c` | `560c1d023`, `35680e28c`, `e755493fe` |
| GET re-registration of a bound session attaches a matching caller and rejects any other; it never rewrites the binding | `pkg/vmcp/server/server.go` (`attachToBoundSession`) | `ab1b5b667` | — (new, plan D5) |
| A GET registration never creates a session: it waits for the creating pod's binding, then attaches or rejects | `pkg/vmcp/server/server.go` (`attachToBoundSession`) | `fccda6842` | — (new) |
| Every GET is checked before mcp-go sees it: 400 without `Mcp-Session-Id`, 404 for a missing, terminated or never-bound session, 403 for a different caller (mcp-go answers 200 whatever the hook does) | `pkg/vmcp/server/server.go` (`listenStreamGuardMiddleware`, `checkListenStreamCaller`) | `854448185` | — (new) |
| A capability query that misses a backend is marked partial (`AggregationMetadata.Partial`) and never cached; a `tools/call` for a tool the session store lacks tops the store up from a fresh query | `pkg/vmcp/aggregator/caching_aggregator.go`, `default_aggregator.go`, `pkg/vmcp/server/server.go` (`lazyInjectSessionTools`) | `d6d76710c` | — (new, PAIINFRA-343) |
| Missing credentials for `authz.primaryUpstreamProvider` return 401 with `WWW-Authenticate` (empty provider names ignored) | `pkg/auth/token.go` (`WithRequiredUpstreamProviders`), `pkg/vmcp/auth/factory/incoming.go` | `44b70f6a5`, `f387a57f2` | `c2cb472a2` |

Tests: `pkg/vmcp/server/serve_*_test.go`, `session_registration_context_test.go`,
`session_telemetry_test.go`, `sessionmanager/session_cache_close_test.go`,
`pkg/vmcp/client/request_timeout_test.go`, `pkg/vmcp/cli/serve_timeouts_test.go`,
`pkg/cache/validating_cache_test.go`, `pkg/auth/token_test.go`.

**Capability refresh scope.** The refresh (`c4984e59c`) clears only the sessions in
`activeClientSessions`: sessions registered on this pod by initialize or a GET listen stream. A
session that a pod only serves through POSTs (registered on another pod, tools filled by lazy
injection) keeps that pod's tool and resource stores until mcp-go's idle sweep clears them, so it
can see a stale tool set there. `startCapabilityRefresh` runs only from `Server.Start`; an embedder
that serves `Handler` without `Start` gets no refresh.

**Partial capabilities.** Upstream fills a session's tool store once per pod and caches a partial
aggregation for 30 s (#5786), so a backend that misses one query (here the fork's 3 s
`capabilityQueryTimeout`, or a 502 during a rollout) leaves calls failing with `tool not found`.
`d6d76710c` is the interim fix. A `tools/list` still never re-derives a filled store: a session
whose first list was partial gets the rest on the next backend refresh or reconnect. Drop the patch
once upstream lands the same fix (PAIINFRA-343); the 3 s timeout is a separate decision there.

**GET guard.** mcp-go v0.55 registers a session again when a GET listen stream reaches a pod that
does not hold it, and upstream's `CreateSession` would re-bind it to the caller. Upstream stops
this only in v0.40.0, as a side effect of #5729 (mcp-go replaced by toolhive-core `mcpcompat`).
mcp-go also answers the GET with 200 whatever the hook does, so `854448185` checks the GET in an
HTTP middleware first; the hook check stays as a fallback. Drop `ab1b5b667`, `fccda6842` and the
middleware of `854448185` once the fork is on v0.40 or later, if `TestCrossPodSessionRebind`,
`TestCrossPodGETDuringRegistration` and `TestListenStreamGuard`
(`pkg/vmcp/server/serve_crosspod_rebind_test.go`) pass without them.

## Dropped patches

Patches that no longer change anything relative to upstream, or whose code path upstream removed.
They stay in history; don't re-apply them on a replay.

| Commit | Patch | Why it was dropped |
|---|---|---|
| `a75f5027b` | Preserve OIDC config ref resource URL | Upstream has the same `ResourceURL` field and fallback since v0.23.1. No net diff. |
| `66be6ebe9` | Accept `best_effort` partial failure mode | Upstream accepts `best_effort` since v0.22.0 (#4865). The fork's extra `bestEffort` alias was removed; no DocPlanner config uses it. |
| `87be189f6` | Restore embedding config resolution | Upstream's `populateOptimizerEmbeddingService` resolves `embeddingServerRef` (with `Validate()` defaulting the optimizer). Upstream's version is used. |
| `690846dd8` | `InlineAuthzConfig.primaryUpstreamProvider` on `VirtualMCPServer` | Upstream added it in v0.27.1 and moved it to `spec.authServerConfig.primaryUpstreamProvider`; the inline location is still read (deprecated). Dropped in the v0.28.3 merge. |
| `4cca58224` | Prefer the caller's live identity on backend requests | Upstream #5335 (v0.28.0) does the same in `identityRoundTripper`. Dropped in the v0.28.3 merge. |
| `e492cbfad` | Bind sessions to the `sub` claim instead of the bearer token | Upstream #5378 (v0.29.x) binds to `(iss, sub)`. Dropped in the v0.29.3 merge. |
| `ee63a49a8`, `fd01fce88`, `f690bcd97`, `6ab79d0b9` | Session-owner advertise URL (`THV_VMCP_SESSION_OWNER_URL`, `POD_IP`), forwarding to the owner pod, claim of orphaned sessions, handover, dial fail-fast | v0.32.0 has no session owner: any pod restores a session from Redis (#5650). Dropped in the v0.32.0 merge. |
| `f7d033ff9`, `704a5c162`, `16ffb4874` (vMCP part), `c40943a83` | Reconnect expired backend sessions; live-session lookup and rebuild in the tool handlers | Each backend call uses a new client (`httpBackendClient`); the handlers were removed upstream (#5622). Dropped in the v0.32.0 merge. |
| `c9ab3ccbc` (stripe locks, `ReplaceSession`, `CompareAndSwap`), `560c1d023` (`CreatorIdentity`), `517f94007`, `e755493fe` (`HasBoundIdentity`) | Safe publication of refreshed sessions, rebuilt with the creator's identity | No session rebuild any more; the refresh clears and notifies instead (`c4984e59c`). Dropped in the v0.32.0 merge. |
| `517f94007` (`keepStoredBackendIDs`) | Stop token-less restores from killing bound sessions | The stored backend list no longer affects calls. Dropped in the v0.32.0 merge. |
| `b2dbce4b7` | Refresh on a backend `list_changed` notification | Covered by the health and registry refresh (`c4984e59c`). Dropped in the v0.32.0 merge. |
| `7a6c9a2f3` | Restore with the owner's live identity (`ownsStoredSession`) | Upstream #5650 restores with the request identity; `enforceSessionBinding` rejects other callers. Dropped in the v0.32.0 merge. |
| `c2cb472a2` (status map) | Upstream-token status map (`UpstreamCredentialStatus`, `UpstreamTokenStatuses`) | Upstream #5651 returns 401 when a refresh fails; the missing-token case is `44b70f6a5`. No Cedar policy read the status. Dropped in the v0.32.0 merge. |
| `8d09330f5` (alias) | Redis `address` alias of `addr` on `MCPExternalAuthConfig` (CRD, `EffectiveAddr`) and `LegacyAddress` in the auth-server RunConfig | All values and live objects use `addr` (PAIINFRA-219). Dropped in the v0.32.0 merge. |

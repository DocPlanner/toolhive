# DocPlanner fork of ToolHive

`dp-stable` is DocPlanner's release branch: upstream `stacklok/toolhive` tags merged in, plus the
fork patches we carry. Upstream releases are brought in with a merge commit
(`Merge upstream vX.Y.Z into dp-stable`), never a rebase.

Merge base: upstream **v0.42.1** (`06940e81d`), merged in `3f02521c8` (PAIINFRA-209).

Goal: carry as few patches as possible. Each row below says what the patch does, why DocPlanner
needs it, and when it can go. Check the "Drop when" column on every upstream merge.

## Patch inventory

Commits are the fork commits that introduced the behaviour. Where a row says "merge", the behaviour
was re-applied by hand in a merge commit (see [Changes that live only in a merge
commit](#changes-that-live-only-in-a-merge-commit)), so replaying the commits alone loses it.

### Operator

| Change | Why | Commit(s) | Drop when |
|---|---|---|---|
| `GenerationChangedPredicate` on every primary watch; vMCP `MaxConcurrentReconciles=3` | Status-only updates started full reconciles, and one slow vMCP blocked the others | `2c68591f2` | Upstream filters status-only events |
| Follow-ups the predicate needs: MCPRegistry keeps reconciling after adding its finalizer, MCPRemoteProxy requeues and watches MCPGroup, EmbeddingServer stays Failed on an invalid PodTemplateSpec, MCPServer reconciles on annotation changes (restart annotation) | The predicate hides these changes | `c7660fbb4`, `1960086e7`, `b3b0da4b1`, `198b61950` | Together with the predicate |
| vMCP env compared with `equality.Semantic`, labels and annotations as a subset, status setters skip unchanged values | False diffs caused an endless vMCP reconcile loop | `8071da52d` | Upstream compares semantically |
| vMCP Service/Deployment AlreadyExists and Conflict errors requeue | Create/update races marked the vMCP as failed | `0532bd27f` | Upstream requeues on these errors |
| vMCP drift check also compares nodeSelector, tolerations and affinity; StatefulSet-era objects of a migrated MCPServer are deleted on reconcile | Scheduling changes did not roll the vMCP; old StatefulSets and Services stayed after the migration | `3a8e50139` | Upstream checks scheduling drift (cleanup part: once no cluster has StatefulSet-era objects) |
| Explicit `spec.config.backends` merged with the discovered backends (explicit wins on the same name) | Hubs declare remote backends there; upstream overwrites the list | `8e474c8b2` | Upstream merges static backends |
| MCPServer Service reconciled before the Deployment; `status.URL` follows port changes; `targetPort` drift detected | A port change left vMCP routing to a stale port | `5df636980` | Upstream updates the URL and targetPort |
| RunConfig checksum taken from the ConfigMap writer | A stale cache read meant config changes did not roll the pods | `e88959899` | Upstream stops reading the checksum back |
| Proxyrunner and vMCP pods take nodeSelector, tolerations and affinity from `spec.podTemplateSpec`; operator PodDisruptionBudget | Proxies must run on the backend's node pool; HA for the operator | `5b6448a0d` | Upstream schedules the proxyrunner from the template |
| Proxyrunner deletes a stuck old-revision pod when a StatefulSet rollout stalls (`pods: delete` in the roles) | Rollouts hung on a crash-looping old pod | `baa5927f2`, `9c8b62f61` | Upstream handles stalled rollouts |
| Operator ClusterRole and RoleBinding names from `operator.rbacName` | The prod and stg operators run in the same cluster | `808a8a693` | Upstream templates the names |
| `sessionStorage.usernameRef`: Redis ACL username for MCPServer, MCPRemoteProxy and vMCP | Our Dragonfly uses ACL users, not only a password | `8d09330f5`, merge v0.28.3 | Upstream adds a username field |
| MCPOIDCConfig `allowedClientIds`, optional `oidcConfigRef.audience`, `client_id` fallback in the token validator | Cognito `client_credentials` tokens have no `aud` | `6d9eee4c1`, `78034a265`, `106deb1b5` | Upstream validates by client ID |
| `MCPServer.spec.secrets` list key is `name` + `key` | One Secret supplies several keys | `b736c5bbb` | Upstream changes the list key |

### Auth, auth server, authz, audit

| Change | Why | Commit(s) | Drop when |
|---|---|---|---|
| 401 with `WWW-Authenticate` when `authz.primaryUpstreamProvider` has no token (empty provider names ignored) | Clients log in again on 401, not on 403 | `44b70f6a5`, `f387a57f2` | Upstream returns 401 for a missing upstream token |
| `upstreamInject` with `providerName: caller` forwards the already-validated caller bearer token to the backend | Lets a backend authenticate the hub caller with the same token, without the embedded auth server | `c333920ac` | Upstream supports forwarding the caller token |
| DCR and CIMD without `scope` default to `scopesSupported` (RFC 7591) | Clients that register without `scope` got no scopes | `16c2fba5e`, `7019ea20c` | Upstream defaults the scope (or `baselineClientScopes` gives the same result for our clients) |
| Upstream-token writes use WATCH/MULTI instead of Lua | Our Dragonfly does not run the Lua scripts upstream uses | `907d7040d`, merge v0.28.3 | Upstream stops using Lua there, or we leave Dragonfly |
| Audit user name falls back to the `username` claim | Cognito access tokens have no `name` or `email` | `a40493885` | Upstream reads `username` |
| Client JSON-RPC responses (replies to elicitation, sampling, roots) pass through authz and the validating webhook. Only a body with no `method` member and a `result` or `error` counts as a reply (`ParsedMCPRequest.IsClientResponse`) | Upstream answers them with 400, so server-to-client requests never complete | `f22ee7fa6`, v0.42.1 follow-up | Upstream parses responses |

### Proxy runner and transport

| Change | Why | Commit(s) | Drop when |
|---|---|---|---|
| `TOOLHIVE_PROXY_SESSION_TTL` sets the proxy session TTL | No CRD field exists; we set 24 h (docplanner-helm `mcpservers.yaml`) to match vMCP sessions | `3a0b285c6`, `d104dfc9f` | Upstream adds a TTL field |
| Proxy tuning env from `spec.env` mirrored into the runner process; on Kubernetes the proxy keeps running after repeated backend health failures (`pkg/runner/proxy_env.go`) | The env reached only the backend container, so the proxy kept a 2 h TTL and backends idle for 2 h answered 404 | `48c702ff2` | Upstream exposes these settings |
| Shallow `/health` on the transparent proxy | The proxyrunner health check pinged the backend, so a slow backend failed the proxy's own probe | `5d7663669` | Upstream separates liveness from backend health |
| The Host header stays the configured target host when `backend_url` pins a pod IP; any other Host is rewritten to the URL host, as upstream does | Backends with strict host validation rejected the pod IP | `ce851b471`, v0.42.1 follow-up | Upstream keeps the target Host |
| HTTP 400 "no valid session ID" or "expired session ID" counts as a lost session (re-initialize and replay); only the first 4 KiB of the body are read | TypeScript SDK servers and mcp-for-argocd answer 400, not 404 | `8abac892e`, `16ffb4874`, merge v0.42.1 | Upstream treats these as session loss |
| Streamable proxy answers a timeout or failure with a JSON-RPC error, not HTTP 504/500 | vMCP got a transport error instead of a call error | `cce5872bd` | Upstream returns JSON-RPC errors |
| `ValidatingCache.Remove` and `EvictIdle`; entries closed outside the lock | The vMCP session cache needs eviction and close | `036974570`, `51de52641` | Upstream adds eviction |

### Virtual MCP server

| Change | Why | Commit(s) | Drop when |
|---|---|---|---|
| Backend init timeout from `failureHandling.healthCheckTimeout`, else `timeouts.default` (`serve_timeouts.go`) | The configured timeouts were not wired to backend initialization | `5feb1b1c9`, merge v0.23.1 | Upstream makes it configurable |
| `timeouts.default` / `timeouts.perWorkload` applied to each backend call (keyed by `WorkloadID`, 90 s fallback), on the Legacy and the Modern client; the HTTP write timeout covers the longest of them | Upstream uses a fixed 30 s per call | `3533730ce`, `4cf28e14c`, `703e8e849`, merge v0.42.1 | Upstream uses the configured timeouts (#6411, v0.45) |
| Session TTL from the config file, the `--session-ttl` flag winning | Session lifetime must match the 24 h of the proxies | `d104dfc9f` | Upstream wires `sessionTTL` |
| Session Redis ACL username and HTTP write timeout wired on the Serve path | See `usernameRef` above; long backend calls outlived the 30 s write timeout | `bafe4d46a` | With the rows above |
| Cached sessions closed on DELETE and after one session TTL idle on this replica (`FactoryConfig.IdleTTL`) | Upstream evicts only on the next Get, which never comes after a DELETE, so backend connections leaked | `036974570`, `51de52641`, merge v0.42.1 | Upstream closes on Terminate |
| Health probes between vMCPs neither create sessions nor list capabilities; the probe header never sets the `healthcontext` marker; a probe may only initialize, ping and list (else 403) | A hub probing peer vMCPs opened a session with backend connections per probe; the header must not switch outgoing auth to service credentials | `46dd7a465`, `37d40cf78`, `43623c120` | Upstream has a lightweight peer probe |
| Health checks of Kubernetes-managed MCPServer backends use the reconciled workload status; others keep the MCP probe | Each periodic check opened a full MCP session to every backend | `5d7663669` | Upstream reads workload status |
| No `structuredContent` synthesized for tools without an output schema, on errors too | Strict clients (Cursor) reject a result whose structured content does not match the schema | `a22a3fb96` | Upstream stops synthesizing it |
| Backend call errors wrapped with their class (`wrapBackendError`) on call, read and prompt | A backend timeout reached the client as a generic error, so the timeout chain could not be told apart | `cce5872bd` | Upstream classifies backend errors on every path |
| Capability refresh: a backend that crosses the advertise boundary (`health.ShouldAdvertise`) or a registry change triggers each local session's `list_changed` sink (15 s debounce, 60 s cooldown) | Upstream resyncs only when a connected backend sends `list_changed`; a backend that comes back or joins sends nothing | `c4984e59c`, merge v0.42.1 | Upstream reacts to health and registry changes |
| Partial capabilities: a query that misses a backend is marked partial and cached at most 5 s; a `tools/call` for a tool the session lacks tops the store up (own caller, not optimizer, add-only); `capabilityQueryTimeout` 10 s | Upstream caches a partial view 30 s and fills a store once, so calls failed with "tool not found" (PAIINFRA-343) | `d6d76710c`, `e2393c8d7`, `96a25efd3` | Upstream fixes #5786; replace the timeout with #6411 (v0.45) |
| A GET listen stream for a session bound to another identity gets 403 (`listenStreamGuardMiddleware`) | The SDK opens the stream for anyone with the session ID, on any pod, and routes the session's elicitation and sampling requests to it | merge v0.42.1 (replaces `ab1b5b667`, `fccda6842`, `854448185`) | Upstream checks the caller on GET |

### CI, tests, dependencies

| Change | Why | Commit(s) | Drop when |
|---|---|---|---|
| Jobs on `ubuntu-latest`; golangci-lint v2.14.0 with `only-new-issues` | The public repo gets no large runners; upstream's lint debt must not block fork PRs | `b387fe750` | Never (fork CI) |
| Lifecycle e2e with 4 ginkgo processes; optimizer e2e timeout 90 s; managed-backend health assertion skipped | Smaller runners; managed backends are checked from workload status | `22368126a`, `05373f634`, `560253e96` | With the runner and health rows |
| Module versions above upstream (x/net, x/crypto, x/sys, x/mod, x/text, x/tools, x/sync, x/term, grpc, zipkin) | govulncheck findings | `fd8d45c58`, `f90409530`, `b3929efa7` | Upstream reaches the same versions |

## Notes

**Capability refresh scope.** Only sessions registered on this pod (`refreshSinks`) are refreshed:
sessions a pod serves only through rehydration (registered on another pod) keep their stores until
the client lists again or reconnects. Resources and prompts resync add-only (upstream limitation).
Sinks of ended sessions are dropped at the next refresh. `startCapabilityRefresh` runs only from
`Server.Start`.

**Partial capabilities.** Upstream fills a session's tool store once per pod and caches a partial
aggregation for 30 s (#5786). Since #6216 the core also checks calls against the cached advertised
view, so the 5 s partial TTL matters on both paths. With a 3 s `capabilityQueryTimeout` about a
quarter of the production hub aggregations were partial on 2026-10-15.

**Sessions across pods (v0.42.1).** mcpcompat registers a session (and runs `OnRegisterSession`)
only while it serves `initialize`, before the client gets the session ID. Any other pod rehydrates
the session without the hook, and go-sdk refuses a second `initialize`. So the binding can no longer
be rewritten by a GET or a repeated initialize (`TestCrossPodSessionRebind`), and a call can no
longer arrive before the binding exists. mcpcompat runs before-hooks for tools only, so a pod that
rehydrates a session serves no resources or prompts for it (upstream gap; `TestCrossPodRehydration`
covers tools only). Accepted for PAIINFRA-209: in Datadog APM from 2026-09-16 to 2026-10-16 the hub
backends got no `resources/read`, `resources/templates/list`, `prompts/list` or `prompts/get`; every
`resources/list` was the hubs' own capability discovery.

## Changes that live only in a merge commit

Some fork behaviour was re-applied by hand while resolving an upstream merge, so it exists in no
standalone commit. Replaying the fork's commits onto a fresh upstream tag (instead of merging) would
silently lose it. Port these explicitly.

### `74e7a003a` — Merge upstream v0.23.1

Upstream moved the vMCP server wiring from `cmd/vmcp/app/commands.go` to `pkg/vmcp/cli`. The fork's
changes to the old file were re-applied in the new package: backend init timeout
(`backendInitTimeoutFromConfig`, `5feb1b1c9`), backend request and write timeouts
(`backendRequestTimeoutsFromConfig`, `serverWriteTimeoutFromConfig`, `3533730ce`) and the session TTL
(`d104dfc9f`), all in `pkg/vmcp/cli/serve_timeouts.go`.

### Merge upstream v0.28.3

Upstream moved the auth-server and session Redis clients onto toolhive-core's `redis` package.
Re-applied: WATCH/MULTI upstream-token writes (`queueUpstreamIndexTTL`, `907d7040d`), the session
Redis ACL username (`buildSessionDataStorage`, `8d09330f5`), Redis credential env injected once after
`resourceOverrides` (`buildSessionRedisCredentialEnvVars`), `TOOLHIVE_PROXY_SESSION_TTL` as the
RunConfig fallback and `--session-ttl` winning over `sessionTTL` (`d104dfc9f`).

### `75ba8d1d5` — Merge upstream v0.39.0

Kept: Service before Deployment with merged labels and annotations (`5df636980`, `e88959899`) and
`mergeStaticBackends` (`8e474c8b2`). `PodTemplateSpecBuilder.SchedulingSpec()` stays for MCPServer and
the vMCP drift check.

### `3f02521c8` — Merge upstream v0.42.1

v0.40.0 replaced `mark3labs/mcp-go` with toolhive-core `mcpcompat` over the official go-sdk (#5729).
mcpcompat has no idle sweep, session-ID-manager resolver, unregister hook, resource hooks or
`SendNotificationToSpecificClient`, so the fork code built on them was dropped or rewritten. The
last two rows (client replies, Host header) are in the follow-up commit "Narrow the client-reply and
Host header patches", on top of the merge:

| Behaviour | How it was re-applied |
|---|---|
| Capability refresh | `serve_refresh.go` triggers upstream's per-session `list_changed` sink (`buildListChangedSink`) stored in `Server.refreshSinks`, instead of clearing stores and notifying through mcp-go |
| Listen-stream guard | One HTTP middleware (`listenStreamGuardMiddleware`) using the stored binding: 403 for another identity, everything else left to the SDK |
| Per-backend timeouts | `requestTimeout(WorkloadID)` in upstream's `newStreamableHTTPClient` and `buildModernHTTPClient` instead of the fixed 30 s |
| No synthesized `structuredContent` | `toolResultFromMCP` takes `hasOutputSchema` |
| Peer probe | `peerProbeMiddleware` placed inside upstream's auth middleware (upstream now wraps auth in audit) |
| Idle close of cached sessions | `FactoryConfig.IdleTTL` kept next to upstream's `BackendHealth` gate |
| Partial-capabilities top-up | The call hook passes the tool name; the owner check reuses `enforceSessionBinding` |
| Client JSON-RPC responses | Narrowed: a reply needs no `method` member and a `result` or `error` (a webhook patch that removes `method` must fail closed, upstream test); one `IsClientResponse` check in authz and the validating webhook |
| Host header | `RoundTrip` keeps only the configured target host and rewrites any other value (upstream's host-injection regression test) |

## Dropped patches

Patches that no longer change anything relative to upstream, or whose code path upstream removed.
They stay in history; don't re-apply them on a replay.

| Commit | Patch | Why it was dropped |
|---|---|---|
| `a75f5027b` | Preserve OIDC config ref resource URL | Upstream has the same field and fallback since v0.23.1. |
| `66be6ebe9` | Accept `best_effort` partial failure mode | Upstream accepts it since v0.22.0 (#4865). |
| `87be189f6` | Restore embedding config resolution | Upstream's `populateOptimizerEmbeddingService` resolves it. |
| `690846dd8` | `InlineAuthzConfig.primaryUpstreamProvider` on `VirtualMCPServer` | Upstream added it in v0.27.1. Dropped in the v0.28.3 merge. |
| `4cca58224` | Prefer the caller's live identity on backend requests | Upstream #5335 (v0.28.0). Dropped in the v0.28.3 merge. |
| `e492cbfad` | Bind sessions to the `sub` claim | Upstream #5378 binds to `(iss, sub)`. Dropped in the v0.29.3 merge. |
| `ee63a49a8`, `fd01fce88`, `f690bcd97`, `6ab79d0b9` | Session owner URL, forwarding to the owner pod, claim, handover, dial fail-fast | v0.32.0 restores a session on any pod (#5650). Dropped in the v0.32.0 merge. |
| `f7d033ff9`, `704a5c162`, `16ffb4874` (vMCP part), `c40943a83` | Reconnect expired backend sessions; live-session rebuild in the tool handlers | Each backend call uses a new client (#5622). Dropped in the v0.32.0 merge. |
| `c9ab3ccbc`, `560c1d023` (`CreatorIdentity`), `517f94007`, `e755493fe` | Safe publication of refreshed sessions | No session rebuild any more. Dropped in the v0.32.0 merge. |
| `b2dbce4b7` | Refresh on a backend `list_changed` | Upstream #5965/#5971 do it. Dropped in the v0.32.0 merge. |
| `7a6c9a2f3` | Restore with the owner's live identity | Upstream #5650. Dropped in the v0.32.0 merge. |
| `8d09330f5` (alias) | Redis `address` alias of `addr` | All values use `addr` (PAIINFRA-219). Dropped in the v0.32.0 merge. |
| `5b6448a0d` (remote proxy part) | `MCPRemoteProxy.spec.podTemplateSpec` | Upstream #5531 (v0.37.0). Dropped in the v0.39.0 merge. |
| `8e474c8b2` (env sort) | Sorted vMCP env, workload and backend loops | Upstream sorts each env group. Dropped in the v0.39.0 merge. |
| `09c117c56` | Digest-pinned image pulls through the Docker daemon | Upstream #5978 does the same. Dropped in the v0.42.1 merge. |
| `c2cb472a2` (what was left), `f387a57f2` (authz part) | Typed upstream-auth error in Cedar, 401 classification in authz middleware and response filter, list filtering failing on an authorizer error | `44b70f6a5` already answers 401 before authz runs, and upstream #5651 answers 401 on a failed refresh. Upstream now denies with a fixed 403 (#5841, #5850, #6066). Dropped in the v0.42.1 merge. |
| `497da99ae` | Default the sole allowed audience on every grant; require `resource` with several audiences | Upstream defaults the sole audience for `authorization_code`, and fosite carries it into refresh grants. Dropped in the v0.42.1 merge. |
| `9db565784`, `08d687ac6` | Structured token-endpoint error logs with refresh-failure classification | Upstream logs the error; `oauth_debug` could carry request fragments. Dropped in the v0.42.1 merge. |
| `8d09330f5` (validation) | Go validation of the auth-server Redis storage block | CEL rules and `controllerutil` cover it (only the `sentinelTls` with `addr` check is gone). Dropped in the v0.42.1 merge. |
| `ee875852d`, `afc71f865` | `health/exposure.go`: new sessions connect only to backends eligible for exposure | Upstream #6162 (`BackendHealth`, `health.ShouldAdvertise`); upstream also tries `Unknown` backends. Dropped in the v0.42.1 merge. |
| `ab1b5b667`, `fccda6842`, `854448185` | GET re-registration guard: attach or reject in the registration hook, wait for the creating pod, HTTP checks | mcpcompat never runs the hook outside `initialize`, so a GET cannot re-bind (`TestCrossPodSessionRebind`). The caller check lives on in `listenStreamGuardMiddleware`. Dropped in the v0.42.1 merge. |
| `bafe4d46a`, `7f57d1f6f` (SDK sweep) | `sessionIDManagerResolver`, `WithSessionIdleTTL`, `Shutdown` of the SDK sweeper | mcpcompat has no idle sweep. Dropped in the v0.42.1 merge. |
| `c94881448`, `7d04b4957` | Calls wait for the registration to write the binding | Registration finishes inside `initialize`. Dropped in the v0.42.1 merge. |
| `0d62ea671` (context), `560c1d023` / `0d62ea671` / `f387a57f2` (gauges) | Registration on a detached context; session-cardinality gauges | The hook runs before the initialize response; mcpcompat has no unregister hook to count sessions. Dropped in the v0.42.1 merge. |
| `536c603b4` | Resources filled on a pod that did not register the session | mcpcompat has no resource hooks (upstream gap, see Notes). Dropped in the v0.42.1 merge. |
| `525718fee`, `3d2af3d90`, `085637aa5`, `b387fe750` (swag pin) | e2e image pins, swag pin | Upstream pins them. Dropped in the v0.42.1 merge. |

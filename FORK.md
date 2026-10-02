# DocPlanner fork of ToolHive

`dp-stable` is DocPlanner's release branch: upstream `stacklok/toolhive` tags merged in, plus the
fork patches we carry. Upstream releases are brought in with a merge commit
(`Merge upstream vX.Y.Z into dp-stable`), never a rebase.

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
| Session-owner advertise URL (`THV_VMCP_SESSION_OWNER_URL`, else `http://$POD_IP:<port>/mcp`) | `pkg/vmcp/cli/serve_timeouts.go` (`resolveSessionOwnerAdvertiseURL`) | `ee63a49a8` |

Tests: `pkg/vmcp/cli/serve_timeouts_test.go`.

The same merge also carried a groupRef transition shim (string-form `MCPServer.spec.groupRef`,
optional `VirtualMCPServer.spec.groupRef`). It was removed in `d0a48cbe3`; nothing to port.

## Dropped patches

Patches that no longer change anything relative to upstream. They stay in history; don't re-apply
them on a replay.

| Commit | Patch | Why it was dropped |
|---|---|---|
| `a75f5027b` | Preserve OIDC config ref resource URL | Upstream has the same `ResourceURL` field and fallback since v0.23.1. No net diff. |
| `66be6ebe9` | Accept `best_effort` partial failure mode | Upstream accepts `best_effort` since v0.22.0 (#4865). The fork's extra `bestEffort` alias was removed; no DocPlanner config uses it. |
| `87be189f6` | Restore embedding config resolution | Upstream's `populateOptimizerEmbeddingService` resolves `embeddingServerRef` (with `Validate()` defaulting the optimizer). Upstream's version is used. |

## Patches waiting on upstream

| Commit | Patch | Drop when |
|---|---|---|
| `690846dd8` | `InlineAuthzConfig.primaryUpstreamProvider` on `VirtualMCPServer`, wired into the vMCP Cedar config | Upstream adds the field in v0.27.1. `toolhive-config` sets `primaryUpstreamProvider: cognito` on every auth-server gateway, so it must stay until then. |

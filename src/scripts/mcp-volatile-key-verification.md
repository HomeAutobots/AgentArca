# MCP Volatile Key Verification (Item 12, OI-12-F)

- Date verified: 2026-06-14
- Verifier: implementer (item 12)
- Pinned VS Code version: 1.124 (June 2026 era; re-verify on each upstream update per item 18)
- Sources consulted: code.visualstudio.com/docs/agent-customization/mcp-servers,
  code.visualstudio.com/docs/agents/reference/mcp-configuration,
  github.com/docker/mcp-gateway/blob/main/docs/mcp-gateway.md,
  github.com/github/github-mcp-server (server-configuration.md, remote-server.md),
  github.com/invariantlabs-ai/mcp-scan (README)

---

## VS Code MCP Settings

| # | Key | Status | Verified Value / Finding | Action taken |
|---|-----|--------|--------------------------|--------------|
| 1 | `chat.mcp.discovery.enabled` KEY NAME | VERIFIED | Key exists. Per docs 2026-06-14: "automatically detect and reuse MCP server configurations from other applications." Accepts boolean OR granular object (e.g. `{"cursor-global": false, "windsurf": false}`). | Set `false` explicitly at managed layer (src/managed-config/settings.json). |
| 2 | `chat.mcp.discovery.enabled` DEFAULT VALUE | UNVERIFIED | Docs do not state the default. Set `false` explicitly regardless of default, per ADR-006 D7. | Set defensively. Not asserted. |
| 3 | `chat.mcp.discovery.enabled` SCOPE | UNVERIFIED | User/workspace/machine scope not stated in docs 2026-06-14. | Set at managed layer. Flag for item 18 regression re-verify. |
| 4 | `chat.mcp.autoStart` KEY CASING | VERIFIED | Exact casing is `autoStart` (camelCase S). Docs 2026-06-14 spell it `autoStart`. Research had lowercase `autostart` - CORRECTED. | Use `chat.mcp.autoStart` in all artifacts. |
| 5 | `chat.mcp.autoStart` DEFAULT | UNVERIFIED | Docs describe the key but do not state the default. One search result mentioned `"newAndOutdated"` as a possible default but this is unconfirmed from docs. | Set `false` explicitly. Flag for item 18 re-verify. |
| 6 | `chat.mcp.autoStart` interaction with D7 immutability | NOT EMPIRICALLY TESTED | If `autoStart` is false, VS Code should not auto-start a server on mcp.json change. Cannot test without VS Code runtime. | Setting to `false` is the defensive posture. Requires-VS-Code-runtime to confirm. |
| 7 | `github.copilot.chat.virtualTools.threshold` DEFAULT | PARTIALLY VERIFIED | Hard cap is 128 (Copilot service-side). Default setting value reported as 128. Not re-confirmed from official docs on 2026-06-14. | Not set in managed config (informational; service enforces the hard cap). |

## VS Code stdio Sandbox Key Shapes

| # | Key | Status | Verified Value / Finding |
|---|-----|--------|--------------------------|
| 19 | `sandboxEnabled` in mcp.json server entry | VERIFIED (2026-06-13, re-confirmed 2026-06-14) | Key is `sandboxEnabled` (camelCase). Used in the server entry object in mcp.json. |
| 20 | `sandbox` object field names | VERIFIED (2026-06-13, re-confirmed 2026-06-14) | Top-level `sandbox` object with: `filesystem.allowWrite` (string[]), `filesystem.denyRead` (string[]), `filesystem.denyWrite` (string[]); `network.allowedDomains` (string[]), `network.deniedDomains` (string[]). |
| 21 | Sandbox AUTO-APPROVE behavior | VERIFIED (2026-06-13) | "When sandboxing is enabled, tool confirmations are auto-approved because the server runs in a controlled environment." The PreToolUse hook interaction REQUIRES-VS-CODE-RUNTIME empirical confirmation before sandbox path may be used. |

## Docker MCP Gateway Flags

These flags are verified from github.com/docker/mcp-gateway/blob/main/docs/mcp-gateway.md (2026-06-14).

| # | Flag | Status | Verified Value / Finding |
|---|------|--------|--------------------------|
| 10 | `--verify-signatures` | VERIFIED | Flag exists. Authenticates server image signatures. |
| 11 | `--block-secrets` | VERIFIED | Flag exists. Enabled by default. Scans inbound/outbound payloads for secrets. |
| 12 | `--log-calls` | VERIFIED | Flag exists. Enabled by default. Records tool invocations. |
| 13 | `--block-network` | VERIFIED | Flag exists. Restricts tool access to unauthorized network resources. |
| 14 | `--cpus` DEFAULT | VERIFIED | Default: 1 CPU per server. |
| 14 | `--memory` DEFAULT | VERIFIED | Default: 2 GB (shown as "2Gb" in docs). |
| 27 | `docker mcp secret set` SYNTAX | UNVERIFIED | The gateway docs reference a `--secrets` flag for a config path rather than a `docker mcp secret set` subcommand. Exact syntax for setting secrets via the CLI is unconfirmed from docs 2026-06-14. Must verify against installed gateway version before use. |

## GitHub MCP Server Minimization Flags

These flags are verified from github.com/github/github-mcp-server (server-configuration.md, 2026-06-14).

| # | Flag | Status | Verified Value / Finding |
|---|------|--------|--------------------------|
| 15 | `--read-only` | VERIFIED | Flag exists. Takes precedence over all other configuration. Disables all write tools. Also available as env var `GITHUB_READ_ONLY`. |
| 16 | `X-MCP-Readonly` header | VERIFIED | Header exists for HTTP/remote mode. Equivalent to `GITHUB_READ_ONLY` env var for local server. |
| 17 | `--toolsets` | VERIFIED | Flag exists. Also available as `GITHUB_TOOLSETS`. Accepts toolset names (e.g. `pull_requests`, `repos`). |
| 18 | `--exclude-tools` | VERIFIED | Flag exists. Also available as `GITHUB_EXCLUDE_TOOLS`. Excluded tools take precedence over toolsets. |

## mcp-scan CLI

| # | Item | Status | Finding |
|---|------|--------|---------|
| 22 | `mcp-scan scan` invocation syntax | PARTIALLY VERIFIED | The invariantlabs-ai/mcp-scan repo exists. The exact install command (pip install mcp-scan vs uvx mcp-scan) and the exact scan invocation could not be confirmed from docs fetched 2026-06-14 (GitHub pages redirected). The ci/mcp-supply-chain-scan.sh uses `mcp-scan scan <file>` as the invocation; verify against the installed version. |
| 23 | `mcp-scan` tool-pinning mode flag | UNVERIFIED | A `--stored` or `--tool-pinning` flag was mentioned in SPEC-06 but not confirmed from current docs. The invariantlabs README does not document this flag. Verify against installed version before asserting. |

## What These Findings Mean for Shipped Artifacts

1. `chat.mcp.discovery.enabled: false` - set defensively at the managed layer. Default unverified but the posture is correct regardless.
2. `chat.mcp.autoStart: false` - set defensively at the managed layer. Casing is confirmed as `autoStart`.
3. The Docker MCP Gateway flags (`--verify-signatures`, `--block-secrets`, `--log-calls`, `--block-network`) are all VERIFIED from docs. The invocation in SPEC-06 section 7 is correct.
4. GitHub MCP flags are all VERIFIED. They may be used as documented if a GitHub MCP server ever clears the gate.
5. VS Code sandbox key shapes are VERIFIED. The auto-approve behavior is VERIFIED. The PreToolUse-hook-fires-for-sandboxed-calls test is REQUIRES-VS-CODE-RUNTIME.
6. `docker mcp secret set` syntax is UNVERIFIED from docs. Do not assert until verified against the installed gateway.
7. `mcp-scan` exact CLI syntax is UNVERIFIED. The `mcp-scan scan` invocation in the CI script is a best-effort stub. Verify against installed version.

## Regression note (item 18)

All UNVERIFIED keys in this table MUST be re-verified against the pinned VS Code version on each upstream VS Code, Copilot extension, or Docker MCP Gateway upgrade. The volatile-settings convention requires this. The keys with defaults that changed in past releases (e.g. `chat.permissions.default` changed to `autopilot` in 1.124) are the highest-risk ones to miss.

# OI-10-B Finding: github.copilot.auth.permissions Key Verification

- Date: 2026-06-14
- Item: 10 (credential handling build)
- Status: KEY NOT CONFIRMED - do not assert in any shipped artifact.

## Question

Does a VS Code setting exist to minimize the Copilot extension's OAuth token scope?
Specifically: is there a key named `github.copilot.auth.permissions` (or similar)
that can be set to restrict the token to "minimal" or "Copilot Requests only" scope?

## Search conducted 2026-06-14

Sources searched:
- code.visualstudio.com/docs/copilot/setup
- code.visualstudio.com/docs/enterprise/ai-settings (VS Code enterprise AI policies)
- code.visualstudio.com/updates/v1_124 (VS Code 1.124 release notes, released 2026-06-10)
- docs.github.com/en/copilot/configuring-github-copilot/configuring-github-copilot-in-your-environment
- GitHub community discussions and vscode-copilot-release issue tracker (web search)

## Finding

**The key `github.copilot.auth.permissions` is NOT confirmed in any official documentation.**

The enterprise AI settings page (code.visualstudio.com/docs/enterprise/ai-settings, verified
2026-06-14) lists enterprise policies for Copilot including: ChatToolsAutoApprove,
ChatToolsEligibleForAutoApproval, ChatToolsTerminalEnableAutoApprove, ChatAgentMode,
ChatAgentSandboxEnabled, ChatAgentNetworkFilter, ChatAgentAllowedNetworkDomains,
ChatAgentDeniedNetworkDomains, ChatHooks, ChatAgentExtensionTools, BrowserChatTools,
ChatPluginsEnabled, CopilotReviewSelection, CopilotReviewAgent, CopilotNextEditSuggestions,
Claude3PIntegration, ChatMCP, ChatApprovedAccountOrganizations. None of these is an
auth-permissions or token-scope-minimization setting.

The VS Code Copilot setup docs and VS Code 1.124 release notes do NOT mention a
token scope minimization setting.

A community discussion referenced `github.copilot.advanced.authPermissions` as a
possible alternate form. This form is ALSO NOT confirmed in official documentation.
The only confirmed use of `github.copilot.advanced` in official docs is:
`"github.copilot.advanced": { "authProvider": "github-enterprise" }` for GHE auth.

## ADR-003 context

ADR-003 D3 carried this key as "carried-from-research-pending-verification" and
explicitly stated: "Do NOT assert this key until item 10 confirms it empirically."
The research draft also mentioned `github.copilot.auth.permissions = minimal`; the
threat-modeler marked it UNVERIFIED and the ADR-003 Verification note states it
"could NOT be confirmed against current official VS Code/Copilot docs on 2026-06-13."

## Consequence

The key is NOT asserted in src/devcontainer.json or any other shipped artifact.
The comment block in devcontainer.json explains this explicitly.

## Committed minimization path (VERIFIED)

The committed Copilot CLI token minimization mechanism is the fine-grained PAT path
(VERIFIED, ADR-003 D3, docs.github.com 2026-06-13/2026-06-14):

A fine-grained PAT with the "Copilot Requests" permission, scopable to a single
repository, supplied via:
  - COPILOT_GITHUB_TOKEN (highest precedence)
  - GH_TOKEN (fallback)
  - GITHUB_TOKEN (fallback)

This is the only confirmed token-scope minimization mechanism for the Copilot CLI path.
For the Copilot Chat extension (the VS Code fallback model), no equivalent
setting was confirmed in official docs. The Chat extension uses GitHub.com OAuth;
its token scope cannot be narrowed via a VS Code setting based on current docs.

## Residual risk implication

R-c (the readable Copilot token) is unaffected by this finding. The token is
irreducibly present and readable (ADR-003 D7). The committed containment is the
ADR-002 egress boundary, not token minimization via a VS Code setting. The CLI
fine-grained-PAT path remains the only confirmed minimization mechanism.

## Regression check required

If a future VS Code/Copilot release adds a token-scope minimization setting, this
finding should be re-verified and the setting added to devcontainer.json. This is
part of the item 18 regression discipline.

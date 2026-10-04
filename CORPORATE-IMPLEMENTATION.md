# Corporate Pi implementation

Source baseline: `200387122ca450d6387f033949423114a270b96c` (Pi 1.0.2).
Plugin baseline: `5463f312fb6d67f3b37f63deb6517e79a6ff8a26` (billion-context-pi 0.1.83).
The installed Pi is unchanged. Corporate endpoint verification is still pending.

## Contract

Allow conversations, tools, cache warming, summaries and ACP delegation to explicitly approved model servers. Deny unrelated services. Keep local coding, sessions, exports and audited extensions. Missing policy, invalid configuration and sandbox failures must fail closed.

## Work and acceptance criteria

- [x] Record baseline; prepare dependencies with lifecycle scripts disabled.
- [x] Add a validated immutable network policy; check model endpoints before credentials and after auth resolution.
- [x] Filter model selection, restore, virtual routes and extension providers; reject invalid configuration without public-provider fallback.
- [x] Disable install telemetry, version checks, remote catalog/cache, uploads, relay and automatic runtime downloads.
- [x] Enforce transport origins and redirects; verify each supported SDK transport.
- [x] Patch local billion-context-pi: disable updater, bind delegate CLI/profile, preserve compression, search, replay and cache.
- [x] Enforce macOS process-tree network isolation; reject sandbox startup errors and inherited bypasses.
- [x] Protect local files, environment and diagnostics; prevent browser export network loads.
- [x] Run targeted synthetic security/compatibility tests and the full required static check.
- [x] Build offline; verify CLI, print, RPC, SDK, model transport, ACP and child processes.
- [ ] Verify the configured corporate endpoint, TLS, proxy/auth and network observations; only then install.

No runtime endpoint or secret is hardcoded. Corporate server details are pending. Synthetic tests must never use real API keys or paid providers. Process isolation and full transport coverage are required before declaring the fork safe for corporate code.

## Verification log

2026-10-04: source working trees were clean. Dependencies were prepared with `npm ci --ignore-scripts`. Lockfiles and dependency versions were not changed. Missing generated provider JSON was restored from the already verified installed 1.0.2 package; `check:model-data` verified it. No live catalog refresh was used.

Production audits: `npm audit --omit=dev --json` in both coding-agent and plugin returned zero known vulnerabilities. The broader Pi development audit reported seven high-severity entries in `braces`/`micromatch` build tooling and the Gondolin example's `node-forge` chain. Plugin development warnings concern its older Pi 0.83.0 test host and build tooling. They are not shipped in the approved single-file extension. These findings do not establish a complete third-party audit.

Verification:

- `npm run check`: passed, including TypeScript, lint, dependency declarations, install-lock and browser import graph checks.
- `npm run build:offline`: passed for all Pi packages and bundled CLI. Plugin `npm run typecheck` and `npm run build`: passed.
- Targeted corporate tests plus existing cache-warmer tests: 37 tests in six files passed. Exact origin/port, provider binding, credential timing, auth and Azure overrides, redirects, unverified API rejection, public credential/session restoration, extension hash/reload, management opt-in bypass and forged sandbox marker coverage.
- Synthetic transports: OpenAI Completions, OpenAI Responses, Anthropic Messages, Azure OpenAI Responses streamed successfully. Live local HTTPS/CONNECT worked with a trusted synthetic certificate and rejected the same endpoint without its CA before any HTTP model request.
- Built CLI print mode and RPC both received a synthetic model reply. SDK via the protected launcher received replies and ran real write/read/bash tools; an unprotected SDK session was refused.
- Actual `acp_delegate` launched the source-built CLI, used the same approved endpoint/key/profile and produced a readable private output and session file. No real API keys or paid endpoints were used.
- Native macOS sandbox blocked direct Node TCP, proxy-bypassing curl and grandchild network access. Approved proxy traffic and local coding writes worked. Protected writes and a hard-link attempt failed.
- Full billion-context-pi test suite: passed. Kernel remains pinned to 0.0.98; compressed data/ref/replay formats are unchanged.
- Interactive Node CLI received a synthetic reply and exited normally in an isolated PTY. tmux was unavailable; the equivalent PTY fixture is recorded outside this repository in the task's outputs.
- HTML export rendered in the in-app browser; injected synthetic external image and fetch destinations both recorded zero requests. CSP evidence is stored with the task outputs.
- Installed symlink, wrapper and release path remain unchanged. At the time of these acceptance checks, no commit, publication or installation had been performed.

Setup, supported APIs, local storage, SDK launch and limitations: [corporate-mode.md](packages/coding-agent/docs/corporate-mode.md).

Remaining acceptance work requires the real corporate URL/API and the user's locally supplied credentials/CA: verify model IDs, TLS/auth, proxy requirements and actual egress before switching installation. Unsupported transports, other OSes and Bun/binary builds have no claimed coverage. Configured endpoints are trusted recipients; their own routing/logging/storage is outside this local policy.

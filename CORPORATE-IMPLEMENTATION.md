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
- [x] Add rootless Linux namespaces, a mandatory native seccomp launcher and a private broker bridge; verify descendants and fail-closed startup on native Linux.
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

## Linux verification — 2026-10-05

- Built in a separate Debian 12 ARM64 container on Docker Desktop's real Linux 6.10.14 kernel, using Node 22.19.0 and non-setuid bubblewrap 0.8.0. No host files, Docker socket, API credentials or existing user containers were exposed to the tests.
- Dependencies used `npm ci --ignore-scripts`; no dependency versions or lockfiles changed. Full offline workspace build and required `npm run check` passed on Linux. The updated macOS build/check also passed.
- Linux: 38 targeted tests passed in seven files; the macOS native test and intentionally unavailable-host test were skipped in that run. A separate run inside a user namespace with further user namespaces disabled passed the unavailable-host test: Pi exited, with zero requests to the synthetic model. Thus 39 distinct tests passed on Linux across the two runs. macOS regression: 37 tests passed, with the three Linux cases skipped.
- Native tests exercise an outer container that has networking: approved broker traffic works, direct Node/curl connections cannot reach servers in the outer namespace, and an unapproved collector receives zero requests. UDP/raw/netlink/named Unix sockets and datagram/seqpacket socketpairs return EPERM. Anonymous stream pairs remain usable for Node subprocess pipes and cannot reconnect/listen on a named host socket. New user namespaces are refused. Protected writes/new hard links fail; local coding writes work. A 200 KB response traverses the bridge intact.
- Built CLI, RPC, SDK write/read/bash, HTTPS trust/rejection, redirects and real ACP delegation all passed under Linux namespaces/seccomp. The existing transport/policy/cache-warmer tests also passed. The ACP extension remained the already approved patched single-file bundle; no plugin source change was required for Linux.
- Interactive Pi received a synthetic model reply and exited normally in a native Linux PTY (one model request).
- Docker's existing default seccomp setting was unconfined. Only the temporary test container used explicit `seccomp=unconfined` and `systempaths=unconfined` to permit nested sandbox setup, with no privileges, all outer capabilities dropped and no-new-privileges enabled. The Pi process then installed its own mandatory filter (Seccomp=2), disabled user namespaces and dropped capabilities. Global Docker settings were not changed. See `test/fixtures/corporate-linux.Dockerfile` for the setup image.
- JSON reports and PTY evidence are retained locally with the task outputs; only source, tests and documentation are published to the fork.

Remaining acceptance work requires the real corporate URL/API and the user's locally supplied credentials/CA: verify model IDs, TLS/auth, proxy requirements and actual egress before switching installation. Native Linux x86-64 and the exact target server configuration have not been tested; the helper supports x86-64 builds but that is not a native integration result. Unsupported transports, Windows and Bun/binary builds have no claimed coverage. Configured endpoints are trusted recipients; their own routing/logging/storage is outside this local policy.

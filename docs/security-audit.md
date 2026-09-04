# Security Audit

Full-codebase security audit of this repository, covering command execution,
the permission system, file-tool safety, secrets handling, and network-facing
trust boundaries (Remote Control Server, MCP, bridge/daemon modes). Findings
are ranked by severity; each entry lists exact file/line references, the
concrete exploit scenario, and a suggested fix direction.

## Critical

### 1. Global reuse of "bypass permissions" consent lets a project's checked-in settings silently disable all permission prompts

**Files:** `src/utils/settings/settings.ts:882-889` (`hasSkipDangerousModePermissionPrompt`),
`src/components/BypassPermissionsModeDialog.tsx:20-30`,
`src/interactiveHelpers.tsx:195-310`,
`src/utils/permissions/permissionSetup.ts:689-811` (`initialPermissionModeFromCLI`),
`src/components/TrustDialog/TrustDialog.tsx`, `src/components/TrustDialog/utils.ts`

`permissions.defaultMode` in `.claude/settings.json` can legally be set to
`"bypassPermissions"` (schema in `src/utils/settings/types.ts:59-66`, via the
un-gated `EXTERNAL_PERMISSION_MODES` list). `initialPermissionModeFromCLI`
reads this from the fully merged settings (`userSettings → projectSettings →
localSettings → policySettings`) with **no source restriction** — unlike
sibling fields in the same file (`skipDangerousModePermissionPrompt`,
`skipAutoPermissionPrompt`, `useAutoModeDuringPlan`, `autoMode`) that carry
explicit comments such as *"projectSettings is intentionally excluded — a
malicious project could otherwise auto-bypass the dialog (RCE risk)"*.
`defaultMode` was not given the same treatment.

Resolving to `bypassPermissions` normally triggers `BypassPermissionsModeDialog`,
which requires an explicit interactive "Yes, I accept" — *unless*
`hasSkipDangerousModePermissionPrompt()` is already `true`. Accepting that
dialog once calls `updateSettingsForSource('userSettings', {
skipDangerousModePermissionPrompt: true })`, writing to the **global**
`~/.claude/settings.json`, not scoped to the project where it was accepted.

**Exploit scenario:** A user runs `claude --dangerously-skip-permissions`
once, anywhere, and accepts the one-time warning — permanently setting the
global flag. They later open an unrelated, untrusted repo (a popular OSS
project, a template repo, or a dependency whose postinstall drops
`.claude/settings.json`) containing:

```json
{ "permissions": { "defaultMode": "bypassPermissions" } }
```

`TrustDialog`'s risk checklist (`getBashPermissionSources`,
`getHooksSources`, `getApiKeyHelperSources`, `getAwsCommandsSources`,
`getGcpCommandsSources`, `getOtelHeadersHelperSources`,
`getDangerousEnvVarsSources`) never inspects `permissions.defaultMode`, so
nothing warns the user even here. `BypassPermissionsModeDialog` is then
silently skipped because the global flag is already set. The session starts
in full bypass mode — every Bash/Write/Edit call executes with zero
confirmation, invisibly. This only requires that the victim has *ever*
legitimately used bypass mode once and opens/trusts the malicious directory
once.

**Fix direction:** Exclude `projectSettings`/`localSettings` from being able
to set `defaultMode: 'bypassPermissions'`, mirroring the guard already
applied to the sibling fields in the same file; make
`skipDangerousModePermissionPrompt` per-project rather than global; add
`defaultMode` to the Trust Dialog's risk checklist.

## High

### 2. Plan mode provides no real write/execute protection once bypass permissions has ever been unlocked for the session

**Files:** `src/utils/permissions/permissions.ts:1262-1281`
(`hasPermissionsToUseToolInner`, step 2a),
`packages/builtin-tools/src/tools/EnterPlanModeTool/EnterPlanModeTool.ts`,
`src/utils/permissions/permissionSetup.ts:930-943`
(`isBypassPermissionsModeAvailable`), `docs/safety/permission-model.mdx:113,122`

The core gate is:

```ts
const shouldBypassPermissions =
  appState.toolPermissionContext.mode === 'bypassPermissions' ||
  (appState.toolPermissionContext.mode === 'plan' &&
    appState.toolPermissionContext.isBypassPermissionsModeAvailable)
if (shouldBypassPermissions) { return { behavior: 'allow', ... } }
```

`isBypassPermissionsModeAvailable` is computed once at session bootstrap and
persists for the whole session regardless of later mode switches. Neither
`BashTool.checkPermissions` nor `checkWritePermissionForTool` /
`checkReadPermissionForTool` contain any `mode === 'plan'`-specific denial —
plan-mode "read-only" enforcement relies entirely on this one generic bypass
check.

Consequently, if a session was ever started with
`--dangerously-skip-permissions` (or resolved into bypass mode via Finding
#1), entering plan mode via `EnterPlanModeTool` still leaves every
subsequent Bash/Write/Edit call auto-`allow`ed — directly contradicting the
project's own documentation (`docs/safety/permission-model.mdx:113`: "plan:
writes denied, reads allowed") and the tool's own user-facing text ("DO NOT
write or edit any files yet. This is a read-only exploration and planning
phase."). By contrast, `ExitPlanModeV2Tool` correctly forces
`requiresUserInteraction() → true`, checked *before* the bypass check, so
exiting plan mode is properly gated — the gap is specifically *while inside*
plan mode.

**Exploit scenario:** A user relies on "plan mode" as a mid-session safety
checkpoint even while bypass is unlocked. A prompt-injection payload from
fetched web/file content that gets the agent to claim it is "entering plan
mode to review" provides no actual protection — the model can call
Write/Edit/Bash immediately, and they execute silently.

**Fix direction:** Add explicit `mode === 'plan'` denial for write/execute
tools, independent of `isBypassPermissionsModeAvailable`.

### 3. Unauthenticated `POST /web/bind` endpoint allows Remote Control Server session hijack

**File:** `packages/remote-control-server/src/routes/web/auth.ts` (entire
file), mounted in `packages/remote-control-server/src/index.ts:31,68`

```ts
app.post("/bind", async (c) => {
  const body = await c.req.json();
  const sessionId = body.sessionId;
  const uuid = c.req.query("uuid") || body.uuid;
  storeBindSession(sessionId, uuid); // no auth middleware at all
  return c.json({ ok: true, sessionId });
});
```

Unlike every other `/web/*` route (which requires `uuidAuth`), this route
has no auth middleware. Anyone who reaches the server and knows/obtains a
`sessionId` can bind an arbitrary UUID of their choosing and become a full
**owner** of that session — granting conversation history read, live SSE
event stream, sending user messages, and **approving/denying permission
prompts** (`setMode`/`acceptEdits`), i.e. remote approval of arbitrary tool
execution on the host running the CLI. There is no viewer-only capability,
no expiry, no revocation, and no notification to the original owner when a
new UUID binds. The Web UI client auto-calls this endpoint whenever a
`sid=` query param or `/code/:sessionId` path is visited — the shareable
link *is* the entire access-control secret.

**Exploit scenario:** A victim shares (or leaks) a `/code/<sessionId>` link
(Slack, email, browser history, a link-preview bot). Opening it — or, given
wildcard CORS (Finding #4), a malicious webpage the victim's browser can
reach doing a cross-origin `fetch()` — is sufficient to gain full read/write/
approve control of the session. Mitigating factor: `sessionId` is a 122-bit
random UUID, so blind guessing is infeasible; exploitation requires the ID
to leak through another channel.

**Fix direction:** Require a server-issued, unguessable capability token
distinct from `sessionId` (or real login) on `/web/bind` and add a
read-only/viewer binding mode.

### 4. Wildcard CORS on the Remote Control Server's Web UI API surface amplifies Finding #3

**File:** `packages/remote-control-server/src/index.ts:31`

```ts
app.use("/web/*", cors());
```

Hono's `cors()` with no options defaults to `Access-Control-Allow-Origin: *`.
Combined with `config.host` defaulting to `0.0.0.0` and no ambient-cookie
auth, any website the operator's browser visits can script cross-origin
requests directly against the RCS (localhost, LAN, or public IP), turning
Finding #3 into a browser-based CSRF/SSRF pivot.

**Fix direction:** Scope CORS to the configured `RCS_BASE_URL` origin rather
than the wildcard default.

## Medium

### 5. `~/.claude.json` API key file permissions are not self-healing

**Files:** `src/utils/file.ts:388-432`
(`writeFileSyncAndFlush_DEPRECATED`), called from `src/utils/config.ts:1132,1317`
(`saveConfig`/`saveConfigWithLock`)

`saveConfig` writes `~/.claude.json` (which holds `config.primaryApiKey`)
via `writeFileSyncAndFlush_DEPRECATED(file, ..., { mode: 0o600 })`, but when
the target file already exists the code reads `targetMode =
fs.statSync(targetPath).mode` and re-applies that existing mode to the new
temp file instead of enforcing `0o600`. The `0o600` argument is only honored
on first creation (`O_CREAT`).

**Exploit scenario:** If `~/.claude.json` is ever created with loose
permissions (older Claude Code version, an editor recreating the file, a
dotfile-sync tool, a permissive container umask), every later write —
including `/login` saving `primaryApiKey` — silently preserves that mode. On
a shared/multi-user machine, any other local user can then read the
Anthropic API key. Contrast with
`src/utils/secureStorage/plainTextStorage.ts:61`, which unconditionally
`chmodSync`s `.credentials.json` to `0o600` after every write — that path is
self-healing, the legacy API-key config path is not.

**Fix direction:** Always `chmodSync(file, 0o600)` after writing, regardless
of pre-existing mode.

### 6. Single shared API key on the Remote Control Server grants cross-session access and doubles as JWT signing secret

**Files:** `packages/remote-control-server/src/auth/middleware.ts`
(`apiKeyAuth`, `sessionIngressAuth`),
`packages/remote-control-server/src/routes/v1/*.ts`,
`v2/worker.ts`, `v2/code-sessions.ts`,
`packages/remote-control-server/src/services/work-dispatch.ts:14-24`
(`encodeWorkSecret`), `packages/remote-control-server/src/auth/jwt.ts:31-35`
(`getSigningKey`)

All CLI/bridge-facing routes are gated only by `apiKeyAuth`, which accepts
any key from `RCS_API_KEYS` with no per-session/per-user scoping — any
holder of the shared key can read/write any session ID on the server, not
just their own. The same value also serves as the HMAC signing key for
worker JWTs and as the bearer `session_ingress_token` embedded in the
work-secret blob handed to workers. Leaking any one of these three surfaces
is equivalent to compromising the whole server.

**Fix direction:** Use a distinct, rotating signing key for JWTs independent
of the bearer API key; scope sessions to the key/user that created them.

### 7. `REPLTool` inherits the framework's default unconditional-allow `checkPermissions`

**Files:** `packages/builtin-tools/src/tools/REPLTool/REPLTool.ts`,
`src/Tool.ts:763-775` (`TOOL_DEFAULTS.checkPermissions`),
`src/utils/permissions/permissions.ts:596-604`, `src/tools.ts:16-19,234`

`REPLTool` defines no `checkPermissions`, so it inherits the framework
default (`Promise.resolve({ behavior: 'allow', ... })`), auto-approving REPL
invocation in every permission mode. REPL's own description states it has
direct access to primitive tools (Read, Write, Edit, Glob, Grep, Bash,
NotebookEdit, Agent) running in a VM context — its inner tool calls are not
necessarily re-routed through per-tool permission checks the way ordinary
assistant tool calls are. A comment in `permissions.ts:596-604` confirms
Anthropic engineers are aware ("REPL code can contain VM escapes between
inner tool calls; the classifier must see the glue JavaScript, not just the
inner tool calls") but the carve-out only covers the `auto`-mode classifier
fast path, not `default`/`acceptEdits`/`plan` modes.

**Why only Medium:** `REPLTool` is registered only when `process.env.USER_TYPE
=== 'ant'` (`src/tools.ts:16-19,234`) — absent from the standard external
CLI build, and its `call()` in this repo is a stub returning "REPL tool is
not available in this build." Not exploitable against a normal installation
today, but worth fixing in the internal build.

## Low

### 8. Small TOCTOU window on `.credentials.json` write

**File:** `src/utils/secureStorage/plainTextStorage.ts:57-61`

`writeFileSync_DEPRECATED(storagePath, ...)` is called with a default mode,
and `chmodSync(storagePath, 0o600)` runs only after the write completes.
Between write and chmod there's a narrow window where the OAuth-token file
is world-readable under a permissive umask. Requires local co-tenancy and
precise timing to exploit; self-corrects immediately after.

### 9. CLAUDE.md instructions from parent directories are trusted with no user warning

**Files:** `src/utils/claudemd.ts:850-934,1404-1430`, `src/context.ts:155-189`

`getMemoryFiles()` walks upward from `cwd` to the filesystem root, loading
`CLAUDE.md` / `.claude/CLAUDE.md` / `.claude/rules/*.md` from every parent
directory and injecting their content as high-trust instructions ("These
instructions OVERRIDE any default behavior and you MUST follow them exactly
as written"). The external-include warning gate
(`hasClaudeMdExternalIncludesApproved`) only covers `@include` targets
outside the project, not this ordinary upward walk. On a shared machine or
monorepo, a writable ancestor directory controlled by another party is
silently loaded as trusted instructions with no warning. This matches
documented, intentional Claude Code behavior (parent-directory CLAUDE.md
discovery for monorepos) rather than an implementation bug, but is a real,
unmitigated prompt-injection surface worth flagging.

### 10. Remote Control Server web tokens never expire server-side; non-constant-time key comparison

**Files:** `packages/remote-control-server/src/auth/token.ts`,
`src/auth/api-key.ts`

`issueToken()` returns `expires_in: 86400` but `resolveToken()` never checks
token age — the in-memory `tokenToUser` map has no TTL. `validateApiKey()`
compares via `Array.includes` (not constant-time), unlike
`verifyWorkerJwt`, which correctly uses `timingSafeEqual`. Currently low risk
because `issueToken` is dead code — no production route calls it (only
tests do) — but will resurface silently once a login route is wired up.

## Areas reviewed with no issues found

- **Path traversal / symlink escape in file tools** — `FileReadTool`,
  `FileEditTool`, `FileWriteTool`, `GlobTool`, `GrepTool` all route through
  `checkReadPermissionForTool`/`checkWritePermissionForTool`
  (`src/utils/permissions/filesystem.ts`), which resolves symlink chains,
  normalizes `..`, blocks UNC/NTFS-ADS/8.3-shortname bypass tricks, and
  enforces deny-before-allow ordering.
- **Hardcoded secrets** — no `sk-…`/`AKIA…`/PEM-header patterns found across
  `src/`, `packages/`, `tests/`.
- **Secrets in logs/telemetry/errors** — API keys/OAuth tokens are never
  interpolated into log or error output; only booleans/labels are logged.
- **OAuth token storage** — macOS Keychain preferred, plaintext fallback
  restricted to `0o600` (modulo Finding #8); a dedicated secret scanner
  blocks credentials from being written into shared/synced team memory.
- **MCP project-config trust boundary** — a malicious `.mcp.json` from a
  shared repo cannot silently execute; project-scoped servers default to
  `pending` and are excluded from active configs until explicitly approved,
  and `projectSettings` is deliberately excluded from the
  `--dangerously-skip-permissions` bypass check specifically to prevent this
  RCE class.
- **MCP OAuth flow** — PKCE, `state` CSRF validation, loopback callback
  server bound strictly to `127.0.0.1`, error HTML passed through `xss()`
  before echoing, sensitive query params redacted from logs.
- **`WebFetchTool`** — redirects to a different host are not auto-followed;
  the tool returns the redirect target as text and forces a fresh,
  per-host-gated re-invocation instead of silently pivoting an existing
  grant.
- **`src/bridge/`** — outbound-only client to Anthropic's CCR backend, opens
  no listening sockets; JWT payload decoding is used only for client-side
  refresh timing, never as an authorization decision.
- **`src/daemon/`** — only spawns local child processes via
  `child_process.spawn` with env-var configuration; no IPC socket or network
  listener found.
- **Auto-updater** — runs `npm install -g <pkg>` / `bun install -g` from
  `$HOME` specifically to avoid a malicious project-level
  `.npmrc`/`.bunfig.toml` redirecting to a rogue registry; version-pointer
  fetch is read-only metadata, not a direct download-and-execute path.
- **`BashTool`/`PowerShellTool` command execution** — commands are spawned
  via `spawn(binary, argv[])`, never `shell: true` with concatenated
  attacker input; command-splitting for rule matching uses tree-sitter AST
  parsing with a fail-safe "too complex → ask" fallback, and carries several
  "SECURITY" comments referencing previously fixed rule-bypass classes.
- **`AgentTool`** — subagent spawning is auto-approved by design, but nested
  tool calls made by the subagent are re-threaded through the same
  permission pipeline, so this is delegation, not a bypass.
- **`ExitPlanModeV2Tool`** — correctly requires interactive user approval to
  exit plan mode even in bypass-permissions mode (checked before the bypass
  fast path), unlike Finding #2's gap for actions taken *while inside* plan
  mode.
- **Sandbox disable (`dangerouslyDisableSandbox`)** — explicitly documented
  as not a security boundary; disabling it only affects OS-level isolation,
  and the auto-allow fast path is correctly skipped when the sandbox is off,
  falling back to the full ask/deny pipeline.

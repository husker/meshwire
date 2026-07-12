# Armed Watcher on Join — Design

**Date:** 2026-07-11
**Status:** Approved in design discussion; pending spec review
**Problem owner:** James
**Repo:** husker/a2acast (`mesh.py`)

## Problem

A node that joins the mesh is not reachable until its agent takes a turn.
Today, real-time responsiveness (answering pings, acking, catching messages
the moment they arrive) requires an armed watcher — and on Claude Code and
Codex the watcher only arms at turn boundaries (Stop hook) or interactively.
A freshly joined idle session is a black hole: `mesh ping` times out,
messages sit at the relay, and the roster shows "never seen" even though the
session is open. Observed live 2026-07-11: the Codex app joined mesh `home`
(announce broadcast received) but timed out on ping because no watcher was
armed.

**Requirement (non-negotiable): as soon as an agent joins the network, it
has an armed watcher.** Presence first, then agent-wake — both required.

## Scope decisions (settled with James)

1. **Both capabilities required, presence first.**
   - *Presence:* a live process answers pings/acks and captures every
     inbound message from the moment the session opens — without waking
     the agent.
   - *Agent-wake:* the idle agent autonomously reads and acts on a
     delivered message without a human turn.
2. **Session-bound lifecycle (no daemon).** Presence lives and dies with
   the agent session. When no session is open the node goes dark and
   messages queue at the relay. No launchd/systemd/Windows-service
   machinery.
3. **v1 targets the three CLIs to parity** — Claude Code, Codex CLI,
   Copilot CLI. Desktop apps (Codex app, Claude Desktop) are an explicit
   later phase.
4. **Claude wake uses the shipped Stop-hook/asyncRewake path in v1.**
   Claude Code **Channels** (`notifications/claude/channel`) is the
   native idle-wake but is research-preview (v2.1.80+, Anthropic-auth
   only, requires `--dangerously-load-development-channels` for custom
   servers) — deferred until it GAs. Claude Code does **not** support MCP
   `sampling/createMessage` (anthropics/claude-code#1785, open), so the
   Copilot mechanism cannot be ported.

## Architecture

Two decoupled layers inside one harness-owned process.

```
Agent session (Claude Code / Codex CLI / Copilot CLI) starts
        │
        ├─ harness spawns  `mesh <mcp-server>`  (stdio, owned by harness)
        │        │
        │        ├─ PRESENCE layer ── background watch-loop thread
        │        │     • single subscriber to <me> + broadcast topics
        │        │     • answers ping→pong, acks, notes announces
        │        │     • appends real messages to the delivery buffer
        │        │
        │        └─ WAKE layer ── on a real message, poke the agent
        │              • Copilot → sampling/createMessage      (shipped)
        │              • Claude  → Stop-hook / asyncRewake      (v1)
        │              • Codex   → Stop-hook                    (v1, spike)
        │
        └─ session ends → stdin EOF → process exits → node goes dark
```

Key idea: **presence is a property of the process being alive**, and every
target harness keeps a stdio MCP server alive for the whole session even if
its tools are never called (verified: Copilot 1.0.70 live; Claude Code per
docs — spawned at session start, kept for session lifetime). So the watch
loop is armed the moment the session opens; waking the agent is a second,
separable event that fires only on real messages.

### Presence layer (uniform, phase 1)

- Generalize `mesh mcp-serve` (today Copilot-specific): the server starts a
  **watch-loop thread** at boot, independent of tool calls. The MCP main
  thread keeps serving `mesh_send` / `mesh_pending` over stdio.
- The loop reuses the existing message path (`_stream_events`,
  `_handle_control`, `_send_ack`): ping→pong, ack, announce→roster — all
  handled in-process with the agent idle. Real messages append to the
  delivery buffer (`.meshwire.activity`) and escalate to the wake layer.
  Control chatter never escalates.
- Wake becomes a pluggable callback selected at launch, e.g.
  `mesh mcp-serve --harness claude|codex|copilot` (exact flag/subcommand
  naming decided at implementation).
- **Registration** (harness spawns the server at session start):
  - Copilot: workspace `.github/mcp.json` via `mesh copilot-setup`
    (exists).
  - Claude Code: project `.mcp.json` via `mesh claude-setup` (the command
    exists but today only prints a CLAUDE.md snippet — the `.mcp.json`
    registration is new code, following the `cmd_copilot_setup` pattern).
  - Codex CLI: `[mcp_servers]` in Codex config via new `mesh codex-setup`.
  - All fronted by `mesh integrate`.
- Identity resolves per-harness (harness-aware naming fix, commit
  04e450f), so each harness's presence is a distinct, correctly named
  node.

### Wake layer (per-harness)

**Single-subscriber rule:** the presence server is the ONLY relay
subscriber per node identity. Wake watchers wait on the **local delivery
buffer** (file), never on the relay. This eliminates subscription races and
means a missed wake can never lose a message — it is already on disk.

- **Copilot (shipped, unchanged):** presence server fires
  `sampling/createMessage` → full idle sub-agent turn → agent reads buffer
  via `mesh_pending`, replies via `mesh_send`. Verified live on 1.0.70.
- **Claude Code (v1):**
  - *Arming at session open:* a plugin **SessionStart hook runs a command**
    without needing a model turn — it spawns the wake-watcher at session
    open. (SessionStart stdout only injects context and does not trigger a
    turn; the hook *command* itself runs regardless — that is what arms.)
  - *Waking:* the watcher observes the buffer go non-empty (local,
    instant) → wakes the session via the existing `claude-hook` /
    asyncRewake path → agent handles + replies → re-arms at the next Stop.
  - *Fallback:* a missed wake leaves the message in the buffer; it
    surfaces on the next turn (same pattern as `copilot-activity`).
- **Codex CLI (v1, spike first):** same buffer-watcher pattern via its
  Stop hook (`{"decision":"block","reason":...}` contract; `{}`/empty is
  rejected — emit `{"continue":true}` for no-op). Spike must confirm:
  (1) whether a session-start-equivalent event can run a command (for
  arm-at-open), and (2) exact stop-hook wake semantics. Until confirmed,
  Codex wake may be turn-windowed in v1 — presence still guarantees zero
  loss.

**Wake-strength assessment (candid):** Copilot = true idle wake (native
push). Claude = **true idle wake, verified live 2026-07-12**: SessionStart
honors `async` + `asyncRewake` hook entries, so the wake watcher arms at
session open with zero turns taken — a never-typed-in session woke on
message arrival and replied in 48s end-to-end (probe outcome (a); the
SessionStart claude-hook entry in hooks/hooks.json is permanent).
Codex = spike-dependent; worst case turn-windowed in v1 (presence
verified live; see 2026-07-12-codex-wake-spike.md).

## Error handling & edge cases

- **Relay stream drops:** watch loop reconnects on
  `URLError / HTTPException / OSError` (v0.7.9 fix) with the existing
  exponential backoff (1s→2s→…→30s), forever. Reconnect resumes via ntfy
  `since=` cursor so drop-window messages are replayed, not lost.
- **Buffer as IPC:** append + atomic rename writes; readers tolerate
  partial lines; the wake watcher treats any change as "check pending"
  (no offset parsing). Duplicate wakes are harmless — `mesh_pending` on an
  empty buffer no-ops (matches known Copilot double-sampling behavior).
- **Two sessions, same directory, same harness:** single-subscriber lock
  (extend `_acquire_hook_lock` pattern) elects one presence server; the
  loser runs tools-only (no watch loop). Different harnesses are distinct
  nodes post-04e450f and each runs its own presence.
- **Non-mesh directory:** `_mcp_idle_serve` handshake-only behavior is
  unchanged.
- **Harness kills the server mid-session** (known Claude Code stdio
  teardown bugs): wake watcher (hook-spawned) survives; presence goes dark
  while the session looks open. v1 accepts this (harness bug), documents
  it in README; server writes a last-gasp note to the buffer on exit.
- **Acks:** the presence loop acks only *inbound* deliveries; acks for
  agent-sent messages continue to come from the agent's own turn. No
  self-ack loops.
- **Wake-watcher crash:** re-armed at every turn boundary (Stop hook) and
  at session open; presence is unaffected meanwhile.

## Testing

**Unit (mocked transport — no real ntfy I/O, per issue #6):**
- Presence loop: ping answered with pong (agent never invoked), ack sent,
  message appended to buffer, control chatter not escalated; stream drop
  (`SSLError` / `IncompleteRead` / `OSError` mid-iteration) → reconnect,
  extending the v0.7.9 probe pattern.
- Single-subscriber lock: second same-identity server → tools-only mode.
- Buffer IPC: concurrent append/read, partial-line tolerance,
  wake-on-change, duplicate wake no-ops on empty buffer.
- Wake dispatch (callback mocked): copilot → sampling emitted; claude →
  asyncRewake path invoked; unknown → buffer-only.
- Setup commands: `claude-setup` / `codex-setup` / `copilot-setup` write
  correct config idempotently (run twice → no duplicates).
- Determinism: suite green under any ambient harness
  (`_detect_harness → None` patch pattern from HarnessNamingTests work).

**Live verification per harness (scripted checklist in the plan):**
1. Fresh session, type nothing → `mesh ping <node>` from another node
   answers within seconds (the headline fix).
2. `mesh send <node> "hi"` to the idle session → Copilot handles+replies
   idle; Claude wakes via asyncRewake; Codex per spike findings.
3. Close the session → node stops answering pings; no orphan processes.
4. Codex spike findings recorded before Codex wake implementation.

**Regression gate:** full `tests.test_mesh` green before each commit.

## Out of scope (v1)

- Persistent daemon / always-on presence (launchd/systemd/service).
- Desktop apps (Codex app, Claude Desktop) — later phase; the Codex app
  joined as a plain `mesh join` (no harness detected) and gets presence
  only while some watcher-capable session covers that node.
- Claude Code Channels-based wake — revisit at GA.
- Fixing `cmd_join`'s non-harness-aware default name (line 786 calls
  `_default_node_name()` bare; join from inside a harness session should
  arguably derive `<host>-<harness>`) — small, may ride along in the
  implementation if trivial, otherwise its own issue.

## Sequencing

1. **Phase 1 — Presence (uniform):** generalize `mcp-serve`; watch-loop
   thread + single-subscriber lock; `claude-setup` / `codex-setup`
   registration; unit tests; live checklist item 1 on all three CLIs.
2. **Phase 2 — Wake:** Claude SessionStart-arm + buffer-watcher +
   asyncRewake rewire; Codex spike then implementation; Copilot re-pointed
   at buffer-only escalation (already close); live checklist items 2–3.

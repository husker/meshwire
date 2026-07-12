# Codex Autonomy (A) + Identity Migration (B) — Design

**Date:** 2026-07-12
**Origin:** Live fleet testing of v0.13.0 surfaced both items. A's architecture
was proposed by the `asus-k53e-claude` node over the mesh; B was reported by the
`desktop` node.
**Repo:** husker/a2acast (`mesh.py`)

## Problem

**A — Codex is not an autonomous peer.** A joined Codex node has presence
(`mesh mcp-serve` answers pings, buffers deliveries) but never *acts* on a
delivered a2a task without a human nudge. Root cause: Codex has no in-process
wake path — sync-only hooks, MCP `sampling` reported "Unsupported", and its
`notify` config is outbound-only. `mesh codex-setup` only registers the MCP
server, not any wake mechanism. Claude wakes via async Stop/SessionStart hooks;
Copilot via MCP sampling; Codex has neither.

**B — Established-name nodes go dark on upgrade.** v0.13.0's harness-aware
naming (`<host>-<harness>`) is intended and stays. But a node that was known as
`desktop` (via a legacy generic `.meshwire.node`) gets recomputed to
`desktop-<host>-claude` on upgrade and disappears from its established identity
(new topic, peers can't reach it). Setting `A2ACAST_NODE=desktop` did not help
because the env var does not reliably propagate into the harness-spawned
subprocess that resolves identity. `desktop` self-healed by writing
`.meshwire.node.claude=desktop` by hand.

## A — `mesh codex-supervise`

Codex can't be woken from inside, so drive it from outside (asus's insight):
Codex CLI's non-interactive `codex exec "<prompt>"` runs a one-shot task. A
small supervisor turns each delivered a2a task into a `codex exec` invocation.

### Architecture

```
codex-setup  ─┬─→ codex mcp add a2acast (presence: pings/acks/buffer)   [existing]
              └─→ launches `mesh codex-supervise` (the actor)           [new]

codex-supervise loop:
  tail .meshwire.activity.<node>           # the delivery buffer
  on each NEW a2a task line:
    if sender NOT in cfg["nodes"] (roster): skip (buffer-only, logged)   # allowlist
    else:
      codex exec  --sandbox <SANDBOX>  "<PREAMBLE + task text>"
      capture stdout; `mesh reply <task-id> "<result>"`
    mark the buffer line handled (dedup: track handled task-ids on disk)
```

### Security (this feature auto-runs network-delivered instructions)

**Threat model, stated plainly.** This feature runs a peer's task text through
`codex exec` with **no human in the loop**, and relays the output back over the
mesh. The mesh's real boundary is *possession of the join secret* ("the code IS
the mesh secret") — NOT curated identity: `note_peer` auto-adds any
authenticated sender to `cfg["nodes"]` on their first message, in the same tick
their task is persisted. So `cfg["nodes"]` (the roster) is **not** a trust
boundary for auto-execution — anyone with the join code is roster-eligible on
first contact. (This was fine before autonomy; it is not fine as the gate for
unattended code execution. The v1 final review caught this.)

Guardrails, corrected:

1. **Curated exec-allowlist, separate from the roster, default EMPTY.** A task is
   auto-run only if its sender is in `cfg["exec_allow"]` — a list the operator
   populates *explicitly* (`mesh codex-allow <node>`), never grown by
   `note_peer`. Default empty ⇒ **nothing auto-executes until the operator names
   trusted peers.** This is the actual trust boundary.
2. **Autonomy is opt-in.** `mesh codex-setup` sets up presence only and does NOT
   launch the supervisor. `mesh codex-setup --supervise` (or `mesh
   codex-supervise` directly) opts in. So the dangerous path is never on by
   default.
3. **Sandbox is defense-in-depth, NOT the boundary — and read-only does NOT stop
   exfiltration.** `codex exec --sandbox read-only` blocks writes/destructive
   ops/network *from* the subprocess, but a read-only task can still READ repo
   secrets (`.env`, keys) and put them in its reply, which is relayed unfiltered.
   Read-only limits blast radius; it does not make an untrusted sender safe. That
   is exactly why exec-eligibility (guardrail 1) must be curated, not the sandbox.
   Default `read-only`; `--supervise-sandbox workspace-write`/`danger-full-access`
   widen it and must be typed explicitly.
4. **Bounded preamble** (defense-in-depth): frames the task text as a request to
   analyze/answer, not commands to the host; forbids destructive/networked ops.
5. **No double-execution / no infinite retry.** Before `codex exec`, the task is
   claimed by writing state `"working"` (excluded from selection), so a second
   poll or a racing manual `mesh reply` can't double-run it. A task that fails is
   retried up to N times (attempts tracked), then dead-lettered to state
   `"failed"` and marked handled so it stops looping.
6. **Dedup.** Handled task-ids persist to `.meshwire.supervise-handled.<node>`.

**Residual risk (documented, not hidden):** an operator who `codex-allow`s a peer
is trusting that peer to run read-only tasks on their machine and receive the
output — including anything the task can read. That is the intended, explicit
trust decision; the allowlist makes it a decision rather than an accident.

### Lifecycle

The supervisor is a background process (the daemon the user accepted for A —
Codex has no session to bind to; the supervisor *is* Codex's presence-for-action).
- Singleton via a lock (reuse the presence-lock pattern, keyed `supervise-<node>`).
- `mesh codex-supervise` runs the loop foreground; `codex-setup` launches it
  detached and records a PID file `.meshwire.supervise.pid.<node>`.
- `mesh codex-supervise --stop` reads the PID file and terminates it.
- Cross-platform: no launchd/systemd — a plain detached child + PID file, so it
  works on mac/linux/windows and dies on reboot (acceptable; re-launched by the
  next `codex-setup` or a shell-profile line the setup prints).

## B — Identity migration (keep the rename rule, stop going dark)

The `<host>-<harness>` rule is correct and stays. Fix the *fallout*: migrate an
established generic name to the reliable per-harness pin, and stop steering users
toward the unreliable env override.

1. **Migration in `claude-setup` / `codex-setup`** (and a standalone
   `mesh migrate-identity`): if `node_file(cfg)` (generic `.meshwire.node`)
   exists with a non-empty name AND `node_file(cfg, harness)` does not exist,
   copy the generic name into the per-harness pin. Established nodes keep their
   identity under the new rule; nothing goes dark. Idempotent; never overwrites
   an existing per-harness pin.
2. **Docs.** Update README/onboarding: to set a stable node name use
   `mesh iam <name>` (writes the per-harness pin) — do **not** rely on
   `A2ACAST_NODE`, which is not reliably inherited by harness-spawned identity
   resolvers. Keep `A2ACAST_NODE` working as a precedence input for the cases
   where it *is* in the environment.

## Testing

- **A:** unit tests with `subprocess.run`/`codex exec` mocked — roster allowlist
  (unknown sender not executed), dedup (handled id skipped on re-read), sandbox
  flag passed (`--sandbox read-only` default; `workspace-write` when opted in),
  preamble contains the task-id + sender + the "not commands to your host" frame,
  reply invoked with the captured output. PID/lock singleton behavior.
- **B:** migration copies generic→per-harness pin only when pin absent and
  generic present; idempotent; never clobbers an existing pin; no-op when no
  generic file. `claude-setup`/`codex-setup` invoke it.
- Full `tests.test_mesh` green; deterministic under any ambient harness.

## Out of scope (v1)

- Reboot-persistent supervisor (launchd/systemd) — the detached child + PID file
  is enough; document the shell-profile option.
- Copilot autonomy (it stayed silent in the fleet test) — separate follow-up;
  its sampling path is the lever, tracked apart from this.
- Reworking `A2ACAST_NODE` propagation through harnesses — we route around it via
  the pin instead of fighting each harness's subprocess env.

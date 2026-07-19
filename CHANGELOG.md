# Changelog

## 0.15.1
- Security: invite bootstrap blocks now download `mesh.py` pinned to the
  inviting node's release tag (`v<VERSION>`) instead of the tip of `main`,
  so a bad or malicious push to main cannot break or compromise future
  joins.
- Add GitHub Actions CI: the unittest suite runs on Linux, macOS, and
  Windows across Python 3.8–3.13, a consistency job keeps
  `mesh.py`/`pyproject.toml`/plugin manifest versions in lock-step, and a
  gitleaks job scans full history for leaked secrets on every push.
- Add a PyPI publish workflow (trusted publishing, runs on GitHub release).
- Docs: list `mesh_delegate` in the MCP tools roster.

## 0.15.0
- Add an opt-in machine-wide worker pool with distinct Codex, Copilot, and
  Goose/Ollama identities.
- Add versioned isolated-worktree jobs, structured branch/commit results, and
  recipient-scoped task records so parallel supervisors cannot race.
- Add journaled execution, reply-only retries, health/cooldown routing, MCP
  delegation, conservative worktree cleanup, and macOS LaunchAgent lifecycle.
- Preserve the existing default-off, default-empty-allowlist Codex supervisor
  and document that worktrees are not security sandboxes.

## 0.14.1
- Fix (security): config writes are now durable read-modify-write under a
  lock — an incoming message (note_peer) or `mesh iam` can no longer clobber
  the curated `exec_allow` allowlist (#30). Also covers cmd_iam and my_node.
- Fix: `mesh codex-supervise` reloads the allowlist each poll, so
  `mesh codex-allow` takes effect on a running supervisor (#31).
- Fix: the supervisor runs its own relay receiver, so a headless Codex node
  (no session open) actually receives tasks instead of starving (#32).
- Fix: identity migration no longer claims the bare hostname — a node whose
  established name was just the old hostname default keeps the harness-aware
  `<host>-<harness>` name (#33).

## 0.14.0
- Identity migration: `mesh claude-setup`/`codex-setup` migrate an established
  generic `.meshwire.node` name into the per-harness pin, so nodes known by a
  plain name keep their identity under the harness-aware naming rule (no dark
  nodes on upgrade). `codex-setup` registers the migrated identity.
- Codex autonomy (opt-in): new `mesh codex-supervise` can make a joined
  Codex node an autonomous peer — it runs each delivered a2a task through
  `codex exec` and replies over the mesh.
- Security: autonomous execution is off by default. `mesh codex-setup` sets
  up presence only; pass `--supervise` to launch the actor. Even then,
  nothing auto-runs until you explicitly trust peers with
  `mesh codex-allow <node>` — a curated allowlist (default empty), not the
  auto-grown roster.
- Sandbox: `codex exec` runs `--sandbox read-only` by default
  (defense-in-depth; note that read-only still lets a task read and return
  repo contents, so only allow peers you trust). `--supervise-sandbox`
  widens it.
- Reliability: a task is claimed (state "working") before exec so it can't
  double-run; `codex exec` is bounded by a 600s timeout; failing or
  timed-out tasks are retried up to 3 times then dead-lettered (state
  "failed"); tasks stranded in "working" by a crash/stop are requeued on
  supervisor startup.

## 0.13.0
- Presence on session open: `mesh mcp-serve` is now the uniform presence
  watcher for Claude Code (`mesh claude-setup`), Codex CLI
  (`mesh codex-setup`), and Copilot (`mesh copilot-setup`) — the node
  answers pings, acks, and captures messages while the agent is idle.
- Single-subscriber rule: hook wake-watchers wait on the local delivery
  buffer when a presence server is live (no double relay subscription).
- Watch loop resubscribes forever on unexpected errors.
- Per-node activity files; harness-aware `mesh join`; `agent-hook-cleanup`
  resolves identity per-harness.

# Changelog

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

# Changelog

## 0.14.0
- Identity migration: `mesh claude-setup`/`codex-setup` migrate an established
  generic `.meshwire.node` name into the per-harness pin, so nodes known by a
  plain name keep their identity under the harness-aware naming rule (no dark
  nodes on upgrade). `codex-setup` registers the migrated identity.
- Codex autonomy: new `mesh codex-supervise` makes a joined Codex node an
  autonomous peer — it runs each delivered a2a task from a ROSTER peer through
  `codex exec --sandbox read-only` (safe default) and replies over the mesh;
  unknown senders are buffered, not executed. `codex-setup` launches it
  (`--supervise-sandbox` to change the sandbox, `--no-supervise` to skip).

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

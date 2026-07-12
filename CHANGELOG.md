# Changelog

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

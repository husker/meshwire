# Codex Spike Findings — presence + identity (plan Task 12)

**Date:** 2026-07-12 (live, Codex CLI on macOS, a2acast v0.13.0)

## Findings

1. **MCP registration works via `codex mcp add`** — `mesh codex-setup`
   registered the watcher on its first real-world run; `codex mcp get
   a2acast` confirms. Registration is global to Codex (documented caveat
   holds).
2. **Codex spawns the MCP server at session start and keeps it alive** —
   a fresh, fully idle Codex session had a live `mesh mcp-serve` process
   and held its presence lock.
3. **Codex does NOT pass the session env to MCP server processes.**
   `_detect_harness()` inside the server found no `CODEX_*` vars, fell
   back to the legacy generic node file, and served `<host>` instead of
   `<host>-codex`. (Claude Code, by contrast, does inherit env — its
   server resolved `<host>-claude` unaided.)
   → **Fix (shipped):** `cmd_codex_setup` pins identity explicitly with
   `--as <host>-codex` at registration time.
4. **Presence verified live under the pinned identity:**
   `MESH_PONG node=jamess-macbook-air-2-codex rtt=604ms` from a fresh,
   idle, untouched Codex session — while the Claude session's presence
   server served `<host>-claude` side by side. Two harnesses, one
   machine, two distinct reachable nodes: the collision fix and the
   presence layer working together.

## Still open (wake on Codex)

- The Codex a2acast plugin (Stop-hook wake) was not exercised in this
  spike — wake remains turn-windowed on Codex until its plugin hooks are
  installed and probed (arm-at-open equivalent unknown).
- Whether any Codex session-start hook event can run a command (for
  arm-at-open) remains unprobed.

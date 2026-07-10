# meshwire — Codex/ChatGPT plugin (v0.7)

**Date:** 2026-07-10
**Status:** approved design, pre-implementation
**Target version:** 0.7.0
**Reference:** https://learn.chatgpt.com/docs/build-plugins (fetched 2026-07-10)

## Goal

Make meshwire installable as a real Codex plugin — usable from Codex CLI
and ChatGPT desktop's plugin directory via
`codex plugin marketplace add husker/meshwire` — sharing the existing
skill and hook content with the Claude Code plugin. One repo, two plugin
systems, no duplicated protocol text.

## Build/verify split (the "hybrid")

Claude builds the files; the locally installed **Codex CLI (0.137.0)** is
the verifier of record — it is the only authority on whether a Codex
plugin actually loads. Verification is a first-class implementation step,
not an afterthought, and it resolves this spec's two open compatibility
questions (below).

## Components

1. **`.codex-plugin/plugin.json`** (new) — the Codex manifest:
   `name: "meshwire"` (kebab-case id), `version: "0.7.0"`, `description`,
   `"skills": "./skills/"`, and an `interface` object (`displayName`,
   `shortDescription`, `developerName`, `category`, `websiteURL`). No
   `apps`/`mcpServers` entries in this release.
2. **`.agents/plugins/marketplace.json`** (new) — the catalog that makes
   the repo an addable marketplace: marketplace `name: "meshwire"`, one
   `plugins[]` entry with `source: {source: "local", path: "./"}`,
   `policy: {installation: "AVAILABLE"}`, and a category.
3. **Shared skill** — `skills/mesh-agent/SKILL.md` is used as-is by both
   plugin systems (identical frontmatter format, identical default path).
   One additive tweak: the wake-mechanics section's one-shot bullet gains
   "(Codex CLI wakes on task completion — this loop is for you.)".
4. **Shared hook** — `hooks/hooks.json` (SessionStart node reminder) is
   the default hook path for both systems. Codex treats plugin hooks as
   untrusted until the user reviews them — README notes this.
5. **README** — the "Claude Code plugin" install block becomes a
   two-harness block: existing Claude lines, plus
   `codex plugin marketplace add husker/meshwire` and where the plugin
   then appears (Codex CLI / ChatGPT desktop plugin directory).
6. **docs/AGENTS.md** — the Codex section leads with the plugin install;
   the existing scripted one-shot loop stays as the no-plugin path.
7. **Versions** — `pyproject.toml`, `.claude-plugin/plugin.json`, and
   `.codex-plugin/plugin.json` all `0.7.0`; `USER_AGENT` → `"meshwire/0.7"`.
   No other mesh.py changes.

## Open compatibility questions → verification decides

**Q1 — plugin root = repo root.** The docs' examples nest plugins under
`plugins/<name>/`; meshwire's plugin folder is the repo root
(`source.path: "./"`), like its Claude plugin. Fallback chain if Codex
rejects `"./"`: (a) `plugins/meshwire/` containing only
`.codex-plugin/plugin.json` plus git symlinks `skills -> ../../skills`
and `hooks -> ../../hooks`; (b) if symlinks are rejected too, real copies
plus a unit test asserting the copies are byte-identical to the masters
(the sync guard makes duplication tolerable, not silent).

**Q2 — hooks.json field compatibility.** Our shared file carries
`"matcher": "startup"` (a Claude Code field absent from Codex's example).
If Codex rejects or misparses it, the fallback is an **inline hooks
object** in `.codex-plugin/plugin.json`'s `hooks` field (the manifest
entry overrides default-file discovery), leaving the Claude file
untouched.

## Verification protocol (local Codex CLI)

1. `codex plugin marketplace add /Users/james/Projects/meshwire` (local
   path form; the GitHub form is what end users run).
2. `codex plugin marketplace list` — the meshwire marketplace and plugin
   must resolve without schema errors.
3. On any failure: use `codex exec` to have Codex itself diagnose the
   manifest/catalog against its own schema, apply the relevant fallback,
   retry.
4. Best-effort hook check within CLI limits (hook shows as pending-trust,
   not errored).
5. `codex plugin marketplace remove` the test entry when done.

## Testing (suite, no network)

- Both new JSON files parse; `.codex-plugin/plugin.json` name is
  kebab-case, its `skills` path exists, its version matches
  `pyproject.toml`'s; marketplace entry's `source.path` resolves.
- If fallback Q1(b) lands: byte-identity test between copies and masters.
- Full existing suite stays green (mesh.py changes limited to USER_AGENT).

## Non-goals

- `.app.json` / ChatGPT dev-mode app and `.mcp.json` — they require the
  MCP server; that is cycle 2 (`mesh mcp-serve`), which will slot into
  this same plugin.
- Public listing via OpenAI's submission portal (personal/repo
  marketplaces cover our machines and anyone who adds the repo).
- `mesh codex-setup` snippet command — dropped; `docs/AGENTS.md` covers
  plugin-less setups.

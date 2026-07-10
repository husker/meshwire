# Codex/ChatGPT Plugin (v0.7.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship meshwire as a real Codex plugin installable via `codex plugin marketplace add husker/meshwire`, sharing the Claude plugin's skill and hook, verified by the locally installed Codex CLI — per the approved spec `docs/superpowers/specs/2026-07-10-codex-plugin-design.md`.

**Architecture:** Two new JSON files (`.codex-plugin/plugin.json` manifest, `.agents/plugins/marketplace.json` catalog) make the existing repo a Codex marketplace whose single plugin is the repo root itself; `skills/mesh-agent/SKILL.md` and `hooks/hooks.json` are shared with the Claude plugin unchanged (one additive SKILL.md sentence). Task 2 is the verification gate: the local Codex CLI (0.137.0) either accepts the files or drives the spec's fallback chains.

**Tech Stack:** JSON + markdown only; stdlib `unittest` for manifest tests; Codex CLI for verification. `mesh.py` changes limited to the `USER_AGENT` string.

## Global Constraints

- Versions in lockstep: `pyproject.toml` → `0.7.0`, `.claude-plugin/plugin.json` → `0.7.0`, `.codex-plugin/plugin.json` → `0.7.0`, `USER_AGENT = "meshwire/0.7"`.
- `skills/mesh-agent/SKILL.md` and `hooks/hooks.json` stay SHARED — no Codex-specific copies unless a spec fallback forces it (and then with a byte-identity test).
- Codex plugin `name` is kebab-case: `meshwire`.
- Tests: `python3 -m unittest discover -s tests -v` from repo root; currently 111 runs green; no network.
- Environment quirk: a PostToolUse hook runs `ruff check --fix` on .py edits — `git diff` before committing.
- Commits end with trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

---

### Task 1: Plugin files, doc edits, version bumps, manifest tests

**Files:**
- Create: `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`
- Modify: `skills/mesh-agent/SKILL.md` (one bullet), `README.md:40-48`, `docs/AGENTS.md:23-25`, `pyproject.toml:7`, `.claude-plugin/plugin.json:4`, `mesh.py:43` (USER_AGENT)
- Test: `tests/test_mesh.py` (append one class)

**Interfaces:**
- Produces: the two JSON files at their exact paths (Task 2 verifies them); `PluginManifestTests` in the suite.
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mesh.py`:

```python
class PluginManifestTests(unittest.TestCase):
    """The Codex plugin files parse, point at real paths, and match versions."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _load(self, rel):
        with open(os.path.join(self.ROOT, rel)) as f:
            return json.load(f)

    def test_codex_manifest_valid(self):
        m = self._load(".codex-plugin/plugin.json")
        self.assertRegex(m["name"], r"^[a-z0-9][a-z0-9-]*$")
        self.assertTrue(m["skills"].startswith("./"))
        self.assertTrue(os.path.isdir(os.path.join(self.ROOT, m["skills"])))

    def test_marketplace_catalog_valid(self):
        cat = self._load(".agents/plugins/marketplace.json")
        entry = cat["plugins"][0]
        self.assertEqual(entry["source"]["source"], "local")
        target = os.path.normpath(
            os.path.join(self.ROOT, entry["source"]["path"]))
        self.assertTrue(os.path.isfile(
            os.path.join(target, ".codex-plugin", "plugin.json")))

    def test_plugin_versions_match_pyproject(self):
        with open(os.path.join(self.ROOT, "pyproject.toml")) as f:
            py = f.read()
        for rel in (".codex-plugin/plugin.json",
                    ".claude-plugin/plugin.json"):
            v = self._load(rel)["version"]
            self.assertIn(f'version = "{v}"', py)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_mesh.PluginManifestTests -v`
Expected: ERROR ×3 — `FileNotFoundError: ... .codex-plugin/plugin.json`.

- [ ] **Step 3: Create `.codex-plugin/plugin.json`**

```json
{
  "name": "meshwire",
  "version": "0.7.0",
  "description": "Let this session message and exchange A2A tasks with AI agents on other machines over an encrypted, zero-infrastructure mesh.",
  "skills": "./skills/",
  "interface": {
    "displayName": "meshwire",
    "shortDescription": "Zero-infrastructure E2E-encrypted messaging between AI agents on different machines.",
    "developerName": "James Gagan",
    "category": "Productivity",
    "websiteURL": "https://github.com/husker/meshwire"
  }
}
```

(No `hooks` entry: Codex auto-discovers `./hooks/hooks.json`. No `apps`/`mcpServers`: cycle 2.)

- [ ] **Step 4: Create `.agents/plugins/marketplace.json`**

```json
{
  "name": "meshwire",
  "plugins": [
    {
      "name": "meshwire",
      "source": {
        "source": "local",
        "path": "./"
      },
      "policy": {
        "installation": "AVAILABLE"
      },
      "category": "Productivity",
      "interface": {
        "displayName": "meshwire"
      }
    }
  ]
}
```

- [ ] **Step 5: SKILL.md — Codex self-identification in the wake bullet**

In `skills/mesh-agent/SKILL.md`, replace:

```markdown
   - Harness only notifies when a background task **finishes** (a plain
     background shell task in most harnesses): a `--follow` watcher would
```

with:

```markdown
   - Harness only notifies when a background task **finishes** (a plain
     background shell task in most harnesses — Codex CLI, this is you): a
     `--follow` watcher would
```

- [ ] **Step 6: README — two-harness install block**

Replace lines 40-48 (`## Using it with Claude Code` through the closing fence):

````markdown
## Using it with Claude Code or Codex

Install the plugin (teaches sessions the protocol and auto-reminds them
when a project is a mesh node):

```
# Claude Code
/plugin marketplace add husker/meshwire
/plugin install meshwire

# Codex CLI / ChatGPT desktop
codex plugin marketplace add husker/meshwire
#   then install "meshwire" from the plugin directory picker
```

Codex asks you to review and trust the plugin's SessionStart hook on first
use — it is the one-liner that reminds sessions this project is a mesh node.
````

- [ ] **Step 7: docs/AGENTS.md — plugin-first Codex section**

Replace:

```markdown
The ChatGPT desktop app can't run persistent shell commands, but **Codex CLI**
(the same account/models, terminal-based) can. Two options:
```

with:

```markdown
The ChatGPT desktop app can't run persistent shell commands, but **Codex CLI**
(the same account/models, terminal-based) can. Easiest: install the plugin —
`codex plugin marketplace add husker/meshwire`, then add "meshwire" from the
plugin directory; it teaches sessions the same mesh-agent skill Claude Code
uses. Without the plugin, two options:
```

- [ ] **Step 8: Version bumps**

- `pyproject.toml`: `version = "0.7.0"`
- `.claude-plugin/plugin.json`: `"version": "0.7.0"`
- `mesh.py:43`: `USER_AGENT = "meshwire/0.7"`

- [ ] **Step 9: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: all pass (111 prior runs + 3 new). Also `git diff` hook-strip check on mesh.py.

- [ ] **Step 10: Commit**

```bash
git add .codex-plugin .agents skills/mesh-agent/SKILL.md README.md docs/AGENTS.md pyproject.toml .claude-plugin/plugin.json mesh.py tests/test_mesh.py
git commit -m "feat: Codex/ChatGPT plugin — manifest + marketplace catalog sharing the Claude plugin's skill and hook"
```

---

### Task 2: Codex CLI verification gate + release

**Files:**
- Possibly modify (fallbacks only): `.agents/plugins/marketplace.json`, `.codex-plugin/plugin.json`, or new `plugins/meshwire/` symlink folder
- No planned file changes on the happy path.

**Interfaces:**
- Consumes: Task 1's two JSON files; local `codex` CLI (0.137.0, at `/opt/homebrew/bin/codex`).

- [ ] **Step 1: Add the repo as a local marketplace**

Run: `codex plugin marketplace add /Users/james/Projects/meshwire`
Expected: success message; no schema errors.

- [ ] **Step 2: Confirm the plugin resolves**

Run: `codex plugin marketplace list`
Expected: a `meshwire` marketplace whose root resolves to the repo, exposing plugin `meshwire`. Record the exact output in the task report.

- [ ] **Step 3 (only on failure): diagnose with Codex itself, apply the spec's fallback, retry**

Run: `codex exec "Read .codex-plugin/plugin.json and .agents/plugins/marketplace.json in /Users/james/Projects/meshwire and explain exactly why 'codex plugin marketplace add' rejects them, citing the current plugin/marketplace schema. Answer with the minimal concrete fix."`

Apply per the spec's fallback chains — Q1 (`"./"` rejected): create `plugins/meshwire/` containing `.codex-plugin/plugin.json` (moved) plus symlinks `skills -> ../../skills`, `hooks -> ../../hooks`, and point the catalog at `./plugins/meshwire`; if symlinks are rejected, copies + byte-identity test:

```python
    def test_codex_plugin_copies_match_masters(self):
        for rel in ("skills/mesh-agent/SKILL.md", "hooks/hooks.json"):
            with open(os.path.join(self.ROOT, rel), "rb") as f:
                master = f.read()
            with open(os.path.join(self.ROOT, "plugins", "meshwire", rel),
                      "rb") as f:
                self.assertEqual(f.read(), master, rel)
```

Q2 (`"matcher"` in hooks.json rejected): add to `.codex-plugin/plugin.json` an inline hooks object (Claude's file untouched):

```json
  "hooks": {
    "hooks": {
      "SessionStart": [
        {
          "hooks": [
            {
              "type": "command",
              "command": "if [ -f .meshwire.json ]; then echo 'This project is a meshwire node. Load the meshwire:mesh-agent skill and arm the watcher in a way that wakes this session per message (one-shot re-arm loop: mesh watch --timeout 5400, act, re-arm).'; fi"
            }
          ]
        }
      ]
    }
  }
```

Then re-run Steps 1-2 until clean. Re-run the full unittest suite after any fallback edit.

- [ ] **Step 4: Best-effort hook state check**

Run: `codex plugin marketplace list` output review + (if available in this CLI version) `codex plugin list`.
Expected: the plugin visible; hook shown as pending-trust or simply present — anything except a parse ERROR. Record what the CLI actually reports; parse-level success is the acceptance bar (the interactive trust flow happens on first real use).

- [ ] **Step 5: Clean up the test marketplace**

Run: `codex plugin marketplace remove meshwire` (use the name Step 2's list shows).
Expected: removed; `codex plugin marketplace list` no longer shows the repo entry.

- [ ] **Step 6: Release commit (only if fallbacks changed files; otherwise amend nothing — tag the release message on the final state)**

If Step 3 made changes:

```bash
git add -u && git add plugins 2>/dev/null; git commit -m "fix: Codex schema fallbacks from live CLI verification"
```

Then in all cases finish with:

```bash
git commit --allow-empty -m "v0.7.0 — Codex/ChatGPT plugin verified against Codex CLI 0.137.0

codex plugin marketplace add husker/meshwire now serves the same
mesh-agent skill and SessionStart hook the Claude Code plugin ships.
Verification transcript in .superpowers/sdd/ report."
```

---

## Self-Review (performed while writing)

1. **Spec coverage:** Components 1-7 → Task 1 Steps 3-8. Verification protocol → Task 2 Steps 1-5. Q1/Q2 fallbacks → Task 2 Step 3 (with the byte-identity test from the spec's testing section). Non-goals respected (no `.app.json`, no `mcpServers`, no codex-setup command). No gaps.
2. **Placeholder scan:** clean — every step has full content; Task 2's conditional steps state their trigger conditions concretely.
3. **Type consistency:** paths and names match across tasks (`.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `plugins/meshwire/` fallback); `PluginManifestTests.ROOT` idiom matches the existing test file's path-resolution style.

# Armed Watcher on Join — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A node has an armed watcher (presence: pings/acks/message capture) the moment its agent session opens, on all three CLIs, with per-harness agent wake — session-bound, no daemon.

**Architecture:** The existing `MeshMCPServer` (`mesh mcp-serve`) already runs a relay watch loop that answers pings, acks, and buffers deliveries — it is the presence layer. This plan hardens it (reconnect-forever, single-subscriber presence lock, per-node activity file), registers it with Claude Code (`.mcp.json`) and Codex (`codex mcp add`) the way `copilot-setup` already does for Copilot, and re-points the existing Stop-hook wake watchers to wait on the server's local activity file instead of opening a second relay subscription.

**Tech Stack:** Python 3 stdlib only (single-file `mesh.py`), `unittest` with mocked transport, JSON plugin configs.

**Spec:** `docs/superpowers/specs/2026-07-11-armed-watcher-on-join-design.md`

## Global Constraints

- All code must work on macOS, Linux, and Windows. No `lsof`, no POSIX-only tricks (except `os.kill(pid, 0)` liveness checks already established in `_hook_lock_is_live`).
- `mesh.py` stays a single stdlib-only file. No new dependencies.
- Plugin configs invoke the `mesh` console script, never `python3 mesh.py`.
- Tests: mocked transport only — no real ntfy.sh I/O (issue #6). Suite must stay green under any ambient harness: patch `mesh._detect_harness` to `None` (or a fixed value) in any test that resolves identity, and pop `A2ACAST_NODE` (uppercase) from env.
- Timezone-aware datetimes only: `datetime.now(timezone.utc)`.
- Run the full suite before every commit: `.venv/bin/python -m unittest tests.test_mesh` → all pass.
- Line numbers below are anchors into the pre-change file — locate by function name if they have drifted.
- Codex Stop-hook JSON: never emit `{}` or empty stdout; `{"continue": true}` is the no-op, `{"decision": "block", "reason": ...}` continues the session.

## File Structure

- `mesh.py` — all runtime changes (single-file constraint):
  - per-node activity file helper + call-site updates
  - `watch_loop` outer reconnect loop
  - presence lock (`presence_lock_file`, `_acquire_presence_lock`, `_presence_is_live`)
  - buffer-mode hook wait (`_wait_for_activity`) wired into `_wait_for_hook_message`
  - `cmd_claude_setup` rewrite (writes `.mcp.json`), new `cmd_codex_setup`, parser entries
  - `cmd_join` harness-aware identity; `cmd_agent_hook_cleanup` harness fix
  - `cmd_agent_session_hook` text update; `_integrate_harness` text updates
- `tests/test_mesh.py` — new test classes: `ActivityFileTests`, `WatchLoopResilienceTests`, `PresenceLockTests`, `BufferWaitTests`, `ClaudeSetupTests`, `CodexSetupTests`, `JoinHarnessTests`; extensions to `MCPServeTests`, `MembershipCmdTests`-family.
- `hooks/hooks.json` — Claude plugin: SessionStart arm-at-open entry (Task 11, gated on live probe).
- `docs/superpowers/specs/2026-07-11-codex-wake-spike.md` — created by Task 12 (findings record).

---

### Task 1: Per-node activity file

Two harness nodes in one directory currently share `.meshwire.activity` — their wake signals and "handled while away" notes cross-talk. Make the file per-node.

**Files:**
- Modify: `mesh.py` (constant near line 45; `_record_activity` ~1491; `cmd_copilot_activity` ~1745)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `activity_file(cfg, node) -> str` — absolute path `<cfg _dir>/.meshwire.activity.<node>`. Tasks 5 and 6 consume it.
- `_record_activity` writes to `activity_file(self.cfg, self.me)`.
- `cmd_copilot_activity` reads per-node file, plus the legacy `.meshwire.activity` if present (merge, legacy first), and removes both.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_mesh.py` (near `MCPServeTests`):

```python
class ActivityFileTests(unittest.TestCase):
    def test_activity_file_is_per_node(self):
        cfg = {"_dir": "/tmp/x"}
        self.assertEqual(mesh.activity_file(cfg, "alpha"),
                         os.path.join("/tmp/x", ".meshwire.activity.alpha"))

    def test_record_activity_writes_per_node_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfg = make_cfg(tmp.name)
        srv = mesh.MeshMCPServer(cfg, "alpha", out=lambda s: None)
        srv._record_activity({"kind": "message", "from": "beta",
                              "text": "hello"})
        path = mesh.activity_file(cfg, "alpha")
        with open(path) as f:
            self.assertIn("message from beta: hello", f.read())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m unittest tests.test_mesh.ActivityFileTests -v`
Expected: FAIL/ERROR with `AttributeError: module 'mesh' has no attribute 'activity_file'`

- [ ] **Step 3: Implement**

In `mesh.py`, directly below the `ACTIVITY_FILE = ".meshwire.activity"` constant (line ~45 — keep the constant; it is the legacy path):

```python
def activity_file(cfg, node):
    """Per-node activity/wake-signal file. Two harness nodes sharing one
    directory must not cross-talk on wake signals."""
    return os.path.join(cfg["_dir"], f"{ACTIVITY_FILE}.{node}")
```

In `_record_activity` (inside `MeshMCPServer`, ~line 1506), replace the `open(...)` target:

```python
        try:
            with open(activity_file(self.cfg, self.me),
                      "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass
```

In `cmd_copilot_activity` (~line 1756), replace the single-path read with a merged per-node + legacy read:

```python
    cfg = json.load(open(path, "r", encoding="utf-8"))
    cfg["_path"] = path
    cfg["_dir"] = os.path.dirname(path)
    me = my_node(cfg, None)
    candidates = [os.path.join(cfg["_dir"], ACTIVITY_FILE),   # legacy
                  activity_file(cfg, me)]
    lines = []
    for act in candidates:
        try:
            with open(act, "r", encoding="utf-8") as f:
                lines.extend(ln.strip() for ln in f if ln.strip())
        except OSError:
            continue
        try:
            os.remove(act)
        except OSError:
            pass
    if not lines:
        print("{}")
        return
```

(Delete the old `act = os.path.join(...)` / single `try/except` read and the old `if not lines` / `os.remove` block it replaces. Keep everything from `n = len(lines)` down unchanged.)

Note: `cmd_copilot_activity` previously never loaded cfg — it only had `path`. `my_node` needs cfg with `_dir`. The replacement above adds that load. `my_node(cfg, None)` auto-detects harness (copilot env is present in a Copilot hook).

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m unittest tests.test_mesh.ActivityFileTests -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Full suite, then commit**

```bash
.venv/bin/python -m unittest tests.test_mesh 2>&1 | tail -3   # all pass
git add mesh.py tests/test_mesh.py
git commit -m "feat: per-node activity file (no cross-talk between harness nodes)"
```

---

### Task 2: Watch-loop reconnect-forever

`MeshMCPServer.watch_loop` (~1585–1637) dies permanently on any exception that escapes `_stream_events` — presence silently dies while the session lives. Wrap it in an outer retry loop with backoff.

**Files:**
- Modify: `mesh.py` (`watch_loop`, ~1585)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `watch_loop()` never returns while `self._stop` is unset (except by process exit); internal `_watch_once(cfg, me, tpc)` holds the old body.

- [ ] **Step 1: Write the failing test**

```python
class WatchLoopResilienceTests(unittest.TestCase):
    def test_watch_loop_resubscribes_after_unexpected_error(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        cfg = make_cfg(tmp.name)
        srv = mesh.MeshMCPServer(cfg, "alpha", out=lambda s: None)
        srv._initialized.set()
        calls = []

        def fake_watch_once(cfg_, me_, tpc_):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")          # unexpected error
            srv._stop.set()                         # second pass: end test

        with mock.patch.object(srv, "_watch_once", fake_watch_once), \
             mock.patch.object(mesh.time, "sleep", lambda s: None):
            srv.watch_loop()
        self.assertEqual(len(calls), 2)             # it came back
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m unittest tests.test_mesh.WatchLoopResilienceTests -v`
Expected: FAIL/ERROR — `_watch_once` does not exist yet.

- [ ] **Step 3: Implement**

Restructure `watch_loop` (keep its current body, move it into `_watch_once`):

```python
    def watch_loop(self):
        cfg, me = self.cfg, self.me
        tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
        self._initialized.wait(30)
        backoff = 1
        while not self._stop.is_set():
            try:
                self._watch_once(cfg, me, tpc)
                return          # clean return only happens on _stop
            except Exception as exc:   # presence must never die silently
                print(f"mesh mcp watch loop error (resubscribing in "
                      f"{backoff}s): {exc}", file=sys.stderr)
                if self._stop.wait(backoff):
                    return
                backoff = min(backoff * 2, 30)

    def _watch_once(self, cfg, me, tpc):
        cf = cursor_file(cfg, me)
        since, seen = _load_cursor(cf)
        skip = set(seen)
        replay_seen = load_replays(cfg, me)
        for ev in _stream_events(cfg, tpc, str(since), None, skip=skip):
            ...            # the ENTIRE existing for-body, unchanged,
            ...            # from `if self._stop.is_set(): return` down to
            ...            # `self.deliver(delivery)`
```

Concretely: cut lines from `cf = cursor_file(cfg, me)` through the end of the `for` body out of the old `watch_loop`, paste into `_watch_once`, and delete the old `try/except Exception ... print("mesh mcp watch loop stopped: ...")` wrapper (the outer loop replaces it). Cursor state is reloaded from disk on every resubscribe, so nothing replays.

- [ ] **Step 4: Run test + full suite**

Run: `.venv/bin/python -m unittest tests.test_mesh.WatchLoopResilienceTests tests.test_mesh.MCPServeTests -v`
Expected: PASS. Then full suite: all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "fix: mcp watch loop resubscribes forever instead of dying on error"
```

---

### Task 3: Presence lock — one relay subscriber per node

**Files:**
- Modify: `mesh.py` (below `hook_lock_file`/`_acquire_hook_lock`, ~1827–1874; and `_run_mcp_server`, ~1705)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces (Tasks 4, 5 consume):
  - `PRESENCE_LOCK_PREFIX = "mw-presence-"` (module constant, next to `HOOK_LOCK_PREFIX`)
  - `presence_lock_file(cfg, node) -> str`
  - `_acquire_presence_lock(cfg, node) -> str | None` (path on success)
  - `_presence_is_live(cfg, node) -> bool`

- [ ] **Step 1: Write the failing tests**

```python
class PresenceLockTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cfg = make_cfg(tmp.name)

    def test_acquire_and_liveness(self):
        self.assertFalse(mesh._presence_is_live(self.cfg, "alpha"))
        path = mesh._acquire_presence_lock(self.cfg, "alpha")
        self.assertIsNotNone(path)
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        self.assertTrue(mesh._presence_is_live(self.cfg, "alpha"))

    def test_second_acquire_fails_while_first_lives(self):
        path = mesh._acquire_presence_lock(self.cfg, "alpha")
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        self.assertIsNone(mesh._acquire_presence_lock(self.cfg, "alpha"))

    def test_stale_lock_is_reclaimed(self):
        path = mesh.presence_lock_file(self.cfg, "alpha")
        with open(path, "w") as f:
            json.dump({"pid": 99999999}, f)      # dead pid
        got = mesh._acquire_presence_lock(self.cfg, "alpha")
        self.assertIsNotNone(got)
        os.unlink(got)

    def test_distinct_nodes_get_distinct_locks(self):
        self.assertNotEqual(mesh.presence_lock_file(self.cfg, "alpha"),
                            mesh.presence_lock_file(self.cfg, "beta"))
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/python -m unittest tests.test_mesh.PresenceLockTests -v`
Expected: ERROR — `mesh` has no attribute `_presence_is_live`.

- [ ] **Step 3: Implement**

Next to `HOOK_LOCK_PREFIX` (find it near the other constants), add `PRESENCE_LOCK_PREFIX = "mw-presence-"`. Below `_acquire_hook_lock`:

```python
def presence_lock_file(cfg, node):
    """Cross-platform singleton lock: one relay-subscribing presence
    server per mesh node (same scheme as hook_lock_file)."""
    identity = f"{os.path.realpath(cfg['_dir'])}\0{node}".encode()
    suffix = hashlib.sha256(identity).hexdigest()[:20]
    return os.path.join(tempfile.gettempdir(), PRESENCE_LOCK_PREFIX + suffix)


def _acquire_presence_lock(cfg, node):
    path = presence_lock_file(cfg, node)
    for _ in range(3):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            if _hook_lock_is_live(path):
                return None
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError:
                return None
            continue
        try:
            os.write(fd, json.dumps({"pid": os.getpid()}).encode())
        finally:
            os.close(fd)
        return path
    return None


def _presence_is_live(cfg, node):
    path = presence_lock_file(cfg, node)
    return os.path.exists(path) and _hook_lock_is_live(path)
```

Wire into `_run_mcp_server` — replace the two lines
`server = MeshMCPServer(cfg, me)` / `threading.Thread(target=server.watch_loop, daemon=True).start()` / `_mcp_stdin_loop(server.handle)` / `server._stop.set()` with:

```python
    server = MeshMCPServer(cfg, me)
    plock = _acquire_presence_lock(cfg, me)
    if plock:
        threading.Thread(target=server.watch_loop, daemon=True).start()
    else:
        print(f"a2acast {label}: another presence server owns node "
              f"'{me}' — serving tools only", file=sys.stderr)
    try:
        _mcp_stdin_loop(server.handle)
    finally:
        server._stop.set()
        if plock:
            try:
                os.unlink(plock)
            except FileNotFoundError:
                pass
```

- [ ] **Step 4: Run tests + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: presence lock — one relay-subscribing server per node"
```

---

### Task 4: Buffer-mode hook wait (single-subscriber rule for wake watchers)

When a presence server is live, the Stop-hook watcher must NOT open a second relay subscription — it waits on the per-node activity file and, on growth, tells the agent to drain `mesh_pending`. When no presence server is live, the legacy relay wait stays (back-compat for users who never ran a setup command).

**Files:**
- Modify: `mesh.py` (`_wait_for_hook_message`, ~1909)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `_wait_for_activity(cfg, me, timeout) -> str | None` — summary text on delivery, `None` on timeout/none. `_wait_for_hook_message` dispatches: presence live → `_wait_for_activity`; else legacy `cmd_watch` capture. Poll interval 1s; consumed file is removed after read.

- [ ] **Step 1: Write the failing tests**

```python
class BufferWaitTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cfg = make_cfg(tmp.name)

    def test_returns_summary_when_activity_appears(self):
        act = mesh.activity_file(self.cfg, "alpha")
        with open(act, "w") as f:
            f.write("message from beta: hi\n")
        with mock.patch.object(mesh, "_presence_is_live", return_value=True):
            got = mesh._wait_for_activity(self.cfg, "alpha", timeout=3)
        self.assertIn("message from beta: hi", got)
        self.assertIn("mesh_pending", got)
        self.assertFalse(os.path.exists(act))     # consumed

    def test_times_out_quietly_when_no_activity(self):
        with mock.patch.object(mesh, "_presence_is_live", return_value=True):
            self.assertIsNone(
                mesh._wait_for_activity(self.cfg, "alpha", timeout=1))

    def test_returns_none_when_presence_dies(self):
        with mock.patch.object(mesh, "_presence_is_live",
                               return_value=False):
            self.assertIsNone(
                mesh._wait_for_activity(self.cfg, "alpha", timeout=5))

    def test_hook_wait_uses_buffer_mode_when_presence_live(self):
        # in cwd with a mesh config + pinned identity
        os.chdir(self.cfg["_dir"])
        with open(mesh.CONFIG_NAME, "w") as f:
            json.dump({k: v for k, v in self.cfg.items()
                       if not k.startswith("_")}, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        act = mesh.activity_file(self.cfg, "alpha")
        with open(act, "w") as f:
            f.write("task from beta: build it\n")
        with mock.patch.object(mesh, "_detect_harness",
                               return_value=None), \
             mock.patch.object(mesh, "_presence_is_live",
                               return_value=True), \
             mock.patch.object(mesh, "cmd_watch") as watch:
            out = mesh._wait_for_hook_message(
                argparse.Namespace(timeout=3), hook_input={})
        watch.assert_not_called()                  # no second subscription
        self.assertIn("task from beta", out)
```

(Adopt the surrounding tests' tempdir/chdir/teardown conventions from `MembershipCmdTests` — this class needs the same `os.chdir` restore in `tearDown`: save `os.getcwd()` in `setUp`, chdir back in cleanup.)

- [ ] **Step 2: Run to verify failure** — `_wait_for_activity` missing.

- [ ] **Step 3: Implement**

Above `_wait_for_hook_message`:

```python
def _wait_for_activity(cfg, me, timeout):
    """Wake-wait against the presence server's local activity file instead
    of opening a second relay subscription (single-subscriber rule). Reads
    and consumes the file; returns a summary telling the agent to drain
    mesh_pending, or None on timeout / when the presence server dies."""
    act = activity_file(cfg, me)
    deadline = time.time() + (timeout or 10800)
    while time.time() < deadline:
        try:
            size = os.path.getsize(act)
        except OSError:
            size = 0
        if size > 0:
            time.sleep(0.2)          # let a mid-write line land
            try:
                with open(act, "r", encoding="utf-8") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                os.remove(act)
            except OSError:
                lines = []
            if lines:
                n = len(lines)
                shown = "; ".join(lines[:5])
                if n > 5:
                    shown += f"; and {n - 5} more"
                noun = "delivery" if n == 1 else "deliveries"
                return (f"{n} a2acast {noun} arrived while the session was "
                        f"idle: {shown}. Read the full content now with the "
                        f"mesh_pending MCP tool and handle it.")
        if not _presence_is_live(cfg, me):
            return None              # server gone; next arm uses relay mode
        time.sleep(1)
    return None
```

In `_wait_for_hook_message`, after the lock is acquired (`if lock is None: return None`), insert the dispatch before the `captured, ignored_err = ...` line:

```python
    if _presence_is_live(cfg, me):
        try:
            return _wait_for_activity(cfg, me, args.timeout)
        finally:
            try:
                os.unlink(lock)
            except FileNotFoundError:
                pass
```

(The legacy `cmd_watch` capture below stays exactly as-is for the no-presence case.)

- [ ] **Step 4: Run BufferWaitTests + the hook classes + full suite** — all pass.

Run: `.venv/bin/python -m unittest tests.test_mesh.BufferWaitTests tests.test_mesh.CodexHookTests -v`, then full suite.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: hook watchers wait on the local buffer when a presence server is live"
```

---

### Task 5: `agent-hook-cleanup` resolves identity per-harness

`cmd_agent_hook_cleanup` (~1997) calls `my_node(cfg, None)` — ambient detection, not the hook's own `--harness`. Post-04e450f this can resolve the wrong node and fail to clean the right lock.

**Files:**
- Modify: `mesh.py` (`cmd_agent_hook_cleanup`, one line)
- Test: `tests/test_mesh.py`

**Interfaces:** none new — behavior fix.

- [ ] **Step 1: Failing test** (in the existing `CodexHookTests` or a small new class using the `MembershipCmdTests` base):

```python
    def test_cleanup_resolves_node_for_its_harness(self):
        cfg = self._write_cfg()          # per the class's existing helper
        with open(".meshwire.node.claude", "w") as f:
            f.write("alpha\n")
        seen = {}
        with mock.patch.object(mesh, "my_node",
                               side_effect=lambda c, o, h=None:
                               seen.setdefault("h", h) or "alpha") as mn, \
             mock.patch.object(mesh.sys, "stdin",
                               io.StringIO('{"session_id": "s1"}')):
            mesh.cmd_agent_hook_cleanup(
                argparse.Namespace(harness="claude"))
        self.assertEqual(seen["h"], "claude")
```

(Adapt the cfg-setup line to the host class's existing helper; the assertion that matters is `my_node` received `harness="claude"`.)

- [ ] **Step 2: Run to verify failure** — `seen["h"]` is `None`.

- [ ] **Step 3: Implement** — in `cmd_agent_hook_cleanup` change:

```python
    me = my_node(cfg, None, args.harness)
```

- [ ] **Step 4: Run test + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "fix: agent-hook-cleanup resolves node identity for its own harness"
```

---

### Task 6: `mesh claude-setup` writes the project `.mcp.json`

Today `cmd_claude_setup` (~2428) only prints `CLAUDE_SNIPPET`. Rewrite it to register the presence server, mirroring `cmd_copilot_setup` (~1782). The snippet stays available via `mesh integrate --format claude`.

**Files:**
- Modify: `mesh.py` (`cmd_claude_setup` ~2428; its parser entry — search `add_parser("claude-setup"`)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `.mcp.json` in the project root with `mcpServers.a2acast = {"command": "mesh", "args": ["mcp-serve", "--config", <abs cfg path>]}`; idempotent; `.mcp.json` added to `.gitignore` (machine-specific pinned path, same rationale as copilot-setup).

- [ ] **Step 1: Failing tests**

```python
class ClaudeSetupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._old = os.getcwd()
        self.addCleanup(lambda: os.chdir(self._old))
        os.chdir(self._tmp.name)
        cfg = make_cfg(self._tmp.name)
        with open(mesh.CONFIG_NAME, "w") as f:
            json.dump({k: v for k, v in cfg.items()
                       if not k.startswith("_")}, f)

    def _run(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mesh.cmd_claude_setup(argparse.Namespace(dir=None))
        return out.getvalue()

    def test_writes_mcp_json_with_pinned_config(self):
        self._run()
        with open(".mcp.json") as f:
            data = json.load(f)
        srv = data["mcpServers"]["a2acast"]
        self.assertEqual(srv["command"], "mesh")
        self.assertEqual(srv["args"][:2], ["mcp-serve", "--config"])
        self.assertTrue(os.path.isabs(srv["args"][2]))

    def test_idempotent_and_preserves_other_servers(self):
        with open(".mcp.json", "w") as f:
            json.dump({"mcpServers": {"other": {"command": "x"}}}, f)
        self._run()
        self._run()
        with open(".mcp.json") as f:
            data = json.load(f)
        self.assertIn("other", data["mcpServers"])
        self.assertIn("a2acast", data["mcpServers"])

    def test_gitignores_mcp_json(self):
        self._run()
        with open(".gitignore") as f:
            self.assertIn(".mcp.json", f.read())

    def test_errors_without_mesh_config(self):
        os.remove(mesh.CONFIG_NAME)
        with self.assertRaises(SystemExit):
            mesh.cmd_claude_setup(argparse.Namespace(dir=None))
```

- [ ] **Step 2: Run to verify failure** — current `cmd_claude_setup` takes no `dir`, writes nothing.

- [ ] **Step 3: Implement**

Replace `cmd_claude_setup` entirely:

```python
def cmd_claude_setup(args):
    """Register the a2acast presence watcher for Claude Code by writing the
    project's .mcp.json (idempotent). Claude Code spawns the server with
    every session, so the node answers pings and captures messages from the
    moment the session opens. Run once per project per machine."""
    cfg_path = find_config(getattr(args, "dir", None))
    if not cfg_path:
        sys.exit(f"error: no {CONFIG_NAME} found here or in any parent "
                 f"directory. Run `mesh init` or `mesh join` first.")
    project = os.path.dirname(cfg_path)
    mcp_path = os.path.join(project, ".mcp.json")
    data = {}
    if os.path.isfile(mcp_path):
        try:
            with open(mcp_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
    if not isinstance(data, dict):
        data = {}
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers["a2acast"] = {
        "command": "mesh",
        "args": ["mcp-serve", "--config", os.path.abspath(cfg_path)],
    }
    data["mcpServers"] = servers
    with open(mcp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    # the pinned path is machine-specific; keep it out of version control
    _gitignore_add(project, [".mcp.json"])
    print(f"Wrote {mcp_path}")
    print(f"  a2acast presence watcher pinned to {os.path.abspath(cfg_path)}")
    print("Start a Claude Code session in this project to pick it up. For "
          "the CLAUDE.md protocol snippet, run `mesh integrate --format "
          "claude`.")
```

Update the parser entry (search `add_parser("claude-setup"`):

```python
    p = sub.add_parser("claude-setup",
                       help="wire the Claude Code presence watcher for this "
                            "project (writes .mcp.json)")
    p.add_argument("--dir", default=None,
                   help="project dir to set up (default: search from cwd)")
    p.set_defaults(fn=cmd_claude_setup)
```

- [ ] **Step 4: Run ClaudeSetupTests + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: mesh claude-setup registers the presence watcher in .mcp.json"
```

---

### Task 7: `mesh codex-setup` registers via `codex mcp add`

Codex owns `~/.codex/config.toml`; writing TOML by hand from stdlib is fragile, and `codex mcp add` exists (verified: `codex mcp` → `list/get/add/remove/...`). Shell out.

**Files:**
- Modify: `mesh.py` (new `cmd_codex_setup` next to `cmd_claude_setup`; parser entry next to claude-setup's; ensure `import subprocess` is present at the top — check, add if missing)
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `codex mcp add a2acast -- mesh mcp-serve --config <abs>` invocation. Registration is global to Codex (documented caveat: last `codex-setup` from any project wins the `a2acast` name; the presence lock keeps servers single-instance per node).

- [ ] **Step 1: Failing tests**

```python
class CodexSetupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._old = os.getcwd()
        self.addCleanup(lambda: os.chdir(self._old))
        os.chdir(self._tmp.name)
        cfg = make_cfg(self._tmp.name)
        with open(mesh.CONFIG_NAME, "w") as f:
            json.dump({k: v for k, v in cfg.items()
                       if not k.startswith("_")}, f)

    def test_invokes_codex_mcp_add_with_pinned_config(self):
        ok = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(mesh.subprocess, "run",
                               return_value=ok) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                mesh.cmd_codex_setup(argparse.Namespace(dir=None))
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[:4], ["codex", "mcp", "add", "a2acast"])
        self.assertIn("mcp-serve", cmd)
        self.assertIn("--config", cmd)
        self.assertTrue(os.path.isabs(cmd[-1]))

    def test_missing_codex_cli_prints_manual_toml(self):
        with mock.patch.object(mesh.subprocess, "run",
                               side_effect=FileNotFoundError):
            with self.assertRaises(SystemExit) as ctx:
                mesh.cmd_codex_setup(argparse.Namespace(dir=None))
        self.assertIn("[mcp_servers.a2acast]", str(ctx.exception))

    def test_codex_failure_surfaces_stderr(self):
        bad = mock.Mock(returncode=1, stdout="", stderr="nope")
        with mock.patch.object(mesh.subprocess, "run", return_value=bad):
            with self.assertRaises(SystemExit) as ctx:
                mesh.cmd_codex_setup(argparse.Namespace(dir=None))
        self.assertIn("nope", str(ctx.exception))

    def test_errors_without_mesh_config(self):
        os.remove(mesh.CONFIG_NAME)
        with self.assertRaises(SystemExit):
            mesh.cmd_codex_setup(argparse.Namespace(dir=None))
```

- [ ] **Step 2: Run to verify failure** — `cmd_codex_setup` missing.

- [ ] **Step 3: Implement**

Check the imports at the top of `mesh.py`; if `subprocess` is absent, add it to the stdlib import block. Then:

```python
def cmd_codex_setup(args):
    """Register the a2acast presence watcher with Codex CLI via
    `codex mcp add` (Codex owns its config format — shelling out keeps us
    compatible). The registration is global to Codex and pinned to this
    project's node; running codex-setup from another mesh project later
    repoints the single `a2acast` entry there."""
    cfg_path = find_config(getattr(args, "dir", None))
    if not cfg_path:
        sys.exit(f"error: no {CONFIG_NAME} found here or in any parent "
                 f"directory. Run `mesh init` or `mesh join` first.")
    pinned = os.path.abspath(cfg_path)
    cmd = ["codex", "mcp", "add", "a2acast", "--",
           "mesh", "mcp-serve", "--config", pinned]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("error: `codex` CLI not found on PATH. Install Codex CLI, "
                 "or add this to ~/.codex/config.toml yourself:\n"
                 "  [mcp_servers.a2acast]\n"
                 "  command = \"mesh\"\n"
                 f"  args = [\"mcp-serve\", \"--config\", \"{pinned}\"]")
    if r.returncode != 0:
        sys.exit("error: `codex mcp add` failed: "
                 f"{(r.stderr or r.stdout).strip()}")
    print("Registered the a2acast presence watcher with Codex CLI "
          f"(pinned to {pinned}).")
    print("Note: Codex MCP registration is global — the watcher starts "
          "with every Codex session on this machine and serves this "
          "project's node; the presence lock keeps it single-instance.")
```

Parser entry (immediately after the claude-setup entry from Task 6):

```python
    p = sub.add_parser("codex-setup",
                       help="wire the Codex CLI presence watcher "
                            "(runs `codex mcp add`)")
    p.add_argument("--dir", default=None,
                   help="project dir to set up (default: search from cwd)")
    p.set_defaults(fn=cmd_codex_setup)
```

- [ ] **Step 4: Run CodexSetupTests + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: mesh codex-setup registers the presence watcher via codex mcp add"
```

---

### Task 8: Onboarding text — integrate + session hook mention the setups and mesh_pending

**Files:**
- Modify: `mesh.py` (`_integrate_harness` ~2458; `cmd_agent_session_hook` ~1224)
- Test: `tests/test_mesh.py`

**Interfaces:** text-only; tests assert key phrases.

- [ ] **Step 1: Failing tests**

```python
class OnboardingTextTests(unittest.TestCase):
    def test_integrate_codex_mentions_codex_setup(self):
        self.assertIn("mesh codex-setup", mesh._integrate_harness("codex"))

    def test_integrate_claude_mentions_claude_setup(self):
        self.assertIn("mesh claude-setup", mesh._integrate_harness("claude"))

    def test_session_hook_mentions_mesh_pending(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        old = os.getcwd()
        self.addCleanup(lambda: os.chdir(old))
        os.chdir(tmp.name)
        cfg = make_cfg(tmp.name)
        with open(mesh.CONFIG_NAME, "w") as f:
            json.dump({k: v for k, v in cfg.items()
                       if not k.startswith("_")}, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mesh.cmd_agent_session_hook(argparse.Namespace())
        self.assertIn("mesh_pending", out.getvalue())
```

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement**

In `_integrate_harness("codex")` return-text, append after the plugin-add lines:

```
mesh codex-setup                     # once per machine — arms presence at session start
```

In the `harness == "claude"` branch, return the snippet plus a header line (prepend before `CLAUDE_SNIPPET`):

```python
    if harness == "claude":
        return ("# a2acast on Claude Code\n\n"
                "mesh claude-setup      # once per project — arms presence "
                "at session start\n\n" + CLAUDE_SNIPPET)
```

In `cmd_agent_session_hook`, extend the printed paragraph (append to the existing string, same print call):

```python
        " If this project registers the a2acast MCP server, start by "
        "calling the mesh_pending tool once — deliveries that arrived "
        "while no session was open are buffered there."
```

- [ ] **Step 4: Run OnboardingTextTests + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "docs: onboarding text points at claude-setup/codex-setup and mesh_pending"
```

---

### Task 9: Harness-aware `mesh join`

`cmd_join` (~786, 795) derives a bare-hostname identity and writes the generic node file even inside a harness session — inconsistent with the 04e450f identity model (this is why the Codex app joined as `jamess-macbook-air-2`).

**Files:**
- Modify: `mesh.py` (`cmd_join`)
- Test: `tests/test_mesh.py`

**Interfaces:** joining inside a detected harness derives `<host>-<harness>` and writes `.meshwire.node.<harness>`; outside a harness, behavior unchanged.

- [ ] **Step 1: Failing test** (pattern-match `HarnessNamingTests` setup):

```python
class JoinHarnessTests(unittest.TestCase):
    def setUp(self):
        self._env = os.environ.pop("A2ACAST_NODE", None)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._old = os.getcwd()
        self.addCleanup(lambda: os.chdir(self._old))
        os.chdir(self._tmp.name)

    def tearDown(self):
        if self._env is not None:
            os.environ["A2ACAST_NODE"] = self._env

    def _code(self):
        cfg = make_cfg(self._tmp.name)
        return mesh.join_code({k: v for k, v in cfg.items()
                               if not k.startswith("_")})

    def test_join_inside_harness_pins_per_harness_name(self):
        code = self._code()
        with mock.patch.object(mesh, "_detect_harness",
                               return_value="claude"), \
             mock.patch.object(mesh, "send_raw"), \
             mock.patch.object(mesh, "_watch_if_interactive"):
            with contextlib.redirect_stdout(io.StringIO()):
                mesh.cmd_join(argparse.Namespace(code=code, as_node=None))
        with open(".meshwire.node.claude") as f:
            name = f.read().strip()
        self.assertTrue(name.endswith("-claude"))
        self.assertFalse(os.path.exists(".meshwire.node"))

    def test_join_outside_harness_writes_generic_file(self):
        code = self._code()
        with mock.patch.object(mesh, "_detect_harness",
                               return_value=None), \
             mock.patch.object(mesh, "send_raw"), \
             mock.patch.object(mesh, "_watch_if_interactive"):
            with contextlib.redirect_stdout(io.StringIO()):
                mesh.cmd_join(argparse.Namespace(code=code, as_node=None))
        self.assertTrue(os.path.exists(".meshwire.node"))
```

(If `join_code` requires specific cfg fields, mirror how `JoinCodeTests` builds codes.)

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement** — in `cmd_join`, change:

```python
    harness = _detect_harness()
    me = args.as_node or _default_node_name(harness)
```

and the node-file write:

```python
    with open(node_file(cfg, harness), "w", encoding="utf-8") as f:
        f.write(me + "\n")
```

(`cfg["_dir"]` is set two lines above the write — `node_file` needs it.)

- [ ] **Step 4: Run JoinHarnessTests + full suite** — all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "fix: mesh join derives and pins a harness-aware identity"
```

---

### Task 10: Version bump + CHANGELOG + push + pipx refresh

Presence-on-open is a feature release.

**Files:**
- Modify: `mesh.py` (`VERSION` constant), `.claude-plugin/plugin.json`, `plugins/copilot-a2acast/plugin.json`, `plugins/a2acast/.codex-plugin/plugin.json` (version fields), `CHANGELOG.md`

- [ ] **Step 1:** Bump `VERSION` to `0.13.0` in `mesh.py` and every `plugin.json` version field (grep `0.12.0`).
- [ ] **Step 2:** CHANGELOG entry:

```markdown
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
```

- [ ] **Step 3:** Full suite green, commit, push, refresh runtime:

```bash
.venv/bin/python -m unittest tests.test_mesh 2>&1 | tail -3
git add -A && git commit -m "release: 0.13.0 — presence on session open"
git push origin main
pipx reinstall a2acast
mesh --help >/dev/null && echo runtime-ok
```

---

### Task 11: LIVE — Claude Code arm-at-open probe + presence verification

Cannot be unit-tested; requires the user's real sessions. Do this WITH the user.

- [ ] **Step 1: Presence check (headline fix).** In this project: `mesh claude-setup`, then open a **fresh** Claude Code session, type nothing. From another node (e.g. the `linux` or `desktop` node): `mesh ping <this-node>`. Expected: `MESH_PONG` within seconds. Record the result in the PR/commit message.
- [ ] **Step 2: Idle capture + next-turn drain.** From another node: `mesh send <this-node> "presence test"`. Expected: ack returns to sender immediately (presence server acked); in the Claude session, the next human turn (or wake, Step 3) surfaces it via `mesh_pending`.
- [ ] **Step 3: Wake probe.** The Stop-hook watcher (`hooks/hooks.json` → `mesh claude-hook`, `async` + `asyncRewake`) now waits in buffer mode. After one turn in the session (arms the Stop watcher), send from another node again. Expected: idle session wakes, reason text says deliveries arrived → agent calls `mesh_pending` and handles.
- [ ] **Step 4: Arm-at-open probe (SessionStart async).** Edit `hooks/hooks.json`, adding to the `SessionStart` entry's `hooks` array (alongside the session-hook command):

```json
{
  "type": "command",
  "command": "mesh",
  "args": ["claude-hook", "--timeout", "86370"],
  "timeout": 86400,
  "async": true,
  "asyncRewake": true
}
```

Open a fresh session, type nothing, send a message from another node. Two outcomes:
  - **Wakes:** arm-at-open works on Claude — keep the entry, commit.
  - **Doesn't wake (context-only / async unsupported on SessionStart):** revert the entry; wake stays armed-from-first-turn; presence still guarantees zero loss (documented in spec). Record which outcome in the spec's Wake-strength section.
- [ ] **Step 5: Session-bound check.** Close the Claude session. `mesh ping` from another node must now time out; `ps` shows no orphan `mesh mcp-serve` / `mesh claude-hook`.
- [ ] **Step 6: Commit** whatever hooks.json change survived, with the probe results in the message.

---

### Task 12: LIVE — Codex spike + registration verification

- [ ] **Step 1:** `mesh codex-setup` in this project; confirm with `codex mcp get a2acast` (source shows the pinned `--config`).
- [ ] **Step 2:** Fresh Codex CLI session in this project, type nothing; `mesh ping <codex-node>` from another node → expect `MESH_PONG` (presence at open).
- [ ] **Step 3:** Determine wake: with the codex plugin's Stop hook now in buffer mode, after one turn send a message; expect the block-reason wake. Probe whether any Codex session-start hook event can run a command for arm-at-open (check `codex plugin` hook event docs / `plugins/a2acast/.codex-plugin` schema).
- [ ] **Step 4:** Record findings in `docs/superpowers/specs/2026-07-11-codex-wake-spike.md`: MCP server spawn timing, cwd/env given to the server, session-start hook capability, stop-hook wake behavior. Commit.

---

## Self-Review (done at plan-writing time)

1. **Spec coverage:** presence layer → Tasks 1–4, 10–12; registration → 6, 7, 8; single-subscriber → 3, 4; wake per-harness → 4, 11, 12 (Copilot unchanged — its sampling path bypasses the hook watcher entirely and `plugins/copilot-a2acast/hooks.json` has no Stop hook to migrate); ride-along join fix → 9; error handling → 2 (reconnect), 3 (lock), 4 (consume-on-read); testing → every task + live checklists.
2. **Placeholder scan:** the two `...` markers in Task 2's `_watch_once` refer to moving the existing body verbatim (explicitly instructed); no TBDs.
3. **Type consistency:** `activity_file(cfg, node)` (Tasks 1→4), `_presence_is_live(cfg, node)` (3→4), `_acquire_presence_lock(cfg, node)` (3), `cmd_claude_setup(args.dir)` / `cmd_codex_setup(args.dir)` parser entries match `getattr(args, "dir", None)` usage.

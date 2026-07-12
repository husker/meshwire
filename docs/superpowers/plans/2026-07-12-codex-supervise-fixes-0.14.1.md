# codex-supervise fixes (v0.14.1) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** make `mesh codex-supervise` actually work end-to-end and durably safe — fix the four bugs live Task-7 verification found (GitHub #30–33).

**Tech:** single-file `mesh.py`, stdlib only; `unittest` with mocked transport.

## Global Constraints
- `mesh.py` single stdlib-only file; macOS/Linux/Windows.
- Tests mocked transport; deterministic under any ambient harness.
- **Security:** the `exec_allow` allowlist is the trust boundary — fixes must make it *durable* and *live-reloaded*, never weaken default-empty/default-off.
- Full `tests.test_mesh` green before each commit.
- Reuse: `load_config`, `_write_json_secure`, `_acquire_presence_lock`/`_hook_lock_is_live` (lock pattern), `MeshMCPServer`, `_supervise_pending`, `_run_task_with_codex`.

---

### Task 1: #30 durable config writes + #31 live allowlist reload

**#30 root cause:** long-running processes hold a stale in-memory cfg; `note_peer`'s `_save_config(cfg)` writes the whole stale dict (last-writer-wins), wiping concurrent changes like `exec_allow`. **#31:** the supervisor loads cfg once and never re-reads the allowlist.

**Files:** Modify `mesh.py` (`note_peer`, `cmd_codex_allow`, `cmd_codex_supervise`, new `_mutate_config`); Test `tests/test_mesh.py`.

**Interfaces:**
- `_config_lock_file(cfg)` + `_acquire_config_lock(cfg)` — brief O_CREAT|O_EXCL lock (mirror `_acquire_presence_lock`), keyed on the config path, so concurrent writers serialize.
- `_mutate_config(cfg, apply) -> None` — acquire the config lock; **re-read the on-disk config** into `latest` (preserving `_path`/`_dir`); `apply(latest)` makes the surgical change; `_write_json_secure(path, {non-underscore keys})`; release lock; then reflect the change into the passed-in `cfg` dict (so the caller's in-memory copy stays consistent). This makes writes read-modify-write against the latest on disk — no lost updates.
- `note_peer`: replace the `cfg["nodes"].append(node); _save_config(cfg)` with
  `_mutate_config(cfg, lambda c: c.setdefault("nodes", []).append(node) if node not in c.get("nodes", []) else None)`.
- `cmd_codex_allow`: route its add/revoke through `_mutate_config` too (so a concurrent `note_peer` can't clobber the allowlist mid-write).
- `cmd_codex_supervise`: reload cfg **each poll** — `while True: cfg = load_config(); for ... in _supervise_pending(cfg, me): ...` — so `mesh codex-allow` takes effect on a running supervisor. (Keep the startup requeue as-is.)

- [ ] **Step 1: Failing tests.**
```python
class ConfigDurabilityTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(); self.addCleanup(self._tmp.cleanup)
        self.cfg = make_cfg(self._tmp.name)
        with open(mesh.CONFIG_NAME_for := os.path.join(self._tmp.name, mesh.CONFIG_NAME), "w") as f:
            json.dump({k:v for k,v in self.cfg.items() if not k.startswith("_")}, f)
        self.cfg["_path"] = CONFIG_NAME_for; self.cfg["_dir"] = self._tmp.name

    def test_note_peer_does_not_clobber_concurrent_exec_allow(self):
        # a DIFFERENT process wrote exec_allow to disk after self.cfg was loaded
        disk = json.load(open(self.cfg["_path"])); disk["exec_allow"] = ["trusted"]
        json.dump(disk, open(self.cfg["_path"], "w"))
        mesh.note_peer(self.cfg, "newpeer", "message")   # stale cfg has no exec_allow
        after = json.load(open(self.cfg["_path"]))
        self.assertEqual(after.get("exec_allow"), ["trusted"])   # preserved!
        self.assertIn("newpeer", after["nodes"])                 # and the peer added
```
Plus: `cmd_codex_allow` add persists and survives a concurrent stale `note_peer`; supervisor `--once` picks up a peer added to exec_allow AFTER a (mocked) startup (reload-per-poll — assert `_run_task_with_codex` called when exec_allow written between two polls; adapt with `--once` twice or by reloading).

- [ ] **Step 2: Run → fail.**
- [ ] **Step 3: Implement** `_mutate_config` + lock; rewire `note_peer`, `cmd_codex_allow`, supervisor reload-per-poll.
- [ ] **Step 4: tests + full suite.**
- [ ] **Step 5: Commit** `fix(security): durable read-modify-write config writes + live allowlist reload (#30, #31)`

---

### Task 2: #32 supervisor is self-contained (headless receive)

**Root cause:** the supervise loop only reads the task store; nothing populates it unless a harness session's `mesh mcp-serve` presence server is running. A headless node starves.

**Files:** Modify `mesh.py` (`cmd_codex_supervise`); Test `tests/test_mesh.py`.

**Interface:** In `cmd_codex_supervise`, before the exec poll loop, start a background **receiver thread** that runs `MeshMCPServer(cfg, me).watch_loop()` (which subscribes to the relay and saves inbound A2A tasks via its delivery path). Store the server so `finally` can `server._stop.set()`. The exec poll loop then reads the store the receiver fills. This makes the supervisor receive + exec + reply with no harness session. Coordinate with the presence lock: the receiver acquires the presence lock (reuse the `_run_mcp_server` pattern) — if a session's presence server already holds it, the receiver still runs its watch_loop (double-receive is harmless: `save_task` is idempotent by task-id) OR skips subscribing; keep it simple and correct — document the choice.

- [ ] **Step 1: Failing test** (`SuperviseReceiverTests`): mock `MeshMCPServer.watch_loop` (or `_stream_events`) so a fake inbound task lands in the store, then assert the supervisor's `--once` pass processes it — proving the supervisor no longer depends on an external presence server. Also assert the receiver thread's `_stop` is set on exit (no leaked thread).
- [ ] **Step 2–4:** implement, tests, suite.
- [ ] **Step 5: Commit** `fix: codex-supervise runs its own relay receiver — headless nodes no longer starve (#32)`

---

### Task 3: #33 migration doesn't claim the bare hostname

**Root cause:** on a machine whose generic `.meshwire.node` equals the bare hostname (the pre-harness default), migration copies that bare name into the per-harness pin, so codex loses its `-<harness>` suffix.

**Files:** Modify `mesh.py` (`_migrate_identity`); Test `tests/test_mesh.py`.

**Interface:** In `_migrate_identity(cfg, harness)`, after reading the generic name, **skip migration when the generic name equals the machine's bare default** (`_default_node_name(None)`) — that's the old auto-default, not a deliberately-chosen identity, so the harness-aware default (`<host>-<harness>`) should apply instead. Only migrate a generic name that differs from the bare hostname (a deliberate `mesh iam` name like `desktop`). Return None in the skip case.

- [ ] **Step 1: Failing tests:** generic name == bare hostname → `_migrate_identity` returns None, no pin written; generic name == a deliberate name ("desktop") different from hostname → migrates as before.
- [ ] **Step 2–4:** implement, tests, suite.
- [ ] **Step 5: Commit** `fix: identity migration skips the bare-hostname default, preserving <host>-<harness> (#33)`

---

### Task 4: Release 0.14.1 + live re-verification

- [ ] Bump 0.14.0 → 0.14.1 everywhere (grep, incl. plugin.json/marketplace.json/pyproject/test pin); CHANGELOG `## 0.14.1` noting the four fixes (#30–33). Full suite green. Commit `release: 0.14.1 — codex-supervise durability + headless fixes`.
- [ ] **LIVE (with the user, post-merge):** `mesh codex-setup --supervise`; `mesh codex-allow mac-test`; send a task from mac-test → auto-runs + replies (no session open needed); send from a non-allowed sender → NOT run; confirm exec_allow SURVIVES incoming messages from other nodes (the #30 regression). `--stop`.

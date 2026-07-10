# Delivery Acknowledgements (v0.8.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Watchers auto-ack every message they receive; `mesh send` (and `ask`) wait up to 5s and report `delivered to <node> (<N>ms)` or `sent — no ack yet` — per the approved spec `docs/superpowers/specs/2026-07-10-delivery-acks-design.md`.

**Architecture:** Acks are control messages (`{"mw": "ack", "of": <relay-msg-id>}`) riding the existing encrypted `c`-field plumbing, answered by watchers exactly like pongs (silent, agent-invisible, best-effort). One new receiver helper (`_send_ack`), one new sender helper (`_await_acks`) built on `_stream_events`, and surgical reworks of `cmd_send`/`cmd_ask`.

**Tech Stack:** Python ≥3.8 stdlib only, single `mesh.py`; stdlib `unittest` with the existing fake transport; live ntfy.sh smoke at release.

## Global Constraints

- Acks exist only on encrypted meshes (`cfg["key"]`); plaintext meshes behave exactly as today on both ends.
- `peek` and `_await_result` never ack — watchers (both modes) are the sole acking authority; ack posted BEFORE the message is emitted; ack failures swallowed.
- Acks are never acked, never consume a one-shot watch, never print to receiving-side stdout.
- `ACK_WAIT = 5` (module constant). Sender exits 0 whether or not an ack arrives. Exact sender strings from the spec: `delivered to <node> (<N>ms)` / `sent — no ack yet (node may be offline; the relay holds the message)` / broadcast: `acked by: <a>, <b>` / broadcast silence: `sent — no ack yet (nodes may be offline; the relay holds the message)`.
- Version lockstep: `pyproject.toml`, `.claude-plugin/plugin.json`, `plugins/meshwire/.codex-plugin/plugin.json` → `0.8.0`; `USER_AGENT = "meshwire/0.8"`.
- `plugins/meshwire/` copies must stay byte-identical to `skills/mesh-agent/SKILL.md` and `hooks/hooks.json` (existing sync test enforces — update master AND copy together).
- Tests: `python3 -m unittest discover -s tests -v` from repo root (115 runs green today; no network). Environment quirk: PostToolUse hook runs `ruff check --fix` on .py edits — `git diff` before committing.
- Commits end with trailer: `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`

Anchor on quoted code, not line numbers (they drift).

---

### Task 1: Receiver side — watchers ack, ack control handled

**Files:**
- Modify: `mesh.py` — constant after `USER_AGENT`; `_handle_control`; new `_send_ack` directly after `_handle_control`; the `note_peer`/`_emit_message` block in `cmd_watch`
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `ACK_WAIT = 5`; `_send_ack(cfg, me, frm, ev) -> None`; `_handle_control` gains an `"ack"` branch (notes peer via `"ack"`, returns None).
- Consumes: `send_raw(..., ctl=)`, `note_peer`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_mesh.py` (inside the existing file, before the `if __name__` guard):

```python
class AckReceiverTests(MembershipCmdTests):
    """Watchers ack what they receive; nothing else does."""

    def _setup_mesh(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        return cfg

    def _msg_event(self, cfg, frm, body, eid, t, ctl=None):
        payload = {"f": frm, "t": "alpha", "b": body}
        if ctl:
            payload["c"] = ctl
        return {"event": "message", "id": eid, "time": t,
                "message": mesh.encrypt(cfg, json.dumps(payload))}

    def test_watch_acks_before_emitting(self):
        cfg = self._setup_mesh()
        evs = [self._msg_event(cfg, "beta", "hello", "m77", 500)]
        sent = []

        def fake_send(c, s, t, b, title=None, ctl=None):
            sent.append((s, t, ctl))
            return {"id": "x"}

        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw", fake_send), \
             contextlib.redirect_stdout(out):
            mesh.cmd_watch(argparse.Namespace(timeout=60, as_node=None,
                                              follow=False))
        self.assertEqual(sent, [("alpha", "beta",
                                 {"mw": "ack", "of": "m77"})])
        self.assertIn("MESH_MESSAGE", out.getvalue())

    def test_watch_does_not_ack_controls_or_own_echo(self):
        cfg = self._setup_mesh()
        pong = self._msg_event(cfg, "beta", "pong", "c1", 500,
                               ctl={"mw": "pong", "n": "x"})
        own = self._msg_event(cfg, "alpha", "mine", "c2", 501)
        real = self._msg_event(cfg, "beta", "real", "c3", 502)
        sent = []
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream([pong, own, real])), \
             mock.patch.object(mesh, "send_raw",
                               lambda c, s, t, b, title=None, ctl=None:
                               sent.append(ctl) or {"id": "x"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_watch(argparse.Namespace(timeout=60, as_node=None,
                                              follow=False))
        # exactly one ack — for the real message only
        self.assertEqual(sent, [{"mw": "ack", "of": "c3"}])

    def test_watch_survives_ack_send_failure(self):
        cfg = self._setup_mesh()
        evs = [self._msg_event(cfg, "beta", "hello", "m1", 500)]

        def boom(*a, **k):
            raise urllib.error.URLError("relay down")

        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw", boom), \
             contextlib.redirect_stdout(out):
            mesh.cmd_watch(argparse.Namespace(timeout=60, as_node=None,
                                              follow=False))
        self.assertIn("MESH_MESSAGE from='beta' to=alpha: hello",
                      out.getvalue())

    def test_peek_does_not_ack(self):
        cfg = self._setup_mesh()
        wire = mesh.encrypt(cfg, json.dumps(
            {"f": "beta", "t": "alpha", "b": "hi"}))
        ev = json.dumps({"event": "message", "id": "p1", "time": 100,
                         "message": wire, "title": "t"})

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return (ev + "\n").encode()

        sent = []
        out = io.StringIO()
        with mock.patch.object(mesh, "http", lambda *a, **k: R()), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: sent.append(1) or {"id": "x"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_peek(argparse.Namespace(node=None, since="all",
                                             as_node=None))
        self.assertEqual(sent, [])

    def test_handle_control_ack_notes_peer_silently(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            out = mesh._handle_control(cfg, "alpha", "beta",
                                       {"mw": "ack", "of": "m1"})
            self.assertIsNone(out)
            self.assertEqual(mesh.load_peers(cfg)["beta"]["via"], "ack")
```

- [ ] **Step 2: Run to verify failures**

Run: `python3 -m unittest tests.test_mesh.AckReceiverTests -v`
Expected: `test_watch_acks_before_emitting`, `test_watch_does_not_ack_controls_or_own_echo` FAIL (no ack sent); `test_handle_control_ack_notes_peer_silently` FAILs on via `"ack"` vs stderr-ignored fallthrough (no peers entry). The peek and survive tests may already pass — fine.

- [ ] **Step 3: Implement**

Add after `USER_AGENT = "meshwire/0.7"` (bumped in Task 4):

```python
ACK_WAIT = 5   # seconds a sender listens for delivery acks
```

In `_handle_control`, insert before the final unknown-kind fallthrough:

```python
    if kind == "ack":
        note_peer(cfg, frm, "ack")
        return None
```

Add directly after `_handle_control`:

```python
def _send_ack(cfg, me, frm, ev):
    """Acknowledge receipt to the sender — silent and best-effort. A
    watcher must never die (or wake its agent) because an ack failed."""
    if not cfg.get("key") or not frm:
        return
    try:
        send_raw(cfg, me, frm, "ack",
                 ctl={"mw": "ack", "of": ev.get("id")})
    except (urllib.error.URLError, socket.timeout):
        pass
```

In `cmd_watch`, change:

```python
        note_peer(cfg, frm, "message")
        _emit_message(cfg, me, frm, body, ev)
```

to:

```python
        note_peer(cfg, frm, "message")
        _send_ack(cfg, me, frm, ev)
        _emit_message(cfg, me, frm, body, ev)
```

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_mesh.AckReceiverTests -v` then the full suite.
Expected: all pass. (`WatchTests.test_control_message_does_not_consume_one_shot` mocks `send_raw` already — unaffected; `test_one_shot_delivers_message_and_saves_cursor` does NOT mock `send_raw`, and the watch now acks — that test's fake `http` raises `_TestDone` on the second call, but `_send_ack` goes through `send_raw`→`_post`→`http.client`, NOT `mesh.http`, so it attempts a real connection to `https://ntfy.example` (nonexistent host) and the swallow-clause eats the failure — slow (~DNS timeout) but passing. To keep the suite fast, ALSO patch `mesh._post` to return `{"id": "x"}` in that existing test — add the mock to it in this step and note it in the commit.)

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: watchers auto-ack received messages"
```

---

### Task 2: Sender side — `mesh send` waits for acks

**Files:**
- Modify: `mesh.py` — new `_await_acks` after `_send_ack`; rework `cmd_send`; `send` argparse parser gains `--no-wait`
- Test: `tests/test_mesh.py`

**Interfaces:**
- Produces: `_await_acks(cfg, me, msg_id, t0, timeout, first=None, want_all=False) -> list[(node, ms)]` — Task 3 reuses it for fire-and-forget ask.
- Consumes: `_stream_open`, `_stream_events`, `_open`, `note_peer`, `ACK_WAIT`.

- [ ] **Step 1: Write the failing tests**

```python
class AckSenderTests(MembershipCmdTests):
    def _setup_mesh(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        return cfg

    def _ack_event(self, cfg, frm, of, eid, t):
        return {"event": "message", "id": eid, "time": t,
                "message": mesh.encrypt(cfg, json.dumps(
                    {"f": frm, "t": "alpha", "b": "ack",
                     "c": {"mw": "ack", "of": of}}))}

    def test_send_prints_delivered_on_ack(self):
        cfg = self._setup_mesh()
        evs = [self._ack_event(cfg, "beta", "msg9", "a1", 600)]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "msg9"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="beta", message=["hi"],
                                             as_node=None, no_wait=False))
        self.assertRegex(out.getvalue(), r"delivered to beta \(\d+ms\)")

    def test_send_ignores_wrong_of_and_reports_no_ack(self):
        cfg = self._setup_mesh()
        evs = [self._ack_event(cfg, "beta", "OTHER", "a1", 600)]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "msg9"}), \
             mock.patch.object(mesh, "ACK_WAIT", 0), \
             contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="beta", message=["hi"],
                                             as_node=None, no_wait=False))
        self.assertIn("no ack yet", out.getvalue())

    def test_send_no_wait_skips_subscribe(self):
        self._setup_mesh()
        out = io.StringIO()

        def no_dial(*a, **k):
            raise AssertionError("subscribed despite --no-wait")

        with mock.patch.object(mesh, "http", no_dial), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "m1"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="beta", message=["hi"],
                                             as_node=None, no_wait=True))
        self.assertIn("sent to beta", out.getvalue())
        self.assertNotIn("delivered", out.getvalue())

    def test_broadcast_lists_all_ackers(self):
        cfg = self._setup_mesh()
        evs = [self._ack_event(cfg, "beta", "msgB", "a1", 600),
               self._ack_event(cfg, "gamma", "msgB", "a2", 601)]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "msgB"}), \
             mock.patch.object(mesh, "ACK_WAIT", 1), \
             contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="all", message=["hi"],
                                             as_node=None, no_wait=False))
        self.assertIn("acked by: beta, gamma", out.getvalue())

    def test_plaintext_mesh_sends_like_today(self):
        cfg = make_cfg(key=False)
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        out = io.StringIO()

        def no_dial(*a, **k):
            raise AssertionError("plaintext mesh must not subscribe")

        with mock.patch.object(mesh, "http", no_dial), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "m1"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="beta", message=["hi"],
                                             as_node=None, no_wait=False))
        self.assertIn("sent to beta", out.getvalue())
```

Note on `test_broadcast_lists_all_ackers`: the fake stream delivers both acks then raises `_TestDone` on reconnect — but `_await_acks` in `want_all` mode keeps listening until the deadline. With `ACK_WAIT` patched to 1 the deadline check after the second yielded ack ends the generator cleanly *if a second has elapsed*; to make it deterministic, the implementation's `want_all` loop must ALSO return early when the stream attempt ends (see Step 3's `except _proceed` note) — the test pins that behavior by expecting no `_TestDone` to escape.

- [ ] **Step 2: Run to verify failures**

Run: `python3 -m unittest tests.test_mesh.AckSenderTests -v`
Expected: FAIL/ERROR — `cmd_send` has no `no_wait` attr handling, `_await_acks` missing, no delivered output.

- [ ] **Step 3: Implement**

Add after `_send_ack`:

```python
def _await_acks(cfg, me, msg_id, t0, timeout, first=None, want_all=False):
    """Collect {"mw": "ack", "of": msg_id} control messages addressed to
    `me`. Returns a list of (node, ms). want_all=False returns on the
    first ack (directed send); True collects until the window closes
    (broadcast). Never raises on transport trouble — an ack wait is
    best-effort reporting, not delivery."""
    got = []
    if not msg_id:
        return got
    deadline = time.time() + timeout
    tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
    try:
        for ev in _stream_events(cfg, tpc, str(int(time.time()) - 5),
                                 deadline, first=first):
            frm, body, trusted, ctl = _open(ev, cfg)
            if not trusted or not ctl or ctl.get("mw") != "ack":
                continue
            if ctl.get("of") != msg_id or not frm:
                continue
            if frm not in [n for n, _ in got]:
                got.append((frm, int((time.monotonic() - t0) * 1000)))
                note_peer(cfg, frm, "ack")
            if not want_all:
                return got
    except Exception:
        pass  # reporting only — the message itself is already sent
    return got
```

Rework `cmd_send`'s tail. Replace:

```python
    msg = " ".join(args.message)
    try:
        resp = send_raw(cfg, sender, to, msg)
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    enc = " [e2e]" if cfg.get("key") else ""
    print(f"sent to {to} (id {resp.get('id', '?')}){enc}: {msg}")
```

with:

```python
    msg = " ".join(args.message)
    wait = bool(cfg.get("key")) and not args.no_wait
    first = None
    if wait:
        try:  # be listening before the message ships
            first = _stream_open(
                cfg, f"{topic(cfg, sender)},{topic(cfg, BROADCAST)}",
                str(int(time.time()) - 5), ACK_WAIT + 5)
        except (urllib.error.URLError, socket.timeout):
            pass
    t0 = time.monotonic()
    try:
        resp = send_raw(cfg, sender, to, msg)
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    enc = " [e2e]" if cfg.get("key") else ""
    print(f"sent to {to} (id {resp.get('id', '?')}){enc}: {msg}")
    if not wait:
        return
    acks = _await_acks(cfg, sender, resp.get("id"), t0, ACK_WAIT,
                       first=first, want_all=(to == BROADCAST))
    if to == BROADCAST:
        if acks:
            print("acked by: " + ", ".join(n for n, _ in acks))
        else:
            print("sent — no ack yet (nodes may be offline; the relay "
                  "holds the message)")
    elif acks:
        print(f"delivered to {acks[0][0]} ({acks[0][1]}ms)")
    else:
        print("sent — no ack yet (node may be offline; the relay holds "
              "the message)")
```

Add to the `send` argparse parser (after the `--as` argument):

```python
    p.add_argument("--no-wait", dest="no_wait", action="store_true",
                   help="don't wait for the delivery ack")
```

Deterministic-broadcast note from Step 1: `_await_acks`'s `try/except Exception` around the generator is what lets the broadcast test end when the fake stream raises `_TestDone` — the collected acks are returned, not lost. That behavior is intentional for real use too: a dropped subscribe mid-window reports whatever acks already arrived.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_mesh.AckSenderTests -v`, then full suite.
Expected: all pass — including pre-existing `SendStatusInviteTests` (their Namespaces lack `no_wait`... they DO lack it: `test_send_to_unknown_warns_but_sends` and `test_send_to_self_still_errors` construct `Namespace(to=..., message=..., as_node=None)`). Update those two Namespaces to include `no_wait=True` in this step — they test the warning/self-check paths, not acks.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: mesh send waits up to 5s for delivery acks"
```

---

### Task 3: `mesh ask` reports task delivery

**Files:**
- Modify: `mesh.py` — `cmd_ask`, `_await_result`
- Test: `tests/test_mesh.py`

**Interfaces:**
- Consumes: `_await_acks` (Task 2), `_stream_open`.
- Produces: `_await_result(cfg, me, task_id, timeout, first=None, ack_of=None, t0=None)` — prints `task delivered to <node> (<N>ms)` once when the matching ack passes by.

- [ ] **Step 1: Write the failing tests**

```python
class AckAskTests(MembershipCmdTests):
    def _setup_mesh(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        return cfg

    def test_ask_wait_prints_task_delivered_then_result(self):
        cfg = self._setup_mesh()
        env = mesh.make_result_envelope("beta", "alpha", "T1", "C1",
                                        "completed", "42")
        ack = {"event": "message", "id": "a1", "time": 600,
               "message": mesh.encrypt(cfg, json.dumps(
                   {"f": "beta", "t": "alpha", "b": "ack",
                    "c": {"mw": "ack", "of": "askmsg"}}))}
        result = {"event": "message", "id": "r1", "time": 601,
                  "message": mesh.encrypt(cfg, json.dumps(
                      {"f": "beta", "t": "alpha",
                       "b": json.dumps(env)}))}
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream([ack, result])), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "askmsg"}), \
             mock.patch.object(mesh, "make_send_envelope",
                               lambda s, t, x: mesh.make_send_envelope
                               .__wrapped__(s, t, x)
                               if hasattr(mesh.make_send_envelope,
                                          "__wrapped__") else
                               {"jsonrpc": "2.0", "id": "rpc1",
                                "method": "message/send",
                                "params": {"message": {"taskId": "T1",
                                                       "contextId": "C1"}}}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_ask(argparse.Namespace(to="beta", text=["2+2"],
                                            wait=30, as_node=None))
        text = out.getvalue()
        self.assertRegex(text, r"task delivered to beta \(\d+ms\)")
        self.assertIn("MESH_TASK_RESULT from=beta task=T1", text)
        self.assertLess(text.index("task delivered"),
                        text.index("MESH_TASK_RESULT"))

    def test_fire_and_forget_ask_reports_delivery(self):
        cfg = self._setup_mesh()
        ack = {"event": "message", "id": "a1", "time": 600,
               "message": mesh.encrypt(cfg, json.dumps(
                   {"f": "beta", "t": "alpha", "b": "ack",
                    "c": {"mw": "ack", "of": "askmsg"}}))}
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream([ack])), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "askmsg"}), \
             contextlib.redirect_stdout(out):
            mesh.cmd_ask(argparse.Namespace(to="beta", text=["2+2"],
                                            wait=0, as_node=None))
        self.assertRegex(out.getvalue(),
                         r"task delivered to beta \(\d+ms\)")
```

**Simplification during implementation:** the `make_send_envelope` mock in the first test is ugly — replace it with the straightforward form: `mock.patch.object(mesh, "make_send_envelope", lambda s, t, x: {"jsonrpc": "2.0", "id": "rpc1", "method": "message/send", "params": {"message": {"taskId": "T1", "contextId": "C1"}}})`. The envelope only needs `taskId`/`contextId` for `cmd_ask`'s bookkeeping and `envelope_summary` on the RESULT side is what the assertion reads.

- [ ] **Step 2: Run to verify failures**

Run: `python3 -m unittest tests.test_mesh.AckAskTests -v`
Expected: FAIL — no `task delivered` output.

- [ ] **Step 3: Implement**

`_await_result` signature and ctl branch. Replace:

```python
def _await_result(cfg, me, task_id, timeout, first=None):
```

with:

```python
def _await_result(cfg, me, task_id, timeout, first=None, ack_of=None,
                  t0=None):
```

and replace its filter line:

```python
        frm, body, trusted, ctl = _open(ev, cfg)
        if not trusted or ctl:
            continue
```

with:

```python
        frm, body, trusted, ctl = _open(ev, cfg)
        if not trusted:
            continue
        if ctl:
            if (ack_of and t0 is not None and ctl.get("mw") == "ack"
                    and ctl.get("of") == ack_of):
                print(f"task delivered to {frm} "
                      f"({int((time.monotonic() - t0) * 1000)}ms)")
                ack_of = None  # print once
            continue
```

`cmd_ask`: capture the send response and timing, and add the fire-and-forget ack wait. The current tail (from the eager-subscribe block onward):

```python
    first = None
    if args.wait:
        tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
        try:  # be listening before the question ships
            first = _stream_open(cfg, tpc, str(int(time.time()) - 5),
                                 min(args.wait, 300))
        except (urllib.error.URLError, socket.timeout):
            pass
    try:
        send_raw(cfg, me, to, json.dumps(env),
                 title=f"{cfg['mesh']}: a2a {me} -> {to}")
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
```

becomes:

```python
    first = None
    if cfg.get("key"):
        tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
        try:  # be listening before the question ships
            first = _stream_open(cfg, tpc, str(int(time.time()) - 5),
                                 min(args.wait, 300) if args.wait
                                 else ACK_WAIT + 5)
        except (urllib.error.URLError, socket.timeout):
            pass
    t0 = time.monotonic()
    try:
        resp = send_raw(cfg, me, to, json.dumps(env),
                        title=f"{cfg['mesh']}: a2a {me} -> {to}")
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
```

and the no-wait / wait branches:

```python
    if not args.wait:
        if cfg.get("key"):
            acks = _await_acks(cfg, me, resp.get("id"), t0, ACK_WAIT,
                               first=first)
            if acks:
                print(f"task delivered to {acks[0][0]} ({acks[0][1]}ms)")
            else:
                print("sent — no ack yet (node may be offline; the relay "
                      "holds the message)")
        print(f"  check later: mesh tasks get {task_id}")
        return
    print(f"  waiting up to {args.wait}s for a reply...")
    result = _await_result(cfg, me, task_id, args.wait, first=first,
                           ack_of=resp.get("id"), t0=t0)
```

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest tests.test_mesh.AckAskTests -v`, then the full suite (the pre-existing `AskOrderTests.test_ask_subscribes_before_sending` mocks `_stream_open`/`send_raw`/`_await_result` and still passes — the subscribe now happens for key-bearing meshes regardless of `--wait`, which strengthens, not breaks, its ordering assertion).
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add mesh.py tests/test_mesh.py
git commit -m "feat: mesh ask reports task delivery via acks"
```

---

### Task 4: Docs, version lockstep, live smoke, release

**Files:**
- Modify: `README.md`, `skills/mesh-agent/SKILL.md` + `plugins/meshwire/skills/mesh-agent/SKILL.md` (byte-identical), `pyproject.toml`, `.claude-plugin/plugin.json`, `plugins/meshwire/.codex-plugin/plugin.json`, `mesh.py` (USER_AGENT)

- [ ] **Step 1: README.** Three edits:

(a) In the quick-start **Talk** block, extend the send line's comment:

```bash
mesh send all "hello mesh"     # → acked by: <b-name> — B's watcher has it
```

(b) After the "How it works" paragraph ending "…get the plain return-immediately behavior instead.", append a new paragraph:

```markdown
Every received message is acknowledged automatically: `mesh send` waits up
to five seconds and prints `delivered to <node> (<N>ms)` when a live
watcher has the message, or `sent — no ack yet` when nothing was listening
— in which case the relay holds the message and the node still receives it
when its watcher next connects. An ack proves delivery; its absence does
not prove failure. `--no-wait` skips the wait.
```

(c) CLI reference — replace the send line:

```
mesh send <node|all> <msg...> [--no-wait]   message a node (or broadcast); waits ~5s for the delivery ack
```

and update the upgrade note's parenthetical: "…render the new join/ping control messages as odd one-off messages" → "…render the new join/ping/ack control messages as odd one-off messages".

- [ ] **Step 2: SKILL.md (master + Codex copy, identical edits).** In the `## Sending` section, add after the quick-ping bullet:

```markdown
- `mesh send` waits ~5s for a delivery ack: "delivered to X" = a live
  watcher has it now; "no ack yet" = queued at the relay (the node gets
  it when its watcher next connects). Absence of an ack is not failure.
```

Then `cp skills/mesh-agent/SKILL.md plugins/meshwire/skills/mesh-agent/SKILL.md` and confirm the sync test passes.

- [ ] **Step 3: Version lockstep.** `pyproject.toml` → `0.8.0`; `.claude-plugin/plugin.json` → `0.8.0`; `plugins/meshwire/.codex-plugin/plugin.json` → `0.8.0`; `mesh.py` `USER_AGENT = "meshwire/0.8"`.

- [ ] **Step 4: Full suite + JSON parse checks**

Run: `python3 -m unittest discover -s tests -v && python3 -c "import json; [json.load(open(p)) for p in ('.claude-plugin/plugin.json', 'plugins/meshwire/.codex-plugin/plugin.json', '.agents/plugins/marketplace.json', 'hooks/hooks.json')]; print('json ok')"`
Expected: all pass; `json ok`.

- [ ] **Step 5: Live smoke (real ntfy.sh, two temp nodes)**

```bash
M=/Users/james/Projects/meshwire/mesh.py
D1=$(mktemp -d); D2=$(mktemp -d)
cd "$D1" && python3 "$M" init acksmoke --as alpha
CODE=$(python3 "$M" invite | grep -oE 'mesh1-[A-Za-z0-9_-]+' | head -1)
cd "$D2" && python3 "$M" join "$CODE" --as beta
# background: cd "$D1" && python3 "$M" watch --follow
cd "$D2" && python3 "$M" send alpha "ack test"
```

Expected: `sent to alpha ...` then `delivered to alpha (<N>ms)` with N under ~2500. Then stop the watcher and send again: expected `sent — no ack yet (...)` after ~5s, exit 0. Record both outputs in the task report. Kill watchers, clean up temp dirs.

- [ ] **Step 6: Release commit**

```bash
git add -A
git commit -m "v0.8.0 — delivery acks: senders know a live watcher has the message

Watchers auto-ack every received message (encrypted control message,
agent-invisible, never acked in turn). mesh send waits up to 5s:
'delivered to <node> (<N>ms)' on ack, 'sent — no ack yet' otherwise
(exit 0 — the relay still holds the message for later delivery).
Broadcasts list who acked. mesh ask prints 'task delivered' the moment
the far watcher has the task, before the reply arrives. --no-wait
restores fire-and-forget. peek never acks."
```

---

## Self-Review (performed while writing)

1. **Spec coverage:** wire format + receiver rules → Task 1; sender UX incl. broadcast + `--no-wait` + exact strings + exit 0 → Task 2; ask (both modes) → Task 3; semantics doc, mixed-version note, versions, live smoke → Task 4. `peek`/`_await_result` non-acking: peek tested (Task 1), `_await_result` acks nothing by construction (its ctl branch only prints). No gaps.
2. **Placeholder scan:** clean; the one flagged test-mock wart (Task 3 Step 1) carries its own concrete simplification instruction.
3. **Type consistency:** `_send_ack(cfg, me, frm, ev)` / `_await_acks(cfg, me, msg_id, t0, timeout, first, want_all)` / `_await_result(..., ack_of, t0)` consistent across tasks and tests; `no_wait` attr name matches the argparse `dest` and every test Namespace.

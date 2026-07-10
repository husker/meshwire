"""Unit tests for mesh.py — stdlib only, no network.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import argparse
import contextlib
import io
import json
import os
import secrets
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mesh


def make_cfg(tmpdir=None, key=True):
    """A minimal in-memory mesh config; pass tmpdir to give it a home on disk."""
    cfg = {"mesh": "t", "id": "abc123", "server": "https://ntfy.example",
           "nodes": ["alpha", "beta"]}
    if key:
        cfg["key"] = secrets.token_hex(32)
    if tmpdir:
        cfg["_path"] = os.path.join(tmpdir, ".meshwire.json")
        cfg["_dir"] = tmpdir
    return cfg


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self):
        cfg = make_cfg()
        wire = mesh.encrypt(cfg, "hello mesh")
        self.assertTrue(wire.startswith("mw1:"))
        self.assertEqual(mesh.decrypt(cfg, wire), "hello mesh")

    def test_wrong_key_fails_closed(self):
        wire = mesh.encrypt(make_cfg(), "secret")
        self.assertIsNone(mesh.decrypt(make_cfg(), wire))  # fresh random key

    def test_tampered_ciphertext_fails_closed(self):
        cfg = make_cfg()
        wire = mesh.encrypt(cfg, "secret")
        flip = "A" if wire[-1] != "A" else "B"
        self.assertIsNone(mesh.decrypt(cfg, wire[:-1] + flip))

    def test_plaintext_body_returns_none(self):
        self.assertIsNone(mesh.decrypt(make_cfg(), "just text"))


class JoinCodeTests(unittest.TestCase):
    def test_roundtrip(self):
        cfg = make_cfg()
        parsed = mesh.parse_join_code(mesh.join_code(cfg))
        for k in ("mesh", "id", "key", "server", "nodes"):
            self.assertEqual(parsed[k], cfg[k])

    def test_garbage_code_exits(self):
        with self.assertRaises(SystemExit):
            mesh.parse_join_code("garbage")


class EnvelopeTests(unittest.TestCase):
    def test_send_envelope_roundtrip(self):
        env = mesh.make_send_envelope("alpha", "beta", "do the thing")
        parsed = mesh._parse_envelope(json.dumps(env))
        kind, task_id, ctx, state, frm, text = mesh.envelope_summary(parsed)
        self.assertEqual(kind, "request")
        self.assertEqual(state, "submitted")
        self.assertEqual(frm, "alpha")
        self.assertEqual(text, "do the thing")
        self.assertEqual(task_id, env["params"]["message"]["taskId"])

    def test_result_envelope_roundtrip(self):
        env = mesh.make_result_envelope("beta", "alpha", "T1", "C1",
                                        "completed", "42")
        kind, task_id, ctx, state, frm, text = mesh.envelope_summary(env)
        self.assertEqual((kind, task_id, state, frm, text),
                         ("result", "T1", "completed", "beta", "42"))

    def test_non_envelope_is_none(self):
        self.assertIsNone(mesh._parse_envelope("hello"))
        self.assertIsNone(mesh._parse_envelope('{"jsonrpc": "1.0"}'))


class NodeNameTests(unittest.TestCase):
    def test_sanitizes_hostname(self):
        with mock.patch("socket.gethostname",
                        return_value="James's MacBook.local"):
            self.assertEqual(mesh._default_node_name(), "james-s-macbook")

    def test_strips_lan_and_collapses_dashes(self):
        with mock.patch("socket.gethostname", return_value="MY--PC.lan"):
            self.assertEqual(mesh._default_node_name(), "my-pc")

    def test_unusable_hostname_returns_none(self):
        with mock.patch("socket.gethostname", return_value="'''"):
            self.assertIsNone(mesh._default_node_name())


class PeerTests(unittest.TestCase):
    def test_note_peer_learns_node_and_records_sighting(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            mesh.note_peer(cfg, "gamma", "message")
            self.assertIn("gamma", cfg["nodes"])
            with open(cfg["_path"]) as f:
                self.assertIn("gamma", json.load(f)["nodes"])
            peers = mesh.load_peers(cfg)
            self.assertEqual(peers["gamma"]["via"], "message")
            self.assertGreater(peers["gamma"]["seen"], 0)

    def test_note_peer_updates_known_node_without_config_write(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            mesh.note_peer(cfg, "beta", "pong")  # already in nodes
            self.assertFalse(os.path.exists(cfg["_path"]))  # config untouched
            self.assertEqual(mesh.load_peers(cfg)["beta"]["via"], "pong")

    def test_note_peer_ignores_broadcast_and_empty(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            mesh.note_peer(cfg, "all", "message")
            mesh.note_peer(cfg, None, "message")
            self.assertEqual(cfg["nodes"], ["alpha", "beta"])
            self.assertFalse(os.path.exists(mesh.peers_file(cfg)))

    def test_note_peer_gitignores_peers_file_on_first_write(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            mesh.note_peer(cfg, "gamma", "message")
            with open(os.path.join(d, ".gitignore")) as f:
                self.assertIn(".meshwire.peers.json", f.read())


class MembershipCmdTests(unittest.TestCase):
    """cmd_* tests run chdir'd into a temp dir (find_config walks up from cwd)."""

    def setUp(self):
        self._env = os.environ.pop("MESHWIRE_NODE", None)
        self._tmp = tempfile.TemporaryDirectory()
        self._old = os.getcwd()
        os.chdir(self._tmp.name)

    def tearDown(self):
        os.chdir(self._old)
        self._tmp.cleanup()
        if self._env is not None:
            os.environ["MESHWIRE_NODE"] = self._env

    def test_init_without_nodes_uses_hostname(self):
        ns = argparse.Namespace(name="home", nodes=None,
                                server="https://ntfy.sh", as_node=None)
        buf = io.StringIO()
        with mock.patch("socket.gethostname", return_value="Laptop.local"), \
             contextlib.redirect_stdout(buf):
            mesh.cmd_init(ns)
        with open(".meshwire.json") as f:
            cfg = json.load(f)
        self.assertEqual(cfg["nodes"], ["laptop"])
        with open(".meshwire.node") as f:
            self.assertEqual(f.read().strip(), "laptop")
        with open(".gitignore") as f:
            self.assertIn(".meshwire.peers.json", f.read())

    def test_init_unusable_hostname_requires_as(self):
        ns = argparse.Namespace(name="home", nodes=None,
                                server="https://ntfy.sh", as_node=None)
        with mock.patch("socket.gethostname", return_value="'''"):
            with self.assertRaises(SystemExit):
                mesh.cmd_init(ns)

    def test_join_defaults_identity_and_announces(self):
        code = mesh.join_code({"mesh": "home", "id": "i1", "key": "aa" * 32,
                               "server": "https://ntfy.example",
                               "nodes": ["laptop"]})
        calls = []

        def fake_send(cfg, s, t, b, title=None, ctl=None):
            calls.append((s, t, ctl))
            return {"id": "1"}

        buf = io.StringIO()
        with mock.patch.object(mesh, "send_raw", fake_send), \
             mock.patch("socket.gethostname", return_value="desktop.local"), \
             contextlib.redirect_stdout(buf):
            mesh.cmd_join(argparse.Namespace(code=code, as_node=None))
        with open(".meshwire.json") as f:
            self.assertIn("desktop", json.load(f)["nodes"])
        self.assertEqual(calls, [("desktop", "all", {"mw": "announce"})])

    def test_join_plaintext_mesh_skips_announce(self):
        code = mesh.join_code({"mesh": "home", "id": "i1", "key": None,
                               "server": "https://ntfy.example", "nodes": []})
        calls = []
        buf = io.StringIO()
        with mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: calls.append(1)), \
             contextlib.redirect_stdout(buf):
            mesh.cmd_join(argparse.Namespace(code=code, as_node="pc"))
        self.assertEqual(calls, [])

    def test_iam_accepts_new_name_and_learns_it(self):
        with open(".meshwire.json", "w") as f:
            json.dump(make_cfg(), f)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            mesh.cmd_iam(argparse.Namespace(node="gamma"))
        with open(".meshwire.json") as f:
            self.assertIn("gamma", json.load(f)["nodes"])

    def test_iam_rejects_broadcast_name(self):
        with open(".meshwire.json", "w") as f:
            json.dump(make_cfg(), f)
        with self.assertRaises(SystemExit):
            mesh.cmd_iam(argparse.Namespace(node="all"))

    def test_my_node_autolearns_unknown_identity(self):
        cfg = make_cfg(self._tmp.name)
        with open(mesh.node_file(cfg), "w") as f:
            f.write("gamma\n")
        self.assertEqual(mesh.my_node(cfg), "gamma")
        self.assertIn("gamma", cfg["nodes"])

    def test_my_node_without_identity_exits(self):
        cfg = make_cfg(self._tmp.name)
        with self.assertRaises(SystemExit):
            mesh.my_node(cfg)
        self.assertNotIn(None, cfg["nodes"])

    def test_join_survives_announce_failure(self):
        code = mesh.join_code({"mesh": "home", "id": "i1", "key": "aa" * 32,
                               "server": "https://ntfy.example",
                               "nodes": []})

        def boom(*a, **k):
            raise urllib.error.URLError("relay down")

        buf = io.StringIO()
        with mock.patch.object(mesh, "send_raw", boom), \
             contextlib.redirect_stdout(buf):
            mesh.cmd_join(argparse.Namespace(code=code, as_node="pc"))
        with open(".meshwire.json") as f:
            self.assertIn("pc", json.load(f)["nodes"])
        self.assertIn("announce failed", buf.getvalue())


class AgoTests(unittest.TestCase):
    def test_buckets(self):
        now = int(mesh.time.time())
        self.assertTrue(mesh._ago(now - 5).endswith("s ago"))
        self.assertEqual(mesh._ago(now - 120), "2m ago")
        self.assertEqual(mesh._ago(now - 7200), "2h ago")
        self.assertEqual(mesh._ago(now - 172800), "2d ago")


class OpenControlTests(unittest.TestCase):
    def test_open_returns_control_field(self):
        cfg = make_cfg()
        wire = mesh.encrypt(cfg, json.dumps(
            {"f": "beta", "t": "alpha", "b": "ping",
             "c": {"mw": "ping", "n": "x1"}}))
        frm, body, trusted, ctl = mesh._open({"message": wire}, cfg)
        self.assertEqual((frm, body, trusted), ("beta", "ping", True))
        self.assertEqual(ctl, {"mw": "ping", "n": "x1"})

    def test_open_without_control_returns_none_ctl(self):
        cfg = make_cfg()
        wire = mesh.encrypt(cfg, json.dumps(
            {"f": "beta", "t": "alpha", "b": "hi"}))
        frm, body, trusted, ctl = mesh._open({"message": wire}, cfg)
        self.assertEqual((frm, body, trusted, ctl), ("beta", "hi", True, None))

    def test_open_foreign_ciphertext_untrusted(self):
        wire = mesh.encrypt(make_cfg(), "x")
        frm, body, trusted, ctl = mesh._open({"message": wire}, make_cfg())
        self.assertEqual((body, trusted, ctl), ("", False, None))


class SendRawTests(unittest.TestCase):
    def test_ctl_rides_inside_ciphertext(self):
        cfg = make_cfg()
        sent = {}

        def fake_post(cfg_, tpc, data, headers):
            sent["tpc"], sent["data"], sent["headers"] = tpc, data, headers
            return {"id": "m1"}

        with mock.patch.object(mesh, "_post", fake_post):
            mesh.send_raw(cfg, "alpha", "beta", "ping",
                          ctl={"mw": "ping", "n": "n1"})
        self.assertEqual(sent["tpc"], mesh.topic(cfg, "beta"))
        wrapper = json.loads(mesh.decrypt(cfg, sent["data"].decode()))
        self.assertEqual(wrapper["c"], {"mw": "ping", "n": "n1"})
        self.assertEqual(wrapper["b"], "ping")
        self.assertEqual(sent["headers"]["Title"], cfg["mesh"])  # generic title

    def test_plain_message_has_no_c_key(self):
        cfg = make_cfg()
        sent = {}

        def fake_post(cfg_, tpc, data, headers):
            sent["data"] = data
            return {"id": "m1"}

        with mock.patch.object(mesh, "_post", fake_post):
            mesh.send_raw(cfg, "alpha", "beta", "hello")
        wrapper = json.loads(mesh.decrypt(cfg, sent["data"].decode()))
        self.assertNotIn("c", wrapper)


class SendStatusInviteTests(MembershipCmdTests):
    """Reuses the chdir-to-tmp setUp/tearDown."""

    def _write_cfg(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        return cfg

    def test_peek_learns_peers(self):
        cfg = self._write_cfg()
        cfg["_path"] = os.path.abspath(".meshwire.json")
        cfg["_dir"] = os.getcwd()
        wire = mesh.encrypt(cfg, json.dumps(
            {"f": "gamma", "t": "alpha", "b": "hi"}))
        ev = json.dumps({"event": "message", "id": "p1", "time": 100,
                         "message": wire, "title": "t"})

        class R:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return (ev + "\n").encode()

        out = io.StringIO()
        with mock.patch.object(mesh, "http", lambda *a, **k: R()), \
             contextlib.redirect_stdout(out):
            mesh.cmd_peek(argparse.Namespace(node=None, since="all",
                                             as_node=None))
        with open(".meshwire.json") as f:
            self.assertIn("gamma", json.load(f)["nodes"])

    def test_send_to_unknown_warns_but_sends(self):
        self._write_cfg()
        sent, err, out = [], io.StringIO(), io.StringIO()
        with mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: sent.append(a) or {"id": "1"}), \
             contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            mesh.cmd_send(argparse.Namespace(to="gamma", message=["hi"],
                                             as_node=None))
        self.assertEqual(len(sent), 1)
        self.assertIn("never seen 'gamma'", err.getvalue())

    def test_send_to_self_still_errors(self):
        self._write_cfg()
        with self.assertRaises(SystemExit):
            mesh.cmd_send(argparse.Namespace(to="alpha", message=["hi"],
                                             as_node=None))

    def test_ask_to_broadcast_errors(self):
        self._write_cfg()
        with self.assertRaises(SystemExit):
            mesh.cmd_ask(argparse.Namespace(to="all", text=["x"], wait=0,
                                            as_node=None))

    def test_status_shows_last_seen(self):
        cfg = self._write_cfg()
        cfg["_path"] = os.path.abspath(".meshwire.json")
        cfg["_dir"] = os.getcwd()
        mesh.note_peer(cfg, "beta", "pong")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mesh.cmd_status(argparse.Namespace(as_node=None))
        text = out.getvalue()
        self.assertIn("beta", text)
        self.assertIn("ago", text)          # last-seen rendered
        self.assertIn("this machine", text)  # self marked

    def test_invite_prints_bootstrap_block(self):
        self._write_cfg()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mesh.cmd_invite(argparse.Namespace())
        text = out.getvalue()
        self.assertIn("curl -fsSLO https://raw.githubusercontent.com/husker/"
                      "meshwire/main/mesh.py", text)
        self.assertIn("python3 mesh.py join mesh1-", text)


class _TestDone(Exception):
    """Raised by the fake transport when its scripted events run out."""


class _FakeResp:
    def __init__(self, lines):
        self._lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        return iter(self._lines)


def fake_stream(events):
    """A mesh.http replacement: first call streams `events`, next call raises
    _TestDone so tests escape the reconnect loop deterministically."""
    lines = [json.dumps(e).encode() + b"\n" for e in events]
    state = {"calls": 0}

    def _http(url, data=None, headers=None, timeout=15):
        state["calls"] += 1
        if state["calls"] > 1:
            raise _TestDone()
        return _FakeResp(lines)

    return _http


class StreamEventsTests(unittest.TestCase):
    def test_yields_messages_dedupes_and_survives_noise(self):
        cfg = make_cfg()
        evs = [
            {"event": "open"},
            {"event": "message", "id": "m1", "time": 100, "message": "x"},
            {"event": "message", "id": "m1", "time": 100, "message": "x"},
            {"event": "keepalive"},
            {"event": "message", "id": "m2", "time": 101, "message": "y"},
        ]
        with mock.patch.object(mesh, "http", fake_stream(evs)):
            gen = mesh._stream_events(cfg, "tp", "0", deadline=None)
            self.assertEqual(next(gen)["id"], "m1")
            self.assertEqual(next(gen)["id"], "m2")
            with mock.patch("time.sleep"):
                self.assertRaises(_TestDone, next, gen)

    def test_first_response_consumed_before_dialing(self):
        cfg = make_cfg()
        ev = {"event": "message", "id": "m1", "time": 100, "message": "x"}
        pre = _FakeResp([json.dumps(ev).encode() + b"\n"])

        def no_dial(url, **kw):
            raise AssertionError("dialed despite pre-opened response")

        with mock.patch.object(mesh, "http", no_dial):
            gen = mesh._stream_events(cfg, "tp", "0",
                                      deadline=mesh.time.time() + 60,
                                      first=pre)
            self.assertEqual(next(gen)["id"], "m1")

    def test_skip_set_prunes_across_seconds(self):
        cfg = make_cfg()
        evs = [
            {"event": "message", "id": "m1", "time": 100, "message": "x"},
            {"event": "message", "id": "m2", "time": 101, "message": "y"},
            {"event": "message", "id": "m3", "time": 102, "message": "z"},
        ]
        skip = set()
        with mock.patch.object(mesh, "http", fake_stream(evs)):
            gen = mesh._stream_events(cfg, "tp", "0", deadline=None, skip=skip)
            self.assertEqual(next(gen)["id"], "m1")
            self.assertEqual(next(gen)["id"], "m2")
            self.assertEqual(next(gen)["id"], "m3")
        self.assertEqual(skip, {"m3"})


class WatchTests(MembershipCmdTests):
    """Chdir fixture; builds a real on-disk config with identity alpha."""

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

    def test_one_shot_delivers_message_and_saves_cursor(self):
        cfg = self._setup_mesh()
        evs = [self._msg_event(cfg, "beta", "hello there", "m1", 200)]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             contextlib.redirect_stdout(out):
            mesh.cmd_watch(argparse.Namespace(timeout=60, as_node=None,
                                              follow=False))
        self.assertIn("MESH_MESSAGE from='beta' to=alpha: hello there",
                      out.getvalue())
        with open(".meshwire.cursor-alpha") as f:
            self.assertEqual(json.load(f)["since"], 200)

    def test_follow_delivers_multiple_messages(self):
        cfg = self._setup_mesh()
        evs = [self._msg_event(cfg, "beta", "one", "m1", 200),
               self._msg_event(cfg, "beta", "two", "m2", 201)]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch("time.sleep"), contextlib.redirect_stdout(out):
            self.assertRaises(_TestDone, mesh.cmd_watch,
                              argparse.Namespace(timeout=None, as_node=None,
                                                 follow=True))
        self.assertIn("one", out.getvalue())
        self.assertIn("two", out.getvalue())

    def test_control_message_does_not_consume_one_shot(self):
        cfg = self._setup_mesh()
        evs = [self._msg_event(cfg, "beta", "ping", "m1", 200,
                               ctl={"mw": "ping", "n": "n1"}),
               self._msg_event(cfg, "beta", "real message", "m2", 201)]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw", lambda *a, **k: {"id": "1"}), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            mesh.cmd_watch(argparse.Namespace(timeout=60, as_node=None,
                                              follow=False))
        self.assertNotIn("MESH_MESSAGE from='beta' to=alpha: ping",
                         out.getvalue())
        self.assertIn("real message", out.getvalue())


class AwaitResultTests(MembershipCmdTests):
    def test_await_matches_task_id(self):
        cfg = make_cfg(self._tmp.name)
        env = mesh.make_result_envelope("beta", "alpha", "T1", "C1",
                                        "completed", "42")
        wire = mesh.encrypt(cfg, json.dumps(
            {"f": "beta", "t": "alpha", "b": json.dumps(env)}))
        evs = [{"event": "message", "id": "r1", "time": 300, "message": wire}]
        with mock.patch.object(mesh, "http", fake_stream(evs)):
            got = mesh._await_result(cfg, "alpha", "T1", timeout=60)
        self.assertEqual(got["result"]["id"], "T1")


class ControlHandlingTests(unittest.TestCase):
    def test_ping_gets_ponged_with_same_nonce(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            sent = []

            def fake_send(c, s, t, b, title=None, ctl=None):
                sent.append((s, t, ctl))
                return {"id": "1"}

            with mock.patch.object(mesh, "send_raw", fake_send):
                out = mesh._handle_control(cfg, "alpha", "beta",
                                           {"mw": "ping", "n": "n9", "ts": 5})
            self.assertIsNone(out)
            self.assertEqual(sent, [("alpha", "beta",
                                     {"mw": "pong", "n": "n9", "ts": 5})])

    def test_announce_prints_marker_and_learns_node(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            out = mesh._handle_control(cfg, "alpha", "gamma",
                                       {"mw": "announce"})
            self.assertEqual(out, "MESH_NODE_JOINED node=gamma")
            self.assertIn("gamma", cfg["nodes"])

    def test_pong_is_silent_but_noted(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = make_cfg(d)
            out = mesh._handle_control(cfg, "alpha", "beta",
                                       {"mw": "pong", "n": "x"})
            self.assertIsNone(out)
            self.assertEqual(mesh.load_peers(cfg)["beta"]["via"], "pong")


class PingCmdTests(MembershipCmdTests):
    def test_ping_prints_rtt(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        pong = mesh.encrypt(cfg, json.dumps(
            {"f": "beta", "t": "alpha", "b": "pong",
             "c": {"mw": "pong", "n": "fixednonce", "ts": 1.0}}))
        evs = [{"event": "message", "id": "p1", "time": 400, "message": pong}]
        out = io.StringIO()
        with mock.patch.object(mesh, "http", fake_stream(evs)), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: {"id": "1"}), \
             mock.patch.object(mesh.secrets, "token_hex",
                               return_value="fixednonce"), \
             contextlib.redirect_stdout(out):
            mesh.cmd_ping(argparse.Namespace(node="beta", timeout=5,
                                             as_node=None))
        self.assertRegex(out.getvalue(), r"MESH_PONG node=beta rtt=\d+ms")

    def test_ping_plaintext_mesh_errors(self):
        with open(".meshwire.json", "w") as f:
            json.dump(make_cfg(key=False), f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        with self.assertRaises(SystemExit):
            mesh.cmd_ping(argparse.Namespace(node="beta", timeout=5,
                                             as_node=None))


class AskOrderTests(MembershipCmdTests):
    def test_ask_subscribes_before_sending(self):
        cfg = make_cfg()
        with open(".meshwire.json", "w") as f:
            json.dump(cfg, f)
        with open(".meshwire.node", "w") as f:
            f.write("alpha\n")
        order = []
        out = io.StringIO()
        with mock.patch.object(mesh, "_stream_open",
                               lambda *a, **k: order.append("open")), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: order.append("send")
                               or {"id": "1"}), \
             mock.patch.object(mesh, "_await_result",
                               lambda *a, **k: None), \
             contextlib.redirect_stdout(out):
            mesh.cmd_ask(argparse.Namespace(to="beta", text=["hi"], wait=5,
                                            as_node=None))
        self.assertEqual(order, ["open", "send"])


class _FakeConn:
    instances = []

    def __init__(self, netloc, timeout=None):
        _FakeConn.instances.append(self)
        self.paths = []
        self.fail_next = False

    def request(self, method, path, body=None, headers=None):
        if self.fail_next:
            self.fail_next = False
            raise ConnectionError("dropped")
        self.paths.append(path)

    def getresponse(self):
        class R:
            status = 200

            def read(self):
                return b'{"id": "ok"}'
        return R()

    def close(self):
        pass


class PostReuseTests(unittest.TestCase):
    def setUp(self):
        _FakeConn.instances = []
        mesh._LOCAL = threading.local()  # fresh per-thread cache

    def test_reuses_one_connection_across_sends(self):
        cfg = make_cfg()
        with mock.patch("mesh.HTTPSConnection", _FakeConn):
            mesh._post(cfg, "tp1", b"a", {})
            mesh._post(cfg, "tp2", b"b", {})
        self.assertEqual(len(_FakeConn.instances), 1)
        self.assertEqual(len(_FakeConn.instances[0].paths), 2)

    def test_retries_once_on_dropped_connection(self):
        cfg = make_cfg()
        with mock.patch("mesh.HTTPSConnection", _FakeConn):
            mesh._post(cfg, "tp1", b"a", {})
            _FakeConn.instances[0].fail_next = True
            out = mesh._post(cfg, "tp2", b"b", {})
        self.assertEqual(out, {"id": "ok"})
        self.assertEqual(len(_FakeConn.instances), 2)  # reconnected once


class AutoWatchTests(MembershipCmdTests):
    """init/join flow into the watcher in a terminal; return otherwise."""

    def _init_ns(self):
        return argparse.Namespace(name="home", nodes=None,
                                  server="https://ntfy.sh", as_node="alpha")

    def test_init_flows_into_watcher_in_terminal(self):
        calls = []
        out = io.StringIO()

        def fake_watch(a):
            calls.append((a, os.path.isfile(".meshwire.json")))

        with mock.patch.object(mesh, "_interactive", lambda: True), \
             mock.patch.object(mesh, "cmd_watch", fake_watch), \
             contextlib.redirect_stdout(out):
            mesh.cmd_init(self._init_ns())
        self.assertTrue(calls[0][1])  # config existed when watching began
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].follow)
        self.assertIsNone(calls[0][0].timeout)
        self.assertIn("Ctrl-C to stop", out.getvalue())
        # a terminal user can't run `mesh invite` anymore — init must
        # print the paste block itself before watching
        self.assertIn("python3 mesh.py join mesh1-", out.getvalue())

    def test_init_returns_when_not_a_terminal(self):
        calls = []
        out = io.StringIO()
        with mock.patch.object(mesh, "_interactive", lambda: False), \
             mock.patch.object(mesh, "cmd_watch",
                               lambda a: calls.append(a)), \
             contextlib.redirect_stdout(out):
            mesh.cmd_init(self._init_ns())
        self.assertEqual(calls, [])
        self.assertIn("mesh invite", out.getvalue())  # pointer line kept

    def test_join_announces_before_watching(self):
        code = mesh.join_code({"mesh": "home", "id": "i1", "key": "aa" * 32,
                               "server": "https://ntfy.example",
                               "nodes": []})
        order = []
        out = io.StringIO()
        with mock.patch.object(mesh, "_interactive", lambda: True), \
             mock.patch.object(mesh, "send_raw",
                               lambda *a, **k: order.append("announce")
                               or {"id": "1"}), \
             mock.patch.object(mesh, "cmd_watch",
                               lambda a: order.append("watch")), \
             contextlib.redirect_stdout(out):
            mesh.cmd_join(argparse.Namespace(code=code, as_node="pc"))
        self.assertEqual(order, ["announce", "watch"])

    def test_invite_block_has_no_watch_tail(self):
        with open(".meshwire.json", "w") as f:
            json.dump(make_cfg(), f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            mesh.cmd_invite(argparse.Namespace())
        self.assertNotIn("watch --follow", out.getvalue())
        self.assertIn("python3 mesh.py join mesh1-", out.getvalue())

    def test_main_exits_130_on_ctrl_c(self):
        def boom(a):
            raise KeyboardInterrupt
        out = io.StringIO()
        with mock.patch.object(mesh, "cmd_status", boom), \
             mock.patch.object(sys, "argv", ["mesh", "status"]), \
             contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as cm:
                mesh.main()
        self.assertEqual(cm.exception.code, 130)


if __name__ == "__main__":
    unittest.main()


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

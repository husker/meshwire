"""Unit tests for mesh.py — stdlib only, no network.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import json
import os
import secrets
import sys
import tempfile
import unittest
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


class AgoTests(unittest.TestCase):
    def test_buckets(self):
        now = int(mesh.time.time())
        self.assertTrue(mesh._ago(now - 5).endswith("s ago"))
        self.assertEqual(mesh._ago(now - 120), "2m ago")
        self.assertEqual(mesh._ago(now - 7200), "2h ago")
        self.assertEqual(mesh._ago(now - 172800), "2d ago")


if __name__ == "__main__":
    unittest.main()

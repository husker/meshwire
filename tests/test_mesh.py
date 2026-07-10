"""Unit tests for mesh.py — stdlib only, no network.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import json
import os
import secrets
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()

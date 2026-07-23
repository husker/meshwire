"""The KEY_MISMATCH rehearsal tool must keep working (#62).

A tool that is only run by hand once per release rots between releases, and
the whole point of landing it was that soak records cite a fresh capture
rather than a frozen comment. This runs it in the normal suite so a change to
the verdict chain breaks the rehearsal here rather than at soak-closure time.
"""
import importlib.util
import io
import os
import unittest

TOOL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "tools", "rehearse_key_mismatch.py")


def _load():
    spec = importlib.util.spec_from_file_location("rehearse_key_mismatch",
                                                  TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RehearsalToolTests(unittest.TestCase):

    def test_rehearsal_passes_both_arms(self):
        out = io.StringIO()
        ok, _ = _load().rehearse(out=out)
        text = out.getvalue()
        self.assertTrue(ok, "rehearsal FAILED:\n" + text)
        # the attack arm derives the mismatch rather than being handed it
        self.assertIn("derived verdict      : 'mismatch'", text)
        self.assertIn("KEY_MISMATCH", text)
        # the control arm proves the harness discriminates -- without it, a
        # verifier that always returned mismatch would pass
        self.assertIn("derived verdict      : 'verified'", text)
        self.assertIn("WOULD_MIGRATE", text)
        self.assertIn("REHEARSAL RESULT: PASS", text)

    def test_rehearsal_cleans_up_its_scratch_mesh(self):
        ok, root = _load().rehearse(out=io.StringIO())
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(root),
                         "scratch mesh left behind at " + root)


if __name__ == "__main__":
    unittest.main()

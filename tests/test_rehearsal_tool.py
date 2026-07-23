"""The KEY_MISMATCH rehearsal tool must keep working (#62).

A tool that is only run by hand once per release rots between releases, and
the whole point of landing it was that soak records cite a fresh capture
rather than a frozen comment. This runs it in the normal suite so a change to
the verdict chain breaks the rehearsal here rather than at soak-closure time.

Assertions read the structured result, never the printed capture: the capture
is human-facing text and reformatting it must not fail the suite (bastion,
PR-109 seat).
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

    def setUp(self):
        self.tool = _load()
        self.mesh = self.tool.mesh

    def test_attack_arm_derives_the_mismatch(self):
        # the verdict must be DERIVED from a real key conflict, not handed
        # in as tests/test_mesh.py does
        result = self.tool.rehearse(out=io.StringIO())
        self.assertTrue(result["ok"], result["failures"])
        self.assertEqual(result["attack"]["verdict"], self.mesh.FRAME_MISMATCH)
        self.assertIn("KEY_MISMATCH", result["attack"]["log"])
        self.assertNotIn("WOULD_MIGRATE", result["attack"]["log"])

    def test_control_arm_proves_the_harness_discriminates(self):
        # without this, a verifier that returned mismatch unconditionally
        # would pass the attack arm and the rehearsal would be theatre
        result = self.tool.rehearse(out=io.StringIO())
        self.assertEqual(result["control"]["verdict"],
                         self.mesh.FRAME_VERIFIED)
        self.assertIn("WOULD_MIGRATE", result["control"]["log"])
        for token in ("KEY_MISMATCH", "UNVERIFIED_SOURCE"):
            self.assertNotIn(token, result["control"]["log"])

    def test_forged_hint_arm_pins_the_signature_check(self):
        # bastion, PR-109 seat: arms 1 and 2 prove the harness discriminates
        # by KEY IDENTITY but not that it checks SIGNATURE BYTES. Replacing
        # _verify_node_sig with `carried hint == pin` passes both of them
        # while gutting the crypto. This arm forges the carried hint -- which
        # a real forger controls freely -- so only verifying against the PIN
        # rejects it.
        result = self.tool.rehearse(out=io.StringIO())
        self.assertEqual(result["forged_hint"]["verdict"],
                         self.mesh.FRAME_MISMATCH)
        self.assertIn("KEY_MISMATCH", result["forged_hint"]["log"])
        self.assertNotIn("WOULD_MIGRATE", result["forged_hint"]["log"])

    def test_rehearsal_cleans_up_its_scratch_mesh(self):
        result = self.tool.rehearse(out=io.StringIO())
        self.assertTrue(result["ok"], result["failures"])
        self.assertFalse(os.path.exists(result["root"]),
                         "scratch mesh left behind at " + result["root"])

    def test_keep_retains_the_scratch_mesh(self):
        import shutil
        result = self.tool.rehearse(out=io.StringIO(), keep=True)
        try:
            self.assertTrue(os.path.isdir(result["root"]))
        finally:
            shutil.rmtree(result["root"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

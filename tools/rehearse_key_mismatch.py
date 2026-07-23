#!/usr/bin/env python3
"""Rehearse the KEY_MISMATCH lifecycle path end-to-end (#62, #76, #93).

WHY THIS EXISTS
---------------
`KEY_MISMATCH` is the one pin-lifecycle path a healthy mesh never produces.
It fires only when a receiver holds pin A for a name while key B signs AS
that name -- by construction the signature of impersonation or of store
corruption. So it cannot be evidenced by a live soak the way membership,
revocation and verified-rename can: the only ways to obtain a live event are
to stage real forgery on the production mesh, or to deliberately mis-pin a
name (and pins never silently replace, so that leaves a durable conflict to
clean up afterwards).

This tool produces the evidence instead, on a scratch mesh, and is meant to
be re-run per release so soak records cite a fresh capture rather than a
frozen comment.

WHAT IT PROVES THAT THE UNIT TESTS DO NOT
-----------------------------------------
`tests/test_mesh.py` calls `_handle_control(..., verdict=FRAME_MISMATCH)`
with the verdict passed in by hand, which proves the branch prints. It cannot
prove the verdict is correctly DERIVED. This drives two real ed25519 keypairs
through the actual chain -- `_sign_wrapper_payload` -> `_frame_verdict` ->
`_verify_frame` -> `_handle_control` -- so the mismatch comes from a genuine
cryptographic key conflict.

Both arms run, and both must hold:

  attack  key B signs as `victim`  -> FRAME_MISMATCH -> KEY_MISMATCH
  control key A signs as `victim`  -> FRAME_VERIFIED -> WOULD_MIGRATE

The control arm is not decoration. Without it, a verifier that returned
`mismatch` unconditionally would pass the attack arm and the rehearsal would
be theatre.

SAFETY
------
Scratch mesh in a temp directory, its own mesh id and shared key, removed on
exit. No relay hop and no network: the properties under test are signature
verification and verdict classification, to which the transport contributes
nothing. Never touches a real mesh directory.

Usage:  python3 tools/rehearse_key_mismatch.py [--keep]
Exit:   0 = rehearsal PASSED, 1 = FAILED
"""
import argparse
import base64
import contextlib
import io
import json
import os
import secrets
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import mesh  # noqa: E402

LAB_MESH_ID = "fedcba9876543210"
VICTIM = "victim"
CLAIMED_NEW = "victim-controlled-by-me"


def _scratch(root, name, shared):
    """A scratch node directory sharing one lab mesh identity."""
    node_dir = os.path.join(root, name)
    os.makedirs(node_dir, exist_ok=True)
    body = {"mesh": "labmesh", "id": LAB_MESH_ID, "key": shared,
            "server": "https://ntfy.sh", "nodes": [VICTIM, "attacker"]}
    path = os.path.join(node_dir, ".meshwire.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(body, f)
    cfg = dict(body)
    cfg["_dir"], cfg["_path"] = node_dir, path
    return cfg


def _keygen(cfg, node):
    mesh._ensure_node_key(cfg, node, "claude")
    return mesh._own_node_pubkey(cfg, "claude")


def _fpr(pub):
    return mesh._key_fingerprint(mesh._normalize_pubkey(pub))


def _run_arm(receiver, signer, frame_id):
    """Sign a rename control frame AS `victim` with `signer`'s key, then run
    it through the real receive path. Returns (verdict, stderr_text)."""
    ctl = {"mw": "rename", "new": CLAIMED_NEW, "ts": 1784847000}
    payload = {"f": VICTIM, "t": mesh.BROADCAST,
               "b": "%s is now %s" % (VICTIM, CLAIMED_NEW), "c": ctl}
    wire_ts, signed = mesh._sign_wrapper_payload(
        signer, mesh.BROADCAST, payload, harness="claude")
    ev = {"id": frame_id, "topic": mesh.topic(receiver, mesh.BROADCAST)}
    verdict = mesh._frame_verdict(
        receiver, signed["f"], signed["t"], signed["b"], signed.get("c"),
        signed.get("s"), signed.get("k"), wire_ts, ev)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        mesh._report_verdict(signed["f"], ev, verdict)
        mesh._handle_control(receiver, "receiver", signed["f"],
                             signed.get("c"), verdict=verdict, ev=ev)
    return verdict, err.getvalue()


def rehearse(out=sys.stdout, keep=False):
    """Run both arms. Returns a result dict; callers assert on its fields
    rather than on the printed text, so reformatting the capture cannot
    break them."""
    root = tempfile.mkdtemp(prefix="mw-rehearsal-")
    shared = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    failures = []

    def say(line=""):
        out.write(line + "\n")

    try:
        say("scratch root : %s" % root)
        say("scratch mesh : labmesh / %s   (NOT a real mesh)" % LAB_MESH_ID)
        say()

        honest = _scratch(root, "honest", shared)      # key A
        attacker = _scratch(root, "attacker", shared)  # key B
        receiver = _scratch(root, "receiver", shared)  # holds the pin store

        key_a, key_b = _keygen(honest, VICTIM), _keygen(attacker, "attacker")
        say("key A (real %s)   : %s" % (VICTIM, _fpr(key_a)))
        say("key B (attacker) : %s" % _fpr(key_b))
        if _fpr(key_a) == _fpr(key_b):
            failures.append("generated keys collided")
        say()

        mesh._bind_peer(receiver, VICTIM, key_a)
        say("receiver pin store   : %s -> %s" % (VICTIM, _fpr(key_a)))
        say()

        # ---- arm 1: the attack ----
        say("--- ARM 1: attacker (key B) signs as '%s' ---" % VICTIM)
        verdict, log = _run_arm(receiver, attacker, "rehearsal-attack-0001")
        say("derived verdict      : %r" % verdict)
        for line in log.strip().splitlines():
            say("  %s" % line)
        if verdict != mesh.FRAME_MISMATCH:
            failures.append("attack arm: verdict %r, want FRAME_MISMATCH"
                            % verdict)
        if "KEY_MISMATCH" not in log:
            failures.append("attack arm: no KEY_MISMATCH evidence line")
        for token in ("WOULD_MIGRATE", "UNVERIFIED_SOURCE"):
            if token in log:
                failures.append("attack arm: leaked %s" % token)
        say()

        # ---- arm 2: the control (a rehearsal that only tests the attack
        # arm would pass with a verifier that always says mismatch) ----
        say("--- ARM 2 (control): real %s (key A) signs as itself ---"
            % VICTIM)
        verdict2, log2 = _run_arm(receiver, honest, "rehearsal-control-0002")
        say("derived verdict      : %r" % verdict2)
        for line in (log2.strip().splitlines() or ["(no verdict warning)"]):
            say("  %s" % line)
        if verdict2 != mesh.FRAME_VERIFIED:
            failures.append("control arm: verdict %r, want FRAME_VERIFIED"
                            % verdict2)
        if "WOULD_MIGRATE" not in log2:
            failures.append("control arm: no WOULD_MIGRATE evidence line")
        for token in ("KEY_MISMATCH", "UNVERIFIED_SOURCE"):
            if token in log2:
                failures.append("control arm: leaked %s" % token)
        say()

        # ---- Ph1 purity: neither arm may mutate durable state ----
        say("--- Ph1 purity: did either arm mutate the pin store? ---")
        pins = mesh._load_pins(receiver)
        say("  %s still pinned to key A : %s"
            % (VICTIM, _fpr(pins.get(VICTIM, "")) == _fpr(key_a)))
        say("  claimed new name pinned  : %s" % (CLAIMED_NEW in pins))
        say("  pin store names          : %s" % sorted(pins))
        if _fpr(pins.get(VICTIM, "")) != _fpr(key_a):
            failures.append("pin for %s was mutated" % VICTIM)
        if CLAIMED_NEW in pins:
            failures.append("claimed new name %r was pinned" % CLAIMED_NEW)
        say()

        if failures:
            say("REHEARSAL RESULT: FAIL")
            for f in failures:
                say("  - %s" % f)
        else:
            say("REHEARSAL RESULT: PASS")
        return {"ok": not failures, "root": root, "failures": failures,
                "attack": {"verdict": verdict, "log": log},
                "control": {"verdict": verdict2, "log": log2}}
    finally:
        if not keep:
            shutil.rmtree(root, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keep", action="store_true",
                    help="keep the scratch mesh directory for inspection")
    args = ap.parse_args()
    result = rehearse(keep=args.keep)
    if args.keep:
        print("\nscratch mesh kept at: %s" % result["root"])
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""meshwire: zero-infrastructure messaging between AI agent sessions on
different machines.

Two-layer design:
  1. PAYLOAD layer — whatever your project already shares (usually a git
     repo). Substantive content travels there, with a full audit trail.
  2. WAKE layer (this tool) — tiny pings over ntfy.sh pub/sub capability
     topics, so the other machine's agent session learns *now* that there is
     something to pull, instead of waiting for its next poll.

Designed for the Claude Code background-task pattern: run `mesh watch` as a
background task; it blocks until a ping arrives, then exits — which re-invokes
the session that launched it. Push delivery with zero infrastructure.

Stdlib only. Works on Linux, macOS, Windows (Python 3.8+).
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_NAME = ".meshwire.json"
NODE_NAME = ".meshwire.node"
TASKS_NAME = ".meshwire.tasks.json"
PEERS_NAME = ".meshwire.peers.json"
BROADCAST = "all"
USER_AGENT = "meshwire/0.3"
MAX_ATTACHMENT = 512 * 1024  # bytes we're willing to fetch for a wrapped body
TERMINAL_STATES = {"completed", "failed", "canceled", "rejected"}


# ---------------------------------------------------------------- config

def find_config(start=None):
    """Walk up from `start` (default cwd) looking for .meshwire.json."""
    d = os.path.abspath(start or os.getcwd())
    while True:
        p = os.path.join(d, CONFIG_NAME)
        if os.path.isfile(p):
            return p
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def load_config():
    p = find_config()
    if not p:
        sys.exit(f"error: no {CONFIG_NAME} found here or in any parent "
                 f"directory. Run `mesh init` first.")
    with open(p, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["_path"] = p
    cfg["_dir"] = os.path.dirname(p)
    return cfg


def node_file(cfg):
    return os.path.join(cfg["_dir"], NODE_NAME)


def my_node(cfg, override=None):
    """Resolve this machine's node name: --as flag > env > .meshwire.node."""
    name = override or os.environ.get("MESHWIRE_NODE")
    if not name and os.path.isfile(node_file(cfg)):
        with open(node_file(cfg), "r", encoding="utf-8") as f:
            name = f.read().strip()
    if not name:
        sys.exit("error: this machine has no node identity. Run "
                 "`mesh iam <node>` (or pass --as / set MESHWIRE_NODE).")
    if name not in cfg["nodes"]:
        sys.exit(f"error: node '{name}' is not in the mesh {cfg['nodes']}. "
                 f"Run `mesh iam <node>` with a listed node, or edit "
                 f"{CONFIG_NAME}.")
    return name


def topic(cfg, node):
    return f"mw-{cfg['mesh']}-{cfg['id']}-{node}"


def cursor_file(cfg, node):
    # per-machine, next to the config; gitignored by `mesh init`
    return os.path.join(cfg["_dir"], f".meshwire.cursor-{node}")


def _default_node_name():
    """This machine's default identity: sanitized hostname, or None."""
    name = socket.gethostname().lower()
    for suffix in (".local", ".lan"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
    name = re.sub(r"[^a-z0-9-]+", "-", name)
    name = re.sub(r"-{2,}", "-", name).strip("-")
    if not name or name == BROADCAST:
        return None
    return name


def _save_config(cfg):
    """Persist config changes wherever the config actually lives."""
    path = cfg.get("_path") or CONFIG_NAME
    with open(path, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in cfg.items() if not k.startswith("_")},
                  f, indent=2)
        f.write("\n")


def peers_file(cfg):
    return os.path.join(cfg["_dir"], PEERS_NAME)


def load_peers(cfg):
    try:
        with open(peers_file(cfg), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def note_peer(cfg, node, via):
    """Record a live sighting of `node`; learn unknown nodes into the config.

    Membership is dynamic: any authenticated message teaches us its sender.
    """
    if not node or node == BROADCAST:
        return
    if node not in cfg["nodes"]:
        cfg["nodes"].append(node)
        _save_config(cfg)
    peers = load_peers(cfg)
    peers[node] = {"seen": int(time.time()), "via": via}
    with open(peers_file(cfg), "w", encoding="utf-8") as f:
        json.dump(peers, f, indent=2)
        f.write("\n")


def _ago(ts):
    d = max(0, int(time.time()) - int(ts))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


# ---------------------------------------------------------------- crypto
#
# End-to-end encryption with only the stdlib. Standard constructions:
#   - HKDF-SHA256 (RFC 5869) derives independent enc + mac keys from the
#     mesh key (a 256-bit secret in .meshwire.json that never goes on the wire)
#   - encryption: HMAC-SHA256 as a PRF in counter mode (PRF-CTR stream
#     cipher) with a random 128-bit nonce per message
#   - authentication: encrypt-then-MAC, HMAC-SHA256 tag over nonce+ciphertext,
#     constant-time comparison
# The relay (ntfy) sees only ciphertext, topic id, size, and timing. Sender/
# recipient names travel INSIDE the encrypted payload.

WIRE_MAGIC = "mw1:"


def _hkdf(key, info, length=32):
    prk = hmac.new(b"meshwire-hkdf-salt", key, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _keys(cfg):
    key = bytes.fromhex(cfg["key"])
    return _hkdf(key, b"enc"), _hkdf(key, b"mac")


def _keystream_xor(k_enc, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 32):
        block = hmac.new(k_enc, nonce + i.to_bytes(8, "big"),
                         hashlib.sha256).digest()
        chunk = data[i:i + 32]
        out += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def encrypt(cfg, plaintext):
    k_enc, k_mac = _keys(cfg)
    nonce = secrets.token_bytes(16)
    ct = _keystream_xor(k_enc, nonce, plaintext.encode("utf-8"))
    tag = hmac.new(k_mac, nonce + ct, hashlib.sha256).digest()[:16]
    return WIRE_MAGIC + base64.b64encode(nonce + ct + tag).decode("ascii")


def decrypt(cfg, body):
    """Return plaintext, or None if not-encrypted/undecryptable."""
    if not body.startswith(WIRE_MAGIC) or not cfg.get("key"):
        return None
    try:
        raw = base64.b64decode(body[len(WIRE_MAGIC):], validate=True)
        nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
        k_enc, k_mac = _keys(cfg)
        want = hmac.new(k_mac, nonce + ct, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, want):
            return None
        return _keystream_xor(k_enc, nonce, ct).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def join_code(cfg):
    """One shareable string carrying everything a machine needs to join."""
    payload = {"mesh": cfg["mesh"], "id": cfg["id"], "key": cfg.get("key"),
               "server": cfg["server"], "nodes": cfg["nodes"]}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return "mesh1-" + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def parse_join_code(code):
    code = code.strip()
    if not code.startswith("mesh1-"):
        sys.exit("error: not a meshwire join code (expected mesh1-...)")
    b = code[len("mesh1-"):]
    b += "=" * (-len(b) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(b))
    except (ValueError, UnicodeDecodeError):
        sys.exit("error: corrupt join code")


# ---------------------------------------------------------------- http

def http(url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("User-Agent", USER_AGENT)
    return urllib.request.urlopen(req, timeout=timeout)


def _unwrap(ev, cfg):
    """ntfy wraps large bodies into attachments. Return the effective body
    text of a message event, fetching the attachment when needed."""
    att = ev.get("attachment")
    if att and att.get("url"):
        if att.get("size", 0) > MAX_ATTACHMENT:
            return ev.get("message", "")
        # only fetch from the mesh's own server, never a third-party URL
        if not att["url"].startswith(cfg["server"] + "/"):
            return ev.get("message", "")
        try:
            with http(att["url"], timeout=30) as r:
                return r.read(MAX_ATTACHMENT).decode("utf-8", "replace")
        except (urllib.error.URLError, socket.timeout):
            return ev.get("message", "")
    return ev.get("message", "")


def _open(ev, cfg):
    """Unwrap + decrypt + unpack a message event.
    Returns (sender_or_None, body_text, trusted: bool). trusted=True only for
    messages that authenticated under the mesh key."""
    body = _unwrap(ev, cfg)
    pt = decrypt(cfg, body)
    if pt is not None:
        try:
            wrapper = json.loads(pt)
            if isinstance(wrapper, dict) and "b" in wrapper:
                return wrapper.get("f"), wrapper["b"], True
        except json.JSONDecodeError:
            pass
        return None, pt, True
    if body.startswith(WIRE_MAGIC):
        return None, "", False  # encrypted but not for us / tampered
    # legacy plaintext: sender via title convention
    title = ev.get("title", "")
    frm = None
    if ": " in title and " -> " in title:
        frm = title.split(": ", 1)[1].split(" -> ", 1)[0]
    return frm, body, not cfg.get("key")


def _parse_envelope(body):
    """Return the parsed A2A JSON-RPC envelope if `body` is one, else None."""
    if not body or body[0] != "{":
        return None
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) and obj.get("jsonrpc") == "2.0" else None


# ---------------------------------------------------------------- a2a tasks

def tasks_file(cfg):
    return os.path.join(cfg["_dir"], TASKS_NAME)


def load_tasks(cfg):
    try:
        with open(tasks_file(cfg), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_task(cfg, task_id, **fields):
    tasks = load_tasks(cfg)
    t = tasks.setdefault(task_id, {})
    t.update(fields)
    t["updated"] = int(time.time())
    with open(tasks_file(cfg), "w", encoding="utf-8") as f:
        json.dump(tasks, f, indent=1)
    return t


def _text_of(message_or_artifact):
    return "\n".join(p.get("text", "") for p in
                     message_or_artifact.get("parts", []) if "text" in p)


def make_send_envelope(sender, to, text, task_id=None, context_id=None):
    """A2A JSON-RPC message/send request, carried over the mesh transport."""
    return {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/send",
        "params": {
            "message": {
                "kind": "message",
                "messageId": str(uuid.uuid4()),
                "taskId": task_id or str(uuid.uuid4()),
                "contextId": context_id or str(uuid.uuid4()),
                "role": "user",
                "parts": [{"kind": "text", "text": text}],
            },
            "metadata": {"mesh": {"from": sender, "to": to}},
        },
    }


def make_result_envelope(sender, to, task_id, context_id, state, text,
                         rpc_id=None):
    """A2A JSON-RPC response carrying a Task with a status update/result."""
    task = {
        "kind": "task",
        "id": task_id,
        "contextId": context_id,
        "status": {
            "state": state,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
        "metadata": {"mesh": {"from": sender, "to": to}},
    }
    if text:
        part = [{"kind": "text", "text": text}]
        if state in TERMINAL_STATES:
            task["artifacts"] = [{"artifactId": str(uuid.uuid4()),
                                  "name": "result", "parts": part}]
        else:
            task["status"]["message"] = {"kind": "message", "role": "agent",
                                         "messageId": str(uuid.uuid4()),
                                         "parts": part}
    return {"jsonrpc": "2.0", "id": rpc_id or str(uuid.uuid4()),
            "result": task}


def envelope_summary(env):
    """(kind, task_id, context_id, state, from_node, text) for any envelope."""
    if "method" in env:  # request: message/send
        msg = env.get("params", {}).get("message", {})
        meta = env.get("params", {}).get("metadata", {}).get("mesh", {})
        return ("request", msg.get("taskId"), msg.get("contextId"),
                "submitted", meta.get("from"), _text_of(msg))
    task = env.get("result", {})  # response: task status/result
    meta = task.get("metadata", {}).get("mesh", {})
    state = task.get("status", {}).get("state", "?")
    text = ""
    for a in task.get("artifacts", []) or []:
        text += _text_of(a)
    if not text and task.get("status", {}).get("message"):
        text = _text_of(task["status"]["message"])
    return ("result", task.get("id"), task.get("contextId"), state,
            meta.get("from"), text)


def send_raw(cfg, sender, to, body, title=None):
    url = f"{cfg['server']}/{topic(cfg, to)}"
    if cfg.get("key"):
        # metadata rides inside the ciphertext; the relay learns nothing
        # beyond topic, size, and timing
        wire = encrypt(cfg, json.dumps({"f": sender, "t": to, "b": body}))
        headers = {"Title": cfg["mesh"]}
    else:
        wire = body
        headers = {"Title": title or f"{cfg['mesh']}: {sender} -> {to}",
                   "X-Mesh-From": sender}
    with http(url, data=wire.encode("utf-8"), headers=headers) as r:
        return json.load(r)


# ---------------------------------------------------------------- commands

def cmd_init(args):
    if find_config():
        sys.exit(f"error: {CONFIG_NAME} already exists at {find_config()}")
    nodes = [n.strip() for n in args.nodes.split(",") if n.strip()]
    if len(nodes) < 2:
        sys.exit("error: need at least 2 nodes (--nodes a,b)")
    if BROADCAST in nodes:
        sys.exit(f"error: '{BROADCAST}' is reserved for broadcast")
    cfg = {
        "mesh": args.name,
        "id": secrets.token_hex(8),
        "key": secrets.token_hex(32),   # E2E encryption key, never on the wire
        "server": args.server.rstrip("/"),
        "nodes": nodes,
    }
    _write_config_here(cfg)
    print(f"mesh '{args.name}' created: nodes {nodes} (end-to-end encrypted)")
    print(f"  config: {os.path.abspath(CONFIG_NAME)}  — contains the mesh "
          f"KEY. Never commit to a public repo.")
    print(f"  join other machines with this code (share it privately —\n"
          f"  it IS the mesh secret):\n")
    print(f"    mesh join {join_code(cfg)} --as <node>\n")
    print(f"  then here: `mesh iam <node>`, and `mesh watch` / `mesh send`.")


def _write_config_here(cfg):
    with open(CONFIG_NAME, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in cfg.items() if not k.startswith("_")},
                  f, indent=2)
        f.write("\n")
    # keep secrets and per-machine files out of version control
    gi_lines = [CONFIG_NAME, NODE_NAME, ".meshwire.cursor-*", TASKS_NAME,
                PEERS_NAME]
    existing = ""
    if os.path.isfile(".gitignore"):
        with open(".gitignore", "r", encoding="utf-8") as f:
            existing = f.read()
    add = [l for l in gi_lines if l not in existing.splitlines()]
    if add:
        with open(".gitignore", "a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write("\n".join(add) + "\n")


def cmd_join(args):
    if find_config():
        sys.exit(f"error: {CONFIG_NAME} already exists at {find_config()}")
    cfg = parse_join_code(args.code)
    for field in ("mesh", "id", "server", "nodes"):
        if not cfg.get(field):
            sys.exit(f"error: join code missing '{field}'")
    _write_config_here(cfg)
    print(f"joined mesh '{cfg['mesh']}' "
          f"({'end-to-end encrypted' if cfg.get('key') else 'PLAINTEXT'}); "
          f"nodes: {cfg['nodes']}")
    if args.as_node:
        with open(NODE_NAME, "w", encoding="utf-8") as f:
            f.write(args.as_node + "\n")
        if args.as_node not in cfg["nodes"]:
            cfg["nodes"].append(args.as_node)
            _write_config_here(cfg)
            print(f"  note: added new node '{args.as_node}' locally — other "
                  f"machines can message it by name regardless.")
        print(f"  this machine is '{args.as_node}'. Try: mesh send all "
              f"\"{args.as_node} online\"")
    else:
        print("  next: mesh iam <node>")


def cmd_invite(args):
    cfg = load_config()
    print("share this join code PRIVATELY (it is the mesh secret):\n")
    print(f"  mesh join {join_code(cfg)} --as <node>")


def cmd_iam(args):
    cfg = load_config()
    if args.node not in cfg["nodes"]:
        sys.exit(f"error: '{args.node}' not in mesh nodes {cfg['nodes']}")
    with open(node_file(cfg), "w", encoding="utf-8") as f:
        f.write(args.node + "\n")
    print(f"this machine is now '{args.node}' in mesh '{cfg['mesh']}'")


def cmd_send(args):
    cfg = load_config()
    sender = my_node(cfg, args.as_node)
    to = args.to
    if to != BROADCAST and to not in cfg["nodes"]:
        sys.exit(f"error: unknown recipient '{to}' (nodes: {cfg['nodes']} "
                 f"or '{BROADCAST}')")
    if to == sender:
        sys.exit("error: refusing to send to self")
    msg = " ".join(args.message)
    try:
        resp = send_raw(cfg, sender, to, msg)
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    enc = " [e2e]" if cfg.get("key") else ""
    print(f"sent to {to} (id {resp.get('id', '?')}){enc}: {msg}")


def _stream_once(cfg, tpc, since, deadline, skip=()):
    """Long-poll topic(s) until a message not in `skip` arrives or deadline
    passes. Returns the message dict, or None on timeout."""
    while time.time() < deadline:
        chunk = min(300, max(5, int(deadline - time.time())))
        url = f"{cfg['server']}/{tpc}/json?since={since}"
        try:
            with http(url, timeout=chunk) as r:
                for raw in r:
                    try:
                        ev = json.loads(raw.decode("utf-8"))
                    except json.JSONDecodeError:
                        continue
                    if (ev.get("event") == "message"
                            and ev.get("id") not in skip):
                        return ev
                    if time.time() >= deadline:
                        return None
        except (urllib.error.URLError, socket.timeout, TimeoutError):
            pass  # chunk expired or connection dropped — reconnect
    return None


def _load_cursor(cf):
    try:
        with open(cf, "r", encoding="utf-8") as f:
            c = json.load(f)
        return int(c["since"]), c.get("seen", [])
    except (OSError, ValueError, KeyError):
        # fresh cursor: include a small grace window so a ping sent moments
        # before the first watch isn't silently skipped
        return int(time.time()) - 5, []


def cmd_watch(args):
    cfg = load_config()
    me = my_node(cfg, args.as_node)
    # subscribe to own inbox AND the broadcast topic in one stream
    tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
    cf = cursor_file(cfg, me)
    since, seen = _load_cursor(cf)
    deadline = time.time() + args.timeout
    skip = set(seen)
    while True:
        ev = _stream_once(cfg, tpc, str(since), deadline, skip=skip)
        if ev is None:
            print(f"MESH_TIMEOUT: no message for '{me}' in {args.timeout}s")
            sys.exit(0)
        frm, body, trusted = _open(ev, cfg)
        env = _parse_envelope(body) if trusted else None
        if trusted and frm != me:
            break  # a real message from someone else
        # own echo, unauthenticated, or undecryptable — skip, keep waiting
        skip.add(ev.get("id"))
        t = int(ev.get("time", time.time()))
        seen = ([i for i in seen if i] if t == since else []) + [ev.get("id")]
        since = t
        with open(cf, "w", encoding="utf-8") as f:
            json.dump({"since": t, "seen": seen[-50:]}, f)
        if not trusted and body != "":
            print(f"MESH_WARN: dropped unauthenticated message "
                  f"id={ev.get('id')}", file=sys.stderr)
    # cursor: resume from this message's second; remember ids seen in that
    # second so re-delivery on the boundary is filtered, not re-consumed
    t = int(ev.get("time", time.time()))
    seen = ([i for i in seen if i] if t == since else []) + [ev.get("id")]
    with open(cf, "w", encoding="utf-8") as f:
        json.dump({"since": t, "seen": seen[-50:]}, f)
    if env:
        kind, task_id, ctx, state, efrm, text = envelope_summary(env)
        frm = efrm or frm
        save_task(cfg, task_id, contextId=ctx, state=state,
                  peer=frm, direction="inbound", text=text,
                  rpcId=env.get("id"))
        if kind == "request":
            print(f"MESH_TASK from={frm} task={task_id} state=submitted: "
                  f"{text}")
            print(f"  -> to answer: mesh reply {task_id} --state completed "
                  f"\"<result>\"")
        else:
            print(f"MESH_TASK_UPDATE from={frm} task={task_id} "
                  f"state={state}: {text}")
        print(json.dumps(env))
        return
    print(f"MESH_MESSAGE from={frm!r} to={me}: {body}")
    print(json.dumps({"from": frm, "message": body, "id": ev.get("id"),
                      "time": ev.get("time")}))


def cmd_peek(args):
    cfg = load_config()
    node = args.node or my_node(cfg, args.as_node)
    url = f"{cfg['server']}/{topic(cfg, node)}/json?poll=1&since={args.since}"
    try:
        with http(url, timeout=15) as r:
            body = r.read().decode("utf-8")
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: peek failed: {e}")
    msgs = [json.loads(l) for l in body.splitlines() if l.strip()]
    msgs = [m for m in msgs if m.get("event") == "message"]
    if not msgs:
        print(f"(no messages for '{node}' since {args.since})")
    for m in msgs:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["time"]))
        frm, text, trusted = _open(m, cfg)
        mark = "" if trusted else " [UNVERIFIED]"
        print(f"[{ts}] {frm or m.get('title', '')}{mark}: {text}")


def cmd_status(args):
    cfg = load_config()
    me = None
    try:
        me = my_node(cfg, args.as_node)
    except SystemExit:
        pass
    print(f"mesh:   {cfg['mesh']}")
    print(f"server: {cfg['server']}")
    print(f"nodes:  {', '.join(cfg['nodes'])}")
    print(f"me:     {me or '(unset — run `mesh iam <node>`)'}")
    print(f"config: {cfg['_path']}")
    if me:
        print(f"topic:  {topic(cfg, me)}")


def _await_result(cfg, me, task_id, timeout):
    """Long-poll own inbox for a result envelope matching task_id, using an
    ephemeral cursor (does not disturb `mesh watch`'s cursor)."""
    tpc = f"{topic(cfg, me)},{topic(cfg, BROADCAST)}"
    since = str(int(time.time()) - 5)
    deadline = time.time() + timeout
    skip = set()
    while time.time() < deadline:
        ev = _stream_once(cfg, tpc, since, deadline, skip=skip)
        if ev is None:
            return None
        skip.add(ev.get("id"))
        _, body, trusted = _open(ev, cfg)
        env = _parse_envelope(body) if trusted else None
        if not env:
            continue
        kind, tid, ctx, state, frm, text = envelope_summary(env)
        if tid == task_id and kind == "result":
            save_task(cfg, tid, contextId=ctx, state=state, peer=frm,
                      direction="outbound", result=text)
            return env
    return None


def cmd_ask(args):
    cfg = load_config()
    me = my_node(cfg, args.as_node)
    to = args.to
    if to not in cfg["nodes"] or to == me:
        sys.exit(f"error: recipient must be another node in {cfg['nodes']}")
    text = " ".join(args.text)
    env = make_send_envelope(me, to, text)
    task_id = env["params"]["message"]["taskId"]
    ctx = env["params"]["message"]["contextId"]
    try:
        send_raw(cfg, me, to, json.dumps(env),
                 title=f"{cfg['mesh']}: a2a {me} -> {to}")
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    save_task(cfg, task_id, contextId=ctx, state="submitted", peer=to,
              direction="outbound", text=text)
    print(f"task {task_id} -> {to}: {text}")
    if not args.wait:
        print(f"  check later: mesh tasks get {task_id}")
        return
    print(f"  waiting up to {args.wait}s for a reply...")
    result = _await_result(cfg, me, task_id, args.wait)
    if result is None:
        print(f"MESH_TASK_PENDING task={task_id} (no reply yet — "
              f"`mesh tasks get {task_id}` later)")
        return
    _, _, _, state, frm, text = envelope_summary(result)
    print(f"MESH_TASK_RESULT from={frm} task={task_id} state={state}:")
    print(text)


def cmd_reply(args):
    cfg = load_config()
    me = my_node(cfg, args.as_node)
    tasks = load_tasks(cfg)
    t = tasks.get(args.task_id)
    if not t:
        sys.exit(f"error: unknown task {args.task_id} (see `mesh tasks`)")
    to = args.to or t.get("peer")
    if not to:
        sys.exit("error: task has no peer recorded; pass --to <node>")
    text = " ".join(args.text)
    env = make_result_envelope(me, to, args.task_id, t.get("contextId"),
                               args.state, text, rpc_id=t.get("rpcId"))
    try:
        send_raw(cfg, me, to, json.dumps(env),
                 title=f"{cfg['mesh']}: a2a {me} -> {to}")
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    save_task(cfg, args.task_id, state=args.state, result=text)
    print(f"task {args.task_id} -> {to}: {args.state}")


def cmd_tasks(args):
    cfg = load_config()
    tasks = load_tasks(cfg)
    if args.action == "get":
        t = tasks.get(args.task_id)
        if not t:
            sys.exit(f"error: unknown task {args.task_id}")
        print(json.dumps({args.task_id: t}, indent=2))
        return
    if not tasks:
        print("(no tasks)")
        return
    for tid, t in sorted(tasks.items(), key=lambda kv: kv[1].get("updated", 0)):
        ts = time.strftime("%m-%d %H:%M", time.localtime(t.get("updated", 0)))
        arrow = "->" if t.get("direction") == "outbound" else "<-"
        print(f"[{ts}] {tid[:8]} {arrow} {t.get('peer', '?'):<10} "
              f"{t.get('state', '?'):<10} {t.get('text', '')[:60]}")


def agent_card(cfg, node, base_url=None):
    cards = cfg.get("cards", {})
    c = cards.get(node, {})
    return {
        "protocolVersion": "0.3.0",
        "name": c.get("name", f"{cfg['mesh']}/{node}"),
        "description": c.get(
            "description",
            f"Agent node '{node}' in meshwire '{cfg['mesh']}', reachable "
            f"over the mesh transport (ntfy relay)."),
        "url": base_url or f"mesh://{cfg['mesh']}/{node}",
        "version": c.get("version", "0.2.0"),
        "capabilities": {"streaming": False, "pushNotifications": True},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": c.get("skills", [{
            "id": "general",
            "name": "General agent",
            "description": c.get("description", "Ask it anything it can do "
                                 "on its machine."),
            "tags": ["general"],
        }]),
    }


def cmd_card(args):
    cfg = load_config()
    node = args.node or my_node(cfg, None)
    if args.description or args.name:
        cards = cfg.setdefault("cards", {})
        c = cards.setdefault(node, {})
        if args.name:
            c["name"] = args.name
        if args.description:
            c["description"] = args.description
        cfg_out = {k: v for k, v in cfg.items() if not k.startswith("_")}
        with open(cfg["_path"], "w", encoding="utf-8") as f:
            json.dump(cfg_out, f, indent=2)
            f.write("\n")
    print(json.dumps(agent_card(cfg, node), indent=2))


# ---------------------------------------------------------------- a2a bridge

class _BridgeHandler(BaseHTTPRequestHandler):
    """Localhost HTTP server speaking standard A2A JSON-RPC, bridging to
    remote mesh nodes over the ntfy transport. Lets any A2A-capable framework
    on this machine talk to agents on other machines with no open ports."""
    cfg = None
    me = None
    wait = 60

    def _json(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        sys.stderr.write("a2a-bridge: " + fmt % a + "\n")

    def do_GET(self):
        cfg, me = self.cfg, self.me
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        peers = [n for n in cfg["nodes"] if n != me]
        if parts == [".well-known", "agent-card.json"]:
            # the bridge itself presents the mesh as a directory agent
            card = agent_card(cfg, me, f"http://{self.server.server_address[0]}"
                                       f":{self.server.server_address[1]}/")
            card["description"] = (f"meshwire bridge on node '{me}'. "
                                   f"Remote agents: " + ", ".join(
                                       f"/agents/{n}" for n in peers))
            return self._json(200, card)
        if parts == ["agents"]:
            return self._json(200, {"agents": peers})
        if (len(parts) == 4 and parts[0] == "agents"
                and parts[2:] == [".well-known", "agent-card.json"]
                and parts[1] in peers):
            base = (f"http://{self.server.server_address[0]}"
                    f":{self.server.server_address[1]}/agents/{parts[1]}")
            return self._json(200, agent_card(cfg, parts[1], base))
        self._json(404, {"error": "not found"})

    def do_POST(self):
        cfg, me = self.cfg, self.me
        parts = [p for p in self.path.split("?")[0].split("/") if p]
        if len(parts) != 2 or parts[0] != "agents" \
                or parts[1] not in cfg["nodes"] or parts[1] == me:
            return self._json(404, {"error": "POST to /agents/<node>"})
        node = parts[1]
        try:
            length = int(self.headers.get("Content-Length", 0))
            rpc = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, KeyError):
            return self._json(400, {"jsonrpc": "2.0", "id": None, "error":
                                    {"code": -32700, "message": "parse error"}})
        method = rpc.get("method")
        if method == "tasks/get":
            tid = rpc.get("params", {}).get("id")
            t = load_tasks(cfg).get(tid)
            if not t:
                return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                        "error": {"code": -32001,
                                                  "message": "task not found"}})
            task = {"kind": "task", "id": tid, "contextId": t.get("contextId"),
                    "status": {"state": t.get("state", "submitted")}}
            if t.get("result"):
                task["artifacts"] = [{"artifactId": "r", "name": "result",
                                      "parts": [{"kind": "text",
                                                 "text": t["result"]}]}]
            return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                    "result": task})
        if method != "message/send":
            return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                    "error": {"code": -32601,
                                              "message": "method not found"}})
        msg = rpc.get("params", {}).get("message", {})
        text = _text_of(msg)
        env = make_send_envelope(me, node, text,
                                 task_id=msg.get("taskId"),
                                 context_id=msg.get("contextId"))
        task_id = env["params"]["message"]["taskId"]
        ctx = env["params"]["message"]["contextId"]
        try:
            send_raw(cfg, me, node, json.dumps(env),
                     title=f"{cfg['mesh']}: a2a {me} -> {node}")
        except (urllib.error.URLError, socket.timeout) as e:
            return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                    "error": {"code": -32003,
                                              "message": f"relay failed: {e}"}})
        save_task(cfg, task_id, contextId=ctx, state="submitted", peer=node,
                  direction="outbound", text=text)
        result = _await_result(cfg, me, task_id, self.wait)
        if result is not None:
            return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                    "result": result["result"]})
        # A2A allows returning a non-terminal Task; client polls tasks/get
        return self._json(200, {"jsonrpc": "2.0", "id": rpc.get("id"),
                                "result": {"kind": "task", "id": task_id,
                                           "contextId": ctx,
                                           "status": {"state": "submitted"}}})


def cmd_a2a_serve(args):
    cfg = load_config()
    me = my_node(cfg, args.as_node)
    _BridgeHandler.cfg = cfg
    _BridgeHandler.me = me
    _BridgeHandler.wait = args.wait
    srv = ThreadingHTTPServer((args.host, args.port), _BridgeHandler)
    peers = [n for n in cfg["nodes"] if n != me]
    print(f"a2a bridge for mesh '{cfg['mesh']}' as node '{me}' on "
          f"http://{args.host}:{args.port}")
    print(f"  agent card:    /.well-known/agent-card.json")
    for n in peers:
        print(f"  remote agent:  /agents/{n}  "
              f"(card: /agents/{n}/.well-known/agent-card.json)")
    print(f"  JSON-RPC POST message/send | tasks/get to /agents/<node>; "
          f"blocking wait {args.wait}s")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


CLAUDE_SNIPPET = """\
## Cross-machine agent comms (meshwire)

This project uses meshwire (https://github.com/husker/meshwire) to link
agent sessions on different machines. Protocol:

1. Substantive content (results, requests, code) travels via the shared repo:
   commit + push, addressed in commit messages or a designated doc.
2. After pushing something the other machine should act on, ping it:
   `python3 mesh.py send <node|all> "one-line summary — pull"`.
3. To receive pings instantly, keep `python3 mesh.py watch` running as a
   BACKGROUND task. When it exits with MESH_MESSAGE, pull the repo, read what
   changed, act on it, and re-arm the watcher (run `mesh watch` in the
   background again).
4. Never put secrets or real content in a ping — topics are capability URLs
   on a public ntfy server. Pings say "look", the repo says "what".

This machine's identity: see `.meshwire.node` (set with `mesh iam <node>`).
"""


def cmd_claude_setup(args):
    print(CLAUDE_SNIPPET, end="")


def main():
    ap = argparse.ArgumentParser(
        prog="mesh",
        description="Zero-infrastructure messaging between AI agent sessions "
                    "on different machines (ntfy.sh wake pings + your shared "
                    "repo as the payload channel).")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a mesh in the current directory")
    p.add_argument("name", help="short mesh name (letters/digits/dashes)")
    p.add_argument("--nodes", required=True,
                   help="comma-separated node names, e.g. laptop,desktop")
    p.add_argument("--server", default="https://ntfy.sh",
                   help="ntfy server (default: https://ntfy.sh; self-host "
                        "for private traffic)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("join", help="join an existing mesh from a join code")
    p.add_argument("code", help="mesh1-... code from `mesh init`/`mesh invite`")
    p.add_argument("--as", dest="as_node", default=None,
                   help="claim this node name immediately")
    p.set_defaults(fn=cmd_join)

    p = sub.add_parser("invite", help="print this mesh's join code")
    p.set_defaults(fn=cmd_invite)

    p = sub.add_parser("iam", help="set this machine's node identity")
    p.add_argument("node")
    p.set_defaults(fn=cmd_iam)

    p = sub.add_parser("send", help="ping another node (or 'all')")
    p.add_argument("to")
    p.add_argument("message", nargs="+")
    p.add_argument("--as", dest="as_node", default=None,
                   help="override sender identity")
    p.set_defaults(fn=cmd_send)

    p = sub.add_parser("watch",
                       help="block until a ping arrives for this node, print "
                            "it, exit (run as a background task)")
    p.add_argument("--timeout", type=int, default=10800,
                   help="max seconds to wait (default 10800 = 3h)")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_watch)

    p = sub.add_parser("peek", help="show recent pings without consuming "
                                    "the cursor")
    p.add_argument("node", nargs="?", default=None,
                   help="node whose inbox to view (default: mine)")
    p.add_argument("--since", default="all",
                   help="ntfy since spec (default: all)")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_peek)

    p = sub.add_parser("status", help="show mesh config and this node")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("ask", help="send an A2A task to another node")
    p.add_argument("to")
    p.add_argument("text", nargs="+")
    p.add_argument("--wait", type=int, default=0, metavar="SECS",
                   help="block up to SECS for the reply (0 = fire and forget)")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("reply", help="answer a received A2A task")
    p.add_argument("task_id")
    p.add_argument("text", nargs="+")
    p.add_argument("--state", default="completed",
                   choices=sorted(TERMINAL_STATES | {"working",
                                                     "input-required"}))
    p.add_argument("--to", default=None, help="override recipient node")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_reply)

    p = sub.add_parser("tasks", help="list or inspect A2A tasks")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "get"])
    p.add_argument("task_id", nargs="?", default=None)
    p.set_defaults(fn=cmd_tasks)

    p = sub.add_parser("card", help="show (or set) a node's A2A agent card")
    p.add_argument("node", nargs="?", default=None)
    p.add_argument("--name", default=None)
    p.add_argument("--description", default=None)
    p.set_defaults(fn=cmd_card)

    p = sub.add_parser("a2a-serve",
                       help="run a localhost A2A HTTP bridge so standard "
                            "A2A clients can reach remote mesh nodes")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4737)
    p.add_argument("--wait", type=int, default=60,
                   help="seconds message/send blocks for a reply before "
                        "returning a pending task (default 60)")
    p.add_argument("--as", dest="as_node", default=None)
    p.set_defaults(fn=cmd_a2a_serve)

    p = sub.add_parser("claude-setup",
                       help="print a CLAUDE.md section teaching an agent "
                            "session the protocol")
    p.set_defaults(fn=cmd_claude_setup)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

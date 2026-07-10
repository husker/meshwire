#!/usr/bin/env python3
"""claude-mesh: zero-infrastructure messaging between AI agent sessions on
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
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request

CONFIG_NAME = ".claude-mesh.json"
NODE_NAME = ".claude-mesh.node"
BROADCAST = "all"
USER_AGENT = "claude-mesh/0.1"


# ---------------------------------------------------------------- config

def find_config(start=None):
    """Walk up from `start` (default cwd) looking for .claude-mesh.json."""
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
    """Resolve this machine's node name: --as flag > env > .claude-mesh.node."""
    name = override or os.environ.get("CLAUDE_MESH_NODE")
    if not name and os.path.isfile(node_file(cfg)):
        with open(node_file(cfg), "r", encoding="utf-8") as f:
            name = f.read().strip()
    if not name:
        sys.exit("error: this machine has no node identity. Run "
                 "`mesh iam <node>` (or pass --as / set CLAUDE_MESH_NODE).")
    if name not in cfg["nodes"]:
        sys.exit(f"error: node '{name}' is not in the mesh {cfg['nodes']}. "
                 f"Run `mesh iam <node>` with a listed node, or edit "
                 f"{CONFIG_NAME}.")
    return name


def topic(cfg, node):
    return f"cmesh-{cfg['mesh']}-{cfg['id']}-{node}"


def cursor_file(cfg, node):
    # per-machine, next to the config; gitignored by `mesh init`
    return os.path.join(cfg["_dir"], f".claude-mesh.cursor-{node}")


# ---------------------------------------------------------------- http

def http(url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    req.add_header("User-Agent", USER_AGENT)
    return urllib.request.urlopen(req, timeout=timeout)


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
        "server": args.server.rstrip("/"),
        "nodes": nodes,
    }
    with open(CONFIG_NAME, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    # keep per-machine files out of version control
    gi_lines = [NODE_NAME, ".claude-mesh.cursor-*"]
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
    print(f"mesh '{args.name}' created: nodes {nodes}")
    print(f"  config: {os.path.abspath(CONFIG_NAME)}  (commit this if the "
          f"repo is PRIVATE; the id is a capability — anyone who has it can "
          f"read/post pings)")
    print(f"  next: `mesh iam <node>` on each machine, then `mesh watch` / "
          f"`mesh send`.")


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
    url = f"{cfg['server']}/{topic(cfg, to)}"
    headers = {"Title": f"{cfg['mesh']}: {sender} -> {to}",
               "X-Mesh-From": sender}
    try:
        with http(url, data=msg.encode("utf-8"), headers=headers) as r:
            resp = json.load(r)
    except (urllib.error.URLError, socket.timeout) as e:
        sys.exit(f"error: send failed: {e}")
    print(f"sent to {to} (id {resp.get('id', '?')}): {msg}")


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
    ev = _stream_once(cfg, tpc, str(since), deadline, skip=set(seen))
    if ev is None:
        print(f"MESH_TIMEOUT: no message for '{me}' in {args.timeout}s")
        sys.exit(0)
    # cursor: resume from this message's second; remember ids seen in that
    # second so re-delivery on the boundary is filtered, not re-consumed
    t = int(ev.get("time", time.time()))
    seen = ([i for i in seen if i] if t == since else []) + [ev.get("id")]
    with open(cf, "w", encoding="utf-8") as f:
        json.dump({"since": t, "seen": seen[-50:]}, f)
    sender = ev.get("title", "")
    print(f"MESH_MESSAGE from={sender!r} to={me}: {ev.get('message', '')}")
    print(json.dumps(ev))


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
        print(f"[{ts}] {m.get('title', '')}: {m.get('message', '')}")


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


CLAUDE_SNIPPET = """\
## Cross-machine agent comms (claude-mesh)

This project uses claude-mesh (https://github.com/husker/claude-mesh) to link
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

This machine's identity: see `.claude-mesh.node` (set with `mesh iam <node>`).
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

    p = sub.add_parser("claude-setup",
                       help="print a CLAUDE.md section teaching an agent "
                            "session the protocol")
    p.set_defaults(fn=cmd_claude_setup)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()

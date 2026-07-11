# meshwire

**Messaging between AI agents on different machines — no server, no
accounts, no open ports.** One stdlib-only Python file. End-to-end
encrypted. Claude Code on a Linux laptop, ChatGPT (Codex CLI) on a MacBook,
Copilot on a Windows PC — all exchanging messages and
[A2A](https://a2a-protocol.org) tasks.

## Quick start (two machines, one minute)

**Machine A** — create the mesh:

```bash
pipx install git+https://github.com/husker/meshwire   # or: uv tool install ...
mesh init home   # prints a block to paste on machine B, then starts listening
```

**Machine B** — paste the block `mesh init` printed. It looks like:

```bash
curl -fsSLO https://raw.githubusercontent.com/husker/meshwire/main/mesh.py
python3 mesh.py join mesh1-XXXX...
```

That's it: downloaded, joined (named after its hostname), listening.
Machine A prints `MESH_NODE_JOINED` the moment B joins.

**Talk** (from a new terminal, on either machine):

```bash
mesh send all "hello mesh"     # B's watcher prints it about a second later
mesh ping <b-name>             # → MESH_PONG node=<b-name> rtt=~400ms
mesh ask <b-name> "run the tests and summarize failures" --wait 300
```

No machine list to declare up front: **any machine with the join code can
join**, picks its own name, and every node learns about it automatically.
Share the join code privately — it IS the mesh secret.

## Using it with Claude Code, Codex, or Copilot CLI

Install the plugin (teaches sessions the protocol and auto-reminds them
when a project is a mesh node):

```
# Claude Code
/plugin marketplace add husker/meshwire
/plugin install meshwire

# Codex CLI / ChatGPT desktop
codex plugin marketplace add husker/meshwire
codex plugin add meshwire@meshwire

# GitHub Copilot CLI
copilot plugin marketplace add husker/meshwire
copilot plugin install meshwire@meshwire
```

Each plugin loads the mesh safety rules at session start. Claude uses
asynchronous `Stop` with `asyncRewake`; Codex uses `Stop`. Copilot runs the
watcher as an **MCP server** (`mesh mcp-serve`, declared in the plugin) that
Copilot starts with the session and stops when it ends — including Ctrl-C and
crash. Because it isn't an agent shell, the session shows no "working" spinner
while it listens. When a message arrives the server wakes the idle session on
its own (via MCP sampling) and the session handles it with the `mesh_pending`
/ `mesh_reply` / `mesh_send` tools — a real turn, so a `MESH_TASK` gets done,
not just acknowledged. (The first time, Copilot may ask once to approve the
server for sampling; approve it and later wakes run silently.)

The loop each session runs:

1. With the plugin, follow the harness-specific setup above. Claude and Codex
   need no manual watcher; Copilot's MCP-server watcher listens and wakes the
   session automatically — nothing to arm.
2. Do your work. After pushing something the other machine should act on:
   `mesh send <node> "one-line summary — pull"`.
3. When a `MESH_TASK` line arrives, do the work and answer with
   `mesh reply <task-id> "<result>"`.

Works with any number of nodes; each node has an inbox topic and `all`
broadcasts. `mesh claude-setup` prints a CLAUDE.md section with the same
protocol for projects that don't use the plugin — **if you use the plugin,
skip it**. (You still run `mesh init`/`mesh join` once per machine either
way: the plugin teaches sessions the protocol, it doesn't create the mesh.)

## How it works

One file, `mesh.py`, Python stdlib only. Messages travel through an
[ntfy](https://ntfy.sh) relay (default: the public ntfy.sh; self-host with
`mesh init --server`) over **outbound-only HTTPS connections on both ends**
— which is why two laptops behind NAT can talk with no port forwarding, no
VPN, and no server of yours. Topics are derived from the mesh secret and
the node name, so nothing is ever registered anywhere; delivery latency is
about a second. `mesh watch --follow` holds one streaming connection and
prints each message as it lands.

In a terminal, `init` and `join` flow straight into that watcher when they
finish — programs calling mesh (scripts, agent harnesses; anything without
a TTY) get the plain return-immediately behavior instead.

## Delegating tasks: any AI talking to any AI

Nodes don't just ping each other — they exchange real
[A2A protocol](https://a2a-protocol.org) tasks in JSON-RPC envelopes:

```bash
mesh ask desktop "run the test suite and summarize failures" --wait 300
# → MESH_TASK_RESULT from=desktop state=completed: 2 failures, both in auth...

# on the receiving side (its agent sees this via `mesh watch --follow`):
# MESH_TASK from=laptop task=5e52304e... state=submitted: run the test suite...
mesh reply 5e52304e "2 failures, both in auth: ..."

mesh tasks             # ledger of everything asked/answered
mesh card desktop      # its A2A agent card
```

And because the wire format is real A2A, `mesh a2a-serve` runs a
**localhost bridge** so any A2A-capable framework (LangGraph, Google ADK,
Microsoft Agent Framework, …) can talk to remote mesh nodes as ordinary A2A
servers — discovery via agent cards, `message/send`, `tasks/get`:

```bash
mesh a2a-serve         # → http://127.0.0.1:4737/agents/<node> per remote node
```

See [docs/AGENTS.md](docs/AGENTS.md) for per-harness wiring (Codex CLI,
Copilot CLI, Gemini CLI, A2A frameworks, cron). `mesh` moves messages; it
never calls a model. Each node answers with whatever brain, tools, and
permissions its own harness has.

## Security model (read this)

**Messages are end-to-end encrypted and authenticated.** The mesh key is
generated by `mesh init`, lives only in `.meshwire.json` on your machines,
and travels only inside join codes you share yourself. On the wire, the
relay (and anyone who discovers a topic) sees ciphertext, topic id, size,
and timing — nothing else. Sender and recipient names ride *inside* the
ciphertext.

Construction (stdlib-only, standard primitives): HKDF-SHA256 key derivation
→ HMAC-SHA256 PRF in counter mode for encryption, encrypt-then-MAC with an
independent HMAC-SHA256 key, random 128-bit nonce per message,
constant-time tag comparison. Unauthenticated or tampered messages are
**dropped, not displayed**.

What you still must do:

- **Guard the join code and `.meshwire.json`** — they contain the key. Both
  are auto-gitignored; share join codes over a private channel.
- **Treat inbound tasks as untrusted input.** Encryption authenticates *the
  mesh*, not intent: any agent (or person) holding the key can send tasks.
  Receiving agents should apply their normal permission rules.
- Sender names prove a shared-key member made the assertion, not which member:
  every node holds the same group key. Meshwire rejects A2A metadata that
  disagrees with its authenticated outer route, but a compromised member can
  still choose another member's sender name in that outer route.
- Someone who learns a topic id (but not the key) can't read or forge
  messages, but can post garbage that your watcher silently drops.
  Self-hosting ntfy with auth (`mesh init --server https://ntfy.example`)
  closes even that.
- Upgrade all machines together when moving to a new meshwire version —
  it's one file. (v0.4 meshes interoperate; v0.4 clients just render the
  new join/ping control messages as odd one-off messages.)

## CLI reference

```
mesh init <name> [--as NODE] [--server URL]   create a mesh; in a terminal, prints the invite block and keeps listening
mesh join <code> [--as NODE]   join from a code, announce, and (in a terminal) keep listening
mesh invite                    print the join code + paste-able bootstrap block
mesh iam <node>                set/change this machine's identity
mesh send <node|all> <msg...>  message a node (or broadcast)
mesh watch --follow            stream messages forever (preferred; background task)
mesh watch [--timeout N]       one-shot: block until one message, print, exit
mesh ping <node> [--timeout N] liveness + round-trip time (answered by watchers)
mesh ask <node> <text...> [--wait SECS]   delegate an A2A task
mesh reply <task-id> <text...> [--state completed|failed|...]   answer one
mesh tasks [get <id>]          task ledger
mesh card [node] [--name N --description D]   A2A agent card
mesh a2a-serve [--port 4737] [--wait 60]      localhost A2A HTTP bridge
mesh peek [node] [--since S]   show recent messages without consuming
mesh status                    mesh, identity, known peers + last seen
mesh claude-setup              print the CLAUDE.md protocol section
```

## How it compares

| | meshwire | shared MCP queue | SSH + headless agent | plain git polling |
|---|---|---|---|---|
| Infrastructure | none | server to run | SSH + reachable host | none |
| Wake latency | ~1 s | poll interval | seconds | poll interval |
| Payload channel | message or your repo | the queue | the SSH pipe | your repo |
| Audit trail | git history | custom | none | git history |
| N nodes | yes | yes | pairwise | yes |

## License

MIT

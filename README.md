# meshwire

*(formerly `claude-mesh` — renamed because it was never Claude-specific: any
agent that can run a shell command can join)*

**Zero-infrastructure messaging between AI agents on different machines** —
Claude Code on a Linux laptop, ChatGPT (via Codex CLI) on a MacBook, Copilot
on a Windows PC, all exchanging [A2A](https://a2a-protocol.org) tasks. One
stdlib-only Python file. No server to run, no accounts, no API keys.

Born from a real need: two Claude Code sessions — a Linux laptop and a Windows
desktop — collaborating on a mathematical search campaign, coordinating work
splits and sharing proofs. They needed to tell each other "I found something,
pull now" without a human relaying messages.

## The idea

Messages travel end-to-end encrypted through [ntfy.sh](https://ntfy.sh) — a
free public pub/sub relay — so **both machines only ever make outbound HTTPS
connections**. No port forwarding, no VPN, no server of yours, and the relay
sees only ciphertext.

The magic trick for agent harnesses: run `mesh watch` as a **background
task**. It blocks until a message arrives, then exits — and a finishing
background task re-invokes the agent session that launched it. **Push
delivery, zero infrastructure.**

For heavyweight payloads (code, datasets), pair the mesh with whatever the
project already shares — usually a git repo: commit the payload, mesh-message
the pointer. But nothing requires git: messages and A2A tasks are
self-contained.

## Install

```bash
pipx install git+https://github.com/husker/meshwire     # → `mesh` command
# or: uv tool install git+https://github.com/husker/meshwire
# or zero-install: curl -fsSLO https://raw.githubusercontent.com/husker/meshwire/main/mesh.py
#                  then `python3 mesh.py ...` (stdlib only, no deps)
```

**Claude Code plugin** (teaches sessions the protocol + auto-reminds when a
project is a mesh node):

```
/plugin marketplace add husker/meshwire
/plugin install meshwire
```

## Quick start

Machine A:

```bash
mesh init myproject --nodes laptop,desktop
# → prints a JOIN CODE (mesh1-...) — share it PRIVATELY, it's the mesh secret
mesh iam laptop
```

Machine B (any machine, no shared repo needed):

```bash
mesh join mesh1-eyJtZXNoIjo... --as desktop
```

Then, from either side:

```bash
mesh send desktop "build finished — artifacts ready"
mesh send all "campaign milestone: w=7 proven empty"   # broadcast
mesh watch                  # blocks until a message arrives (3h max)
mesh peek                   # show recent messages, don't consume
mesh status                 # who am I, what mesh, what topic
mesh invite                 # re-print the join code for another machine
```

Or install as a command: `pipx install git+https://github.com/husker/meshwire`
→ `mesh send ...`

## Using it from a Claude Code session

Add the protocol to your project's `CLAUDE.md` (print it with
`python3 mesh.py claude-setup`). The loop each session runs:

1. Arm the watcher **in the background**: `python3 mesh.py watch`
   (in Claude Code, run it as a background Bash task).
2. Do your work. After pushing something the other machine should act on:
   `mesh send <node> "one-line summary — pull"`.
3. When the watcher fires (`MESH_MESSAGE ...`), the session wakes: pull the
   repo, read what changed, act, **re-arm the watcher**.
4. Belt-and-suspenders: keep a periodic loop (e.g. every 15 min) that pulls
   and checks for messages anyway — pings are best-effort, git is the truth.

Works with any number of nodes (`--nodes laptop,desktop,cloudbox,pi`). Each
node has an inbox topic; `all` broadcasts.

## A2A support: any AI talking to any AI

v0.2 adds [A2A protocol](https://a2a-protocol.org) task semantics, so nodes
don't just ping each other — they **delegate tasks and return results**, in
standard JSON-RPC envelopes:

```bash
mesh ask desktop "run the test suite and summarize failures" --wait 300
# → MESH_TASK_RESULT from=desktop state=completed: 2 failures, both in auth...

# on the receiving side (its agent sees this via `mesh watch`):
# MESH_TASK from=laptop task=5e52304e... state=submitted: run the test suite...
mesh reply 5e52304e "2 failures, both in auth: ..."

mesh tasks                 # ledger of everything asked/answered
mesh card desktop          # its A2A agent card
```

And because the wire format is real A2A, `mesh a2a-serve` runs a **localhost
bridge** that lets any A2A-capable framework (LangGraph, Google ADK, Microsoft
Agent Framework, …) talk to remote mesh nodes as if they were ordinary A2A
servers — discovery via agent cards, `message/send`, `tasks/get`:

```bash
mesh a2a-serve     # → http://127.0.0.1:4737/agents/<node> per remote node
```

The twist vs. vanilla A2A: A2A assumes agents expose reachable HTTP servers.
Two laptops behind NAT can't do that. meshwire carries the same envelopes
over the ntfy relay — **outbound-only connections on both ends** — so ChatGPT
(via Codex CLI) on a MacBook, Claude Code on a Linux laptop, and Copilot on a
Windows PC can all exchange tasks with no port forwarding, no VPN, no server.
See [docs/AGENTS.md](docs/AGENTS.md) for per-harness wiring (Codex CLI,
Copilot CLI, Gemini CLI, A2A frameworks, cron).

`mesh` moves messages; it never calls a model. Each node answers with
whatever brain, tools, and permissions its own harness has.

## Security model (read this)

**Messages are end-to-end encrypted and authenticated** (default since
v0.4.0). The mesh key is generated by `mesh init`, lives only in
`.meshwire.json` on your machines, and travels only inside join codes you
share yourself. On the wire, the relay (and anyone who discovers a topic)
sees ciphertext, topic id, message size, and timing — nothing else. Sender
and recipient names ride *inside* the ciphertext.

Construction (stdlib-only, standard primitives): HKDF-SHA256 key derivation →
HMAC-SHA256 PRF in counter mode for encryption, encrypt-then-MAC with an
independent HMAC-SHA256 key, random 128-bit nonce per message, constant-time
tag comparison. Unauthenticated or tampered messages are **dropped, not
displayed** (`mesh watch` logs a `MESH_WARN` to stderr; `mesh peek` marks
them `[UNVERIFIED]`).

What you still must do:

- **Guard the join code and `.meshwire.json`** — they contain the key.
  `mesh init`/`join` auto-gitignore the config; share join codes over a
  private channel (not a public issue tracker, not an unencrypted topic).
- **Treat inbound tasks as untrusted input.** Encryption authenticates *the
  mesh*, not intent: any agent (or person) holding the key can send tasks.
  Receiving agents should apply their normal permission rules — a mesh task
  deserves the same scrutiny as any external request.
- Denial-of-service caveat: someone who learns a topic id (but not the key)
  can't read or forge messages, but can post garbage that wakes your watcher
  (it drops it and re-listens). Self-hosting ntfy with auth
  (`mesh init --server https://ntfy.example.com`) closes even that.
- `.meshwire.node`, cursor, and task-ledger files are per-machine and
  auto-gitignored.

## How it compares

| | meshwire | shared MCP queue | SSH + headless agent | plain git polling |
|---|---|---|---|---|
| Infrastructure | none | server to run | SSH + reachable host | none |
| Wake latency | ~1–3 s | poll interval | seconds | poll interval |
| Payload channel | your repo | the queue | the SSH pipe | your repo |
| Audit trail | git history | custom | none | git history |
| N nodes | yes | yes | pairwise | yes |

## CLI reference

```
mesh init <name> --nodes a,b[,c...] [--server URL]   create mesh config here
mesh iam <node>                set this machine's identity
mesh send <node|all> <msg...>  ping a node (or broadcast)
mesh watch [--timeout N]       block until a message arrives, print, exit
mesh ask <node> <text...> [--wait SECS]   delegate an A2A task
mesh reply <task-id> <text...> [--state completed|failed|...]   answer one
mesh tasks [get <id>]          task ledger
mesh card [node] [--name N --description D]   A2A agent card
mesh a2a-serve [--port 4737] [--wait 60]      localhost A2A HTTP bridge
mesh peek [node] [--since S]   show recent messages without consuming
mesh status                    show mesh, identity, topic
mesh claude-setup              print the CLAUDE.md protocol section
```

## License

MIT

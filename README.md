# claude-mesh

**Zero-infrastructure messaging between AI agent sessions on different
machines.** One stdlib-only Python file. No server to run, no accounts, no
API keys.

Born from a real need: two Claude Code sessions — a Linux laptop and a Windows
desktop — collaborating on a mathematical search campaign, coordinating work
splits and sharing proofs. They needed to tell each other "I found something,
pull now" without a human relaying messages.

## The idea

Agent sessions on different machines almost always already share a payload
channel: a git repo. What's missing is **wake latency** — the other session
doesn't know something landed until its next poll. claude-mesh fixes exactly
that gap, and nothing more:

1. **Payload travels via your shared repo** (commit → push). Full audit trail,
   code review applies, nothing new to trust.
2. **Wake pings travel via [ntfy.sh](https://ntfy.sh)** pub/sub capability
   topics — a free public relay. A ping says *"look"*; the repo says *what*.

The magic trick for Claude Code: run `mesh watch` as a **background task**.
It blocks until a ping arrives, then exits — and a finishing background task
re-invokes the Claude session that launched it. **Push delivery, zero
infrastructure.** Works the same for any agent harness that can watch a
process.

## Quick start

Machine A (in your shared project directory):

```bash
curl -fsSLO https://raw.githubusercontent.com/husker/claude-mesh/main/mesh.py
python3 mesh.py init myproject --nodes laptop,desktop
python3 mesh.py iam laptop
git add .claude-mesh.json mesh.py && git commit -m "add mesh" && git push
```

Machine B (after `git pull`):

```bash
python3 mesh.py iam desktop
```

Then, from either side:

```bash
python3 mesh.py send desktop "pushed the fix — pull and rerun tests"
python3 mesh.py send all "campaign milestone: w=7 proven empty"   # broadcast
python3 mesh.py watch                  # blocks until a ping arrives (3h max)
python3 mesh.py peek                   # show recent pings, don't consume
python3 mesh.py status                 # who am I, what mesh, what topic
```

Or install as a command: `pipx install git+https://github.com/husker/claude-mesh`
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
Two laptops behind NAT can't do that. claude-mesh carries the same envelopes
over the ntfy relay — **outbound-only connections on both ends** — so ChatGPT
(via Codex CLI) on a MacBook, Claude Code on a Linux laptop, and Copilot on a
Windows PC can all exchange tasks with no port forwarding, no VPN, no server.
See [docs/AGENTS.md](docs/AGENTS.md) for per-harness wiring (Codex CLI,
Copilot CLI, Gemini CLI, A2A frameworks, cron).

`mesh` moves messages; it never calls a model. Each node answers with
whatever brain, tools, and permissions its own harness has.

## Security model (read this)

- Topics are **capability URLs**: `cmesh-<mesh>-<128-bit-hex>-<node>` on a
  public ntfy server. Anyone who learns the topic can read and post pings.
  - Commit `.claude-mesh.json` **only to private repos**. For public repos,
    share it out-of-band (it's one small file).
  - **Never put secrets or real content in a ping.** Pings are wake-up calls;
    content belongs in your (access-controlled) repo.
  - Treat inbound pings as **untrusted data**: they tell your agent *to look
    at the repo*, not *what to do*. Agents should act on what they find in
    the authenticated channel (git), not on instructions embedded in pings.
- Want private traffic? Self-host ntfy (`mesh init --server https://ntfy.example.com`)
  or use ntfy's paid reserved topics with auth.
- `.claude-mesh.node` and cursor files are per-machine and auto-gitignored.

## How it compares

| | claude-mesh | shared MCP queue | SSH + headless agent | plain git polling |
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

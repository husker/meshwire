# a2acast

**Messaging between AI agents on different machines — no server, no
accounts, no open ports.** One stdlib-only Python file. End-to-end
encrypted. Claude Code on a Linux laptop, ChatGPT (Codex CLI) on a MacBook,
Copilot on a Windows PC — all exchanging messages and
[A2A](https://a2a-protocol.org) tasks.

## Quick start (two machines, one minute)

**Machine A** — create the mesh:

```bash
pipx install git+https://github.com/husker/a2acast   # or: uv tool install ...
mesh init home   # prints a block to paste on machine B, then starts listening
```

**Machine B** — paste the block `mesh init` printed. It looks like:

```bash
curl -fsSLO https://raw.githubusercontent.com/husker/a2acast/vX.Y.Z/mesh.py
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
/plugin marketplace add husker/a2acast
/plugin install a2acast
mesh claude-setup             # once per project — arms presence at session start

# Codex CLI / ChatGPT desktop
codex plugin marketplace add husker/a2acast
codex plugin add a2acast@a2acast
mesh codex-setup              # once per machine — arms presence at session start

# GitHub Copilot CLI
copilot plugin marketplace add husker/a2acast
copilot plugin install a2acast@a2acast
mesh copilot-setup            # once per project — pins the watcher to this node
```

Each plugin loads the mesh safety rules at session start. Claude uses
asynchronous `Stop` with `asyncRewake`; Codex uses `Stop`. Copilot runs the
watcher as an **MCP server** (`mesh mcp-serve`, wired per project by
`mesh copilot-setup` — see below) that Copilot starts with the session and
stops when it ends — including Ctrl-C and
crash. Because it isn't an agent shell, the session shows no "working" spinner
while it listens. When a message arrives the server wakes the idle session on
its own (via MCP sampling) and the session handles it with the `mesh_pending`
/ `mesh_reply` / `mesh_send` tools — a real turn, so a `MESH_TASK` gets done,
not just acknowledged. (The first time, Copilot may ask once to approve the
server for sampling; approve it and later wakes run silently.)

The loop each session runs:

1. With the plugin, follow the harness-specific setup above. Claude and Codex
   need no manual watcher; on Copilot, run `mesh copilot-setup` once in the
   project (Copilot hands a plugin MCP server no project info and there's no
   portable way to guess it, so this pins the node in a workspace
   `.github/mcp.json`). After that its MCP-server watcher listens and wakes the
   session automatically — nothing to arm. Handling happens out of band (no
   "working" spinner); the next prompt you send opens with a one-line note of
   anything a2acast handled while you were away.
2. Do your work. After pushing something the other machine should act on:
   `mesh send <node> "one-line summary — pull"`.
3. When a `MESH_TASK` line arrives, do the work and answer with
   `mesh reply <task-id> "<result>"`.

Works with any number of nodes; each node has an inbox topic and `all`
broadcasts. `mesh claude-setup` registers the a2acast presence watcher by
writing the project's `.mcp.json` — the CLAUDE.md protocol snippet itself
now lives at `mesh integrate --format claude`. (You still run `mesh
init`/`mesh join` once per machine either way: the plugin teaches sessions
the protocol, it doesn't create the mesh. On Copilot you also run `mesh
copilot-setup` once per project. The plugin's
hooks and MCP server invoke the `mesh` CLI on your PATH — the same one
`mesh init` installed — so it works the same on macOS, Linux, and Windows.
On Windows, private state relies on your account's ACLs rather than POSIX
file modes, and evidence files are opened with verified-identity checks in
place of kernel `O_NOFOLLOW`; the full test suite runs green on
windows-latest in CI. Keep it current: `pipx upgrade a2acast` (or `uv tool
upgrade a2acast`) when you update the plugin.)

**Autonomous Codex nodes (opt-in).** Claude and Copilot wake an idle session
in-process to handle a `MESH_TASK`; Codex has no such path, so a joined Codex
machine can instead run a background **supervisor** that executes delegated
tasks with no session open. Enable it with `mesh codex-setup --supervise`,
then name the peers you trust to run code on this machine with
`mesh codex-allow <node>`. Nothing runs until you do both — the supervisor is
off by default and its allowlist starts empty. See the security model below.

## Machine-wide worker pool (opt-in)

The worker pool runs repository tasks through local Codex, Copilot, and
Goose/Ollama CLIs. Run it on a joined worker host only after all three CLIs are
installed; authenticate Codex and Copilot for the current user, and start
Ollama with the configured model available (default `qwen3:4b`). The
coordinator must already be a current known mesh identity; confirm it with
`mesh status` before setup.

```bash
mesh pool-setup --workspace-root ~/Projects \
  --coordinator jamess-macbook-air-2
mesh pool-start
mesh pool-status
mesh delegate auto "add a regression test" --repo /abs/repo --wait 300
```

`pool-setup` permits repositories only below the listed workspace roots and
sets `exec_allow` to the single named coordinator. It does not start a worker;
`pool-start` is the explicit activation step. Because every mesh member has
the shared key and can assert any sender name, this allowlist is not per-node
cryptographic identity. Configure only a coordinator you trust.

On macOS, `pool-start` manages current-user LaunchAgents. On other operating
systems, `pool-start` and `pool-stop` print foreground supervisor commands for
you or your service manager to run; they do not install a service.

For normal `auto` jobs, dispatch selects the first eligible backend in
Goose/Ollama, Copilot, then Codex order, skipping workers that are blocked,
busy, unavailable, or cooling down. Nonblocking CLI calls (the default
`--wait 0`) and the nonblocking MCP tool dispatch that one worker and do not
auto-redispatch. With a positive `--wait`, the CLI can try the next eligible
backend only after an authenticated `quota` or `unavailable` result, within
the same total wait budget. Security and integration jobs select only Codex
unless a backend is explicitly named.

Each job runs in a separate Git worktree. A worktree prevents checkout
collisions; a worktree is not a security sandbox. Worker processes still have
the local user's OS permissions, and repository tasks are untrusted input.
Results report an outcome, branch, commit, worktree, summary, and verification.
A branch and commit contain proposed production changes; they are not
integrated until you review and merge or cherry-pick them yourself.

The pool creates worktrees and local commits. Its worker instructions forbid
merge, push, PR, deploy, publish, and worktree deletion, and a2acast performs
none of those as automatic postprocessing. Cleanup is an explicit command:

```bash
mesh pool-clean --integrated-into main
mesh pool-stop
```

Normal cleanup removes only terminal, clean worktrees with consistent durable
records whose commits are integrated into the named ref; uncertain or
unintegrated work is preserved. `mesh pool-clean --task <id> --force` is an
explicit escape hatch for exactly one terminal task and may discard its
unintegrated or dirty worktree.

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
Copilot CLI, Gemini CLI, A2A frameworks, cron). By default, `mesh` only moves
messages; the explicitly started worker pool is the exception and invokes its
configured local CLI. Interactive nodes answer with whatever brain, tools,
and permissions their own harness has.

## Security model (read this)

**Messages are end-to-end encrypted and authenticated.** The mesh key is
generated by `mesh init`, lives only in `.meshwire.json` on your machines,
and travels only inside join codes you share yourself. On the wire, the
relay (and anyone who discovers a topic) sees ciphertext, topic id, size,
and timing — nothing else. Sender and recipient names ride *inside* the
ciphertext.

Construction (stdlib-only, standard primitives): HKDF-SHA256 key derivation
→ HMAC-SHA256 PRF in counter mode for encryption, encrypt-then-MAC with an
independent HMAC-SHA256 key, random 128-bit nonce per message, and
constant-time tag comparison. The `mw2` authentication tag also binds the
mesh id, exact relay topic, and send timestamp. Envelopes older than seven
days (or implausibly far in the future) are rejected, and authenticated
ciphertext fingerprints are persisted per node so duplicate relay deliveries
and replays are suppressed across restarts. `mw1` remains readable during
rolling upgrades but new sends always use `mw2`. Unauthenticated, stale,
misrouted, replayed, or tampered messages are **dropped, not displayed**.

What you still must do:

- **Guard the join code and `.meshwire.json`** — they contain the key. Both
  are auto-gitignored; config writes use mode `0600`; share join codes over a
  private channel. The key is never placed in an environment variable:
  `A2ACAST_CONFIG` contains only a path. MCP tools, agent cards, and the local
  A2A HTTP bridge never return config or key fields.
- A join code grants **full membership in one trust domain**: its holder can
  decrypt traffic, publish authenticated traffic, and mint the same sender
  names as any other member. There are no per-node cryptographic identities
  or roles. `exec_allow` limits autonomous execution, not mesh membership.
- **Treat inbound tasks as untrusted input.** Encryption authenticates *the
  mesh*, not intent: any agent (or person) holding the key can send tasks.
  Receiving agents should apply their normal permission rules.
- **Autonomous Codex execution is opt-in and gated on a curated allowlist.**
  `mesh codex-supervise` runs delegated tasks through `codex exec` and replies
  over the mesh. It stays off unless you start it (`codex-setup --supervise`),
  and even then only peers you add with `mesh codex-allow` run — a
  default-empty allowlist (`exec_allow`), **not** the roster of everyone who
  holds the key. The `--sandbox read-only` default is defense-in-depth, not
  the boundary: a read-only task can still read repo secrets and return them
  in its reply, so only allow peers you actually trust.
- Sender names prove a shared-key member made the assertion, not which member:
  every node holds the same group key. a2acast rejects A2A metadata that
  disagrees with its authenticated outer route, but a compromised member can
  still choose another member's sender name in that outer route.
- Someone who learns a topic id (but not the key) can't read or forge
  messages, but can post garbage that your watcher silently drops.
  Self-hosting ntfy with auth (`mesh init --server https://ntfy.example`)
  closes even that.
- Upgrade all machines together when moving to a new a2acast version —
  it's one file. (v0.4 meshes interoperate; v0.4 clients just render the
  new join/ping control messages as odd one-off messages.)

### Incident response: revoke and rotate the mesh key

If a join code, config, or member machine is compromised, rotate both the key
and topic capability from one trusted node:

```
mesh rotate-key
```

That command switches new commands on the current node to a fresh key and
fresh topic id, then prints a private `mesh rotate-key mesh1-...` command. Run
that exact command on every remaining trusted node over a private channel. Do
not send it through the compromised mesh. Restart long-running `mesh watch`,
MCP/harness, and supervisor processes on each node so they drop their in-memory
copy of the old config. Nodes that have not applied the new code remain on the
revoked mesh and cannot read or publish on the new topics. Compare the
`key: sha256:...` line from `mesh status` out of band to confirm every trusted
node completed the cutover.

## CLI reference

```
mesh init <name> [--as NODE] [--server URL]   create a mesh; in a terminal, prints the invite block and keeps listening
mesh join <code> [--as NODE]   join from a code, announce, and (in a terminal) keep listening
mesh invite                    print the join code + paste-able bootstrap block
mesh rotate-key [mesh1-code]   rotate the key/topics, or apply a peer rotation
mesh iam <node>                set/change this machine's identity
mesh send <node|all> <msg...> [--intent request|inform|ack] [--reply-to ID]
                               message a node (or broadcast) with reply intent
mesh presence listening|working|blocked   set and broadcast agent status
mesh watch --follow            stream messages forever (preferred; background task)
mesh watch [--timeout N]       one-shot: block until one message, print, exit
mesh ping <node> [--timeout N] liveness + round-trip time (answered by watchers)
mesh ask <node> <text...> [--wait SECS]   delegate an A2A task
mesh run ensemble [--timeout N] -- "<prompt>"   fan out and collate replies
mesh run cross-review [--timeout N] -- <diff-or-ref>   two independent reviews
mesh reply <task-id> <text...> [--state completed|failed|...]   answer one
mesh tasks [get <id>]          task ledger
mesh tasks --wait <id> [--timeout N]   wait for a terminal task result
mesh card [node] [--name N --description D]   A2A agent card
mesh a2a-serve [--port 4737] [--wait 60]      localhost A2A HTTP bridge
mesh peek [node] [--since S]   show recent messages without consuming
mesh peek --wait [--from NODE] [--timeout N]   wait for the next arrival
mesh status                    mesh, identity, known peers + last seen
mesh integrate [--format codex|copilot|claude|mcp|skill]   print setup for a harness/route
mesh mcp [--config PATH]       stdio MCP tool server for any MCP client (Claude Desktop, Cursor, …)
mesh claude-setup              register the Claude Code presence watcher (writes .mcp.json)
mesh codex-setup [--supervise] arm Codex presence; --supervise also launches the autonomous actor
mesh copilot-setup             register the Copilot CLI presence watcher
mesh codex-allow <node> [--revoke|--list]   trust (or untrust) a peer to run delegated tasks here
mesh codex-supervise [--once] [--sandbox S] [--interval N] [--stop]   the autonomous task actor
mesh pool-setup --workspace-root DIR --coordinator NODE [--model MODEL]   configure the worker pool
mesh pool-start|pool-status|pool-stop   manage or inspect worker supervisors
mesh delegate auto|codex|copilot|goose <task...> --repo ABS [--base COMMIT]
  [--kind implementation|analysis] [--class normal|security|integration]
  [--verify TEXT (repeatable)] [--wait 0..300] [--as NODE]   run an isolated task
mesh pool-clean [--integrated-into REF] [--task ID [--force]]   remove eligible worktrees
```

The blocking commands use shell-friendly exit codes: `tasks --wait` exits
`0` for `completed`, `1` for any other terminal state, and `124` on timeout;
`peek --wait` exits `0` on an arrival and `124` on timeout.

`mesh run ensemble` creates one correlated task per other node in the dynamic
roster, waits for all terminal replies or the time window, then prints each
answer plus a no-reply list. `mesh run cross-review` prefers two available
peers (blocked nodes rank last), gives both the same independent review brief,
and collates their findings. Recipes exit `0` when every task completes, `1`
for dispatch or terminal failures, and `124` when any dispatched node does not
reply before the timeout.

New messages carry a stable message id and default to `inform` when intent is
missing (including messages from older clients). Use `request` when a reply is
required, `inform` for FYI traffic, and `ack` to close a loop; `--reply-to`
correlates a response to the displayed message id. Agent integrations follow a
fixed rule: always answer `request`, answer `inform` only when it adds value,
never answer `ack`, and do not send filler greetings or thanks.

Presence controls carry `listening`, `working`, or `blocked` through normal
announce/ping/pong/ack traffic and explicit `mesh presence` beacons. Session
and stop hooks maintain `working`/`listening`; approval integrations can run
`mesh presence blocked` while waiting for permission. `mesh status` and
`mesh_list_agents` show the latest reported state, and `mesh ask` warns before
sending to a blocked node.

To set a stable node name use `mesh iam <name>` (writes a per-harness pin).
Prefer this over the `A2ACAST_NODE` env var, which is not reliably inherited
by harness-spawned processes.

To keep the mesh key outside a project, point `A2ACAST_CONFIG` at an existing
config file. The explicit path takes precedence over ancestor discovery and is
inherited by lifecycle hooks:

```bash
export A2ACAST_CONFIG=/absolute/path/to/mesh-node/.meshwire.json
# PowerShell: $env:A2ACAST_CONFIG = 'C:\path\to\mesh-node\.meshwire.json'
```

`mesh claude-setup` and `mesh copilot-setup` still write their MCP workspace
files in the current project while pinning that isolated config path.

**Onboarding & MCP clients.** `mesh integrate` prints the right setup for
whatever you run — a harness plugin (`--format codex`/`copilot`), a CLAUDE.md
snippet (`--format claude`), a paste-in skill (`--format skill`), or the MCP
config (`--format mcp`). For GUI/desktop agents, `mesh mcp` runs a stdio MCP
**tool** server (add it with `mesh integrate --format mcp`) exposing
`mesh_send` / `mesh_pending` / `mesh_ask` / `mesh_reply` / `mesh_delegate` /
`mesh_list_agents`, so Claude Desktop, Cursor, or any MCP host can talk to
the mesh — no plugin needed. (This is the pull-mode tool server; the Copilot plugin's `mcp-serve`
is the push-mode watcher that wakes an idle session.)

## How it compares

| | a2acast | shared MCP queue | SSH + headless agent | plain git polling |
|---|---|---|---|---|
| Infrastructure | none | server to run | SSH + reachable host | none |
| Wake latency | ~1 s | poll interval | seconds | poll interval |
| Payload channel | message or your repo | the queue | the SSH pipe | your repo |
| Audit trail | git history | custom | none | git history |
| N nodes | yes | yes | pairwise | yes |

## License

MIT

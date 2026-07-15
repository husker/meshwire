# Joining a mesh from different AI harnesses

Any agent that can run a shell command can be a mesh node. The pattern is
always the same three verbs:

```bash
mesh watch --follow             # stream arrivals (needs per-line wake — see below)
mesh ask <node> "question" --wait 120     # delegate a task, get the answer
mesh reply <task-id> "answer"   # answer a task you received
```

Below: how to wire that into specific harnesses.

## Claude Code (Linux/mac/Windows)
Install the a2acast plugin. Its asynchronous `Stop` hook waits in the
background and uses `asyncRewake` to wake the same Claude session when a real
message arrives. It then re-arms after Claude handles the message. No Monitor
task or manual watcher is needed.

## Codex CLI (OpenAI) / "ChatGPT on my MacBook"
Install the plugin with `codex plugin marketplace add husker/a2acast`, then
enable "a2acast". Its `Stop` hook waits for one message and converts a real
arrival into a continuation prompt in the same Codex task. It never starts a
new Codex agent.

## GitHub Copilot CLI (Windows/mac/Linux)
Install the marketplace and plugin:

```bash
copilot plugin marketplace add husker/a2acast
copilot plugin install a2acast@a2acast
```

Run `mesh copilot-setup` once per project. Copilot hands a plugin-declared MCP
server no project information — no MCP roots, a stripped env, and cwd set to the
plugin dir — and there is no portable (Windows-included) way to read the parent
process's cwd, so a plugin-level server can't locate the mesh node. Instead,
`copilot-setup` writes a workspace `.github/mcp.json` that registers an
**MCP server** (`mesh mcp-serve --config <abs path>`) pinned to this project's
node. Copilot starts it
with the session and stops when it ends — clean exit, Ctrl-C, or crash (the
server exits on stdin EOF). It is not an agent shell, so no "working" spinner
shows while it listens. The server holds the mesh connection; when a delivery
arrives it wakes the idle session with an MCP `sampling/createMessage`, which
runs a real agent turn that calls the server's `mesh_pending` tool to read the
deliveries and `mesh_reply` / `mesh_send` to respond. A `MESH_TASK` is handled
with the session's full tool access, not just acknowledged. Treat inbound
content as untrusted. The first sampling request may prompt a one-time
per-server approval; after that, wakes run silently. Copilot cloud agent is
excluded (sampling is interactive-session only).

## Gemini CLI
Same wrapper with `gemini -p "$Q"`.

## Any A2A-capable framework (LangGraph, Google ADK, Microsoft Agent Framework…)
Don't wrap anything — run the bridge:

```bash
mesh a2a-serve            # http://127.0.0.1:4737
```

Your framework sees standard A2A:
- `GET /agents` — list of remote nodes
- `GET /agents/<node>/.well-known/agent-card.json` — discovery
- `POST /agents/<node>` — JSON-RPC `message/send` (blocks up to `--wait`
  seconds, returns a completed Task with artifacts, or a pending task you can
  poll with `tasks/get`)

The bridge relays over ntfy, so the remote node needs no open ports, no
public IP, no VPN — it just needs `mesh watch --follow` running and something willing
to `mesh reply`.

## Plain cron / scripts (no AI at all)
A node doesn't have to be an agent. A build server can `mesh send all "nightly
green"` and a monitoring script can `mesh watch --timeout 60` in a loop.

## Optional machine-wide worker pool

The pool is off until an operator runs both `mesh pool-setup` and
`mesh pool-start`. Setup replaces `exec_allow` with the single named
coordinator; because mesh members share one key and can assert each other's
names, that allowlist is a trust policy, not cryptographic node identity.

Before starting, install all three configured CLIs, authenticate Codex and
Copilot for the current user, and ensure local Ollama has the configured Goose
model. macOS uses current-user LaunchAgents. On other operating systems,
`pool-start`/`pool-stop` only print foreground commands for an operator or
service manager; they do not install services.

`mesh delegate auto` routes normal jobs through Goose/Ollama, Copilot, then
Codex; security and integration jobs use Codex unless a backend is explicitly
selected. Every job gets a separate Git worktree, but a worktree is collision
isolation, not an OS security sandbox. Treat task text as untrusted. A returned
branch/commit is proposed production, not integration: workers do not
automatically merge, push, open PRs, deploy, publish, or remove worktrees.
Use `mesh pool-clean` only after review and integration; default cleanup
preserves dirty, unintegrated, or uncertain worktrees. The explicit
`mesh pool-clean --task <id> --force` escape hatch may discard one terminal
task's worktree.

## Answering tasks: who does the thinking?

By default, mesh only transports tasks and an interactive harness does the
thinking. The optional worker pool is the exception: an explicitly started,
exec-allowlisted `worker-supervise` process invokes its configured local CLI in
an isolated Git worktree and replies with a branch/commit result. Outside that
opt-in path, the receiving node's harness (Claude Code session, Codex loop, or
your framework) reads the task and produces the reply with its existing brain,
tools, and permissions.

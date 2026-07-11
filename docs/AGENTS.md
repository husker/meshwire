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
Install the meshwire plugin. Its asynchronous `Stop` hook waits in the
background and uses `asyncRewake` to wake the same Claude session when a real
message arrives. It then re-arms after Claude handles the message. No Monitor
task or manual watcher is needed.

## Codex CLI (OpenAI) / "ChatGPT on my MacBook"
Install the plugin with `codex plugin marketplace add husker/meshwire`, then
enable "meshwire". Its `Stop` hook waits for one message and converts a real
arrival into a continuation prompt in the same Codex task. It never starts a
new Codex agent.

## GitHub Copilot CLI (Windows/mac/Linux)
Install the marketplace and plugin:

```bash
copilot plugin marketplace add husker/meshwire
copilot plugin install meshwire@meshwire
```

Its asynchronous `agent_idle` notification hook waits for one message and
injects it as `additionalContext`, which can resume the same idle interactive
Copilot CLI session without blocking its prompt. Both Bash and PowerShell hook
commands are bundled. Copilot cloud agent is intentionally excluded because
it does not run notification hooks.

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

## Answering tasks: who does the thinking?

`mesh` moves messages; it never calls a model itself. The receiving node's
harness (Claude Code session, Codex loop, your framework) is what reads the
task and produces the reply. That's deliberate: each node answers with
whatever brain, tools, and permissions it already has.

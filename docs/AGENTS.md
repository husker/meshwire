# Joining a mesh from different AI harnesses

Any agent that can run a shell command can be a mesh node. The pattern is
always the same three verbs:

```bash
mesh watch --follow             # stream every arrival (run in background)
mesh ask <node> "question" --wait 120     # delegate a task, get the answer
mesh reply <task-id> "answer"   # answer a task you received
```

Below: how to wire that into specific harnesses.

## Claude Code (Linux/mac/Windows)
The native fit. `mesh watch --follow` as a background task = push delivery:
every line it prints wakes the session, no re-arming. Add the protocol to
CLAUDE.md (`mesh claude-setup` prints it). Answer `MESH_TASK` lines with
`mesh reply`.

## Codex CLI (OpenAI) / "ChatGPT on my MacBook"
The ChatGPT desktop app can't run persistent shell commands, but **Codex CLI**
(the same account/models, terminal-based) can. Two options:
- Interactive: tell Codex "run `python3 mesh.py watch --timeout 300`, act on
  what arrives, reply with `mesh reply`, repeat."
- Scripted: wrap it —
  ```bash
  while true; do
    OUT=$(python3 mesh.py watch --timeout 3600 | tail -1) || continue
    echo "$OUT" | grep -q '"method": "message/send"' || continue
    TID=$(echo "$OUT" | python3 -c "import json,sys;print(json.load(sys.stdin)['params']['message']['taskId'])")
    Q=$(echo "$OUT"   | python3 -c "import json,sys;print(json.load(sys.stdin)['params']['message']['parts'][0]['text'])")
    A=$(codex exec "$Q")            # non-interactive Codex run
    python3 mesh.py reply "$TID" "$A"
  done
  ```

## GitHub Copilot CLI (Windows/mac/Linux)
Same wrapper shape with `copilot -p "$Q"` (or `gh copilot` suggest/explain for
older versions). On Windows, run it in Git Bash or adapt to PowerShell —
mesh.py itself is identical on Windows.

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

# meshwire v0.8 — delivery acknowledgements

**Date:** 2026-07-10
**Status:** approved design, pre-implementation
**Target version:** 0.8.0 (mesh.py stays a single stdlib-only file)

## Goal

Senders learn that a message was actually received by a live node — not
just accepted by the relay — via automatic, agent-invisible acks riding
the existing control-message machinery.

## Wire format

An ack is a control message like ping/pong, inside the encrypted wrapper:

```json
{"f": "desktop", "t": "laptop", "b": "ack", "c": {"mw": "ack", "of": "<relay-message-id>"}}
```

`of` is the relay-assigned id of the message being acknowledged — the
sender already holds it (the relay's publish response returns it), so
matching is exact with no new id scheme. Acks exist only on encrypted
meshes (`cfg["key"]`), like every control message; plaintext legacy
meshes keep today's behavior throughout.

## Receiver behavior

- **Watchers ack** — both `--follow` and one-shot: every trusted,
  non-control message they process (plain messages AND task envelopes),
  acked to the sender's inbox **before** the message is emitted, so a
  one-shot watch acks before it exits. No agent involvement.
- Own echoes and control messages are never acked. Acks are never acked
  (no storms), never consume a one-shot watch, and never print to
  agent-facing stdout on the receiving side (stderr log only, like pong).
- **`peek` does NOT ack** — it is a read-without-consuming debug view;
  acking from it would fake delivery/liveness.
- **`_await_result` does NOT ack** — it is an ephemeral listener; the
  node's watcher is the single acking authority (prevents duplicate acks
  from one node; a sender ignores duplicates anyway — first match wins).
- An incoming ack refreshes the peers file: `note_peer(frm, "ack")`.
- Ack send failures are swallowed (a watcher must never die because an
  ack could not be posted) — same rule as pong.

## Sender behavior

Constant `ACK_WAIT = 5` (seconds).

- **`mesh send <node> ...`** — subscribe own inbox eagerly (the
  ping/ask `_stream_open` pattern), publish, then wait up to `ACK_WAIT`
  for `{"mw": "ack", "of": <this message's id>}`:
  - ack → `delivered to <node> (<N>ms)`
  - silence → `sent — no ack yet (node may be offline; the relay holds
    the message)`
  - **exit 0 either way**; `--no-wait` skips the subscribe+wait entirely
    (behaves exactly like today). Plaintext mesh: no wait, today's output.
- **`mesh send all ...`** — waits the FULL window, collecting acks, then
  prints `acked by: <name>, <name>` (or the no-ack line). No
  "missing nodes" list — a node this machine has never seen must not be
  implied dead.
- **`mesh ask <node> ... --wait N`** — the result stream is already
  open; when the task's ack arrives, print
  `task delivered to <node> (<N>ms)`, then keep waiting for the reply as
  today. Fire-and-forget `ask` (no `--wait`) performs the same
  `ACK_WAIT` ack wait as `send`.

## Semantics (documented in README)

An ack proves a live watcher decrypted the message *now*. **No ack means
"not delivered yet", not "failed"** — the relay caches messages, and a
watcher that connects later (with its cursor) still receives them.

## Compatibility

- Mixed versions: pre-0.8 watchers don't ack (senders print "no ack yet"
  despite eventual delivery); pre-0.8 senders/watchers treat incoming
  acks as unknown control messages (stderr "ignored", nothing surfaces).
  README repeats the standing advice: upgrade all machines together.
- Wire/config/join codes unchanged. Version bumps: pyproject,
  both plugin manifests (`.claude-plugin`, `plugins/meshwire/.codex-plugin`)
  → `0.8.0`; `USER_AGENT` → `"meshwire/0.8"`; the Codex plugin's copied
  skill/hook stay byte-identical to the masters (existing sync test).

## Testing

- Unit (stdlib, no network, fake transport): watcher acks a plain message
  and a task envelope (both modes, ack posted before emit); no ack for
  own echo, control messages, or from `peek`; sender matches ack by `of`
  id and prints the delivered line; sender timeout path prints the
  no-ack line and exits 0; broadcast collects and lists multiple ackers;
  `--no-wait` posts without subscribing.
- Live smoke (two temp nodes on ntfy.sh): `send` prints a delivered line
  with a plausible ms figure; `ask --wait` prints task-delivered before
  the scripted reply arrives.

## Non-goals

- Read receipts / agent-acted acknowledgements (that is `ask`/`reply`).
- Retry/resend logic — the relay's cache plus cursor replay already
  covers store-and-forward; acks only report.
- Configurable wait window (5s constant; revisit only if real use bites).

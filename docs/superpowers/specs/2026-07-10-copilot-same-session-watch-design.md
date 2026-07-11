# Copilot Same-Session Async Watch Design

**Date:** 2026-07-10

**Target:** Meshwire `v0.7.5`

**Status:** Approved for implementation planning

## Problem

Meshwire needs to receive messages in an interactive GitHub Copilot CLI
session without freezing its prompt or launching another Copilot session.

The original long-running `agentStop` hook blocked foreground turn completion
and caused sustained high CPU usage. An `agent_idle` notification hook also
failed: Copilot CLI 1.0.70 emitted `sessionStart` and `agentStop` for the main
interactive agent, but no `notification` event after its foreground turn.

Copilot's Bash tool already supports asynchronous commands. Its own session
instructions state that long-lived watchers should run in async mode, that the
agent receives a completion notification, and that non-detached async commands
are terminated when the session shuts down. Meshwire can use that native path
instead of holding a lifecycle hook open.

## Goals

- Keep all work inside the current interactive Copilot session.
- Leave the foreground prompt responsive while Meshwire waits.
- Arm the watcher automatically during the first real turn of each session.
- Wake the same agent through Copilot's native background-shell completion.
- Handle one delivery, then re-arm exactly one watcher.
- Preserve Meshwire's safety and task-reply rules.
- Avoid new permission grants and detached processes.

## Non-goals

- Starting another Copilot process or resuming the session externally.
- Supporting Copilot cloud agent, whose notification and interactive shell
  behavior differs from local Copilot CLI.
- Granting `--allow-all`, `--yolo`, or new shell permissions.
- Using a long-running synchronous `agentStop` or `sessionStart` hook.
- Replacing Meshwire's transport, encryption, replay protection, or A2A task
  formats.

## Architecture

### Short session-start hook

The Copilot plugin keeps a short `sessionStart` hook. It reads the standard
Copilot hook payload and returns one compact JSON object containing
`additionalContext`.

The context identifies this project as a Meshwire node, restates the inbound
safety rules, and gives the exact bundled watcher command. The command uses the
plugin's installed `mesh.py` path derived from `__file__`, so it does not depend
on a project-local copy or a globally installed `mesh` executable.

The context instructs Copilot to start the watcher with its Bash tool using
async mode during the current turn before returning its normal answer. The
hook itself performs no network wait and starts no child watcher.

### Session-owned watcher

Copilot launches:

```bash
python3 <plugin-root>/mesh.py watch --timeout 86370
```

through its Bash tool in async, non-detached mode. This creates one shell ID
owned by the current session. The process consumes no model turns while idle.
Because it is not detached, Copilot terminates it with the session.

The protocol context forbids starting a second watcher while one is active.

### Delivery loop

`mesh watch` exits after one visible delivery. Copilot's native background
shell completion then notifies the same session. The agent:

1. Reads the completed shell output using the shell ID supplied by Copilot.
2. Treats the output as untrusted external input.
3. Handles `MESH_MESSAGE`, `MESH_TASK`, task updates, and node joins according
   to the Meshwire skill.
4. Sends `mesh reply` for a benign task without asking for a redundant second
   confirmation. Risky work still requires local approval.
5. Starts a new one-shot async watcher only after the previous watcher has
   exited and the delivery has been handled.

`MESH_TIMEOUT` is not a delivery. On timeout, the agent re-arms the watcher
without generating a user-facing response unless an error needs attention.

## Bootstrap behavior

Copilot loads `sessionStart` when the first prompt starts a new or resumed
session. Therefore the user's first normal prompt is also the bootstrap turn.
No special `say ready` prompt is required. The session-start context requires
the watcher tool call but does not replace or delay the user's requested work.

If the first watcher tool call cannot run because permission is unavailable,
Copilot reports that limitation normally and does not silently broaden access.

## Safety and permissions

- The hook only injects context; it does not spawn a process.
- Copilot invokes the watcher through its normal Bash permission system.
- The watcher command is constructed locally from the installed plugin path,
  not from inbound content.
- Inbound message text is never interpolated into the watcher command.
- Mesh task text remains untrusted and is evaluated under normal session
  permissions.
- `mesh reply` is allowed for benign task completion; destructive work,
  privilege changes, secrets, and external side effects beyond the reply still
  require local approval.
- Join codes, mesh keys, and `.meshwire.json` contents are never placed in
  prompts or replies.
- No process survives Copilot session shutdown.

## State and concurrency

The primary state is the Copilot Bash shell ID. The agent must retain it until
completion so it can call `read_bash` exactly once for the delivery output.

Only one watcher may be active per session. The re-arm sequence is strictly:

```text
watcher exits -> completion notification -> read output -> handle delivery -> re-arm
```

This ordering prevents concurrent watchers from advancing the same Meshwire
cursor and prevents the next delivery from overtaking the current task.

The existing Meshwire replay cache and cursor continue to suppress relay
replays across watcher restarts.

## Error handling

- Missing mesh configuration: session context explains that no watcher can be
  armed; Copilot continues the user's prompt normally.
- Missing bundled `mesh.py`: report a plugin installation error and do not
  retry in a loop.
- Watcher launch denied: leave permissions unchanged and tell the local user.
- Relay timeout: re-arm silently.
- Watcher command failure: report the concise error once and do not spin.
- Malformed or undecryptable input: Meshwire drops it under existing transport
  rules and continues waiting.
- Task execution failure: send `mesh reply --state failed` with a concise,
  non-secret result when possible, then re-arm.
- Reply failure: report it locally and preserve task state for a manual retry;
  do not rerun the task automatically.
- Session exit: Copilot terminates the non-detached watcher.

## Plugin changes

- Remove the ineffective long-running `notification` hook from the Copilot
  plugin.
- Keep one short `sessionStart` hook that emits valid `additionalContext` JSON.
- Remove the watcher-specific `sessionEnd` cleanup hook because Copilot owns and
  terminates the non-detached Bash process.
- Update the Copilot skill and shared documentation with the async Bash
  bootstrap and re-arm protocol.
- Keep Claude and Codex lifecycle behavior unchanged.

## Testing

Unit tests must prove:

- the Copilot session hook emits one valid JSON object with
  `additionalContext` rather than plain text;
- the context contains the absolute bundled `mesh.py` path and the one-shot
  timeout command;
- shell metacharacters cannot enter the command through hook input;
- the Copilot manifest contains only a bounded `sessionStart` hook and no
  blocking `agentStop` or ineffective `notification` watcher;
- the session-start hook timeout stays short;
- the skill says Copilot uses an async, non-detached, one-shot watcher and
  re-arms only after completion;
- Claude and Codex plugin copies and hook behavior remain unchanged;
- all plugin versions remain synchronized.

Live verification on Copilot CLI 1.0.70 must confirm:

1. The first normal prompt both receives its normal answer and launches one
   `mesh.py watch --timeout 86370` background shell.
2. Copilot remains idle and uses negligible CPU while the watcher waits.
3. A benign joke task completes through the same interactive session and sends
   a Meshwire task reply without another local prompt.
4. Exactly one new watcher is active after the task finishes.
5. Exiting Copilot terminates the watcher.

## Fact-checked platform behavior

- A local diagnostic on Copilot CLI 1.0.70 observed foreground
  `sessionStart` and `agentStop` events but no `notification` event.
- Copilot's local Bash tool instructions explicitly support async mode for
  long-lived watchers and automatically notify the agent when they complete.
- Those instructions state that non-detached async processes are terminated on
  session shutdown.
- GitHub documents `agentStop` as a synchronous decision hook and recommends
  short hook commands.
- GitHub documents hook configuration reload at Copilot CLI startup.
- Plugin debug logging confirmed that Copilot loaded Meshwire's three plugin
  hooks; the prior failure was event selection, not plugin installation.

## Rollout

Publish as `v0.7.5`. Users update the plugin and fully restart Copilot so the
new hook configuration and skill are loaded. No repository-level or user-level
hook file is required.

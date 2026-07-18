# Machine-wide a2acast worker pool

**Status:** Design approved in conversation; written specification awaiting
user review.

**Date:** 2026-07-14

## Summary

Extend a2acast's opt-in Codex supervisor into a reusable, machine-wide pool of
three independently addressed workers:

- Codex CLI for coordination, difficult work, review, integration, and
  overflow implementation.
- GitHub Copilot CLI for bounded implementation while its included quota is
  available.
- Goose backed by a compact local Ollama model for unlimited low-cost work.

Each implementation job runs in a dedicated Git worktree and branch. Workers
never edit the user's active checkout and never automatically merge, push, or
open a pull request. The Codex coordinator receives a structured result,
reviews it, and decides whether to integrate it.

The first deployment targets this Apple Silicon Mac with 8 GiB RAM, while the
worker-supervisor core remains portable Python. macOS login persistence is an
installation-layer feature, not a dependency of the core protocol.

## Goals

1. Make the pool usable from any Git repository beneath an explicit workspace
   root, initially `/Users/james/Projects`.
2. Reuse a2acast's task transport, state transitions, curated execution
   allowlist, deduplication, timeout, retry, and headless receiver.
3. Give every backend a distinct a2acast identity so tasks can be routed,
   observed, retried, and disabled independently.
4. Keep concurrent agents from colliding by giving each job its own worktree,
   branch, process, and task result.
5. Prefer local capacity for straightforward work, Copilot for bounded coding,
   and Codex for ambiguous, sensitive, or integrative work.
6. Degrade gracefully: one missing, logged-out, quota-limited, or unhealthy
   backend must not stop the rest of the pool.
7. Require no new cloud account or API key in the first release.

## Non-goals

- The pool is not a cryptographic security boundary. Every member holding the
  shared mesh key can assert any sender name.
- A Git worktree is collision isolation, not host or secret isolation.
- Version one does not automatically merge, cherry-pick, push, open PRs, or
  delete unintegrated work.
- Version one does not scrape or predict provider quota. It reacts to explicit
  CLI failures and cooldowns.
- Version one does not promise that a small local model can complete every
  coding task. The local backend must pass a smoke test or remain unavailable.
- Version one does not add dormant adapters for Gemini, Groq, OpenRouter, or
  any service requiring a new account or credential.
- Linux systemd and Windows service installation are deferred. The portable
  foreground supervisor remains usable there.

## Verified current state

The following claims were checked against the repository and local tools on
2026-07-14:

- a2acast 0.14.1 contains `mesh codex-supervise`, which starts a self-contained
  relay receiver, selects only inbound submitted tasks from `exec_allow`,
  claims them as `working`, invokes `codex exec`, caps retries, replies, and
  persists handled task IDs.
- `mesh codex-setup --supervise` only launches a detached process for the
  Codex backend. There is no generic backend registry or worktree lifecycle.
- The existing `.meshwire.tasks.json` ledger is shared by every node rooted at
  the same mesh config. Inbound task records do not currently store the local
  recipient, and `_supervise_pending` does not filter by recipient. This must
  be corrected before multiple supervisors use the same ledger.
- The MCP server currently exposes `mesh_pending`, `mesh_reply`, `mesh_send`,
  `mesh_ask`, and `mesh_list_agents`; it has no structured delegation tool.
- `mesh run ensemble` and `mesh run cross-review` already provide useful
  multi-node collection primitives, but they fan out plain-text requests to
  roster nodes rather than constructing isolated implementation jobs.
- Local Codex CLI is `0.144.1`. Its `codex exec` supports `--sandbox`, `--cd`,
  `--ephemeral`, JSONL output, and a final-output file.
- Local GitHub Copilot CLI is `1.0.70`. GitHub documents programmatic `-p`
  execution, `--no-ask-user`, explicit available/allowed/denied tool sets, and
  structured output modes.
- Homebrew is installed on arm64 macOS. Ollama and Goose are not installed.
- The machine reports 8,589,934,592 bytes of RAM. A compact model is required;
  a large local coding model is outside this design's resource budget.

External interface claims were checked against primary documentation:

- [GitHub Copilot CLI programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference)
- [GitHub Copilot CLI tool permissions](https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools)
- [Goose provider documentation](https://github.com/aaif-goose/goose/blob/main/documentation/docs/getting-started/providers.md)
- [Goose environment variables](https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/environment-variables.md)
- [Ollama quickstart](https://docs.ollama.com/quickstart)

Exact Goose and Ollama command lines will be probed from the installed
versions before implementation locks their adapters. Documentation establishes
the supported relationship, but local `--help` output is the executable
contract.

## Architecture

```text
Codex coordinator identity
        |
        | mesh_delegate / mesh delegate
        v
     a2acast relay + shared task ledger
        |
        +--> worker-codex   --> isolated worktree --> structured result
        +--> worker-copilot --> isolated worktree --> structured result
        +--> worker-ollama  --> isolated worktree --> structured result
```

The coordinator remains a normal interactive Codex identity. Worker identities
are separate and must never reuse the coordinator's name; a2acast refuses
self-directed tasks, and a separate identity also makes health and ownership
visible.

The current Codex-specific execution loop becomes a backend-neutral supervisor:

```text
mesh worker-supervise --backend codex|copilot|goose [options]
```

`mesh codex-supervise` remains as a compatibility wrapper around the Codex
adapter and preserves its current read-only default. The new pool explicitly
chooses writable worktrees.

## Pool configuration

`mesh pool-setup` writes `.meshwire.pool.json` beside the selected
`.meshwire.json`. The existing `.meshwire.*` ignore rule prevents it from being
committed. It contains no mesh key or provider credential; it references the
existing config path.

Conceptual schema:

```json
{
  "version": 1,
  "mesh_config": "/Users/james/Projects/meshwire/.meshwire.json",
  "coordinator": "jamess-macbook-air-2-codex",
  "workspace_roots": ["/Users/james/Projects"],
  "worktree_root": "/Users/james/.cache/a2acast/worktrees",
  "workers": {
    "codex": {"node": "jamess-macbook-air-2-worker-codex"},
    "copilot": {"node": "jamess-macbook-air-2-worker-copilot"},
    "goose": {
      "node": "jamess-macbook-air-2-worker-ollama",
      "provider": "ollama",
      "model": "qwen3:4b"
    }
  },
  "routing": ["goose", "copilot", "codex"]
}
```

The Ollama model is an initial candidate, not a hard-coded promise. Setup pulls
one compact tool-capable model and records the actual model only after a live
file-edit smoke test succeeds.

All path checks use canonical real paths and `os.path.commonpath`; string
prefix checks are insufficient. Repository paths outside `workspace_roots` are
rejected before Git or an AI CLI runs.

## Task and result protocol

Plain `mesh ask` remains unchanged. Isolated implementation uses a versioned
payload so the supervisor does not infer security-sensitive metadata from
prose:

```text
A2ACAST_JOB_V1
{"repo":"/abs/repo","base":"<40-hex commit>","task":"...",
 "verification":["descriptive hints only"],"kind":"implementation",
 "class":"normal"}
```

The task ID and sender continue to come from the authenticated A2A envelope.
The payload parser accepts only known fields, validates their types and bounds,
canonicalizes `repo`, resolves `base` to an exact commit, and rejects malformed
or unsupported versions. Verification entries are instructions to the model,
not shell commands executed blindly by the supervisor.

Transport sanitization runs before JSON decoding, so escaped JSON controls can
become real characters afterward. The job/result parsers therefore sanitize
decoded human-text fields (task, verification entries, summary, and
verification output) a second time before they reach a prompt or coordinator
context. Metadata paths and refs reject control/format characters rather than
normalizing them.

The complete encoded job is limited to 64 KiB; `task` is limited to 48 KiB;
paths are limited to 4,096 characters; and `verification` is limited to 16
entries of at most 2 KiB each. `kind` is `implementation` or `analysis`.
`class` is `normal`, `security`, or `integration`; it is supplied explicitly by
the coordinator rather than guessed from task prose.

Each inbound task record gains `local_node`, set from the receiver identity.
`_supervise_pending(cfg, node)` must require `task.local_node == node`. This is
the prerequisite that prevents worker processes sharing one ledger from racing
tasks addressed to another identity. Legacy records without `local_node` remain
eligible only for the legacy `codex-supervise` path, preserving compatibility
without exposing them to pool workers.

Results use a second versioned prefix:

```text
A2ACAST_RESULT_V1
{"backend":"copilot","outcome":"completed","branch":"...",
 "commit":"...","changed_files":["..."],"summary":"...",
 "verification":"...","runtime_seconds":123,"worktree":"..."}
```

`outcome` is one of `completed`, `no_change`, `failed`, `unavailable`, or
`quota`. Machine-readable results let an automatic dispatcher distinguish a
bad implementation from a backend that should be skipped temporarily. Results
are limited to 128 KiB, with backend output truncated explicitly and its full
local log path retained when needed.

## Worktree lifecycle

For a validated implementation task, the supervisor:

1. Confirms `repo` is a Git worktree beneath an allowed root.
2. Resolves the requested base to an exact commit object.
3. Creates a collision-resistant branch such as
   `codex/a2acast-<task-token>-<backend>`, where the filesystem/Git-safe task
   token is a stable SHA-256 prefix of the original A2A task ID.
4. Adds a worktree beneath
   `~/.cache/a2acast/worktrees/<repo-fingerprint>/<task-token>/<backend>`.
5. Starts the backend with that directory as its working root.
6. On successful exit, independently inspects `git status` and the diff.
7. If files changed, stages and commits them with a local a2acast worker
   identity; workers do not need permission to push.
8. Sends the structured result and retains the worktree for coordinator review.

An implementation task that exits successfully but produces no diff returns
`no_change`, not a fabricated successful commit. Analysis-only tasks may return
a prose result without a branch.

Cleanup is conservative. `mesh pool-clean` removes only worktrees whose commit
is already reachable from an operator-specified integration ref. Unintegrated
or failed worktrees require an explicit task ID plus `--force`. Cleanup verifies
that the path is beneath the configured worktree root before removal.

## Backend adapters

### Codex

The adapter uses the locally verified non-interactive interface, conceptually:

```text
codex exec --sandbox workspace-write --cd <worktree> --ephemeral <prompt>
```

The worktree is the only writable project directory supplied. The prompt
contains the fixed a2acast security frame, exact task metadata, completion
contract, and prohibition on push/merge/PR operations.

### GitHub Copilot CLI

The adapter uses programmatic prompt mode with no user questions and an
explicit tool surface. It allows repository reads, writes, and the shell needed
for local tests while denying URL tools, memory writes, remote-control tools,
subagent delegation, `git push`, and `gh` mutation. Exact flags are derived from
the installed `copilot help` output and covered by a command-construction test.

Copilot's permission flags reduce accidental capability but are not an OS
sandbox: an allowed shell can execute arbitrary user-level code. Therefore the
trusted-coordinator allowlist, workspace-root validation, worktree isolation,
no injected secrets, and post-run inspection remain mandatory.

### Goose with Ollama

Setup installs Goose and Ollama, starts the local Ollama service, pulls a
compact tool-capable model, and configures an isolated Goose profile with the
built-in developer tools required for file edits and local tests. It does not
configure a cloud provider or API key.

The adapter pins `GOOSE_PROVIDER=ollama`, `GOOSE_MODEL=<smoke-tested model>`, a
bounded context appropriate for 8 GiB RAM, a maximum turn count, and the
worktree as cwd. The local model is marked available only if it can create a
file in a temporary Git repository, inspect it, and finish within the timeout.

## Routing

The proposed user-facing commands are:

```text
mesh pool-setup --workspace-root <path> --coordinator <node>
mesh pool-start
mesh pool-status
mesh pool-stop
mesh pool-clean [--integrated-into <ref>] [--task <id> --force]
mesh delegate auto|codex|copilot|goose "<task>" --repo <path> [--base <ref>]
  [--kind implementation|analysis] [--class normal|security|integration]
```

The MCP server gains `mesh_delegate` with the same logical fields so Codex can
dispatch without constructing protocol text. Existing tools remain unchanged.

Automatic routing uses the explicit task kind/class, configured priority, live
presence, and cooldown state:

1. Security and integration classes always route to Codex unless the
   coordinator explicitly names another backend.
2. Normal analysis and small bounded implementation route to Goose/Ollama.
3. Normal implementation falls through to Copilot, then Codex, when the local
   worker is unavailable or the coordinator marks the task unsuitable for the
   compact model.

Explicit backend selection always overrides automatic routing. A backend that
returns `quota`, `unavailable`, or an auth error enters a bounded cooldown and
is skipped. Generic task failures use the existing capped retry/dead-letter
behavior and are not mislabeled as quota failures. The pool does not blindly
fan out implementation tasks; `ensemble` and `cross-review` remain explicit
review workflows.

## Process lifecycle on this Mac

The portable `worker-supervise` command runs in the foreground. For this setup,
`pool-setup` creates one per-user macOS LaunchAgent per backend. Each plist
contains only executable arguments, backend name, node identity, log path, and
the path to the existing mesh config; it does not contain the mesh key.

Each worker has a node-keyed lock, PID file, log, health file, and cooldown
state. `pool-start`, `pool-status`, and `pool-stop` use `launchctl` on macOS and
print direct foreground commands elsewhere. Processes restart after login and
after unexpected exit with bounded backoff. Health is one of `idle`, `busy`,
`cooldown`, or `unavailable`, with the current task, last success/error, and
cooldown deadline recorded atomically. Worker logs use bounded size rotation:
five files of at most 5 MiB per backend.

Ollama service ownership remains with its installer/service manager rather than
being embedded in the a2acast worker process. Pool status checks its local API
and model availability before marking Goose healthy.

## Error handling

- Malformed job, unsupported version, unauthorized sender, disallowed path,
  nonexistent base, or identity mismatch: reject without creating a worktree.
- Existing branch/worktree collision: generate a new suffix; never delete an
  existing path automatically.
- Backend missing or logged out: return `unavailable`, set cooldown, retain no
  implementation commit.
- Explicit quota/rate-limit response: return `quota`, set cooldown, permit the
  coordinator to reroute.
- Timeout or nonzero exit: use capped retries; retain the failed worktree and
  logs for diagnosis after the final attempt.
- Reply transport failure: preserve the completed commit and structured result
  locally, reset only delivery state, and retry the reply rather than rerunning
  the model.
- Supervisor crash while `working`: on restart, inspect the task's worktree and
  result journal before deciding whether to resume, reply, or requeue. It must
  not blindly run a second model against the same branch.

The last two rules intentionally refine the existing supervisor, which treats
execution and reply delivery as one retry unit. Model work is expensive and
must not be repeated merely because ntfy reply delivery failed.

## Security model

Only the explicitly named coordinator is placed in each worker's execution
allowlist. Roster membership is never execution authorization. Setup prints the
shared-key identity limitation before enabling the pool.

Job text is untrusted quoted content. Metadata is parsed separately, control
characters and framing-like tags are sanitized by the existing delivery path,
and task prose cannot override repository roots, backend, base commit, timeout,
or cleanup policy.

No `.env`, API key, mesh key, or unrelated process environment is copied into a
worktree or job payload. Adapters start from a minimal allowlisted environment,
adding only PATH, locale, temporary directory, backend auth/config locations,
and local Ollama variables required by that backend. Provider authentication
remains in the provider's own credential store.

No worker is granted automatic push, merge, PR, package publication, service
deployment, or destructive cleanup authority. Those remain coordinator/user
actions after reviewing evidence.

## Testing and acceptance

### Unit tests

- Versioned job/result parsing, unknown-field rejection, size limits, and
  control/framing sanitization.
- Canonical workspace-root checks, including sibling-prefix and symlink escape
  cases.
- Recipient-scoped task storage and selection with multiple worker identities.
- Backend command construction and sanitized environment.
- Failure classification, cooldown, retry, dead-letter, and reply-only retry.
- Branch/path collision handling and conservative cleanup.
- CLI parsing and backward compatibility for `codex-supervise`.
- MCP `mesh_delegate` schema and dispatch.

### Integration tests

- Fake Codex, Copilot, and Goose executables operating on temporary Git repos.
- Two supervisors sharing one ledger process only tasks addressed to their own
  identities.
- A successful worker changes and commits only its worktree; the active
  checkout's index and files remain byte-for-byte unchanged.
- A failed reply is retried without rerunning the fake model.
- Quota/unavailable response causes automatic selection of the next backend.
- Unintegrated work cannot be cleaned without explicit force.

### Live acceptance on this Mac

1. Install and version-check Goose and Ollama.
2. Pull and smoke-test a compact tool-capable local model.
3. Start the three worker identities and confirm `pool-status` reports them.
4. Send a tiny isolated edit to each backend and receive a structured result.
5. Confirm each result has the expected branch/commit and the active checkout
   remains unchanged.
6. Stop one worker and confirm automatic routing uses another.
7. Restart/login persistence is verified through LaunchAgent status and a
   controlled process restart; an actual logout is not required.
8. Run the complete Python test suite and repository validation. Per workspace
   instructions, also attempt `tsc --noEmit`; this Python-only repository is
   expected to report that no TypeScript project/compiler is configured, which
   is recorded rather than misrepresented as a TypeScript build pass.

## Adversarial review

The design was challenged against these failure modes, with the resulting
changes incorporated above:

1. **Wrong worker races a task:** discovered in current shared-ledger behavior;
   resolved by recording and filtering `local_node` before parallel workers.
2. **Coordinator and worker share an identity:** resolved by distinct worker
   node names; self-delegation is never required.
3. **Worktree described as a sandbox:** corrected throughout. It prevents Git
   collisions but not host reads or arbitrary shell behavior.
4. **Quota detection retries forever:** explicit quota/auth classification gets
   cooldown; unknown failures retain capped retry/dead-letter semantics.
5. **Successful exit falsely claims edits:** supervisor independently inspects
   Git and reports `no_change` when there is no diff.
6. **Reply outage repeats paid model work:** execution output is journaled and
   reply delivery retries independently.
7. **Cleanup deletes valuable work:** only integrated commits are cleaned by
   default; unintegrated work requires task ID plus force.
8. **Small model is installed but cannot use tools:** availability requires a
   real temporary-repository edit smoke test.
9. **Launch configuration leaks the mesh key:** plists carry only the config
   path, never config contents.
10. **Allowlisted name implies cryptographic identity:** rejected explicitly;
    the shared-key impersonation limitation remains visible and accepted.
11. **Task requests smuggle paths or commands:** repository/base are typed
    metadata validated independently; verification text is never blindly
    executed by the supervisor.
12. **Dirty active checkout is overwritten:** work starts from an exact commit
    in a separate worktree and integration remains a later reviewed action.
13. **Automatic routing guesses risk from attacker-controlled prose:** resolved
    by an explicit coordinator-supplied task class; security/integration default
    to Codex.
14. **JSON escapes restore framing after transport sanitization:** resolved by
    sanitizing decoded human-text fields again and rejecting controls in typed
    metadata.

## Delivery sequence

1. Add recipient-scoped task records and regression tests.
2. Extract the generic supervisor state machine while preserving the legacy
   Codex command.
3. Add versioned job/result types and worktree management.
4. Add Codex and Copilot adapters with fake-CLI integration tests.
5. Add Goose/Ollama adapter and runtime health/cooldown state.
6. Add pool configuration, lifecycle commands, routing, and MCP delegation.
7. Add macOS LaunchAgent generation and lifecycle handling.
8. Update README, harness documentation, version/changelog as required.
9. Install the missing local tools, run live smoke jobs, and leave the pool
   enabled only after every safety and acceptance check passes.

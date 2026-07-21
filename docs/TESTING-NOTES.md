# Testing notes: verifying the instrument

These are lessons from #62 phase 2, written down because every one of them
produced a *confident wrong answer* rather than an obvious error.

Two rules, because there are two distinct failures here and one of them is
not about instruments at all:

> **1. Verify the instrument before trusting its output, and check hardest
> when the output is what you hoped for.**
>
> **2. A report of an execution is not evidence of an execution. Ask where a
> result came from, not whether it is right.**

Confirming results are the ones that do not get checked. A sweep reporting
"all mutations survived" to someone who just claimed a gap, or "all tests
pass" to someone who just wrote them, is the exact shape that ships.

## Provenance

Rule 1 assumes a run occurred. One failure in this series had no instrument
to verify: a mutation sweep was reported as run, with a specific list of
mutations attached, and had not been run at all. It was the most reassuring
paragraph in the message containing it.

Every harness requirement below — assert the mutant is present, disable
bytecode caching, use a worktree — presupposes execution. None of them
reaches a result that was never produced.

- **Results a reader cannot reproduce are claims, not evidence.** Mark which
  they are. "804 tests pass" from an author is a claim; a CI run on a pushed
  sha is evidence, because nobody in the conversation authored its output.
- **The question that works is "where did this come from".** Correctness-
  flavoured challenges — "are you sure?", "re-run it" — can all be answered
  by the same process that produced the original, so they cannot detect
  this. Provenance can.
- The catch here came from a reviewer noticing that a load-bearing sentence
  had no stated origin — not from doubting whether the claim was true.

### The summary is where motivation re-enters

A result you ran and read is still a claim once you summarise it.

One failure in this series had a working instrument and correct output. The
terminal showed `FAILED (failures=1, errors=7)`; the commit message said the
new test fails legibly "instead of" seven unrelated errors. It is *alongside*
them — eight failures, one of which is legible. The data was on screen and
had been read.

Nothing above catches this. The harness was sound, so no instrument check
applies. The run happened, so no provenance question surfaces it. It was
found by a reviewer re-reading the raw output against the prose — and
incidentally, because they wanted to see the failure mode themselves, not
because they doubted the description.

The two failures with no mechanical remedy are the two where a person, not a
tool, is the last step: reporting a run that did not happen, and describing a
run that did. For both, the only defence is someone else comparing the claim
to the artefact. Quote the actual output in the commit message or PR body
rather than characterising it, so the comparison is possible without
re-running anything.

## Tests can pass without testing anything

Three of the six tests originally written for `_ensure_node_key` were
hollow — they passed with or without the code they claimed to cover. Three
distinct shapes, all from tests written carefully by someone who would have
defended them on reading:

1. **The assertion was carried by something else.** A half-present-keypair
   test deleted the `.pub` and asserted a refusal. `ssh-keygen` refuses to
   clobber an existing private key on its own, so the assertion passed
   whether or not our guard existed. The direction that *needed* the guard —
   private half missing, `.pub` surviving, where a fresh pair silently
   replaces the node's identity — was untested.
2. **Both sides of the assertion came from the code under test.** A test
   asked `node_key_file()` where the key should be, then asserted it was
   there. Any mutation renaming paths *consistently* — the bug the test
   existed to catch — passed. **Assert the literal; never ask the code under
   test what to expect.**
3. **The assertion was too narrow.** An idempotence test compared the
   returned public keys across two calls and never looked at the private key
   file. A one-line `os.chmod(key_path, 0o644)` on the re-entry path
   world-readable'd the private key on every call and passed all 803 tests.

### Assertions carried by a third party

Worth hunting for deliberately rather than tripping over: a property that
appears tested but is actually enforced by a tool you shell out to. Three
instances in one area, which is why it gets its own heading.

It shows up with both signs:

- **As an accidental pass** (shape 1 above). The half-present test asserted
  a refusal that `ssh-keygen` produces on its own.
- **As accidental coverage.** The owner private key had no permission
  assertion anywhere, yet mutating `_owner_init` to `chmod 0644` failed
  seven approval tests — `ssh-keygen` refuses to sign with a world-readable
  key. The property was enforced; nothing *stated* it.

"Nothing asserts X" and "X is unprotected" are different claims, and a grep
of the test suite establishes only the first. Check which one you have.

The tell for both is platform- or tool-dependence. `ssh-keygen` applies no
POSIX permission check on Windows, so the same code was incidentally covered
on Linux and macOS and entirely unchecked on the one platform where the
owner key actually lives. Coverage that comes from a third party inherits
that party's platform behaviour, silently.

A related pattern, offered as a **hypothesis from a single case**, not an
established rule: *the branch added late to satisfy a reviewer may be the
branch the existing tests were not written for.* The one case: the same
defect recurred in three locations — generation, re-entry, recovery — and
the recovery branch, added last in response to review and the most likely of
the three to execute in practice, stayed uncovered longest. n=1. Weigh it
accordingly; it is recorded so a second instance can be recognised, not so
it can be cited. The practical form, which costs nothing either way: when
adding a branch, extend the test covering its siblings rather than writing a
new one for its shape.

## Mutation-testing harness requirements

If a harness cannot distinguish "the mutant survived" from "the code was
never mutated", its output is noise that reads like a finding.

- **Assert the mutant is present before running.** Not that the edit applied
  cleanly — that the string is verifiably in the file. A harness that
  silently failed to inject reported five clean survivals from an unmodified
  file.
- **Assert the anchor is unique, and that the injection landed in the
  intended function.** The neighbouring failure to not injecting at all is
  injecting in the wrong place, when the anchor string occurs more than once.
  A mutation applied to a function the tests never exercise reads exactly
  like a survival.
- **Disable bytecode caching.** Set `PYTHONDONTWRITEBYTECODE=1` and remove
  `__pycache__` between mutants. Same-length mutations (`0o644`, `0o640`,
  `0o700`) rewritten within mtime granularity let Python reuse the previous
  mutant's `.pyc`, so runs execute the *prior* mutation's bytecode. This
  presents as intermittent, plausible, wrong results.
- **Use `git worktree add --detach`, not a copy of the module.** Copying
  `mesh.py` and `tests/` into a bare directory omits `plugins/`, `README.md`
  and `.gitattributes`, producing ~17 unrelated errors. A harness emitting
  unrelated failures cannot tell you whether a mutation was killed.
- **Never use `git checkout -- <file>` as mutation cleanup.** It reverts the
  mutation *and* any uncommitted work in that file. It fails silently and in
  the direction of confident wrong conclusions — the next run's failures look
  like the tests being wrong rather than the source having been rolled back.
- **Invent mutations after the fix exists.** A fix that kills exactly the
  reported mutant and nothing else is teaching to the test.
- **Label equivalent mutants as such.** A mutation that changes nothing
  observable (touching only mtime, or a no-op write) is not a coverage gap,
  and counting it as a survivor inflates the apparent problem.

## Platform assertions

`os.stat().st_mode` is synthesised from the read-only attribute on Windows
and reports `0o666` whatever the ACL says. An assertion there is not merely
failing — it cannot observe the mechanism that protects the file.

The wrong response is to stop asserting: that resolves an ambiguous
observation to whichever reading unblocks, and makes the ambiguity
permanent. Guard the POSIX assertion with
`skipUnless(os.name == "posix", ...)` **and** assert the real mechanism on
the other platform — `icacls` shows the ACL, and CI already runs Windows
jobs, so it is checkable continuously rather than once by hand.

When a check is skipped or narrowed, record what is now unverified. A silent
skip and a verified pass look identical in a green run.

**Confirm a test ran rather than skipped.** Test count up, skip count flat
is the arithmetic; a green from a test that cannot execute is worth nothing.

## Three instruments, three different gaps

None of these substitutes for the others:

| Instrument | Answers |
|---|---|
| CI on a pushed head sha | Did it actually run? |
| A reviewer's own local run | Is anything uncovered by the declared tests? |
| Mutation testing | Can these tests fail at all? |

Observed within one hour: CI caught a Windows failure review would not have,
review caught a hollow test CI was green on, and mutation testing caught
what neither did. By rule 2, the CI row cannot be satisfied by an author's
account of having run the suite — that is a claim, and the point of CI here
is that its output has no author in the conversation.

Note that CI is only independent if the workflow is. `.github/workflows` is
a file in the branch under review, and for a same-repo PR the workflow is
read from the head branch. Changes touching `.github/` need review by
someone the change cannot configure.

# Testing notes: verifying the instrument

These are lessons from #62 phase 2, written down because every one of them
produced a *confident wrong answer* rather than an obvious error, and each
was caught by someone checking the instrument rather than the result.

The single rule underneath all of it:

> **Verify the instrument before trusting its output, and check hardest when
> the output is what you hoped for.**

Confirming results are the ones that do not get checked. A sweep reporting
"all mutations survived" to someone who just claimed a gap, or "all tests
pass" to someone who just wrote them, is the exact shape that ships.

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

A related pattern, worth its own line: **the branch added late to satisfy a
reviewer is the branch the existing tests were not written for.** The same
defect recurred in three locations — generation, re-entry, and recovery —
and the recovery branch, added last and most likely to execute in practice,
was uncovered longest. When adding a branch, extend the test that covers its
siblings rather than the one that covers its shape.

## Mutation-testing harness requirements

If a harness cannot distinguish "the mutant survived" from "the code was
never mutated", its output is noise that reads like a finding.

- **Assert the mutant is present before running.** Not that the edit applied
  cleanly — that the string is verifiably in the file, in the right
  function. A harness that silently failed to inject reported five clean
  survivals from an unmodified file.
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
what neither did. A report of an execution is not evidence of an execution —
which is why the CI half cannot be satisfied by an author's account of
having run the suite.

Note that CI is only independent if the workflow is. `.github/workflows` is
a file in the branch under review, and for a same-repo PR the workflow is
read from the head branch. Changes touching `.github/` need review by
someone the change cannot configure.

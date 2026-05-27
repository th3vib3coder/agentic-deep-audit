# Reviewer Protocol

This protocol is mandatory for adversarial closure reviews of Agentic Deep Audit remediation batches.

## Fresh Workspace

- Use a reviewer identity distinct from the patch author and from the previous round's internal reviewers.
- Review from a clean checkout or disposable copy. Before pytest, run `git clean -ndx` and inspect the deletion plan; if the workspace is disposable, run `git clean -fdx`.
- Do not validate from the author's warm working tree when build, wheel or egg-info artifacts may exist.

## Required Checks

- Run `python -m pytest tests -q` and record the exact pass/fail count.
- Run `python -m compileall -q src hooks`.
- Run `git diff --check`.
- Confirm no residual `build/`, `dist/`, `*.egg-info`, `.coverage`, or `.pytest_cache` artifacts remain after tests.

## Anti-Pattern Enumeration

- For every claimed fix, grep the whole plugin for the fixed anti-pattern before accepting:
  - `INSERT OR REPLACE`
  - `load_json(..., [])`
  - dangerous git args and `=` forms
  - hook matcher tool names
  - sanitizer control/tag/bidi ranges
- Enumerate the live tool surface available in the current session and test policy coverage against risky `mcp__*` tools, not only the author's listed examples.
- For prior false claims, read the patched function line-by-line and cite the exact control flow that closes the claim.

## Verdict Discipline

- A reviewer may issue `ACCEPT` only for code they did not author.
- Any failing test, untested bypass, single-site fix for a multi-site anti-pattern, or unverifiable claim is `REDIRECT`.
- Report undeclared changes separately from the requested PR-R4 scope.

# Review Protocol

The plugin follows adversarial review discipline. The author of a sequence, artifact or remediation cannot issue ACCEPT on that same artifact.

## Internal Review

- Every implementation sequence starts with a pending row in `REVIEW_LEDGER.md`.
- A reviewer different from the author checks scope, tests, gate behavior and drift from `piano_doc/implementazione/`.
- REDIRECT or BLOCK findings need file and line, impact, requested patch and closing verification.
- The author remediates and returns the same scope for post-remediation review.
- Only after reviewer ACCEPT can the row move from pending to OK.

## External Review

Claude review receives the review packet only after internal ACCEPT and local validation. External verdicts are ACCEPT, REDIRECT or BLOCK, with scope stated explicitly.

## Stop Conditions

Stop and record a blocker when evidence coverage is missing, target code execution is requested in default mode, schema validation fails, artifact claims cannot be traced to evidence, or a reviewer finds unclosed drift.

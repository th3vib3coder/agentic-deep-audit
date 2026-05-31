# Release Process

How release decisions (REDIRECT / BLOCK), failed release gates, post-GO failures, rollback, and
adapter demotion are handled. This is the public governance contract referenced by the adapter
docs (e.g. `docs/adapters/claude-code.md`).

## Distinct reviewer requirement

The author of a change cannot issue ACCEPT on their own change. A reviewer distinct from the
author (or an external reviewer) issues ACCEPT / REDIRECT / BLOCK. No self-certification: a change
is not accepted until a distinct reviewer accepts it.

## REDIRECT

If a review returns REDIRECT, the change is not accepted. The author addresses each finding (file,
line, impact, requested fix) and returns the same scope for post-remediation review. The gate stays
in remediation; implementation does not proceed until a distinct reviewer issues ACCEPT.

## BLOCK

If a review returns BLOCK, the gate reopens. The next author records a new amendment and a fresh
internal review before another external review packet is prepared. A BLOCK expires any prior
operator GO.

## Failed release gate

If any release gate fails (unit suite, public-root scan, wheel install smoke, package-resource,
dependency-metadata, adapter independence, encoding/path, or the cross-OS CI matrix): stop sequence
execution; record the failure with the command output and the affected step in the review ledger;
demote the affected adapter or OS status; revert only the failed step's changes or apply a forward
fix under a new ledger row; rerun the failed gate and the nearest upstream dependency gate; resume
only after a distinct reviewer issues ACCEPT.

## Post-GO implementation failure

A failure that surfaces after operator GO (during implementation) follows the same procedure as a
failed release gate — stop, record, demote any affected status claim, revert-or-forward-fix under a
new ledger row, rerun, resume after ACCEPT. Operator GO is not a license to ship a red gate.

## Rollback

Rollback is per-step and forward-fix-preferred: revert only the current step's changes (never
unrelated work), or land a corrective commit under a new ledger row. The public package is
re-synced only after the gates pass again. Never force-push or rewrite published history to repair
a release; always land a forward corrective commit.

## Demotion

Any `first-class*` adapter is demoted before release if entry/runbook/required-file verification
fails twice, required files are absent from the exported package, security verification fails, OS
evidence is absent for a claimed OS, or validation cannot produce an observable failure mode.
Demotions are recorded in the public `RELEASE_CHECKLIST.md` demotion table with old status, new
status, evidence, and next review gate.

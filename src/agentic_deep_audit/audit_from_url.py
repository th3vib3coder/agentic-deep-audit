"""Auto config generation and orchestrator for the ``url`` workflow.

SEQ-URL-003 — ``generate_minimal_config``:
    Spec ``url_workflow/006_seq_auto_config.md`` (REMEDIATED
    2026-05-31). Emits a schema-conformant ``audit.config.yaml`` and
    validates it defense-in-depth via the real loader pipeline.

SEQ-URL-005 — ``run_url_workflow``:
    Spec ``url_workflow/008_seq_orchestrator.md``. Orchestrates
    parse_github_url + clone_repo + generate_minimal_config + cli.main(["run",
    ...]) and returns the int exit code that the CLI surfaces to the operator.

Both functions share this module so the ``url`` subcommand has a single
public surface; only ``run_url_workflow`` is invoked by the CLI dispatch and
all other helpers are also reachable from the orchestrator without an extra
cross-module hop.

Key REMEDIATION trail:

- REMEDIATION-001: the pre-REDIRECT template emitted ``target_path``,
  ``output_path``, ``allowed_roots``, ``allow_system_roots`` — all of which
  the audit_config schema rejects via ``additionalProperties: false``. The
  REMEDIATED template emits ONLY the 7 required fields (schema_version, repo,
  profile, mode, output_dir, target_context, binary_triage_consent) plus the
  ``repo`` subfields (kind, path, github). ``allowed_roots`` is propagated
  via the CLI ``--allowed-root`` flag by the orchestrator (sequence 008),
  NOT via YAML.
- REMEDIATION-002 (Codex 016 F1): the defense-in-depth probe forwards
  ``allowed_roots=(repo.path, audit_dir)`` so that
  ``normalize_run_config`` accepts the YAML even when ``output_dir`` lives
  outside the current working directory tree (e.g., in a tmp_path-rooted
  sandbox). Without the forwarded ``allowed_roots`` the probe was a false
  negative whenever the operator chose an out-of-cwd output_dir.
- REMEDIATION-006 (F-PLAN002-1, 2026-05-31): ``run_url_workflow`` passes
  ``audit_dir`` to ``clone_repo`` as a REQUIRED positional. The SEQ-005
  signature is ``clone_repo(parsed, output_dir, audit_dir, *, ...)``; omitting
  ``audit_dir`` is a ``TypeError`` at runtime that the mocked-clone tests
  could not catch. AC-14 covers this with REAL ``clone_repo`` and only
  ``subprocess.run`` mocked.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .audit_clone import ClonedRepo
from .audit_validate_common import ValidationResult
from .config import (
    ArgvOverrides,
    ConfigError,
    TARGET_CONTEXT_PRESETS,
    load_config_file,
    normalize_run_config,
)

#: Exit codes emitted by ``run_url_workflow`` (mapped from the spec table).
#:
#: ``EXIT_OK`` and ``EXIT_INVALID_URL`` align with argparse's own exit-code
#: conventions (0 for success, 2 for usage errors). ``EXIT_CLONE_FAILED``,
#: ``EXIT_CONFIG_FAILED``, and ``EXIT_PIPELINE_FAILED`` are URL-workflow
#: specific so the operator can distinguish a sandbox/network failure from a
#: schema/policy failure from a pipeline-phase failure without parsing logs.
EXIT_OK = 0
EXIT_INVALID_URL = 2
EXIT_CLONE_FAILED = 3
EXIT_CONFIG_FAILED = 4
EXIT_PIPELINE_FAILED = 5
#: Pipeline ``run`` succeeded but the finalize/validate step WITHHELD the final REPORT.md
#: (validation blockers — e.g. a genuinely secret-bearing corpus). Distinct from
#: ``EXIT_PIPELINE_FAILED`` so an automated caller can tell "audit produced, final report gated"
#: from "pipeline crashed"; mirrors the non-zero exit ``deep-audit validate`` returns on blockers.
#: FIX-3 (Tier-0, 2026-06-02). The human-facing blockers live in ``VALIDATION_REPORT.md``.
EXIT_VALIDATION_BLOCKED = 6

__all__ = [
    "ACCEPTED_PROFILES",
    "ACCEPTED_TARGET_CONTEXT_STRINGS",
    "DEFAULT_TARGET_CONTEXT",
    "EXIT_CLONE_FAILED",
    "EXIT_CONFIG_FAILED",
    "EXIT_INVALID_URL",
    "EXIT_OK",
    "EXIT_PIPELINE_FAILED",
    "EXIT_VALIDATION_BLOCKED",
    "ConfigGenerationError",
    "generate_minimal_config",
    "run_url_workflow",
]


#: Profile values accepted by ``generate_minimal_config``. Mirror of the
#: ``profile`` enum in ``audit_config.schema.json``; kept in sync with the
#: schema so a future schema change surfaces here at import time.
ACCEPTED_PROFILES: frozenset[str] = frozenset(
    {"minimal", "standard", "extended", "research"}
)

#: ``target_context`` preset strings accepted when ``target_context`` is
#: supplied as a string. Object-form (custom dict) input is allowed too and
#: bypasses this whitelist; the loader's ``canonicalize_target_context``
#: validates the object shape downstream.
ACCEPTED_TARGET_CONTEXT_STRINGS: frozenset[str] = frozenset(
    TARGET_CONTEXT_PRESETS.keys()
)

#: Default preset for ``target_context`` when the operator does not pass one.
#: Operator decision Q-NEW-2, re-opened 2026-06-02: the original ``MIT downstream`` default
#: imposed an ``allowed_languages == ["python"]`` reuse lens on EVERY audited repo, which made
#: the Understand-Anything (TypeScript/React) reuse cards all ``target_language_mismatch``.
#: The URL workflow now defaults to the language-agnostic preset (match-all) so the audit never
#: pre-filters by the wrong language. See ``url_workflow/026_seq_tier0_hardening.md``.
DEFAULT_TARGET_CONTEXT: str = "language-agnostic"


class ConfigGenerationError(Exception):
    """Raised when ``generate_minimal_config`` cannot produce a valid YAML.

    Carries a stable ``reason_code`` so callers branch on the reason without
    parsing English text. Reason codes:

    - ``INVALID_PROFILE`` — ``profile`` argument not in ``ACCEPTED_PROFILES``.
    - ``INVALID_TARGET_CONTEXT`` — ``target_context`` string arg not in
      ``ACCEPTED_TARGET_CONTEXT_STRINGS`` (object form is allowed).
    - ``AUDIT_DIR_OUTSIDE_OUTPUT`` — ``audit_dir`` not located under
      ``output_dir`` after resolve().
    - ``EXISTING_CONFIG_UNREADABLE`` — pre-existing ``audit.config.yaml``
      could not be parsed.
    - ``CONFIG_REPO_MISMATCH`` — pre-existing ``audit.config.yaml`` exists
      with a different ``repo.path``; refusing to silently clobber.
    - ``LOADER_REJECT`` — defense-in-depth probe via
      ``load_config_file`` + ``normalize_run_config`` raised ``ConfigError``
      after the YAML was written. The half-written file is deleted before
      re-raising so a caller cannot consume a schema-invalid config.
    """

    __slots__ = ("message", "reason_code")

    def __init__(self, message: str, reason_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code

    def __repr__(self) -> str:  # pragma: no cover - cosmetic only
        return (
            f"ConfigGenerationError(reason_code={self.reason_code!r}, "
            f"message={self.message!r})"
        )


def generate_minimal_config(
    cloned: ClonedRepo,
    profile: str,
    output_dir: Path,
    audit_dir: Path,
    target_context: str | dict[str, Any] = DEFAULT_TARGET_CONTEXT,
) -> Path:
    """Emit ``audit.config.yaml`` for the URL workflow and return its path.

    Parameters
    ----------
    cloned:
        ``ClonedRepo`` produced by ``audit_clone.clone_repo`` in SEQ-URL-002.
    profile:
        Audit profile (one of ``ACCEPTED_PROFILES``). The CLI defaults to
        ``"standard"`` (see SEQ-URL-004 in 007_seq_cli_url_subcommand.md).
    output_dir:
        Operator-supplied output root. ``audit_dir`` MUST resolve to a path
        under this directory.
    audit_dir:
        Audit-run directory (typically ``output_dir/audit_<safe_repo_name>``).
        The YAML is written at ``audit_dir/audit.config.yaml``; the directory
        is created if missing.
    target_context:
        Reuse-policy preset (string) or custom object. Defaults to
        ``DEFAULT_TARGET_CONTEXT`` per operator decision Q-NEW-2.

    Returns
    -------
    Path
        Absolute path of the written ``audit.config.yaml``.

    Raises
    ------
    ConfigGenerationError
        With a stable ``reason_code`` on validation or loader failure. See
        the class docstring for the reason-code enumeration.
    """
    # --- AC-16: profile whitelist (reject BEFORE any FS / YAML work). ---
    if profile not in ACCEPTED_PROFILES:
        raise ConfigGenerationError(
            f"profile not whitelisted: {profile}",
            "INVALID_PROFILE",
        )

    # --- AC-17: target_context whitelist (string form only). Object form is
    # passed through and validated downstream by canonicalize_target_context.
    if (
        isinstance(target_context, str)
        and target_context not in ACCEPTED_TARGET_CONTEXT_STRINGS
    ):
        raise ConfigGenerationError(
            f"target_context preset not whitelisted: {target_context}",
            "INVALID_TARGET_CONTEXT",
        )

    output_dir = output_dir.resolve()
    audit_dir = audit_dir.resolve()

    # --- AC-18: audit_dir MUST be under output_dir. relative_to() raises
    # ValueError if not, which we surface as a structured reason code.
    try:
        audit_dir.relative_to(output_dir)
    except ValueError as exc:
        raise ConfigGenerationError(
            f"audit_dir {audit_dir} not inside output_dir {output_dir}",
            "AUDIT_DIR_OUTSIDE_OUTPUT",
        ) from exc

    # --- AC-15: ISO-8601 UTC timestamp with Z suffix for the header. ---
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    # --- AC-3 / AC-12: emit ONLY the 7 required schema fields plus the
    # ``repo`` subobject. NO target_path / output_path / allowed_roots /
    # allow_system_roots; those are rejected by additionalProperties: false.
    config: dict[str, Any] = {
        "schema_version": "1.0",
        "repo": {
            "kind": "local",
            "path": str(cloned.clone_path.resolve()),
            "github": cloned.git_metadata.get("remote_url", ""),
        },
        "profile": profile,
        "mode": "source-audit",
        "output_dir": str(audit_dir),
        "target_context": target_context,
        "binary_triage_consent": False,
    }

    # --- AC-15: leading comment header with source URL / head SHA / timestamp.
    header_lines = [
        "# Generated by agentic-deep-audit url subcommand",
        f"# Source: {cloned.git_metadata.get('remote_url', 'unknown')}",
        f"# Head: {cloned.git_metadata.get('head_sha', 'unknown')}",
        f"# Generated at: {timestamp}",
        "",
    ]
    # --- AC-14: safe_dump (no Python-specific tags), sort_keys=True for
    # deterministic output (the regression-test diff is meaningful only if the
    # order is stable).
    yaml_body = yaml.safe_dump(config, sort_keys=True)
    yaml_content = "\n".join(header_lines) + yaml_body

    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigGenerationError(
            f"failed to create audit_dir: {exc}",
            "CONFIG_WRITE_FAILED",
        ) from exc
    config_path = audit_dir / "audit.config.yaml"

    # --- AC-19: no silent clobber. If a YAML already exists at the same path
    # with a different ``repo.path``, surface CONFIG_REPO_MISMATCH so the
    # operator decides; an unreadable existing YAML surfaces
    # EXISTING_CONFIG_UNREADABLE.
    if config_path.exists():
        try:
            existing = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as exc:
            raise ConfigGenerationError(
                f"failed to read existing config: {exc}",
                "EXISTING_CONFIG_UNREADABLE",
            ) from exc
        if existing is None:
            existing = {}
        if not isinstance(existing, dict):
            raise ConfigGenerationError(
                f"existing config must be a mapping, got {type(existing).__name__}",
                "EXISTING_CONFIG_INVALID",
            )
        existing_repo = existing.get("repo", {})
        if not isinstance(existing_repo, dict):
            raise ConfigGenerationError(
                f"existing config repo must be a mapping, got {type(existing_repo).__name__}",
                "EXISTING_CONFIG_INVALID",
            )
        existing_repo_path = existing_repo.get("path")
        if existing_repo_path != config["repo"]["path"]:
            raise ConfigGenerationError(
                f"config exists with different repo.path: {existing_repo_path}",
                "CONFIG_REPO_MISMATCH",
            )

    try:
        config_path.write_text(yaml_content, encoding="utf-8")
    except OSError as exc:
        raise ConfigGenerationError(
            f"failed to write config: {exc}",
            "CONFIG_WRITE_FAILED",
        ) from exc

    # --- AC-13 / AC-20 / AC-21: defense-in-depth probe.
    #
    # REMEDIATION-002 2026-05-31 (Codex 016 F1): the probe MUST pass the same
    # allowed_roots that the orchestrator will pass at run time. Without
    # them, normalize_run_config rejects repo.path whenever output_dir is
    # external to cwd (a routine condition under pytest's tmp_path or any
    # operator-chosen non-cwd output root). Forwarding
    # ``(repo.path, audit_dir)`` makes the probe verify BOTH schema
    # conformance AND allowed-root compatibility.
    #
    # If the probe fails we unlink the half-written file BEFORE re-raising so
    # a caller cannot consume a schema-invalid YAML; ``missing_ok=True`` keeps
    # the cleanup idempotent if the file was already removed in a race.
    try:
        loaded = load_config_file(config_path)
        normalize_run_config(
            loaded,
            ArgvOverrides(
                command="run",
                argv=["run", "--config", str(config_path)],
                allowed_roots=(
                    str(Path(config["repo"]["path"]).resolve()),
                    str(audit_dir.resolve()),
                ),
            ),
            config_path,
        )
    except ConfigError as exc:
        try:
            config_path.unlink(missing_ok=True)
        except OSError as unlink_exc:
            raise ConfigGenerationError(
                f"generated yaml rejected and cleanup failed: {unlink_exc}",
                "CONFIG_WRITE_FAILED",
            ) from unlink_exc
        raise ConfigGenerationError(
            f"generated yaml rejected by loader: {exc}",
            "LOADER_REJECT",
        ) from exc

    return config_path


# =============================================================================
# SEQ-URL-005 — Orchestrator (run_url_workflow)
# =============================================================================
#
# Spec: ``url_workflow/008_seq_orchestrator.md``.
#
# The orchestrator is the integration glue that turns a single URL into a full
# audit run by chaining the four primitives defined in 004/005/006/007:
#
#   parse_github_url  ->  clone_repo  ->  generate_minimal_config  ->  cli.main
#
# It owns:
#
# - the default ``output_dir`` policy (``./audit_runs/<safe_repo_name>/``);
# - the canonical ``audit_dir`` layout (``output_dir/audit/``);
# - the dry-run path (no clone, no config gen, no pipeline);
# - the auto-propagation of ``--allowed-root <clone_path>`` and
#   ``--allowed-root <output_path>`` BEFORE any user-supplied roots so the
#   loader's ``normalize_run_config`` accepts the sandbox paths;
# - the exit-code mapping that lets the CLI surface a structured failure
#   reason (2/3/4/5) without the operator having to grep stderr.
#
# Two REMEDIATION contracts pin invariants the test suite enforces:
#
# - REMEDIATION-006 (F-PLAN002-1): ``clone_repo`` MUST receive ``audit_dir``
#   as a REQUIRED positional. AC-14 is the integration test that verifies
#   this propagation end-to-end with REAL ``clone_repo`` and only
#   ``subprocess.run`` mocked.
# - REMEDIATION (Codex P1 allowed-root): the orchestrator NEVER emits
#   ``--allow-system-roots`` to the ``run`` subcommand. AC-11b enforces this.


def run_url_workflow(
    url: str,
    output_dir: str | None,
    profile: str,
    allowed_roots: list[str],
    dry_run: bool,
    timeout_seconds: int,
) -> int:
    """Drive the URL workflow end-to-end and return the CLI exit code.

    Parameters
    ----------
    url:
        Operator-supplied GitHub HTTPS URL. Validated by ``parse_github_url``;
        any rejection short-circuits to ``EXIT_INVALID_URL``.
    output_dir:
        Operator-supplied output root or ``None``. When ``None`` the default
        is ``./audit_runs/<safe_repo_name>/`` (AC-7).
    profile:
        Audit profile passed through to ``generate_minimal_config``. The CLI
        argparse layer has already restricted this to the accepted enum, but
        ``generate_minimal_config`` re-validates defense-in-depth.
    allowed_roots:
        User-supplied ``--allowed-root`` entries. The orchestrator
        UNCONDITIONALLY prepends ``clone_path`` and ``output_path`` (resolved
        absolute) BEFORE any user-supplied entries (AC-11). The user list is
        therefore additive and cannot displace the canonical roots.
    dry_run:
        When True the function prints the resolved plan to stdout and returns
        ``EXIT_OK`` WITHOUT calling clone_repo / generate_minimal_config /
        cli.main (AC-6). Any side-effecting tool that this branch were to
        invoke would defeat the dry-run contract.
    timeout_seconds:
        Per-clone timeout. Propagated verbatim into ``clone_repo`` (AC-12).

    Returns
    -------
    int
        ``EXIT_OK`` on success; ``EXIT_INVALID_URL`` (2) on URL validation
        failure; ``EXIT_CLONE_FAILED`` (3) on ``CloneError``;
        ``EXIT_CONFIG_FAILED`` (4) on ``ConfigGenerationError``;
        ``EXIT_PIPELINE_FAILED`` (5) iff ``cli.main`` returned exactly 1
        (the generic-error convention) — any other non-zero exit from the
        ``run`` subcommand is returned verbatim so specific argparse codes
        (e.g. 2 for unrecognized argv) reach the operator unchanged;
        ``EXIT_VALIDATION_BLOCKED`` (6) when the pipeline ran but the
        finalize/validate step withheld ``REPORT.md`` (validation blockers).
    """
    # Lazy imports keep the module top free of audit_clone + cli dependencies
    # at module load. This also avoids a potential circular import: cli.py
    # already imports audit_from_url lazily (the URL dispatch happens inside
    # ``main``), and pulling cli back at top-level here would tie the two
    # modules together more tightly than the spec wants.
    from .audit_clone import (
        CloneError,
        InvalidGithubUrlError,
        clone_repo,
        parse_github_url,
    )

    # ---- Step 1: parse / validate URL (AC-1) ------------------------------
    try:
        parsed = parse_github_url(url)
    except InvalidGithubUrlError as exc:
        print(f"ERROR: invalid url: {exc}", file=sys.stderr)
        return EXIT_INVALID_URL

    # ---- Step 2: resolve output and audit dirs (AC-7..AC-9) ---------------
    # AC-7: ``./audit_runs/<safe_repo_name>/`` default. The choice of cwd as
    # the anchor is deliberate — operators run the CLI from a project root
    # they trust; an absolute default rooted somewhere else would surprise.
    output_path = (
        Path(output_dir)
        if output_dir is not None
        else Path.cwd() / "audit_runs" / parsed.safe_repo_name
    )
    # AC-9: ``output_dir/audit/`` is the canonical audit layout. The same
    # path is later passed to clone_repo (for ENGINE_PRIMITIVES.json) AND to
    # generate_minimal_config (for audit.config.yaml + sibling artifacts).
    audit_dir = output_path / "audit"

    # ---- Step 3: dry-run branch (AC-6) ------------------------------------
    # No clone, no config gen, no pipeline. Print the plan so the operator
    # can sanity-check the resolved paths and re-run without ``--dry-run``.
    if dry_run:
        print("DRY RUN PLAN:")
        print(f"  url:             {parsed.clone_url}")
        print(f"  owner:           {parsed.owner}")
        print(f"  repo:            {parsed.repo}")
        print(f"  safe_repo_name:  {parsed.safe_repo_name}")
        print(f"  output_path:     {output_path.resolve()}")
        print(f"  audit_dir:       {audit_dir.resolve()}")
        print(f"  profile:         {profile}")
        print(f"  allowed_roots:   {list(allowed_roots)}")
        print(f"  timeout_seconds: {timeout_seconds}")
        return EXIT_OK

    # ---- Step 4: clone (AC-2, AC-10, AC-12, AC-14) ------------------------
    print(
        f"INFO: cloning {parsed.clone_url} "
        f"(safe_repo_name={parsed.safe_repo_name}) "
        f"to {output_path}/_clone/{parsed.safe_repo_name}",
        file=sys.stderr,
    )
    # REMEDIATION-006 (F-PLAN002-1, 2026-05-31): ``audit_dir`` is a REQUIRED
    # positional on ``clone_repo``. AC-14 is the integration test pinning
    # this contract with REAL clone_repo + mocked subprocess.run.
    try:
        cloned = clone_repo(
            parsed,
            output_path,
            audit_dir,
            timeout_seconds=timeout_seconds,
        )
    except CloneError as exc:
        print(
            f"ERROR: clone failed: {exc} (reason={exc.reason_code})",
            file=sys.stderr,
        )
        return EXIT_CLONE_FAILED

    head_sha = cloned.git_metadata.get("head_sha", "unknown")
    print(
        f"INFO: cloned head_sha={head_sha[:12]} branch={cloned.git_metadata.get('branch_name', 'unknown')}",
        file=sys.stderr,
    )

    # ---- Step 5: generate the minimal config (AC-3, AC-10) ----------------
    try:
        config_path = generate_minimal_config(
            cloned=cloned,
            profile=profile,
            output_dir=output_path,
            audit_dir=audit_dir,
        )
    except ConfigGenerationError as exc:
        print(
            f"ERROR: config generation failed: {exc} (reason={exc.reason_code})",
            file=sys.stderr,
        )
        return EXIT_CONFIG_FAILED

    # ---- Step 6: invoke the existing pipeline via cli.main (AC-4, AC-5,
    # AC-10, AC-11, AC-11b) -------------------------------------------------
    # The lazy import here mirrors cli.py's own lazy import of this module;
    # keeping it lazy means a dry-run path never touches the cli module
    # (already exercised by AC-6).
    from .cli import main as cli_main

    run_argv: list[str] = ["run", "--config", str(config_path)]
    # AC-11 (REMEDIATED Codex P1): orchestrator-canonical roots come FIRST so
    # ``normalize_run_config`` accepts ``repo.path`` (the clone) and the audit
    # output path even when the operator's cwd is unrelated. ``resolve()`` is
    # mandatory because ``normalize_run_config`` compares resolved paths.
    run_argv.extend(["--allowed-root", str(cloned.clone_path.resolve())])
    run_argv.extend(["--allowed-root", str(output_path.resolve())])
    # AC-11: user-supplied roots are appended AFTER the canonical pair. They
    # are additive (allow-list union); they cannot displace the canonical
    # roots and they cannot grant ``--allow-system-roots`` (AC-11b).
    for extra in allowed_roots:
        run_argv.extend(["--allowed-root", extra])

    print(
        f"INFO: invoking deep-audit run --config {config_path} "
        f"profile={profile}",
        file=sys.stderr,
    )
    # REMEDIATION-S008-1 Fix 1 (F-SF-08-3): wrap cli_main with a broad safety
    # net so any unhandled Exception from the pipeline (RuntimeError, KeyError,
    # OSError leak from clone/config defense-in-depth, ...) surfaces as a
    # structured EXIT_PIPELINE_FAILED instead of crashing the orchestrator and
    # leaking a traceback to the operator. We intentionally catch only
    # ``Exception`` and not ``BaseException``: KeyboardInterrupt and SystemExit
    # must propagate so the operator can Ctrl-C cleanly and so sys.exit(N)
    # invariants in deeper layers continue to terminate the process normally.
    try:
        exit_code = cli_main(run_argv)
    except Exception as exc:  # noqa: BLE001 - intentional broad safety net per REMEDIATION-S008-1 (F-SF-08-3)
        print(
            f"ERROR: pipeline raised unhandled exception: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return EXIT_PIPELINE_FAILED

    if exit_code != 0:
        print(
            f"ERROR: pipeline run failed with exit {exit_code}",
            file=sys.stderr,
        )
        # The spec table maps the "generic" non-zero exit 1 to our structured
        # ``EXIT_PIPELINE_FAILED`` (5) so the operator immediately knows the
        # failure was inside the pipeline (not URL / clone / config). Any
        # OTHER non-zero exit (e.g. argparse 2 for unrecognized argv, future
        # 6+ codes) is propagated verbatim so the specific signal survives.
        return EXIT_PIPELINE_FAILED if exit_code == 1 else exit_code

    # ---- Step 7: artifact-presence smoke check (AC-5, AC-10; F-SF-08-5) ----
    # Non-blocking presence check for the three baseline markers. We WARN on
    # missing markers but do NOT return here; the authoritative gate is the
    # finalize step (Step 8) below. REMEDIATION-S008-1 Fix 3 invariant: an
    # "OK" success marker is NEVER emitted alongside a "WARNING: audit
    # incomplete" line (the OK print in Step 8 is gated on ``not missing``).
    expected_artifacts = ("RUN_CONFIG.json", "TOOL_STATUS.json", "PROGRESS.md")
    missing = [name for name in expected_artifacts if not (audit_dir / name).exists()]
    if missing:
        print(
            f"WARNING: audit incomplete (missing artifacts: {missing})",
            file=sys.stderr,
        )
        print(f"audit dir: {audit_dir}", file=sys.stderr)

    # ---- Step 8 (FIX-3, Tier-0 2026-06-02): finalize so REPORT.md is produced
    # end-to-end. The ``run`` subcommand stops after the pipeline phases and
    # NEVER calls finalize_audit, so historically ``deep-audit url`` produced
    # every artifact EXCEPT the human-facing REPORT.md (emitted only by the
    # validate/finalize path) — the operator had to run ``deep-audit validate``
    # by hand. We finalize here so the URL workflow is genuinely end-to-end.
    #
    # finalize_audit returns a validation-result object (it does not raise on
    # validation blockers). A failed finalize WITHHOLDS the report and returns
    # EXIT_VALIDATION_BLOCKED (6) — a distinct non-zero signal, NOT exit-0 — so an
    # automated caller can distinguish "report gated by validation" from a clean
    # run; the blockers are recorded in VALIDATION_REPORT.md, which the
    # operator/agent reads. We deliberately do NOT echo the raw blocker text to
    # stderr (it can contain artifact paths and would couple this diagnostic to
    # validator wording); a count + a pointer to the report is the stable,
    # leak-free signal. See url_workflow/026_seq_tier0_hardening.md (FIX-3).
    from .cli import finalize_audit

    finalize_command = f"deep-audit url {url} --profile {profile}"
    try:
        finalize_result: ValidationResult = finalize_audit(audit_dir, finalize_command)
    except Exception as exc:  # noqa: BLE001 - never crash the orchestrator; surface the crash.
        # A finalize CRASH (OSError writing the report, or a programming bug in validate/report
        # code) is distinct from a routine validation BLOCK (handled below via finalize_result.ok).
        # We say "crashed" and include a truncated message so a genuine bug is not mistaken for a
        # benign gated report; exit stays EXIT_VALIDATION_BLOCKED (no clean report produced either
        # way). Swarm P2.
        print(
            f"WARNING: finalize step crashed; final report withheld: "
            f"{type(exc).__name__}: {str(exc)[:200]}",
            file=sys.stderr,
        )
        print(f"audit dir: {audit_dir}", file=sys.stderr)
        return EXIT_VALIDATION_BLOCKED

    if not finalize_result.ok:
        print(
            "WARNING: final report withheld; audit validation has "
            f"{len(finalize_result.errors)} blocker(s); see VALIDATION_REPORT.md",
            file=sys.stderr,
        )
        print(f"audit dir: {audit_dir}", file=sys.stderr)
        return EXIT_VALIDATION_BLOCKED

    # finalize ok -> REPORT.md produced. Suppress the OK marker when the baseline smoke check
    # flagged missing markers, preserving REMEDIATION-S008-1 Fix 3 (never co-emit WARNING+OK).
    if not missing:
        print(f"OK: audit finalized; REPORT.md written to {audit_dir}", file=sys.stderr)
    return EXIT_OK

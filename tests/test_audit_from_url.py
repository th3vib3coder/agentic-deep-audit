"""Tests for ``agentic_deep_audit.audit_from_url.generate_minimal_config`` (SEQ-URL-003).

Covers AC-1..AC-21 of ``url_workflow/006_seq_auto_config.md``
(REMEDIATION-002 added AC-20 and AC-21 for the loader-probe defense-in-depth).

The most important AC is AC-13: the generated YAML must pass the real
``load_config_file`` + ``normalize_run_config`` pipeline without raising
``ConfigError``. AC-20 verifies the probe also passes when ``output_dir`` is
external to cwd (because the probe forwards ``allowed_roots``). AC-21 is a
mutation test confirming the probe surfaces ``LOADER_REJECT`` when an
extra-field (``target_path``) is injected into the config dict — this proves
the defense-in-depth is wired correctly against ``additionalProperties: false``.
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from agentic_deep_audit.audit_clone import (
    CloneError,
    ClonedRepo,
    InvalidGithubUrlError,
    ParsedGithubUrl,
)
from agentic_deep_audit.audit_from_url import (
    ACCEPTED_PROFILES,
    ACCEPTED_TARGET_CONTEXT_STRINGS,
    DEFAULT_TARGET_CONTEXT,
    EXIT_CLONE_FAILED,
    EXIT_CONFIG_FAILED,
    EXIT_INVALID_URL,
    EXIT_OK,
    EXIT_PIPELINE_FAILED,
    EXIT_VALIDATION_BLOCKED,
    ConfigGenerationError,
    generate_minimal_config,
    run_url_workflow,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_clone_dir(root: Path) -> Path:
    """Create a minimally-valid local clone (with .git marker) and return its path."""
    clone_path = (root / "_clone" / "octocat__hello-world").resolve()
    clone_path.mkdir(parents=True, exist_ok=True)
    (clone_path / ".git").mkdir(exist_ok=True)
    return clone_path


def _make_cloned_repo(clone_path: Path) -> ClonedRepo:
    """Build a ClonedRepo fixture matching the SEQ-005 dataclass shape."""
    return ClonedRepo(
        clone_path=clone_path,
        safe_repo_name="octocat__hello-world",
        git_metadata={
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "remote_url": "https://github.com/octocat/Hello-World.git",
            "branch_name": "main",
        },
        timeout_seconds=300,
    )


@pytest.fixture()
def cloned_and_dirs(tmp_path: Path) -> tuple[ClonedRepo, Path, Path]:
    """Standard fixture: returns (cloned, output_dir, audit_dir).

    ``audit_dir`` lives under ``output_dir/audit_octocat__hello-world`` so the
    ``audit_dir.relative_to(output_dir)`` check passes.
    """
    output_dir = (tmp_path / "runs").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_dir = (output_dir / "audit_octocat__hello-world").resolve()
    clone_path = _make_clone_dir(output_dir)
    return _make_cloned_repo(clone_path), output_dir, audit_dir


# ---------------------------------------------------------------------------
# AC-1: function returns existing path
# ---------------------------------------------------------------------------


def test_generate_config_returns_existing_path(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-1: function returns a Path to an existing YAML file."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    result = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert isinstance(result, Path)
    assert result.exists()
    assert result.is_file()
    assert result.name == "audit.config.yaml"


# ---------------------------------------------------------------------------
# AC-2: YAML parses as dict
# ---------------------------------------------------------------------------


def test_generate_config_parses_as_dict(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-2: YAML body parses via ``yaml.safe_load`` to a dict."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)


# ---------------------------------------------------------------------------
# AC-3: all 7 required schema fields present
# ---------------------------------------------------------------------------


def test_generate_config_required_fields_present(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-3: YAML contains all 7 required fields per the audit_config schema."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "repo",
        "profile",
        "mode",
        "output_dir",
        "target_context",
        "binary_triage_consent",
    }
    assert required.issubset(loaded.keys())


# ---------------------------------------------------------------------------
# AC-4: repo.kind == "local"
# ---------------------------------------------------------------------------


def test_generate_config_repo_kind_local(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-4: ``repo.kind`` is ``"local"`` (URL workflow always clones first)."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["repo"]["kind"] == "local"


# ---------------------------------------------------------------------------
# AC-5: repo.path is absolute path to clone_path
# ---------------------------------------------------------------------------


def test_generate_config_repo_path(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-5: ``repo.path`` is the absolute resolved clone_path."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    repo_path = Path(loaded["repo"]["path"])
    assert repo_path.is_absolute()
    assert repo_path.resolve() == cloned.clone_path.resolve()


# ---------------------------------------------------------------------------
# AC-6: repo.github is the clone_url from git_metadata
# ---------------------------------------------------------------------------


def test_generate_config_repo_github_url(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-6: ``repo.github`` is the ``remote_url`` from ``ClonedRepo.git_metadata``."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["repo"]["github"] == cloned.git_metadata["remote_url"]


# ---------------------------------------------------------------------------
# AC-7: output_dir is absolute path to audit_dir
# ---------------------------------------------------------------------------


def test_generate_config_output_dir(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-7: ``output_dir`` is the absolute resolved ``audit_dir``."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    yaml_output = Path(loaded["output_dir"])
    assert yaml_output.is_absolute()
    assert yaml_output.resolve() == audit_dir.resolve()


# ---------------------------------------------------------------------------
# AC-8: profile validates against schema enum
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("profile", sorted(ACCEPTED_PROFILES))
def test_generate_config_profile_enum(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
    profile: str,
) -> None:
    """AC-8: every whitelisted profile is accepted and written to the YAML."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, profile, output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["profile"] == profile


# ---------------------------------------------------------------------------
# AC-9: mode == "source-audit"
# ---------------------------------------------------------------------------


def test_generate_config_mode_source_audit(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-9: ``mode`` is always ``"source-audit"`` for the URL workflow."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["mode"] == "source-audit"


# ---------------------------------------------------------------------------
# AC-10: target_context whitelisted preset string
# ---------------------------------------------------------------------------


def test_generate_config_target_context_preset(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-10: ``target_context`` default is a whitelisted preset string."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["target_context"] == DEFAULT_TARGET_CONTEXT
    assert loaded["target_context"] in ACCEPTED_TARGET_CONTEXT_STRINGS


def test_default_target_context_is_language_agnostic_not_python_only(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """FIX-1 (Q-NEW-2 re-opened 2026-06-02): the URL-mode default target_context must NOT
    impose a python-only reuse lens.

    The Understand-Anything audit (a TypeScript/React repo) had every reuse card flagged
    ``target_language_mismatch`` because the default ``MIT downstream`` canonicalized to
    ``allowed_languages == ['python']``. The URL-mode default must be language-agnostic
    (empty allowed_languages -> canonicalizes to ['*'] = match-all)."""
    from agentic_deep_audit.audit_reuse import language_match
    from agentic_deep_audit.config import canonicalize_target_context

    canon = canonicalize_target_context(DEFAULT_TARGET_CONTEXT)
    assert canon["allowed_languages"] == ["*"]
    # The exact Understand-Anything symptom: a TS repo must not be language-mismatched by default.
    assert language_match(["typescript"], canon) is True
    assert language_match(["python"], canon) is True


# ---------------------------------------------------------------------------
# AC-11: binary_triage_consent: false
# ---------------------------------------------------------------------------


def test_generate_config_no_binary_consent(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-11: ``binary_triage_consent`` is ``False`` (URL workflow is source-only)."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert loaded["binary_triage_consent"] is False


# ---------------------------------------------------------------------------
# AC-12: YAML does NOT contain legacy/non-schema fields
# ---------------------------------------------------------------------------


def test_generate_config_no_legacy_fields(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-12: YAML omits fields not in the schema (``additionalProperties: false``).

    The pre-REMEDIATION-001 version emitted ``target_path``, ``output_path``,
    ``allowed_roots``, ``allow_system_roots`` — all of which the schema
    rejects. The REMEDIATED template must NOT contain them.
    """
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    forbidden = {"target_path", "output_path", "allowed_roots", "allow_system_roots"}
    assert forbidden.isdisjoint(loaded.keys())


# ---------------------------------------------------------------------------
# AC-13: YAML passes the real loader pipeline (the P0 contract)
# ---------------------------------------------------------------------------


def test_generate_config_passes_loader(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-13: end-to-end probe — generated YAML loads cleanly through
    ``load_config_file`` + ``normalize_run_config`` without ``ConfigError``.

    This is the P0 contract. If this fails the entire approach is broken;
    the pre-REMEDIATION-001 template hit ``additionalProperties: false`` on
    ``target_path`` / ``output_path`` / ``allowed_roots`` / ``allow_system_roots``.
    The generator itself runs this probe defense-in-depth before returning, so
    if ``generate_minimal_config`` returns at all the probe has succeeded.
    """
    from agentic_deep_audit.config import (
        ArgvOverrides,
        load_config_file,
        normalize_run_config,
    )

    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)

    loaded = load_config_file(path)
    normalized = normalize_run_config(
        loaded,
        ArgvOverrides(
            command="run",
            argv=["run", "--config", str(path)],
            allowed_roots=(
                str(cloned.clone_path.resolve()),
                str(audit_dir.resolve()),
            ),
        ),
        path,
    )
    assert isinstance(normalized, dict)
    assert normalized["mode"] == "source-audit"
    assert normalized["profile"] == "standard"


# ---------------------------------------------------------------------------
# AC-14: YAML uses safe_dump (no Python-specific tags)
# ---------------------------------------------------------------------------


def test_generate_config_safe_yaml(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-14: the serialized YAML contains no ``!!python/`` tags.

    ``yaml.safe_dump`` emits only the safe-YAML core types; any leak of
    ``yaml.dump`` Python tags would indicate use of the unsafe dumper.
    """
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    text = path.read_text(encoding="utf-8")
    assert "!!python/" not in text
    # safe_load round-trips cleanly (proof of "safe" type domain).
    assert isinstance(yaml.safe_load(text), dict)


# ---------------------------------------------------------------------------
# AC-15: header comment carries source URL, head SHA, ISO timestamp UTC
# ---------------------------------------------------------------------------


def test_generate_config_header(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-15: header comment includes source URL, head SHA, ISO-8601 UTC timestamp."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    text = path.read_text(encoding="utf-8")
    assert "# Generated by agentic-deep-audit url subcommand" in text
    assert f"# Source: {cloned.git_metadata['remote_url']}" in text
    assert f"# Head: {cloned.git_metadata['head_sha']}" in text
    # ISO-8601 UTC with Z suffix; relaxed regex tolerates microsecond precision.
    assert re.search(
        r"# Generated at: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z",
        text,
    )


# ---------------------------------------------------------------------------
# AC-16: invalid profile rejected before write
# ---------------------------------------------------------------------------


def test_generate_config_invalid_profile(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-16: profile not in ACCEPTED_PROFILES rejected with ``INVALID_PROFILE``."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "bogus-profile", output_dir, audit_dir)
    assert excinfo.value.reason_code == "INVALID_PROFILE"
    # No file written when the input is rejected.
    assert not (audit_dir / "audit.config.yaml").exists()


# ---------------------------------------------------------------------------
# AC-17: invalid target_context string rejected before write
# ---------------------------------------------------------------------------


def test_generate_config_invalid_target_context(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-17: unknown target_context preset string rejected with
    ``INVALID_TARGET_CONTEXT``. Object form (custom dict) is allowed."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(
            cloned, "standard", output_dir, audit_dir, target_context="bogus-context"
        )
    assert excinfo.value.reason_code == "INVALID_TARGET_CONTEXT"
    assert not (audit_dir / "audit.config.yaml").exists()


# ---------------------------------------------------------------------------
# AC-18: audit_dir outside output_dir rejected
# ---------------------------------------------------------------------------


def test_generate_config_audit_dir_inside_output(
    tmp_path: Path,
) -> None:
    """AC-18: ``audit_dir`` not under ``output_dir`` rejected with
    ``AUDIT_DIR_OUTSIDE_OUTPUT``."""
    output_dir = (tmp_path / "runs").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    # audit_dir is a sibling of output_dir, NOT under it.
    audit_dir = (tmp_path / "elsewhere" / "audit").resolve()
    clone_path = _make_clone_dir(output_dir)
    cloned = _make_cloned_repo(clone_path)

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "AUDIT_DIR_OUTSIDE_OUTPUT"


# ---------------------------------------------------------------------------
# AC-19: existing config with different repo.path raises (no silent clobber)
# ---------------------------------------------------------------------------


def test_generate_config_no_silent_clobber(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """AC-19: pre-existing ``audit.config.yaml`` for a different repo is NOT clobbered.

    Surfaces as ``CONFIG_REPO_MISMATCH`` so the operator notices and decides.
    """
    cloned, output_dir, audit_dir = cloned_and_dirs
    audit_dir.mkdir(parents=True, exist_ok=True)
    existing_path = audit_dir / "audit.config.yaml"
    existing_payload = {
        "schema_version": "1.0",
        "repo": {
            "kind": "local",
            "path": str((output_dir / "_clone" / "different__repo").resolve()),
            "github": "https://github.com/different/repo.git",
        },
        "profile": "standard",
        "mode": "source-audit",
        "output_dir": str(audit_dir.resolve()),
        "target_context": DEFAULT_TARGET_CONTEXT,
        "binary_triage_consent": False,
    }
    existing_path.write_text(yaml.safe_dump(existing_payload), encoding="utf-8")

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "CONFIG_REPO_MISMATCH"
    # Existing file not overwritten.
    loaded = yaml.safe_load(existing_path.read_text(encoding="utf-8"))
    assert loaded["repo"]["github"] == "https://github.com/different/repo.git"


# ---------------------------------------------------------------------------
# AC-19b: existing config that is unreadable surfaces EXISTING_CONFIG_UNREADABLE
# ---------------------------------------------------------------------------


def test_generate_config_existing_config_unreadable(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """Coverage: existing ``audit.config.yaml`` with non-YAML / malformed body
    is rejected via ``EXISTING_CONFIG_UNREADABLE`` rather than silently clobbered.
    """
    cloned, output_dir, audit_dir = cloned_and_dirs
    audit_dir.mkdir(parents=True, exist_ok=True)
    bad_path = audit_dir / "audit.config.yaml"
    # Intentionally-broken YAML: mismatched braces trigger yaml.YAMLError.
    bad_path.write_text(":\n  - [unbalanced\n", encoding="utf-8")

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "EXISTING_CONFIG_UNREADABLE"


def test_generate_config_existing_config_scalar_rejected(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """Existing YAML that parses but is not a mapping must not leak AttributeError."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    audit_dir.mkdir(parents=True, exist_ok=True)
    bad_path = audit_dir / "audit.config.yaml"
    bad_path.write_text("42\n", encoding="utf-8")

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "EXISTING_CONFIG_INVALID"


def test_generate_config_existing_config_repo_scalar_rejected(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
) -> None:
    """Existing YAML is a mapping but its ``repo`` value is a scalar.

    Sibling to the root-scalar case above: here the top-level config parses to a
    dict (passing the first guard) but ``repo`` is a bare string, so
    ``existing.get("repo")`` is not a mapping. Without the second isinstance
    guard, the subsequent ``existing_repo.get("path")`` would leak
    ``AttributeError: 'str' object has no attribute 'get'``. It must instead
    surface ``EXISTING_CONFIG_INVALID``.
    """
    cloned, output_dir, audit_dir = cloned_and_dirs
    audit_dir.mkdir(parents=True, exist_ok=True)
    bad_path = audit_dir / "audit.config.yaml"
    # Mapping whose ``repo`` is a scalar str -> existing_repo is not a dict.
    bad_path.write_text("repo: hello\n", encoding="utf-8")

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "EXISTING_CONFIG_INVALID"


def test_generate_config_mkdir_oserror_surfaces_structured(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Filesystem mkdir failures must surface as ConfigGenerationError, not raw OSError."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    real_mkdir = Path.mkdir

    def _selective_mkdir(self, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if self == audit_dir:
            raise OSError("permission denied")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _selective_mkdir)

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "CONFIG_WRITE_FAILED"


def test_generate_config_write_oserror_surfaces_structured(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Config write failures must surface as ConfigGenerationError, not raw OSError."""
    cloned, output_dir, audit_dir = cloned_and_dirs
    real_write_text = Path.write_text

    def _selective_write_text(self, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if self == audit_dir / "audit.config.yaml":
            raise OSError("disk full")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _selective_write_text)

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "CONFIG_WRITE_FAILED"


# ---------------------------------------------------------------------------
# AC-20 (REMEDIATION-002 Codex 016 F1): probe passes with external output_dir
# ---------------------------------------------------------------------------


def test_generate_config_external_output_dir_loader_passes(
    tmp_path: Path,
) -> None:
    """AC-20: the defense-in-depth probe MUST pass even when ``output_dir`` is
    ESTERNO a ``cwd`` (e.g. under ``tmp_path``).

    The pre-REMEDIATION-002 probe omitted ``allowed_roots`` from
    ``ArgvOverrides``; that caused ``normalize_run_config`` to reject
    ``repo.path`` because the cwd-based default allowed_roots do not contain
    the tmp_path tree. The REMEDIATED probe forwards
    ``allowed_roots=(repo.path, audit_dir)`` so the loader accepts the YAML.
    """
    output_dir = (tmp_path / "external_runs").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_dir = (output_dir / "audit_remote").resolve()
    clone_path = _make_clone_dir(output_dir)
    cloned = _make_cloned_repo(clone_path)

    # Probe runs inside generate_minimal_config; if it raised the call
    # would have re-raised as ConfigGenerationError(LOADER_REJECT).
    config_path = generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert config_path.exists()
    loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert Path(loaded["repo"]["path"]).resolve() == clone_path.resolve()
    assert Path(loaded["output_dir"]).resolve() == audit_dir.resolve()


# ---------------------------------------------------------------------------
# AC-21 (REMEDIATION-002 Codex 016 F1): mutation — extra field triggers
# LOADER_REJECT and the partial file is deleted.
# ---------------------------------------------------------------------------


def test_generate_config_loader_rejects_extra_field(
    cloned_and_dirs: tuple[ClonedRepo, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-21: injecting an extra-field (``target_path``) into the YAML serialization
    causes the defense-in-depth probe to surface ``LOADER_REJECT`` and the
    half-written file is removed.

    The mutation is applied via monkeypatching ``yaml.safe_dump`` inside the
    ``audit_from_url`` module so the on-disk YAML contains ``target_path:`` —
    which the schema's ``additionalProperties: false`` rejects.
    """
    import agentic_deep_audit.audit_from_url as module_under_test

    cloned, output_dir, audit_dir = cloned_and_dirs

    real_safe_dump = yaml.safe_dump

    def mutating_safe_dump(data, *args, **kwargs):
        if isinstance(data, dict):
            data = dict(data)
            data["target_path"] = "/tmp/illegal-extra-field"
        return real_safe_dump(data, *args, **kwargs)

    monkeypatch.setattr(module_under_test.yaml, "safe_dump", mutating_safe_dump)

    with pytest.raises(ConfigGenerationError) as excinfo:
        generate_minimal_config(cloned, "standard", output_dir, audit_dir)
    assert excinfo.value.reason_code == "LOADER_REJECT"
    # Defense in depth: the half-written file must be deleted so a follow-up
    # caller does not consume a schema-invalid YAML.
    assert not (audit_dir / "audit.config.yaml").exists()


# =============================================================================
# SEQ-URL-005 — Orchestrator (run_url_workflow) tests
# =============================================================================
#
# Spec: ``url_workflow/008_seq_orchestrator.md``.
#
# These 14 tests cover AC-1..AC-14 of the orchestrator. AC-1..AC-13 mock the
# four underlying primitives (parse_github_url, clone_repo,
# generate_minimal_config, cli.main) so the orchestrator's branching and exit
# code mapping are exercised without touching the network, the filesystem
# beyond ``tmp_path``, or the real ~30-phase pipeline.
#
# AC-14 (REMEDIATION-006 / F-PLAN002-1) is the ONE integration test that
# leaves ``clone_repo`` REAL and mocks only ``subprocess.run``. Its purpose
# is to verify that ``run_url_workflow`` actually propagates ``audit_dir`` to
# ``clone_repo`` as a positional. Mocking ``clone_repo`` would mask the
# regression: a wrong-arity call would be silently accepted by the mock.


def _stub_finalize_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub ``cli.finalize_audit`` to a passing result.

    The orchestration AC tests mock the pipeline (``cli.main``) but never produce a real audit, so
    the real ``finalize_audit`` (FIX-3) would reject their stub/empty audit dirs and return
    ``EXIT_VALIDATION_BLOCKED``. Those tests assert WIRING (exit mapping, allowed-root ordering,
    diagnostics, audit_dir propagation), NOT finalize, so we stub finalize to "ok" to isolate them.
    The finalize-blocked path has its own dedicated test
    (``test_run_url_workflow_blocks_when_finalize_reports_validation_failure``)."""
    from types import SimpleNamespace

    monkeypatch.setattr(
        "agentic_deep_audit.cli.finalize_audit",
        lambda *_a, **_k: SimpleNamespace(ok=True, errors=[]),
    )


def _make_parsed() -> ParsedGithubUrl:
    """Build a minimal ParsedGithubUrl matching the SEQ-URL-001 dataclass shape."""
    return ParsedGithubUrl(
        owner="octocat",
        repo="Hello-World",
        safe_repo_name="octocat__hello-world",
        clone_url="https://github.com/octocat/Hello-World.git",
    )


def _make_cloned_repo_for_orchestrator(tmp_path: Path) -> ClonedRepo:
    """Build a ClonedRepo with an on-disk clone_path so .resolve() is meaningful."""
    clone_path = (tmp_path / "_clone" / "octocat__hello-world").resolve()
    clone_path.mkdir(parents=True, exist_ok=True)
    (clone_path / ".git").mkdir(exist_ok=True)
    return ClonedRepo(
        clone_path=clone_path,
        safe_repo_name="octocat__hello-world",
        git_metadata={
            "head_sha": "0123456789abcdef0123456789abcdef01234567",
            "remote_url": "https://github.com/octocat/Hello-World.git",
            "branch_name": "main",
        },
        timeout_seconds=300,
    )


# ---------------------------------------------------------------------------
# AC-1: invalid URL -> EXIT_INVALID_URL (2)
# ---------------------------------------------------------------------------


def test_run_url_workflow_invalid_url(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-1: URL validation failure short-circuits to exit code 2 (EXIT_INVALID_URL).

    Mutation guard: changing EXIT_INVALID_URL from 2 to any other code makes
    this test fail (see spec mutation-test note).
    """
    import agentic_deep_audit.audit_from_url as module_under_test

    def fake_parse(_url: str) -> ParsedGithubUrl:
        raise InvalidGithubUrlError("bad", "URL_PATTERN_MISMATCH")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", fake_parse
    )

    exit_code = module_under_test.run_url_workflow(
        url="not-a-url",
        output_dir=str(tmp_path / "out"),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_INVALID_URL
    captured = capsys.readouterr()
    assert "invalid url" in captured.err.lower()


# ---------------------------------------------------------------------------
# AC-2: clone failure -> EXIT_CLONE_FAILED (3)
# ---------------------------------------------------------------------------


def test_run_url_workflow_clone_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-2: CloneError propagates as exit code 3 (EXIT_CLONE_FAILED).

    The mock raises CloneError(GIT_CLONE_FAILED) which mirrors a real
    upstream-git refusal; the reason_code must reach stderr.
    """
    parsed = _make_parsed()
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )

    def fake_clone(*_args, **_kwargs):
        raise CloneError("simulated failure", "GIT_CLONE_FAILED")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo", fake_clone
    )

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(tmp_path / "out"),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_CLONE_FAILED
    captured = capsys.readouterr()
    assert "clone failed" in captured.err.lower()
    assert "GIT_CLONE_FAILED" in captured.err


# ---------------------------------------------------------------------------
# AC-3: config generation failure -> EXIT_CONFIG_FAILED (4)
# ---------------------------------------------------------------------------


def test_run_url_workflow_config_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-3: ConfigGenerationError surfaces as exit code 4 (EXIT_CONFIG_FAILED).

    Use the real cloned-repo fixture so clone_path is on-disk for the
    diagnostics path; only generate_minimal_config raises.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )

    def fake_generate(**_kwargs):
        raise ConfigGenerationError("simulated", "LOADER_REJECT")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        fake_generate,
    )

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(tmp_path / "out"),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_CONFIG_FAILED
    captured = capsys.readouterr()
    assert "config generation failed" in captured.err.lower()
    assert "LOADER_REJECT" in captured.err


# ---------------------------------------------------------------------------
# AC-4: pipeline run failure -> mapped exit code
# ---------------------------------------------------------------------------


def test_run_url_workflow_run_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-4: cli.main non-zero return is propagated with the spec mapping:
    exit 1 -> EXIT_PIPELINE_FAILED (5); any other non-zero -> passthrough.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: tmp_path / "audit.config.yaml",
    )

    # Mapping case A: cli.main returns 1 -> orchestrator must return 5.
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 1)
    assert (
        run_url_workflow(
            url="https://github.com/octocat/Hello-World",
            output_dir=str(tmp_path / "out"),
            profile="standard",
            allowed_roots=[],
            dry_run=False,
            timeout_seconds=300,
        )
        == EXIT_PIPELINE_FAILED
    )

    # Mapping case B: cli.main returns 7 -> orchestrator must return 7 verbatim.
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 7)
    assert (
        run_url_workflow(
            url="https://github.com/octocat/Hello-World",
            output_dir=str(tmp_path / "out2"),
            profile="standard",
            allowed_roots=[],
            dry_run=False,
            timeout_seconds=300,
        )
        == 7
    )


# ---------------------------------------------------------------------------
# AC-5: success path -> EXIT_OK (0)
# ---------------------------------------------------------------------------


def test_run_url_workflow_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-5: success path returns EXIT_OK (0) and the diagnostic OK marker."""
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    # AC-5 spec says success requires the 3 baseline artifacts; create empty
    # files so the optional smoke check does NOT emit the WARNING line. The
    # check is non-blocking; missing artifacts only WARN, not fail.
    for name in ("RUN_CONFIG.json", "TOOL_STATUS.json", "PROGRESS.md"):
        (audit_dir / name).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_OK


# ---------------------------------------------------------------------------
# AC-6: dry-run skips clone, config, and pipeline
# ---------------------------------------------------------------------------


def test_run_url_workflow_dry_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-6: ``dry_run=True`` returns EXIT_OK and does NOT call the three side-effecting primitives.

    Mutation guard: removing the ``if dry_run`` branch would cause clone_repo
    to be called and the MagicMock side_effect would mark the test as fail.
    """
    parsed = _make_parsed()

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )

    clone_mock = MagicMock(
        side_effect=AssertionError("clone_repo MUST NOT be called in dry_run")
    )
    config_mock = MagicMock(
        side_effect=AssertionError("generate_minimal_config MUST NOT be called in dry_run")
    )
    cli_mock = MagicMock(
        side_effect=AssertionError("cli.main MUST NOT be called in dry_run")
    )

    monkeypatch.setattr("agentic_deep_audit.audit_clone.clone_repo", clone_mock)
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config", config_mock
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", cli_mock)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(tmp_path / "out"),
        profile="standard",
        allowed_roots=[],
        dry_run=True,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_OK
    clone_mock.assert_not_called()
    config_mock.assert_not_called()
    cli_mock.assert_not_called()
    captured = capsys.readouterr()
    assert "DRY RUN PLAN" in captured.out


# ---------------------------------------------------------------------------
# AC-7: default output_dir = ./audit_runs/<safe_repo_name>/
# ---------------------------------------------------------------------------


def test_run_url_workflow_default_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-7: ``output_dir=None`` defaults to ``Path.cwd() / "audit_runs" / safe_repo_name``.

    Uses the dry-run path to capture the resolved paths without touching the
    pipeline. ``monkeypatch.chdir`` pins cwd to ``tmp_path`` so the assertion
    is hermetic.
    """
    parsed = _make_parsed()
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.chdir(tmp_path)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=None,
        profile="standard",
        allowed_roots=[],
        dry_run=True,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_OK
    captured = capsys.readouterr()
    expected_output = (tmp_path / "audit_runs" / parsed.safe_repo_name).resolve()
    expected_audit = (expected_output / "audit").resolve()
    assert str(expected_output) in captured.out
    assert str(expected_audit) in captured.out


# ---------------------------------------------------------------------------
# AC-8: explicit output_dir is respected
# ---------------------------------------------------------------------------


def test_run_url_workflow_explicit_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-8: an explicit ``output_dir`` argument is used verbatim (resolved)."""
    parsed = _make_parsed()
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    explicit = (tmp_path / "explicit").resolve()

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(explicit),
        profile="standard",
        allowed_roots=[],
        dry_run=True,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_OK
    captured = capsys.readouterr()
    assert str(explicit) in captured.out


# ---------------------------------------------------------------------------
# AC-9: audit_dir is output_path / "audit"
# ---------------------------------------------------------------------------


def test_run_url_workflow_audit_dir_layout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-9: the audit_dir is canonically ``<output_path>/audit``."""
    parsed = _make_parsed()
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    output_path = (tmp_path / "runs").resolve()

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=True,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_OK
    captured = capsys.readouterr()
    expected_audit = (output_path / "audit").resolve()
    assert f"audit_dir:       {expected_audit}" in captured.out


# ---------------------------------------------------------------------------
# AC-10: diagnostic logs include safe_repo_name / clone_url / head_sha / profile
# ---------------------------------------------------------------------------


def test_run_url_workflow_logs_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """AC-10: stderr contains the operator-visible markers for triage."""
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    captured = capsys.readouterr()
    err = captured.err
    # At least one of the three triage markers must surface in stderr.
    assert (
        parsed.safe_repo_name in err
        or parsed.clone_url in err
        or cloned.git_metadata["head_sha"][:12] in err
    )
    # The profile and the run subcommand invocation must also be visible.
    assert "standard" in err


# ---------------------------------------------------------------------------
# AC-11: --allowed-root auto-propagation with canonical-first ordering
# ---------------------------------------------------------------------------


def test_run_url_workflow_auto_propagates_allowed_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-11: clone_path FIRST, output_path SECOND, user-supplied AFTER.

    The auto-injected roots must always precede the user roots so the
    canonical sandbox paths cannot be displaced by a user override.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    cli_mock = MagicMock(return_value=0)
    monkeypatch.setattr("agentic_deep_audit.cli.main", cli_mock)

    run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=["/usr/local"],
        dry_run=False,
        timeout_seconds=300,
    )

    cli_mock.assert_called_once()
    called_argv = cli_mock.call_args.args[0]
    # Must contain exactly 3 --allowed-root entries and their VALUES must be
    # ordered: clone_path FIRST, output_path SECOND, user-supplied LAST.
    indices = [i for i, v in enumerate(called_argv) if v == "--allowed-root"]
    assert len(indices) == 3
    values = [called_argv[i + 1] for i in indices]
    assert values[0] == str(cloned.clone_path.resolve())
    assert values[1] == str(output_path.resolve())
    assert values[2] == "/usr/local"


# ---------------------------------------------------------------------------
# AC-11b: --allow-system-roots is NEVER emitted
# ---------------------------------------------------------------------------


def test_run_url_workflow_never_emits_allow_system_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-11b: the orchestrator MUST NOT use ``--allow-system-roots`` as a shortcut."""
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    cli_mock = MagicMock(return_value=0)
    monkeypatch.setattr("agentic_deep_audit.cli.main", cli_mock)

    run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=["/etc", "/var"],
        dry_run=False,
        timeout_seconds=300,
    )

    called_argv = cli_mock.call_args.args[0]
    assert "--allow-system-roots" not in called_argv


# ---------------------------------------------------------------------------
# AC-12: timeout_seconds propagates to clone_repo
# ---------------------------------------------------------------------------


def test_run_url_workflow_timeout_passthrough(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-12: ``timeout_seconds`` is forwarded verbatim to ``clone_repo``."""
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    clone_mock = MagicMock(return_value=cloned)
    monkeypatch.setattr("agentic_deep_audit.audit_clone.clone_repo", clone_mock)
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=999,
    )
    clone_mock.assert_called_once()
    # ``clone_repo`` takes timeout_seconds as a keyword-only argument.
    assert clone_mock.call_args.kwargs.get("timeout_seconds") == 999


# ---------------------------------------------------------------------------
# AC-13: no unhandled exceptions propagate past the orchestrator boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url_input",
    [
        "",  # empty
        "ftp://example.com/notgithub",  # wrong scheme
        "https://example.com/foo/bar",  # wrong host
        "https://github.com//repo",  # empty owner segment
        "https://github.com/owner/",  # empty repo segment
        "https://github.com/owner/repo?injection=1",  # query rejected
    ],
)
def test_run_url_workflow_no_unhandled_exception(
    tmp_path: Path,
    url_input: str,
) -> None:
    """AC-13: every malformed URL surfaces as a structured exit, never an exception.

    No monkeypatching: this uses the REAL ``parse_github_url`` so we are sure
    the validation path actually rejects every entry without the orchestrator
    leaking an exception.
    """
    exit_code = run_url_workflow(
        url=url_input,
        output_dir=str(tmp_path / "out"),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_INVALID_URL


# ---------------------------------------------------------------------------
# AC-14 (REMEDIATION-006 / F-PLAN002-1): audit_dir propagated to REAL clone_repo
# ---------------------------------------------------------------------------


def test_run_url_workflow_audit_dir_propagated_integration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """AC-14 (REMEDIATION-006 / F-PLAN002-1): integration test that uses the
    REAL ``clone_repo`` and only mocks ``subprocess.run``.

    The pre-REMEDIATION-006 orchestrator called
    ``clone_repo(parsed, output_path, timeout_seconds=...)`` which would raise
    ``TypeError: clone_repo() missing 1 required positional argument:
    'audit_dir'`` at runtime. The other 13 tests mock ``clone_repo`` and
    therefore CANNOT detect this regression. This test, by leaving
    ``clone_repo`` real and only stubbing ``subprocess.run``, pins the
    contract: ``audit_dir`` MUST flow from the orchestrator into the engine
    primitive that writes ``ENGINE_PRIMITIVES.json`` under that path.

    Strategy:
      - mock ``subprocess.run`` so the inner ``git clone`` does not touch the
        network; the mock returns CompletedProcess(returncode=0) and creates
        the expected ``.git`` directory on the filesystem so the post-clone
        ``.git/`` existence check passes;
      - the rev-parse calls return deterministic stdout so ``read_clone_metadata``
        succeeds without exceptions;
      - we stub ``generate_minimal_config`` and ``cli.main`` because the GOAL
        of this test is to verify the clone step, not to spin the real
        pipeline.
    """
    import subprocess

    import agentic_deep_audit.audit_clone as audit_clone_module
    from agentic_deep_audit.audit_clone import parse_github_url

    output_path = (tmp_path / "out").resolve()
    audit_dir_expected = output_path / "audit"
    # Derive the safe_repo_name via the REAL ``parse_github_url`` so the
    # expected sandbox path reflects whatever the validator actually produces
    # (e.g. single vs double underscore depending on the derivation rule).
    real_parsed = parse_github_url("https://github.com/octocat/Hello-World")
    expected_clone_path = (output_path / "_clone" / real_parsed.safe_repo_name).resolve()

    # The mock subprocess.run implementation. ``git clone`` must populate the
    # destination's .git/ marker (the real git would). Other invocations
    # (rev-parse HEAD, rev-parse --abbrev-ref HEAD) return deterministic
    # stdout. We pin returncode=0 throughout so the orchestrator proceeds.
    def fake_subprocess_run(cmd, *args, **kwargs):
        if cmd[:2] == ["git", "clone"]:
            # The real git clone creates the dest dir + .git/. ``clone_repo``
            # has ALREADY ``mkdir``-ed the leaf dir before invoking us; we
            # only need to drop the .git/ marker so the post-clone check
            # passes.
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:2] == ["git", "rev-parse"]:
            # ``rev-parse HEAD`` and ``rev-parse --abbrev-ref HEAD``: both
            # path branches in read_clone_metadata.
            if cmd[-1] == "HEAD" and "--abbrev-ref" not in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="abc1234567890def1234567890abc1234567890d\n", stderr=""
                )
            if "--abbrev-ref" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="main\n", stderr="")
        # Default: succeed with empty stdout so unexpected calls do not error.
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(audit_clone_module.subprocess, "run", fake_subprocess_run)

    # Stub the rest of the workflow so the test focuses on clone propagation.
    # ``generate_minimal_config`` is stubbed (the YAML is not the subject).
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir_expected / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )

    # The orchestrator proceeded past the clone step (no TypeError from the
    # missing audit_dir positional). EXIT_OK is the expected outcome.
    assert exit_code == EXIT_OK

    # The F-PLAN002-1 contract: ENGINE_PRIMITIVES.json was written UNDER the
    # audit_dir we computed in the orchestrator, NOT under some sibling path.
    # If audit_dir had been omitted from the clone_repo call the REAL
    # clone_repo would have raised TypeError before _engine_primitive_subprocess
    # could even run.
    engine_log = audit_dir_expected / "ENGINE_PRIMITIVES.json"
    assert engine_log.exists(), (
        f"ENGINE_PRIMITIVES.json missing at {engine_log}; this means "
        f"clone_repo did not receive the orchestrator's audit_dir or the "
        f"audit-log path diverged from the expected layout."
    )
    # Defense in depth: the clone directory was created at the expected sandbox path.
    assert expected_clone_path.exists()
    assert (expected_clone_path / ".git").exists()


# ---------------------------------------------------------------------------
# FIX-3 (Tier-0 2026-06-02): a successful run is finalized so REPORT.md exists
# ---------------------------------------------------------------------------


def test_run_url_workflow_finalizes_audit_to_produce_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """FIX-3: after a successful pipeline run, the URL workflow MUST call finalize_audit so
    REPORT.md is produced end-to-end.

    Pre-fix, ``deep-audit url`` invoked only the ``run`` subcommand, which stops after the
    pipeline phases and never calls finalize_audit — REPORT.md (emitted only by the
    validate/finalize path) was therefore never produced, and the operator had to run
    ``deep-audit validate`` by hand (the Understand-Anything confusion)."""
    from types import SimpleNamespace

    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    # Complete baseline so the smoke check does NOT warn; finalize is the subject here.
    for name in ("RUN_CONFIG.json", "TOOL_STATUS.json", "PROGRESS.md"):
        (audit_dir / name).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo", lambda *_a, **_kw: cloned
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    finalize_calls: list[Path] = []

    def fake_finalize(target_dir, command):
        finalize_calls.append(Path(target_dir))
        return SimpleNamespace(ok=True, errors=[])

    monkeypatch.setattr("agentic_deep_audit.cli.finalize_audit", fake_finalize)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )

    assert exit_code == EXIT_OK
    # The fix: finalize_audit MUST be invoked exactly once with the orchestrator's audit_dir.
    assert [p.resolve() for p in finalize_calls] == [audit_dir.resolve()]
    # The operator-facing success marker references the report that is now produced.
    assert "REPORT.md" in capsys.readouterr().err


def test_run_url_workflow_blocks_when_finalize_reports_validation_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """FIX-3 (remediated, swarm P2): when finalize_audit reports a validation failure (REPORT.md
    withheld), the URL workflow returns EXIT_VALIDATION_BLOCKED — a distinct machine signal that the
    pipeline ran but the final report was gated, matching ``deep-audit validate``'s
    non-zero-on-blockers contract. The raw blocker text MUST NOT be echoed to stderr (leak-free; the
    detail lives in VALIDATION_REPORT.md)."""
    from types import SimpleNamespace

    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    for name in ("RUN_CONFIG.json", "TOOL_STATUS.json", "PROGRESS.md"):
        (audit_dir / name).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo", lambda *_a, **_kw: cloned
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)
    monkeypatch.setattr(
        "agentic_deep_audit.cli.finalize_audit",
        lambda *_a, **_k: SimpleNamespace(
            ok=False, errors=["CORPUS.sqlite contains raw secret-like text"]
        ),
    )

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )

    assert exit_code == EXIT_VALIDATION_BLOCKED
    err = capsys.readouterr().err
    assert "withheld" in err
    assert "VALIDATION_REPORT.md" in err
    assert "1 blocker(s)" in err
    # Leak-free: the raw blocker text must NOT be echoed to stderr.
    assert "raw secret-like text" not in err


def test_run_url_workflow_surfaces_finalize_crash_without_propagating(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """FIX-3 (remediated, swarm P2): an UNEXPECTED finalize crash (e.g. OSError writing the report)
    must NOT propagate out of the orchestrator; it surfaces as EXIT_VALIDATION_BLOCKED with a
    'crashed' diagnostic that NAMES the exception (distinct wording from a routine validation
    block) so a real bug is not mistaken for a benign gated report."""
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    for name in ("RUN_CONFIG.json", "TOOL_STATUS.json", "PROGRESS.md"):
        (audit_dir / name).write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo", lambda *_a, **_kw: cloned
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)

    def boom(*_a, **_k):
        raise OSError("disk full writing VALIDATION_REPORT")

    monkeypatch.setattr("agentic_deep_audit.cli.finalize_audit", boom)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )

    assert exit_code == EXIT_VALIDATION_BLOCKED
    err = capsys.readouterr().err
    assert "crashed" in err
    assert "OSError" in err


# =============================================================================
# REMEDIATION-S008-1 — round-2 regression tests
# =============================================================================
#
# These tests pin the three Fixes dispatched by SEQ-008 round-1 synthesis:
#
# - Fix 1 (F-SF-08-3): cli_main wrap. RuntimeError / KeyError raised inside
#   cli.main must surface as EXIT_PIPELINE_FAILED (5), not propagate as a
#   raw exception out of run_url_workflow. SystemExit MUST still propagate
#   (BaseException is intentionally NOT caught).
# - Fix 2 (F-SF-08-4): AC-13 contract widening. The existing parametrized
#   "no unhandled exception" test only covered URL-validation rejects; we add
#   3 sibling tests that inject exceptions deeper in the pipeline.
# - Fix 3 (F-SF-08-5): non-contradictory diagnostics. When artifacts are
#   missing, stderr must contain "WARNING: audit incomplete" and must NOT
#   contain "OK: audit written". Exit code stays 0 (warning-only contract).


# ---------------------------------------------------------------------------
# Fix 1 / Fix 2 (F-SF-08-3, F-SF-08-4): cli_main RuntimeError -> EXIT_PIPELINE_FAILED
# ---------------------------------------------------------------------------


def test_run_url_workflow_no_unhandled_exception_from_cli_main_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """REMEDIATION-S008-1 Fix 1 + Fix 2 (F-SF-08-3 / F-SF-08-4):
    a RuntimeError raised inside ``cli.main`` MUST be caught by the
    orchestrator's broad safety net and surfaced as ``EXIT_PIPELINE_FAILED``
    (5), NOT propagated as a raw exception out of ``run_url_workflow``.

    Pre-REMEDIATION the cli_main call was bare and a RuntimeError would
    crash the orchestrator with a traceback to stderr — exactly the
    silent-failure pattern AC-13 was supposed to prevent. AC-13's existing
    parametrize only covered URL-validation rejects; this test pins the
    deeper exception-injection path.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )

    def fake_cli_main(_argv):
        raise RuntimeError("simulated pipeline crash")

    monkeypatch.setattr("agentic_deep_audit.cli.main", fake_cli_main)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_PIPELINE_FAILED
    captured = capsys.readouterr()
    # Diagnostic must name the exception type so the operator can triage.
    assert "RuntimeError" in captured.err
    assert "simulated pipeline crash" in captured.err
    assert "unhandled exception" in captured.err.lower()


# ---------------------------------------------------------------------------
# Fix 1 / Fix 2 (F-SF-08-3, F-SF-08-4): cli_main KeyError -> EXIT_PIPELINE_FAILED
# ---------------------------------------------------------------------------


def test_run_url_workflow_no_unhandled_exception_from_cli_main_keyerror(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """REMEDIATION-S008-1 Fix 1 + Fix 2: a KeyError raised inside ``cli.main``
    is ALSO caught by the broad safety net (proving the catch is broad and
    not narrowed to ``RuntimeError``). Surfaces as ``EXIT_PIPELINE_FAILED``.

    KeyError chosen because it inherits from ``LookupError`` (not from
    ``RuntimeError``) — pre-REMEDIATION a narrow ``except RuntimeError`` would
    miss it. This test is the negative-control that proves the catch is
    ``except Exception``, the widest level we can use without trapping
    ``KeyboardInterrupt`` / ``SystemExit``.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )

    def fake_cli_main(_argv):
        raise KeyError("missing_pipeline_key")

    monkeypatch.setattr("agentic_deep_audit.cli.main", fake_cli_main)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    assert exit_code == EXIT_PIPELINE_FAILED
    captured = capsys.readouterr()
    assert "KeyError" in captured.err
    assert "unhandled exception" in captured.err.lower()


# ---------------------------------------------------------------------------
# Fix 1 / Fix 2 (F-SF-08-3, F-SF-08-4): SystemExit MUST propagate
# ---------------------------------------------------------------------------


def test_run_url_workflow_no_unhandled_exception_systemexit_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """REMEDIATION-S008-1 Fix 1 contract: ``SystemExit`` raised inside
    ``cli.main`` MUST propagate out of ``run_url_workflow`` unchanged. The
    broad safety net is ``except Exception`` (NOT ``except BaseException``)
    precisely so ``KeyboardInterrupt`` and ``SystemExit`` continue to flow.

    This test is the negative-control proving the safety net does NOT
    over-catch. If a future refactor widened the catch to ``BaseException``
    (or added ``except SystemExit`` ahead of it) this test would fail
    because ``run_url_workflow`` would swallow the SystemExit and return an
    int instead of letting the exception propagate.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )

    def fake_cli_main(_argv):
        raise SystemExit(0)

    monkeypatch.setattr("agentic_deep_audit.cli.main", fake_cli_main)

    with pytest.raises(SystemExit) as excinfo:
        run_url_workflow(
            url="https://github.com/octocat/Hello-World",
            output_dir=str(output_path),
            profile="standard",
            allowed_roots=[],
            dry_run=False,
            timeout_seconds=300,
        )
    # SystemExit code preserved verbatim — the broad safety net did NOT
    # rewrite it to EXIT_PIPELINE_FAILED.
    assert excinfo.value.code == 0


# ---------------------------------------------------------------------------
# Fix 3 (F-SF-08-5): missing artifacts -> WARNING, NOT OK; exit_code stays 0
# ---------------------------------------------------------------------------


def test_run_url_workflow_success_missing_artifacts_warn_not_ok(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """REMEDIATION-S008-1 Fix 3 (F-SF-08-5): when the post-pipeline artifact
    smoke check finds missing markers, stderr MUST contain
    ``WARNING: audit incomplete`` and MUST NOT contain ``OK: audit written``.

    Pre-REMEDIATION both lines were emitted together, producing a
    contradictory diagnostic ("WARNING: ... missing" immediately followed by
    "OK: audit written") that hid the real condition from the operator. The
    REMEDIATED flow suppresses the OK marker whenever artifacts are missing.

    Exit code stays 0 per the spec's "warning only, non-blocking" contract —
    finalize_audit + validate_audit (downstream of cli.main) are the
    authoritative gate, not this smoke check.
    """
    parsed = _make_parsed()
    cloned = _make_cloned_repo_for_orchestrator(tmp_path)
    output_path = tmp_path / "out"
    audit_dir = output_path / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    # Pre-create ONLY RUN_CONFIG.json. TOOL_STATUS.json and PROGRESS.md are
    # intentionally absent so the smoke check populates ``missing`` and the
    # WARNING-not-OK branch is exercised.
    (audit_dir / "RUN_CONFIG.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.parse_github_url", lambda _u: parsed
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_clone.clone_repo",
        lambda *_a, **_kw: cloned,
    )
    monkeypatch.setattr(
        "agentic_deep_audit.audit_from_url.generate_minimal_config",
        lambda **_kw: audit_dir / "audit.config.yaml",
    )
    monkeypatch.setattr("agentic_deep_audit.cli.main", lambda _argv: 0)
    _stub_finalize_ok(monkeypatch)

    exit_code = run_url_workflow(
        url="https://github.com/octocat/Hello-World",
        output_dir=str(output_path),
        profile="standard",
        allowed_roots=[],
        dry_run=False,
        timeout_seconds=300,
    )
    # Warning-only contract: exit code stays 0 even when artifacts missing.
    assert exit_code == EXIT_OK
    captured = capsys.readouterr()
    # The WARNING line MUST be present and name the missing artifacts.
    assert "WARNING: audit incomplete" in captured.err
    assert "TOOL_STATUS.json" in captured.err
    assert "PROGRESS.md" in captured.err
    # The OK marker MUST NOT be present — that's the contradiction Fix 3
    # eliminated. RUN_CONFIG.json was pre-created so it must NOT show up in
    # the missing list.
    assert "OK: audit written" not in captured.err
    assert "RUN_CONFIG.json" not in captured.err

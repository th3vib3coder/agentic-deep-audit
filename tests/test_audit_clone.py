"""Tests for `agentic_deep_audit.audit_clone` URL parser/validation (SEQ-URL-001)
and sandbox-clone primitive (SEQ-URL-002).

Covers AC-1..AC-22 of `url_workflow/004_seq_url_validation.md` and
AC-1..AC-24 of `url_workflow/005_seq_sandbox_clone.md`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agentic_deep_audit import audit_clone
from agentic_deep_audit.audit_clone import (
    FORBIDDEN_CHARS_IN_URL,
    GITHUB_HTTPS_PATTERN,
    URL_MAX_LENGTH,
    WINDOWS_RESERVED_NAMES,
    InvalidGithubUrlError,
    ParsedGithubUrl,
    derive_safe_repo_name,
    parse_github_url,
)


# --- AC-1 ---------------------------------------------------------------------


def test_url_valid_basic() -> None:
    """AC-1: canonical valid URL parses without error and yields expected owner/repo."""
    result = parse_github_url("https://github.com/octocat/Hello-World")
    assert isinstance(result, ParsedGithubUrl)
    assert result.owner == "octocat"
    assert result.repo == "Hello-World"
    assert result.clone_url == "https://github.com/octocat/Hello-World.git"
    assert result.safe_repo_name  # non-empty


# --- AC-2 ---------------------------------------------------------------------


def test_url_valid_dot_git_suffix() -> None:
    """AC-2: ``.git`` suffix is accepted and normalized away from repo."""
    result = parse_github_url("https://github.com/octocat/Hello-World.git")
    assert result.owner == "octocat"
    assert result.repo == "Hello-World"
    assert result.clone_url == "https://github.com/octocat/Hello-World.git"


# --- AC-3 ---------------------------------------------------------------------


def test_url_valid_trailing_slash() -> None:
    """AC-3: trailing slash is accepted; repo field does not include slash."""
    result = parse_github_url("https://github.com/owner/repo/")
    assert result.owner == "owner"
    assert result.repo == "repo"
    assert "/" not in result.repo
    assert result.clone_url == "https://github.com/owner/repo.git"


# --- AC-4 ---------------------------------------------------------------------


def test_url_rejects_www_subdomain() -> None:
    """AC-4: ``www.github.com`` subdomain is rejected (host must be exactly github.com)."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://www.github.com/owner/repo")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-5 ---------------------------------------------------------------------


def test_url_rejects_http_scheme() -> None:
    """AC-5: plain HTTP scheme rejected; only HTTPS is allowed."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("http://github.com/owner/repo")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-6 ---------------------------------------------------------------------


def test_url_rejects_ssh_scheme() -> None:
    """AC-6: SSH-form URL rejected (``git@github.com:owner/repo.git``)."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("git@github.com:owner/repo.git")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-7 ---------------------------------------------------------------------


def test_url_rejects_query_and_fragment() -> None:
    """AC-7: any URL with ``?`` query or ``#`` fragment is rejected."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/repo?token=secret")
    assert excinfo.value.reason_code == "URL_QUERY_OR_FRAGMENT"

    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/repo#frag")
    assert excinfo.value.reason_code == "URL_QUERY_OR_FRAGMENT"


# --- AC-8 ---------------------------------------------------------------------


def test_url_rejects_path_traversal() -> None:
    """AC-8: path-traversal segments rejected (regex denies ``.`` in owner segment)."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/../etc/passwd")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-9 ---------------------------------------------------------------------


def test_url_rejects_control_chars() -> None:
    """AC-9: NUL byte (any control char 0x00..0x1f or 0x7f) rejected."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/own\x00er/repo")
    assert excinfo.value.reason_code == "URL_CONTROL_CHARS"


# --- AC-10 --------------------------------------------------------------------


def test_url_rejects_excessive_length() -> None:
    """AC-10: URL longer than ``URL_MAX_LENGTH`` (2048) rejected before regex."""
    long_repo = "a" * 3000
    url = f"https://github.com/owner/{long_repo}"
    assert len(url) > URL_MAX_LENGTH
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url(url)
    assert excinfo.value.reason_code == "URL_TOO_LONG"


# --- AC-11 --------------------------------------------------------------------


def test_url_rejects_extra_path_segments() -> None:
    """AC-11: extra path segments beyond ``owner/repo`` rejected."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/repo/issues")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-12 --------------------------------------------------------------------


def test_url_rejects_empty_owner() -> None:
    """AC-12: empty owner segment rejected."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com//repo")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-13 --------------------------------------------------------------------


def test_url_rejects_empty_repo() -> None:
    """AC-13: empty repo segment rejected."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-14 --------------------------------------------------------------------


def test_url_rejects_long_owner() -> None:
    """AC-14: owner > 39 chars rejected (GitHub username spec limit)."""
    long_owner = "a" * 40
    url = f"https://github.com/{long_owner}/repo"
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url(url)
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-15 --------------------------------------------------------------------


def test_url_rejects_long_repo() -> None:
    """AC-15: repo > 100 chars rejected."""
    long_repo = "a" * 101
    url = f"https://github.com/owner/{long_repo}"
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url(url)
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# --- AC-16 --------------------------------------------------------------------


def test_url_rejects_invalid_owner_chars() -> None:
    """AC-16: owner with characters outside [a-zA-Z0-9-] rejected.

    The regex only allows alnum + dash inside owner, and the first char must be
    alnum. An underscore, dot, or '@' in owner must therefore fail.
    """
    for bad_owner in ("own_er", "own.er", "own@er", "-owner"):
        url = f"https://github.com/{bad_owner}/repo"
        with pytest.raises(InvalidGithubUrlError) as excinfo:
            parse_github_url(url)
        assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH", (
            f"expected URL_PATTERN_MISMATCH for owner={bad_owner!r}, "
            f"got {excinfo.value.reason_code!r}"
        )


# --- AC-17 --------------------------------------------------------------------


def test_safe_repo_name_derivation() -> None:
    """AC-17: ``safe_repo_name`` derived from ``owner__repo`` with characters sanitized.

    The spec's pseudo-code joins owner and repo with ``__``, then sanitizes
    non-``[a-z0-9_-]`` chars to ``_``, then collapses runs of ``_`` to a single
    underscore. So the visible separator after collapse is a single ``_``.
    """
    result = parse_github_url("https://github.com/Octocat/Hello-World")
    # After lowercase + collapse, the literal output is ``octocat_hello-world``.
    assert result.safe_repo_name == "octocat_hello-world"

    # Direct derivation: lowercase, all chars within [a-z0-9_-], owner prefix,
    # repo content preserved (except non-allowed chars sanitized to ``_``).
    direct = derive_safe_repo_name("Octocat", "Hello.World")
    assert direct.startswith("octocat_hello")  # post-collapse single underscore
    assert direct == direct.lower()
    assert all(c.isalnum() or c in {"_", "-"} for c in direct), (
        f"derive_safe_repo_name produced disallowed chars: {direct!r}"
    )


# --- AC-18 --------------------------------------------------------------------


def test_safe_repo_name_reserved_words() -> None:
    """AC-18: Windows-reserved repo names (e.g. ``con``, ``aux``) produce a disambiguated safe name."""
    # The combined ``owner__repo`` itself won't typically hit a reserved name,
    # but the pure helper must defend against it directly.
    for reserved in ("con", "aux", "nul", "prn", "com1", "lpt9"):
        safe = derive_safe_repo_name("", reserved)
        # Either suffixed with "_repo" or otherwise mangled so it no longer
        # collides with a reserved Windows device name.
        assert safe not in WINDOWS_RESERVED_NAMES, (
            f"safe_repo_name for owner='', repo={reserved!r} still equals reserved name: {safe!r}"
        )
        assert reserved in safe  # still recognizable, just disambiguated


# --- AC-19 --------------------------------------------------------------------


def test_clone_url_canonicalization() -> None:
    """AC-19: ``clone_url`` always normalized to ``https://github.com/<owner>/<repo>.git``."""
    cases = [
        "https://github.com/octocat/Hello-World",
        "https://github.com/octocat/Hello-World.git",
        "https://github.com/octocat/Hello-World/",
    ]
    expected = "https://github.com/octocat/Hello-World.git"
    for url in cases:
        assert parse_github_url(url).clone_url == expected


# --- AC-20 --------------------------------------------------------------------


def test_exception_reason_code_present() -> None:
    """AC-20: ``InvalidGithubUrlError`` exposes a machine-readable ``reason_code``."""
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("not a url at all")
    err = excinfo.value
    assert hasattr(err, "reason_code"), "InvalidGithubUrlError must expose reason_code attribute"
    assert hasattr(err, "message"), "InvalidGithubUrlError must expose message attribute"
    assert isinstance(err.reason_code, str) and err.reason_code
    assert isinstance(err.message, str) and err.message


# --- AC-21 --------------------------------------------------------------------


def test_url_canonical_octocat_accepted() -> None:
    """AC-21: canonical octocat URL ACCEPTED — gates the regex dot escape correctness.

    A double-escaped pattern (`github\\\\.com`) would NOT match this URL; a
    pattern that treats ``.`` as a metachar (no escape at all) would match too
    much. This test together with AC-22 pins the escape level.
    """
    result = parse_github_url("https://github.com/octocat/Hello-World")
    assert result.owner == "octocat"
    assert result.repo == "Hello-World"


# --- AC-22 --------------------------------------------------------------------


def test_url_rejects_dot_metachar_substitute() -> None:
    """AC-22: ``https://githubxcom/owner/repo`` REJECTED — negative test for regex dot escape.

    If ``.`` in ``github.com`` were treated as a regex metachar (no escape), the
    pattern would match the host ``githubxcom`` because ``.`` matches any single
    character. This test guarantees the escape is present.
    """
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://githubxcom/owner/repo")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"

    # Direct probe on the exported regex constant to make the intent crystal clear.
    assert GITHUB_HTTPS_PATTERN.match("https://github.com/octocat/Hello-World") is not None
    assert GITHUB_HTTPS_PATTERN.match("https://githubxcom/owner/repo") is None


# --- Misc smoke probes (defensive, no AC mapping) ----------------------------


def test_module_constants_present() -> None:
    """Sanity: the four module constants enumerated by the spec are exposed."""
    assert URL_MAX_LENGTH == 2048
    assert isinstance(GITHUB_HTTPS_PATTERN.pattern, str)
    assert "\x00" in FORBIDDEN_CHARS_IN_URL
    assert "con" in WINDOWS_RESERVED_NAMES


def test_non_string_input_rejected() -> None:
    """Defensive: non-string input raises with ``TYPE_NOT_STRING``.

    Not listed in the AC table but explicit in the spec's pseudo-code and
    necessary for 100% line coverage on ``parse_github_url`` per the
    Acceptance Gate.
    """
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url(12345)  # type: ignore[arg-type]
    assert excinfo.value.reason_code == "TYPE_NOT_STRING"


def test_empty_safe_repo_name_branch_unreachable_via_url() -> None:
    """Defensive: covers the ``URL_NO_SAFE_NAME`` guard branch.

    The regex guarantees a non-empty owner/repo before this branch is reached,
    so under the current sanitization scheme this branch is currently
    unreachable from real URLs. The branch is kept as a defensive guard for
    future sanitizer changes — this test exercises it via direct probing of
    ``derive_safe_repo_name`` so the line is covered without faking inputs to
    ``parse_github_url``.
    """
    # Sanity probe: an all-dash owner + all-dash repo collapses to empty after
    # ``.strip("_-")``. parse_github_url would never reach this state because
    # the regex requires a leading alnum, but the pure helper must handle it.
    empty = derive_safe_repo_name("-", "-")
    assert empty == "", f"expected empty derived name from all-dash input, got {empty!r}"


# --- REMEDIATION-S004-1 closures (round 1 review findings) -------------------


def test_url_no_safe_name_via_monkeypatched_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Close F-CR-1: pin the ``URL_NO_SAFE_NAME`` raise branch end-to-end via ``parse_github_url``.

    Monkeypatches ``derive_safe_repo_name`` on the module so the helper returns
    an empty string for any input. With the regex guard satisfied (canonical
    octocat URL), ``parse_github_url`` must then hit the ``URL_NO_SAFE_NAME``
    branch and raise. This exercises the line that direct-helper probing would
    miss when reading coverage on ``parse_github_url`` itself.
    """
    monkeypatch.setattr(audit_clone, "derive_safe_repo_name", lambda o, r: "")
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/octocat/Hello-World")
    assert excinfo.value.reason_code == "URL_NO_SAFE_NAME"


def test_url_rejects_pure_dots_repo_double_dot() -> None:
    """Close F-CR-2: a pure-dot repo segment ``..`` is rejected as URL_PATTERN_MISMATCH.

    The regex pattern character class ``[a-zA-Z0-9._-]`` accepts dots, so
    ``/owner/..`` matches structurally. The post-match guard rejects it because
    a repo of only dots is a path-traversal hazard and downstream sandbox-
    clone cannot operate on it.
    """
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/..")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


def test_url_rejects_pure_dots_repo_single_dot() -> None:
    """Close F-CR-2: a single-dot repo segment ``.`` is rejected as URL_PATTERN_MISMATCH.

    Same rationale as the double-dot case: structurally the regex accepts a
    single ``.`` in the repo position, but the post-match guard rejects any
    repo made entirely of dot characters.
    """
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/.")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


def test_url_rejects_empty_repo_after_dot_git_strip() -> None:
    """Close F-CR-3: ``/owner/.git`` strips to empty repo, must be rejected.

    The regex matches ``.git`` as the repo segment plus the optional ``.git``
    suffix (greedy or not, ``removesuffix`` strips the trailing ``.git`` and
    leaves an empty string). The post-strip empty-repo guard must reject this
    via ``URL_PATTERN_MISMATCH`` so the downstream sandbox-clone is never
    handed an empty repo name.
    """
    with pytest.raises(InvalidGithubUrlError) as excinfo:
        parse_github_url("https://github.com/owner/.git")
    assert excinfo.value.reason_code == "URL_PATTERN_MISMATCH"


# =============================================================================
# SEQ-URL-002 Sandbox Clone tests (AC-1..AC-24)
# =============================================================================
#
# Spec: url_workflow/005_seq_sandbox_clone.md
#
# Mocking discipline: every test that would invoke ``git clone`` MUST mock
# ``subprocess.run`` so no real network call ever leaves the test process. The
# mock returns a ``subprocess.CompletedProcess`` with ``returncode=0`` by
# default and, when the clone is expected to "succeed", also materializes the
# ``.git/`` directory on disk so the post-clone existence guard passes.
#
# Imports come from ``agentic_deep_audit.audit_clone`` once SEQ-005 lands. The
# tests reference attribute lookups via ``audit_clone.<symbol>`` so a missing
# symbol surfaces as an ``AttributeError`` (the RED-baseline signal) rather
# than an ``ImportError`` at module load time.


# --- Helpers (private to SEQ-005 block) --------------------------------------


def _make_parsed(
    owner: str = "octocat",
    repo: str = "Hello-World",
) -> ParsedGithubUrl:
    """Build a ParsedGithubUrl directly — bypasses parse_github_url so we can
    inject crafted ``safe_repo_name`` for defense-in-depth probes (AC-9).
    """
    safe = derive_safe_repo_name(owner, repo)
    return ParsedGithubUrl(
        owner=owner,
        repo=repo,
        safe_repo_name=safe,
        clone_url=f"https://github.com/{owner}/{repo}.git",
    )


def _make_subprocess_success(
    clone_dest: Path | None = None,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    """Build a ``subprocess.run`` mock side-effect that:

    - Returns a ``CompletedProcess`` with ``returncode=0``.
    - When invoked with a ``git clone ... <dest>`` argv, creates
      ``<dest>/.git/`` so the post-clone existence guard passes.
    """

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        # If this is a git-clone invocation, materialize the dest .git dir.
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout=stdout, stderr=stderr
        )

    return _side_effect


# --- AC-1 ---------------------------------------------------------------------


def test_clone_success_creates_git_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-1: clone exits 0 and the .git directory exists at clone_path."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    cloned = audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert (cloned.clone_path / ".git").exists()
    assert cloned.safe_repo_name == parsed.safe_repo_name


# --- AC-2 ---------------------------------------------------------------------


def test_clone_uses_depth_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-2: ``--depth 1`` appears in the git clone argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    # First call is the clone itself.
    clone_call = run_mock.call_args_list[0]
    argv = clone_call.args[0]
    assert "--depth" in argv
    assert argv[argv.index("--depth") + 1] == "1"


def test_clone_uses_core_longpaths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows MAX_PATH: clone passes ``core.longpaths=true`` so repos whose nested paths + the audit
    output-dir prefix exceed 260 chars don't fail checkout with 'Filename too long' (observed on real
    repos: cpath-ukk/SPARK, nousresearch/hermes-agent). The engine-primitive boundary allowlist must
    also permit it — otherwise clone_repo raises EnginePrimitiveError before subprocess.run and the
    clone_call lookup below fails, so this test guards the cmd and the allowlist staying in lockstep."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    clone_call = run_mock.call_args_list[0]
    argv = clone_call.args[0]
    assert "core.longpaths=true" in argv
    assert argv[argv.index("core.longpaths=true") - 1] == "--config"


# --- AC-3 ---------------------------------------------------------------------


def test_clone_uses_no_tags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-3: ``--no-tags`` appears in the git clone argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    assert "--no-tags" in argv


# --- AC-4 ---------------------------------------------------------------------


def test_clone_uses_single_branch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-4: ``--single-branch`` appears in the git clone argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    assert "--single-branch" in argv


# --- AC-5 ---------------------------------------------------------------------


def test_clone_disables_hooks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-5: ``--config core.hooksPath=<placeholder>`` appears in argv.

    The placeholder is ``/dev/null`` on POSIX and ``NUL`` on Windows — either
    is accepted so the test runs cross-platform.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    hooks_kv = [
        argv[i + 1]
        for i, tok in enumerate(argv[:-1])
        if tok == "--config" and argv[i + 1].startswith("core.hooksPath=")
    ]
    assert hooks_kv, f"--config core.hooksPath=... missing from argv: {argv!r}"
    assert hooks_kv[0] in {"core.hooksPath=/dev/null", "core.hooksPath=NUL"}


# --- AC-6 ---------------------------------------------------------------------


def test_clone_skips_submodules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-6: ``--config submodule.recurse=false`` appears in argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    submodule_kv = [
        argv[i + 1]
        for i, tok in enumerate(argv[:-1])
        if tok == "--config" and argv[i + 1].startswith("submodule.recurse=")
    ]
    assert submodule_kv, f"--config submodule.recurse=... missing from argv: {argv!r}"
    assert submodule_kv[0] == "submodule.recurse=false"


# --- AC-7 ---------------------------------------------------------------------


def test_clone_passes_no_recurse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-7: ``--no-recurse-submodules`` appears in argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    assert "--no-recurse-submodules" in argv


# --- AC-8 ---------------------------------------------------------------------


def test_clone_disables_credential_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-8: ``--config credential.helper=`` (empty value) appears in argv."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    cred_kv = [
        argv[i + 1]
        for i, tok in enumerate(argv[:-1])
        if tok == "--config" and argv[i + 1].startswith("credential.helper=")
    ]
    assert cred_kv, f"--config credential.helper= missing from argv: {argv!r}"
    assert cred_kv[0] == "credential.helper="


def test_clone_clears_http_extraheader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """T-URL-13: clone must clear http.extraheader as well as credential.helper."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    argv = run_mock.call_args_list[0].args[0]
    extra_headers = [
        argv[i + 1]
        for i, tok in enumerate(argv[:-1])
        if tok == "--config" and argv[i + 1].startswith("http.extraheader=")
    ]
    assert extra_headers == ["http.extraheader="]


# --- AC-9 ---------------------------------------------------------------------


def test_clone_path_stays_in_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-9: a sandbox-escape ``safe_repo_name`` (e.g. via ``..``) is rejected.

    ``derive_safe_repo_name`` already sanitizes via regex so a real URL cannot
    produce ``..`` here. We construct a malicious ``ParsedGithubUrl`` directly
    to exercise the defense-in-depth check in ``clone_repo``.
    """
    # Build by hand: bypass derive_safe_repo_name to inject the attacker path.
    malicious = ParsedGithubUrl(
        owner="octocat",
        repo="Hello-World",
        safe_repo_name="../escape",
        clone_url="https://github.com/octocat/Hello-World.git",
    )
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # subprocess.run should NEVER be called when the boundary fires.
    run_mock = MagicMock(side_effect=AssertionError("subprocess.run must not be called"))
    monkeypatch.setattr("subprocess.run", run_mock)

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(malicious, output_dir, audit_dir)
    assert excinfo.value.reason_code == "SANDBOX_ESCAPE"


def test_clone_root_symlink_escape_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-URL-08: pre-existing output_dir/_clone symlink cannot redirect writes outside output_dir."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    outside = tmp_path / "outside"
    output_dir.mkdir()
    audit_dir.mkdir()
    outside.mkdir()

    try:
        (output_dir / "_clone").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - Windows without symlink privilege
        pytest.skip("symlink creation unavailable on this platform")

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "SANDBOX_ESCAPE"
    assert not (outside / parsed.safe_repo_name).exists()


def test_clone_root_symlink_escape_rejected_via_resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-URL-08 (platform-independent): a ``_clone`` that RESOLVES outside
    output_dir (the symlink-redirect hole) is rejected with SANDBOX_ESCAPE
    before any subprocess. The sibling test_clone_root_symlink_escape_rejected
    needs real symlink-creation privilege and SKIPS on Windows-without-privilege
    (which is why CI, not local Windows, first caught the missing guard); this
    monkeypatch variant simulates the escape so the guard is verified on EVERY
    platform.
    """
    parsed = _make_parsed()
    output_dir = (tmp_path / "out").resolve()
    audit_dir = output_dir / "audit"
    outside = (tmp_path / "outside").resolve()
    output_dir.mkdir()
    audit_dir.mkdir()
    outside.mkdir()

    real_resolve = Path.resolve

    def _fake_resolve(self: Path, *args: object, **kwargs: object) -> Path:
        resolved = real_resolve(self, *args, **kwargs)  # type: ignore[arg-type]
        # Simulate ``output_dir/_clone`` being a symlink that points outside.
        if resolved.name == "_clone":
            return outside
        return resolved

    monkeypatch.setattr(Path, "resolve", _fake_resolve)
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "SANDBOX_ESCAPE"
    assert not (outside / parsed.safe_repo_name).exists()


def test_clone_rejects_audit_dir_outside_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The engine-primitive log path must not be an arbitrary write outside output_dir."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = tmp_path / "audit-outside"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "AUDIT_DIR_OUTSIDE_OUTPUT"


# --- AC-10 --------------------------------------------------------------------


def test_clone_existing_path_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-10: clone_path already exists without ``force=True`` → CLONE_PATH_EXISTS."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # Pre-create the would-be clone path.
    pre = output_dir / "_clone" / parsed.safe_repo_name
    pre.mkdir(parents=True)

    run_mock = MagicMock(side_effect=AssertionError("subprocess.run must not be called"))
    monkeypatch.setattr("subprocess.run", run_mock)

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "CLONE_PATH_EXISTS"


# --- AC-11 --------------------------------------------------------------------


def test_safe_repo_name_reserved_words_e2e(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-11: reserved Windows names in safe_repo_name are mangled to avoid collision.

    SEQ-004 already pins ``derive_safe_repo_name`` reserved-name behaviour. This
    SEQ-005 test exercises the end-to-end pipeline: feeding a parsed URL whose
    derived safe name comes from a reserved-word repo MUST not blow up the
    sandbox path. We assert the clone path is creatable and ends in a
    disambiguated suffix.
    """
    # Use the empty-owner trick from SEQ-004 to land on a reserved name path
    # straight from derive_safe_repo_name; then wrap in a ParsedGithubUrl.
    safe = derive_safe_repo_name("", "con")
    assert safe not in WINDOWS_RESERVED_NAMES
    parsed = ParsedGithubUrl(
        owner="octocat",
        repo="con",
        safe_repo_name=safe,
        clone_url="https://github.com/octocat/con.git",
    )
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    run_mock = MagicMock(side_effect=_make_subprocess_success())
    monkeypatch.setattr("subprocess.run", run_mock)

    cloned = audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert cloned.clone_path.name == safe  # name preserved through the pipeline
    assert "con" in cloned.safe_repo_name


# --- AC-12 --------------------------------------------------------------------


def test_clone_handles_symlinks_safely(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-12: a symlink left inside the clone after the mock-clone is preserved as data.

    The mock side-effect materializes ``<dest>/.git`` and a symlink under
    ``<dest>``. The function MUST NOT dereference or follow the symlink; we
    verify the symlink object survives at the post-clone path.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            # Drop a symlink the function must NOT follow.
            link = dest / "symlink_to_etc"
            target = tmp_path / "outside_target"
            target.mkdir(exist_ok=True)
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):  # pragma: no cover - Windows w/o privilege
                pytest.skip("symlink creation requires elevated privileges on Windows")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    cloned = audit_clone.clone_repo(parsed, output_dir, audit_dir)
    sym = cloned.clone_path / "symlink_to_etc"
    # The symlink is preserved (not deleted, not dereferenced into a copy).
    assert sym.is_symlink(), (
        f"clone_repo dereferenced symlink at {sym} — expected to preserve as link"
    )


# --- AC-13 --------------------------------------------------------------------


def test_clone_handles_404(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-13: git clone exit code != 0 surfaces as structured CloneError(GIT_CLONE_FAILED)."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        return subprocess.CompletedProcess(
            args=cmd, returncode=128, stdout="", stderr="fatal: repository not found"
        )

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "GIT_CLONE_FAILED"


# --- AC-14 --------------------------------------------------------------------


def test_clone_respects_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-14: subprocess.TimeoutExpired surfaces as CloneError(CLONE_TIMEOUT).

    Pins the default ``CLONE_DEFAULT_TIMEOUT_SECONDS == 300`` value so a
    mutation that drops the default to 0 (or any other non-positive value)
    is detected by this test. We assert on the dataclass field plus the
    propagated kwarg into subprocess.run.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # Pin the constant default value — mutation probe target.
    assert audit_clone.CLONE_DEFAULT_TIMEOUT_SECONDS == 300, (
        "default timeout must remain 300 seconds; any other value indicates a regression"
    )

    captured: dict = {}

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        captured.setdefault("clone_timeout", kwargs.get("timeout"))
        # Simulate timeout at subprocess level.
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    # Use the DEFAULT (no override) so the test pins the constant.
    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "CLONE_TIMEOUT"
    assert captured["clone_timeout"] == 300, (
        f"subprocess.run should receive timeout=300 (the default); got {captured['clone_timeout']!r}"
    )
    payload = json.loads((audit_dir / "ENGINE_PRIMITIVES.json").read_text(encoding="utf-8"))
    assert payload["entries"][-1]["exit_code"] == -1
    assert payload["entries"][-1]["error_type"] == "TimeoutExpired"


def test_clone_missing_git_surfaces_as_clone_error_and_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing git executable must not leak FileNotFoundError or skip the primitive audit log."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        raise FileNotFoundError("git executable not found")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "CLONE_SUBPROCESS_FAILED"
    payload = json.loads((audit_dir / "ENGINE_PRIMITIVES.json").read_text(encoding="utf-8"))
    assert payload["entries"][-1]["exit_code"] == -1
    assert payload["entries"][-1]["error_type"] == "FileNotFoundError"


# --- AC-15 --------------------------------------------------------------------


def test_cloned_repo_metadata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-15: ClonedRepo.git_metadata exposes head_sha, remote_url, branch_name."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    calls: list[tuple] = []

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        calls.append((tuple(cmd), kwargs.get("cwd")))
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        # post-clone metadata calls: rev-parse HEAD / rev-parse --abbrev-ref HEAD
        if cmd[1:3] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="abc123def456\n", stderr=""
            )
        if cmd[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="main\n", stderr=""
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    cloned = audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert set(cloned.git_metadata.keys()) >= {"head_sha", "remote_url", "branch_name"}
    assert cloned.git_metadata["head_sha"] == "abc123def456"
    assert cloned.git_metadata["branch_name"] == "main"
    assert cloned.git_metadata["remote_url"] == parsed.clone_url


# --- AC-16 --------------------------------------------------------------------


def test_sandbox_mkdir_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-16: calling clone_repo twice on the same path → second raises CLONE_PATH_EXISTS.

    Demonstrates the mkdir is atomic in the sense that ``exist_ok=False`` is the
    effective contract (the function refuses to re-enter an existing path).
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    first = audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert first.clone_path.exists()

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "CLONE_PATH_EXISTS"


# --- AC-17 --------------------------------------------------------------------


def test_clone_uses_engine_primitive_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-17: clone_repo dispatches via ``_engine_primitive_subprocess``, NOT direct subprocess.run."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # Wrap the real subprocess.run via the success side-effect so the clone
    # actually completes; then probe call count on the wrapper.
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    wrapper_spy = MagicMock(side_effect=audit_clone._engine_primitive_subprocess)
    monkeypatch.setattr(audit_clone, "_engine_primitive_subprocess", wrapper_spy)

    audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert wrapper_spy.call_count >= 1, (
        "_engine_primitive_subprocess must be called for the clone"
    )
    # First wrapper call must be the git clone (positional cmd argv).
    first_cmd = wrapper_spy.call_args_list[0].args[0]
    assert first_cmd[0] == "git" and first_cmd[1] == "clone"


# --- AC-18 --------------------------------------------------------------------


def test_engine_primitives_log_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-18: audit_dir/ENGINE_PRIMITIVES.json exists with an exit_code=0 entry after clone."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    log_path = audit_dir / "ENGINE_PRIMITIVES.json"
    assert log_path.exists(), "ENGINE_PRIMITIVES.json must be created"
    payload = json.loads(log_path.read_text(encoding="utf-8"))
    assert "entries" in payload
    assert any(e.get("exit_code") == 0 for e in payload["entries"])


# --- AC-19 --------------------------------------------------------------------


def test_primitive_url_not_allowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-19: non-GitHub URL in argv raises EnginePrimitiveError + log NOT written."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    # subprocess.run must NOT be called when the boundary fires.
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    cmd = [
        "git", "clone",
        "https://evil.example.com/owner/repo.git",
        str(tmp_path / "dest"),
    ]
    with pytest.raises(audit_clone.EnginePrimitiveError) as excinfo:
        audit_clone._engine_primitive_subprocess(
            cmd,
            audit_dir=audit_dir,
            primitive_id="git-clone-url-workflow",
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=30,
        )
    assert excinfo.value.reason_code == "PRIMITIVE_URL_NOT_ALLOWED"
    # Audit log MUST NOT be written when boundary fires (defense in depth).
    assert not (audit_dir / "ENGINE_PRIMITIVES.json").exists()


# --- AC-20 --------------------------------------------------------------------


def test_primitive_cmd_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-20: argv[0] != git OR argv[1] != clone raises EnginePrimitiveError + log NOT written."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    # argv[0] != git
    bad_cmd_1 = ["curl", "clone", "https://github.com/o/r.git", str(tmp_path / "d1")]
    with pytest.raises(audit_clone.EnginePrimitiveError) as excinfo:
        audit_clone._engine_primitive_subprocess(
            bad_cmd_1,
            audit_dir=audit_dir,
            primitive_id="git-clone-url-workflow",
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=30,
        )
    assert excinfo.value.reason_code == "PRIMITIVE_CMD_MISMATCH"

    # argv[1] != clone
    bad_cmd_2 = ["git", "fetch", "https://github.com/o/r.git", str(tmp_path / "d2")]
    with pytest.raises(audit_clone.EnginePrimitiveError) as excinfo:
        audit_clone._engine_primitive_subprocess(
            bad_cmd_2,
            audit_dir=audit_dir,
            primitive_id="git-clone-url-workflow",
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=30,
        )
    assert excinfo.value.reason_code == "PRIMITIVE_CMD_MISMATCH"

    # And the audit log was NOT created in either case.
    assert not (audit_dir / "ENGINE_PRIMITIVES.json").exists()


def test_primitive_rejects_unknown_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unknown engine primitives must fail closed instead of executing arbitrary subprocesses."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.EnginePrimitiveError) as excinfo:
        audit_clone._engine_primitive_subprocess(
            ["git", "clone", "https://github.com/o/r.git", str(tmp_path / "d")],
            audit_dir=audit_dir,
            primitive_id="unexpected",
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=30,
        )
    assert excinfo.value.reason_code == "PRIMITIVE_UNKNOWN"


def test_primitive_rejects_dangerous_clone_arg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The primitive boundary must reject dangerous git-clone options such as --upload-pack."""
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.EnginePrimitiveError) as excinfo:
        audit_clone._engine_primitive_subprocess(
            [
                "git",
                "clone",
                "--upload-pack=/tmp/evil",
                "https://github.com/o/r.git",
                str(tmp_path / "d"),
            ],
            audit_dir=audit_dir,
            primitive_id="git-clone-url-workflow",
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=30,
        )
    assert excinfo.value.reason_code == "PRIMITIVE_ARG_NOT_ALLOWED"


# --- AC-21 --------------------------------------------------------------------


def test_run_git_uses_cwd_not_dash_C(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-21a: _run_git uses cwd=clone_path; NEVER passes `-C` flag.

    Policy probe per BLOCKED_COMMANDS_ALLOWLIST: ``-C`` is blocked as
    dangerous_argument. The allowlisted subcommand path is
    ``["git", "rev-parse", "HEAD"]`` with cwd set via subprocess kwarg.
    """
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    captured: dict = {}

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        captured["argv"] = list(cmd)
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="x\n", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    audit_clone._run_git(clone_path, "rev-parse", "HEAD")

    assert "-C" not in captured["argv"], (
        f"_run_git must NEVER pass -C; argv was {captured['argv']!r}"
    )
    assert captured["argv"][:2] == ["git", "rev-parse"]
    assert captured["cwd"] == str(clone_path)


def test_run_git_no_config_subcommand(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-21b: read_clone_metadata never issues a ``git config ...`` subcommand.

    Policy probe: ``git config`` is NOT in the allowlist (only rev-parse,
    status, ls-files, log). REMEDIATION-003 demands remote_url be derived
    from parsed.clone_url, not git config.
    """
    parsed = _make_parsed()
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    calls: list[list[str]] = []

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        calls.append(list(cmd))
        if cmd[1:3] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="sha\n", stderr="")
        if cmd[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="main\n", stderr="")
        # Any other call is a policy violation for this function.
        raise AssertionError(f"unexpected git invocation: {cmd!r}")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    audit_clone.read_clone_metadata(clone_path, parsed)
    for argv in calls:
        assert "config" not in argv, (
            f"read_clone_metadata MUST NOT invoke `git config ...`; saw {argv!r}"
        )
        # And the allowlisted subcommand set is strictly {rev-parse, status, ls-files, log}.
        assert argv[1] in {"rev-parse", "status", "ls-files", "log"}, (
            f"non-allowlisted git subcommand: {argv!r}"
        )


def test_run_git_rejects_non_allowlisted_subcommand(tmp_path: Path) -> None:
    """Defense-in-depth: private metadata helper cannot be reused for git config."""
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone._run_git(clone_path, "config", "--get", "remote.origin.url")
    assert excinfo.value.reason_code == "METADATA_GIT_NOT_ALLOWLISTED"


def test_run_git_rejects_dash_c(tmp_path: Path) -> None:
    """Policy truth: -C is a dangerous git argument even if a caller passes it indirectly."""
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone._run_git(clone_path, "rev-parse", "-C", "other", "HEAD")
    assert excinfo.value.reason_code == "METADATA_GIT_DANGEROUS_ARG"


def test_run_git_rejects_dangerous_flags_beyond_dash_c(tmp_path: Path) -> None:
    """VER-F003: flag-allowlist rejects dangerous git flags beyond -C.

    The prior one-token denylist ({"-C"}) let --git-dir / --output / -c /
    --ext-diff / --work-tree through; the allowlist rejects every dash-prefixed
    arg that is not explicitly allow-listed (only --abbrev-ref is).
    """
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    for bad in ("--git-dir=/tmp/g", "--output=/tmp/x", "-c", "--ext-diff", "--work-tree=/tmp/w"):
        with pytest.raises(audit_clone.CloneError) as excinfo:
            audit_clone._run_git(clone_path, "rev-parse", bad, "HEAD")
        assert excinfo.value.reason_code == "METADATA_GIT_DANGEROUS_ARG", (
            f"expected METADATA_GIT_DANGEROUS_ARG for {bad}; got {excinfo.value.reason_code}"
        )


def test_run_git_allows_abbrev_ref_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """VER-F003: the one allow-listed metadata flag (--abbrev-ref) is NOT rejected."""
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    captured: dict = {}

    def _fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="main\n", stderr="")

    monkeypatch.setattr(audit_clone.subprocess, "run", _fake_run)
    out = audit_clone._run_git(clone_path, "rev-parse", "--abbrev-ref", "HEAD")
    assert out == "main\n"
    assert captured["cmd"] == ["git", "rev-parse", "--abbrev-ref", "HEAD"]


# --- AC-22 --------------------------------------------------------------------


def test_engine_primitives_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-22: ENGINE_PRIMITIVES.json conforms to ``{entries:[{timestamp,primitive_id,argv,exit_code}]}``."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    payload = json.loads((audit_dir / "ENGINE_PRIMITIVES.json").read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    assert isinstance(payload.get("entries"), list) and payload["entries"]
    for entry in payload["entries"]:
        assert set(entry.keys()) >= {"timestamp", "primitive_id", "argv", "exit_code"}
        assert isinstance(entry["timestamp"], str)
        # ISO-8601 UTC stamp ending with Z (per spec append_log impl).
        assert entry["timestamp"].endswith("Z")
        assert isinstance(entry["primitive_id"], str)
        assert isinstance(entry["argv"], list)
        assert isinstance(entry["exit_code"], int)


def test_engine_primitives_json_schema_rejects_invalid_shape(tmp_path: Path) -> None:
    """ENGINE_PRIMITIVES.json must be schema-validated, not exempted."""
    from agentic_deep_audit.validate_json_schema import validate_json_artifact_schemas

    (tmp_path / "ENGINE_PRIMITIVES.json").write_text(
        json.dumps({"entries": "not-a-list"}),
        encoding="utf-8",
    )

    errors = validate_json_artifact_schemas(tmp_path)
    assert any(
        error.startswith("engine_primitives_schema: ENGINE_PRIMITIVES.json: entries:")
        for error in errors
    ), errors


# --- AC-23 --------------------------------------------------------------------


def test_engine_primitives_in_artifact_paths() -> None:
    """AC-23: ARTIFACT_PATHS in models.py includes ENGINE_PRIMITIVES.json."""
    from agentic_deep_audit import models

    assert hasattr(models, "ARTIFACT_PATHS")
    # Search by value — key naming convention varies historically but the
    # canonical filename must appear among the registered artifact paths.
    values = set(models.ARTIFACT_PATHS.values())
    assert "ENGINE_PRIMITIVES.json" in values, (
        f"ENGINE_PRIMITIVES.json not registered in ARTIFACT_PATHS; got values={sorted(values)!r}"
    )


# --- AC-24 --------------------------------------------------------------------


def test_metadata_remote_url_from_parsed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-24: read_clone_metadata returns ``remote_url == parsed.clone_url`` (NOT git config)."""
    parsed = _make_parsed(owner="octocat", repo="Hello-World")
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if cmd[1:3] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="deadbeef\n", stderr="")
        if cmd[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="main\n", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    metadata = audit_clone.read_clone_metadata(clone_path, parsed)
    assert metadata["remote_url"] == parsed.clone_url
    assert metadata["remote_url"] == "https://github.com/octocat/Hello-World.git"


# --- Defensive smoke: is_windows ---------------------------------------------


def test_is_windows_returns_bool() -> None:
    """Smoke: is_windows() is a no-arg bool, matching sys.platform at import time."""
    assert audit_clone.is_windows() is (sys.platform.startswith("win"))


# --- Defensive: coverage closures for guarded branches ----------------------


def test_clone_force_flag_not_implemented(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Defensive: ``force=True`` on an existing path → FORCE_NOT_IMPLEMENTED.

    Closes the coverage gap for the documented-but-deferred force code path
    so a future implementer is forced to update the corresponding test when
    the behaviour changes.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    pre = output_dir / "_clone" / parsed.safe_repo_name
    pre.mkdir(parents=True)

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("must not run"))
    )

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir, force=True)
    assert excinfo.value.reason_code == "FORCE_NOT_IMPLEMENTED"


def test_clone_primitive_boundary_reraises_as_clone_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive: EnginePrimitiveError raised inside the wrapper surfaces as PRIMITIVE_BOUNDARY.

    Force the wrapper to raise (rather than the boundary check inside it) so
    we exercise the ``except EnginePrimitiveError`` arm in ``clone_repo``.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _wrapper_boom(*args, **kwargs):  # noqa: ANN001 - mock side-effect
        raise audit_clone.EnginePrimitiveError("synthetic boundary trip", "PRIMITIVE_URL_NOT_ALLOWED")

    monkeypatch.setattr(audit_clone, "_engine_primitive_subprocess", _wrapper_boom)
    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "PRIMITIVE_BOUNDARY"


def test_clone_missing_git_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Defensive: clone exits 0 but no .git/ on disk → MISSING_GIT_DIR.

    Simulates a hostile or buggy remote/proxy that returns success but
    delivers nothing on disk.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        # Do NOT create .git/ at the destination; just claim success.
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "MISSING_GIT_DIR"


def test_engine_primitives_log_appends_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defensive: second clone appends to the existing ENGINE_PRIMITIVES.json file.

    Closes the coverage gap for the ``log_path.exists()`` branch in
    ``_append_engine_primitive_log``.
    """
    parsed_a = _make_parsed(owner="octocat", repo="A")
    parsed_b = _make_parsed(owner="octocat", repo="B")
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    audit_clone.clone_repo(parsed_a, output_dir, audit_dir)
    audit_clone.clone_repo(parsed_b, output_dir, audit_dir)

    payload = json.loads((audit_dir / "ENGINE_PRIMITIVES.json").read_text(encoding="utf-8"))
    assert len(payload["entries"]) >= 2


def test_engine_primitives_corrupt_log_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A corrupt ENGINE_PRIMITIVES.json must not be silently replaced with a new empty log."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()
    log_path = audit_dir / "ENGINE_PRIMITIVES.json"
    original = "{not json"
    log_path.write_text(original, encoding="utf-8")

    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=_make_subprocess_success())
    )

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "PRIMITIVE_LOG_FAILED"
    assert log_path.read_text(encoding="utf-8") == original


# --- REMEDIATION-S005-1 closures (round 1 review findings) -------------------


def test_clone_path_exists_via_filenotexists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Close F-CR-2: the atomic-mkdir contract surfaces FileExistsError as CLONE_PATH_EXISTS.

    The remediation replaced the stat()-then-mkdir TOCTOU window with
    ``mkdir(exist_ok=False)``. This test pins the new behaviour by mocking
    ``Path.mkdir`` to raise ``FileExistsError`` (which is what the OS would do
    if a concurrent worker grabbed the leaf between our resolve and our mkdir)
    and asserts the structured ``CloneError(CLONE_PATH_EXISTS)`` re-raise.

    Note: ``test_clone_existing_path_fails`` (above) still pins the
    end-to-end behaviour with a real pre-existing directory; this test is the
    finer-grained probe that the FileExistsError exception path is wired.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # subprocess.run must NEVER be called when the boundary fires.
    monkeypatch.setattr(
        "subprocess.run", MagicMock(side_effect=AssertionError("subprocess.run must not be called"))
    )

    real_mkdir = Path.mkdir

    def _selective_mkdir(self, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        # Trip ONLY on the clone leaf (the one with exist_ok=False); pass-through
        # for the parent ``_clone/`` and the audit dir which use exist_ok=True.
        if kwargs.get("exist_ok") is False and self.name == parsed.safe_repo_name:
            raise FileExistsError(17, "File exists", str(self))
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _selective_mkdir)

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "CLONE_PATH_EXISTS"
    # Cause-chain preserved per ``raise ... from exc``.
    assert isinstance(excinfo.value.__cause__, FileExistsError)


def test_metadata_read_failure_surfaces_as_clone_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Close F-SF-4: CalledProcessError from ``_run_git`` must surface as
    ``CloneError(METADATA_READ_FAILED)``, not raw subprocess exception.

    ``_run_git`` invokes ``subprocess.run(..., check=True)``; if ``git
    rev-parse HEAD`` fails post-clone (corrupt repo, missing HEAD, hostile
    remote that produced a malformed pack), the raw CalledProcessError would
    otherwise leak out of ``clone_repo`` and break its docstring contract
    that promises CloneError-only on failure.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        # Clone phase: succeed and materialize ``.git/`` so the post-clone
        # existence guard passes and we reach read_clone_metadata.
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        # Metadata phase: rev-parse fails non-zero; check=True turns it into
        # CalledProcessError(128, cmd=...). This is what the remediation
        # must catch and rewrap.
        if cmd[:2] == ["git", "rev-parse"]:
            raise subprocess.CalledProcessError(
                returncode=128,
                cmd=cmd,
                output="",
                stderr="fatal: not a git repository",
            )
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "METADATA_READ_FAILED"
    # Cause-chain preserved per ``raise ... from exc``.
    assert isinstance(excinfo.value.__cause__, subprocess.CalledProcessError)


def test_metadata_read_timeout_surfaces_as_clone_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Close F-SF-4 (timeout sibling): ``_run_git`` has a 30s timeout. A
    ``TimeoutExpired`` from rev-parse must also surface as
    ``CloneError(METADATA_READ_FAILED)`` — same contract as
    CalledProcessError. This pins the second arm of the wrap clause.
    """
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if cmd[:2] == ["git", "rev-parse"]:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "METADATA_READ_FAILED"
    assert isinstance(excinfo.value.__cause__, subprocess.TimeoutExpired)


def test_metadata_read_oserror_surfaces_as_clone_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """FileNotFoundError from post-clone metadata reads must not leak raw."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise FileNotFoundError("git executable disappeared")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    assert excinfo.value.reason_code == "METADATA_READ_FAILED"
    assert isinstance(excinfo.value.__cause__, FileNotFoundError)


# =============================================================================
# REMEDIATION-MAXI-002 — git subprocess environment isolation + ValueError wrap
# =============================================================================
#
# NEW-SECURITY-1/-2/-4 (P1/P1/P2): both ``subprocess.run`` sites in this module
# (the clone via ``_engine_primitive_subprocess`` and the metadata reads via
# ``_run_git``) historically inherited the FULL process environment (no ``env=``
# kwarg). That is an injection channel even for an HTTPS clone:
# ``GIT_CONFIG_COUNT``/``GIT_CONFIG_KEY``/``GIT_CONFIG_VALUE`` inject arbitrary
# git config NOT covered by the argv allowlist; ``GIT_SSH_COMMAND`` /
# ``GIT_PROXY_COMMAND`` are command vectors; and a URL-scoped
# ``http.<url>.extraheader`` in a global/system gitconfig leaks credentials that
# the generic ``--config http.extraheader=`` does NOT clear. The root fix is an
# explicit MINIMAL ``env=`` (``_hardened_git_env``) that does not copy
# ``os.environ`` and sets ``GIT_CONFIG_NOSYSTEM=1``,
# ``GIT_CONFIG_GLOBAL=os.devnull``, ``GIT_TERMINAL_PROMPT=0``,
# ``GIT_ALLOW_PROTOCOL=https``.
#
# F-REREVIEW-001 (P2): the clone-call ``except (TimeoutExpired, OSError)`` did
# NOT catch ``ValueError`` (e.g. embedded-null-byte argv) — it leaked past
# ``clone_repo`` AND skipped the audit-log write the docstring promises.


def _capture_env_side_effect(captured: dict):
    """subprocess.run side-effect that records the ``env`` kwarg of the FIRST
    (clone) call and the LAST call, materializes ``<dest>/.git`` for clone argv,
    and returns success for clone + canned rev-parse output for metadata."""

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        captured.setdefault("envs", []).append(kwargs.get("env"))
        if (
            isinstance(cmd, (list, tuple))
            and len(cmd) >= 2
            and cmd[0] == "git"
            and cmd[1] == "clone"
        ):
            captured.setdefault("clone_env", kwargs.get("env"))
            dest = Path(cmd[-1])
            (dest / ".git").mkdir(parents=True, exist_ok=True)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        if cmd[1:3] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="abc123\n", stderr="")
        if cmd[1:4] == ["rev-parse", "--abbrev-ref", "HEAD"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="main\n", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    return _side_effect


def _assert_hardened_env(env: dict | None) -> None:
    """Assert the captured env is the hardened minimal env, not inherited."""
    assert env is not None, "git subprocess must receive an explicit env=, not None (inheriting os.environ)"
    assert isinstance(env, dict)
    # Explicit hardening vars are SET.
    assert env.get("GIT_CONFIG_NOSYSTEM") == "1", f"GIT_CONFIG_NOSYSTEM must be '1'; env={env!r}"
    assert env.get("GIT_CONFIG_GLOBAL") == os.devnull, (
        f"GIT_CONFIG_GLOBAL must be os.devnull ({os.devnull!r}); env={env!r}"
    )
    assert env.get("GIT_TERMINAL_PROMPT") == "0", f"GIT_TERMINAL_PROMPT must be '0'; env={env!r}"
    assert env.get("GIT_ALLOW_PROTOCOL") == "https", f"GIT_ALLOW_PROTOCOL must be 'https'; env={env!r}"
    # MAXI-002 follow-up (reviewer NIT): pin GIT_PROTOCOL_FROM_USER=0 so a regression
    # dropping it is caught (prevents config/env-driven protocol re-enablement).
    assert env.get("GIT_PROTOCOL_FROM_USER") == "0", f"GIT_PROTOCOL_FROM_USER must be '0'; env={env!r}"
    # Hostile GIT_* injection vectors must NOT survive (env was NOT copied from os.environ).
    assert "GIT_SSH_COMMAND" not in env, f"GIT_SSH_COMMAND must be stripped; env={env!r}"
    assert "GIT_PROXY_COMMAND" not in env, f"GIT_PROXY_COMMAND must be stripped; env={env!r}"
    assert "GIT_CONFIG_COUNT" not in env, f"GIT_CONFIG_COUNT must be stripped; env={env!r}"
    assert "GIT_CONFIG_KEY" not in env, f"GIT_CONFIG_KEY must be stripped; env={env!r}"
    assert "GIT_CONFIG_VALUE" not in env, f"GIT_CONFIG_VALUE must be stripped; env={env!r}"
    assert "GIT_DIR" not in env, f"GIT_DIR must be stripped; env={env!r}"
    # PATH must be preserved so git is still discoverable cross-platform.
    assert "PATH" in env, f"PATH must be preserved so git resolves; env={env!r}"


def test_clone_uses_hardened_env_no_git_inheritance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEW-SECURITY-1/-2: the clone subprocess runs with an explicit hardened
    env (GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=os.devnull,
    GIT_TERMINAL_PROMPT=0, GIT_ALLOW_PROTOCOL=https) and hostile GIT_* set in
    os.environ does NOT leak into the subprocess env."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    # Plant hostile env vars that MUST NOT propagate to the git subprocess.
    monkeypatch.setenv("GIT_SSH_COMMAND", "touch /tmp/pwned;")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "echo pwned")
    monkeypatch.setenv("GIT_PROXY_COMMAND", "nc evil 1234")

    captured: dict = {}
    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_capture_env_side_effect(captured)))

    audit_clone.clone_repo(parsed, output_dir, audit_dir)

    _assert_hardened_env(captured["clone_env"])
    # Defense-in-depth: the literal GIT_CONFIG_KEY_0 form is also absent.
    assert "GIT_CONFIG_KEY_0" not in captured["clone_env"]
    assert "GIT_CONFIG_VALUE_0" not in captured["clone_env"]


def test_run_git_uses_hardened_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEW-SECURITY-4: the ``_run_git`` metadata subprocess also runs with the
    hardened env and does not inherit hostile GIT_* (e.g. GIT_DIR)."""
    clone_path = tmp_path / "clone"
    clone_path.mkdir()

    monkeypatch.setenv("GIT_DIR", "/some/other/repo/.git")
    monkeypatch.setenv("GIT_SSH_COMMAND", "touch /tmp/pwned;")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")

    captured: dict = {}

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        captured["env"] = kwargs.get("env")
        captured["cwd"] = kwargs.get("cwd")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="abc\n", stderr="")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    audit_clone._run_git(clone_path, "rev-parse", "HEAD")

    _assert_hardened_env(captured["env"])
    # cwd contract from the existing AC-21 test must still hold alongside env=.
    assert captured["cwd"] == str(clone_path)


def test_clone_valueerror_logged_and_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-REREVIEW-001: a ValueError from subprocess.run (e.g. embedded null byte
    in argv) must (a) surface as a structured CloneError, not a raw ValueError,
    and (b) still be appended to ENGINE_PRIMITIVES.json (the docstring promises
    every invocation is logged regardless of exit code)."""
    parsed = _make_parsed()
    output_dir = tmp_path / "out"
    audit_dir = output_dir / "audit"
    output_dir.mkdir()
    audit_dir.mkdir()

    def _side_effect(cmd, *args, **kwargs):  # noqa: ANN001 - mock side-effect
        raise ValueError("embedded null byte")

    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=_side_effect))

    with pytest.raises(audit_clone.CloneError) as excinfo:
        audit_clone.clone_repo(parsed, output_dir, audit_dir)
    # (a) wrapped, not leaked raw.
    assert isinstance(excinfo.value, audit_clone.CloneError)
    assert excinfo.value.reason_code == "CLONE_SUBPROCESS_ERROR"
    assert isinstance(excinfo.value.__cause__, ValueError)

    # (b) the attempt was logged despite the exception.
    log_path = audit_dir / "ENGINE_PRIMITIVES.json"
    assert log_path.exists(), "ENGINE_PRIMITIVES.json must be written even when subprocess.run raises ValueError"
    payload = json.loads(log_path.read_text(encoding="utf-8"))
    assert payload["entries"], "expected at least one logged entry for the failed attempt"
    last = payload["entries"][-1]
    assert last["exit_code"] == -1
    assert last["error_type"] == "ValueError"

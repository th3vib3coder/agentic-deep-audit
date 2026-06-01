"""Tests for the ``url`` subcommand of the agentic-deep-audit CLI (SEQ-URL-004).

Spec: ``url_workflow/007_seq_cli_url_subcommand.md``.

These tests cover the 13 acceptance criteria for the parser surface and the
dispatch into ``audit_from_url.run_url_workflow``. The latter is mocked because
its real implementation lands in SEQ-URL-005 (008_seq_orchestrator.md). We use
``monkeypatch.setattr(..., raising=False)`` to attach the mock as an attribute
of the ``audit_from_url`` module BEFORE the lazy ``from .audit_from_url import
run_url_workflow`` resolves inside ``cli.main``; ``raising=False`` permits the
attribute to be created when it does not yet exist (which is the case until
SEQ-008 lands).
"""

from __future__ import annotations

import pytest

from agentic_deep_audit import audit_from_url, cli


# ----- AC-1 -----------------------------------------------------------------

def test_cli_url_basic_parse() -> None:
    """AC-1: ``url <URL>`` parses successfully with command='url' and url set.

    Mutation guard: if ``URL_COMMAND`` were renamed to ``"urll"`` the parser
    would no longer accept the bare ``url`` token and argparse would exit.
    """

    parser = cli.build_parser()
    args = parser.parse_args(["url", "https://github.com/octocat/Hello-World"])
    assert args.command == "url"
    assert args.url == "https://github.com/octocat/Hello-World"


# ----- AC-2 -----------------------------------------------------------------

def test_cli_url_missing_url_arg() -> None:
    """AC-2: missing positional URL triggers argparse SystemExit (code 2)."""

    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["url"])
    assert exc_info.value.code == 2


# ----- AC-3 -----------------------------------------------------------------

def test_cli_url_output_dir_arg() -> None:
    """AC-3: ``--output-dir <PATH>`` populates ``args.output_dir``."""

    parser = cli.build_parser()
    args = parser.parse_args(
        ["url", "https://github.com/octocat/Hello-World", "--output-dir", "/tmp/x"]
    )
    assert args.output_dir == "/tmp/x"


# ----- AC-4 -----------------------------------------------------------------

def test_cli_url_profile_arg() -> None:
    """AC-4: ``--profile standard`` populates ``args.profile``."""

    parser = cli.build_parser()
    args = parser.parse_args(
        ["url", "https://github.com/octocat/Hello-World", "--profile", "standard"]
    )
    assert args.profile == "standard"


# ----- AC-5 -----------------------------------------------------------------

def test_cli_url_invalid_profile_rejected() -> None:
    """AC-5: ``--profile bogus`` is rejected at parse time via argparse choices."""

    parser = cli.build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(
            ["url", "https://github.com/octocat/Hello-World", "--profile", "bogus"]
        )
    assert exc_info.value.code == 2


# ----- AC-6 -----------------------------------------------------------------

def test_cli_url_dry_run_arg() -> None:
    """AC-6: ``--dry-run`` toggles ``args.dry_run`` to True."""

    parser = cli.build_parser()
    args = parser.parse_args(
        ["url", "https://github.com/octocat/Hello-World", "--dry-run"]
    )
    assert args.dry_run is True


# ----- AC-7 -----------------------------------------------------------------

def test_cli_url_timeout_arg() -> None:
    """AC-7: ``--timeout 600`` is parsed as int."""

    parser = cli.build_parser()
    args = parser.parse_args(
        ["url", "https://github.com/octocat/Hello-World", "--timeout", "600"]
    )
    assert args.timeout == 600
    assert isinstance(args.timeout, int)


# ----- AC-8 -----------------------------------------------------------------

def test_cli_url_output_dir_default() -> None:
    """AC-8: without ``--output-dir`` the parser leaves ``args.output_dir=None``.

    The spec text (``Defaults to ./audit_runs/<safe_repo_name>/``) describes
    the *orchestrator's* default behavior; the parser itself does not default
    the value — that is delegated to ``audit_from_url.run_url_workflow``.
    """

    parser = cli.build_parser()
    args = parser.parse_args(["url", "https://github.com/octocat/Hello-World"])
    assert args.output_dir is None


# ----- AC-9 -----------------------------------------------------------------

def test_cli_url_profile_default() -> None:
    """AC-9: default ``--profile`` is ``"standard"``."""

    parser = cli.build_parser()
    args = parser.parse_args(["url", "https://github.com/octocat/Hello-World"])
    assert args.profile == "standard"


# ----- AC-10 ----------------------------------------------------------------

def test_cli_url_timeout_default() -> None:
    """AC-10: default ``--timeout`` is 300 seconds."""

    parser = cli.build_parser()
    args = parser.parse_args(["url", "https://github.com/octocat/Hello-World"])
    assert args.timeout == 300


# ----- AC-11 ----------------------------------------------------------------

def test_cli_url_help_text(capsys: pytest.CaptureFixture[str]) -> None:
    """AC-11: ``url --help`` output includes the positional and key flags."""

    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["url", "--help"])
    captured = capsys.readouterr()
    out = captured.out
    assert "url" in out
    assert "--profile" in out
    assert "--timeout" in out


# ----- AC-12 ----------------------------------------------------------------

def test_cli_url_dry_run_does_not_clone(monkeypatch: pytest.MonkeyPatch) -> None:
    """AC-12: ``--dry-run`` reaches the dispatch and forwards ``dry_run=True``.

    The dispatch performs a lazy ``from .audit_from_url import run_url_workflow``;
    we patch the attribute on the ``audit_from_url`` module BEFORE calling
    ``cli.main`` so the from-import binds to our mock. ``raising=False`` is
    required because ``run_url_workflow`` does not yet exist (SEQ-008 lands it).
    """

    calls: list[dict[str, object]] = []

    def fake_run_url_workflow(**kwargs: object) -> int:
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(
        audit_from_url, "run_url_workflow", fake_run_url_workflow, raising=False
    )
    exit_code = cli.main(
        ["url", "https://github.com/octocat/Hello-World", "--dry-run"]
    )
    assert exit_code == 0
    assert len(calls) == 1
    assert calls[0]["dry_run"] is True
    assert calls[0]["url"] == "https://github.com/octocat/Hello-World"


# ----- AC-13 ----------------------------------------------------------------

def test_cli_url_dispatches_to_orchestrator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-13: dispatch forwards all six fields with the expected kwarg names.

    Mocking strategy is identical to AC-12 — see that docstring for the
    rationale on ``raising=False``.
    """

    calls: list[dict[str, object]] = []

    def fake_run_url_workflow(**kwargs: object) -> int:
        calls.append(kwargs)
        return 0

    monkeypatch.setattr(
        audit_from_url, "run_url_workflow", fake_run_url_workflow, raising=False
    )
    exit_code = cli.main(
        [
            "url",
            "https://github.com/octocat/Hello-World",
            "--profile",
            "extended",
            "--timeout",
            "600",
        ]
    )
    assert exit_code == 0
    assert len(calls) == 1
    kwargs = calls[0]
    assert kwargs == {
        "url": "https://github.com/octocat/Hello-World",
        "output_dir": None,
        "profile": "extended",
        "allowed_roots": [],
        "dry_run": False,
        "timeout_seconds": 600,
    }

"""URL parser/validation and sandbox-clone primitive for GitHub repos.

Phase 1 — SEQ-URL-001 (``parse_github_url``):
    Pure side-effect-free validation of operator-supplied GitHub HTTPS URLs.
    See ``url_workflow/004_seq_url_validation.md``.

Phase 2 — SEQ-URL-002 (``clone_repo``, ``read_clone_metadata``, ...):
    Bounded ``git clone`` invocation against a sandbox path, with the
    subprocess wrapped by a documented "engine primitive" boundary so the
    operation is logged and the URL is re-checked before egressing the
    network. See ``url_workflow/005_seq_sandbox_clone.md``.

The module exposes a tight allow-list of HTTPS GitHub URLs and rejects
anything else with a structured `InvalidGithubUrlError` carrying both a
human-readable ``message`` and a machine-readable ``reason_code``.

Threat model references: T-URL-01..T-URL-15 (see
``url_workflow/003_threat_model_url.md``).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "CLONE_DEFAULT_TIMEOUT_SECONDS",
    "ClonedRepo",
    "CloneError",
    "EnginePrimitiveError",
    "FORBIDDEN_CHARS_IN_URL",
    "GITHUB_HTTPS_PATTERN",
    "URL_MAX_LENGTH",
    "WINDOWS_RESERVED_NAMES",
    "InvalidGithubUrlError",
    "ParsedGithubUrl",
    "clone_repo",
    "derive_safe_repo_name",
    "is_windows",
    "parse_github_url",
    "read_clone_metadata",
]


# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

#: Maximum accepted URL length, in characters. Anything longer is rejected
#: before any regex work to bound CPU.
URL_MAX_LENGTH = 2048

#: Strict allow-list pattern for the only URL shape we accept.
#:
#: REMEDIATED 2026-05-31: the dot in ``github.com`` is escaped with a SINGLE
#: backslash inside a raw string (``r"github\.com"``). A double-backslash
#: variant (``r"github\\.com"``) would attempt to match a literal backslash
#: before the ``com`` and would therefore NOT accept any real GitHub URL. See
#: ``url_workflow/015_codex_adversarial_followup.md``.
#:
#: Owner: GitHub allows usernames up to 39 characters, alphanumeric or single
#: hyphens, must not start or end with a hyphen, no consecutive hyphens. We
#: enforce the length and "first char must be alnum" rules in the pattern;
#: hyphen-edge / consecutive-hyphen rules are not strictly required for
#: clone-target validation (clone still succeeds upstream) but the pattern
#: rejects a leading hyphen by virtue of the leading alnum anchor.
#:
#: Repo: GitHub repo names accept ``[a-zA-Z0-9._-]`` up to 100 chars.
GITHUB_HTTPS_PATTERN = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,38})?)/"
    r"(?P<repo>[a-zA-Z0-9._-]{1,100})"
    r"(?:\.git)?"
    r"/?$"
)

#: Characters that must never appear inside an accepted URL. Covers all C0
#: controls (``0x00``..``0x1f``) and DEL (``0x7f``). NUL alone would already
#: derail clone tooling on POSIX; the broader set defends against shell-
#: parser quirks on Windows.
FORBIDDEN_CHARS_IN_URL = frozenset(chr(c) for c in range(0, 32)) | frozenset({chr(0x7F)})

#: Windows device-name reservations. A repo whose sanitized name collides
#: with one of these would be unusable as a top-level directory on Windows
#: (``CON``, ``AUX``, ...). The safe-name derivation appends ``_repo`` to
#: disambiguate.
WINDOWS_RESERVED_NAMES = frozenset(
    {
        "con", "prn", "aux", "nul",
        "com1", "com2", "com3", "com4", "com5",
        "com6", "com7", "com8", "com9",
        "lpt1", "lpt2", "lpt3", "lpt4", "lpt5",
        "lpt6", "lpt7", "lpt8", "lpt9",
    }
)


# ---------------------------------------------------------------------------
# Errors and result types
# ---------------------------------------------------------------------------


class InvalidGithubUrlError(ValueError):
    """Raised when an input URL fails any validation rule.

    The exception carries both a human-readable ``message`` and a stable
    machine-readable ``reason_code`` so callers can branch on the reason
    without parsing English text.
    """

    __slots__ = ("message", "reason_code")

    def __init__(self, message: str, reason_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code

    def __repr__(self) -> str:  # pragma: no cover - cosmetic only
        return f"InvalidGithubUrlError(reason_code={self.reason_code!r}, message={self.message!r})"


@dataclass(frozen=True)
class ParsedGithubUrl:
    """Successful parse result.

    Attributes
    ----------
    owner:
        GitHub username or organisation, as it appeared in the URL.
    repo:
        Repository name with any trailing ``.git`` or ``/`` already stripped.
    safe_repo_name:
        Deterministically-sanitized ``owner__repo`` identifier suitable for
        use as a filesystem directory name on any platform (Linux, macOS,
        Windows).
    clone_url:
        Canonical clone URL in the form ``https://github.com/<owner>/<repo>.git``.
        Always normalized regardless of trailing slash or ``.git`` suffix on
        the input.
    """

    owner: str
    repo: str
    safe_repo_name: str
    clone_url: str


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def derive_safe_repo_name(owner: str, repo: str) -> str:
    """Derive a deterministic filesystem-safe identifier from owner and repo.

    The output is lowercased, restricted to ``[a-z0-9_-]``, collapses runs of
    underscores, trims leading/trailing ``_``/``-``, and disambiguates names
    that would collide with Windows device reservations.

    This function is pure: no I/O, no global state.
    """
    combined = f"{owner.lower()}__{repo.lower()}"
    safe = re.sub(r"[^a-z0-9_-]", "_", combined)
    safe = re.sub(r"_+", "_", safe).strip("_-")
    if safe in WINDOWS_RESERVED_NAMES:
        safe = f"{safe}_repo"
    return safe


def parse_github_url(url: str) -> ParsedGithubUrl:
    """Validate and parse a GitHub HTTPS clone URL.

    Parameters
    ----------
    url:
        Untrusted operator-supplied URL string.

    Returns
    -------
    ParsedGithubUrl
        Parsed and normalized components on success.

    Raises
    ------
    InvalidGithubUrlError
        With a stable ``reason_code`` on any validation failure.

    Notes
    -----
    Pure function: no network, filesystem, or subprocess access.
    """
    if not isinstance(url, str):
        raise InvalidGithubUrlError("url must be a string", "TYPE_NOT_STRING")

    if len(url) > URL_MAX_LENGTH:
        raise InvalidGithubUrlError(
            f"url exceeds max length {URL_MAX_LENGTH}",
            "URL_TOO_LONG",
        )

    if any(c in FORBIDDEN_CHARS_IN_URL for c in url):
        raise InvalidGithubUrlError(
            "url contains control or zero bytes",
            "URL_CONTROL_CHARS",
        )

    if "?" in url or "#" in url:
        raise InvalidGithubUrlError(
            "url must not contain query or fragment",
            "URL_QUERY_OR_FRAGMENT",
        )

    match = GITHUB_HTTPS_PATTERN.match(url)
    if match is None:
        raise InvalidGithubUrlError(
            "url does not match accepted GitHub HTTPS pattern",
            "URL_PATTERN_MISMATCH",
        )

    owner = match.group("owner")
    repo = match.group("repo").removesuffix(".git")

    if not repo:
        raise InvalidGithubUrlError(
            "url repo segment empty after .git suffix strip",
            "URL_PATTERN_MISMATCH",
        )

    if set(repo) <= {"."}:
        raise InvalidGithubUrlError(
            f"url repo segment is purely dots: {repo!r}",
            "URL_PATTERN_MISMATCH",
        )

    safe_repo_name = derive_safe_repo_name(owner, repo)
    if not safe_repo_name:
        raise InvalidGithubUrlError(
            "url produces empty safe_repo_name",
            "URL_NO_SAFE_NAME",
        )

    clone_url = f"https://github.com/{owner}/{repo}.git"

    return ParsedGithubUrl(
        owner=owner,
        repo=repo,
        safe_repo_name=safe_repo_name,
        clone_url=clone_url,
    )


# =============================================================================
# SEQ-URL-002 — Sandbox Clone Primitive
# =============================================================================
#
# Spec: ``url_workflow/005_seq_sandbox_clone.md``.
#
# The clone is the ONE explicit network-egress operation in this workflow. It
# is treated as an "engine primitive": every invocation passes through
# ``_engine_primitive_subprocess`` which:
#
# 1. asserts that the argv is exactly ``git clone <flags...> <url> <dest>``
#    with the URL matching the same GitHub HTTPS allow-list pattern used by
#    ``parse_github_url`` (defense in depth — the URL has ALREADY been
#    validated by parse_github_url, but we re-check at the boundary so an
#    accidental call site bypassing the validator still cannot egress);
# 2. appends a structured audit entry to ``audit_dir/ENGINE_PRIMITIVES.json``
#    (timestamp, primitive_id, argv, exit_code) regardless of success or
#    failure — defense in depth so a failed clone is still observed.
#
# Direct ``subprocess.run`` from ``clone_repo`` is forbidden — the wrapper is
# the only code path that may spawn the network-touching git process.
#
# Policy alignment: post-clone metadata reads (rev-parse, etc.) use the
# allow-listed subcommands from ``policies/BLOCKED_COMMANDS_ALLOWLIST.json``
# WITHOUT the ``-C`` flag (which the policy blocks as a dangerous argument).
# The working directory is conveyed via the ``cwd=`` kwarg of subprocess.run.


#: Default ``git clone`` timeout, in seconds. Bounds total network egress time
#: even when the remote stalls; surfaces as ``CloneError(CLONE_TIMEOUT)``.
CLONE_DEFAULT_TIMEOUT_SECONDS = 300
ENGINE_PRIMITIVE_GIT_CLONE = "git-clone-url-workflow"
GIT_METADATA_ALLOWED_SUBCOMMANDS = frozenset({"rev-parse", "status", "ls-files", "log"})
# VER-F003 remediation: a flag-ALLOWLIST (robust) supersedes the prior one-token
# denylist ({"-C"}). Any dash-prefixed metadata argument that is NOT explicitly
# allow-listed is rejected, so dangerous git flags beyond -C (e.g. --git-dir,
# --output, -c <config>, --ext-diff, --work-tree) cannot pass even if a future
# caller supplied them. Current metadata reads use only the --abbrev-ref flag.
GIT_METADATA_ALLOWED_FLAGS = frozenset({"--abbrev-ref"})


class CloneError(Exception):
    """Raised when ``clone_repo`` cannot produce a usable sandbox clone.

    Carries a stable ``reason_code`` so callers branch on the reason rather
    than parsing English text. Reason codes:

    - ``SANDBOX_ESCAPE`` — clone target resolves outside ``output_dir/_clone``.
    - ``CLONE_PATH_EXISTS`` — destination already exists; no ``force``.
    - ``FORCE_NOT_IMPLEMENTED`` — ``force=True`` requested but unsupported here.
    - ``CLONE_TIMEOUT`` — ``git clone`` exceeded the timeout budget.
    - ``CLONE_SUBPROCESS_FAILED`` — ``git clone`` raised an ``OSError`` (e.g.
      missing ``git`` executable).
    - ``CLONE_SUBPROCESS_ERROR`` — ``git clone`` raised an unexpected
      ``ValueError`` (e.g. embedded-null-byte argv); logged then wrapped so it
      never leaks raw (F-REREVIEW-001).
    - ``PRIMITIVE_BOUNDARY`` — engine primitive boundary check tripped.
    - ``GIT_CLONE_FAILED`` — git exited non-zero.
    - ``MISSING_GIT_DIR`` — clone completed but produced no ``.git/`` dir.
    - ``POST_CLONE_SANDBOX_ESCAPE`` — post-clone resolve escapes sandbox.
    - ``METADATA_READ_FAILED`` — post-clone ``git rev-parse`` failed or timed
      out; covers CalledProcessError / TimeoutExpired from ``_run_git``.
    """

    __slots__ = ("message", "reason_code")

    def __init__(self, message: str, reason_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code

    def __repr__(self) -> str:  # pragma: no cover - cosmetic only
        return f"CloneError(reason_code={self.reason_code!r}, message={self.message!r})"


class EnginePrimitiveError(Exception):
    """Raised when an engine-primitive boundary contract is violated.

    Reason codes:

    - ``PRIMITIVE_CMD_MISMATCH`` — argv head not ``["git", "clone"]``.
    - ``PRIMITIVE_URL_NOT_ALLOWED`` — URL does not match allowed pattern.
    """

    __slots__ = ("message", "reason_code")

    def __init__(self, message: str, reason_code: str) -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code

    def __repr__(self) -> str:  # pragma: no cover - cosmetic only
        return (
            f"EnginePrimitiveError(reason_code={self.reason_code!r}, "
            f"message={self.message!r})"
        )


@dataclass(frozen=True)
class ClonedRepo:
    """Successful clone result.

    Attributes
    ----------
    clone_path:
        Absolute path of the produced clone, inside ``output_dir/_clone``.
    safe_repo_name:
        The filesystem-safe identifier (mirror of ``ParsedGithubUrl.safe_repo_name``).
    git_metadata:
        Dict with keys ``head_sha``, ``remote_url``, ``branch_name`` derived
        from policy-allowlisted git subcommands (rev-parse) and the validated
        ``parsed.clone_url`` (NOT from ``git config --get``).
    timeout_seconds:
        Effective timeout used for the clone (returned for caller audit).
    """

    clone_path: Path
    safe_repo_name: str
    git_metadata: dict
    timeout_seconds: int


def is_windows() -> bool:
    """Return True iff running on a Windows platform.

    Used to pick the platform-appropriate ``core.hooksPath`` sentinel.
    """
    return sys.platform.startswith("win")


#: Process-environment variable names preserved (if present) when building the
#: hardened git environment. These are NOT git-behaviour knobs — they are the
#: minimum the OS/git needs to locate and run the ``git`` executable and write
#: to a temp dir cross-platform. Notably ABSENT: every ``GIT_*`` variable (they
#: are injection vectors and are re-set explicitly below), plus ``HOME`` on
#: POSIX (``GIT_CONFIG_GLOBAL=os.devnull`` bypasses ``~/.gitconfig`` so HOME is
#: not needed for config, and not exposing it removes a credential-store/path
#: surface).
_GIT_ENV_PASSTHROUGH_POSIX = ("PATH",)
_GIT_ENV_PASSTHROUGH_WINDOWS = (
    "PATH",
    "PATHEXT",
    "SystemRoot",
    "SystemDrive",
    "windir",
    "TEMP",
    "TMP",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "ProgramData",
    "LOCALAPPDATA",
    "APPDATA",
    "COMSPEC",
)


def _hardened_git_env() -> dict[str, str]:
    """Return a MINIMAL, hardened environment for git subprocesses.

    Security rationale (NEW-SECURITY-1, NEW-SECURITY-2, NEW-SECURITY-4 — see
    ``url_workflow/impl_reviews/CLAUDE_NONAUTHOR_REVIEW_OF_MAXI_REMEDIATION_001.md``):

    The clone (``_engine_primitive_subprocess``) and the post-clone metadata
    reads (``_run_git``) previously called ``subprocess.run`` with NO ``env=``
    kwarg, so they inherited the FULL ``os.environ``. For a security-audit tool
    whose premise is "no target-code execution", an inherited environment is a
    real injection channel even for an HTTPS clone:

    - ``GIT_CONFIG_COUNT`` / ``GIT_CONFIG_KEY_<n>`` / ``GIT_CONFIG_VALUE_<n>``
      inject arbitrary git config keys (e.g. ``core.fsmonitor=<cmd>``,
      ``core.pager``, aliases) that the argv ``--config`` allowlist does NOT
      cover (NEW-SECURITY-1).
    - ``GIT_SSH_COMMAND`` / ``GIT_PROXY_COMMAND`` are direct command vectors.
    - A URL-scoped ``http.<url>.extraheader`` in a pre-existing global/system
      gitconfig leaks credentials on the clone request — the generic argv
      ``--config http.extraheader=`` clears ONLY the generic key, not the
      URL-scoped one (NEW-SECURITY-2).

    The robust, single root fix is to run git with an EXPLICIT minimal env that
    is NOT a copy of ``os.environ`` (so every ``GIT_*`` injection vector is
    dropped by construction), preserving only the handful of variables git/OS
    needs to find and run the executable, and SETTING the hardening knobs:

    - ``GIT_CONFIG_NOSYSTEM=1`` — ignore ``/etc/gitconfig`` (system config).
    - ``GIT_CONFIG_GLOBAL=os.devnull`` — bypass ``~/.gitconfig`` entirely,
      including any URL-scoped ``http.<url>.extraheader`` (closes
      NEW-SECURITY-2 at the root; ``NUL`` on Windows, ``/dev/null`` on POSIX).
    - ``GIT_TERMINAL_PROMPT=0`` — never block on an interactive credential
      prompt.
    - ``GIT_ALLOW_PROTOCOL=https`` — restrict transports to https only; blocks
      ``ext::``, ``file://``, ``ssh://`` redirection vectors.
    - ``GIT_PROTOCOL_FROM_USER=0`` — user-supplied URLs may not enable extra
      protocols beyond the allowlist above.

    By NOT copying ``os.environ``, ``GIT_CONFIG_COUNT``/``KEY``/``VALUE``,
    ``GIT_SSH_COMMAND``, ``GIT_PROXY_COMMAND``, ``GIT_DIR``, ``GIT_WORK_TREE``,
    and every other ``GIT_*`` are stripped automatically.

    Returns
    -------
    dict[str, str]
        A fresh dict suitable to hand to ``subprocess.run(..., env=...)``.
    """
    passthrough = _GIT_ENV_PASSTHROUGH_WINDOWS if is_windows() else _GIT_ENV_PASSTHROUGH_POSIX
    env: dict[str, str] = {}
    for name in passthrough:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    # Explicit hardening — set LAST so a (hypothetical) passthrough collision
    # could never override these.
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ALLOW_PROTOCOL"] = "https"
    env["GIT_PROTOCOL_FROM_USER"] = "0"
    return env


def clone_repo(
    parsed: ParsedGithubUrl,
    output_dir: Path,
    audit_dir: Path,
    *,
    timeout_seconds: int = CLONE_DEFAULT_TIMEOUT_SECONDS,
    force: bool = False,
) -> ClonedRepo:
    """Clone ``parsed.clone_url`` into a sandboxed location under ``output_dir``.

    Threats covered (T-URL-07..T-URL-13, T-URL-15 — see threat model 003):
    sandbox escape via crafted safe_repo_name, hook execution on clone,
    submodule recursion, credential leakage, tag-flood, branch-flood,
    network stall, post-clone path escape, atomic mkdir race.

    Parameters
    ----------
    parsed:
        Validated URL components from ``parse_github_url``.
    output_dir:
        Operator-supplied output directory; the clone lands at
        ``output_dir/_clone/<safe_repo_name>``.
    audit_dir:
        Directory where ``ENGINE_PRIMITIVES.json`` is appended. REMEDIATION-002:
        passed explicitly so the orchestrator (008) controls audit-log location.
    timeout_seconds:
        Per-clone timeout. Defaults to ``CLONE_DEFAULT_TIMEOUT_SECONDS``.
    force:
        Future hook for safe re-clone with cleanup; not implemented in this
        sequence — raises ``FORCE_NOT_IMPLEMENTED`` if set.

    Raises
    ------
    CloneError
        With a stable ``reason_code`` on any failure.
    """
    output_dir = output_dir.resolve()
    audit_dir = audit_dir.resolve()
    clone_root = (output_dir / "_clone").resolve()
    clone_path = (clone_root / parsed.safe_repo_name).resolve()

    try:
        audit_dir.relative_to(output_dir)
    except ValueError as exc:
        raise CloneError(
            f"audit_dir outside output_dir: {audit_dir}",
            "AUDIT_DIR_OUTSIDE_OUTPUT",
        ) from exc

    # T-URL-08 sandbox escape check: the resolved clone path MUST live under
    # the resolved clone_root. A crafted safe_repo_name with ``..`` would slip
    # the directory boundary; we reject before any FS or subprocess work.
    try:
        clone_path.relative_to(clone_root)
    except ValueError as exc:
        raise CloneError(
            f"clone path outside sandbox: {clone_path}",
            "SANDBOX_ESCAPE",
        ) from exc

    # T-URL-15 atomic mkdir contract: the mkdir itself IS the atomic check.
    # ``force`` is documented but not implemented in this iteration; reject up
    # front so the contract surface is explicit rather than implicit via a
    # would-be FileExistsError on a pre-created path.
    if force:
        raise CloneError(
            "force flag not implemented in this iteration",
            "FORCE_NOT_IMPLEMENTED",
        )

    # Atomic create-or-fail: a stat()-then-mkdir TOCTOU race window cannot
    # occur because mkdir(exist_ok=False) is itself the existence check. If a
    # concurrent worker (or pre-existing artifact from a previous run) holds
    # the path, the FS surfaces FileExistsError which we re-raise as the
    # structured CLONE_PATH_EXISTS reason code. Parent directories are still
    # created best-effort (parents=True) — only the LEAF is the atomic check.
    try:
        clone_path.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise CloneError(
            f"clone path exists: {clone_path}",
            "CLONE_PATH_EXISTS",
        ) from exc

    # ``git clone`` refuses a non-empty destination; the empty dir we just
    # created is acceptable because git also accepts an existing empty dir.

    # Pick the platform-appropriate hooksPath sentinel before assembling argv.
    hooks_target = "core.hooksPath=NUL" if is_windows() else "core.hooksPath=/dev/null"

    cmd = [
        "git", "clone",
        "--depth", "1",
        "--no-tags",
        "--single-branch",
        "--no-recurse-submodules",
        "--config", "submodule.recurse=false",
        "--config", "credential.helper=",
        "--config", "http.extraheader=",
        "--config", hooks_target,
        parsed.clone_url,
        str(clone_path),
    ]

    try:
        result = _engine_primitive_subprocess(
            cmd,
            audit_dir=audit_dir,
            primitive_id=ENGINE_PRIMITIVE_GIT_CLONE,
            allowed_url_pattern=GITHUB_HTTPS_PATTERN,
            timeout_seconds=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise CloneError(
            f"clone exceeded timeout {timeout_seconds}s",
            "CLONE_TIMEOUT",
        ) from exc
    except OSError as exc:
        raise CloneError(
            f"clone subprocess failed: {exc}",
            "CLONE_SUBPROCESS_FAILED",
        ) from exc
    except ValueError as exc:
        # F-REREVIEW-001: an unexpected ValueError from subprocess.run (e.g.
        # ``embedded null byte`` in argv) was already logged to
        # ENGINE_PRIMITIVES.json inside the wrapper; convert it to a structured
        # CloneError here so it never leaks raw out of clone_repo / the
        # orchestrator's structured-exit contract. (InvalidGithubUrlError is a
        # ValueError subclass but is not raised on this code path — the URL
        # re-check inside the wrapper raises EnginePrimitiveError instead.)
        raise CloneError(
            f"clone subprocess raised unexpected error: {exc}",
            "CLONE_SUBPROCESS_ERROR",
        ) from exc
    except EnginePrimitiveError as exc:
        reason_code = (
            "PRIMITIVE_LOG_FAILED"
            if exc.reason_code == "PRIMITIVE_LOG_FAILED"
            else "PRIMITIVE_BOUNDARY"
        )
        raise CloneError(
            f"engine primitive boundary violated: {exc}",
            reason_code,
        ) from exc

    if result.returncode != 0:
        # Truncate stderr to bound the error message; git's "fatal: ..." is
        # usually well under 500 chars but a misbehaving remote could spam.
        raise CloneError(
            f"git clone failed: {result.stderr[:500]}",
            "GIT_CLONE_FAILED",
        )

    # T-URL-08 defense-in-depth: re-verify clone_path is still under the
    # sandbox after the clone (e.g., a server-side trick that wrote symlinks
    # into the destination cannot push our anchor outside).
    if not clone_path.exists() or not (clone_path / ".git").exists():
        raise CloneError(
            f"clone did not produce expected git dir at {clone_path}",
            "MISSING_GIT_DIR",
        )

    try:
        clone_path.resolve().relative_to(clone_root)
    except ValueError as exc:  # pragma: no cover - defensive: pre-check makes this unreachable.
        raise CloneError(
            f"clone path escaped sandbox after clone: {clone_path}",
            "POST_CLONE_SANDBOX_ESCAPE",
        ) from exc

    # F-SF-4: ``_run_git`` invokes subprocess.run with ``check=True``; any
    # non-zero exit from rev-parse (corrupt repo, missing HEAD, etc.) would
    # otherwise leak ``subprocess.CalledProcessError`` (and TimeoutExpired
    # from the 30s rev-parse timeout) out of ``clone_repo``, breaking the
    # docstring contract that promises CloneError-only on failure. Wrap and
    # restate as a structured ``METADATA_READ_FAILED`` reason code.
    try:
        metadata = read_clone_metadata(clone_path, parsed)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise CloneError(
            f"post-clone metadata read failed: {exc}",
            "METADATA_READ_FAILED",
        ) from exc

    return ClonedRepo(
        clone_path=clone_path,
        safe_repo_name=parsed.safe_repo_name,
        git_metadata=metadata,
        timeout_seconds=timeout_seconds,
    )


def read_clone_metadata(clone_path: Path, parsed: ParsedGithubUrl) -> dict:
    """Return ``{head_sha, remote_url, branch_name}`` for a freshly-cloned repo.

    REMEDIATION-003 (Codex 017 F1): policy probes verified verbatim:

    - ``["git", "-C", "x", "rev-parse", "HEAD"]`` is BLOCKED as
      ``dangerous_argument`` (the ``-C`` flag).
    - ``["git", "config", "--get", ...]`` is BLOCKED as ``not_allowlisted``
      (``config`` is not in ``BLOCKED_COMMANDS_ALLOWLIST.subcommands``).
    - ``["git", "rev-parse", "HEAD"]`` is ALLOWED.

    Therefore: use ``cwd=clone_path`` (NOT ``-C``) and derive ``remote_url``
    from ``parsed.clone_url`` directly. ``parse_github_url`` has ALREADY pinned
    it to the GitHub HTTPS allow-list, so the value is trustworthy.
    """
    head_sha = _run_git(clone_path, "rev-parse", "HEAD")
    branch_name = _run_git(clone_path, "rev-parse", "--abbrev-ref", "HEAD")
    return {
        "head_sha": head_sha.strip(),
        # REMEDIATION-003: remote_url is the validated clone URL, NOT a result of
        # ``git config --get remote.origin.url`` (which the policy blocks).
        "remote_url": parsed.clone_url,
        "branch_name": branch_name.strip(),
    }


def _run_git(clone_path: Path, *args: str) -> str:
    """Run an allow-listed git subcommand inside ``clone_path`` and return stdout.

    REMEDIATION-003: argv MUST start with ``["git", <allowlisted-subcommand>]``
    WITHOUT the ``-C`` flag; the working directory is set via subprocess
    ``cwd=``. Allow-listed subcommands per ``BLOCKED_COMMANDS_ALLOWLIST.json``:
    ``rev-parse``, ``status``, ``ls-files``, ``log``. Any other subcommand
    (including ``config``) is blocked by the runtime policy.
    """
    if not args or args[0] not in GIT_METADATA_ALLOWED_SUBCOMMANDS:
        subcommand = args[0] if args else "<missing>"
        raise CloneError(
            f"git metadata subcommand not allowlisted: {subcommand}",
            "METADATA_GIT_NOT_ALLOWLISTED",
        )
    # VER-F003: flag-allowlist. Reject any dash-prefixed argument (after the
    # subcommand at args[0]) that is not explicitly allow-listed. This is robust
    # vs the prior denylist: -C, --git-dir, --output, -c, --ext-diff, --work-tree,
    # etc. are ALL rejected, not just -C.
    unsafe = [
        arg
        for arg in args[1:]
        if arg.startswith("-") and arg not in GIT_METADATA_ALLOWED_FLAGS
    ]
    if unsafe:
        raise CloneError(
            f"git metadata flag not allowlisted: {unsafe[0]}",
            "METADATA_GIT_DANGEROUS_ARG",
        )
    result = subprocess.run(
        ["git", *args],
        cwd=str(clone_path),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
        # NEW-SECURITY-4: run with an explicit minimal env so GIT_DIR /
        # GIT_CONFIG_* / GIT_SSH_COMMAND etc. inherited from os.environ cannot
        # redirect or subvert these read-only metadata reads.
        env=_hardened_git_env(),
    )
    return result.stdout


def _engine_primitive_subprocess(
    cmd: list[str],
    *,
    audit_dir: Path,
    primitive_id: str,
    allowed_url_pattern,
    timeout_seconds: int,
) -> subprocess.CompletedProcess:
    """Bounded subprocess wrapper for engine network primitives.

    Boundary contract for ``primitive_id == "git-clone-url-workflow"``:

    - ``argv[0]`` must equal ``"git"`` and ``argv[1]`` must equal ``"clone"``.
    - The URL (the penultimate argv element; the last is the destination
      path) must match ``allowed_url_pattern``.
    - Every invocation is appended to ``audit_dir/ENGINE_PRIMITIVES.json``
      regardless of exit code — defense in depth so failed clones are still
      observed.

    Boundary violations raise ``EnginePrimitiveError`` BEFORE spawning the
    subprocess, and (critically) BEFORE writing the audit log, so an attacker
    cannot use a failed-boundary call as a log-injection channel.
    """
    if primitive_id != ENGINE_PRIMITIVE_GIT_CLONE:
        raise EnginePrimitiveError(
            f"unknown primitive_id: {primitive_id}",
            "PRIMITIVE_UNKNOWN",
        )

    if len(cmd) < 4 or cmd[0] != "git" or cmd[1] != "clone":
        raise EnginePrimitiveError(
            f"primitive {primitive_id} expects git clone; got {cmd[:2]}",
            "PRIMITIVE_CMD_MISMATCH",
        )
    # URL is the penultimate argv element (last is the destination path).
    url = cmd[-2]
    if not allowed_url_pattern.match(url):
        raise EnginePrimitiveError(
            f"primitive {primitive_id} url not allowed: {url}",
            "PRIMITIVE_URL_NOT_ALLOWED",
        )

    allowed_options = [
        "--depth", "1",
        "--no-tags",
        "--single-branch",
        "--no-recurse-submodules",
        "--config", "submodule.recurse=false",
        "--config", "credential.helper=",
        "--config", "http.extraheader=",
        "--config",
    ]
    option_segment = cmd[2:-2]
    if not (
        len(option_segment) == len(allowed_options) + 1
        and option_segment[: len(allowed_options)] == allowed_options
        and option_segment[-1] in {"core.hooksPath=NUL", "core.hooksPath=/dev/null"}
    ):
        raise EnginePrimitiveError(
            f"primitive {primitive_id} argv contains non-allowlisted clone options",
            "PRIMITIVE_ARG_NOT_ALLOWED",
        )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            # NEW-SECURITY-1/-2: run the network-egress clone with an explicit
            # minimal env (GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=os.devnull,
            # GIT_TERMINAL_PROMPT=0, GIT_ALLOW_PROTOCOL=https) so inherited
            # GIT_CONFIG_*/GIT_SSH_COMMAND/GIT_PROXY_COMMAND injection vectors
            # and a URL-scoped http.<url>.extraheader credential leak are
            # neutralized at the root. See ``_hardened_git_env``.
            env=_hardened_git_env(),
        )
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        # F-REREVIEW-001: ValueError (e.g. embedded-null-byte argv) is NOT a
        # subclass of (TimeoutExpired, OSError); previously it leaked past
        # clone_repo AND skipped this audit-log write, violating the docstring
        # promise that every invocation is logged regardless of exit code. We
        # now log it like any other subprocess failure, then re-raise so
        # clone_repo can map it to a structured CloneError. KeyboardInterrupt /
        # SystemExit (BaseException, not Exception) intentionally still
        # propagate uncaught.
        _append_engine_primitive_log(
            audit_dir=audit_dir,
            primitive_id=primitive_id,
            argv=cmd,
            exit_code=-1,
            error_type=type(exc).__name__,
        )
        raise

    # Defense in depth: log every completed invocation, success or failure.
    # Note: this is AFTER the boundary checks above; a boundary violation
    # therefore does NOT produce a log entry (by design, see docstring).
    _append_engine_primitive_log(
        audit_dir=audit_dir,
        primitive_id=primitive_id,
        argv=cmd,
        exit_code=result.returncode,
        error_type=None,
    )

    return result


def _append_engine_primitive_log(
    *,
    audit_dir: Path,
    primitive_id: str,
    argv: list[str],
    exit_code: int,
    error_type: str | None = None,
) -> None:
    """Append an entry to ``audit_dir/ENGINE_PRIMITIVES.json``.

    Schema:

    .. code-block:: json

       {
         "entries": [
           {
             "timestamp": "<ISO-8601 UTC, Z-suffixed>",
             "primitive_id": "<string>",
             "argv": ["<string>", ...],
             "exit_code": <int>
           }
         ]
       }
    """
    log_path = audit_dir / "ENGINE_PRIMITIVES.json"
    try:
        audit_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EnginePrimitiveError(
            f"failed to create audit_dir for ENGINE_PRIMITIVES.json: {exc}",
            "PRIMITIVE_LOG_FAILED",
        ) from exc
    existing: dict = {"entries": []}
    if log_path.exists():
        try:
            existing = json.loads(log_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise EnginePrimitiveError(
                f"failed to read existing ENGINE_PRIMITIVES.json: {exc}",
                "PRIMITIVE_LOG_FAILED",
            ) from exc
        if not isinstance(existing, dict) or not isinstance(existing.get("entries"), list):
            raise EnginePrimitiveError(
                "ENGINE_PRIMITIVES.json must be an object with entries array",
                "PRIMITIVE_LOG_FAILED",
            )
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "primitive_id": primitive_id,
        "argv": list(argv),
        "exit_code": exit_code,
    }
    if error_type is not None:
        entry["error_type"] = error_type
    existing["entries"].append(entry)
    try:
        log_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except OSError as exc:
        raise EnginePrimitiveError(
            f"failed to write ENGINE_PRIMITIVES.json: {exc}",
            "PRIMITIVE_LOG_FAILED",
        ) from exc

"""MCP host metadata redaction helpers."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse


SECRET_PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"ghp_[A-Za-z0-9_]{16,}|github_pat_[A-Za-z0-9_]+"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bsk-proj-[A-Za-z0-9_-]{16,}\b|\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bBearer\s+\S{8,}\b", re.IGNORECASE),
]

MAX_REDACTION_DEPTH = 256

# FIX-2 (Tier-0, 2026-06-02; remediated after swarm review): entropy detection is a BACKSTOP behind
# the precise SECRET_PATTERNS. It fires on a contiguous OPAQUE RUN (the secret alphabet: letters,
# digits, ``_ + -``), NOT on whole whitespace tokens. Ordinary high-entropy CODE/markup — TS/JS
# identifiers (``expect(x).toBe(y``, ``a.b[0].c``), badge URLs (``src="https://.../badge/...``) —
# is broken by ``. ( ) [ ] " : / =`` into short fragments and contains NO 20+ contiguous opaque run,
# so it is excluded (this killed the Understand-Anything false-positive avalanche: 80 flagged file
# bodies, all README/test-code). An opaque secret embedded in punctuation (connection string
# ``Pwd=<run>;``, quoted JSON value, ``KEY=<run>``) still EXPOSES its run and is caught — the earlier
# whole-token ``fullmatch`` gate MISSED these and leaked them (fail-OPEN). ``/`` and ``=`` are
# deliberately EXCLUDED from the run alphabet so URL paths/query strings cannot form false opaque
# runs; base64url tokens (``- _``) and bare base64/alnum secrets still match. ``findall`` (not a
# whole-string match) means redact_text and contains_raw_secret now agree on which runs are
# secret-like regardless of their differing surrounding-punctuation handling. Provider-prefixed
# tokens stay caught by SECRET_PATTERNS regardless. See url_workflow/026_seq_tier0_hardening.md.
#
# Why ``/`` and ``=`` are excluded: an experiment over the real corpus found NO charset/ratio
# threshold that robustly separates a base64-standard secret's run from benign URL/path runs
# (shields.io badge 0.81, repo path 0.78); including ``/`` reintroduces the URL/badge false-positive
# avalanche. So the entropy run alphabet stays alnum + ``- _`` (base64url).
#
# KNOWN LIMITATION (documented, accepted — operator scope decision 2026-06-02): this detector is a
# redaction BACKSTOP for a repo-audit tool, NOT a comprehensive secret scanner. A base64-STANDARD
# secret with no provider prefix whose ``/`` fragments it into sub-20 runs is not entropy-flagged.
# Covered regardless: provider-prefixed tokens via SECRET_PATTERNS (incl. AWS ``AKIA/ASIA`` IDs),
# base64url, JWT, and any ``/``-free opaque run >=20. Comprehensive / per-provider secret detection
# is explicitly OUT OF SCOPE (unbounded whack-a-mole; a prior AWS-specific key-name redactor was
# removed as scope creep). If real secret-scanning is ever wanted, adopt an established scanner
# ruleset (gitleaks/detect-secrets) as a separate effort. See url_workflow/026_seq_tier0_hardening.md.
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9_+-]{20,}")


def _high_entropy(value: str) -> bool:
    for run in _OPAQUE_RUN.findall(value):
        unique_ratio = len(set(run)) / len(run)
        if (
            unique_ratio > 0.55
            and bool(re.search(r"[A-Z]", run))
            and bool(re.search(r"[a-z]", run))
            and bool(re.search(r"\d", run))
        ):
            return True
    return False


def looks_secret(value: str) -> bool:
    if re.fullmatch(r"run-\d{8}T\d{6}Z", value):
        return False
    if any(pattern.search(value) for pattern in SECRET_PATTERNS):
        return True
    try:
        parsed = urlparse(value)
    except ValueError:
        # Malformed URL-like value (e.g. invalid IPv6 'https://[::1') makes urlparse raise. Do not
        # propagate: looks_secret runs on untrusted input across redaction and validation, so a
        # crash here would take down a redactor/validator. Skip the userinfo check and fall back to
        # entropy detection (which never parses URLs), always returning a bool.
        return _high_entropy(value)
    if parsed.username or parsed.password:
        return True
    return _high_entropy(value)


def redact_value(value: object) -> object:
    if not isinstance(value, str):
        return value
    if not looks_secret(value):
        return value
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"<redacted sha256:{digest}>"


def redact_host_metadata(data: object, depth: int = 0) -> object:
    if depth > MAX_REDACTION_DEPTH:
        return "<redacted:depth-limit>"
    if isinstance(data, dict):
        return {key: redact_host_metadata(value, depth + 1) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_host_metadata(item, depth + 1) for item in data]
    return redact_value(data)

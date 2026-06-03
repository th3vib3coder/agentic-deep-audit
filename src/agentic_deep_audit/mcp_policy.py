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

# FIX-2 (Tier-0, 2026-06-02) + FIX-SECRET-FP (2026-06-03, hardened after swarm review): entropy
# detection is a BACKSTOP behind the precise SECRET_PATTERNS. It fires on a contiguous OPAQUE RUN
# (alphabet = alnum + ``_ - +``), NOT on whole whitespace tokens. ``/ = . ( ) [ ] " :`` are EXCLUDED
# from the run so URL/path/markup fragments cannot form false runs (this killed the Understand-Anything
# badge / TS-assertion FP avalanche). ``_ - +`` ARE kept so base64url (``_ -``) and base64-standard
# (``+``) secrets stay whole and are covered.
#
# Discriminating CODE/PATH IDENTIFIERS from SECRETS (the hard part — a naive ``longest same-case run
# < 6`` rule leaked 12-21% of real random secrets, found by adversarial review): a random secret is a
# high-churn mix of case/digits with only SHORT same-case letter substrings; an identifier is built
# from WORDS (snake_case ``read_points3D_binary``, SCREAMING_SNAKE ``main_PROGN_EVAL_P2_ANALYSIS``,
# camelCase ``GaussianModel3DRenderer``, kebab) so most of its characters live in LONG same-case letter
# runs. We measure WORD-COVERAGE = (chars inside same-case letter runs of length >=5) / len(run); a run
# is secret-like only if coverage < 0.40 AND mixed-case AND has a digit AND unique-ratio > 0.55.
# Measured over 180k random class-mixed tokens this flags >=97% of base62 AND >=99% of base64url
# secrets while excluding 0/12 representative identifiers.
#
# Embedded secrets (``prefix_<random>`` — e.g. an MCP tool name ``agentic_deep_audit_<token>``): a word
# PREFIX can lift the whole-run coverage above the threshold, so we ALSO test each >=20-char
# ``_``/``-``-delimited SUB-SEGMENT; the random tail is isolated, flagged, and the whole value redacted.
# Provider-prefixed tokens (ghp_, sk-, AKIA, JWT, …) are caught by SECRET_PATTERNS regardless. ``findall``
# means redact_text and contains_raw_secret agree on which runs are secret-like. See 026_seq_tier0_hardening.md.
#
# KNOWN LIMITATION (documented, accepted — operator scope decision): a redaction BACKSTOP, not a
# comprehensive scanner. Unprefixed secrets that are word-like (coverage >= 0.40) or fragmented by
# ``/ = .`` into sub-20 runs are not entropy-flagged. Per-provider secret detection is OUT OF SCOPE
# (incl. AWS-specific); adopt gitleaks/detect-secrets separately if wanted. See 026_seq_tier0_hardening.md.
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9_+-]{20,}")
# A same-case LETTER run of length >=5 is treated as a "word"; identifiers are word-built, secrets are not.
_SAME_CASE_WORD = re.compile(r"[a-z]{5,}|[A-Z]{5,}")
_WORD_COVERAGE_THRESHOLD = 0.40


def _is_secret_like_run(candidate: str) -> bool:
    # candidate is always a >=20-char opaque run (or a >=20-char sub-segment of one), so len > 0.
    word_chars = sum(len(match) for match in _SAME_CASE_WORD.findall(candidate))
    return (
        len(set(candidate)) / len(candidate) > 0.55
        and word_chars / len(candidate) < _WORD_COVERAGE_THRESHOLD
        and bool(re.search(r"[A-Z]", candidate))
        and bool(re.search(r"[a-z]", candidate))
        and bool(re.search(r"\d", candidate))
    )


def _high_entropy(value: str) -> bool:
    for run in _OPAQUE_RUN.findall(value):
        if _is_secret_like_run(run):
            return True
        # A word-prefix can mask a random secret tail (prefix_<token>); test each long sub-segment
        # split on the identifier separators _ and - so the tail is isolated and still caught.
        for segment in re.split(r"[_-]+", run):
            if len(segment) >= 20 and segment != run and _is_secret_like_run(segment):
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

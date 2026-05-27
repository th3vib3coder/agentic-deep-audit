"""Untrusted Markdown sanitizer."""

from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass


INVISIBLE_CHARS = "\u00ad\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\u2066\u2067\u2068\u2069\ufeff"
HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        "\u0456": "i",
        "\u0406": "I",
        "\U0001d456": "i",
        "\U0001d5c2": "i",
        "\u043e": "o",
        "\u041e": "O",
        "\u03bf": "o",
        "\u039f": "O",
        "\u0585": "o",
        "\u0430": "a",
        "\u0410": "A",
        "\u0435": "e",
        "\u0415": "E",
        "\u0440": "p",
        "\u0420": "P",
        "\u0441": "c",
        "\u0421": "C",
        "\u0445": "x",
        "\u0425": "X",
        "\u0443": "y",
        "\u0423": "Y",
    }
)

BLOCK_PATTERNS = {
    "hidden_tag": re.compile(r"</?(system|assistant|developer|tool)\b[^>]*>|<\|?\s*(system|assistant|developer|tool)\s*\|?>|\[/?\s*(instruction|system|user|assistant|developer|tool)\b[^\]]*\]", re.IGNORECASE),
    "override_marker": re.compile(
        r"ignore\s+(all\s+)?(previous|prior)"
        r"|developer\s+instruction|system\s+prompt|do\s+not\s+tell\s+user"
        r"|ignorier(?:e|en)?\s+(?:alle\s+)?(?:vorherige|frühere|fruehere)\s+anweisungen"
        r"|ignorez?\s+(?:toutes\s+)?les\s+instructions\s+pr[ée]c[ée]dentes"
        r"|ignor(?:a|ar|e)\s+(?:todas\s+)?las\s+instrucciones\s+(?:previas|anteriores)"
        r"|olvida\s+(?:todas\s+)?las\s+instrucciones\s+(?:previas|anteriores)"
        r"|ignora\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti"
        r"|dimentica\s+(?:tutte\s+)?le\s+istruzioni\s+precedenti"
        r"|ignor(?:a|ar|e)\s+(?:todas?\s+)?as\s+instru[cç][õo]es\s+(?:anteriores|pr[ée]vias)"
        r"|esque[çc]a\s+(?:todas?\s+)?as\s+instru[cç][õo]es\s+(?:anteriores|pr[ée]vias)"
        r"|vergiss\s+(?:alle\s+)?(?:vorherige|frühere|fruehere)\s+anweisungen"
        r"|oubliez\s+(?:toutes\s+)?les\s+instructions\s+pr[ée]c[ée]dentes"
        r"|前の指示を無視|以前の指示を無視|忽略(?:之前|以前)的指示",
        re.IGNORECASE,
    ),
    "zero_width": re.compile(f"[{re.escape(INVISIBLE_CHARS)}]|[\U000e0000-\U000e007f]"),
    "base64_like": re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
    "secret_request": re.compile(r"\b(env vars?|home directory|token|secret|api key)\b", re.IGNORECASE),
    "tool_request": re.compile(
        r"\b(run|execute|call)\s+(a\s+)?(shell|tool|command)\b|\bbash\s+-c\b|\beval\b"
        r"|\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(sh|bash)\b"
        r"|\bnc\s+-e\b|\bpython\s+-c\b|\bpowershell\s+-Command\b"
        r"|\b__import__\s*\(|\bos\.(?:system|popen|spawn\w*|exec\w*)\s*\(|\bsubprocess\.",
        re.IGNORECASE,
    ),
}


@dataclass(frozen=True)
class SanitizedMarkdown:
    sanitized_text: str
    flagged_ranges: list[dict[str, object]]
    raw_reference: dict[str, object]
    decision: str


def detection_text(markdown_text: str) -> str:
    decoded = html.unescape(markdown_text)
    normalized = unicodedata.normalize("NFKC", decoded).translate(HOMOGLYPH_TRANSLATION)
    return "".join(char for char in normalized if char not in INVISIBLE_CHARS and not (0xE0000 <= ord(char) <= 0xE007F))


def sanitize_markdown(path: str, markdown_text: str, start_byte: int = 0, evidence_id: str | None = None) -> SanitizedMarkdown:
    flags: list[dict[str, object]] = []
    for kind, pattern in BLOCK_PATTERNS.items():
        for match in pattern.finditer(markdown_text):
            flags.append({"kind": kind, "start_byte": start_byte + match.start(), "end_byte": start_byte + match.end(), "severity": "critical" if kind in {"hidden_tag", "override_marker"} else "medium"})
    normalized_text = detection_text(markdown_text)
    if normalized_text != markdown_text:
        for kind in ["hidden_tag", "override_marker", "secret_request", "tool_request"]:
            pattern = BLOCK_PATTERNS[kind]
            if pattern.search(normalized_text) and not any(flag["kind"] == kind for flag in flags):
                flags.append({"kind": kind, "start_byte": start_byte, "end_byte": start_byte + len(markdown_text.encode("utf-8")), "severity": "critical" if kind in {"hidden_tag", "override_marker"} else "medium"})
    decision = "blocked_from_llm_context" if any(flag["kind"] in {"hidden_tag", "override_marker", "secret_request", "tool_request"} for flag in flags) else ("quoted_with_flags" if flags else "pass")
    quoted = "\n".join(f"> {line}" for line in markdown_text.splitlines())
    raw_reference = {
        "path": path,
        "evidence_id": evidence_id,
        "start_byte": start_byte,
        "end_byte": start_byte + len(markdown_text.encode("utf-8")),
        "raw_sha256": hashlib.sha256(markdown_text.encode("utf-8")).hexdigest(),
    }
    return SanitizedMarkdown(sanitized_text=quoted, flagged_ranges=flags, raw_reference=raw_reference, decision=decision)

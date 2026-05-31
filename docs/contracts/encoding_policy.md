# Encoding & Newline Policy

This contract defines how the engine decodes text, so behaviour is deterministic across Windows
and POSIX. It is enforced by `tests/test_encoding_portability.py` against fixtures under
`tests/fixtures/encoding_portability/`.

## Config files

- **UTF-8** is the required encoding for user config files (`audit.config.yaml` / `.json`). They
  are read with `utf-8-sig`, so a leading **BOM** is accepted and stripped before parsing.
- **CRLF and LF** line endings are both accepted; config parsing does not depend on the line
  ending. `read_text_auto_capped(..., normalize_newlines=True)` collapses CRLF and lone CR to LF
  for callers that want line-ending-independent text.
- A **non-UTF-8 config** fails fast with a clear **diagnostic** (`ConfigError: config file is not
  valid UTF-8: <path>`) rather than a raw `UnicodeDecodeError` or a silent mis-decode.

## Target-repo source files

- Source files in the audited repository are untrusted input. A **non-UTF-8 source** file
  **degrades** deterministically under best-effort extraction (`errors="replace"`): invalid bytes
  become the Unicode **replacement character** (`U+FFFD`) and extraction never crashes.
- BOM and UTF-16 BOM-prefixed inputs are detected and decoded via `utf-8-sig` / `utf-16` so the
  byte-order mark is not mistaken for content.

## Byte-faithful paths

- Evidence byte ranges, corpus hashes, and any offset-sensitive reader keep the **default**
  (`normalize_newlines=False`); newline rewriting is opt-in only, so those paths stay
  byte-faithful to the raw file.

## Decode helper summary

| Input | Behaviour |
|---|---|
| UTF-8 | decoded as-is |
| UTF-8 with BOM | BOM stripped (`utf-8-sig`) |
| UTF-16 with BOM | decoded via `utf-16` |
| CRLF | accepted; normalized to LF only when `normalize_newlines=True` |
| LF | accepted unchanged |
| non-UTF-8 config | `ConfigError` with a clear diagnostic |
| non-UTF-8 source | degrades to `U+FFFD` (replacement character), no crash |

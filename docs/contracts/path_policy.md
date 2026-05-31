# Path Portability Policy

How the engine accepts repository **root** paths and resolves repo-**relative** paths across
Windows and POSIX. Enforced by `tests/test_path_portability.py` and
`tests/test_validator_helper_units.py`.

## Repository root paths (`repo.path`, `output_dir`)

Resolved by `config.resolve_repo_path` / `normalize_output_dir`: expanded, made absolute against
the config dir (or CWD), `resolve()`-d, required to exist, and constrained under the allowed
roots.

| Shape | Expectation |
|---|---|
| Windows **drive** path (`D:\work\repo`) | accepted on Windows as an absolute root |
| **UNC**-like path (`\\server\share\repo`) | handled gracefully — resolved if it exists, else a clear `ConfigError`; never a crash |
| **POSIX** absolute path (`/home/me/repo`) | accepted on POSIX as an absolute root |
| relative path | resolved against the config dir / CWD, then constrained under allowed roots |

## Repository-relative paths (artifact/evidence references)

Classified by `limits.is_safe_repo_relative_path` and resolved by `resolve_repo_file` /
`resolve_repo_existing_file`. These are a security boundary: a path that fails the check resolves
to `None` (no read), never an exception the caller must handle ad hoc.

| Shape | Expectation |
|---|---|
| forward-slash relative (`src/app.py`) | the **normalized**, accepted form |
| **backslash** (`src\app.py`) | rejected — backslash is not a valid separator for repo-relative paths; use forward slashes |
| **colon** (`a:b`, `C:/x`, NTFS streams) | rejected (drive/stream markers are never valid repo-relative paths) |
| `..` (dot-dot) traversal | rejected — `..` in any path segment is blocked |
| absolute path (`/etc/passwd`) | rejected — repo-relative paths must not be absolute |

## Symlinks

`resolve_repo_file` calls `resolve()` (which follows symlinks) and then enforces containment with
`relative_to(repo_root)`. A **symlink** whose target escapes the repo root resolves out of
containment and is rejected (`None`). Where the platform/privilege level does not support creating
symlinks, the symlink test is skipped.

## Case sensitivity

Filesystem **case** sensitivity is honoured by the OS: on case-sensitive filesystems (typical
POSIX) `App.py` and `app.py` are distinct files; on Windows (NTFS, case-insensitive by default)
this behaviour is **unverified** and the case-sensitivity test is skipped there. No path-matching
logic assumes one regime.

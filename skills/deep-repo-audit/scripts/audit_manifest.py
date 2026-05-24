from __future__ import annotations

import json
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = PLUGIN_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from agentic_deep_audit.audit_manifest import run_manifest  # noqa: E402
from agentic_deep_audit.models import ARTIFACT_PATHS  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python audit_manifest.py <audit-dir>", file=sys.stderr)
        return 2
    audit_dir = Path(args[0])
    run_config = json.loads((audit_dir / ARTIFACT_PATHS["RUN_CONFIG"]).read_text(encoding="utf-8"))
    run_manifest(run_config, audit_dir)
    print(f"wrote manifest artifacts in {audit_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

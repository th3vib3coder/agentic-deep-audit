from __future__ import annotations

import json

from agentic_deep_audit.models import PLUGIN_ROOT


def test_skill_md_enumerates_audit_profile_enum() -> None:
    # OQ-B08: SKILL.md must enumerate the exact audit-profile enum values so an agent acting
    # on SKILL.md alone cannot invent an invalid profile. The expected values are read from the
    # schema so this guard stays in sync if the enum ever changes.
    skill_dir = PLUGIN_ROOT / "skills" / "deep-repo-audit"
    skill = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    schema = json.loads((skill_dir / "schemas" / "audit_config.schema.json").read_text(encoding="utf-8"))
    profile_enum = schema["properties"]["profile"]["enum"]
    assert profile_enum, "schema must define a non-empty profile enum"
    for value in profile_enum:
        assert value in skill, f"SKILL.md must enumerate audit profile value: {value}"

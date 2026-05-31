from __future__ import annotations

from agentic_deep_audit.models import PLUGIN_ROOT


CONTAINER_DOC = PLUGIN_ROOT / "docs" / "adapters" / "container.md"

NINE_FIELDS = (
    "adapter id",
    "user entry command",
    "required files",
    "optional files",
    "output directory",
    "security model",
    "expected skipped/deferred behavior",
    "validation command",
    "ownership of docs/tests",
)


def test_container_doc_states_deferred_with_criteria() -> None:
    text = CONTAINER_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    assert "Status: deferred" in text, "container.md must declare 'Status: deferred'"
    lowered = text.lower()
    for token in ("approval criteria", "base-image", "no host secret mounts", "network"):
        assert token in lowered, f"container.md missing deferred-criteria token: {token!r}"


def test_container_doc_has_no_dockerfile_claim() -> None:
    lowered = CONTAINER_DOC.read_text(encoding="utf-8").lower()
    assert "no dockerfile" in lowered, "container.md must explicitly state no Dockerfile ships"
    # The claim must be true: no Dockerfile actually ships in the package root.
    assert not (PLUGIN_ROOT / "Dockerfile").exists(), "a Dockerfile exists but the deferred doc claims none ships"


def test_container_doc_has_nine_fields() -> None:
    lowered = CONTAINER_DOC.read_text(encoding="utf-8").lower()
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"container.md missing field sections: {missing}"

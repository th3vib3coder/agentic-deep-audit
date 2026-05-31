from __future__ import annotations

from agentic_deep_audit.models import PLUGIN_ROOT


INSTALL_DOC = PLUGIN_ROOT / "docs" / "adapters" / "package-managers.md"

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


def test_install_doc_has_nine_fields_and_pip_pipx() -> None:
    text = INSTALL_DOC.read_text(encoding="utf-8")  # FileNotFoundError when absent (RED)
    lowered = text.lower()
    missing = [field for field in NINE_FIELDS if f"## {field}" not in lowered]
    assert not missing, f"package-managers.md missing field sections: {missing}"
    assert "```" in text, "package-managers.md must contain fenced code blocks"
    assert "pip install" in lowered, "package-managers.md must document a pip install path"
    assert "pipx install" in lowered, "package-managers.md must document a pipx install path"


def test_doc_has_windows_path_convention() -> None:
    text = INSTALL_DOC.read_text(encoding="utf-8")
    assert r"Scripts\deep-audit.exe" in text, r"doc must show the Windows entry-point path Scripts\deep-audit.exe"


def test_doc_has_posix_path_convention() -> None:
    text = INSTALL_DOC.read_text(encoding="utf-8")
    assert "bin/deep-audit" in text, "doc must show the POSIX entry-point path bin/deep-audit"

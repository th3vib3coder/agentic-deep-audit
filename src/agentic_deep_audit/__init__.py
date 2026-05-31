"""Agentic Deep Audit — evidence-first repository audit engine.

Frozen public API surface (see docs/adapters/python-api.md and tests/test_python_api_contract.py).
Adding a name requires a recorded amendment.
"""

from .audit_validate import validate_audit
from .bootstrap import bootstrap_audit

__all__ = ["bootstrap_audit", "validate_audit"]

from __future__ import annotations

import os
from datetime import datetime, timezone


SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH"


def current_utc() -> datetime:
    epoch = os.environ.get(SOURCE_DATE_EPOCH)
    if epoch is not None:
        try:
            return datetime.fromtimestamp(int(epoch), timezone.utc)
        except (OSError, OverflowError, ValueError):
            pass
    return datetime.now(timezone.utc)


def current_utc_iso() -> str:
    return current_utc().isoformat()


def current_run_id() -> str:
    return f"run-{current_utc().strftime('%Y%m%dT%H%M%SZ')}"

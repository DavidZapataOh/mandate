"""Test-only calendars, block sources and recorded OpenTimestamps answers."""

import base64
import json
from pathlib import Path
from typing import Any

OTS_FILE = (
    Path(__file__).resolve().parent.parent
    / "console/src/explorer/__fixtures__/ots.json"
)
OTS: dict[str, Any] = json.loads(OTS_FILE.read_text()) if OTS_FILE.exists() else {}


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)

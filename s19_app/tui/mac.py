from __future__ import annotations

import re
from pathlib import Path


_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f]+$")


def parse_mac_file(path: Path) -> dict:
    """Parse a .mac file into records and diagnostics.

    Supported record format:
      TAG_NAME=70001a88
    """
    records: list[dict] = []
    diagnostics: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        return {
            "path": str(path),
            "records": [],
            "diagnostics": [f"Failed to read file: {exc}"],
        }

    for index, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        record = {
            "line_number": index,
            "raw": raw_line.rstrip("\n"),
            "name": None,
            "address": None,
            "parse_ok": False,
            "parse_error": "",
        }

        if line.count("=") != 1:
            record["parse_error"] = "expected one '=' separator"
            diagnostics.append(f"Line {index}: {record['parse_error']}")
            records.append(record)
            continue

        name_text, addr_text = [part.strip() for part in line.split("=", maxsplit=1)]
        if not _NAME_RE.match(name_text):
            record["parse_error"] = "invalid tag name"
            diagnostics.append(f"Line {index}: {record['parse_error']}")
            record["name"] = name_text or None
            records.append(record)
            continue
        if not _HEX_RE.match(addr_text):
            record["parse_error"] = "invalid hex address"
            diagnostics.append(f"Line {index}: {record['parse_error']}")
            record["name"] = name_text
            records.append(record)
            continue

        address = int(addr_text, 16)
        record["name"] = name_text
        record["address"] = address
        record["parse_ok"] = True
        records.append(record)

    return {"path": str(path), "records": records, "diagnostics": diagnostics}

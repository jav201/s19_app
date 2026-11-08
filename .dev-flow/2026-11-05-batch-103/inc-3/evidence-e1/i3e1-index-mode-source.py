"""Inc 3 E1 source check (batch-103): the published description of the
FNC_VALUES index modes and the AXIS_PTS index order that D-2 and the
INDEX_DECR row rely on. The ASAM MCD-2 MC text is not available offline; this
fetches a public tool guide that reproduces the standard's figure (Intrepid
Control Systems, ASAP2 editor, "Create/Edit Record Layouts") and prints only
the lines about the modes. Imports no s19_app; standard library only.

Usage: python i3e1-index-mode-source.py
"""
from __future__ import annotations

import html
import re
import sys
import urllib.request

URL = "https://guide.intrepidcs.com/docs/asap2/main-toolbar/edit-tools/create-edit-record-layouts/"
KEYS = ("a11", "a21", "COLUMN_DIR", "ROW_DIR", "Map 'a'", "Y1", "Y2", "X1", "INDEX_INCR", "INDEX_DECR",
        "X-Axis points", "Y-Axis points", "axis point sequence")


def main() -> int:
    req = urllib.request.Request(URL, headers={"User-Agent": "Mozilla/5.0 (b103-e1 source check)"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    text = html.unescape(re.sub(r"<[^>]+>", "\n", raw))
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in text.splitlines()]
    lines = [ln for ln in lines if ln]
    print(f"url: {URL}")
    print(f"bytes: {len(raw)}; text lines: {len(lines)}")
    for i, ln in enumerate(lines):
        if any(k in ln for k in KEYS):
            print(f"{i:5d}: {ln[:200]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""The docs-canon guard (AT-285 — batch-91 carry): the README's key tables stay true.

Two arms:
1. every key the README's keybinding table names exists in the shipped seat
   (`S19TuiApp.BINDINGS`) — a documented key that leaves the keymap reddens here,
   so the docs cannot drift from the app again;
2. no unmarked `CDFX` token and no `s19tool` presented as a runnable command in
   README.md or docs/ — `s19tool` is the DISTRIBUTION name (paths, "Distribution
   name", and the honest module-only negations are its live truth), so the arm
   excuses those shapes and historic-marked lines, and forbids the rest.

RED on base: any of these was true of the pre-batch-91 docs.
"""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _readme_keys() -> set[str]:
    """Every key token the README's keybinding table names (single-key cells)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    keys: set[str] = set()
    in_table = False
    for line in text.splitlines():
        if "|" in line and ("key" in line.lower() or in_table):
            in_table = True
            for cell in line.split("|"):
                cell = cell.strip().strip("*`")
                if re.fullmatch(r"(?:Ctrl\+|Shift\+)?[`~!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|A-Za-z0-9]", cell):
                    keys.add(cell)
        elif in_table and not line.strip().startswith("|"):
            in_table = False
    return keys


def _shipped_keys() -> set[str]:
    from s19_app.tui.app import S19TuiApp
    out: set[str] = set()
    for b in S19TuiApp.BINDINGS:
        if hasattr(b, "key"):
            key, display = b.key, b.key_display
        else:
            key = b[0]
            display = b[3] if len(b) > 3 else None
        for k in str(key).split(","):
            out.add(_norm(k.strip()))
        if display:
            out.add(_norm(str(display)))
    return out


_GLYPH = {"/": "slash", "?": "question_mark", ",": "comma", ".": "period",
          "+": "plus", "-": "minus"}


def _norm(key: str) -> str:
    key = key.strip().lower()
    return _GLYPH.get(key, key)


def test_at285_every_readme_named_key_exists_in_the_seat():
    missing = {k for k in _readme_keys() if _norm(k) not in _shipped_keys()}
    assert not missing, f"README names keys the seat does not bind: {sorted(missing)}"


_HISTORIC = re.compile(r"removed|deleted|historic|superseded|legacy|no longer|moot", re.I)
_S19TOOL_OK = re.compile(
    r"\.s19tool/|s19tool/|Distribution name|module-only|runs only as a module|"
    r"No `s19tool` console script|what remains", re.I)


def test_at285_no_live_cdfx_or_s19tool_console_script_token():
    bad: list[str] = []
    for rel in ("README.md", "docs/overview.md", "docs/architecture.md"):
        for i, line in enumerate((ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if _HISTORIC.search(line) or _S19TOOL_OK.search(line):
                continue
            if re.search(r"\bCDFX\b", line):
                bad.append(f"{rel}:{i}: unmarked CDFX: {line.strip()[:90]}")
            elif re.search(r"\bs19tool\b", line):
                bad.append(f"{rel}:{i}: s19tool as a live command: {line.strip()[:90]}")
    assert not bad, "live CDFX / s19tool-console-script tokens:\n" + "\n".join(bad)

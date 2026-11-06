"""The docs-canon guard (AT-285 — batch-91 carry): the README's key tables stay true.

Two arms:
1. every key the README's keybinding table names exists in the shipped seat
   (`S19TuiApp._merged_bindings` plus the palette key while the palette is on) —
   a documented key that leaves the keymap reddens here,
   so the docs cannot drift from the app again;
2. no unmarked `CDFX` token and no `s19tool` presented as a runnable command in
   README.md or docs/ — `s19tool` is the DISTRIBUTION name (paths, "Distribution
   name", and the honest module-only negations are its live truth), so the arm
   excuses those shapes and historic-marked lines, and forbids the rest.

RED on base: any of these was true of the pre-batch-91 docs.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _readme_keys(text: str | None = None) -> set[str]:
    """Every key token the README's keybinding table names (single-key cells).

    ``text`` replaces the README (the negative controls feed a synthetic one).
    """
    if text is None:
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
    """Every key the app binds: the merged bindings (the class's own and the
    ones it inherits from Textual's ``App``, e.g. ``ctrl+q``), plus the command
    palette key while the palette is enabled (batch-101 Inc 14, E3 A-5)."""
    from s19_app.tui.app import S19TuiApp
    out: set[str] = set()
    for key, bindings in S19TuiApp._merged_bindings.key_to_bindings.items():
        for k in str(key).split(","):
            out.add(_norm(k.strip()))
        for binding in bindings:
            if binding.key_display:
                out.add(_norm(str(binding.key_display)))
    if S19TuiApp.ENABLE_COMMAND_PALETTE:
        out.add(_norm(S19TuiApp.COMMAND_PALETTE_BINDING))
    return out


_GLYPH = {"/": "slash", "?": "question_mark", ",": "comma", ".": "period",
          "+": "plus", "-": "minus", "=": "equals_sign",
          "]": "right_square_bracket"}


def _norm(key: str) -> str:
    key = key.strip().lower()
    return _GLYPH.get(key, key)


def _unbound(keys: set[str]) -> set[str]:
    shipped = _shipped_keys()
    return {k for k in keys if _norm(k) not in shipped}


def test_at285_every_readme_named_key_exists_in_the_seat(monkeypatch):
    missing = _unbound(_readme_keys())
    assert not missing, f"README names keys the seat does not bind: {sorted(missing)}"
    # Negative controls (batch-101 Inc 14, E3 A-5; R-DOC-README.3/2).
    # (1) a table row for a key nothing binds is reported;
    synthetic = "| Key | Action |\n|---|---|\n| `h` | nothing |\n| `Ctrl+Q` | quit |\n"
    assert _unbound(_readme_keys(synthetic)) == {"h"}
    # (2) the README lists Ctrl+P (D-11) and the keys Textual's App binds;
    #     with the command palette disabled the same README is then RED.
    keys = _readme_keys()
    assert {"Ctrl+P", "=", "]"} <= keys, (
        "the README key tables must list Ctrl+P, = and ] as single-key cells"
    )
    from s19_app.tui.app import S19TuiApp

    monkeypatch.setattr(S19TuiApp, "ENABLE_COMMAND_PALETTE", False)
    assert _unbound(keys) == {"Ctrl+P"}


# Removal marks: the words of AT-285 plus "retired" and "moved" (CTX-DOCHYG).
_HISTORIC = re.compile(
    r"removed|deleted|historic|superseded|legacy|no longer|moot|retired|moved", re.I
)
# The shapes in which the distribution name stays legitimate (CTX-DOCHYG
# "s19tool shape"): the work-area folder, a path, the egg-info folder,
# `pip <verb> <name>`, and the honest module-only negations.
_S19TOOL_OK = re.compile(
    r"\.s19tool[/\\]|s19tool/|s19tool\.egg-info|pip\s+\w[\w-]*\s+s19tool|"
    r"Distribution name|module-only|runs only as a module|"
    r"No `s19tool` console script|what remains", re.I)

_DOC_PREFIXES_OUT = (".dev-flow/", "docs/requirements/", "tests/goldens/", "tests/__snapshots__/")


def _repository_documents() -> list[str]:
    """Tracked .md/.txt/.rst files (CTX-DOCHYG "repository document"), by git."""
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode("utf-8")
    return [
        p
        for p in out.split("\0")
        if p.endswith((".md", ".txt", ".rst"))
        and not p.startswith(_DOC_PREFIXES_OUT)
        and p != "REQUIREMENTS.md"
    ]


def _live_token_findings(line: str) -> list[str]:
    """Findings for one line: an unmarked CDFX / CDF 2.0 token, or `s19tool`
    outside an allowed shape (matched case-sensitively, as AT-285 does)."""
    if _HISTORIC.search(line):
        return []
    if re.search(r"\bCDFX\b|CDF 2\.0", line, re.I):
        # only a removal mark excuses CDFX (R-DOC-REF.6); the s19tool shapes do not
        return ["unmarked CDFX"]
    if re.search(r"\bs19tool\b", line) and not _S19TOOL_OK.search(line):
        return ["s19tool as a live command"]
    return []


def test_at285_no_live_cdfx_or_s19tool_console_script_token():
    """AT-285 arm 2, widened to every repository document (R-DOC-REF.5,
    R-DOC-REF.6): no unmarked CDFX / CDF 2.0 token and no `s19tool` outside an
    allowed shape in any tracked .md/.txt/.rst document.

    Instrument check first: the allowed shapes pass and a command is caught.
    """
    tool = "s19" + "tool"
    controls = [
        (f"pip show {tool}", 0),
        (f"the common `.{tool}\\templates\\` library", 0),
        (f"`.{tool}/workarea/temp/`", 0),
        (f"Distribution name `{tool}`", 0),
        (f"{tool} firmware.s19 info", 1),
        ("the " + "CD" + "FX exporter", 1),
        ("the " + "CD" + "FX exporter was removed", 0),
        ("ASAM " + "CDF 2" + ".0 for vCDM", 1),
        ("Distribution name " + f"`{tool}`; ASAM " + "CD" + "FX exchange", 1),
    ]
    wrong = [(l, n, len(_live_token_findings(l))) for l, n in controls if len(_live_token_findings(l)) != n]
    assert not wrong, f"negative-control lines misjudged (line, expected, got): {wrong}"

    documents = _repository_documents()
    assert documents, "git ls-files returned no repository document"
    bad: list[str] = []
    for rel in documents:
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for finding in _live_token_findings(line):
                bad.append(f"{rel}:{i}: {finding}: {line.strip()[:90]}")
    assert not bad, "live CDFX / s19tool-console-script tokens:\n" + "\n".join(bad)

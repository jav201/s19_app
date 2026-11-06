"""Documentation-hygiene guards (batch-101 Inc 16).

One test per row family of ``.dev-flow/2026-11-01-batch-101/inc-16/02-test-cases.md``;
every test name carries its row id (``test_r_doc_ref_1_1_...``) and every
docstring names the requirement ids it verifies.

Method: text and ``git ls-files`` only. Nothing here imports ``s19_app``;
code facts (console scripts, sub-command names, rail labels, workflow
branches) are read from the source files as text, so a document is compared
with what the shipped files say, never with a copy of it kept in this file.

Notes for the reader of a failure:
- "tracked" means ``git ls-files``: a new file counts once it is staged or
  committed, a removed one stops counting when ``git rm`` stages it.
- Every synthetic input and exempt key that names a retired folder, the
  retired workflow, ``s19tool`` or a local identity is assembled from parts
  at runtime (the "guard probe" rule), so this file passes its own scans and
  no file is exempt as a whole.
"""
from __future__ import annotations

import ast
import fnmatch
import functools
import json
import os
import posixpath
import re
import socket
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
THIS_FILE_REL = "tests/test_b101_doc_hygiene.py"

# --- guard probes: built from parts so this file never holds them whole ------
_PROTO = "proto" + "types"
_FDF = "fast" + "-dev-" + "flow"
_FDF_DIR = "." + _FDF
_S19T = "s19" + "tool"
_CLOUD_DRIVE = "G" + ":/My Dri" + "ve/"  # a drive-letter cloud-folder path


# =============================================================================
# repository enumeration
# =============================================================================
@functools.lru_cache(maxsize=1)
def _tracked() -> tuple[str, ...]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    return tuple(p for p in out.decode("utf-8").split("\0") if p)


@functools.lru_cache(maxsize=1)
def _tracked_set() -> frozenset[str]:
    return frozenset(_tracked())


@functools.lru_cache(maxsize=1)
def _tracked_folders() -> frozenset[str]:
    folders: set[str] = set()
    for path in _tracked():
        parent = posixpath.dirname(path)
        while parent:
            folders.add(parent)
            parent = posixpath.dirname(parent)
    return frozenset(folders)


def _ls(*pathspec: str) -> list[str]:
    """`git ls-files -- <pathspec>` (the index, not the working tree)."""
    out = subprocess.run(
        ["git", "ls-files", "-z", "--", *pathspec],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def _read(rel: str) -> str | None:
    """UTF-8 text of a working-tree file; None if absent or binary."""
    try:
        data = (ROOT / rel).read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _need(rel: str) -> str:
    text = _read(rel)
    assert text is not None, f"{rel} is missing from the working tree"
    return text


_DOC_EXTENSIONS = (".md", ".txt", ".rst")
_NOT_DOC_PREFIXES = (".dev-flow/", "docs/requirements/", "tests/goldens/", "tests/__snapshots__/")


def _repository_documents() -> list[str]:
    """CTX-DOCHYG "repository document"."""
    return [
        p
        for p in _tracked()
        if p.endswith(_DOC_EXTENSIONS)
        and not p.startswith(_NOT_DOC_PREFIXES)
        and p != "REQUIREMENTS.md"
    ]


def _is_text_file_path(rel: str) -> bool:
    return not rel.startswith((".dev-flow/", "docs/requirements/"))


# =============================================================================
# shared text helpers
# =============================================================================
_REMOVAL_MARK = re.compile(
    r"removed|deleted|historic|superseded|legacy|no longer|moot|retired|moved", re.I
)


def _section(text: str, number: int) -> str:
    """The body of the level-2 section "## <number>." up to the next "## "."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^## {number}\.", line):
            start = i
            break
    assert start is not None, f"no heading '## {number}.' found"
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j].startswith("## "):
            end = j
            break
    return "\n".join(lines[start:end])


def _cells(line: str) -> list[str]:
    s = line.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|") and not s.endswith("\\|"):
        s = s[:-1]
    return [c.strip() for c in re.split(r"(?<!\\)\|", s)]


def _tables(text: str) -> list[dict]:
    """Blocks of consecutive lines starting with '|': header, rows, raw text."""
    tables: list[dict] = []
    block: list[str] = []
    for line in text.splitlines() + [""]:
        if line.lstrip().startswith("|"):
            block.append(line)
            continue
        if block:
            rows = [_cells(b) for b in block]
            body = rows[2:] if len(rows) > 1 and re.fullmatch(r"[\s:|-]+", block[1]) else rows[1:]
            tables.append({"header": rows[0], "rows": body, "text": "\n".join(block)})
            block = []
    return tables


def _plain(cell: str) -> str:
    return re.sub(r"[*`]", "", cell).strip()


def _list_items(text: str) -> list[str]:
    """Markdown list items, each with its continuation lines."""
    items: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if re.match(r"^\s*[-*]\s+", line):
            if current:
                items.append("\n".join(current))
            current = [line]
        elif current and line.strip() and line.startswith((" ", "\t")):
            current.append(line)
        else:
            if current:
                items.append("\n".join(current))
                current = []
    if current:
        items.append("\n".join(current))
    return items


def _paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n\s*\n", text) if p.strip()]


def _links(text: str) -> list[str]:
    """Targets of Markdown ``](target)`` links."""
    rx = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)")
    return [m.group(1) for m in rx.finditer(text)]


def _resolve_link(rel_doc: str, target: str) -> str | None:
    """Repository-relative path of a relative link, or None for URL/anchor."""
    if target.startswith("#") or re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", target):
        return None
    target = unquote(re.split(r"[#?]", target, maxsplit=1)[0])
    if not target:
        return None
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(rel_doc), target))
    return joined


def _link_exists(resolved: str) -> bool:
    if resolved.startswith(".."):
        return False
    return resolved in _tracked_set() or resolved.rstrip("/") in _tracked_folders()


# =============================================================================
# R-DOC-REF.1 — repository paths
# =============================================================================
_PATH_PREFIXES = (
    "s19_app",
    "tests",
    "tools",
    "docs",
    "examples",
    _PROTO,
    re.escape(_FDF_DIR),
    r"\.github",
    "evidence",
)
_PATH_RX = re.compile(
    r"(?<![A-Za-z0-9./\-])(?:" + "|".join(p if "\\" in p else re.escape(p) for p in _PATH_PREFIXES)
    + r")/[^\s`'\")\],]*"
)


def _clean_path_token(tok: str) -> str:
    tok = tok.split("::", 1)[0]
    previous = None
    while previous != tok:
        previous = tok
        tok = tok.rstrip(".:;/")
        tok = re.sub(r":[0-9][0-9,\-\u2013]*$", "", tok)
    return tok


def _path_exists(path: str) -> bool:
    if "*" in path:
        if path.endswith("/**") and "*" not in path[:-3]:
            return path[:-3] in _tracked_folders() or any(
                t.startswith(path[:-3] + "/") for t in _tracked()
            )
        return any(fnmatch.fnmatchcase(t, path) for t in _tracked())
    return path in _tracked_set() or path in _tracked_folders()


def _unmarked_missing_paths(rel: str, text: str) -> list[str]:
    found: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if _REMOVAL_MARK.search(line):
            continue
        for match in _PATH_RX.finditer(line):
            path = _clean_path_token(match.group(0))
            if path and not _path_exists(path):
                found.append(f"{rel}:{number}: {path}")
    return found


def test_r_doc_ref_1_1_named_paths_exist():
    """Verifies R-DOC-REF.1 (case /1): every repository path a repository
    document names exists, unless its line carries a removal mark."""
    bad: list[str] = []
    documents = _repository_documents()
    assert documents, "git ls-files returned no repository document"
    for rel in documents:
        text = _read(rel)
        if text is not None:
            bad.extend(_unmarked_missing_paths(rel, text))
    assert not bad, f"{len(bad)} unmarked repository paths that do not exist:\n" + "\n".join(bad)


def test_r_doc_ref_1_2_path_scan_reports_a_missing_path():
    """Verifies R-DOC-REF.1 (case /2, instrument check): the path scan reports
    a missing path and passes a marked one, a matching glob and a ``::<name>``
    node."""
    cases = [
        ("see tests/does_not_exist.py", 1),
        ("see s19_app/tui/hexview.py (removed)", 0),
        ("tests/test_flow_*", 0),
        ("see tests/test_docs_canon.py::test_x", 0),
    ]
    got = [(line, len(_unmarked_missing_paths("synthetic.md", line))) for line, _ in cases]
    assert got == cases, f"path scan instrument: {got}"


# =============================================================================
# R-DOC-REF.2 — links
# =============================================================================
def test_r_doc_ref_2_1_relative_links_resolve():
    """Verifies R-DOC-REF.2 (case /1): every relative Markdown link of a
    repository document resolves to a tracked file or folder."""
    broken: list[str] = []
    checked = 0
    for rel in _repository_documents():
        if not rel.endswith(".md"):
            continue
        text = _read(rel)
        if text is None:
            continue
        for target in _links(text):
            resolved = _resolve_link(rel, target)
            if resolved is None:
                continue
            checked += 1
            if not _link_exists(resolved):
                broken.append(f"{rel}: ]({target}) -> {resolved}")
    assert checked > 100, f"only {checked} relative links were checked; the scan lost its inputs"
    assert not broken, f"{len(broken)} broken links:\n" + "\n".join(broken)


def test_r_doc_ref_2_2_no_link_to_the_diagrams_file():
    """Verifies R-DOC-REF.2 (case /2) and R-DOC-README.4 (case /4): nothing
    links the removed diagrams file, the README, the docs index and the
    overview each link the architecture map, and the README documentation
    table holds exactly one row linking it."""
    names = ["README.md", "docs/README.md", "docs/overview.md", "docs/architecture.md"]
    dead_suffix = "diagrams/architecture.md"
    dead: list[str] = []
    linking: dict[str, set[str]] = {}
    for rel in names:
        text = _need(rel)
        resolved = {r for r in (_resolve_link(rel, t) for t in _links(text)) if r}
        linking[rel] = resolved
        for target in _links(text):
            if target.split("#", 1)[0].endswith(dead_suffix):
                dead.append(f"{rel}: ]({target})")
    assert not dead, "links to the removed diagrams file:\n" + "\n".join(dead)
    for rel in ("README.md", "docs/README.md", "docs/overview.md"):
        assert "docs/architecture.md" in linking[rel], f"{rel} does not link docs/architecture.md"

    readme = _need("README.md")
    heading = re.search(r"(?m)^## Documentation\s*$", readme)
    assert heading, "README.md has no '## Documentation' section"
    rest = readme[heading.end():]
    nxt = re.search(r"(?m)^## ", rest)
    body = rest[: nxt.start()] if nxt else rest
    architecture_rows = 0
    for line in body.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        row_targets = {r for r in (_resolve_link("README.md", t) for t in _links(line)) if r}
        assert not any(t.endswith(dead_suffix) for t in row_targets), f"diagrams row stays: {line}"
        if "docs/architecture.md" in row_targets:
            architecture_rows += 1
    assert architecture_rows == 1, (
        f"README documentation table: {architecture_rows} rows link docs/architecture.md, expected 1"
    )


# =============================================================================
# R-DOC-REF.3 / R-DOC-REF.4 — retired folder paths and the retired workflow
# =============================================================================
_RETIRED_FDF_PATH_RX = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(_FDF_DIR) + "/")
_RETIRED_PROTO_PATH_RX = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(_PROTO) + "/")
_RETIRED_PATH_RX = re.compile(_RETIRED_FDF_PATH_RX.pattern + "|" + _RETIRED_PROTO_PATH_RX.pattern)
_RETIRED_WORKFLOW_RX = re.compile(re.escape(_FDF), re.I)

# (id, file, key text, line number or None, families that skip it)
_EXEMPT = (
    ("X-1", ".gitignore", "/" + _PROTO + "/", None, (3,)),
    ("X-2", "AT-TC-REGISTRY.jsonl", '"not_scanned": [', 1, (3, 4)),
    ("X-3a", "tools/seed_id_registry.py", '"not_scanned": [', None, (3, 4)),
    ("X-3b", "tools/seed_id_registry.py", 'for folder in (".dev-flow", "' + _FDF_DIR + '"):', None, (4,)),
    ("X-4", "tools/id_registry.py", 'for folder in (".dev-flow", "' + _FDF_DIR + '"):', None, (4,)),
    ("X-5", ".gitattributes", "# " + _FDF + ".md is LF)", None, (4,)),
)


def _is_exempt(rel: str, number: int, line: str, family: int) -> bool:
    for _id, f, key, only_line, families in _EXEMPT:
        if family in families and rel == f and key in line and only_line in (None, number):
            return True
    return False


def _retired_hits(
    files: dict[str, str], family: int, exempt: bool = True, path_rx: re.Pattern = _RETIRED_PATH_RX
) -> list[str]:
    """family 3 = retired-folder paths (path_rx picks the folder); family 4 = the
    retired workflow's name."""
    hits: list[str] = []
    for rel, text in files.items():
        for number, line in enumerate(text.splitlines(), 1):
            if family == 3:
                if not path_rx.search(line):
                    continue
            else:
                if not _RETIRED_WORKFLOW_RX.search(line) or _REMOVAL_MARK.search(line):
                    continue
            if exempt and _is_exempt(rel, number, line, family):
                continue
            hits.append(f"{rel}:{number}: {line.strip()[:100]}")
    return hits


@functools.lru_cache(maxsize=1)
def _retired_candidates() -> dict[str, str]:
    """Tracked text files that mention either needle (prefiltered on bytes)."""
    needle = re.compile(
        re.escape(_FDF.encode()) + b"|" + re.escape(_PROTO.encode()) + b"/", re.I
    )
    found: dict[str, str] = {}
    for rel in _tracked():
        if not _is_text_file_path(rel):
            continue
        try:
            data = (ROOT / rel).read_bytes()
        except OSError:
            continue
        if b"\0" in data or not needle.search(data):
            continue
        try:
            found[rel] = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
    return found


def test_r_doc_ref_3_1_no_fast_dev_flow_path():
    """Verifies R-DOC-REF.3 (case /1): no tracked text file names a path in the
    retired workflow's folder outside the exempt lines."""
    hits = _retired_hits(_retired_candidates(), 3, path_rx=_RETIRED_FDF_PATH_RX)
    assert not hits, f"{len(hits)} paths in the retired workflow folder:\n" + "\n".join(hits)


def test_r_doc_ref_3_2_no_prototypes_path():
    """Verifies R-DOC-REF.3 (case /2): no tracked text file names a path in the
    removed design-probe folder outside the exempt lines (the plain words are
    not paths and pass)."""
    hits = _retired_hits(_retired_candidates(), 3, path_rx=_RETIRED_PROTO_PATH_RX)
    assert not hits, f"{len(hits)} paths in the removed design-probe folder:\n" + "\n".join(hits)


def test_r_doc_ref_3_3_exemptions_are_by_file_and_text():
    """Verifies R-DOC-REF.3 (case /3): the 3 exempt lines are skipped (and are
    caught when not exempted), a synthetic comment is reported, the exempt text
    in another file is reported, and this guard file reports nothing."""
    exempt_ids = [e for e in _EXEMPT if 3 in e[4]]
    assert len(exempt_ids) == 3
    for _id, rel, key, only_line, _fam in exempt_ids:
        text = _need(rel)
        lines = text.splitlines()
        if only_line is not None:
            real = lines[only_line - 1]
            assert key in real, f"{_id}: {rel} line {only_line} no longer holds the exempt text"
        else:
            matching = [l for l in lines if key in l]
            assert matching, f"{_id}: {rel} no longer holds the exempt text"
            real = matching[0]
        assert _retired_hits({rel: real}, 3, exempt=False), f"{_id}: line would not be caught"
        assert not _retired_hits({rel: real}, 3), f"{_id}: exempt line not skipped"
    synthetic = {"tests/x.py": "# see " + _PROTO + "/x.svg"}
    assert len(_retired_hits(synthetic, 3)) == 1, "synthetic comment not reported"
    moved = {"README.md": "/" + _PROTO + "/"}
    assert len(_retired_hits(moved, 3)) == 1, "the X-1 text in another file is not reported"
    same_text_other_line = {"AT-TC-REGISTRY.jsonl": "x\n" + '"not_scanned": [' + ' "' + _FDF_DIR + '/"'}
    assert len(_retired_hits(same_text_other_line, 3)) == 1, "line-1 exemption leaks to line 2"
    own = _need(THIS_FILE_REL)
    assert _retired_hits({THIS_FILE_REL: own}, 3) == [], "the guard file holds a retired-folder path"


def test_r_doc_ref_4_1_retired_workflow_named_only_as_retired():
    """Verifies R-DOC-REF.4 (case /1): the retired workflow's name appears in a
    tracked text file only on a line with a removal mark, outside the exempt
    lines."""
    hits = _retired_hits(_retired_candidates(), 4)
    assert not hits, f"{len(hits)} unmarked mentions of the retired workflow:\n" + "\n".join(hits)


def test_r_doc_ref_4_2_exempt_lines_skipped():
    """Verifies R-DOC-REF.4 (case /2): the 5 exempt lines are skipped (and are
    caught when not exempted), a synthetic line is reported, and this guard
    file reports nothing."""
    exempt_entries = [e for e in _EXEMPT if 4 in e[4]]
    assert len(exempt_entries) == 5
    for _id, rel, key, only_line, _fam in exempt_entries:
        text = _need(rel)
        lines = text.splitlines()
        if only_line is not None:
            real = lines[only_line - 1]
            assert key in real, f"{_id}: {rel} line {only_line} no longer holds the exempt text"
        else:
            matching = [l for l in lines if key in l]
            assert matching, f"{_id}: {rel} no longer holds the exempt text"
            real = matching[0]
        assert _retired_hits({rel: real}, 4, exempt=False), f"{_id}: line would not be caught"
        assert not _retired_hits({rel: real}, 4), f"{_id}: exempt line not skipped"
    assert len(_retired_hits({"README.md": "run /" + _FDF}, 4)) == 1
    assert _retired_hits({"README.md": "run /" + _FDF + " (removed)"}, 4) == []
    own = _need(THIS_FILE_REL)
    assert _retired_hits({THIS_FILE_REL: own}, 4) == [], "the guard file names the retired workflow"


# =============================================================================
# R-DOC-DEV.1 … DEV.7 — CLAUDE.md, PROJECT_RULES.md, engineering rules
# =============================================================================
def _pyproject() -> dict:
    return tomllib.loads(_need("pyproject.toml"))


def test_r_doc_dev_1_1_claude_lists_declared_console_scripts():
    """Verifies R-DOC-DEV.1 (case /1): CLAUDE.md "Project layout" lists exactly
    the console scripts pyproject.toml declares and presents none other as an
    entry point."""
    text = _need("CLAUDE.md")
    layout = re.search(r"(?ms)^## Project layout\s*$(.*?)(?=^## )", text)
    assert layout, "CLAUDE.md has no '## Project layout' section"
    arrow = re.compile(r"^\s*[-*]\s+`([^`]+)`\s*\u2192\s*`([\w.]+:\w+)`", re.M)
    listed = {m.group(1) for m in arrow.finditer(layout.group(1))}
    declared = set(_pyproject()["project"]["scripts"])
    assert listed == declared, f"CLAUDE.md lists {sorted(listed)}, pyproject declares {sorted(declared)}"
    assert _S19T not in listed


def test_r_doc_dev_2_1_cli_examples_run_the_module():
    """Verifies R-DOC-DEV.2 (case /1): each CLI example line of CLAUDE.md's
    common-commands block runs the module and a sub-command cli.py defines."""
    text = _need("CLAUDE.md")
    marker = re.search(r"(?m)^# CLI examples\b[^\n]*$", text)
    assert marker, "CLAUDE.md has no '# CLI examples' comment"
    lines = []
    for line in text[marker.end():].splitlines()[1:]:
        if line.strip().startswith("```"):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            lines.append(line.strip())
    assert len(lines) >= 4, f"expected the 4 CLI examples, found {lines}"
    defined = set(re.findall(r'add_parser\("([^"]+)"', _need("s19_app/cli.py")))
    assert {"info", "verify", "dump", "patch-hex"} <= defined
    bad = []
    for line in lines:
        tokens = line.split()
        if not line.startswith("python -m s19_app.cli ") or len(tokens) < 5 or tokens[4] not in defined:
            bad.append(line)
    assert not bad, "CLI example lines that do not run the module and a defined sub-command:\n" + "\n".join(bad)


def test_r_doc_dev_3_1_ci_sentence_matches_the_workflow():
    """Verifies R-DOC-DEV.3 (case /1): the CLAUDE.md sentence about the CI
    workflow names the branches and the two lane markers the workflow has."""
    claude = _need("CLAUDE.md")
    workflow = _need(".github/workflows/tui-ci.yml")
    paragraphs = [p for p in _paragraphs(claude) if ".github/workflows/tui-ci.yml" in p]
    assert len(paragraphs) == 1, f"{len(paragraphs)} paragraphs name the workflow, expected 1"
    sentence = paragraphs[0]
    on_block = re.search(r"(?ms)^on:\s*$(.*?)(?=^\S)", workflow)
    assert on_block, "workflow has no top-level on: block"
    branches = set(re.findall(r"(?m)^\s+-\s+([\w./-]+)\s*$", on_block.group(1)))
    assert {"main", "main-tui"} <= branches, f"workflow branches: {branches}"
    named_main = re.search(r"(?<![\w-])main(?![\w-])", sentence)
    named_tui = re.search(r"(?<![\w-])main-tui(?![\w-])", sentence)
    assert named_main and named_tui, "CI sentence must name both `main` and `main-tui`"
    assert "pushes/PRs to `main-tui`" not in sentence
    for marker in ('-m "not serial_timing"', "-m serial_timing"):
        assert marker in sentence, f"CI sentence does not name the lane marker {marker}"
        assert marker in workflow, f"workflow has no lane marker {marker}"


def test_r_doc_dev_4_1_no_tui_hexview_path():
    """Verifies R-DOC-DEV.4 (case /1): no developer document names the removed
    tui/hexview.py."""
    bad = [
        rel
        for rel in ("CLAUDE.md", "PROJECT_RULES.md", "docs/engineering-rules.md")
        if "tui/hexview.py" in _need(rel)
    ]
    assert not bad, f"still name tui/hexview.py: {bad}"


def test_r_doc_dev_4_2_hex_renderer_named_at_render():
    """Verifies R-DOC-DEV.4 (case /2): each of the three developer documents
    names render/hexview.py, and CLAUDE.md's bullet on the hex renderer does."""
    missing = [
        rel
        for rel in ("CLAUDE.md", "PROJECT_RULES.md", "docs/engineering-rules.md")
        if "render/hexview.py" not in _need(rel)
    ]
    assert not missing, f"do not name render/hexview.py: {missing}"
    bullets = [
        item
        for item in _list_items(_need("CLAUDE.md"))
        if "hexview" in item and re.search(r"render_hex_view_text|find_string_in_mem|MAX_HEX_BYTES", item)
    ]
    assert bullets, "CLAUDE.md has no bullet on the hex renderer"
    assert all("render/hexview.py" in b for b in bullets), (
        "CLAUDE.md's hex-renderer bullet does not name render/hexview.py:\n" + "\n".join(bullets)
    )


_MODULE_SIZE_RX = re.compile(r"\d[\d,]*(\.\d+)?k?[- ](lines?|LOC)\b", re.I)


def test_r_doc_dev_5_1_claude_states_no_module_size():
    """Verifies R-DOC-DEV.5 (case /1): CLAUDE.md states no module size in
    lines; the pattern catches a comma-grouped count (instrument check)."""
    probe = _MODULE_SIZE_RX.search("a 21,138 lines module")
    assert probe and probe.group(0) == "21,138 lines", "instrument: pattern misses '21,138 lines'"
    hits = [
        f"CLAUDE.md:{n}: {line.strip()[:100]}"
        for n, line in enumerate(_need("CLAUDE.md").splitlines(), 1)
        if _MODULE_SIZE_RX.search(line)
    ]
    assert not hits, "module sizes in CLAUDE.md:\n" + "\n".join(hits)


def test_r_doc_dev_6_1_claude_cites_no_line_numbers():
    """Verifies R-DOC-DEV.6 (case /1): CLAUDE.md cites code without line
    numbers, and its project.toml paragraph names the two readers."""
    text = _need("CLAUDE.md")
    hits = [
        f"CLAUDE.md:{n}: {m.group(0)}"
        for n, line in enumerate(text.splitlines(), 1)
        for m in re.finditer(r"[\w/]+\.py:\d+", line)
    ]
    assert not hits, "file:line citations in CLAUDE.md:\n" + "\n".join(hits)
    paragraphs = [p for p in _paragraphs(text) if "project.toml" in p]
    assert paragraphs, "CLAUDE.md has no project.toml paragraph"
    joined = "\n".join(paragraphs)
    assert "find_repo_root" in joined, "project.toml paragraph does not name find_repo_root"
    assert "tests/test_changes_schema.py" in joined, (
        "project.toml paragraph does not name tests/test_changes_schema.py"
    )


def test_r_doc_dev_7_1_rules_cite_no_memory_file():
    """Verifies R-DOC-DEV.7 (case /1): the engineering rules point to no
    personal memory file."""
    text = _need("docs/engineering-rules.md")
    assert "project_devflow_control_lineage" not in text, "a personal memory file is still cited"
    assert "Canonical history: memory" not in text, "a personal memory source is still cited"


# =============================================================================
# R-DOC-DEV.8 … DEV.15 — requirements.txt, docs index, overview, manifest
# =============================================================================
def test_r_doc_dev_8_1_requirements_txt_equals_runtime_dependencies():
    """Verifies R-DOC-DEV.8 (case /1): requirements.txt declares the runtime
    requirements pyproject.toml declares."""
    lines = set()
    for raw in _need("requirements.txt").splitlines():
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if line and not line.startswith("#"):
            lines.add(re.sub(r"\s+", "", line))
    declared = {re.sub(r"\s+", "", d) for d in _pyproject()["project"]["dependencies"]}
    assert len(declared) == 3, f"pyproject declares {declared}"
    assert lines == declared, f"requirements.txt {sorted(lines)} != pyproject {sorted(declared)}"


_ROOT_DOCUMENTS = ("README.md", "REQUIREMENTS.md", "CLAUDE.md", "PROJECT_RULES.md", "SECURITY.md", "CHANGELOG.md")


def _docindex_entries(tracked) -> list[str]:
    """CTX-DOCINDEX: top-level entries of docs/ (less README.md and images/)
    plus the root documents."""
    entries: set[str] = set()
    for path in tracked:
        if not path.startswith("docs/"):
            continue
        first = path.split("/")[1]
        if first in ("README.md", "images"):
            continue
        entries.add("docs/" + first)
    return sorted(entries) + list(_ROOT_DOCUMENTS)


def _docindex_missing(entries: list[str], link_targets: set[str]) -> list[str]:
    return [
        e
        for e in entries
        if not any(t == e or t.startswith(e + "/") for t in link_targets)
    ]


def _docs_index_targets() -> set[str]:
    resolved = (_resolve_link("docs/README.md", t) for t in _links(_need("docs/README.md")))
    return {r.rstrip("/") for r in resolved if r}


def test_r_doc_dev_9_1_docs_index_links_every_entry():
    """Verifies R-DOC-DEV.9 (case /1): docs/README.md links every entry of the
    documentation index, computed from the tree."""
    for root_doc in _ROOT_DOCUMENTS:
        assert root_doc in _tracked_set(), f"{root_doc} is not tracked"
    entries = _docindex_entries(_tracked())
    missing = _docindex_missing(entries, _docs_index_targets())
    assert not missing, f"docs/README.md does not link {len(missing)} of {len(entries)} entries: {missing}"


def test_r_doc_dev_9_2_index_rule_follows_the_tree():
    """Verifies R-DOC-DEV.9 (case /2, instrument check): an entry added to
    docs/ is reported missing by the index rule."""
    extra = "docs/new-note.md"
    tracked = list(_tracked()) + [extra]
    entries = _docindex_entries(tracked)
    assert extra in entries
    missing = _docindex_missing(entries, _docs_index_targets())
    assert extra in missing, "the rule does not follow the tree"
    baseline = _docindex_missing(_docindex_entries(_tracked()), _docs_index_targets())
    assert sorted(set(missing) - set(baseline)) == [extra]


def test_r_doc_dev_10_1_docs_index_states_no_project_state():
    """Verifies R-DOC-DEV.10 (case /1): docs/README.md states no branch,
    commit, test tally or per-batch table as the project's state."""
    text = _need("docs/README.md")
    assert not re.search(r"(?mi)^#{1,6}\s*Project state\b", text), "a 'Project state' heading remains"
    assert "latest merge" not in text
    assert not re.search(r"\d+ pass", text), "a test tally remains"
    rows = [
        l for l in text.splitlines() if l.lstrip().startswith("|") and re.search(r"`2026-\d\d-\d\d-batch-\d+`", l)
    ]
    assert not rows, "per-batch table rows remain:\n" + "\n".join(rows)


def _rail_labels() -> set[str]:
    rx = re.compile(r'RailEntry\(\s*"[^"]*",\s*"[^"]*",\s*"[^"]*",\s*"([^"]+)"')
    labels: set[str] = set()
    for rel in ("s19_app/tui/rail.py", "s19_app/tui/app.py"):
        labels.update(rx.findall(_need(rel)))
    return labels


def test_r_doc_dev_11_1_overview_names_every_window():
    """Verifies R-DOC-DEV.11 (case /1): docs/overview.md section 3 names every
    rail window by its label and the Split / Join / Export window."""
    labels = _rail_labels()
    assert len(labels) == 12, f"expected 12 distinct rail labels, read {sorted(labels)}"
    section = _section(_need("docs/overview.md"), 3)
    wanted = sorted(labels) + ["Split / Join / Export"]
    missing = [w for w in wanted if w not in section]
    assert not missing, f"overview section 3 does not name: {missing}"


_KEY_RANGE_RX = re.compile(r"(?i)\btwelve\b.*`1`\s*[\u2013-]\s*`0`.*`=`.*`\]`")
_COUNT_WORD_RX = re.compile(r"\b(nine|ten|eleven|thirteen|9|10|11|13)\b", re.I)


def _is_rail_count_line(line: str) -> bool:
    return bool(re.search("rail", line, re.I)) and bool(
        _COUNT_WORD_RX.search(re.sub(r"`[^`]*`", "", line))
    )


def test_r_doc_dev_12_1_rail_counted_as_twelve():
    """Verifies R-DOC-DEV.12 (case /1): the overview and the architecture map
    count twelve rail windows with the twelve-key range and state no other
    count on a rail line."""
    problems: list[str] = []
    for rel in ("docs/overview.md", "docs/architecture.md"):
        text = _need(rel)
        if not any(_KEY_RANGE_RX.search(l) for l in text.splitlines()):
            problems.append(
                f"{rel} holds no line stating twelve rail windows with keys `1`-`0`, `=` and `]`"
            )
        problems += [
            f"rail line with another count, {rel}:{n}: {l.strip()[:100]}"
            for n, l in enumerate(text.splitlines(), 1)
            if _is_rail_count_line(l)
        ]
    if not re.search(r"(?m)^#+\s*The twelve rail screens\s*$", _need("docs/architecture.md")):
        problems.append("docs/architecture.md lost the heading 'The twelve rail screens'")
    assert not problems, "\n".join(problems)


_LINE_28_AT_BASE = (
    "- **Activity rail (left).** Exactly twelve ordered items \u2014 keys `1`\u2013`0` plus two "
    "non-digit bindings, `=` (Check Editor) and `]` (Flow Execution), both `show=False` "
    "(batch-94's R-1 closure; probe evidence `evidence/pdr_rail_key_probe.txt` + "
    "`evidence/inc003_rail12_probe.txt`) \u2014 with exactly one active marker, glyph + "
    "per-item ASCII fallback. Rail items toggle twelve sibling screen containers via the "
    "`.hidden` CSS class (not a `push_screen` stack), so the rail and command bar stay "
    "persistently mounted."
)


def test_r_doc_dev_12_2_predicates_on_fixed_lines():
    """Verifies R-DOC-DEV.12 (case /2, instrument check): the count predicate
    and the key-range pattern give the stated answers on four fixed lines."""
    lines = [
        _LINE_28_AT_BASE,
        "a left activity rail + ten single-context screens",
        "the rail grew 10\u219212",
        "twelve rail screens (keys `1`\u2013`0`)",
    ]
    # a fifth line (beyond the four of the case) shows that the word "twelve"
    # is part of what the key-range pattern requires
    lines.append("**ten** rail screens, keys `1`–`0`, `=` and `]`")
    counts = [int(_is_rail_count_line(l)) for l in lines]
    keys = [bool(_KEY_RANGE_RX.search(l)) for l in lines]
    assert counts == [0, 1, 1, 0, 1], f"count predicate: {counts}"
    assert keys == [True, False, False, False, False], f"key-range pattern: {keys}"


def test_r_doc_dev_13_1_no_test_count():
    """Verifies R-DOC-DEV.13 (case /1): the overview and the architecture map
    state no count of tests; a snapshot-baseline count is not one."""
    rx = re.compile(r"\d[\d,]*\s+(collected\s+)?tests\b")
    assert not rx.search("29 SVG baselines"), "instrument: baseline count read as a test count"
    assert rx.search("2760 collected tests") and rx.search("**2760 tests**")
    hits = [
        f"{rel}:{n}: {m.group(0)}"
        for rel in ("docs/overview.md", "docs/architecture.md")
        for n, line in enumerate(_need(rel).splitlines(), 1)
        for m in rx.finditer(line)
    ]
    assert not hits, "test counts remain:\n" + "\n".join(hits)


def test_r_doc_dev_14_1_overview_names_placeholder_operations():
    """Verifies R-DOC-DEV.14 (case /1): the overview says the Operations modal
    lists extract and split_by_segment without running them."""
    text = _need("docs/overview.md")
    assert "executable from the in-app Operations modal" not in text, (
        "the overview still says the Operations modal executes the placeholder operations"
    )
    items = [
        i for i in _list_items(text) if "extract" in i and "split_by_segment" in i
    ]
    assert items, "no bullet names both extract and split_by_segment"
    assert any(re.search(r"not (yet )?implemented", i, re.I) for i in items), (
        "the Operations bullet does not say extract and split_by_segment are not implemented"
    )


def _example_case_folders() -> list[str]:
    folders: set[str] = set()
    for path in _ls("examples/"):
        parts = path.split("/")
        if len(parts) >= 3 and parts[1].startswith("case_") and parts[1] != "case_00_public":
            folders.add(parts[1])
        if len(parts) >= 4 and parts[1] == "professional_validation":
            folders.add("professional_validation/" + parts[2])
    return sorted(folders)


def _manifest_missing(text: str, folders: list[str]) -> list[str]:
    missing = []
    for folder in folders:
        if "/" in folder:
            named = folder in text
        else:
            named = re.search(r"(?<![\w/.\-])" + re.escape(folder) + r"(?![\w])", text) is not None
        if not named:
            missing.append(folder)
    return missing


def test_r_doc_dev_15_1_manifest_lists_every_case():
    """Verifies R-DOC-DEV.15 (case /1): the examples manifest lists each case
    folder of examples/ by its path relative to examples/; deleting one entry
    is reported."""
    folders = _example_case_folders()
    assert len(folders) == 15, f"expected 15 case folders, found {folders}"
    text = _need("examples/case_00_public/MANIFEST.md")
    missing = _manifest_missing(text, folders)
    assert not missing, f"MANIFEST.md does not name {len(missing)} of 15 case folders: {missing}"
    control = "professional_validation/case_03_overlapping_records"
    mutated = text.replace(control, "")
    assert _manifest_missing(mutated, folders) == [control], "control: the deleted entry is not reported"


# =============================================================================
# R-DOC-ARCH — the architecture map
# =============================================================================
def _architecture() -> str:
    return _need("docs/architecture.md")


def _module_table(section10: str) -> dict:
    found = [t for t in _tables(section10) if any("Paths it owns" in c for c in t["header"])]
    assert len(found) == 1, f"{len(found)} module tables in section 10, expected 1"
    return found[0]


def _module_prefixes(table: dict) -> list[str]:
    col = next(i for i, c in enumerate(table["header"]) if "Paths it owns" in c)
    prefixes = []
    for row in table["rows"]:
        prefixes += re.findall(r"([^\s`]+)/\*\*", row[col])
    return prefixes


def test_r_doc_arch_1_1_module_table_covers_python_folders():
    """Verifies R-DOC-ARCH.1 (case /1): the module table of the architecture
    map declares a module prefix for each Python folder."""
    folders = {p.split("/")[0] for p in _ls("*.py") if "/" in p}
    assert folders >= {".dev-flow", "docs", "s19_app", "tests", "tools"}, folders
    prefixes = set(_module_prefixes(_module_table(_section(_architecture(), 10))))
    missing = sorted(folders - prefixes)
    assert not missing, f"Python folders without a module prefix: {missing}"


def test_r_doc_arch_2_1_no_empty_module_prefix():
    """Verifies R-DOC-ARCH.2 (case /1): the module table declares no prefix
    that matches no tracked file, and no rationale row names the removed
    design-probe module."""
    section = _section(_architecture(), 10)
    empty = [
        p
        for p in _module_prefixes(_module_table(section))
        if not any(t.startswith(p + "/") for t in _tracked())
    ]
    assert not empty, f"module prefixes that match no tracked file: {empty}"
    named = [l.strip()[:100] for l in section.splitlines() if _PROTO + "/**" in l]
    assert not named, "rows naming the removed design-probe module:\n" + "\n".join(named)


def test_r_doc_arch_3_1_no_amendment_note():
    """Verifies R-DOC-ARCH.3 (case /1): no amendment note of batches 88-100
    stays in the architecture map."""
    bad = [
        f"{n}: {l[:100]}"
        for n, l in enumerate(_architecture().splitlines(), 1)
        if l.startswith("> **Amended at") or l.startswith("> **Post-gate amendment")
    ]
    assert not bad, "amendment notes remain:\n" + "\n".join(bad)


def test_r_doc_arch_3_2_no_batch_declaration_heading():
    """Verifies R-DOC-ARCH.3 (case /2): no per-batch declaration heading stays
    in the architecture map."""
    rx = re.compile(r"^#{2,4} Batch-(88|92|94|97|99|100)\b")
    bad = [f"{n}: {l[:100]}" for n, l in enumerate(_architecture().splitlines(), 1) if rx.match(l)]
    assert not bad, "per-batch headings remain:\n" + "\n".join(bad)


def test_r_doc_arch_3_3_no_batch_interface_amendment():
    """Verifies R-DOC-ARCH.3 (case /3): no per-batch interface amendment, no
    'none frozen yet' and no '(planned' stays in the architecture map."""
    text = _architecture()
    rx = re.compile(r"^\*\*Batch-(92|94|97|99|100) interface amendments\*\*", re.M)
    bad = [f"amendment paragraph: {m.group(0)}" for m in rx.finditer(text)]
    bad += [f"'none frozen yet' at char {m.start()}" for m in re.finditer(re.escape("none frozen yet"), text)]
    bad += [f"'(planned' at char {m.start()}" for m in re.finditer(re.escape("(planned"), text)]
    assert not bad, "per-batch declarations remain:\n" + "\n".join(bad)


def _submodule_tables(section10: str) -> list[dict]:
    return [t for t in _tables(section10) if t["header"] and _plain(t["header"][0]) == "Sub-module"]


def test_r_doc_arch_4_1_submodules_declared():
    """Verifies R-DOC-ARCH.4 (case /1): section 10 declares the three
    sub-modules with their facts in present tense."""
    section = _section(_architecture(), 10)
    tables = _submodule_tables(section)
    assert len(tables) == 1, f"{len(tables)} sub-module tables in section 10, expected 1"
    table = tables[0]
    assert [_plain(c) for c in table["header"]] == [
        "Sub-module",
        "Encapsulates",
        "Exposes",
        "Must not import",
    ]
    expected = ["s19_app/render/hexview.py", "s19_app/render/format.py", "s19_app/tui/flow_screens.py"]
    rows = {}
    for row in table["rows"]:
        assert len(row) == 4, f"malformed row: {row}"
        for path in expected:
            if path in row[0]:
                rows[path] = row
    assert sorted(rows) == sorted(expected), f"sub-module rows: {sorted(rows)}"
    assert len(table["rows"]) == 3
    for path, row in rows.items():
        assert _plain(row[1]) and _plain(row[2]), f"{path}: empty Encapsulates or Exposes cell"
    for path in expected[:2]:
        assert "s19_app.tui" in rows[path][3], f"{path}: Must-not-import cell does not name s19_app.tui"
    assert _plain(rows[expected[2]][3]).lower() == "not declared", (
        f"flow_screens.py Must-not-import cell reads {rows[expected[2]][3]!r}"
    )
    assert not re.search(r"\bNEW\b|landed|Inc-00", table["text"]), "history wording in the sub-module table"


def test_r_doc_arch_4_2_no_broken_import_rule_restated():
    """Verifies R-DOC-ARCH.4 (case /2): the map restates no import rule the
    code breaks, and each section the flow_screens module docstring cites
    resolves to a section holding the sub-module table."""
    text = _architecture()
    assert "never called directly" not in text, "the map restates the batch-94 'never called directly' rule"
    assert "flow_screens \u2192 services/flow_model" not in text, "the map restates the batch-94 data-edge rule"
    tree = ast.parse(_need("s19_app/tui/flow_screens.py"))
    doc = ast.get_docstring(tree) or ""
    cited = re.findall(r"docs/architecture\.md[`'\"\s]*(?:\u00a7|section\s)\s*(\d+)", doc)
    for number in cited:
        section = _section(text, int(number))
        assert _submodule_tables(section), (
            f"flow_screens.py cites docs/architecture.md section {number}; it holds no sub-module table"
        )


_NAMED_CONTRACTS = (
    "loaded_panel",
    "screen_workspace",
    "workspace_body",
    "render.hexview",
    "render.format",
    "utils.safe_text",
    "tui/__init__",
    "PatchEditorPanel.ActionRequested",
    ".chk.json",
    "flow_screens",
    "chain-set",
)


def _source_tags() -> list[str]:
    tags = [f"B97-I-{i}" for i in range(1, 12)]
    tags += [f"B99-I{i}" for i in range(1, 13)] + ["B99-I2a"]
    tags += [f"B100-I{i}" for i in range(1, 23)]
    return tags


def _tag_rx(tag: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9\-])" + re.escape(tag) + r"(?![A-Za-z0-9])")


def _interfaces_table() -> dict:
    section = _section(_architecture(), 11)
    tables = _tables(section)
    assert len(tables) == 1, f"section 11 holds {len(tables)} tables, expected exactly 1"
    table = tables[0]
    assert [_plain(c) for c in table["header"]] == [
        "Interface",
        "Owner module",
        "Consumers",
        "Shape",
        "Frozen?",
    ], f"Interfaces table header: {table['header']}"
    for row in table["rows"]:
        assert len(row) == 5, f"malformed Interfaces row: {row}"
    return table


def _row_for(table: dict, matcher) -> list[str]:
    rows = [r for r in table["rows"] if matcher(r[0])]
    assert rows, "no row matches"
    return rows[0]


def test_r_doc_arch_5_1_one_interfaces_table():
    """Verifies R-DOC-ARCH.5 (case /1): section 11 holds one Interfaces table
    whose first column holds the 12 named contracts and the 46 source tags."""
    assert len(_source_tags()) == 46
    table = _interfaces_table()
    first = [r[0] for r in table["rows"]]
    joined = "\n".join(first)
    missing = [n for n in _NAMED_CONTRACTS if n not in joined]
    if not re.search(r"(?i)rail[- ]invariant", joined):
        missing.append("rail invariant")
    missing += [t for t in _source_tags() if not _tag_rx(t).search(joined)]
    assert not missing, f"{len(missing)} contracts missing from the first column: {missing}"
    assert not re.search(r"\.py:\d+", table["text"]), "a .py:<line> citation stays in the table"
    assert not any(re.search(r"Current|After", c) for c in table["header"])


def test_r_doc_arch_5_2_rail_saved_files_and_frozen_cells():
    """Verifies R-DOC-ARCH.5 (case /2): the rail-invariant row says twelve, the
    five saved-file contracts say 'saved file', and each Frozen? cell reads
    'no' or names the open batch."""
    table = _interfaces_table()
    rail = _row_for(table, lambda c: re.search(r"(?i)rail[- ]invariant", c) is not None)
    rail_text = " ".join(rail)
    assert re.search(r"(?i)\btwelve\b", rail_text), f"rail-invariant row does not say twelve: {rail}"
    assert not re.search(r"(?i)\bten\b", rail_text), f"rail-invariant row still says ten: {rail}"
    saved = [
        ("`.chk.json`", lambda c: ".chk.json" in c),
        ("chain-set", lambda c: "chain-set" in c),
        ("B100-I1", lambda c: _tag_rx("B100-I1").search(c) is not None),
        ("B100-I9", lambda c: _tag_rx("B100-I9").search(c) is not None),
        ("B100-I16", lambda c: _tag_rx("B100-I16").search(c) is not None),
    ]
    bad = []
    for name, matcher in saved:
        row = _row_for(table, matcher)
        if "saved file" not in row[3].lower():
            bad.append(f"{name}: Shape cell {row[3]!r}")
    assert not bad, "saved-file contracts whose Shape cell lacks 'saved file':\n" + "\n".join(bad)
    batch_id = json.loads(_need(".dev-flow/state.json"))["batch_id"]
    odd = [
        f"{r[0][:50]}: {r[4]!r}"
        for r in table["rows"]
        if _plain(r[4]).lower() != "no" and batch_id not in r[4]
    ]
    assert not odd, f"Frozen? cells that are neither 'no' nor {batch_id}:\n" + "\n".join(odd)


def test_r_doc_arch_6_1_increment_cap_is_four_source_files():
    """Verifies R-DOC-ARCH.6 (case /1): section 9 states the increment cap as
    at most 4 source files and the old cap is gone."""
    text = _architecture()
    assert "\u2264 4 source files" in _section(text, 9), "section 9 does not state the 4-source-file cap"
    assert "\u2264 5 files" not in text, "the old 5-file cap is still stated"


# =============================================================================
# R-DOC-ARCHIVE — archive and removal
# =============================================================================
_ARCHIVE_DIR = ".dev-flow/design/archive/"
_MOVED_NOTES = (
    ("PENDIENTES-batch96.md", _ARCHIVE_DIR + "PENDIENTES-batch96.md"),
    (
        "docs/crc-algorithm-designer/01-requirements.md",
        _ARCHIVE_DIR + "crc-algorithm-designer-requirements-draft-2026-07-20.md",
    ),
    ("tools/synth/VERIFY.md", _ARCHIVE_DIR + "synth-case08-release-demo-VERIFY.md"),
)


def test_r_doc_archive_1_1_notes_only_in_the_archive():
    """Verifies R-DOC-ARCHIVE.1 (case /1): each finished note is tracked at its
    archive path only, and no archived draft is named 01-requirements.md."""
    tracked = _tracked_set()
    absent = [new for _old, new in _MOVED_NOTES if new not in tracked]
    present = [old for old, _new in _MOVED_NOTES if old in tracked]
    assert not absent, f"not tracked at the archive path: {absent}"
    assert not present, f"still tracked at the earlier path: {present}"
    clash = [p for p in tracked if p.startswith(_ARCHIVE_DIR) and posixpath.basename(p) == "01-requirements.md"]
    assert not clash, f"archived draft keeps the requirements file name: {clash}"


def test_r_doc_archive_3_1_no_fast_dev_flow_folder():
    """Verifies R-DOC-ARCHIVE.3 (case /1): the retired workflow's folder holds
    no tracked file."""
    left = _ls(_FDF_DIR)
    assert not left, f"{len(left)} tracked files remain in the retired workflow folder"


def test_r_doc_archive_3_2_no_diagrams_file():
    """Verifies R-DOC-ARCHIVE.3 (case /2): the superseded diagrams file is
    gone."""
    assert _ls("docs/diagrams") == []


def test_r_doc_archive_3_3_no_req_crc_in_package():
    """Verifies R-DOC-ARCHIVE.3 (case /3): the package tree holds no
    requirements document."""
    assert _ls("s19_app/tui/operations/requirements") == []


def test_r_doc_archive_3_4_no_unused_example_txt():
    """Verifies R-DOC-ARCHIVE.3 (case /4): the two unused example text files
    are gone."""
    assert _ls(
        "examples/case_00_public/from_source_input.txt", "examples/case_00_public/s19_sample.txt"
    ) == []


@functools.lru_cache(maxsize=1)
def _hygiene_namespace() -> dict:
    """`_REDACTION_PATTERNS` and `_PLACEHOLDER` of tests/test_suite_hygiene.py,
    evaluated from that file's source (no import, so no drift and no side
    effect)."""
    tree = ast.parse(_need("tests/test_suite_hygiene.py"))
    wanted = {"_REDACTION_PATTERNS", "_PLACEHOLDER"}
    found: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in wanted:
                expr = ast.Expression(node.value)
                ast.fix_missing_locations(expr)
                found[target.id] = eval(compile(expr, "<hygiene>", "eval"), {"re": re})
    assert set(found) == wanted, f"could not read {wanted - set(found)} from tests/test_suite_hygiene.py"
    return found


def _local_account_and_host_names() -> set[str]:
    names = set()
    for value in (
        os.environ.get("USERNAME"),
        os.environ.get("USER"),
        Path.home().name,
        socket.gethostname(),
        os.environ.get("COMPUTERNAME"),
        os.environ.get("HOSTNAME"),
    ):
        if value:
            short = value.split(".")[0]
            if len(short) >= 3 and short.lower() != "runner":
                names.add(short)
    return names


_CLOUD_DRIVE_RX = re.compile(r"[A-Za-z]:[\\/]+My Drive[\\/]", re.I)


def _local_identity_hits(text: str) -> list[str]:
    ns = _hygiene_namespace()
    placeholder = ns["_PLACEHOLDER"]
    hits: list[str] = []
    for label, pattern in ns["_REDACTION_PATTERNS"]:
        for match in pattern.finditer(text):
            name = match.group("name")
            if not all(placeholder.fullmatch(part) for part in re.split(r"[@.]", name)):
                hits.append(f"{label}: {match.group(0).strip()}")
    for match in _CLOUD_DRIVE_RX.finditer(text):
        hits.append(f"drive-letter cloud folder: {match.group(0)}")
    for name in sorted(_local_account_and_host_names()):
        for match in re.finditer(rf"(?<![A-Za-z0-9]){re.escape(name)}(?![A-Za-z0-9])", text, re.I):
            hits.append(f"local account or host name: {match.group(0)}")
    return hits


def test_r_doc_archive_4_1_archive_holds_no_local_identity():
    """Verifies R-DOC-ARCHIVE.4 (case /1): the files of the archive folder hold
    no local identity (home path, profile path, account or host name, LAN
    address, cloud-folder drive path)."""
    files = _ls(_ARCHIVE_DIR)
    required = [new for _old, new in _MOVED_NOTES] + [
        _ARCHIVE_DIR + "architecture-batch-declarations-88-100.md"
    ]
    absent = [p for p in required if p not in files]
    assert not absent, f"archive files not tracked, nothing to scan: {absent}"
    hits = []
    for rel in files:
        text = _read(rel)
        if text is None:
            continue
        hits += [f"{rel}: {h}" for h in _local_identity_hits(text)]
    assert not hits, "local identities in the archive folder:\n" + "\n".join(hits)


def test_r_doc_archive_4_2_scan_reports_a_local_path():
    """Verifies R-DOC-ARCHIVE.4 (case /2, instrument check): the scan reports a
    drive-letter cloud-folder path and a user-profile path, and passes a sample
    path."""
    cloud = "see " + _CLOUD_DRIVE + "project/notes.md"
    profile = "see C:\\Us" + "ers\\alice\\project"
    sample = "load C:\\work\\flash\\app_v2.s19"
    counts = [len(_local_identity_hits(x)) for x in (cloud, profile, sample)]
    assert counts == [1, 1, 0], f"local-identity scan: {counts}"

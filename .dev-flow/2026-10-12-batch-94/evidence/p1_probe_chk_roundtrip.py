"""P1 C-35/C-15 probe — the shipped v2 writer/reader/check-runner/apply-gate
over a kind="check" document (.chk.json shape, no from/to fields).

Executes the REAL producer chain (no hand-written artifact):
  parse_change_document(authored check text)  [the shipped reader]
  -> serialize_change_document                [the shipped writer]
  -> parse_change_document(bytes)             [re-read what it wrote]
  -> run_check_document                       [the shipped check runner]
  -> apply_change_document                    [the shipped no-apply gate]
Plus the C-15 identity probes: _safe_name on a .chk.json name, and the
document-kind constants.

Run headless from the repo root:

    PYTHONUTF8=1 python -B .dev-flow/2026-10-12-batch-94/evidence/p1_probe_chk_roundtrip.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.tui.changes.apply import apply_change_document
from s19_app.tui.changes.check import run_check_document
from s19_app.tui.changes.io import (
    DUMMY_CHANGESET_TEXT,
    FORMAT_ID,
    FORMAT_VERSION,
    _safe_name,
    parse_change_document,
    serialize_change_document,
)

CHECK_TEXT = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "check",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    {"type": "bytes", "address": "0x00000100", "bytes": "DE AD BE EF"},
    {"type": "string", "address": "0x00000200", "value": "ABC"}
  ]
}"""

print("== C-15 identity probes ==")
print(f"FORMAT_ID        : {FORMAT_ID!r}")
print(f"FORMAT_VERSION   : {FORMAT_VERSION!r}")
print(f"_safe_name('baseline.chk.json') -> {_safe_name('baseline.chk.json')!r}")
print(f"_safe_name('hotfix.pch.json')   -> {_safe_name('hotfix.pch.json')!r}")
print(f"DUMMY_CHANGESET_TEXT kind line  : "
      f"{[l for l in DUMMY_CHANGESET_TEXT.splitlines() if 'kind' in l]!r}")

print("\n== producer chain over kind=check ==")
doc1 = parse_change_document(CHECK_TEXT)
print(f"parsed kind      : {doc1.kind!r}  entries: {len(doc1.entries)}  "
      f"blocking errors: {doc1.has_errors}")

emitted = serialize_change_document(doc1)
print(f"emitted {len(emitted)} bytes; first lines:")
for line in emitted.decode('utf-8').splitlines()[:8]:
    print(f"  | {line}")

doc2 = parse_change_document(emitted)
print(f"re-read kind     : {doc2.kind!r}  entries: {len(doc2.entries)}")
assert doc2.kind == "check" and len(doc2.entries) == 2, "round-trip lost kind/entries"

mem_map = {0x100: 0xDE, 0x101: 0xAD, 0x102: 0xBE, 0x103: 0xEF}
result = run_check_document(doc2, mem_map, [(0x100, 0x104)], [], [])
print(f"run_check_document: blocked reason code = {result.run_blocked_reason_code!r}  "
      f"entry verdicts = {[e.verdict if hasattr(e, 'verdict') else e for e in result.entries]!r}")

applied = apply_change_document(doc2, dict(mem_map), [(0x100, 0x104)], [], [])
print(f"apply_change_document over kind=check: counts = {dict(applied.counts)}")
print(f"mem_map untouched after apply gate  : {mem_map == {0x100: 0xDE, 0x101: 0xAD, 0x102: 0xBE, 0x103: 0xEF}}")

print("\nPROBE OK")

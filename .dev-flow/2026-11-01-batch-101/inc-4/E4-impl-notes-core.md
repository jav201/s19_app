# Inc 4 — E4 implementer notes (reader + change-service unit)

Unit: G1 `s19_app/tui/changes/io.py` (the lazy per-read tag-name index,
`SYMBOL_NO_A2L_CONTEXT_TEXT`, `_parse_entries` / `_parse_entry` /
`_resolve_symbol_tag`) + G2 `s19_app/tui/services/change_service.py`
(`ChangeService.edit_entry_json` keyword, `run_checks_for_project` deletion —
D-1).

## Functions changed per file

- `s19_app/tui/changes/io.py`:
  - `_symbol_name_index` (NEW function)
    - The loop moved unchanged out of `_resolve_symbol_tag`
      (`a2l_context["tags"]` → dict tags only, `str(tag.get("name") or "").strip()`,
      non-empty name → `index.setdefault(name.lower(), tag)`, first match wins).
    - Returns `None` when `a2l_context` is not a dict; else
      `dict[str, dict]` of `{lowercased_name: tag}`.
    - Built at most once per read (R-CHG-SYM.13); called only from
      `_parse_entries`.
  - `SYMBOL_NO_A2L_CONTEXT_TEXT` (NEW module constant, interface I-1)
    - `= "no A2L context is declared for this change-set"`, the R-CHG-SYM.2
      no-context tail; added to the module `__all__`.
  - `_parse_entries`
    - Now builds the index lazily: `symbol_index` starts `None`; on the first
      in-ceiling element that is a dict whose `symbol` is a `str`,
      `symbol_index = _symbol_name_index(a2l_context)` once, then
      `symbol_index=symbol_index` is forwarded to that and every later
      `_parse_entry`. A document with no string-`symbol` entry builds none.
    - Signature unchanged (still takes `a2l_context`); entry-count ceiling
      unchanged. Docstring Data Flow + Dependencies updated to record the lazy
      index.
  - `_parse_entry`
    - Keyword `a2l_context` → `symbol_index: Optional[dict[str, dict]] = None`,
      forwarded to `_resolve_symbol_tag(symbol, symbol_index)`. Every other
      limb (structure, address, symbol limb, value parse, drift, symbol stamp)
      unchanged. Docstring Args updated.
  - `_resolve_symbol_tag`
    - Takes the prebuilt `symbol_index` instead of rebuilding the name index
      from `a2l_context` on every call. `None` → the R-CHG-SYM.2 reason built
      from `SYMBOL_NO_A2L_CONTEXT_TEXT`; miss → the R-CHG-SYM.3 reason; tag
      without address/length → the R-CHG-SYM.4 reason. Reason texts byte-for-byte
      identical to base. Docstring Args + Data Flow updated.

- `s19_app/tui/services/change_service.py`:
  - `ChangeService.edit_entry_json`
    - New keyword `a2l_context: Optional[dict] = None` (interface I-2), forwarded:
      `parse_change_document(envelope_text)` →
      `parse_change_document(envelope_text, a2l_context=a2l_context)`.
    - Envelope, one-entry rule, history push, replace and message texts
      unchanged. Docstring Args updated.
  - `run_checks_for_project` (DELETED — D-1, CODE-CHANGES D9-7)
    - The whole `Headless project entry point (LLR-004.4)` section, its module
      docstring paragraph, and the imports used only by it are removed:
      `from ...core import S19File`, `from ...hexfile import IntelHexFile`,
      `from ..a2l_parse import parse_a2l_file`, `from ..mac import parse_mac_file`,
      `from .a2l_service import enrich_tags_and_render`,
      `from .load_service import build_loaded_hex, build_loaded_s19`, and
      `CheckRunResult` (the `..changes.model` import line is now
      `CHECK_AGGREGATE_KEYS` only). Each removal verified with grep: no other
      code usage remains (one textual `CheckRunResult` mention stays in a
      comment, which needs no import).
    - `grep -rn "run_checks_for_project(" s19_app` after the change → 0 hits.

## Deviations from the graph

None in behaviour. Every code change is exactly the graph's `func:` for the
G1 nodes (`_symbol_name_index` NEW, `_parse_entries` / `_parse_entry` /
`_resolve_symbol_tag` CHANGED) and for `ChangeService.edit_entry_json`, plus
the D-1 deletion of `run_checks_for_project`. The index is built lazily on the
first string-`symbol` entry (E3 A-2), matching the call-counter oracle: 1 call
for a symbol-bearing read, 0 for a document with no string `symbol`.

Two non-behaviour, within-unit accuracy edits: (1) the change_service module
docstring's import sentence was reworded (`core / hexfile / mac / a2l_parse`
and `sibling services` no longer imported after D-1) — kept inside the same
file; (2) `SYMBOL_NO_A2L_CONTEXT_TEXT` was added to `io.py`'s `__all__`, which
is harmless and keeps the module's public-symbol list complete (the app unit
imports it directly from `changes.io`, not via `__all__`). No test file,
REQUIREMENTS.md, AT-TC-REGISTRY.jsonl, or any other source file was touched.
No UI layout change.

## py_compile result

`python -m py_compile s19_app/tui/changes/io.py` → OK (exit 0).
`python -m py_compile s19_app/tui/services/change_service.py` → OK (exit 0).
Line endings preserved as CRLF in both files (`file` reports CRLF before and
after; a byte scan shows 0 bare-LF and 0 bare-CR lines in each).

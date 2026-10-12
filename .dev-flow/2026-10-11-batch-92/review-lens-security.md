# Security lens review — batch 2026-10-11-batch-92 (station P2, trigger C8 / family C)

**Lens:** security-reviewer · **Worktree:** `C:/Users/jjgh8/Github/s19_app-b92` · **Date:** 2026-10-12
**Inputs read:** role file, `stations/p2-review.md`, `01-requirements.md` (LLR-003.2, IFC, §6.3), `design/module-map-delta.md` §3, plus the live code and tests cited below.

## Verdict

**OK to ship** — no HIGH, no MEDIUM, no LOW findings. Zero `Text.from_markup` call sites exist in
`s19_app/` today; the single scrub table has exactly one definition site; the hostile-input oracle
drives the shipped sink and re-derives the control class, so the planned repoint cannot weaken or
bypass it. Phase-3 execution items the contract already binds (repoint of the oracle's own import,
TC-653 census, mutation re-run at the new address) are owed as contract obligations, not new
security mitigations.

## Findings

| id | severity | location | finding | required action |
|----|----------|----------|---------|-----------------|
| — | — | — | No findings. | — |

## Verified clean (executed evidence)

1. **C-17 contract of `safe_text` is as the contract claims — move is byte-preserving, no smuggled behavior edit.**
   `tui/screens_directionb.py:878` `_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x7F, 0xA0)))` — C0 (0x00–0x1F, 32) + DEL (0x7F, 1) + C1 (0x80–0x9F, 32) = 65 codepoints; the normative byte-class comment at `:869-877` (incl. the U+009B/U+009D single-byte CSI/OSC rationale) is on disk verbatim. Body at `:936`: `return Text(value.translate(_CONTROL_SCRUB), style=style)` — literal `Text`, `style` developer-supplied, no markup path. Contract LLR-003.1/003.2 state verbatim relocation; the plan contains no behavior edit. **Evidence state: executed (read `tui/screens_directionb.py:855-949`).**

2. **`_CONTROL_SCRUB` moves WITH the function (contract R7); no second, divergent scrub table exists.**
   Strict grep `dict\.fromkeys|\.translate\(` over `s19_app/` → exactly 2 hits, both the single
   definition/call site at `screens_directionb.py:878`/`:936`. No other module defines a scrub table,
   divergent or otherwise; the strict `^def safe_text|^_CONTROL_SCRUB` census returns one definition
   site. The batch-77 test discipline (`tests/test_tui_hostile_map.py:88-92`) re-derives the class
   (`frozenset(range(0x00,0x20)) | frozenset(range(0x7F,0xA0))`) rather than importing the table, so
   the oracle cannot be made to agree with a wrong implementation by construction. **Evidence state: executed.**

3. **`Text.from_markup` census: zero call sites in product code; the move changes no markup-parsing reachability.**
   `grep -rn "from_markup(" s19_app/` → **0 hits**. All 13 loose `from_markup` mentions in the
   touched modules are docstrings/comments asserting the never-from_markup rule
   (`screens_directionb.py:915`, `insight_style.py:32`, `validation_service.py:48`, etc.). The hex
   renderer under move builds output via `Text()` + styled spans (`tui/hexview.py:430` `text = Text()`,
   `:462`/`:475` `text.append(..., style=byte_style)`), no markup parsing; its imports are
   `rich.text`, engine modules, and style constants only (`tui/hexview.py:1-17`). `microbar`
   (`insight_style.py:216-277`, to `render/format.py`) is likewise pure `Text` + glyphs. **Evidence state: executed.**

4. **Hostile-input oracle exercises the same entry points and sink before/after the move — repoint cannot bypass the sink.**
   `tests/test_tui_hostile_map.py` drives the shipped surface (`S19TuiApp` + `MemoryMapPanel`, both
   `click` and `autoselect` drives, each asserting its own payload-reached-the-body precondition) and
   asserts at the sink `#map_detail_body`: non-control payload verbatim in `render().plain`,
   `spans == []`, and no C0/DEL/C1 byte in the painted `render_line` strip. Its only direct
   `safe_text` import (`:83`) is a test-side convenience; the safety limbs are sink-level and
   import-address-independent. AT-290's view-level nodes (`test_c17_*` in `test_tui_checks_view.py`,
   `test_at082f_*` in `test_tui_issues_view.py`) exercise the checks/issues screens end-to-end; current
   view imports confirmed at `checks_view.py:41`, `issues_view.py:40` (`from .screens_directionb import safe_text`),
   `app.py:79` — all bound for `..utils` repoint by LLR-003.3/TC-653. The executed mutation transcript
   (`safe_text → Text.from_markup` reddens limb 1 ∧ limb 2) is on disk at `test_tui_hostile_map.py:259`;
   LLR-003.2 binds its re-run at the new address as the Phase-3 negative control. **Evidence state: executed.**

5. **No new attack surface from the new addresses.**
   `s19_app/utils.py` (today stdlib-only: `format_bytes`/`is_printable`/`safe_decode`, verified by
   read) gains `safe_text` + `rich.text.Text`; rich is already a package-wide dependency, no new
   supply-chain surface. Module-map §1.3/R6 bounds utils to `rich.text` only (tui/textual forbidden)
   and names the consumer set as closed (app, checks_view, issues_view, screens_directionb + tests);
   no new caller feeding untrusted text into a previously unreachable context is planned anywhere in
   the batch. `render/hexview` and `render/format` expose pure data renderers; their forbidden-dependency
   sets (no `tui/services`, no textual) are declared in module-map §1.1/§1.2. The `insight_style`
   re-export shim (R4) re-exports identical objects only — it widens no parsing surface.
   **Evidence state: executed (module-map §1.1–§1.5 read; consumer sets cross-checked against IFC Part B).**

6. **Registry hygiene (out of security scope, checked as instructed):** `AT-TC-REGISTRY.jsonl` carries
   the batch-92 RESERVED rows — AT-290/AT-291 (`:1386-1387`) and TC-651/TC-652/TC-653/TC-654
   (`:1422-1425`), all `conforming: true`, `origin/reserved_by: batch-92`. Consistent with §5.2. No action.

## Security review summary (for `02-review.md`)

Trigger C8 fired (code rendering file-derived bytes moves address). Verified: single `_CONTROL_SCRUB`
definition site moving verbatim with `safe_text` to `s19_app/utils.py`; zero `Text.from_markup` call
sites in `s19_app/` (all mentions are never-parse assertions); the batch-77 hostile oracle drives the
shipped sink with the control class re-derived in-test, so the import repoint cannot weaken it; no new
caller of the safety primitive and no new dependency surface at the new addresses. **No HIGH — does not
block the gate.** Verdict: **OK to ship** (Phase-3 owes only what the contract already binds: TC-653
census, oracle import repoint, mutation re-run at the new address).

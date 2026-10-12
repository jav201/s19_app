# P2 review closure — code-reviewer — 2026-10-11-batch-92

**Lens:** `code-reviewer` closure pass at P2, worktree `s19_app-b92` @ `410cde5`.
**Task:** verify by EXECUTION that review findings C1/C2 (HIGH) and C3 (MEDIUM) are closed by the
amended contract (disposition C1-(c): `render/hexview.py` 100% tui-free, 5 style constants owned by
`render/format.py`, TC-655-pinned), and check the amendment for new gaps.
**Method:** full re-simulation of Inc-A per the amended contract in a scratch copy of `s19_app/`
(`.dev-flow/2026-10-11-batch-92/_p2sim2/`, since DELETED). Transforms were AST-anchored (wrapper spans
re-derived and asserted: `build_sorted_range_index` 61-84, `address_in_sorted_ranges` 87-113,
`range_in_sorted_ranges` 116-141 — contiguous block 61-141) and the exact LLR repoint texts; the moved
file's import block was rewritten to
`from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE`;
`render/__init__.py` created empty; `render/format.py` created with the 7 constants + `microbar` +
glyphs, values read live from `tui/insight_style.py:43-61,117-118,216-277` and `tui/color_policy.py:13-14`.
All probes ran in FRESH interpreters with the scratch on `PYTHONPATH`, each printing
`s19_app.__file__` to prove which tree answered (every print shows `...\_p2sim2\s19_app\__init__.py`).
Evidence state: `executed`.

---

## Verdict

| finding | severity | status | evidence |
|---|---|---|---|
| C1 (render-first circular import trap) | HIGH | **CLOSED** | P1/P2/P3/P6 below — every render-first cold entry and the pytest collection probe succeed in the sim; root cause (render→tui edges) is killed by design |
| C2 (moved file's own import rewrite unchartered) | HIGH | **CLOSED** | Amended LLR-001.1 states the rewrite verbatim; sim applied it and proved the amended hash threshold measurable (body == base − wrappers − import block, byte-identical, asserted) |
| C3 (census probe under-measured, "10 test files") | MEDIUM | **CLOSED** | LED-…92.7 amended LLR-001.4: AST-walk runtime set-equality + corrected 8-file/3-form census; text verified consistent with the lens's measured sets |
| C4 (stale docstring paths in frozen files) | LOW | open, recorded | named in census; frozen files cannot be edited this batch — unchanged |
| C5 (services drag full TUI at import) | LOW | open, recorded | no regression; residual recorded so the gate is not surprised |

New findings from this pass: **N1 (MEDIUM, process)**, **N2 (LOW, wording)** — below.

---

## Load-bearing probes (all PASS, scratch tree, fresh interpreters)

- **P1** `import s19_app.render.hexview` (cold) → OK; `tree: ...\_p2sim2\s19_app\__init__.py`.
- **P2** `from s19_app.render.hexview import render_hex_view, render_hex_view_text, build_row_bases` (cold) → OK.
- **P3** `import s19_app.render.format` (cold) → OK; `'s19_app.tui' in sys.modules` = **False**
  (render.format is tui-free — the cycle root is gone); `CYAN='#7dd3fc'`, `FOCUS_HIGHLIGHT_STYLE='bold yellow'`.
- **P4** `import s19_app.tui.app` (cold) → OK; `S19TuiApp`/`render_hex_view_text` present.
- **P5** `import s19_app.tui.services.load_service` (cold) → OK; consumer identity:
  `load_service.build_mem_map_s19 is render.hexview.build_mem_map_s19` = True;
  `report_service.render_hex_view` / `diff_report_service.render_hex_view` are `render.hexview`'s objects = True/True.
- **P6** pytest collection touching render-first through a conftest with NO module-level s19_app import
  (the C1 precondition): `python -m pytest tests_renderprobe -q --co` → `1 test collected`, node passes.
  Sim-harness note: the worktree `pyproject.toml` (`pythonpath=["."]`) made pytest resolve rootdir to the
  REAL worktree and shadow the scratch with the real (render-less) `s19_app`; fixed by giving the scratch
  its own `pytest.ini` (`pythonpath=["."]`), which mirrors the real Phase-3 run shape (rootdir = tree
  containing `s19_app/render/`). Artifact of the sim, not of the batch.
- **P7 (negative controls, HLR-002/LLR-002.1/002.2):** the 3 wrapper names absent from `s19_app.tui`
  namespace and `tui.__all__`, absent from `render.hexview`; `from s19_app.range_index import
  address_in_sorted_ranges` still works (engine intact).
- **P8 (namespace surface):** all **12** renderer names re-exported via `tui` (see N2 — the contract text
  says "10/10"; the measured surviving set is 12).
- **P9 (behavior identity):** same inputs rendered through the REAL tree's `tui/hexview.py` and the
  scratch's `render/hexview.py` — `diff` of JSON dumps: **byte-identical** `Text.plain`, style spans,
  `render_hex_view` str output, and the 10 constants (incl. `CYAN/DGRAY/VALUE/FOCUS_HIGHLIGHT_STYLE/
  MAC_ADDRESS_OVERLAY_STYLE`).
- **Shim probe (amendment step-3):** the planned `insight_style` shim
  (`from s19_app.render.format import …` × 8) appended in the scratch → cold `import
  s19_app.tui.insight_style` OK, 8/8 `is`-identity to `render.format` objects, retained palette +
  `human_bytes/label_value/threshold_style/cap_gauge_style` intact, `microbar` clamp arms 0/8/1
  (= `microbar(-0.5,8)`, `microbar(1.5,8)`, `microbar(0.01,8,floor=True)` per the contract), and
  `import s19_app.tui.app` through the shim OK. One-directional as designed (tui→render only).
- **Public-API test (step-4 probe):** the REAL `tests/test_tui_public_api.py` run against the scratch →
  `6 passed, 1 xfailed` — `test_tui_public_api_exports_main_helpers_and_constants` pins the surface via
  `issubset(tui.__all__)` (`:34`) with NO wrapper name pinned → dropping the 3 wrappers from `__all__`
  is deletion-safe. `tests/test_report_service.py:595` does assert `"from ..hexview import" in source`
  exactly as LLR-001.4's negative control states (repoint owed at Phase 3).

## Contract consistency (amended LLR-001.1/001.4 · HLR-001 · §5.2 · AT/TC · module-map §6.1)

- **TC-655** is referenced where it belongs: LLR-001.1 verification+threshold, LLR-001.2 verification,
  LLR-004.1, HLR-001 numeric threshold, §5.2 rule (3); RESERVED in `AT-TC-REGISTRY.jsonl` with a
  conforming statement; `high_water TC=655` / `next_free 656`. ✓
- **44-node union rule** is stated identically across HLR-001 threshold, §5.2 (4-rule gate), §1.3 glossary
  row, §6.3 risk — same evidence path, "never a count comparison" in all sites. ✓
- **Module-map §6.1:** the two `render→tui` rows say **KILLED this batch** with the exact amended import
  text; the `change_service → color_policy` residual is declared; the new `insight_style → render/format`
  shim edge is declared; no "survives" language left for the killed rows. ✓
- **HLR-002/003/004 thresholds** say "0 NEW failures"; read against §5.2 rule (1) this means
  outside-union flips — coherent by reference, no contradiction. ✓
- **N1 (MEDIUM — NEW):** **Inc-A/Inc-B sequencing contradiction.** Amended LLR-001.1 (Inc-A) rewrites the
  moved file to `from .format import …`, which requires `render/format.py` to exist at Inc-A — but the
  module-map §5 cut and §1.2 scope still assign `NEW s19_app/render/format.py` to **Inc-B** ("B drops
  `format.py` into the existing package"). Implemented literally, Inc-A's own gate fails at import
  (`ModuleNotFoundError: s19_app.render.format`); this sim had to create `format.py` with Inc-A for any
  probe to pass — i.e. the amended contract is executable ONLY with format.py creation folded into Inc-A
  (which LED-…92.5's text arguably already intends, but the increment cut was never updated). One-line
  fix: scope `render/format.py` into Inc-A's touch set (package scaffolding), or move the import rewrite
  to Inc-B (it cannot stay at Inc-A without format.py).
- **N2 (LOW — NEW):** LLR-002.2's threshold says "renderer names present (10/10)" but the surviving
  re-export set measures **12** (base block :18-32 minus the 3 wrappers). The "10" is unenumerated, so a
  TC-652 authored against it is ambiguous. Fix: enumerate the 12 names or drop the parenthetical.

## Gate recommendation

**PASS — C1/C2/C3 closed by execution; contract is implementable.** Send to Phase 3 with N1 as a
mandatory one-line scoping clarification (fold `render/format.py` into Inc-A) and N2 as an optional
wording fix; neither reopens the findings. C4/C5 remain recorded-open by design.

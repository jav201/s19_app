# Increment 001 — HLR-001/HLR-002 (LLR-001.1–001.4 · LLR-002.1–002.3) · `hexview byte-preserving move to s19_app/render/ + wrapper removal`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/increment-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `SOURCE files` · `Instrument RED-proof` · `Correction population` · `Mutation verdicts` · `Emitted-form assertion` · `Reverse census` · `RED counterfactual` · `Independent review` · `Evidence files` · `Traces to` · `File` · `Kind` · `source` · `test` · `doc` · `config` · `generated` · `fixture` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Where this lives:** the **repo**, next to the diff it describes —
> `.dev-flow/2026-10-11-batch-92/03-increments/increment-001.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

| Field | Value |
|---|---|
| Batch | `2026-10-11-batch-92` |
| Increment | `001` |
| Lane (if the batch forked) | `none — sequential Inc-A → Inc-B (module-map §5, ARQ Exit-1)` |
| Requirement(s) | `HLR-001 · HLR-002 · LLR-001.1 · LLR-001.2 · LLR-001.3 · LLR-001.4 · LLR-002.1 · LLR-002.2 · LLR-002.3` (+ `LLR-004.1` for the `render/format.py` creation folded into Inc-A per LED-…92.12 / design #D3 / finding N1) |
| Acceptance | `AT-288` · white-box `TC-651 · TC-652 · TC-655` · unit `test_tc_023_*` repointed constants nodes |
| Agent | `software-dev` |
| Date | `2026-10-12` |

---

## 1 · What changed

BLUF: `s19_app/tui/hexview.py` is gone; `s19_app/render/hexview.py` (byte-identical to the base file
minus the 3 `range_index` re-export wrappers minus the style-constant import block, verified by SHA-256
body-hash) and the new package `s19_app/render/` (`__init__.py` marker + `format.py` owning the 5 style
constants, `microbar` + glyphs, and the two TC-655-pinned copies of the frozen `tui/color_policy.py`
styles) replaced it. All 8 measured product consumers and all 8 measured old-address TEST importers
(3 forms) now read `s19_app.render.hexview`; `app.py` sources the range primitives from the engine
`s19_app.range_index`; `tui/__init__.py` re-exports the 12-name renderer surface from the render
address and dropped the 3 wrapper names. The shipped surface (Direction-B hex view, report services,
app shell) renders from the new address, and AT-288 — the batch's sole byte-identity oracle — proves
the emitted report bytes are identical to the pinned pre-move capture.

Mechanism, in the chartered order: (1) the AT-288 node
`tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` was authored and
run against the BASE tree first; its emitted report bytes (7 739 bytes, SHA-256
`061ee94c07bbed51f5cb99962ba3ed4acbc0c7c6a4461168d1f596d5cdfa4c39`) are pinned at
`evidence/at288-pre-move-report.bin`. The node drives a modified region at the tail of fixture range 0
with non-default `context_bytes=0x200`, so the emitted `row_bases` window `0x08000DF0-0x08001200`
spans the unmapped gap into disjoint fixture range 1 (asserted on the emitted bytes, including the
all-dots gap row). (2) The move: `render/hexview.py` body = base `tui/hexview.py` minus base lines
61-143 (the 3 wrappers, AST-verified contiguous span 61-141, plus their 2 trailing blank lines 142-143)
with base lines 16-17 (the two `tui` style imports) replaced by exactly
`from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE`.
Body-hash equality recorded in §4. (3) Repoints per the measured set (LLR-001.4). (4) New census TCs
TC-651/TC-652 (`tests/test_render_hexview.py`) and TC-655 (`tests/test_render_format.py`).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/render/__init__.py` | source | LLR-001.1 | NEW package marker, empty of logic (#D2) |
| `s19_app/render/hexview.py` | source | LLR-001.1 · LLR-001.2 · LLR-001.3 · LLR-002.1 | NEW — byte-preserving move of base `tui/hexview.py` minus wrappers minus import block |
| `s19_app/render/format.py` | source | LLR-001.1 · LLR-004.1 | NEW — owns `CYAN/DGRAY/VALUE/GREEN/LABEL`, `MICROBAR_FILLED/EMPTY`, `microbar` (verbatim move), + the two pinned `color_policy` style copies (TC-655) |
| `s19_app/tui/hexview.py` | source | LLR-001.1 · LLR-002.1 | DELETED (retired path; existence probe → 0) |
| `s19_app/tui/app.py` | source | LLR-001.4 · LLR-002.3 | hexview block repointed: `build_row_bases`/`find_string_in_mem`/`render_hex_view_text` → `s19_app.render.hexview`; `address_in_sorted_ranges`/`build_sorted_range_index` → `s19_app.range_index` |
| `s19_app/tui/__init__.py` | source | LLR-001.4 · LLR-002.2 | renderer re-exports sourced from `s19_app.render.hexview`; 3 wrapper names dropped from imports and `__all__` (12-name surface kept) |
| `s19_app/tui/screens.py` | source | LLR-001.4 | `from ..render.hexview import MAX_HEX_ROWS, render_hex_view_text` |
| `s19_app/tui/screens_directionb.py` | source | LLR-001.4 | two function-local imports (`:3336`, `:7581`) repointed to `..render.hexview` |
| `s19_app/tui/services/load_service.py` | source | LLR-001.4 | `from ...render.hexview import (4 builders)` |
| `s19_app/tui/services/report_service.py` | source | LLR-001.4 | `from ...render.hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view` |
| `s19_app/tui/services/diff_report_service.py` | source | LLR-001.4 | `from ...render.hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view` |
| `tests/test_render_hexview.py` | test | LLR-001.4 · LLR-002.1 · LLR-002.2 · LLR-002.3 | NEW — TC-651 (AST import census) + TC-652 (wrapper absence + renderer surface) |
| `tests/test_render_format.py` | test | LLR-001.1 · LLR-004.1 | NEW — TC-655 value/equality pin to the frozen tui origins |
| `tests/test_report_service.py` | test | HLR-001 (AT-288) · LLR-001.4 | NEW node `test_at288_report_hex_sections_identical_after_move`; `:595` source-census string repointed (`"from ..hexview import"` → `"from ...render.hexview import"`) |
| `tests/test_tui_diff_screen.py` | test | LLR-001.4 | local import repointed (`:2788`) |
| `tests/test_tui_directionb.py` | test | LLR-001.4 | two locals repointed (`:1172`, `:1191`; form 3) |
| `tests/test_tui_goto_marker.py` | test | LLR-001.4 | module import (`:28`) + local (`:195`) repointed |
| `tests/test_tui_hexview.py` | test | LLR-001.4 · LLR-002.1 | module block split (6 wrapper behavior nodes → `s19_app.range_index`; renderer names → `s19_app.render.hexview`); 7 local `import ... as` repointed |
| `tests/test_tui_hexview_classed.py` | test | LLR-001.4 | module import repointed (`:34`) |
| `tests/test_tui_operations_view.py` | test | LLR-001.4 | module import repointed (`:42`) |
| `tests/test_tui_search_pagination.py` | test | LLR-001.4 | module import repointed (`:19`; form 3) |

| Count | Value |
|---|---|
| **SOURCE files** | **11 / 4** (3 new + 8 modified − 1 deleted) |
| Test files | 10 (uncapped) |
| Doc files | 0 (outside the count) |

- ⚠ **Above 4 source files:** the measured repoint set is closed and authoritative (module-map §5 F-2;
  the radiography-derived consumer census), and the byte-preserving move + wrapper removal cannot be
  cut smaller without leaving a consumer at the old address (the TC-651 census exists precisely to
  police that set). **Waiver: PDR condition C1 — the >4 source-file budget is waived for this
  repoint-only increment** (operator-ratified at the P1 gate; restated here per the increment brief;
  the §6.3 gate question of `01-requirements.md` is discharged by that ruling).
- ✗ No file from Inc-B's set was touched (`utils.py`, `insight_style.py`, `validation_service.py`,
  `checks_view.py`, `issues_view.py`, and the `app.py` `safe_text` block are untouched — verified by
  `git diff 410cde5 --name-only` over that set → 0 entries).
- ⚠ **§2 addendum — close-out reconciliation, 2026-10-12 (V59):** three files in the batch's
  final diff were touched by STATION gates, not by this increment's edits; they are named here
  so the record carries every touched file, with the true authorship stated (batch-91 precedent:
  registry/guard rows carried in an increment table as `config`/`test`). The Count block above
  stays as sealed — `config`/`doc` rows are outside the source count, and the guard row is a
  post-increment DDR edit.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `AT-TC-REGISTRY.jsonl` | config | HLR-001 · HLR-002 · HLR-003 · HLR-004 (id chartering) | RESERVED rows for AT-288…AT-291 / TC-651…TC-655 appended + `high_water`/`next_free` bumps at the P1 chartering gates (LED-…92.1/.2/.4/.5); the AT-290/AT-291 re-binding RESERVED→LIVE is a carried close item, NOT done in-batch |
| `tests/test_id_registry.py` | test | HLR-001 · HLR-002 (registry guard) | DDR condition C-1: `EXPECTED_SCANNED_TEST_FILES` 159 → 162 at :70 (LED-…92.14); guard 13/13 — touched at the DDR, after both increments |
| `docs/architecture.md` | doc |  | ARQ module-map application: the `render/` module entry + module-map §6.1 residual rows 1–2 flipped to KILLED (F-1 frozen-list amendment; DDR C2 condition) |

---

## 3 · How to test

```bash
# The new census TCs (one complete run)
python -m pytest tests/test_render_hexview.py tests/test_render_format.py -q
# The repointed test files (one complete run)
python -m pytest tests/test_tui_hexview.py tests/test_tui_hexview_classed.py tests/test_tui_goto_marker.py tests/test_tui_operations_view.py tests/test_tui_search_pagination.py tests/test_tui_diff_screen.py tests/test_report_service.py tests/test_report_field_census.py -q --tb=short -rf
# The FULL render-module guard host (never a -k subset)
python -m pytest tests/test_tui_directionb.py -q
# AT-288 — the byte-identity oracle (post-move: compares against the pinned capture)
python -m pytest "tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move" -q
# Frozen dual-guard (C-27): SOURCE guard + the TC-031 pair/TC-032 (color_policy freeze coverage)
python -m pytest tests/test_engine_unchanged.py -q
python -m pytest "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main" "tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_name_only_diff_vs_main" "tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main" -q
# Body-hash verification of the move (stored transcript; the comparator is the
# base file at 410cde5 minus wrappers 61-143 minus import block 16-17)
cat .dev-flow/2026-10-11-batch-92/evidence/increment-001-body-hash.txt
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | `test_tc655_render_format_values_pinned_to_frozen_origins` (+ the 5 repointed `test_tc_023_*` constant nodes inside the guard host run) | 1 passed (TC-655 transcript, §Evidence files); constants 5/5 probe executed (`HEX_WIDTH=16`, `MAX_HEX_ROWS=512`, `MAX_HEX_BYTES=65536`, `FOCUS_CONTEXT_ROWS=64`, `SEARCH_ENCODING="ascii"` at the new address) |
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | `test_tc651_import_census_all_consumers_read_render_hexview` · `test_tc652_wrapper_absence_and_renderer_surface` | 2 passed (one complete run of both new modules: 3 passed incl. TC-655, exit 0) |
| **B · black-box** `AT-NNN` ↔ story, through the shipped surface | `core` · `full` | `test_at288_report_hex_sections_identical_after_move` | 1 passed pre-move at BASE (capture stored), 1 passed post-move (byte-equality with the pinned capture asserted) |

Repointed files (one complete run, read from its own transcript):
186 collected — 185 passed, 1 failed, exit 1 (`increment-001-repointed-files-run2.transcript`,
215 s). The single failure is `tests/test_report_field_census.py::test_a16_canonicaliser_residue_guard_can_actually_fire`,
a node INSIDE the pinned 44-id union (`evidence/baseline-failing-set.txt:18`) — recorded per the §5.2
gate rule, not counted. Every node outside the union passed, including `AT-288` (which rides in
`tests/test_report_service.py` and asserted byte-equality against the pinned capture in this run) and
`test_tc024_report_trigger_invalid_dest_refused` (the load-sensitive flake dissected in §5 — passed
here). The first run of this same set (`increment-001-repointed-files.transcript`, 2 failed: the same
a16 node + one tc024 flip) is retained as the flake's primary evidence.

Full guard host `tests/test_tui_directionb.py` (one complete run, C-19/C-34 — never a `-k` subset):
183 passed, 0 failed, exit 0 (`increment-001-directionb-guard.transcript`, 247 s) — every node outside
the 44-id pinned union passed, and no in-union node even flipped.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | TC-651's own census: `tui/screens.py` import flipped back to the retired address `from .hexview import ...` + the old `s19_app/tui/hexview.py` restored byte-exact from `410cde5` (move-aside restore — no stash/staging used, C-20) |
| Instrument | project code: my own hand (python edit); the restore proven by SHA-256, not `git status` |
| Where it ran | **my own worktree** `C:/Users/jjgh8/Github/s19_app-b92` |
| Transcript | `evidence/increment-001-tc651-red.transcript` — `AssertionError: hexview importer set drifted from the measured set: extra=[] missing=['s19_app.tui.screens']` (the census went RED on the flipped consumer) |
| Restore proven by | **file hash returned to its pre-mutation value**: `s19_app/tui/screens.py` `94003d51a83ffb955273f4203dfc42f330f8aa4bff162f75e124051c21f9d48c` (pre == post); the restored `tui/hexview.py` was deleted again (existence probe → 0) |
| Bytecode cache | `PYTHONDONTWRITEBYTECODE=1` on every run (C-46) |
| Arms resolved at baseline | 1 (the TC-651 census node) |
| Verdict granularity | per resolved node id — `test_tc651_import_census_all_consumers_read_render_hexview` FAILED |
| Arms that stayed GREEN | none — the single armed node went RED |

| Field | Value |
|---|---|
| **RED counterfactual** | one consumer (`s19_app/tui/screens.py:34`) flipped back to `from .hexview import …` with the retired file restored from `410cde5` made THIS increment's own TC-651 census fail (`missing=['s19_app.tui.screens']`) · transcript `evidence/increment-001-tc651-red.transcript` (SHA-256 `b0d3defae4f67c1a742f238c7818905f225280edf5042b2e987aa2b3e13e0c65`) · restore digest `94003d51a83ffb955273f4203dfc42f330f8aa4bff162f75e124051c21f9d48c` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 4 arms, all KILLED (each per resolved node id, inert arms: none): **(1)** TC-651 arm above → KILLED · **(2)** TC-652 arm: one wrapper shim re-added to `s19_app/tui/__init__.py` (`address_in_sorted_ranges` import + `__all__` entry, sourced from the engine) → `test_tc652_wrapper_absence_and_renderer_surface` FAILED (`s19_app.tui must not expose address_in_sorted_ranges`), transcript `increment-001-tc652-red.transcript`, restore digest `bed98ccf1bb52dffeb314a86b20ea39c333da2f2fc148734f90d606b18a7bf2a` → KILLED · **(3)** TC-655 arm: `CYAN` drifted one hex digit at the new address (`#7dd3fc`→`#7dd3fd`) → `test_tc655_render_format_values_pinned_to_frozen_origins` FAILED (`assert '#7dd3fd' == '#7dd3fc'`), transcript `increment-001-tc655-red.transcript`, restore digest `eaad0a3ce57eff50826e959525e961ee8fbd8ecd675c62b963a1b104d6e18a8d` → KILLED · **(4)** AT-288 arm: the PINNED CAPTURE COPY corrupted at offset 500 (one byte XOR 0xFF; the pristine bytes ride in `at288-pre-move-report.bin.PRE`, digest `061ee94c…`) → `test_at288_report_hex_sections_identical_after_move` FAILED (`post-move report bytes differ from the pinned pre-move capture`), transcript `increment-001-at288-red.transcript`; the capture was restored to the pinned digest `061ee94c07bbed51f5cb99962ba3ed4acbc0c7c6a4461168d1f596d5cdfa4c39` (re-hash proven) → KILLED |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| TC-651 AST census (`tests/test_render_hexview.py`) | one consumer flipped back to the retired address + old file restored | census RED naming the flipped consumer (`missing=['s19_app.tui.screens']`) |
| TC-652 absence census (`tests/test_render_hexview.py`) | one wrapper shim re-added to `s19_app/tui/__init__.py` | positive-absence assertion fired (`s19_app.tui must not expose address_in_sorted_ranges`) |
| TC-655 value pin (`tests/test_render_format.py`) | `CYAN` value drifted one hex digit at the new address | `assert '#7dd3fd' == '#7dd3fc'` |
| AT-288 byte oracle (`tests/test_report_service.py`) | pinned capture copy corrupted (1 byte) | `post-move report bytes differ from the pinned pre-move capture` |
| tui-free import probe (TC-651 § + TC-655 §) | same probe run over the BASE body (known-present case) | on the base body it FINDS the edges (`['.color_policy', '.insight_style']`); on the moved body it returns `[]` — the absence is discriminating, not vacuous (`increment-001-tuifree-positive-control.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 5 instruments, each shown RED (or finding the known-present case) before its first PASS was believed |

Fixture discrimination (C-57): the AT-288 fixture makes "spans ≥2 disjoint ranges" observable — the
emitted window carries the all-dots gap row (`0x08001000 … |................|`) between mapped range-0
rows and mapped range-1 rows; the in-test assertions pin the window header, the non-default
`Context bytes: 512` line, the gap row, and a mapped range-1 row, so a default-only image or a
single-range window cannot satisfy the node.

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| The AT-288 project report (`<tmp>/reports/…-report.md` via `generate_project_report`) | `path.read_bytes()` compared for byte-equality against `evidence/at288-pre-move-report.bin` (7739 bytes) | post-move run: `1 passed` — the emitted bytes equal the pinned capture exactly |
| The moved source body | SHA-256 of base-minus-wrappers-minus-import-block vs `s19_app/render/hexview.py` | `fe6921c79b8f44776e2350db317b8f01150f341b9280f36f26b25ac4a2185f3b` == `fe6921c79b8f44776e2350db317b8f01150f341b9280f36f26b25ac4a2185f3b` → BYTE-IDENTITY: True (`increment-001-body-hash.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 2 artifacts, each asserted against the form its producer emitted (file bytes via `read_bytes()`, not rendered text) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| Pinned pre-move report capture (7739 B) | `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.bin` | `061ee94c07bbed51f5cb99962ba3ed4acbc0c7c6a4461168d1f596d5cdfa4c39` |
| Capture digest record | `.dev-flow/2026-10-11-batch-92/evidence/at288-pre-move-report.sha256` | `c00f0c19f2c2e426cfe57b6b1de4af82500d9bee4c9ab01a356d10220898471d` |
| Body-hash verification of the move | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-body-hash.txt` | `fe0262982322d9814050cd9bd3345ee35876216bf7fa60804d9dc3f974c4d276` |
| New TC modules run (3 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-tc-modules.transcript` | `78747a66548fb5eded1ac1fd61754996195625e72bd8f3f5f44cedca56e6626e` |
| Repointed test files run | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-repointed-files-run2.transcript` | `a2d855f384d38680f96b37309352a843f59aba889b0f9cdffe7c1d5d79d24d29` |
| Full directionb guard host run (183 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-directionb-guard.transcript` | `151ae874bcc2082a5494fc5cc0c8a997940be5701502aca08eb85b1b8e6abf1d` |
| AT-288 post-move run (1 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-at288-post-move.transcript` | `ddf500f18602b83f77d91aa049f275516df4c06cdbd1b108c32fbe8507c4d04c` |
| Frozen SOURCE guard TC-027 run (1 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-dual-guard-source.transcript` | `e7e1207f0cc87925e1d6215c3f912d7e320f4610d6484644d4bd515cf926e740` |
| Frozen TEST-file guard TC-031 pair + TC-032 run (3 passed) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-dual-guard-testfile.transcript` | `2d091a7f218d574f26b5e1482a2a6771e011684f78ea3e9ca53482985c8716e4` |
| Cold-import probes (5/5) | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-cold-probes.transcript` | `9622ad395e4c3ba0215811b9630b69d396b69a0e4335f35b24bc947146f4c3ae` |
| TC-651 RED counterfactual | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-tc651-red.transcript` | `b0d3defae4f67c1a742f238c7818905f225280edf5042b2e987aa2b3e13e0c65` |
| TC-652 RED arm | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-tc652-red.transcript` | `03cc5b62c4294413eb7d0088fb9d443113f1bb2e81cf99c24b7ffa5ac29bdd92` |
| TC-655 RED arm | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-tc655-red.transcript` | `5bf99d6ca666122a18d4a9c4d2f149f06f7f0ca321ac00b08a3033a2bde89fc1` |
| AT-288 RED arm | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-at288-red.transcript` | `f3561da8e693cccfe3ef024aed4794210fadbe4d500e77c128137cb9bdd40697` |
| tui-free positive control | `.dev-flow/2026-10-11-batch-92/evidence/increment-001-tuifree-positive-control.txt` | `204048121506988528031514a9590fd0c095a21e1cd7032ae090041597752a43` |

| Field | Value |
|---|---|
| **Evidence files** | 15 artifacts at the declared home, each cited with the digest of its stored bytes; `.gitattributes` marks `evidence/**` `-text` (mixed line endings stored verbatim). The first repointed-files run (`increment-001-repointed-files.transcript`, digest `7356482a41a9f81a2841733433094c6df2c17e0ea0937e49a07055f54ce80eaa`) is retained and dissected in §5 — its tc024 flip is the flaky node under analysis. |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (a) "no live import of the retired `s19_app.tui.hexview` address" (TC-651); (b) "no wrapper name in the `s19_app.tui` namespace/`__all__`" (TC-652); (c) "zero `s19_app.tui.*` imports under `render/`" (tui-free rule) |
| If the result is an ABSENCE, what made the search wide enough | (a)+(b) AST walk over ALL of `s19_app/` (every `Import`/`ImportFrom`, aliased/plain, module-level and function-local) + a tests/-side census, derived from the live tree at run time — not a marker list; (c) AST walk over every `.py` under `render/` |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_tc651_import_census_all_consumers_read_render_hexview` (conclusion: the measured consumer set is exactly the declared set); `test_tc652_wrapper_absence_and_renderer_surface` (conclusion: wrappers are un-importable from `s19_app.tui`) |
| Conjunctive criteria: one mutation per conjunct | 4 arms, one per conjunct: consumer-at-old-address (TC-651) · wrapper-shim-restored (TC-652) · copied-value drift (TC-655) · capture corruption (AT-288) — each verdict reported separately above |
| Synthetic instance of the absent case | (a) the restored `tui/hexview.py` + flipped consumer IS the synthetic instance — the same unmodified census probe then reported the retired module as present (RED transcript); (c) the same tui-free probe over the BASE body returns `['.color_policy', '.insight_style']` (known-present case) while the moved body returns `[]` |
| **Positive control for every probe that returned an ABSENCE** | TC-651: the synthetic instance above (probe non-absent on it). TC-652: the 12 renderer names ARE present in the same `s19_app.tui` namespace — the identical probe returns non-absent output for them (`tui.X is render_hexview.X` 12/12). tui-free rule: the base-body probe finds the two tui edges. TC-655: the frozen origins still hold every value (equality asserted both directions) |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl "render_hex_view\|build_row_bases\|build_mem_map_s19\|FOCUS_HIGHLIGHT_STYLE\|MAC_ADDRESS_OVERLAY_STYLE" tests/ --include="*.py"` | 14 files assert the touched renderer symbols (repointed files + `test_tui_helpers.py`, `test_tui_public_api.py`, `test_range_index.py`, the two new TC modules, …); 8 files assert the 3 wrapper symbols (`test_range_index.py`, `test_tui_hexview.py` ×6 nodes, `test_render_hexview.py`, `test_linkage_soundness.py`, `test_report_addendum_bound.py`, `test_report_producer_bound.py`, `test_tui_map_big.py`, `test_tui_directionb.py`) — all green in the §4 runs |
| B2 file moved on disk | `grep -rn "tui\.hexview\|tui/hexview" s19_app/ tests/ --include="*.py"` | no live readers of the old path. Surviving text mentions only: `s19_app/range_index.py:29,60,94` docstrings (frozen file — C4-declared, routed to BACKLOG-CODE lane A at close) and the TC-023 census string at `tests/test_tui_hexview.py:360` (a negative assertion, see below) |
| B3 byte-identical golden captures this source | `grep -rln "hexview" tests/goldens/ tests/__snapshots__/` | 0 hits — no golden/snapshot captures this source; AT-288 is the byte-identity oracle instead (design F-QA-3) |
| B4 artifact produced here is consumed elsewhere | who reads `s19_app/render/{hexview,format}` + the AT-288 capture | product consumers = exactly the 7-file measured set (TC-651 census, set-equality); the capture is consumed only by the AT-288 node; `render/format` is consumed by `render/hexview` (and, from Inc-B, the shim + services) |

| A3 | interface consumed by another module changed | `grep -rn "render.hexview\|render.format" s19_app/ --include="*.py" | grep import` | consumers = the measured set only — `tui/app.py`, `tui/__init__.py`, `tui/screens.py`, `tui/screens_directionb.py` (2 locals), the 3 services; plus `render/hexview.py` importing `.format`. No consumer outside the owning module's declared set (F-QA-2 census) |

| Field | Value |
|---|---|
| **Reverse census** | 5 probes run of B1 · B2 · B3 · B4 · A3 — B1: 14+8 asserting files, all green in the cited runs · B2: 0 live readers (2 C4-declared text mentions) · B3: 0 goldens · B4/A3: consumer set == measured set, closed |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| hexview import addresses (product) | every import statement addressing the moved module in `s19_app/` | `grep -rn "hexview import\|from .hexview\|from ..hexview" s19_app/` (pre-state: 8 consumer sites in 7 files) | 8 sites / 7 files | all 8 (app.py block, `__init__` block, screens.py, screens_directionb.py ×2, load/report/diff services) | 0 left |
| hexview import addresses (tests) | every import of the moved module across `tests/` in all 3 forms + source-census strings | `grep -rn "s19_app.tui.hexview\|from .hexview import\|import hexview" tests/*.py` (pre-state measured: 8 files, 3 forms, LED-…92.7) | 8 files / 3 forms + 1 string | all 8 files + the `test_report_service.py:595` expected string | 0 left |
| stale `s19_app.tui.hexview` TEXT mentions (C4) | docstring/comment mentions of the retired path | the B2 probe above | 3 text sites (`range_index.py:29,60,94`) | 0 | 3 left — all inside the FROZEN engine `range_index.py` (cannot be edited this batch; C4 routes them to BACKLOG-CODE lane A at close and names them in this census so the drift does not read as a surprise) |

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated with its method before its first site was edited |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `from .hexview import` / `from ..hexview import` (old relative forms) | 0 hits in `s19_app/` and `tests/` (outside frozen docstrings) | yes | probe output in §5 evidence; TC-651 asserts the retired module unimportable |
| `s19_app.tui.hexview` | 0 live imports; 3 frozen docstring mentions + 1 census string in `tests/test_tui_hexview.py:360` | yes | `range_index.py:29,60,94` are documentation in a frozen file; `test_tui_hexview.py:360` is itself a negative assertion (private-helper absence census) |
| `address_in_sorted_ranges` / `build_sorted_range_index` / `range_in_sorted_ranges` as `tui` exports | 0 in `tui/__all__`; unimportable from `s19_app.tui` | yes | TC-652; mutation arm 2 reddened exactly this |

### Signed-balance test ledger

`post = base − deleted + added` → the repointed 8-file set: `186 = 185 − 0 + 1` ✓ reconciles
(base 185 nodes at `410cde5` + the new AT-288 node; the first-run count `185+1` and the base A/B runs
measured 183/184 passed + the same failing family — see §5). Guard host: `183 = 183 − 0 + 0` ✓
(directionb untouched apart from 2 repointed locals, no node added/removed). New TC modules: `3 = 0 − 0 + 3` ✓.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · **OK to advance** (no HIGH, no MAJOR; 4 LOW notes below; every check below was executed by me in the worktree, not read from the packet) |

**Verdict: OK to advance** — no HIGH findings; nothing blocks the increment gate. The move is
byte-exact, every contract repoint claim holds on disk, the three new TCs are real discriminating
oracles (one RED arm re-executed by me), AT-288's pinned capture verifies and the node passes now
against the moved tree, all 15 cited evidence artifacts re-hash to their recorded digests, and scope
discipline holds (Inc-B set and frozen set: 0 diff entries). LOW notes only; the tc024 disposition
is an orchestrator ruling, not an increment defect.

Executed evidence (reviewer-run, 2026-10-12, worktree `C:/Users/jjgh8/Github/s19_app-b92`):

- **Body hash recomputed independently** — `git show 410cde5:s19_app/tui/hexview.py` minus base
  lines 61–143 (3 wrappers + 2 trailing blanks) minus base lines 16–17 plus the single
  `from .format import …` line ⇒ SHA-256 **`fe6921c79b8f44776e2350db317b8f01150f341b9280f36f26b25ac4a2185f3b`** —
  **MATCH** with `s19_app/render/hexview.py` and with the packet's claim. Zero `s19_app.tui.*`
  imports under `render/` (grep + the AST probes in TC-651/TC-655).
- **Repoints vs contract** — all 8 product consumer sites at the contract-named lines
  (app.py:37-42, `tui/__init__.py:17-31`, screens.py:34, screens_directionb.py:3336,7581,
  load_service.py:8, report_service.py:58, diff_report_service.py:96); `tui/__init__` drops exactly
  the 3 wrapper names from the import block **and** `__all__` and keeps the 12 renderer names;
  `app.py` carries `from ..range_index import address_in_sorted_ranges, build_sorted_range_index`
  + `from ..render.hexview import build_row_bases, find_string_in_mem, render_hex_view_text`
  (LLR-002.3 verbatim). All 8 old-address test importers (3 forms) + the `:595` census string
  repointed — verified by direct read, and independently by the passing TC-651 census.
- **TC oracle judgment** — TC-651 derives the importer set from the **live tree at run time**
  (AST walk over all of `s19_app/` + `tests/`, both aliased and plain forms, module-level and
  function-local) and asserts two-way **set-equality** (`extra=` / `missing=`) — drift in either
  direction fails it; not a hand list. TC-652 is a true positive-absence census (`hasattr` +
  `__all__` + `import_module` raising `ImportError`) plus 12/12 object-identity (`is`) checks on
  the renderer surface. TC-655 pins literal values **and** equality to the frozen origins in both
  directions (`render.format.X == tui.origin.X`) plus `inspect.getsource` verbatim-equality of the
  moved `microbar`. All three discriminate. I re-ran the 3-node module myself: **3 passed**.
- **Reviewer-executed RED arm** — I added a scratch consumer `s19_app/tui/_review_scratch.py` with
  `from s19_app.tui.hexview import build_row_bases` (no file restore needed — the census is
  AST-based): TC-651 went **RED** naming it
  (`AssertionError: s19_app.tui.hexview still imported by ['s19_app.tui._review_scratch']`).
  Scratch removed → TC-651 green again → `git status` over `s19_app/` byte-identical to the
  pre-mutation file set. The instrument reports FAILURE first. ✓
- **AT-288 integrity** — capture present (7 739 B), `sha256 = 061ee94c…4c39` matches the sidecar
  `.sha256` **and** the retained `.PRE`; the node drives the re-chartered driveable set **in
  source** (non-default `context_bytes=0x200` asserted on the emitted form as
  `- Context bytes: 512`; `row_bases` window asserted `low < range0_end < range1_start < high`
  across the unmapped gap with the all-dots gap row and a mapped range-1 row — a default-only or
  single-range image cannot satisfy it). Node run by me now: **1 passed** (byte-equality with the
  pinned capture).
- **Evidence artifacts** — all 15 cited files re-hashed by me: **15/15 match** the packet's
  recorded digests (incl. the sidecar's own digest `c00f0c19…` and the retained first-run
  transcript `7356482a…`). `.gitattributes` `-text` line for this batch's evidence is itself
  declared in the packet. The §5.2 data `evidence/baseline-failing-set.txt` is untouched: 44 ids,
  `a16` at line 18 exactly as cited, mtime 2026-10-12 07:04 — **predates every increment
  transcript** (10:08–10:38); tc024 is not in the union, a16 is.
- **Scope discipline (reverse trace)** — `git diff 410cde5 --name-only` over the product tree =
  exactly the 8 modified + 1 deleted + `s19_app/render/` (new), every one listed in §2 with
  ≥1 Traces-to id. Inc-B set (`utils.py`, `insight_style.py`, `validation_service.py`,
  `checks_view.py`, `issues_view.py`, app.py `safe_text` block): **0 entries**. Frozen set
  (`color_policy.py`, `range_index.py`, `core.py`, `hexfile.py`, `validation/`, `a2l.py`,
  `mac.py`): **0 entries**. C1 waiver restated in §2 ✓. Observation (LOW, not a defect): flow
  bookkeeping also sits in the uncommitted diff outside §2's table — `AT-TC-REGISTRY.jsonl`
  (TC-651…655/AT-288…291 reservations), `.gitattributes` (evidence `-text`), `docs/architecture.md`
  (attributed "Amended at DOC" batch-92 amendment), `.dev-flow/state.json` + `_derived/ATLAS-*` —
  all orchestration-managed, none implementation scope; suggest listing them at close for
  completeness.
- **tc024 characterization** — ran standalone 8× on the Inc-A tree: **8/8 passed** (packet's own
  loop saw 2 flips under load, then 8/8 interleaved). The failure mechanism is the worker-thread
  race the test's own comment admits (batch-68 N5: status written after the handler returns); it
  monkeypatches `app_mod.generate_diff_report` / `compare_images` **by name** — identical objects
  at both addresses, untouched by this diff (app.py's diff-service import line is not one of the
  repointed lines). **No causal path from the move; pre-existing load-sensitive flake.**
  Disposition per §5.2 rule (1): tc024 sits OUTSIDE the 44-id union, so a flip reads as
  functionality loss at a gate — recommend the orchestrator add it to the flaky registry / pinned
  union at close (as §5 already requests). Gate question, not an increment defect.

**Findings (severity-graded)**

- F1 [LOW] — unused imports retained in `s19_app/render/hexview.py` (`RangeIndex` + the 3 aliased
  range primitives) — declared in §5 and forced by LLR-001.1's byte-identity threshold; cleanup at
  close/next batch. No action for this gate.
- F2 [LOW] — `test_tc023_app_does_not_import_private_hexview_helpers` now matches nothing
  (vacuous pass) — declared in §5; the protecting conclusion rides on TC-651/TC-652; suggest the
  follow-up census-string extension at close.
- F3 [LOW] — §2 does not list the flow-bookkeeping files in the diff (registry, `.gitattributes`,
  `docs/architecture.md`, `.dev-flow/state.json`, `_derived/ATLAS-*`) — none is implementation
  scope; record them at close for reverse-trace completeness.
- F4 [LOW — orchestrator ruling owed] — tc024 load-sensitive flake: pre-existing, not diff-caused
  (evidence above); recommend flaky-registry/pinned-union addition at close.

Every finding and check above is state `executed` (reviewer-run in the worktree); none is
`planned` or `not-run`. Verdict token: **OK to advance**.

---

## 5 · Risks

- **`test_tui_diff_screen.py::test_tc024_report_trigger_invalid_dest_refused` is load-sensitive flaky
  on this machine** (outside the 44-id pinned union). Evidence: it failed once in the first repointed-files
  run (`increment-001-repointed-files.transcript`) and twice in a tight standalone loop on the Inc-A tree,
  then passed 8/8 in interleaved A/B rounds; at the base worktree (`/tmp` probe worktree at `410cde5`) it
  passed 5/5 standalone, 8/8 interleaved, and in the full 8-file rerun — but the FIRST base 8-file run also
  showed 2 failures (a16 + one other, its FAILED line lost to a `tail -2` slip; a16 is union-pinned and the
  only other candidate is this node). Failure mode is the worker-thread race the test's own comment admits
  ("the status is written after this handler returns… a race this suite must not depend on"); the assertion
  reads a stale `#diff_status` ("Compared A.s19 vs B.s19: 1 runs." instead of "bad destination"). No causal
  mechanism to the repoint exists (the test monkeypatches `app_mod.generate_diff_report` by name; the
  symbol is the identical object at both addresses). **Disposition: recorded as a pre-existing load-sensitive
  flake; recommend the orchestrator add it to the flaky registry / pinned union at close.** This is the one
  gate question this increment leaves open.
- **Unused import kept by charter**: `s19_app/render/hexview.py` still imports `RangeIndex` and the three
  aliased range primitives from `..range_index` — they are now unused after the wrapper deletion, but
  LLR-001.1's byte-identity threshold ("base minus wrappers minus import block") names exactly two
  permitted deviations, so the bytes stay. Cleanup candidate for a later batch (or the close station).
- **TC-023 census now vacuous**: `tests/test_tui_hexview.py:345`
  (`test_tc023_app_does_not_import_private_hexview_helpers`) matches modules ending in `tui.hexview`;
  post-move `app.py` imports `s19_app.render.hexview`, so the guard passes vacuously. The protecting
  conclusion now rides on TC-651 (app.py ∈ measured consumer set, reading the render address) and TC-652
  (renderer surface identical objects). Declared as load-bearing emptiness above; a follow-up may extend
  the census string to the render address.
- **C4 stale text**: `range_index.py:29,60,94` docstrings still name `s19_app.tui.hexview` (frozen file).
  Routed to BACKLOG-CODE lane A at close per the design's C4 disposition.
- **Cross-cutting**: `render/format.py`'s `insight_style` shim relation and the service/view repoints land
  in Inc-B (design §4: the render surfaces freeze at this gate; Inc-B must not touch them).

---

## 6 · Pending items / spec deviations

- §5 item 1 (tc024 flaky flip) — awaiting the orchestrator's ruling for the flaky registry.
- §5 items 2-4 (unused import, TC-023 vacuity, C4 text) — backlog candidates at close.
- No deviations from the chartered LLR texts; the AT-288 driveable set follows QA-PDR-1 exactly
  (row_bases window across ≥2 disjoint fixture ranges + non-default `context_bytes`; the focus/highlight
  parameters are not driveable through the report surface, verified at the PDR).

---

## 7 · Suggested next task

**Inc-B (US-92-3 + US-92-4)**: `safe_text` + `_CONTROL_SCRUB` → `s19_app/utils.py`; the 8-symbol
`insight_style` re-export shim (identical objects); `validation_service.py:17` → `s19_app.render.format`;
`app.py` `safe_text` block + `checks_view.py:41` / `issues_view.py:40` repoints; TC-653/TC-654 minting;
AT-289/AT-290/AT-291 evidence. Inc-B must NOT touch `render/hexview.py` or `render/format.py` (frozen
at this gate per design §4).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ⚠ | 11 source files (3 new + 8 modified − 1 deleted) — >4 waiver per PDR condition C1, restated in §2; repoint-only increment over the measured closed set |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_render_hexview.py` (TC-651/652), `tests/test_render_format.py` (TC-655), AT-288 node in `tests/test_report_service.py` — 3 passed transcript |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | TC-655 (`tests/test_render_format.py`, unit pin; clamp arms microbar cyclomatic ≥3) 1 passed |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 RED row: TC-651 census reddened by one flipped consumer; transcript `increment-001-tc651-red.transcript`; restore digest `94003d51a83ffb955273f4203dfc42f330f8aa4bff162f75e124051c21f9d48c` |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 Reverse census: 5 probes (B1 14+8 files · B2 0 live readers · B3 0 goldens · B4 measured-set consumers · A3 closed set) |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ⚠ | §4b intentionally left EMPTY for the orchestrator's reviewer (per the increment brief) |
| 7 | No file from another lane touched | all | ✓ | `git diff 410cde5 --name-only` shows only Inc-A set files; Inc-B set (`utils.py`, `insight_style.py`, `validation_service.py`, `checks_view.py`, `issues_view.py`, app.py safe_text block) → 0 entries |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `git diff 410cde5 --name-only -- s19_app/tui/color_policy.py s19_app/range_index.py s19_app/core.py s19_app/hexfile.py s19_app/validation/ s19_app/tui/a2l.py s19_app/tui/mac.py` → 0; TC-027 + TC-031 pair + TC-032 all pass |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | every §4 figure names its stored transcript under `evidence/` with SHA-256 of the stored bytes |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 Load-bearing emptiness: 3 absence claims, synthetic instances + positive controls named |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 Mutation verdicts: 4 arms, all KILLED, per-node verdicts, restore digests, no inert arms |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 Instrument RED-proof: 5 instruments each fed a mechanism corruption (or the known-present base body) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 Correction population: 3 corrections (product imports, test imports 3 forms, C4 text) enumerated before editing |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 Emitted-form assertion: 2 artifacts (report bytes via `read_bytes()`; moved body via SHA-256) |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ⚠ | §4b empty by the orchestrator's instruction — the reviewer fills it at the gate |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 Evidence files: 15 artifacts + the retained first-run transcript, each with the digest of its stored bytes |

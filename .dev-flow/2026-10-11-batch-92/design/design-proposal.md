# Design proposal — s19_app — Batch 2026-10-11-batch-92

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language
> The normative rules below are language-independent. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Design proposal` · `7 · Forward-applicability table` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **Why a HEADING is reserved here and a FIELD NAME everywhere else:** `C-49`'s artifact is the §7 TABLE, and a rule that read a summary bullet instead of the rows would be reading a claim about the table rather than the table. `V52` therefore keys on this document's own H1 and on the §7 heading, which is why both are on the machine plane. **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`.

> **Owed in.** `core` by trigger · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

> **Where this lives: the VAULT + Drive**, not the repo — it is deliberation, and its traceability to
> code is weak. It is **cited by id** from the repo (`PDR-<batch_id>#D<n>`), never copied.
> What binds code — a frozen interface, a design characteristic — also lands in the **repo**, in the
> requirement or in `docs/ARCHITECTURE.md`. *The vault keeps the deliberation; the repo keeps the commitment.*

> **The forward-applicability rule (ISO/IEC/IEEE 15288).** Everything below must be NAMED as the input
> of a later activity. **If a section of this proposal is nobody's input, delete it — it does not belong
> in the PDR.** That rule is what allows this document to cost half the batch without being waste.

| Field | Value |
|---|---|
| Id | `PDR-2026-10-11-batch-92` — cited as `PDR-2026-10-11-batch-92#D1…#D7` from `01-requirements.md` §3/§4 and at the post-gate `docs/ARCHITECTURE.md` amendment |
| Requirements covered | `HLR-001 v1 · HLR-002 v1 · HLR-003 v1 · HLR-004 v1` (`01-requirements.md` §3; stories US-92-1…US-92-4) |
| Modules touched (from `docs/ARCHITECTURE.md`) | `product` (`s19_app/**` — NEW `render/` sub-package at file granularity: `render/__init__.py`, `render/hexview.py`, `render/format.py`; changed `utils.py`, `tui/insight_style.py`, `tui/screens_directionb.py`, `tui/app.py`, `tui/__init__.py`, `tui/screens.py`, `tui/checks_view.py`, `tui/issues_view.py`, `tui/services/{load,report,diff_report,validation}_service.py`; RETIRED `tui/hexview.py`) · `tests` (repoints + 2 new census files) · `flow` (this record) |
| Triggers that fired | `A1 · A2 · A3 · B1 · B2 · B3 · C8 · E1` (`state.json` triggers block, evaluated 2026-10-11) |
| Author / reviewers | `architect` · `qa-reviewer` (D1/D2 did not fire — no `ux-reviewer` owed) |

---

## 1 · Objective and scope

**Objective.** Hand Phase 3 the complete, P2-de-risked design for the behavior-preserving relocation
chartered by `01-requirements.md`: the pure hex renderer and the presentation-neutral formatting
primitives move out of `tui/` into `s19_app/render/`, the markup-safety primitive moves to
`s19_app/utils.py`, and every measured consumer is repointed — killing the four densest
service→presentation import inversions of the 2026-10-11 dependency radiography with zero
runtime-behavior change. This design is the C1-(c) amendment ratified at the P1 gate
(review `02-review.md`; closure `review-closure-code.md` — C1/C2/C3 closed by executed scratch-tree
simulation), bound as `PDR-2026-10-11-batch-92#D1…#D7`.

**Design characteristics (consumed by the Phase-3 increments):**

- **#D1 (map R1) — byte-preserving whole-file move.** `s19_app/render/hexview.py` is the base
  `s19_app/tui/hexview.py` (477 LOC, 0 classes) byte-identical except (a) the 3 `range_index`
  re-export wrappers deleted (base `:61-141`, AST-verified contiguous block) and (b) the
  style-constant import block rewritten. The integrity threshold is **base minus wrappers minus
  import block** — the hash comparison Phase 3 records in the increment packet is defined over
  exactly that body (review C2 closure: the sim body is byte-identical under this definition).
- **#D2 (map R2) — `render/` is a package, inside `product`.** New `render/__init__.py` marker,
  empty of logic (owned by Inc-A). One boundary rule stated at directory level: pure Rich,
  no Textual, service-consumable.
- **#D3 (map R3, amended) — `render/format.py` owns the constants; the moved file's import block
  rewrites verbatim.** `s19_app/render/format.py` — created in **Inc-A** (closure finding N1,
  LED-…92.12: amended LLR-001.1 makes Inc-A's moved file import it, so a literal Inc-B scoping
  fails Inc-A's own gate) — takes canonical ownership of the 8 moved symbols: `microbar`,
  `MICROBAR_FILLED = "█"`, `MICROBAR_EMPTY = "░"`, `GREEN = "#54efae"`, `LABEL = "#c5c7d2"`,
  `VALUE = "#e9e9e9"`, `CYAN = "#7dd3fc"`, `DGRAY = "#969aad"`, and DEFINES
  `FOCUS_HIGHLIGHT_STYLE = "bold yellow"` / `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"`
  value-equal to the frozen `tui/color_policy.py:13-14`, pinned by **TC-655**. The moved file's
  import block rewrites to exactly this one line (replacing base `tui/hexview.py:16-17`):

  ```python
  from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE
  ```
- **Tui-free render rule.** `render/*` carries **zero `s19_app.tui.*` imports** — both
  `render→tui` style-constant residual edges are killed this batch (map §6.1, rows 1–2). The C1
  partial-module cycle root is dead by design, not by import-order luck: cold render-first entries,
  tui-first entries, service entries, and pytest collection through a no-tui conftest all succeed
  in the executed sim (closure probes P1–P6; `'s19_app.tui' in sys.modules` = False after cold
  `import s19_app.render.format`).
- **#D4 (map R4) — the `insight_style` re-export shim (8 symbols).** `tui/insight_style.py`
  re-exports exactly `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`,
  `CYAN`, `DGRAY` from `render/format` as the identical objects; the 7 measured view consumers
  (`app.py:85`, `checks_view.py:40`, `issues_view.py:39`, `crc_designer_view.py:81`,
  `json_highlight.py:82`, `screens_directionb.py:90`) stay untouched — 0 snapshot risk. The 2
  `color_policy` style strings are NOT shimmed: tui keeps sourcing them from `color_policy`;
  only `render/format` carries the pinned copies. Consumer rule: services use `render/format`,
  never `tui.insight_style` — the shim is permanent by declaration, not an edge to "fix".
- **#D5 (map R5) — `microbar` moves with its glyphs as one unit** (its contract includes the
  `MICROBAR_*` pair; no third module).
- **#D6/#D7 (map R6/R7) — `utils.safe_text` + private `_CONTROL_SCRUB`.** `s19_app/utils.py` gains
  `safe_text(value, style="")` (base `screens_directionb.py:881-936`) and its single-use private
  table `_CONTROL_SCRUB` (base `:878`; C0 `0x00-0x1F` + DEL `0x7F` + C1 `0x80-0x9F` = 65
  codepoints), moved verbatim; `screens_directionb.py` becomes a consumer (~96 internal call sites
  become imports of `..utils`). Root-`utils` is the address with zero layer meaning: a future
  non-render consumer must not drag presentation deps in.
- **Measured repoint sets per LLR** (authoritative over story text — module-map §5/§7.2 finding F-2):
  hexview consumers = `tui/app.py:37-42`, `tui/__init__.py:17-31`, `tui/screens.py:34`,
  `tui/screens_directionb.py:3336,7581`, `services/{load,report,diff_report}_service.py:8/:58/:96`;
  `safe_text` consumers = `app.py:79`, `checks_view.py:41`, `issues_view.py:40` (+ the
  screens_directionb internals); `insight_style`-kin consumer repoint = `validation_service.py:17`;
  test-side old-address importers = 8 files in 3 import forms (LED-…92.7).

**Will NOT do:** US-92-5 (`css_class_for_severity` stays in frozen `tui/color_policy.py` — the
`change_service → color_policy` edge survives as a declared residual); US-92-6 (satisfied
externally at `b167828`); any behavior change, restyling, or edit to the frozen engine set
(`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`,
`tui/color_policy.py`); the `app.py` split (next batch, already planned).

**Enablers (consumed by Phase 3 and validation):**

- **Reused fixtures (existing):** `large_s19` at `tests/conftest.py:302` — the synthetic
  200-range × 4 KB S19 built by `make_large_s19` (`tests/conftest.py:71`); the hostile-input
  fixtures/table of `tests/test_tui_hostile_map.py` (batch-77 oracle, 65-codepoint class
  re-derived in-test, plus the executed RED mutation transcript at `:259`).
- **NEW — the pinned pre-move capture for AT-288** (sole byte-identity oracle, F-QA-3). Production
  protocol inside **Inc-A, BEFORE any repoint edit lands**: (1) author the AT-288 node
  `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` and run it
  against the **base** tree — the report service end-to-end over `large_s19`, driving
  **non-default parameters through the surface** per F-QA-5 as re-chartered by PDR condition
  QA-PDR-1 (LED-…92.13): a `row_bases` window spanning ≥2 disjoint fixture ranges and a non-default
  `context_bytes` — the focus/highlight/mac-highlight trio is NOT driveable through the report
  surface (`report_service.py:590`, verified at the PDR), so the oracle exercises the moved
  functions (`build_row_bases` / `build_mem_map_s19` / `render_hex_view`) instead
  (a default-only image is not acceptable evidence); (2) store the emitted report
  bytes and their content hash under `.dev-flow/2026-10-11-batch-92/evidence/` (convention:
  `at288-pre-move-report.bin` + `at288-pre-move-report.sha256`); (3) then implement the move;
  (4) at the gate, re-run AT-288 against the moved tree and assert byte-equality with the pinned
  capture.
- **The scratch-simulation methodology as de-risking precedent** (`review-lens-code.md`,
  `review-closure-code.md`): AST-anchored transforms of the exact LLR repoint texts, fresh-
  interpreter cold-entry probes, `s19_app.__file__` printed to prove which tree answered. The P2
  sims were deleted with their scratch trees by design; Phase 3's own diff IS the re-run, and the
  same probe discipline (cold entries + tree proofs) applies to the increment gates.

## 2 · Modules and boundaries

| Module | What it owns here | What it exposes | What it must NOT reach into |
|---|---|---|---|
| NEW `s19_app/render/__init__.py` | package marker, empty of logic (Inc-A) | nothing | — |
| NEW `s19_app/render/hexview.py` (#D1) | the pure hex-window renderer: 7 fns (`render_hex_view` `:330`, `render_hex_view_text` `:360`, `build_mem_map_s19` `:144`, `build_range_validity_s19` `:153`, `build_range_validity_hex` `:173`, `build_row_bases` `:179`, `find_string_in_mem` `:187`) + 5 layout constants (`HEX_WIDTH=16`, `MAX_HEX_ROWS=512`, `MAX_HEX_BYTES=65536`, `FOCUS_CONTEXT_ROWS=64`, `SEARCH_ENCODING="ascii"`, base `:20-24`) | the 9-name surface, imported directly from `s19_app.render.hexview`; no re-export chain via `tui/__init__` | any `s19_app.tui.*` symbol (tui-free render rule); `textual`; `s19_app.validation`; `tui/services/*` |
| NEW `s19_app/render/format.py` (#D3–#D5) | `microbar` + glyphs + `GREEN/LABEL/VALUE/CYAN/DGRAY` + the 2 pinned style strings (created Inc-A, N1) | 11 symbols; new service consumers MUST import from here, never `tui.insight_style` | `s19_app.tui.*`, `textual`, engine, services |
| CHANGED `s19_app/utils.py` (#D6/#D7) | gains `safe_text` + `_CONTROL_SCRUB` (security primitive, C-17) | `safe_text(value, style="") -> Text` — the canonical markup-/control-safety primitive | `s19_app.tui.*`, `textual`; no screen/widget logic |
| CHANGED `tui/insight_style.py` (#D4) | keeps palette + view-side helpers (`human_bytes`, `label_value`, `threshold_style`, `cap_gauge_style`); gains the 8-symbol re-export shim | the shim as identical objects; ownership of everything else | engine internals beyond existing use |
| CHANGED `tui/screens_directionb.py` | loses `safe_text`/`_CONTROL_SCRUB` (→ `..utils`); 2 lazy hexview imports repointed | Direction-B screen shell (unchanged ownership) | engine primitives (already imports `range_index` directly, `:107`) |
| CHANGED `tui/app.py`, `tui/__init__.py`, `tui/screens.py` | repoint-only: hexview block → `render.hexview`; wrappers → engine; `__init__` drops 3 wrapper names, keeps 12 renderer names (N2) | `tui.__all__` renderer surface 12/12 | — |
| CHANGED `tui/checks_view.py`, `tui/issues_view.py` | `safe_text` import → `..utils` (repaint-free) | unchanged view surfaces | `screens_directionb` (the killed edge) |
| CHANGED `services/{load,report,diff_report,validation}_service.py` | 3 hexview repoints + `validation_service.py:17` → `render.format` | unchanged service contracts | `tui.insight_style` / `tui` hexview addresses |
| RETIRED `s19_app/tui/hexview.py` | deleted by Inc-A | nothing | declared so no reader mistakes it for drift |

- Boundaries respected as declared in `docs/ARCHITECTURE.md`: ✓ — `render/` is declared at
  sub-module (file) granularity **inside `product`**, not as a 7th top-level module (map §6.3:
  overlapping prefixes are a defect of the document; the staleness checker's
  `startswith(prefix + "/")` rule cannot express a hole in `s19_app/**`). The frozen set is
  respected: **`tui/color_policy.py` receives no edit — it is pinned instead** (`render/format`
  DEFINES value-equal copies, TC-655 asserts the equality; `color_policy` stays canonical-for-tui).
  No module boundary moves this batch — nothing returns to the trunk as trigger A3.

**Controls applying to Phase 3:**

- **C-17** (markup-safety) is discharged *via the `safe_text` move itself*: the primitive's
  contract travels verbatim — every C0/DEL/C1 codepoint deleted by the single `_CONTROL_SCRUB`
  table, remainder wrapped as literal `Text`, never `Text.from_markup` (base `:869-877` contract;
  P2 security closure: 24 `from_markup` mentions in `s19_app/`, all docstrings/comments, 0 call
  sites). The hostile-input oracle is repointed, not weakened; the executed RED counterfactual
  (`safe_text → Text.from_markup` reddens `test_b77_hostile_symbol_is_literal_and_carries_no_span`,
  `tests/test_tui_hostile_map.py:259`) is re-run at the new address in Phase 3.
- **C-19** (one complete run): every increment gate = ONE complete run of the FULL
  `tests/test_tui_directionb.py` guard host (~3 min, C-34 render-increment rule) + the affected
  repointed files + the dual-guard below; evidence (exit code, tail) read from that run's own
  output, never stitched across partial runs. Batch acceptance = the one complete 2765-test suite
  run under the §5.2 gate rule.
- **C-27** (frozen dual-guard — run BOTH guards, a single-guard check is incomplete). Both guards
  exist on disk and are named for the increment gates: **SOURCE guard**
  `tests/test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` (TC-027); **TEST-file
  guard** `tests/test_tui_directionb.py::test_tc032_engine_test_files_unmodified_vs_main` (TC-032,
  `_ENGINE_TEST_FILES` includes `tests/test_color_policy_round_trip.py`).
  ⚠ **FLAG for reviewers:** TC-027's own `_ENGINE_PATHS` omits `tui/color_policy.py` — the
  batch-premise freeze of `color_policy` is mechanically guarded only by the TC-031 pair in the
  guard host (`test_tc031_engine_modules_have_no_diff_vs_main` /
  `test_tc031_engine_modules_have_no_name_only_diff_vs_main`, whose `_ENGINE_PATHS` DOES include
  `s19_app/tui/color_policy.py` at `tests/test_tui_directionb.py:6132`, plus
  `test_tc031_engine_imports_still_resolve`). The freeze's coverage therefore rests on the
  full-guard-host run that §5.2 already mandates — a TC-027-only frozen check is INCOMPLETE for
  this batch. (Map finding F-1: the standing doc's §7 list omits `color_policy` too — the post-gate
  doc amendment adds it; the guard gap itself is a backlog candidate.)

## 3 · Diagrams

n/a for the runtime viewpoints — this batch moves import edges, no runtime flow
(module-map §9, same ruling). The structural viewpoint Phase 3 consumes is the edge inventory
(map §2):

- **Edges killed (6 of 7 measured at intake):** `services/{load,report,diff_report}_service →
  tui/hexview` · `services/validation_service → tui/insight_style` · `tui/app → tui/hexview`
  (range_index indirection) · `tui/__init__ → tui/hexview` (wrapper chain) ·
  `checks_view/issues_view → screens_directionb` (the `safe_text` edge).
- **Residuals killed this batch by the review amendment (C1-(c)/C2):** `render/hexview →
  tui/color_policy` and `render/hexview → tui/insight_style` — zero `s19_app.tui.*` imports in
  `render/*`.
- **New edges (allowed, declared):** `services/* → render.hexview` · `services/validation_service →
  render.format` · `views → render.hexview`/`render.format` · `insight_style → render/format`
  (shim, R4 — presentation consuming presentation-neutral is the permitted direction) · any layer →
  `utils.safe_text`.
- **Declared surviving residual:** `services/change_service → tui/color_policy`
  (`css_class_for_severity`, US-92-5 OUT).

## 4 · Interfaces that change — and which ones FREEZE

| Interface | Current | After | Consumers | **Frozen for the fork?** |
|---|---|---|---|---|
| `s19_app.render.hexview` (7 fns + 5 constants, base `tui/hexview.py:27-360` + `:20-24`) | does not exist | new module: base content minus wrappers minus import block | `screens_directionb:3336,7581`, `screens.py:34`, `app.py:37-42`, `tui/__init__.py`, 3 report services, tests | **YES — FROZEN at PDR once Inc-A lands; Inc-B must not touch it** |
| `s19_app.render.format` (`microbar`, `MICROBAR_*`, `GREEN/LABEL/VALUE/CYAN/DGRAY`, `FOCUS_HIGHLIGHT_STYLE`, `MAC_ADDRESS_OVERLAY_STYLE`) | does not exist | new module (Inc-A, N1) | `validation_service.py:17`, `insight_style` shim, `render/hexview` | **YES — FROZEN at PDR once Inc-A lands; Inc-B must not touch it** |
| `s19_app.utils.safe_text` (+ `_CONTROL_SCRUB`) | `screens_directionb.py:878-936` | same contract at `utils.py`; old address retires | `app.py:79`, `checks_view.py:41`, `issues_view.py:40`, `screens_directionb` internals | Contract frozen (signature + behavior, C-17); the address change is Inc-B's whole job |
| `s19_app.tui` namespace (`__init__.py:17-31`, `:81-95`) | hexview block + 3 wrappers in import/`__all__` (`:28`, `:87`) | 12 renderer names re-exported from `render.hexview`; 3 wrapper names gone (breaking-by-design, US-92-2; consumer set closed, map §5) | every tui consumer | engine `range_index` stays frozen — untouched |
| `tui.insight_style` palette surface | owns all 8 moved symbols | shim re-export of the 8 (identical objects); canonical ownership of the rest | 7 view consumers (`app.py:85`, `checks_view.py:40`, `issues_view.py:39`, `crc_designer_view.py:81`, `json_highlight.py:82`, `screens_directionb.py:90`) | view surface frozen by R4 — untouched (0 snapshot risk) |
| `s19_app.tui.hexview` | 477-LOC module | **DELETED** (Inc-A) | none | retired path — TC-651 asserts its absence |
| `s19_app.range_index` (engine `:9-79`) | sole definition site of the 3 primitives | unchanged | direct consumers (`app.py`, tests) | already frozen — untouched |

**A frozen interface is not touched inside a lane.** If a lane needs to change one, the work returns to
the trunk — that is trigger **A3**. Between the two sequential increments the frozen-interface rule
binds Inc-B: the `render.hexview` and `render.format` surfaces are frozen once Inc-A lands, and
Inc-B (which owns `utils`, the shim, and the service/view repoints) must not touch them.

## 5 · Proposed test cases

| Id | Layer (0 unit / A white / B black / UX) | What it asserts | **The mutation that would turn it RED** |
|---|---|---|---|
| TC-651 | A (integration) — `tests/test_render_hexview.py`, minted Phase 3 | AST import-census over `s19_app/` **derived from the live tree at run time** (`ast.parse`, all aliased/plain forms), asserting set-equality against the declared measured set: all 8 hexview consumers read `s19_app.render.hexview`; zero `s19_app.tui.*` hexview imports; grep census over `tui/services/*.py` → 0 hits at a tui address; `s19_app/tui/hexview.py` absent from disk | Restore `s19_app/tui/hexview.py`, or point any one consumer back at `s19_app.tui.hexview` — the census goes red by construction. Pre-state executed 2026-10-12: `python -c "import s19_app.tui.hexview"` succeeds; 8 consumer sites at the old address (C3-corrected census covers the 8 test files in 3 import forms) |
| TC-652 | 0/A — `tests/test_render_hexview.py`, minted Phase 3 | The 3 wrapper names absent from `s19_app.render.hexview`, from the `s19_app.tui` import surface and `__all__`; renderer names present 12/12 (N2-measured surviving surface); `app.py` shows `s19_app.range_index` + `s19_app.render.hexview` edges and no `.hexview` edge | Leave one wrapper line in `tui/__init__.py` (import `:28` or `__all__` `:87`) — the positive-absence assertions fire. Pre-state grep executed; the deletion itself is the reddening inverse |
| TC-653 | A (integration) — `tests/test_tui_hostile_map.py -k tc653`, minted Phase 3 | AST census: `safe_text` and `_CONTROL_SCRUB` defined **only** at `s19_app/utils.py` (exactly 1 definition site each); `screens_directionb.py` defines neither; `app.py:79`, `checks_view.py:41`, `issues_view.py:40` import from `..utils`; importer set-equality derived from the live tree | Any view left importing `safe_text` from `screens_directionb` (the killed edge restored). Pre-state executed: `checks_view.py:41`, `issues_view.py:40` carry the old import today |
| TC-654 | A (integration) — `tests/test_render_format.py`, minted Phase 3 | Identity + census: `insight_style.X is render.format.X` for all 8 shimmed symbols; `MICROBAR_EMPTY == "░"` (closes the snapshot-only pin of §6.3); palette values at the new address; `validation_service.py:17` imports from `s19_app.render.format`; zero `insight_style` imports across `tui/services/*`; AST-derived service-layer set-equality (a post-radiography consumer fails the test instead of passing silently through the shim — F-QA-2) | Repoint `validation_service` back to `..insight_style`, or redefine/drift a glyph or palette value at the new address — the identity/value assertions fire. Pre-state executed: the old edge sits at `:17` |
| TC-655 | 0 (unit) — `tests/test_render_format.py -k tc655`, minted Phase 3 | Equality pin of the pinned copies: `render.format.FOCUS_HIGHLIGHT_STYLE == s19_app.tui.color_policy.FOCUS_HIGHLIGHT_STYLE` ("bold yellow") and the MAC-overlay pair ("bold orange3"); `CYAN`/`DGRAY` equal their frozen tui origins — drift fails a test by construction (the freeze is respected *and* enforced) | Restyle `tui/color_policy.py` without updating the pinned copy (or drift the copies) — the cross-module equality assertion fires. This is the guard that makes the pinned-copy design drift-impossible |

**Declared here, at authoring time, not at execution time.** A proposed case whose reddening mutation
cannot be named is not yet a test case — it is a hope. Layer 0 applies where the unit has cyclomatic
complexity ≥3 **or** transforms data crossing a declared module boundary.

**Repointed existing nodes per LLR** (existing on-disk coverage; imports repointed at Phase 3, behavior
untouched — the full named lists live in `01-requirements.md` §4 verification lines):

| LLR | Nodes carrying it | Repoint |
|---|---|---|
| LLR-001.2 | 12 renderer behavior nodes across `test_tui_hexview.py` / `test_tui_helpers.py` / `test_tui_hexview_classed.py` (mem maps, range validity, row bases, focus context, truncation, MAC-overlay rows, string search) | module import → `s19_app.render.hexview` |
| LLR-001.3 | 5 `test_tc_023_*` constant nodes + `test_tui_public_api_exports_main_helpers_and_constants` (pins `tui.__all__` renderer surface, `issubset` — deletion-safe for the wrappers) | imports → `render.hexview`; public-API test unchanged |
| LLR-001.4 | TC-651 + 8 test files in 3 import forms (LED-…92.7) + `test_report_service.py:595` source-census expected string (`"from ..hexview import"` → new text) | per file, 3 forms |
| LLR-002.1 | 6 wrapper behavior nodes `tests/test_tui_hexview.py:83-119` | import → `s19_app.range_index`; `test_range_index.py` untouched |
| LLR-003.x | 3 direct test importers: `test_tui_hostile_map.py:83` (module), `test_a2l_multiline_headers.py:360` (local), `test_tui_directionb.py:3225` (local); hostile behavioral nodes unchanged | → `s19_app.utils` / consumer modules |
| LLR-004.x | `test_microbar*` + `test_palette_constants_present_and_correct` (stay shim-imported — no repoint); AT-291 strip nodes `test_at071_strip`, `test_build_mac_coverage_strip_counts`, `test_zero_total_no_divzero` | none needed (R4) |

**Layer-B acceptance nodes** (named for completeness; chartered in `01-requirements.md` §3): AT-288
(new node + the pinned pre-move capture enabler of §1) · AT-289
(`test_range_index.py::test_at289_tui_namespace_drops_range_index_wrappers`, executable today as an
import probe) · AT-290 (existing hostile nodes `test_c17_seed_hostile_linkage_and_reason_render_literal`,
`test_at082f_hostile_issue_tokens_render_literal`) · AT-291 (the 3 strip nodes above).

**The gate rule (flaky-tolerant — the §5.2 reference Phase 3 and DDR apply):** the pinned reference is
the **44-node union** at `evidence/baseline-failing-set.txt` (29 `test_tc016s_density_layout_snapshot[...]`
cells + 15 known-unstable nodes; union of two executed full-suite baselines on identical code,
2026-10-12; per-run ids in `baseline-run2-ids.txt` / `baseline-run3-ids.txt`). (1) every node OUTSIDE
the union must PASS at the gate — a stable-passing node flipping to failure is functionality loss and
fails the gate; (2) nodes INSIDE the union may pass or fail (recorded, not counted); (3) TC-651..TC-655
and every repointed functional TC must pass; (4) for the TUI snapshot family this rule IS the
byte-identity criterion and AT-288 is the sole byte-identity oracle. **Never a count comparison.**

## 6 · Risks and rejected alternatives

**Known MINOR carry-forwards (and where each is discharged):**

| Item | Disposition / where discharged |
|---|---|
| C4 — stale `s19_app.tui.hexview` path references in frozen files (`range_index.py:29,60,94` docstrings, `test_tui_workspace_layout.py:37` comment, `diff_report_service.py:35` docstring) | Frozen files cannot be edited this batch → routed to **BACKLOG-CODE.md lane A at close** (P5/P6 close station); named in the TC-651 census note so the drift does not read as a surprise |
| C5 — importing any `tui.services.*` module drags the full TUI package at import time (`s19_app.tui.app` in `sys.modules` = True, at base and identically post-sim) | Informational, no action; recorded at `01-requirements.md` §6.3 and here so the gate is not surprised — the batch's neutrality is address-deep only, no regression vs today |
| Contract-budget NOTICE — the standing ≤5-product-files increment convention vs the measured repoint sets (Inc-A: 8 product + 2 new − 1 deleted; Inc-B: 8); the module map's own Exit-1 text repeats the cap while its §8 touch list exceeds it | Recorded as a gate question in `01-requirements.md` §6.3 — **discharge point: the operator ruling at the PDR gate** (waive the cap for repoint-only increments, or re-cut). ⚠ Still OPEN at authoring time; Phase 3 must not start before the ruling is on the record |

| Alternative considered | Why it was rejected |
|---|---|
| R1: gradual copy-and-repoint, old module left as a shim | A shim keeps the `tui.hexview` import address alive — exactly the inverted edge US-92-1 kills; 11 test files already pin the new address; behavior-preservation forbids a coexistence window (second source of truth, zero benefit). Re-open: none expected — the consumer set is closed and measured |
| R2: flat `s19_app/hexview.py` + `s19_app/format.py` | The two modules share one boundary rule; a package states it once at directory level and leaves room for the next renderer without another ARQ cycle (map §6.3 records the checker-expressiveness flow input) |
| R3 (pre-amendment): keep the `render→tui` constant edges as declared data residuals | **Executed failure of both arms** (P2 code lens): render-first cold entries raise the partial-module `ImportError` (C1), and literal "byte-identical minus wrappers" compliance breaks the module (`ModuleNotFoundError: s19_app.render.color_policy` — C2). Disposition C1-(a) (tui-initializing first import per test module) and C1-(b) (module-level tui import in `tests/conftest.py`) were rejected in favor of **C1-(c)**: kill the cycle root — the only option protecting every future render-first consumer; respects the `color_policy` freeze via TC-655-pinned copies instead of edits |
| R4: full repoint of all 7 view consumers to `render.format` | Violates the ≤5-file increment budget and adds snapshot risk for cosmetic gain; the shim repoints exactly one service edge while the view surface is untouched. The asymmetry with US-92-2 (engine re-exports die, presentation shim stays) is deliberate and declared (consumer rule written in map §1.2) |
| R5: split constants into a third module | `microbar`'s contract includes the glyph pair; splitting creates a dependency between two tiny modules to save nothing — one module, one boundary rule |
| R6: `safe_text` in `render/format.py` | `safe_text` is a safety primitive (C-17/B-1), not a formatter: `checks_view`/`issues_view` consume it as a security sink, and a future non-render consumer must not drag presentation deps in. Root `utils` is the address with zero layer meaning |
| R7: leave `_CONTROL_SCRUB` in `screens_directionb` as an import | The table is `safe_text`'s single-use private dependency; a cross-module constant import recreates the very `screens_directionb`-coupling US-92-3 removes |
| §5 Exit-2: trunk pre-commit (or an ARQ boundary move) to force parallel lanes | The intersection is two single files edited at disjoint line ranges; no module split makes the file sets disjoint short of splitting `app.py` itself — forbidden by the behavior-preserving acceptance. Recorded as a legitimate re-cut variant if the operator wants concurrency; sequential Inc-A → Inc-B recommended and adopted (zero merge surface, no third review packet) |

Remaining open risks carried into Phase 3 (all mirrored in `01-requirements.md` §6.3): baseline
flakiness (mitigated by the 44-id union + "never a count comparison"); snapshot drift if a repoint
changes import-time behavior (mitigated by repoint-only discipline + the full guard host + AT-288);
shim permanence (consumer rule above); `MICROBAR_EMPTY` snapshot-only pin (closed by TC-654);
cross-checkout overlap with batch-91 on `tests/*` (declared at P0 — batch-91 owns the main checkout,
this batch works in `s19_app-b92`).

## 7 · Forward-applicability table — **the section that makes this document honest**

| Output of this PDR | Named consumer downstream | Where the consumer will read it |
|---|---|---|
| design characteristics | the Phase-3 increments (Inc-A, Inc-B) | §1/§2/§4 here + the binding text already in `01-requirements.md` §3/§4 (cites `#D1…#D7`); post-gate, `docs/ARCHITECTURE.md` (F-1 amendment adds `color_policy` to §7 and records `render/`) |
| enablers (fixtures, data, scaffolding, env) | Phase 3 and validation | §1 enabler block: the AT-288 pinned-capture protocol (Inc-A steps (1)–(4), bytes + hash at `.dev-flow/2026-10-11-batch-92/evidence/`); reused fixtures at `tests/conftest.py:302` / `tests/test_tui_hostile_map.py`; the scratch-sim probe discipline as the de-risking precedent |
| proposed test cases | layers 0/A/B and the DDR | §5 tables here; nodes minted at Phase 3 (`tests/test_render_hexview.py`, `tests/test_render_format.py`) and repoints per the LLR verification lines of `01-requirements.md` §4; the DDR re-reads them at Phase 4 against the gate rule |
| design → requirement traceability | the matrix and the DDR | the table below; the traceability matrix and `04-validation.md` reconcile design element ↔ LLR ↔ HLR at DDR |

- ⚠ Any row whose consumer column is empty: **remove the output, or explain why it is being produced.**

**Design → requirement traceability** (design element → LLR → HLR):

| Design element | LLR | HLR |
|---|---|---|
| #D1 byte-preserving move; retired `tui/hexview.py`; hash = base − wrappers − import block | LLR-001.1 | HLR-001 |
| #D2 `render/` package + empty marker | LLR-001.1 | HLR-001 |
| #D3 constants re-homed in `render/format`; import-block rewrite; tui-free render rule; TC-655 pinned copies | LLR-001.1 · LLR-001.2 · LLR-004.1 | HLR-001 · HLR-004 |
| #D4 8-symbol `insight_style` shim; `validation_service` repoint | LLR-004.1 · LLR-004.2 · LLR-004.3 | HLR-004 |
| #D5 `microbar` + glyphs as one unit | LLR-004.1 | HLR-004 |
| #D6 `safe_text` → root `utils` | LLR-003.1 · LLR-003.2 · LLR-003.3 | HLR-003 |
| #D7 `_CONTROL_SCRUB` moves private | LLR-003.1 · LLR-003.2 | HLR-003 |
| Renderer function + layout-constant surface preserved at the new address | LLR-001.2 · LLR-001.3 | HLR-001 |
| Wrapper deletion; `tui` namespace drops 3 names (keeps 12); `app.py` sources the engine | LLR-002.1 · LLR-002.2 · LLR-002.3 | HLR-002 |
| Measured repoint sets (8 hexview consumers; `safe_text` consumers; service edge) + AST censuses | LLR-001.4 · LLR-003.3 · LLR-004.3 | HLR-001 · HLR-003 · HLR-004 |
| AT-288 pinned pre-move capture (sole byte-identity oracle) + 44-id union gate rule | HLR-001 acceptance (LED-…92.8/.10/.11) | HLR-001 |

## 8 · Parallelisation plan *(only if the batch forks)*

The batch does **not** fork — ARQ §5 verdict: `modules(Inc-A) ∩ modules(Inc-B) ≠ ∅` (`tui/app.py`,
`tui/screens_directionb.py`, 3 shared test files, the new package marker) ⇒ re-cut as **sequential
Inc-A → Inc-B** in this worktree (Exit-1; Exit-2 trunk pre-commit recorded in §6 above). Phase 3
consumes the split as:

| Lane | Modules / layer | Files it owns | Agent |
|---|---|---|---|
| Inc-A (US-92-1+2, + `render/format.py` creation per N1/LED-…92.12) | product layer: hexview move, wrapper deletion, package scaffolding, 8-consumer repoint | NEW `render/{__init__,hexview,format}.py` · DEL `tui/hexview.py` · `tui/{app,__init__,screens,screens_directionb}.py` · `services/{load,report,diff_report}_service.py` + 11 named test files | `software-dev` |
| Inc-B (US-92-3+4) | product layer: `safe_text` move, `insight_style` shim, service/view repoints | `utils.py` · `tui/{screens_directionb,insight_style,checks_view,issues_view}.py` · `services/validation_service.py` · `tui/app.py` (safe_text block only) + 20 named test files | `software-dev` |

- `modules(lane_i) ∩ modules(lane_j) = { }` — or same domain / different layers with the interface frozen: ✓ sequential; Inc-A freezes `render.hexview` + `render.format` at its gate, Inc-B must not touch them (§4)
- **File sets are disjoint** (not just modules — two lanes may not edit the same file, not even different regions): ✓ under the sequential re-cut; within Inc-B, `app.py` is touched only at the `safe_text` block (`:66-79`) and `screens_directionb.py` only for the `safe_text`/`_CONTROL_SCRUB` removal — the Inc-A repoint regions (`:37-42`, `:3336`, `:7581`) are not re-edited
- Family-B reverse census run **per lane and shared** before forking: ✓ run per increment gate (the census TCs TC-651..TC-655 are the mechanized form)
- Trunk-only artifacts (requirements · traceability · backlog · SPEC) are written **only** by the trunk: ✓ this proposal and the contract are trunk artifacts; increment agents touch only product/test files

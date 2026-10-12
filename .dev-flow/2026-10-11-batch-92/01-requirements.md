# Requirements Document — s19_app — Batch 2026-10-11-batch-92

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
This document is the live requirements contract for batch `2026-10-11-batch-92`: a behavior-preserving
module refactor of `s19_app` that relocates pure presentation primitives out of the `tui/` layer to
presentation-neutral addresses, killing the four densest service→presentation import inversions measured
by the 2026-10-11 dependency radiography. The refactor moves code only; it changes no runtime behavior.

### 1.2 Scope
**Covers (READY stories US-92-1 … US-92-4):** the byte-preserving move of `s19_app/tui/hexview.py` to
`s19_app/render/hexview.py` (Inc-A); the deletion of the 3 `range_index` re-export wrappers (Inc-A); the
move of `safe_text` + `_CONTROL_SCRUB` to `s19_app/utils.py` (Inc-B); the move of `microbar` + its glyphs
+ `GREEN`/`LABEL`/`VALUE` + `CYAN`/`DGRAY` to the new `s19_app/render/format.py`, which additionally
DEFINES `FOCUS_HIGHLIGHT_STYLE`/`MAC_ADDRESS_OVERLAY_STYLE` value-equal to the frozen `tui/color_policy.py`
(review C1-(c), operator-ratified; pinned by TC-655) (Inc-B); and the repoint of every measured
consumer (module-map-delta §5/§7.2 F-2 consumer sets are authoritative).

**Does NOT cover:** US-92-5 (`css_class_for_severity` stays in `tui/color_policy.py` — operator-confirmed
freeze 2026-10-11; the `change_service → color_policy` edge is a declared residual); US-92-6 (satisfied
externally at `b167828`); any behavior change, restyling, or edit to frozen engine modules
(`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`,
`tui/color_policy.py`). The surviving residual (`change_service → color_policy`) is declared, not a
defect; the two `render→tui` style-constant edges are **killed this batch** by the review amendment
(module-map §6.1) — `render/hexview.py` carries zero `s19_app.tui.*` imports.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| AT / TC | Black-box acceptance test id / white-box functional test id (global numeric, governed by `AT-TC-REGISTRY.jsonl`) |
| HLR / LLR | High-level requirement / low-level requirement (the two-level decomposition of a user story) |
| EARS | Easy Approach to Requirements Syntax — the `shall` statement patterns used in §3/§4 |
| Byte-preserving move | A file relocation whose content is unchanged, verified by hash equality |
| Re-export shim | A module that re-exports symbols owned elsewhere so existing importers keep working |
| Import census | A test that asserts the import-graph edges of a module set (who imports what from where) |
| Snapshot byte-identity | For the TUI snapshot family, pre/post equivalence is decided by the flaky-tolerant gate rule of §5.2 against the pinned baseline reference (`.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` — union of two executed baselines, 52 known-unstable/failing node ids); AT-288 is the sole byte-identity oracle (review F-QA-3; flaky-set rider LED-…92.11) |
| Repoint | Changing an import statement to address the same symbol at its new module address |

### 1.4 References
- `.dev-flow/2026-10-11-batch-92/design/module-map-delta.md` — approved module map; measured consumer sets (§5, §7.2 F-2) are authoritative for repoint coverage
- `.dev-flow/2026-10-11-batch-92/design/PDR-2026-10-11-batch-92.md` and `DDR-2026-10-11-batch-92.md` — design records (`PDR-2026-10-11-batch-92#D1…#D7` bind module-map decisions R1–R7)
- `docs/architecture.md` — standing architecture oracle (batch-88 six-module cut)
- `.dev-flow/BACKLOG-CODE.md` — frozen-module list (RC-1 conventions block)
- `AT-TC-REGISTRY.jsonl` + `.dev-flow/AT-TC-REGISTRY-SPEC.md` — the AT/TC id allocation authority and its grammar
- `tests/test_tui_directionb.py` — the render-module guard suite run at every gate (~3 min, 2765-test corpus)

### 1.5 Document overview
§2 holds the source stories, premise evaluation and fork preconditions (filled at Phase 0). §3 derives one
HLR per READY story with its black-box acceptance block. §4 decomposes each HLR into LLRs and carries the
Information Flow Contract (Part A always, Part B). §5 states the validation strategy and batch acceptance
criteria. §6 carries risks; the append-only ledger is the separate file `01-requirements-ledger.md`.

---

## 2. Overall description

### 2.1 Product perspective
*(How the change fits into the larger system.)*

### 2.2 Product functions
*(High-level list of functional capabilities.)*

### 2.3 User characteristics
*(Roles, permissions, expected experience levels.)*

### 2.4 Constraints
*(Technological, regulatory, business.)*

### 2.5 Assumptions and dependencies
*(What we take for granted. If an assumption fails, the batch is invalidated.)*

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-92-1 | As a maintainer splitting the codebase for parallel work, I want the pure hex renderer (`hexview.py`: 477 LOC, 0 classes, no Textual import) to live in a presentation-neutral module `s19_app/render/hexview.py`, so that the services layer (`load_service`, `report_service`, `diff_report_service`) stops importing a `tui/` module. | 2026-10-11 dependency radiography (AST census, `model.json`) + operator commission | READY |
| US-92-2 | As a maintainer, I want `hexview`'s `range_index` re-export wrappers (`address_in_sorted_ranges`, `build_sorted_range_index`, `range_in_sorted_ranges`) gone and consumers (`app.py`, `tui/__init__`) importing `range_index` directly, so that the import graph carries no indirection. | Same radiography | READY |
| US-92-3 | As a maintainer, I want `safe_text` (`screens_directionb.py:881`) moved to `s19_app/utils.py`, so that `checks_view` and `issues_view` stop importing the root screens module. | Same radiography | READY |
| US-92-4 | As a maintainer, I want `microbar` and the pure style constants used by services (`GREEN`/`LABEL`/`VALUE` kin) in a presentation-neutral format module, so that `validation_service` stops importing `insight_style`. | Same radiography | READY |
| US-92-5 | As a maintainer, I want `css_class_for_severity` moved out of `tui/color_policy.py`, so that `change_service` stops importing it. | Same radiography | OUT — operator confirmed the freeze stands ("si haz el freeze de color policy", 2026-10-11); deferred to BACKLOG-CODE.md lane A. The `change_service → color_policy` arrow survives this batch, declared as residual. |
| US-92-6 | As any agent running the suite, I want a fresh checkout to collect and run the full test suite on this machine, so that every gate's evidence exists. | P0-discovered defect (executed, see §2.7 premise 3) | OUT — SATISFIED-EXTERNALLY at `b167828` (batch-91's P0 repair: `tests/__init__.py` + uniformized imports vs mapper's stray `.pth`); the batch-92 worktree rebased onto the new base `410cde5` (2026-10-11) |

#### Refinement log (one block per story)

**US-92-1 — hexview out of `tui/`**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = maintainer/paired agents · outcome = services import a neutral renderer, not a TUI module · why = the 3 service→presentation edges are the densest inversion cluster in the radiography · out of scope = any behavior change, any edit to frozen files, app.py's split.
- **Feasibility (E, S):** path = move file + repoint 6 consumers (verified import lists in `model.json`); unknown = none; fits one increment.
- **Evaluability (T):** "When the full suite runs after the move, the user observes every test green and every TUI snapshot byte-identical to the pre-move capture" → AT id at Phase 1. Structural companion: an import census test asserting no `s19_app/tui/services/*` module imports the old path.
- **Open questions:** residual `render/hexview` → `tui/color_policy`/`tui/insight_style` constant imports stay until US-92-5/-4 land — declared, accepted? → **Resolved at P1 (review C1-(c)/C2, operator-ratified): the residuals are KILLED this batch** — `render/format` owns the 5 constants, `render/hexview.py` carries zero `s19_app.tui.*` imports, and TC-655 pins the copies (module-map §6.1).
- **Classification:** `READY`.

**US-92-2 — range_index re-exports removed**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** outcome = import graph carries no re-export indirection · out of scope = editing frozen `range_index.py` itself.
- **Feasibility:** trivial import repoints in `app.py` and `tui/__init__.py`; `screens_directionb.py` already imports `range_index` directly.
- **Evaluability (T):** same suite-green + snapshot-identity observable; census asserts the wrappers absent from the moved module.
- **Open questions:** none.
- **Classification:** `READY`.

**US-92-3 — safe_text to utils**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** outcome = `checks_view`/`issues_view` import `utils.safe_text`; root screens module stops being a utility shelf · out of scope = the other 24 pure helpers in `screens_directionb.py` (entropy/sparkline/cell family) — a later batch.
- **Feasibility:** move ~10 lines + repoint 2 importers.
- **Evaluability (T):** suite green + snapshots identical; census asserts the two views no longer import `screens_directionb`.
- **Open questions:** none.
- **Classification:** `READY`.

**US-92-4 — microbar + style constants to a neutral format module**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** outcome = `validation_service` imports `microbar` and the constants from a module with no `tui/` address · out of scope = restyling, `color_policy.py` (frozen — US-92-5).
- **Feasibility:** `insight_style.py` is NOT in the frozen set (verified against the freeze list); consumers repointed mechanically.
- **Evaluability (T):** suite green + snapshots identical; census asserts no service imports `insight_style`.
- **Open questions:** exact home (`s19_app/render/format.py` vs top-level `format_utils.py`) — Phase 1/ARQ decision.
- **Classification:** `READY`.

**US-92-5 — css_class_for_severity out of color_policy (REFINE)**
- **Functionality:** outcome = `change_service` drops its `color_policy` import.
- **Blocker:** `tui/color_policy.py` is in the engine-frozen set — "OFF-LIMITS (needs an explicit operator unfreeze)" (`.dev-flow/BACKLOG-CODE.md`, RC-1 conventions block). No unfreeze ruling found (`grep -in unfreeze docs/engineering-rules.md .dev-flow/BACKLOG-CODE.md` → no ruling).
- **Open questions:** unfreeze for a behavior-preserving move, or defer?
- **Classification:** `OUT` (operator, 2026-10-11: "si haz el freeze de color policy" — the freeze stands) → carried to BACKLOG-CODE.md lane A at close. Residual declared: `change_service → color_policy` survives this batch.

**US-92-6 — suite runnable from a fresh checkout (OUT — SATISFIED-EXTERNALLY)**
- **Functionality:** user = any agent/CI on this machine · outcome = `python -m pytest tests/ -q` collects and runs from a clean checkout · why = without it, every gate's evidence in this batch is built on a shimmed tree.
- **Measured defect (executed, not inferred):** committed `HEAD` `983f898` in the worktree → **22 collection errors**: `tests` resolves to `C:\Users\jjgh8\Github\mapper\tests` (editable install `_editable_impl_mapper.pth` shadows the namespace `tests/`); copying the main checkout's untracked `tests/__init__.py` in → 14 residual errors: 6 modules with flat `from conftest import` + 9 with flat `from test_*`/`import test_*`, incompatible with the package fix. The main checkout's uncommitted batch-91 tree collects **2765 tests, 0 errors** — the fix exists and is theirs.
- **Open questions:** resolved externally.
- **Classification:** `OUT` — `SATISFIED-EXTERNALLY` at `b167828` (batch-91's P0 repair: `tests/__init__.py` + uniformized imports vs mapper's stray `.pth`); coordination option (a) discharged 2026-10-11 — worktree rebased onto `410cde5`, `base_ref` re-stamped per RC-1.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| 1 | `tui/hexview.py` is presentation-pure: no Textual import, 0 classes | measured | ✅ TRUE | `grep -n "^from\|^import" s19_app/tui/hexview.py` → `rich.text`, `core`, `hexfile`, `range_index`, `color_policy`/`insight_style` constants only; AST census: 0 classes, 12 functions | relied on (US-92-1) |
| 2 | `origin/main` tip `c6b57ab` is contained in the worktree base `983f898` | measured | ✅ TRUE | `git log --oneline HEAD..origin/main` → 0 commits; `origin/main..HEAD` → 1 (unpushed rev101 backlog close-out) | RC-1 (a) satisfied; nothing to rebase |
| 3 | The committed suite (rebased base `410cde5`) collects and runs on this machine with only the declared pre-existing failure family | measured | ✅ TRUE (post-rebase, 2026-10-11; baseline re-measured 2026-10-12 at the P1 amendment) | worktree rebased onto `410cde5` (batch-91 `b167828` carries the `tests` repair): `python -m pytest tests/ -q --co` → **2765 collected, 0 errors**. Full-suite baseline executed 2026-10-12 in this worktree (P1 amendment, finding F-QA-1): `python -m pytest tests/ -q` → **2765 collected / 2724 passed / 36 failed / 2 skipped / 3 xfailed**, failing set proved FLAKY across identical runs (38 / 36 / 40 failures in three full-suite executions 2026-10-11/12); the pinned reference is the union of the two fully-logged executions = 52 node ids at `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` (29 `test_tc016s_density_layout_snapshot[...]` cells + 15 known-unstable nodes); pass rule = the flaky-tolerant gate rule of §5.2, never a count comparison | RC-1 (b) satisfied at the rebased base |
| 4 | `tui/color_policy.py` is frozen absent an explicit operator unfreeze | measured | ✅ TRUE | freeze list `.dev-flow/BACKLOG-CODE.md` RC-1 conventions block; `grep -in unfreeze docs/engineering-rules.md .dev-flow/BACKLOG-CODE.md` → no ruling | US-92-5 REFINE |
| 5 | batch-91 owns the main checkout (single-slot rule) | measured | ✅ TRUE | main checkout working-tree `.dev-flow/state.json` → `batch_id: 2026-10-08-batch-91`, `operator_words: "This batch runs in the MAIN checkout"` | batch-92 runs in worktree `s19_app-b92` |
| 6 | `insight_style.py` and `tui/screens_directionb.py` are NOT in the frozen set | measured | ✅ TRUE | freeze list (premise 4's source) names neither | relied on (US-92-3, US-92-4) |

- **Premise evaluation:** 6 premise(s) · 6 ✅ TRUE — premise 3 flipped TRUE on 2026-10-11 when batch-91's `b167828` landed the `tests` collection repair and the batch-92 worktree rebased onto base `410cde5` (RC-1 (b) re-run at the rebased base).

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

- **Fork preconditions:** **none — this batch runs one lane.** The parallel batch-91 lives in a DIFFERENT checkout (the flow's worktree-per-batch model, not an in-batch fork); the cross-checkout file-set overlap on `tests/*` is declared as a risk in PLAN.md and raised at the P0 gate, not discharged here.

---

## 3. High-level requirements (HLR)

### HLR-001 — Hex renderer relocated to `s19_app/render/hexview.py`
- **Traceability:** US-92-1
- **Ledger:** LED-2026-10-11-batch-92.1 · LED-2026-10-11-batch-92.6 · LED-2026-10-11-batch-92.8 · LED-2026-10-11-batch-92.10 · LED-2026-10-11-batch-92.11 · LED-2026-10-11-batch-92.12 · LED-2026-10-11-batch-92.13 · LED-2026-10-11-batch-92.15
- **Statement:** When Inc-A lands, the system shall render every hex view and hex-bearing report from `s19_app.render.hexview`, and no shipped surface shall source the hex renderer from a `tui/` address.
- **Rationale (informative):** The 3 service→`tui/hexview` edges are the densest inversion cluster in the radiography; the module is pure (Rich + engine, 0 classes, no Textual). Design: `PDR-2026-10-11-batch-92#D1` (module-map R1, byte-preserving whole-file move), `#D2` (R2, `render/` package), `#D3` (R3, style constants re-homed in `render/format` with TC-655-pinned copies — P1 amendment).
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/ -q` (full 2765-test suite at the rebased base `410cde5`) + `python -m pytest tests/test_render_hexview.py -q` (TC-651 node, minted at Phase 3) + the snapshot-identity gate per §5.2 against the pinned baseline reference (`.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt`, union of two executed baselines — 52 known-unstable/failing node ids), with AT-288 as the sole byte-identity oracle.
- **Numeric pass threshold:** no functionality loss against the pinned baseline — the gate run must pass EVERY node outside the 52-id reference union (`.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt`; 2765 collected) and may flip only nodes INSIDE the union (flaky tolerance, recorded not counted); the census TCs TC-651..TC-655 and every repointed functional TC must pass; AT-288 is the sole byte-identity oracle (F-QA-3; flaky rider LED-…92.11); TC-651 passes (1 passed).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** An agent running the suite after the move observes every test at its baseline state and observes the hex view and generated reports byte-identical to the pre-move capture.
  - **Shipped surface:** the Direction-B hex view screen (`tui/screens_directionb.py:3336,7581`), `tui/screens.py:34`, the report services (`tui/services/load_service.py:8`, `report_service.py:58`, `diff_report_service.py:96`), `tui/app.py:37-42`.
  - **Acceptance test(s):** AT-288 — node to be authored at Phase 3: `tests/test_report_service.py::test_at288_report_hex_sections_identical_after_move` (runs the report service end-to-end over the `large_s19` fixture — `tests/conftest.py:302`, the synthetic 200-range × 4 KB S19 built by `make_large_s19` (`tests/conftest.py:71`) — and asserts the emitted report's hex sections match the pinned pre-move capture). Per review F-QA-5 the node shall drive **non-default parameters through the surface**; per the PDR condition QA-PDR-1 (discharged 2026-10-12, LED-…92.13) the driveable non-default set is: a row window (`row_bases`) spanning **≥2 disjoint ranges** of the fixture image and a **non-default `context_bytes`** — the report path calls the plain `render_hex_view` (the `Text`-variant entry points and the focus/highlight/mac-highlight parameters are NOT driveable through the report surface, verified `tui/services/report_service.py:590` at PDR) and the plain path touches none of the 5 moved style constants, so the oracle must exercise the moved *functions* (`build_row_bases` / `build_mem_map_s19` / `render_hex_view`) rather than parameter plumbing that does not reach them. A default-only image is not acceptable evidence. AT-288 is the batch's **sole byte-identity oracle** (F-QA-3); the full-suite gate evidence is the flaky-tolerant rule in `§5.2`, and the pinned baseline reference lives at `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` (52-id union).
  - **Boundary catalog (QC-3):** none — repoint-only change; the batch moves an address, it introduces no new input class. Behavioral coverage is carried by the repointed existing suite (43 nodes in `test_tui_hexview.py` / `test_tui_helpers.py` / `test_tui_hexview_classed.py`, verified green at draft: 43 passed, 2026-10-12).
  - **Negative control:** restoring the deleted `s19_app/tui/hexview.py` or pointing any consumer back at `s19_app.tui.hexview` fails TC-651 (census asserts the old address is absent and every consumer reads `s19_app.render.hexview`). Pre-state probe executed 2026-10-12: `python -c "import s19_app.tui.hexview"` succeeds today; the stated grep probe `grep -c "from s19_app.tui.hexview import\|from .hexview import\|from ..hexview import" tests/*.py` matches only 6 files/7 occurrences — the measured live old-address TEST importers are **8 files in 3 forms** (code-lens C3): `from s19_app.tui.hexview import …` (`test_report_service.py:595` — a source-census *string assertion* whose expected text repoints at Inc-A, `test_tui_diff_screen.py:2788` local, `test_tui_goto_marker.py:28` module + `:195` local, `test_tui_hexview.py:4` module, `test_tui_hexview_classed.py:34` module, `test_tui_operations_view.py:42` module), `import s19_app.tui.hexview as …` (locals inside `test_tui_hexview.py`), `from s19_app.tui import hexview …` (`test_tui_directionb.py:1172,1191` locals, `test_tui_search_pagination.py:19` module) — the TC-651 census (AST walk) covers all three forms; both arms go RED post-move by construction of the census. The mutation is executed and recorded when TC-651 is minted at Phase 3.

### HLR-002 — `range_index` re-export wrappers removed
- **Traceability:** US-92-2
- **Ledger:** LED-2026-10-11-batch-92.2 · LED-2026-10-11-batch-92.14
- **Statement:** When Inc-A lands, the system shall expose the range-membership primitives only at their engine address `s19_app.range_index`, and the `tui` namespace shall carry no `range_index` re-export indirection.
- **Rationale (informative):** The wrappers (`tui/hexview.py:61-141`) are a dead indirection layer over the frozen engine `s19_app/range_index.py:9-79`; ownership stays in the engine. Breaking-by-design: the consumer set is fully enumerated (module-map §5). Design: `PDR-2026-10-11-batch-92#D1` (module-map R1, wrappers die with the move).
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/test_render_hexview.py tests/test_range_index.py tests/test_tui_hexview.py tests/test_tui_public_api.py -q` (TC-652 census node minted at Phase 3; the wrapper behavior nodes in `test_tui_hexview.py:83-119` repointed to `s19_app.range_index` at Phase 3) + full suite per HLR-001.
- **Numeric pass threshold:** TC-652 passes; the 3 wrapper names absent from `s19_app.render.hexview` and from `tui/__init__` import surface and `__all__`; `tests/test_range_index.py` green (engine untouched); 0 NEW failures on the full suite.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** An agent inspecting the import graph observes `from s19_app.tui import address_in_sorted_ranges` failing and `from s19_app.range_index import address_in_sorted_ranges` succeeding, with every range-membership behavior test green.
  - **Shipped surface:** the `s19_app.tui` package namespace (`tui/__init__.py:17-31`, `:81-95`) and `tui/app.py:37-42`.
  - **Acceptance test(s):** AT-289 — V-5 reconciliation at the DDR (LED-…92.14): the chartered node `tests/test_range_index.py::test_at289_tui_namespace_drops_range_index_wrappers` did not realize; the observation is realized by `tests/test_render_hexview.py::test_tc652_wrapper_absence_and_renderer_surface` (asserts the 3 names are not importable from `s19_app.tui`, absent from `tui.__all__`, and still live at `s19_app.range_index`). The id keeps its single on-disk node (C-18 satisfied via the re-point).
  - **Boundary catalog (QC-3):** none — deletion-only change; the wrapper input domain (sorted range lists) is already exercised by the engine suite, which this batch does not touch.
  - **Negative control:** leaving any one wrapper in `tui/__init__.py` fails TC-652 and `test_at289_tui_namespace_drops_range_index_wrappers` (the names are positively asserted absent). Pre-state probe executed 2026-10-12: `grep -n "range_index" s19_app/tui/__init__.py` → `:28` (import) and `:87` (`__all__`) both carry `build_sorted_range_index`; the deletion is the reddening inverse, executed at Phase 3.

### HLR-003 — `safe_text` relocated to `s19_app/utils.py`
- **Traceability:** US-92-3
- **Ledger:** LED-2026-10-11-batch-92.3
- **Statement:** When Inc-B lands, the system shall serve the markup-safety primitive `safe_text` from `s19_app.utils`, and every string that originates in a loaded file shall be rendered through it exactly as before the move.
- **Rationale (informative):** `safe_text` is a security primitive (scrubs C0/DEL/C1, wraps literal `Text`, never `Text.from_markup` — C-17/B-1 contract per `screens_directionb.py:869-877`), not a formatter; its root-screens address forces `checks_view`/`issues_view` to import the 8700-line screens module. Design: `PDR-2026-10-11-batch-92#D6` (module-map R6, root-`utils` home), `#D7` (R7, `_CONTROL_SCRUB` moves with it, private).
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/test_tui_hostile_map.py tests/test_tui_checks_view.py tests/test_tui_issues_view.py -q` (existing hostile-input oracle, repointed at Phase 3) + `python -m pytest tests/test_tui_hostile_map.py -q -k tc653` (TC-653 census node minted at Phase 3) + full suite per HLR-001.
- **Numeric pass threshold:** 0 NEW failures on the full suite; the 3 `test_b77_*` hostile nodes pass (control-byte class scrubbed, payload literal, no span); TC-653 passes (safe_text defined only at `s19_app.utils`; `screens_directionb` no longer defines it; `app.py:79`, `checks_view.py:41`, `issues_view.py:40` import from `..utils`).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** An agent loading a hostile map observes the checks and issues screens rendering hostile symbols literally — no parse error, no style leak — with the views importing `safe_text` from `s19_app.utils`.
  - **Shipped surface:** the checks view (`tui/checks_view.py:41`), the issues view (`tui/issues_view.py:40`), the app shell (`tui/app.py:79`), and every rendered row in `tui/screens_directionb.py` (~96 internal call sites become imports).
  - **Acceptance test(s):** AT-290 — existing nodes, repointed at Phase 3: `tests/test_tui_checks_view.py::test_c17_seed_hostile_linkage_and_reason_render_literal` and `tests/test_tui_issues_view.py::test_at082f_hostile_issue_tokens_render_literal` (both observe the hostile payload rendered literally through the shipped screen surface).
  - **Boundary catalog (QC-3):** ☒ invalid — hostile inputs (bracket/ANSI/control-byte payloads in file-derived symbols) are the exercised class; the boundary arm (empty string, style parameter default) is covered inside the existing `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` table. ☐ empty ☐ boundary ☐ error — not applicable: the primitive's contract is total over `str`; there is no error arm.
  - **Negative control:** flipping the implementation to `Text.from_markup` reddens `test_b77_hostile_symbol_is_literal_and_carries_no_span` — mutation already executed and recorded in `tests/test_tui_hostile_map.py:259` (batch-77, Inc-2); re-confirmed green pre-state at draft (43 passed, 2026-10-12).

### HLR-004 — `microbar` + service style constants relocated to `s19_app/render/format.py`
- **Traceability:** US-92-4
- **Ledger:** LED-2026-10-11-batch-92.4 · LED-2026-10-11-batch-92.9
- **Statement:** When Inc-B lands, the system shall serve `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`, `CYAN` and `DGRAY` from `s19_app.render.format`, the same module shall define `FOCUS_HIGHLIGHT_STYLE` and `MAC_ADDRESS_OVERLAY_STYLE` value-equal to the frozen `tui/color_policy.py` (TC-655 pins the equality), and `validation_service` shall import the palette constants and `microbar` from that address and from no `tui/` address.
- **Rationale (informative):** `validation_service` is a service and must not import the presentation style module; the moved symbols are pure (Rich `Text` + constants). View consumers stay untouched via a declared re-export shim (asymmetry with US-92-2 is deliberate: engine re-exports die, presentation shim stays — module-map R4). Design: `PDR-2026-10-11-batch-92#D4` (R4, canonical ownership moves, shim), `#D5` (R5, one unit with its glyphs).
- **Validation:** `test`
- **Executed verification:** `python -m pytest tests/test_tui_insight_style.py tests/test_tui_mac_coverage.py -q` (existing microbar/palette oracle, shim-imported) + `python -m pytest tests/test_render_format.py -q` (TC-654 census + identity node minted at Phase 3) + full suite per HLR-001.
- **Numeric pass threshold:** 0 NEW failures on the full suite; `test_microbar*` and `test_palette_constants_present_and_correct` pass via the shim; TC-654 passes (validation_service `tui/services/validation_service.py:17` imports from `s19_app.render.format`; shim re-exports are identical objects; `MICROBAR_FILLED == "█"`, `MICROBAR_EMPTY == "░"`, `GREEN == "#54efae"`, `LABEL == "#c5c7d2"`, `VALUE == "#e9e9e9"` at the new address; no `tui/services/*` module imports `insight_style`).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** An agent running the MAC coverage flow observes the micro-bar strip and validation reporting rendered identically to the pre-move capture, with `validation_service` importing from `s19_app.render.format`.
  - **Shipped surface:** the MAC coverage strip in `tui/services/validation_service.py:17` and the views that consume the shim (`tui/app.py:85`, `checks_view.py:40`, `issues_view.py:39`, `crc_designer_view.py:81`, `json_highlight.py:82`, `screens_directionb.py:90` — measured module-map §1.4).
  - **Acceptance test(s):** AT-291 — existing nodes, repointed at Phase 3: `tests/test_tui_mac_coverage.py::test_at071_strip` (the coverage strip driven through the shipped app surface: `mac_in_s19 of mac_total` rendered via the service path), `tests/test_tui_mac_coverage.py::test_build_mac_coverage_strip_counts` (strip builder: counts and `Text` payload), and `tests/test_tui_mac_coverage.py::test_zero_total_no_divzero` (the microbar divide-by-zero edge) — plus the TC-654 identity census; the full-suite gate evidence is the flaky-tolerant rule in `§5.2`.
  - **Boundary catalog (QC-3):** ☒ boundary — `microbar` clamping at `frac` 0.0/1.0 and beyond (`microbar(-0.5)`, `microbar(1.5)`, `microbar(1.0, 0)`) is exercised by the existing `test_microbar` / `test_microbar_floor_opt_in`. ☐ empty ☐ invalid ☐ error — not applicable: total function over `float`, no error arm.
  - **Negative control:** repointing `validation_service` back to `insight_style` fails TC-654 (census asserts the service edge targets `render.format`); redefining the glyph pair at the new address fails the TC-654 identity assertions. Pre-state probe executed 2026-10-12: `grep -n "insight_style import" s19_app/tui/services/validation_service.py` → `:17` carries the old edge; the census node minted at Phase 3 executes both reddening arms.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.
> Per the operator's standing instruction, every LLR that owns a moved symbol states that symbol's
> preserved behavior contract and names the TC that exercises it — an existing on-disk test node where one
> exists, or a new TC authored in Phase 3 (TC-651…TC-654, reserved from the global registry) where coverage
> is missing. All named node paths and `-k` selectors are provisional until Phase 3 (V-5) and reconciled at Phase 4.

### LLR-001.1 — Byte-preserving move and old-path deletion (Inc-A)
- **Traceability:** HLR-001
- **Ledger:** LED-2026-10-11-batch-92.5
- **Statement:** The system shall provide `s19_app/render/hexview.py` and `s19_app/render/__init__.py` (package marker, empty of logic), shall delete `s19_app/tui/hexview.py`, and the moved file's content shall be byte-identical to the base file except for (a) the deletion of the 3 range_index re-export wrappers and (b) the rewrite of the style-constant import block — base `tui/hexview.py:16-17` (`from .color_policy import FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE` / `from .insight_style import CYAN, DGRAY, VALUE`) becomes `from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE`, leaving **zero `s19_app.tui.*` imports** in the moved module (review C2 + C1-(c), operator-ratified: `render/format.py` owns the 5 constants). The byte-identity/hash threshold is accordingly defined as **base file minus the 3 range_index wrappers minus the import block**.
- **Validation:** `test (unit)`
- **Executed verification:** `git diff --stat 410cde5 -- s19_app/tui/hexview.py s19_app/render/` + `python -m pytest tests/test_render_hexview.py -q -k tc651` (TC-651, minted at Phase 3) + `python -m pytest tests/test_render_format.py -q -k tc655` (TC-655 equality pin, NEW — pins `render/format`'s copies to the frozen tui origins) — plus hash comparison of the moved body (base-minus-wrappers-minus-import-block) vs base `s19_app/tui/hexview.py` recorded in the increment packet.
- **Numeric pass threshold:** `s19_app/tui/hexview.py` absent from disk (existence probe → 0); base-minus-wrappers-minus-import-block body hash equality holds (1 assertion); the import block carries zero `s19_app.tui.*` imports (grep probe → 0); TC-651 and TC-655 pass.
- **Negative control:** leaving the old file on disk fails TC-651 (census asserts the retired path is absent); pre-state probe executed 2026-10-12: `ls s19_app/render` → "No such file or directory"; `wc -l s19_app/tui/hexview.py` → 477.
- **Boundary catalog:** none — structural relocation; no input class.

### LLR-001.2 — Renderer function surface preserved at the new address
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** The module `s19_app/render/hexview.py` shall export `render_hex_view` (base `tui/hexview.py:330`), `render_hex_view_text` (`:360`), `build_mem_map_s19` (`:144`), `build_range_validity_s19` (`:153`), `build_range_validity_hex` (`:173`), `build_row_bases` (`:179`) and `find_string_in_mem` (`:187`) with unchanged signatures and behavior.
- **Validation:** `test (unit)`
- **Executed verification:** repointed existing nodes: `python -m pytest tests/test_tui_hexview.py tests/test_tui_helpers.py tests/test_tui_hexview_classed.py -q` — `test_build_mem_map_s19_flattens_record_bytes`, `test_build_range_validity_s19_marks_invalid_ranges`, `test_build_range_validity_hex_reflects_loader_errors`, `test_build_row_bases_aligns_and_sorts_rows`, `test_render_hex_view_text_highlights_match_range`, `test_render_hex_view_text_accepts_row_bases_set`, `test_render_hex_view_includes_focus_context`, `test_render_hex_view_truncates_output`, `test_render_hex_view_text_includes_rows_for_mac_overlay_addresses`, `test_find_string_in_mem_finds_address`, `test_find_string_in_mem_returns_none_when_missing`, `test_find_string_in_mem_supports_next_search` (imports repointed to `s19_app.render.hexview` at Phase 3) + `python -m pytest tests/test_render_format.py -q -k tc655` (TC-655 — the rewritten import block's style constants pinned equal to their frozen tui origins).
- **Numeric pass threshold:** 0 failures across the repointed nodes (draft pre-state: all pass, 2026-10-12); every listed symbol importable from `s19_app.render.hexview` (7/7).
- **Negative control:** any signature or output change to a moved renderer reddens its named node (e.g. dropping the focus-context rows reddens `test_render_hex_view_includes_focus_context`); a one-line output change inside `render_hex_view_text` reddens `test_render_hex_view_text_highlights_match_range` — arm to be executed when the repoint lands at Phase 3.
- **Boundary catalog:** none — behavior preserved verbatim; the input domains (S19/HEX images, range lists, search strings) are already the existing nodes' domains.

### LLR-001.3 — Layout-constant surface preserved
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** The module `s19_app/render/hexview.py` shall define `HEX_WIDTH = 16`, `MAX_HEX_ROWS = 512`, `MAX_HEX_BYTES = 65536`, `FOCUS_CONTEXT_ROWS = 64` and `SEARCH_ENCODING = "ascii"` (base `tui/hexview.py:20-24`), and the `s19_app.tui` package shall keep re-exporting the renderer names.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_hexview.py tests/test_tui_public_api.py -q` — `test_tc_023_hex_width_governs_row_alignment`, `test_tc_023_max_hex_rows_caps_collect_hex_rows`, `test_tc_023_max_hex_bytes_truncation_is_governed_by_constant`, `test_tc_023_focus_context_rows_drives_focus_window`, `test_tc_023_search_encoding_is_the_only_knob_for_find_string_in_mem`, `test_tui_public_api_exports_main_helpers_and_constants` (asserts the renderer surface stays in `tui.__all__`).
- **Numeric pass threshold:** 0 failures; the 5 constants hold their base values at the new address (5/5 assertions).
- **Negative control:** monkeypatching any constant away from its base value reddens the matching `test_tc_023_*` node (the nodes pin the constants by name); executed form recorded at Phase 3.
- **Boundary catalog:** none — constants move as data; the pinning nodes already exist.

### LLR-001.4 — Measured consumer set repointed (import census)
- **Traceability:** HLR-001
- **Ledger:** LED-2026-10-11-batch-92.7
- **Statement:** When Inc-A lands, no `s19_app/tui/services/*` module shall import a `tui` hexview address, and every measured hexview consumer — `tui/app.py:37-42`, `tui/__init__.py:17-31`, `tui/screens.py:34`, `tui/screens_directionb.py:3336,7581`, `tui/services/load_service.py:8`, `tui/services/report_service.py:58`, `tui/services/diff_report_service.py:96` — shall import the same symbols from `s19_app.render.hexview`. The TC-651 census shall derive the importer set from the live tree at run time — an **AST walk** (`ast.parse` import-census over `s19_app/`, covering all aliased/plain import forms) — and assert **set-equality** against the declared measured set, so radiography-vs-code drift fails the test (review F-QA-2; the static radiography already under-measured once, module-map F-2).
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest tests/test_render_hexview.py -q -k tc651` (TC-651, NEW — created in Phase 3; node name provisional per V-5).
- **Numeric pass threshold:** 1 passed; census grep over `s19_app/tui/services/*.py` for `hexview` import lines → 0 hits at a `tui` address; 0 consumer left at the old address (8/8 consumers repointed).
- **Negative control:** pre-state executed 2026-10-12: `grep -rn "hexview import" s19_app/tui/app.py s19_app/tui/__init__.py s19_app/tui/screens.py s19_app/tui/screens_directionb.py s19_app/tui/services/*.py` → 8 consumer sites at the old address; any consumer left behind fails the census. One existing node requires a census-string update in Inc-A: `tests/test_report_service.py` asserts `"from ..hexview import" in source` (report_service source census) — it is repointed to the new import string at Phase 3.
- **Boundary catalog:** none — structural census over a closed, measured module set.

### LLR-002.1 — Re-export wrappers deleted; engine ownership untouched
- **Traceability:** HLR-002
- **Ledger:** none
- **Statement:** The module `s19_app/render/hexview.py` shall not define `build_sorted_range_index`, `address_in_sorted_ranges` or `range_in_sorted_ranges` (base wrapper bodies `tui/hexview.py:61-141`), and the engine `s19_app/range_index.py:9-79` shall remain the sole definition site, unedited.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_range_index.py tests/test_tui_hexview.py -q` — the 6 wrapper behavior nodes in `tests/test_tui_hexview.py:83-119` (`test_build_sorted_range_index_empty_returns_empty_pair`, `test_build_sorted_range_index_sorts_by_start`, `test_address_in_sorted_ranges_boundary_cases`, `test_address_in_sorted_ranges_empty_index_is_false`, `test_address_in_sorted_ranges_single_range`, `test_range_in_sorted_ranges_span_containment`) are repointed to import from `s19_app.range_index` at Phase 3; `tests/test_range_index.py` runs untouched.
- **Numeric pass threshold:** 0 failures; `hasattr(s19_app.render.hexview, "address_in_sorted_ranges")` is False (3/3 wrapper names absent).
- **Negative control:** retaining one wrapper re-import in `test_tui_hexview.py` fails collection at Phase 3 (the module no longer exports the name) — the repoint itself is the reddening arm; executed transcript recorded in the increment packet.
- **Boundary catalog:** none — deletion; the primitives' input domain stays exercised at the engine address.

### LLR-002.2 — `tui` namespace drops the wrappers, keeps the renderer surface
- **Traceability:** HLR-002
- **Ledger:** none
- **Statement:** The package `s19_app/tui/__init__.py` shall drop the 3 wrapper names from its import block and its `__all__` (base `:28`, `:87`) and shall keep re-exporting the renderer names, now sourced from `s19_app.render.hexview`.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_public_api.py tests/test_render_hexview.py -q` — `test_tui_public_api_exports_main_helpers_and_constants` (renderer surface ⊆ `tui.__all__`, `tui.render_hex_view` callable) + TC-652 census node (NEW, Phase 3).
- **Numeric pass threshold:** 0 failures; the 3 wrapper names absent from `tui.__all__` and not importable from `s19_app.tui` (3/3); renderer names present (12/12 — the measured surviving re-export surface, closure finding N2).
- **Negative control:** pre-state executed 2026-10-12: `grep -n "range_index" s19_app/tui/__init__.py` → `:28` import and `:87` `__all__` both carry `build_sorted_range_index`; leaving either line in place fails TC-652.
- **Boundary catalog:** none — namespace-surface deletion.

### LLR-002.3 — `app.py` sources the primitives from the engine
- **Traceability:** HLR-002
- **Ledger:** none
- **Statement:** The module `tui/app.py` shall import `address_in_sorted_ranges` and `build_sorted_range_index` directly from `s19_app.range_index` (base `.hexview` indirection at `:37-42`) and shall import `build_row_bases`, `find_string_in_mem` and `render_hex_view_text` from `s19_app.render.hexview`.
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest tests/test_render_hexview.py -q -k tc652` (TC-652, NEW, Phase 3) + import probe `python -c "from s19_app.tui.app import S19TuiApp"` + full direction-b suite.
- **Numeric pass threshold:** 1 passed (TC-652); app import graph shows `s19_app.range_index` and `s19_app.render.hexview` edges, no `.hexview` edge (2/2 new edges, 0 old).
- **Negative control:** an `app.py` left importing the wrappers fails at import time post-deletion (collection error in every app-touching test file) — arm executed by construction when Inc-A lands; transcript at Phase 3.
- **Boundary catalog:** none — import-edge change over a closed set.

### LLR-003.1 — `safe_text` + `_CONTROL_SCRUB` relocated verbatim
- **Traceability:** HLR-003
- **Ledger:** none
- **Statement:** The module `s19_app/utils.py` shall define `safe_text` (base `tui/screens_directionb.py:881-936`) and the private `_CONTROL_SCRUB` byte-class table (base `:878`, C0 `0x00-0x1F` + DEL `0x7F` + C1 `0x80-0x9F`), and `tui/screens_directionb.py` shall no longer define either symbol, importing `safe_text` from `..utils` instead.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_hostile_map.py -q -k tc653` (TC-653, NEW, Phase 3) + AST probe: `safe_text`/`_CONTROL_SCRUB` defined only in `s19_app/utils.py` (grep `^def safe_text\|^_CONTROL_SCRUB` over `s19_app/`).
- **Numeric pass threshold:** 1 passed; exactly 1 definition site per symbol (`utils.py`); `screens_directionb.py` references `safe_text` only as an import (96 call sites measured at base become consumer sites).
- **Negative control:** pre-state executed 2026-10-12: `grep -n "_CONTROL_SCRUB\|def safe_text" s19_app/tui/screens_directionb.py` → `:878`, `:881`, `:936` (definition sites); the post-move census asserting 0 definition sites there is the reddening inverse.
- **Boundary catalog:** none — verbatim relocation of a closed 59-line unit.

### LLR-003.2 — Markup-safety behavior contract preserved (security)
- **Traceability:** HLR-003
- **Ledger:** none
- **Statement:** The function `safe_text(value, style="")` shall delete every C0/DEL/C1 codepoint via `_CONTROL_SCRUB`, shall wrap the remainder as a literal `rich.text.Text` with the given style, and shall never route the value through `Text.from_markup` or any markup-parsing path.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_hostile_map.py tests/test_tui_checks_view.py tests/test_tui_issues_view.py -q` — `test_b77_hostile_symbol_is_literal_and_carries_no_span`, `test_b77_hostile_symbol_emits_no_control_byte_into_the_strip`, `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` (imports repointed to `s19_app.utils` / consumer modules at Phase 3), plus the view-level hostile nodes `test_c17_seed_hostile_linkage_and_reason_render_literal` (checks_view) and `test_at082f_hostile_issue_tokens_render_literal` (issues_view).
- **Numeric pass threshold:** 0 failures; the scrub table covers all 65 control codepoints (C0 32 + DEL 1 + C1 32 = 65/65) and preserves every non-control character verbatim (asserted over the node's source table).
- **Negative control:** executed on disk: `tests/test_tui_hostile_map.py:259` records the Inc-2 mutation `safe_text → Text.from_markup` that reddens `test_b77_hostile_symbol_is_literal_and_carries_no_span` (batch-77 transcript); the same mutation at the new address is the Phase-3 re-run arm.
- **Boundary catalog:** ☒ invalid — hostile bracket/ANSI/control payloads (C-17 class). ☐ empty ☐ boundary ☐ error — not applicable; the contract is total over `str` (the `:881` signature keeps the `style=""` default).

### LLR-003.3 — `safe_text` consumer set repointed (import census)
- **Traceability:** HLR-003
- **Ledger:** none
- **Statement:** The modules `tui/app.py:79`, `tui/checks_view.py:41` and `tui/issues_view.py:40` shall import `safe_text` from `s19_app.utils`, and no view module shall import `safe_text` from `tui/screens_directionb.py`. The TC-653 census shall derive the `safe_text`-importer set from the live tree at run time (AST walk over `s19_app/`) and assert set-equality against this declared measured set — drift fails the test (review F-QA-2).
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest tests/test_tui_hostile_map.py -q -k tc653` (TC-653, NEW, Phase 3) + `python -m pytest tests/test_tui_checks_view.py tests/test_tui_issues_view.py -q`.
- **Numeric pass threshold:** 1 passed (TC-653); 0 remaining `screens_directionb → safe_text` importer edges across `tui/` (3/3 named consumers repointed; `screens_directionb`'s internal sites reference its own import).
- **Negative control:** any view left importing `safe_text` from `screens_directionb` fails TC-653; pre-state executed 2026-10-12: `grep -n "from .screens_directionb import safe_text" s19_app/tui/checks_view.py s19_app/tui/issues_view.py` → `checks_view.py:41`, `issues_view.py:40`; `grep -n "safe_text" s19_app/tui/app.py` → `:79` (inside the `screens_directionb` import block).
- **Boundary catalog:** none — census over the measured consumer set.

### LLR-004.1 — `microbar` + glyphs + palette constants relocated verbatim
- **Traceability:** HLR-004
- **Ledger:** none
- **Statement:** The new module `s19_app/render/format.py` shall define `microbar` (base `tui/insight_style.py:216-277`), `MICROBAR_FILLED = "█"` and `MICROBAR_EMPTY = "░"` (base `:117-118`), and `GREEN = "#54efae"`, `LABEL = "#c5c7d2"`, `VALUE = "#e9e9e9"` (base `:43-61`), each preserving its behavior and value; shall hold canonical ownership of `CYAN = "#7dd3fc"` and `DGRAY = "#969aad"` (base `tui/insight_style.py:61`, `:57`), which move with `insight_style` shimming them (review C1-(c)); and shall define `FOCUS_HIGHLIGHT_STYLE = "bold yellow"` and `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"` value-equal to the frozen `tui/color_policy.py:13-14` — `color_policy` remains canonical-for-tui and TC-655 pins the copies, so drift fails a test.
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_insight_style.py tests/test_render_format.py -q` — `test_microbar`, `test_microbar_floor_opt_in`, `test_microbar_returns_text`, `test_palette_constants_present_and_correct` (existing, shim-imported) + TC-654 identity assertions (NEW, Phase 3) pinning the glyph pair and palette values at the new address + TC-655 (NEW, Phase 3) pinning `CYAN == "#7dd3fc"`, `DGRAY == "#969aad"`, `FOCUS_HIGHLIGHT_STYLE == "bold yellow"`, `MAC_ADDRESS_OVERLAY_STYLE == "bold orange3"` and their equality to the frozen tui origins.
- **Numeric pass threshold:** 0 failures; 8/8 insight_style-kin symbols (`microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`, `CYAN`, `DGRAY`) defined at `s19_app.render.format` with base values (`microbar(0.5, 8).plain.count("█") == 4`, clamp arms from `test_microbar` hold); 2/2 `color_policy` style strings value-equal to `s19_app.tui.color_policy` (TC-655).
- **Negative control:** pre-state executed 2026-10-12: `grep -n "def microbar\|MICROBAR_FILLED\|^GREEN\|^LABEL\|^VALUE" s19_app/tui/insight_style.py` → definitions only at the old address (`:43-47`, `:117-118`, `:216`); `render/format.py` does not exist. A value drift at the new address (e.g. `MICROBAR_EMPTY` changed, or a `CYAN`/`DGRAY`/`FOCUS_HIGHLIGHT_STYLE` value diverging from its frozen origin) reddens the TC-654/TC-655 identity assertion — arm executed at Phase 3.
- **Boundary catalog:** ☒ boundary — frac clamp arms (`microbar(-0.5)` → 0 filled, `microbar(1.5)` → full, `microbar(1.0, 0)` → empty) exercised by existing nodes. ☐ empty ☐ invalid ☐ error — not applicable.

### LLR-004.2 — `insight_style` keeps an identity-preserving re-export shim
- **Traceability:** HLR-004
- **Ledger:** none
- **Statement:** The module `tui/insight_style.py` shall re-export exactly the 8 moved symbols (`microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`, `CYAN`, `DGRAY`) from `s19_app.render.format` as the identical objects, and shall keep canonical ownership of every other symbol in the palette (`YELLOW/RED/HILITE/LBLUE/PURPLE/MAGENTA`, `DEPTH_*`, `human_bytes:124`, `label_value:175`, `threshold_style:280`, `cap_gauge_style:322`).
- **Validation:** `test (unit)`
- **Executed verification:** `python -m pytest tests/test_tui_insight_style.py tests/test_render_format.py -q` — existing shim-imported nodes stay green + TC-654 identity assertion `s19_app.tui.insight_style.microbar is s19_app.render.format.microbar` (and the 7 other names, 8/8).
- **Numeric pass threshold:** 1 passed; identity holds for all 8 names; the retained palette symbols (`YELLOW/RED/HILITE/LBLUE/PURPLE/MAGENTA`), `DEPTH_*` and the 4 view-side helpers remain defined in `insight_style.py`.
- **Negative control:** a shim that redefines rather than re-imports (copying a constant) fails the `is` identity assertion; pre-state executed 2026-10-12: the 8 symbols are defined (not imported) at `insight_style.py:43-118,216` — the Phase-3 shim flip is the reddening arm.
- **Boundary catalog:** none — module-surface contract.

### LLR-004.3 — `validation_service` repointed; service→`insight_style` edge dead
- **Traceability:** HLR-004
- **Ledger:** none
- **Statement:** The module `tui/services/validation_service.py:17` shall import `GREEN`, `LABEL`, `VALUE` and `microbar` from `s19_app.render.format`, and no `s19_app/tui/services/*` module shall import `tui/insight_style.py`. The TC-654 census shall derive the service-layer importer set from the live tree at run time (AST walk over `s19_app/`) and assert set-equality against the declared measured set — a consumer added after the radiography fails the test instead of silently passing through the `insight_style` shim (review F-QA-2).
- **Validation:** `test (integration)`
- **Executed verification:** `python -m pytest tests/test_render_format.py tests/test_tui_mac_coverage.py -q` — TC-654 census (NEW, Phase 3) + the existing MAC coverage strip nodes (microbar rendering through the shipped service path).
- **Numeric pass threshold:** 1 passed (TC-654); service-layer grep for `insight_style` import lines → 0; `validation_service` renders byte-identical strip output (snapshot identity per HLR-001 gate).
- **Negative control:** pre-state executed 2026-10-12: `sed -n '14,18p' s19_app/tui/services/validation_service.py` → `:17` `from ..insight_style import GREEN, LABEL, VALUE, microbar`; leaving the old edge in place fails TC-654.
- **Boundary catalog:** none — census over a closed module set.

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:** three flows cross the system boundary in this batch (the batch moves their addresses, not their values):

```
FLOW: F-92-1
  SOURCE : s19_app.core.S19File / s19_app.hexfile.IntelHexFile loaded images + range lists
  NODES  :
    - fn    : render_hex_view / render_hex_view_text (+ build_mem_map_s19, build_range_validity_s19,
              build_range_validity_hex, build_row_bases, find_string_in_mem)
      owner : LLR-001.2
      in    : S19File | IntelHexFile, ranges, focus/match parameters
      out   : rich.text.Text rows / plain str rows
  SINK   : Direction-B hex view screen (s19_app/tui/screens_directionb.py), report emitters
           (s19_app/tui/services/{load,report,diff_report}_service.py → report files on disk)
```

```
FLOW: F-92-2
  SOURCE : file-derived / untrusted strings (map symbols, filenames, linkage reasons, issue tokens)
  NODES  :
    - fn    : safe_text (+ private _CONTROL_SCRUB)
      owner : LLR-003.2
      in    : str value + style
      out   : literal rich.text.Text with every C0/DEL/C1 codepoint deleted
  SINK   : rendered rows of s19_app/tui/checks_view.py, s19_app/tui/issues_view.py,
           s19_app/tui/screens_directionb.py (screen elements)
```

```
FLOW: F-92-3
  SOURCE : service-side metrics (coverage fractions, percent values)
  NODES  :
    - fn    : microbar (+ MICROBAR_FILLED, MICROBAR_EMPTY, GREEN, LABEL, VALUE)
      owner : LLR-004.1
      in    : frac, width, style
      out   : rich.text.Text bar + style-string constants
  SINK   : s19_app/tui/services/validation_service.py (MAC coverage strip), view palette consumers
           via the s19_app/tui/insight_style.py shim
```

- **Part B — boundary decomposition:** yes — the system is a TUI whose panels and service emitters are independently addressable (the same trigger the standing doc's three frozen Part B contracts declare). The batch's new boundary components:

```
COMPONENT: C-92-1
  PARENT : SYSTEM
  SURFACE: render package (s19_app/render/)
  INPUTS : loaded image: S19File | IntelHexFile ; ranges: list[tuple[int, int]] ; focus/match params
  OUTPUTS:
    - id          : hex-rendered rows
      value       : Text / str rows of the hex window
      address     : s19_app.render.hexview.render_hex_view / render_hex_view_text (+ builder fns)
      consumers   : s19_app/tui/screens_directionb.py ; s19_app/tui/screens.py ;
                    s19_app/tui/services/load_service.py ; s19_app/tui/services/report_service.py ;
                    s19_app/tui/services/diff_report_service.py ; s19_app/tui/app.py ;
                    s19_app/tui/__init__.py ;
                    tests/test_tui_hexview.py ; tests/test_tui_hexview_classed.py ;
                    tests/test_tui_helpers.py ; tests/test_tui_goto_marker.py ;
                    tests/test_tui_diff_screen.py ; tests/test_tui_operations_view.py ;
                    tests/test_tui_commandbar.py ; tests/test_tui_search_pagination.py ;
                    tests/test_report_service.py ; tests/test_tui_public_api.py
      owner       : LLR-001.2
    - id          : layout constants
      value       : HEX_WIDTH, MAX_HEX_ROWS, MAX_HEX_BYTES, FOCUS_CONTEXT_ROWS, SEARCH_ENCODING
      address     : s19_app.render.hexview::<constant name>
      consumers   : s19_app/tui/screens.py ; s19_app/tui/screens_directionb.py ;
                    s19_app/tui/services/report_service.py ; s19_app/tui/services/diff_report_service.py ;
                    s19_app/tui/__init__.py ; tests/test_tui_hexview.py ;
                    tests/test_tui_hexview_classed.py ; tests/test_tui_public_api.py
      owner       : LLR-001.3
```

```
COMPONENT: C-92-2
  PARENT : SYSTEM
  SURFACE: render package (s19_app/render/)
  INPUTS : value: str ; style: str
  OUTPUTS:
    - id          : microbar bar + style constants
      value       : microbar Text bar; MICROBAR_FILLED/EMPTY glyphs; GREEN/LABEL/VALUE palette
      address     : s19_app.render.format.microbar / ::MICROBAR_FILLED / ::MICROBAR_EMPTY /
                    ::GREEN / ::LABEL / ::VALUE
      consumers   : s19_app/tui/services/validation_service.py ;
                    s19_app/tui/insight_style.py ;
                    tests/test_tui_insight_style.py ; tests/test_tui_patch_checks_strip.py ;
                    tests/test_tui_mac_coverage.py
      owner       : LLR-004.1
```

```
COMPONENT: C-92-3
  PARENT : SYSTEM
  SURFACE: app root utilities (s19_app/utils.py)
  INPUTS : value: str ; style: str
  OUTPUTS:
    - id          : markup-safe Text
      value       : literal Text with C0/DEL/C1 deleted
      address     : s19_app.utils.safe_text
      consumers   : s19_app/tui/app.py ; s19_app/tui/checks_view.py ; s19_app/tui/issues_view.py ;
                    s19_app/tui/screens_directionb.py ;
                    tests/test_tui_hostile_map.py ; tests/test_tui_checks_view.py ;
                    tests/test_tui_issues_view.py ; tests/test_tui_directionb.py ;
                    tests/test_flow_builder_render.py ; tests/test_tui_a2l_detail.py ;
                    tests/test_tui_a2l_issue_recolor.py ; tests/test_tui_checks_screen.py ;
                    tests/test_a2l_multiline_headers.py ; tests/test_tui_patch_big.py
      owner       : LLR-003.2
```


---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

### 5.2 Batch acceptance criteria
- 100% of LLRs (13) carry an assigned validation method with an executed-verification line and a numeric pass threshold; 100% of HLRs trace to a READY US; 100% of LLRs trace to a parent HLR.
- Every moved symbol names a TC: an existing on-disk test node (repointed at Phase 3) or a new TC authored in Phase 3 — TC-651, TC-652, TC-653, TC-654 (reserved from the global registry 2026-10-12) and TC-655 (reserved by the P1 amendment pass 2026-10-12: the style-constant equality pin of review finding C1-(c)).
- Every READY story (US-92-1…US-92-4) has ≥1 black-box AT observing its outcome through the shipped surface: AT-288, AT-289, AT-290, AT-291 (reserved from the global registry 2026-10-12); AT ids are provisional until Phase 3 mints their nodes (V-5) and reconcile at Phase 4.
- Each increment gate runs the FULL `tests/test_tui_directionb.py` render-module guard (~3 min) plus the affected repointed files; batch acceptance on the full 2765-test suite is decided against the pinned baseline reference — the UNION of two executed full-suite baselines (2026-10-12, identical tree): 2765 collected / 2 skipped / 3 xfailed, **52 known-unstable/failing node ids at `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt`** (29 `test_tc016s_density_layout_snapshot[...]` cells + 15 nodes proven flaky across runs: the failing set measured 36, then 40, on unchanged code). **Gate rule (flaky-tolerant, never a count comparison):** (1) every node OUTSIDE the reference union must PASS at the gate — a stable-passing node flipping to failure is functionality loss and fails the gate; (2) nodes INSIDE the union may pass or fail (recorded, not counted); (3) census TCs TC-651..TC-655 and every repointed functional TC must pass; (4) for the TUI snapshot family this rule IS the byte-identity criterion, and **AT-288 is the sole byte-identity oracle** (F-QA-3; flaky rider LED-…92.11).
- Frozen modules untouched: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` (operator-confirmed freeze); `tui/color_policy.py` receives NO edit from this batch (US-92-5 OUT).
- Increments run sequentially Inc-A → Inc-B in this worktree; the surviving declared residual (`change_service → color_policy`) survives by declaration, not oversight — the two `render→tui` constant edges are killed this batch (§6.3).

---

## 6. Appendices (optional)

### 6.1 Extended glossary
*(Terms live in §1.3; nothing further required.)*

### 6.2 Relevant design decisions
- `PDR-2026-10-11-batch-92#D1`–`#D7` bind module-map-delta decisions R1–R7: byte-preserving whole-file move (R1); `render/` as a package (R2); the 5 renderer style constants re-homed in `render/format`, with the frozen `color_policy` pair as TC-655-pinned copies (R3, amended at P1); canonical ownership + presentation shim (R4); microbar moves with its glyphs as one unit (R5); `safe_text` home is root `utils`, not `render/` (R6); `_CONTROL_SCRUB` moves with the function, private (R7).
- ARQ §5 parallelisation verdict: increments re-cut as sequential Inc-A → Inc-B (intersection `{tui/app.py, tui/screens_directionb.py}` + 3 shared test files + the package marker); US-92-5 OUT per operator freeze ruling 2026-10-11.

### 6.3 Open risks
- **≤5-product-files convention vs measured touch sets.** The standing convention caps increments at ≤5 product files; the measured repoint sets are larger (Inc-A: 8 product files + 2 new − 1 deleted; Inc-B: 8). The module map's own Exit-1 text repeats the ≤5 cap while its §8 checkable-paths list exceeds it — an internal tension only the operator can settle. **Gate question recorded for the orchestrator** (see the P1 return): waive the cap for repoint-only increments, or re-cut.
- **`MICROBAR_EMPTY` identity pinned only via snapshots today** (`test_microbar` pins length and the filled glyph; the empty glyph's value rides on snapshots) — closed by the TC-654 identity assertion authored in Phase 3.
- **Cross-checkout overlap with batch-91 on `tests/*`** — declared at P0 in PLAN.md; batch-91 owns the main checkout (premise 5), batch-92 works in `s19_app-b92`.
- **Residual edges are declared, not defects:** `services/change_service → tui/color_policy` (`css_class_for_severity`, US-92-5 OUT) survives the batch. The two `render→tui` style-constant edges (`render/hexview → tui/color_policy`, `render/hexview → tui/insight_style`) are **killed this batch** by the review amendment (C1-(c)/C2, operator-ratified): `render/hexview.py` imports zero `s19_app.tui.*` symbols, `render/format` owns the 5 constants, and TC-655 pins the copies to the frozen origins.
- **Baseline drift risk:** the pinned reference is the 44-node union at `.dev-flow/2026-10-11-batch-92/evidence/baseline-failing-set.txt` (two executed baselines on identical code, 2026-10-12); the failing set is flaky on this machine, so the gate tolerates flips INSIDE the union only — a repoint that flips any node OUTSIDE the union from pass to fail is functionality loss and fails the gate (rule of §5.2, not counts).
- **Security pattern scan verdict** (station P1, executed 2026-10-12): `python <flow root>/scripts/devflow-scan-spec.py .dev-flow/2026-10-11-batch-92/01-requirements.md` → exit 1, all 4 controls ok, `security_required: true`, flags `` `hash` `` (×4), `` `form` `` (×1), `` `expose` `` (×1). Per C-53 the flags are declared, not reworded: `hash` names the batch's integrity-verification method (byte-preserving move checked by content-hash equality — no cryptographic material anywhere in the batch); `form` is the phrase "executed form recorded at Phase 3"; `expose` is the HLR-002 namespace-surface statement (import-graph exposure, no network endpoint). The batch's one genuine security question — the C-17 markup-safety contract of the moved `safe_text` primitive — is answered by LLR-003.2 and AT-290: scrub C0/DEL/C1, wrap literal `Text`, never `Text.from_markup`, with the hostile-input oracle (`tests/test_tui_hostile_map.py`, batch-77 mutation transcript at `:259`) repointed, not weakened. No new sensitive surface is introduced; the refactor moves an existing security primitive's address while preserving its contract.

### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-11-batch-92

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```

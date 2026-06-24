# Traceability Matrix — s19_app — Batch 2026-06-24-batch-15

> **Audience:** engineering / QA reviewers and the batch closer.
> **Purpose:** prove the single in-scope story (US-016) traces down BOTH chains — behavioral (black-box, the WHAT) and functional (white-box, the HOW) — to real, passing test nodes, with surface and file:line evidence.
> **Source of truth:** `01-requirements.md` (HLR/LLR), `04-validation.md` (real node ids + PASS results + the V-5 TC-230/231 reconciliation, all confirmed at Phase 4).
> All node ids below are the REAL function names confirmed at Phase 4 (`pytest -v` / `--collect-only`), not the provisional `TC-230`/`TC-231` selectors. **Verdict: PASS — HLR-016 + 3/3 LLRs covered, 0 blocker fails, 0 orphan ids.**
> **Scope note:** US-015 was **deferred** out of this batch — US-016 is the only story. There is no US-015 row by design.

**Story under trace — US-016:** *As a firmware engineer comparing two images, I want the A↔B compare to report the genuine differing byte runs (or, when an image can't be loaded, a visible diagnostic) instead of a silent "no diff".*

---

## 1. Behavioral chain (Layer B — black-box) — US-016 → HLR-016 → AT → observed outcome

> A story is complete only when its outcome is observed **through the shipped surface**. All four ATs live in `tests/test_tui_diff_compare_realpath.py` and drive the real `#diff_compare_button` (`S19TuiApp.run_test` → `action_show_screen("diff")` → type `#diff_path_a`/`#diff_path_b` → press the real button) with **no `compare_images` monkeypatch** (`grep compare_images` on the file → 1 hit, the docstring stating there is NO monkeypatch).

| US | HLR | AT (real node) | Role | Observed outcome — through which widget | Status |
|----|-----|----------------|------|-----------------------------------------|--------|
| US-016 | HLR-016 | `test_at_016_1_two_wellformed_images_show_changed_runs` | representative / **regression lock** | ≥1 `changed` run via `#diff_range_list` + `sev-ok` on `#diff_status`; 0 exceptions | **PASS** |
| US-016 | HLR-016 | `test_at_016_2_degenerate_image_is_flagged_not_silent` | boundary/degenerate — **THE escaped-bug proof** | `#diff_status.has_class('sev-error')` AND names side (`"degenerate.s19" in status_text`) AND `result.refused is False`; reached the non-refused display path; now carries a fixture-durability guard | **PASS post-fix / RED pre-fix** |
| US-016 | HLR-016 | `test_at_016_3_unresolvable_path_refuses_without_crash` | negative — raise path (over-correction guard) | `#diff_status` `sev-error` refusal on an unresolvable path; `run_test` clean, 0 unhandled exceptions | **PASS** |
| US-016 | HLR-016 | `test_at_016_4_legit_small_valid_image_is_not_flagged` | negative — legit-empty-valid (over-correction guard) | NOT `sev-error`; proceeds `sev-ok` on `#diff_status` for a valid small (2-byte) image | **PASS** |

**HLR-016 satisfied:** the compare reports genuine diffs (AT-016.1) OR a visible load diagnostic (AT-016.2/.3), and never a silent "no diff" — and does not over-flag a legitimately-empty-but-valid result (AT-016.4). Both deliverables (`#diff_status` severity AND `#diff_range_list` rows) are read back through the Pilot; the test fails if the diagnostic is silently absent.

### 1.1 Escaped-bug evidence (mandatory) — AT-016.2 RED→GREEN

`git stash push -- s19_app/tui/app.py` (stashed ONLY the fix; the untracked test stayed):

- **RED — pre-fix tree:** same degenerate input rendered `#diff_status` = `sev-ok` with status `'Compared degenerate.s19 vs full.s19: 1 runs.'` (`has_class('sev-error') is False`, a spurious `only_b` run) — a silent "no diff" reaching the **non-refused display branch** (`reached_display_path is True` even pre-fix). `1 failed in 1.14s`.
- **GREEN — `git stash pop`:** same input → `#diff_status` `sev-error` naming `degenerate.s19`; all 4 ATs re-run GREEN (`4 passed in 2.55s`). Orchestrator independently confirmed post-pop: stash list empty, only `app.py` changed, 4 ATs green.

---

## 2. Functional chain (Layer A — white-box) — US-016 → HLR-016 → LLR → test node → method

> The white-box mechanism is exercised with **real inputs, no mock**. Per Phase 4 §3 (V-5), the provisional white-box ids **TC-230 (LLR-016.1)** and **TC-231 (LLR-016.2)** were never created as separate tests; they are **RECONCILED AS SUBSUMED** by AT-016.2 / AT-016.1, which drive the exact predicate / runs path a unit test would assert. This is a deliberate reconciliation, not a silent omission.

| US | HLR | LLR | Mapped test node (real, no mock) | Method | Status | Subsumption note |
|----|-----|-----|----------------------------------|--------|--------|------------------|
| US-016 | HLR-016 | **LLR-016.1** — detect + surface a per-side load failure instead of a silent empty map (**the production fix**) | `test_at_016_2_degenerate_image_is_flagged_not_silent` (+ guard `test_at_016_4_*`) | real on-disk degenerate file → real `S19File` parse → `records==[]` → predicate `not mem_map and _source_has_content(image)` (`app.py:2220-2221`) fires → caller `sev-error` branch (`app.py:2144-2155`); `#diff_status` stays `markup=False` | **PASS** | **TC-230 ⊆ AT-016.2** — provisional id **RETIRED**, no separate node |
| US-016 | HLR-016 | **LLR-016.2** — genuine diff still reports ≥1 run + `sev-ok` (**verification-dominant**) | `test_at_016_1_two_wellformed_images_show_changed_runs` | verification-only (engine unchanged); real `compare_images` → `result.runs` → `#diff_range_list` with a fixed 1-changed-run fixture | **PASS** | **TC-231 ⊆ AT-016.1** — provisional id **RETIRED**, no separate node |
| US-016 | HLR-016 | **LLR-016.3** — a real e2e regression test drives the unfaked compare path | whole `test_tui_diff_compare_realpath.py` AT band + "no `compare_images` monkeypatch" inspection + RED-pre-fix evidence | real-path suite through `#diff_compare_button`; grep proves 0 monkeypatch escapes | **PASS** | maps to the AT band itself (no separate TC by design) |

**Retired provisional ids (recorded explicitly):** `TC-230` and `TC-231` have **no separate test node** and are **not orphans** — they are subsumed by the ATs above. Phase-6 carry (non-blocking): retire the `TC-230`/`TC-231` labels in `01-requirements.md` and `REQUIREMENTS.md` so they do not survive as dangling identifiers.

---

## 3. Shipped surface (call path, for reviewer reachability)

`AbDiffPanel` → `#diff_compare_button` → `on_ab_diff_panel_compare_requested` (`app.py:2083`) → `_diff_load_maps` (`app.py:2151`, `failed_sides` returned out-of-band) → `#diff_status` (severity) / `#diff_range_list` (runs). Every input dimension (well-formed S19, degenerate non-empty→empty-map, unresolvable/raise, tiny-but-valid) and every output deliverable (`sev-error`, `sev-ok`, named failed side, runs) is reachable **through the button handler** — none exercised only via direct service kwargs (Phase 4 §5).

---

## 4. Repo R-* cross-reference (living-doc traceability)

| R-* id | Location | Traces to |
|--------|----------|-----------|
| **R-DIFF-LOADFAIL-001** | `REQUIREMENTS.md §20` | US-016 / HLR-016 / LLR-016.1–.3 → the four ATs in `tests/test_tui_diff_compare_realpath.py`; references this batch's `04-validation.md` + `06-docs`. |

---

## 5. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories (in scope) | 1 (US-016; US-015 deferred) |
| Covered user stories | 1 (100%) |
| Total HLR | 1 (HLR-016) |
| Implemented HLR | 1 (100%) |
| Total LLR | 3 (016.1, 016.2, 016.3) |
| Implemented LLR | 3 (100%) |
| Behavioral ATs (black-box) | 4 (AT-016.1/.2/.3/.4) — all PASS |
| Functional nodes (white-box) | 0 separate (TC-230/231 subsumed by ATs, V-5); LLR-016.3 = AT band |
| Escaped-bug evidence | captured (AT-016.2 RED→GREEN via `git stash`) |
| Full suite | 866 passed / 29 skipped / 3 xfailed / **0 failed / 0 errored** (898 collected, exit 0) |
| Ledger | 894 baseline + 4 ATs = **898 EXACT** |
| Engine-frozen guards | PASS (`test_engine_unchanged.py::test_tc027_*` + `test_tui_directionb.py::test_tc031_*`) |

---

## 6. Detected gaps

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **None.** 0 blocker / 0 major / 0 minor functional gaps (`04-validation.md` §7/§8). | Proceed to close. |

**0 orphan ids / 0 gaps.** Every requirement (HLR-016, LLR-016.1/.2/.3) maps to a real, passing node; both chains are complete; the only provisional ids (`TC-230`/`TC-231`) are explicitly reconciled as subsumed, not left dangling.

Non-blocking notes (recorded, not gaps): pre-existing `app.py` ruff `F401/F402` (MEMORY.md, 6 errors) — NOT a regression, out of scope this batch; provisional `TC-230`/`TC-231` label retirement is a Phase-6 documentation carry.

---

## 7. Quick bidirectional mapping

### 7.1 By user story
- **US-016** → HLR-016 → LLR-016.1 / .2 / .3 → AT-016.1, AT-016.2, AT-016.3, AT-016.4 (TC-230/231 subsumed)

### 7.2 By code file / test file
- `s19_app/tui/app.py` (`on_ab_diff_panel_compare_requested:2083`, `_diff_load_maps:2151`, predicate `:2220-2221`, caller `sev-error` branch `:2144-2155`) → LLR-016.1 → `test_at_016_2_*` (+ guard `test_at_016_4_*`)
- `tests/test_tui_diff_compare_realpath.py` (the 4 real-path ATs, no monkeypatch) → LLR-016.1 / .2 / .3 → AT-016.1/.2/.3/.4
- `REQUIREMENTS.md §20` (`R-DIFF-LOADFAIL-001`) → US-016 / HLR-016 / LLR-016.1–.3

---

## 8. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-24-batch-15` |
| Validation verdict | **PASS** (`04-validation.md` §5/§7/§8) |
| Story scope | US-016 only (US-015 deferred) |
| HLR / LLR coverage | HLR-016 (1/1) · LLR 3/3 (100%) |
| Behavioral coverage | 4/4 ATs PASS, escaped-bug RED→GREEN proven |
| Functional coverage | TC-230/231 reconciled as subsumed (V-5); 0 orphans |
| Full suite | 866 passed / 0 failed / 0 errored (898 collected) |
| Synced to Obsidian | pending (run `/dev-flow-sync` after merge) |

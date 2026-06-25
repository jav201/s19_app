# Validation — s19_app — Batch 2026-06-25-batch-16 (Phase 4)

**Story:** US-017 — Per-variant file-assignment at project save (closes batch-11 SCOPE-1).
**Branch:** `claude/batch-16-gap2` (Phase 3 committed: Inc1 `a151d56`/`60aebf0`, Inc2 `2fc948b`/`043c3a2`). **Base:** `origin/main b734c19`.
**Reviewer:** qa-reviewer (Phase 4). **NOT committed.**

---

## ✅ Verdict (read first)

**PASS.**

- **Suite:** full `python -m pytest -q` → **900 passed · 29 skipped · 3 xfailed · 932 collected · exit 0**. not-slow `-m "not slow"` → **879 passed · 29 skipped · 21 deselected · 3 xfailed**. 0 failed.
- **Ledger reconciles exactly:** 922 (Phase-1 baseline `b734c19`) + 10 (Inc1 +7 / Inc2 +3) = **932 collected** (confirmed `--collect-only`).
- **SCOPE-1 counterfactual PROVEN:** with production reverted to `origin/main` and tests at HEAD, **AT-017.1, AT-017.4, AT-017.5, and TC-302/303 go RED** (`TypeError: SaveProjectPayload.__init__() got an unexpected keyword argument 'batch'` — the handler/payload path does not exist pre-fix). All restore GREEN post-fix.
- **0 engine-frozen edits; `manifest_writer.py` + `variant_execution_service.py` EDIT-FREE** vs `origin/main` (`git diff --name-only origin/main` over those paths = empty).
- **Honest deviation from §5.3 #2:** AT-017.2 is **GREEN pre-fix** (1 passed under revert) — and that is CORRECT, not a vacuous pass. AT-017.2 writes `project.json` directly and exercises only the consumer `plan_variant_executions` (unchanged substrate); it never drives the reverted handler. It is a **consumer-contract guard**, not a handler counterfactual. The spec's §5.3 #2 enumerated AT-017.2 in the "RED pre-fix" set; that enumeration is imprecise — the four genuine handler counterfactuals are AT-017.1/.4/.5 + TC-302/303. Recorded as a non-blocking spec-precision note (G-3), not a gate failure: every dimension the *handler* threads IS proven RED pre-fix.

---

## STEP 1 — Authoritative suite + ledger

| Run | Command | Collected | Passed | Skipped | xfail | Deselected | Failed | Exit |
|---|---|---|---|---|---|---|---|---|
| Full | `python -m pytest -q` | 932 | 900 | 29 | 3 | — | 0 | 0 |
| not-slow | `python -m pytest -q -m "not slow"` | 911 | 879 | 29 | 3 | 21 | 0 | 0 |

**Ledger (signed-balance):** `922 + 7 (Inc1) + 3 (Inc2) = 932`. ✓ matches `--collect-only` (`932 tests collected`).
**Sanity:** full-run accounting `900 + 29 + 3 = 932` = collected. ✓

---

## STEP 2 — Counterfactual evidence (the SCOPE-1 proof)

**Method:** Phase 3 is committed, so there were no working-tree changes to `git stash`. Instead, reverted the production triplet to pre-feature while keeping tests at HEAD:
`git checkout origin/main -- s19_app/tui/app.py s19_app/tui/screens.py s19_app/tui/styles.tcss`, run the 4 handler ATs + AT-017.2, then `git checkout HEAD -- …` to restore. Restoration confirmed (`git diff --stat HEAD -- s19_app/` empty; only `.dev-flow/state.json` doc-state dirty).

**Result — pre-feature tree (production reverted, tests at HEAD):**

| Node | Pre-fix | Captured failing assertion | Counterfactual? |
|---|---|---|---|
| `test_at017_1_save_persists_and_round_trips_composition` | **RED** | `TypeError: SaveProjectPayload.__init__() got an unexpected keyword argument 'batch'` (`test_tui_manifest_save.py:339`) | YES — handler/payload path absent |
| `test_at017_4_escaping_assignment_refused_no_file_written` | **RED** | same `TypeError` — refusal path never reachable pre-fix (no `batch` field to carry the escaping entry) | YES — POSITIVE-refusal observable impossible pre-fix |
| `test_at017_5_stem_collision_assignment_keyed_by_full_filename` | **RED** | same `TypeError` | YES — collision-keyed assignment unsendable pre-fix |
| `test_tc302_303_handler_threads_batch_assignments_to_write_and_verify` | **RED** | same `TypeError` | YES — nothing to thread pre-fix |
| `test_at017_2_consumer_pickup_of_saved_composition` | **GREEN (1 passed)** | n/a — writes `project.json` directly, exercises only unchanged consumer | NO — consumer-contract guard, not handler counterfactual (see G-3) |

**Post-restore green-check (production back at HEAD):** the 11 US-017 nodes (AT-017.1/.3/.4/.5 + AT-017.2 + TC-301/302-303/304/305/306 + duplicate-stem guard) → **all GREEN** (`11 passed` core set + collision guard green in the full run).

**Note (per spec):** AT-017.3 (zero-selection) is a NO-REGRESSION guard, not a counterfactual — it is green both pre- and post-fix (empty payload re-reads identically); that is its purpose.

---

## STEP 3.1 — Per-requirement pass/fail table (Layer A · white-box, provisional ids reconciled V-5)

> Provisional spec ids `TC-301..312` / `AT-017.1..5` reconciled to the real `def test_*` nodes; each verified to EXIST on disk (grep + executed).

| Req | Method | Real node id(s) (verified on disk) | Pass/Fail | Evidence |
|---|---|---|---|---|
| **HLR-017** | test (pilot) rollup | `test_at017_1_…` (`test_tui_manifest_save.py:352`), `test_at017_2_…` (`test_variant_execution.py:473`) | **PASS** | on-disk round-trip 0-drift + exact-tuple consumer pickup; both RED-proven where applicable |
| **LLR-017.1** payload carries composition | test (unit) | `test_tc301_payload_carries_batch_and_assignments` (`:537`) | **PASS** | `payload.batch == ("doc.json",)`, `assignments == {"b": ("extra.json",)}`; bare ⇒ `()`/`{}` |
| **LLR-017.2** handler threads write+verify | test (integration) + inspection | `test_tc302_303_handler_threads_batch_assignments_to_write_and_verify` (`:557`) | **PASS** | spies assert write & verify each receive `batch`/`assignments`; R1 `verify == write` (`:611-612`); grep `app.py:3785/3786` (write) + `:3803/3804` (verify) carry the kwargs |
| **LLR-017.3** assignment UI, workarea-restricted, key from `variant_id` | test (pilot) | `test_tc304_…` (`:644`), `test_tc305_…` (`:705`), `test_tc306_…` (`:762`) | **PASS** | TC-304 keys `{"b": ("extra.json",)}` from variant set; TC-305 offers only `["doc.json"]` (excludes `outside.json` + `project.json`); TC-306 empty ⇒ `()`/`{}`, no crash |
| **LLR-017.4** reader-as-oracle round-trip + consumer pickup | test (pilot) | `test_at017_1_…`, `test_at017_2_…`, `test_at017_5_…` (`:477`) | **PASS** | `manifest.issues == []`; on-disk `batch`/`assignments[vid]` deep-equal resolved files; plan tuple exact-equals `batch + assignments[vid]` |

**100% of LLR-017.* covered by ≥1 passing TC. Every test row has executed-verification + numeric threshold met.**

## STEP 3.2 — Layer B (black-box AT) table + pre-fix RED evidence

| AT | Observable outcome (the WHAT) | Real node | Post-fix | Pre-fix | Pre-fix RED evidence |
|---|---|---|---|---|---|
| **AT-017.1** | `project.json` carries `assignments[vid]` + `batch`, re-reads 0-drift, `active_variant` preserved | `test_at017_1_save_persists_and_round_trips_composition` | **PASS** | **RED** | `TypeError: …unexpected keyword argument 'batch'` (`:339`) |
| **AT-017.2** | consumer plan tuple **exactly equals** `batch + assignments[vid]` (`("doc.json","extra.json")` resolved) | `test_at017_2_consumer_pickup_of_saved_composition` | **PASS** | GREEN¹ | consumer-contract guard (writes manifest directly; consumer unchanged) — see G-3 |
| **AT-017.3** | zero-selection ⇒ on-disk `batch==[]`/`assignments=={}`, `active_variant` preserved | `test_at017_3_zero_selection_save_no_regression` | **PASS** | GREEN² | no-regression guard, not a counterfactual (by design) |
| **AT-017.4** | escaping assignment → POSITIVE "Manifest write failed" notice surfaced **AND no `project.json` written** | `test_at017_4_escaping_assignment_refused_no_file_written` | **PASS** | **RED** | same `TypeError` — refusal path unreachable pre-fix |
| **AT-017.5** | stem-collision (`fw.s19`+`fw.hex`) round-trips + picked up under FULL-filename id `fw.hex` (D-KEY) | `test_at017_5_stem_collision_assignment_keyed_by_full_filename` | **PASS** | **RED** | same `TypeError` |

¹ Correct — not vacuous (G-3). ² Expected — guard, not counterfactual.

**Dual traceability — BOTH chains exist for US-017:** behavioral `US-017 → AT-017.1..5 → observed (project.json on disk + execution plan)` AND functional `US-017 → HLR-017 → LLR-017.1/.2/.3/.4 → TC-301..306 + AT spine`. ✓

## STEP 3.3 — A-5 surface-reachability matrix

> Confirms every story dimension reaches the manifest THROUGH the shipped save handler/UI — not only via the writer's direct kwargs (the SCOPE-1 hole).

| Dimension | SCOPE-1 hole (white-box, direct kwargs) | Shipped surface (now reached) | Reaching node | Service-kwargs-only? |
|---|---|---|---|---|
| `batch` (project-wide) | `test_manifest_verify.py:89/95` calls `write_project_manifest(… batch=…)` directly | save dialog → `_handle_save_dialog` → `_write_and_verify_manifest(batch=payload.batch)` → write `app.py:3785` + verify `:3803` | **AT-017.1, AT-017.2** | **NO** |
| `assignments` (per-variant) | `test_manifest_verify.py:89/95` direct `assignments=` | same handler → write `app.py:3786` + verify `:3804` | **AT-017.1, AT-017.2, AT-017.5** | **NO** |
| assignment via the UI | — (no UI pre-batch-16) | `action_save_project` (`app.py:2637`) → `SaveProjectScreen._collect_composition` (`screens.py:274`, keys from `variant_id`) | **TC-304** | **NO** |
| escaping entry refusal | writer `_reject_unsafe_entry` only unit-tested | driven through the handler end-to-end | **AT-017.4** | **NO** |
| stem-collision key (output/deliverable) | — | full-filename id `fw.hex` round-trips + consumer pickup | **AT-017.5** | **NO** |

**No dimension is service-kwargs-only. Bidirectional reachability holds:** every input (`batch`, `assignments`, escaping entry, collision key) AND every output/deliverable (`project.json` on disk, execution plan tuple) is exercised/observed through the handler — not only the service API. **The SCOPE-1 hole (`test_manifest_verify.py` direct-kwargs coverage) is now closed.**

## STEP 3.4 — Invariants

| Invariant | Status | Evidence |
|---|---|---|
| **R1** write-intent == verify-intent | ✓ | TC-302/303 `verify_calls[-1] == write_calls[-1]` for both `batch` & `assignments` (`test_tui_manifest_save.py:611-612`) |
| **D-KEY** key by full filename on collision | ✓ | AT-017.5 asserts `assignments == {"fw.hex": …}` + consumer pickup `files_by_id["fw.hex"]`; `_collect_composition` keys from `variant_id` by index, no `Path.stem` (`screens.py:298-303`) |
| **Exact-tuple consumer pickup** | ✓ | AT-017.2 `files_by_id["b"] == (doc.json, extra.json)` resolved, in LLR-006.2 order; unassigned `a` gets only `(doc.json,)` |
| **Escape refused — positive + no-file** | ✓ | AT-017.4 asserts refusal notice present AND `not (project_dir / PROJECT_MANIFEST_NAME).exists()` |
| **Zero-selection no-regression** | ✓ | AT-017.3 `batch==[]`/`assignments=={}`, `active_variant` preserved, "manifest verified" status |
| **0 engine-frozen edits** | ✓ | `git diff --name-only origin/main` over `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py`/`tui/color_policy.py` = **empty** |
| **`manifest_writer.py` + `variant_execution_service.py` EDIT-FREE** | ✓ | same diff over both service paths = **empty** (read-only substrate, as census predicted) |

**Full changed-file set vs `origin/main`** (production): `s19_app/tui/app.py`, `s19_app/tui/screens.py`, `s19_app/tui/styles.tcss` + tests `tests/test_tui_manifest_save.py`, `tests/test_variant_execution.py`. All outside the frozen set. ✓

## STEP 3.5 — Gaps / non-blocking notes

- **G-1 (pre-existing, NOT introduced):** `app.py` ruff C-7 (F401/F402) — carried from batch-15; both increment packets confirm "not introduced." Not in scope of this batch; not a gate item.
- **G-2 (cosmetic, optional):** code-reviewer F2 docstring nit on `screens.py::_collect_composition` — Summary/Returns present and accurate (D-KEY documented), but the CLAUDE.md fixed-order `Data Flow`/`Dependencies` sections are absent on this new helper. Cosmetic; does not affect behavior or any TC. Optional Phase-6 polish.
- **G-3 (spec-precision, non-blocking):** §5.3 #2 lists AT-017.2 in the "RED pre-fix" set, but AT-017.2 is a consumer-contract guard that writes `project.json` directly and never drives the reverted handler — so it is correctly GREEN pre-fix. The genuine handler counterfactuals are AT-017.1/.4/.5 + TC-302/303 (all proven RED). No production or test change needed; flagged so the §5.3 enumeration is read precisely. The SCOPE-1 closure is fully proven by the four handler REDs.
- **Provisional-id drift (V-5):** reconciled — all `TC-301..306` / `AT-017.1..5` provisional ids map to real on-disk `def test_*` nodes (tables 3.1/3.2); no rename chore owed to Phase 6 (node names already encode `tc30x`/`at017_x`).

---

## Batch acceptance criteria (§5.3) — checklist

| # | Criterion | Met? | Evidence |
|---|---|---|---|
| 1 | 100% LLR-017.* covered by ≥1 passing TC; every row has exec-verification + threshold | ✓ | table 3.1 |
| 2 | AT-017.1/.4/.5 PASS post-fix AND RED pre-fix (AT-017.4 = positive refusal + no-file) | ✓ | STEP 2; AT-017.2 deviation explained G-3 (still proven via 4 handler REDs) |
| 3 | Through-the-handler round-trip: on-disk deep-equal, 0 verify drift | ✓ | AT-017.1 |
| 4 | Consumer pickup exact-tuple `batch + assignments[vid]` | ✓ | AT-017.2 |
| 5 | Zero-selection no-regression, existing tests green | ✓ | AT-017.3 + full suite 0 failed |
| 6 | Security: escaping assignment refused through handler, surfaced not crashed | ✓ | AT-017.4 |
| 7 | 0 engine-frozen edits; dual traceability complete | ✓ | STEP 3.4 + 3.2 |
| 8 | Stem-collision round-trips + picked up under full-filename id; UI keys from `variant_id` | ✓ | AT-017.5 + `screens.py:298-303` |

---

## Evidence checklist

- [x] Acceptance criteria use Given/When/Then equivalent (AT = observable-outcome form). — STEP 3.2
- [x] Test cases have explicit Expected, not vague "works". — exact tuples / deep-equals throughout
- [x] Edge cases include empty (AT-017.3), boundary (stem-collision AT-017.5), invalid/error (escape AT-017.4). — ✓
- [x] Regression checklist exists — zero-selection no-regression + full suite 0 failed. — STEP 1
- [x] Exit criteria stated — §5.3 checklist all ✓. — above
- [x] No real PII / secrets — fixtures only (`tmp_path`, `S19_A/B`, `doc.json`/`extra.json`). — ✓
- [x] Test results filled because I actually ran them (full + not-slow + counterfactual + isolated). — `exit 0`, 932 collected
- [x] Layer B black-box: every output-producing deliverable observed through the SHIPPED surface with boundary + negative evidence. — `project.json` on disk + plan tuple via `_handle_save_dialog`; boundary (collision), negative (escape) covered
- [x] Bidirectional surface-reachability: every input AND every output exercised through the handler, not only the service API. — STEP 3.3, no service-kwargs-only dimension
- [x] No unfilled template: no `<…>` / `TC-NNN` placeholders; every provisional id reconciled to a real node. — STEP 3.1/3.2
- [x] Counterfactual proven RED pre-fix (4 handler ATs) + restored GREEN. — STEP 2
- [x] 0 engine-frozen edits + `manifest_writer.py`/`variant_execution_service.py` edit-free. — STEP 3.4

---

## Verdict: **PASS**

US-017 closes batch-11 SCOPE-1 at the shipped surface. All LLRs covered and green; both traceability chains complete; the four handler counterfactuals are RED pre-fix and GREEN post-fix; surface-reachability has no service-kwargs-only hole; 0 frozen/substrate edits; full suite 932 collected / 900 passed / 0 failed. **No iterate-to-fix required → proceed to Phase 5 (post-mortem).**

## Phase-4 iteration (operator: iterate) — G-3 + G-2 resolved
- **G-3 CLOSED — consumer pickup now observed END-TO-END through the handler.** New AT `tests/test_tui_manifest_save.py::test_at017_2_e2e_consumer_pickup_through_handler` drives the SHIPPED save handler (`_save_through_handler`, `batch=("doc.json",)` + `assignments={"b":("extra.json",)}`), re-reads the **handler-written** `project.json` via `read_project_manifest` (NOT a direct `write_project_manifest`), feeds it + the post-save `ProjectVariantSet` into `plan_variant_executions(scope="all")`, and asserts the assigned variant's tuple **exactly equals** `(doc.json, extra.json).resolve()` (batch + assignment) with the unassigned variant batch-only. The original `test_variant_execution.py::test_at017_2_consumer_pickup_of_saved_composition` is kept as the consumer-contract guard. The two-step proof is now also a one-step through-handler pilot.
- **G-2 CLOSED** — `screens.py::SaveProjectScreen._collect_composition` docstring brought to PROJECT_RULES order (Data Flow + Dependencies added).
- **Ledger:** 932 → **933** (+1, the new e2e AT). 2 files (test + docstring), ruff clean, 26 affected tests passed, 0 frozen/substrate edits. **G-1** (pre-existing app.py ruff C-7) remains a standing carry, not introduced. Verdict stands **PASS**.

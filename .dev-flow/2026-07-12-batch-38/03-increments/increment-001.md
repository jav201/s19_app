# Increment 001 — US-065 (B-16) — Change-set free-path label clarity

**Story:** US-065 / HLR-065 (R-TUI-054) · LLR-065.1 + LLR-065.2
**Tests:** AT-065a (black-box) + TC-332 (white-box)
**Base:** `claude/stat-batch-38-dev-flow-2d7ba9` @ `5a6c45b` (batch-38 base)
**Type:** copy-only relabel + acceptance test (no behavior change)

---

## 1. What changed

Copy-only relabel of two rendered strings in the Patch Editor's change-document
UI so the free-path field reads as an **alternative way to point at the same
primary change-set** (not a second / "v2" file):

1. `screens_directionb.py:1854` — entries-pane section-title `Label`:
   `"Change document (v2 JSON)"` → **`"Change document (JSON)"`** (drops the
   `v2` token only). The other two `patch-section-title` labels (`:1918`
   `#patch_script_section_label`, `:1936` `#patch_checks_section_label`) are
   **untouched** — they live in `#patch_pane_changefile`, not `#patch_pane_entries`.
2. `screens_directionb.py:1904` — `#patch_doc_path_input` placeholder:
   `"path to v2 change-set .json"` →
   **`"or type a path to the same change-set JSON (alternative to the patches/ dropdown)"`**.

No widget ids/classes renamed; no logic touched. The `#patch_doc_path_input` id
survives (every existing selector/test that queries it stays valid).

Two test nodes added to `tests/test_tui_directionb.py` (the C-18 node file for
AT-065a) plus a batch-38 snapshot-drift `xfail` helper.

## 2. Files modified (3 source/test files; state.json is orchestrator-owned)

- `s19_app/tui/screens_directionb.py` — the two pinned copy edits (:1854, :1904).
- `tests/test_tui_directionb.py` — `+2` nodes:
  `test_at065a_change_doc_label_reads_as_dropdown_alternative` (AT-065a),
  `test_tc332_change_doc_copy_pins_verbatim` (TC-332), plus a shared
  `_patch_label_and_placeholder` helper and the two pinned-copy constants.
- `tests/test_tui_snapshot.py` — added `_batch38_drift_marks(...)` (active
  `xfail(strict=False)` for the two `patch` cells) and wired it into
  `_SCAFFOLD_CELLS` marks. No baselines regenerated (canonical-CI only).

Frozen set untouched (verified — see §7).

## 3. How to test

```bash
# AT-065a + TC-332 (the increment's ATs)
python -m pytest tests/test_tui_directionb.py -k "at065a or tc332" -q

# Full target file (regression sweep)
python -m pytest tests/test_tui_directionb.py -q

# Snapshot drift cells (expected xfail, non-gating)
python -m pytest "tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot" -k patch -q

# Lint
python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_directionb.py tests/test_tui_snapshot.py
```

## 4. Test results

| Check | Result | Evidence |
|-------|--------|----------|
| AT-065a + TC-332 (post-edit) | **2 passed** | `2 passed, 163 deselected in 1.61s` |
| RED-first counterfactual (pre-edit) | **2 failed as designed** | `AssertionError: section title must read 'Change document (JSON)', got 'Change document (v2 JSON)'` (test_tui_directionb.py:7511) |
| Full `tests/test_tui_directionb.py` | **165 passed** | `165 passed in 156.81s` (163 base + 2 new) |
| Snapshot patch cells | **2 xfailed** (expected copy drift) | `27 deselected, 2 xfailed` |
| ruff (touched files) | **clean** | `All checks passed!` |
| Ledger (collected, `-m "not slow"`) | **1365 → 1367 (+2)** | collect-only: base 1365, post 1367; A=2, D=0 |
| Frozen-file guard | **0 frozen diffs** | `git diff --name-only` → none in frozen set |

**RED → GREEN evidence:**
- **RED (pre-edit, against `main`'s "v2" copy):**
  `AssertionError: assert 'Change document (v2 JSON)' == 'Change document (JSON)'` — AT-065a fails at `test_tui_directionb.py:7511`; TC-332 fails identically at `:7539`.
- **GREEN (post-edit):** `2 passed, 163 deselected in 1.61s`.

## 5. Risks

- **Low.** Copy-only static-label change; no logic, no id/class churn, no engine
  file touched. Regression surface is the two rendered strings.
- **Snapshot drift (R-D, expected):** the two `patch-comfortable-{80x24,120x30}`
  SVG cells re-render because the visible title + empty-input placeholder text
  changed. Marked `xfail(strict=False)` with a batch-38 reason. Baseline regen is
  **canonical-CI only** (snapshot-regen.yml, pinned textual==8.2.8) — never local
  (snapshot-regen-env convention). Follow-up (a later PR) drops the xfail once the
  canonical baselines land, per the batch-33/36 precedent.

## 6. Pending items

- Canonical-CI snapshot regen for the two `patch-*` cells → then drop
  `_batch38_drift_marks` (separate follow-up PR, not this increment).
- Remaining batch-38 stories: US-066, US-067, US-068a, US-068b (later increments).

## 7. Evidence checklist (C-26 census + frozen guard)

- **C-26 reverse census** (`grep -rn "patch_doc_path_input|Change document (v2|path to v2 change-set|patch-section-title" tests/`): **0** existing tests assert the OLD "v2" copy — all `#patch_doc_path_input` refs use `.value` (never `.placeholder`); no test pins `patch-section-title` or the old strings. Architect's "0" confirmed; no breaking-by-design test updates needed.
- **Frozen files:** `git diff --name-only` shows only `s19_app/tui/screens_directionb.py`, `tests/test_tui_directionb.py`, `tests/test_tui_snapshot.py` (+ orchestrator-owned `.dev-flow/state.json`). **0** files in the frozen set (`core.py/hexfile.py/range_index.py/validation/*/tui/a2l.py/tui/mac.py/tui/color_policy.py`).
- **File cap:** 3 source/test files edited (≤5). ✓
- **No secrets, no destructive commands.** ✓
- **Docstrings + type hints** on the new `_patch_label_and_placeholder` helper (7-section order); snapshot helper matches sibling one-liner style (conformance). ✓

## 8. Suggested next task

Increment 2 — **US-066 (B-17)**: TUI-side oversized-address WARNING producer
(`supplemental_a2l_oversized_address_issues` in `services/validation_service.py`),
merged into `build_validation_report` both branches, with AT-066a/AT-066b +
TC-333/334/335. New public issue code `A2L_ADDRESS_EXCEEDS_32BIT`.

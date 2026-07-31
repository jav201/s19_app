# PLAN — batch-74 · `report_service` producer bounding (OB-4 + F4 + D2)

**Living compendium.** Updated at every gate and significant checkpoint.

| | |
|---|---|
| **Batch** | `2026-07-31-batch-74` · Lane **A** (code) · flow `/dev-flow` (full V-model) |
| **Branch** | `claude/batch-74-s19-app-a693ff` |
| **RC-1** | ✅ `git fetch`; `origin/main` tip = `d81cb3d` = HEAD = merge-base. Working tree clean. |
| **Base move** | Plan authored at `6524afd`; main advanced `→ 37f2a4b → d81cb3d`. **`report_service.py` diff `6524afd..d81cb3d` is EMPTY**, so every `@6524afd` address in the plan still resolves. |
| **Flow currency (C-45)** | ✅ `2026.07.28-rev1`, aggregate `sha256 = 0127a2767ff11c8a` — EXACT match to `~/.claude/docs/FLOW-VERSION.md`. |
| **Collision check** | `git ls-remote --heads origin | grep batch-74` → **0**. `batch-73` → **0** (not started). No `.dev-flow/*batch-74*` dir existed. |
| **ID allocation** | Census over `REQUIREMENTS.md` + `tests/` + `.dev-flow/`: prior max **AT-219**, **TC-520**. Allocated **AT-220…**, **TC-521…**. Re-run at Phase 3 — batch-73 may consume ids. |
| **Engine-frozen** | ✅ Neither target is in the frozen set. |
| **Authorization** | **Full autonomy + merge** (operator, 2026-07-31). Recording: **"Acknowledged + flag design rulings inline"**. |

---

## 0. Objective — and its explicit limit

Close **OB-4** (resident memory), **F4** (emitted bytes), **D2** (a schema-legal address denies the
report) — three axes of the **same two functions**, `_modifications_lines` (`:1031`) and
`_checklist_lines` (`:1203`) in `s19_app/tui/services/report_service.py`.

**Out of scope, explicitly:** **D-11** (host-path redaction — three failed revisions, correct design
already specified, deserves its own batch) and **`diff_report_service`** (P3 consistency carry, closes
zero defects here).

**This batch closes OB-4 / F4 / D2 and nothing more.** `R-TUI-098` carries further open residuals over
this same module (the relocated `R` multiplier; `options.declared_regions` having no cardinality cap;
intra-class eviction *disclosed not prevented*). If this batch's work makes a memory claim over
`report_service` as a whole, **the `R-TUI-098` residual line must be discharged explicitly** — §7 of
the close-out names which residuals remain open rather than letting a broad claim swallow them.

## 1. The load-bearing design constraint

**Bound the PRODUCER, not the document.** batch-63's Phase-2 finding was that *bounding output does not
bound traversal*. Verified here as **P-6 TRUE**: `emit()` (`:2215-2217`) calls `budget.consume(...)`
only — it **accounts, never gates** — and `emit(_modifications_lines(...))` at `:2243` has already
fully evaluated the producer before `consume` is reached. Charging these tables to `_ByteBudget` would
close F4 and leave OB-4 **completely** untouched.

Precedent read before designing: **batch-65's `_addendum_lines`** (`:1903-2066`). §3 of
`00-measurements.md` records which of its four mechanisms transfer and which do not.

## 2. Phase-0 premise results (C-43) — 16 TRUE, 1 FALSE

Full table: [`00-measurements.md`](00-measurements.md) §1. Headline:

- **P-14 ❌ FALSE — the plan's flat `988 B/entry` is not a constant.** Measured **140.1 B/entry**
  (mods) / **126.1 B/entry** (chk) at an 8-byte run; the cost is **linear in the entry's byte-run
  length** (`≈ 92 + 6·run`). 988 B/entry is the value at a ~149-byte run.
- **P-15 ⚠️ TRUE WITH A NAMED ADAPTATION** — batch-65's shape transfers except its
  format-after-membership-test step, which has no analogue here.
- All 15 other premises TRUE by executed probe, including every line address after the base move.

## 3. Key decisions

| id | Decision | Status |
|---|---|---|
| **D-1** | **The producer bound is TWO-AXIS: (a) cardinality *and* (b) per-row width.** P-14's falsity means a row-count cap alone does not bound memory — `_format_bytes` is unlimited and `MF_RUN_LENGTH_CEILING = 1_048_576` allows **one row to cost ~6 MiB**, so a 200-row cap bounds the table at ~1.2 GB. Axis (b) is **not** in the plan's sketch; added on measurement. | ✅ **RULED (autonomous, flagged inline)** |
| **D-2** | The **cardinality cap value**. Measured: a cap **< 415** drifts `tests/goldens/batch64/addendum-below-bound.md` (415 Modifications rows); **≥ 415** drifts zero goldens. The plan's "mirror `MAX_REPORT_ISSUES_PER_VARIANT`" would take **200** and silently re-baseline another batch's golden. | ⏳ **Phase 1, option table** |
| **D-3** | The **per-row width bound value** + its in-document truncation notice form. Zero golden risk (widest byte cell in any golden = 1 byte). | ⏳ **Phase 1** |
| **D-4** | Whether axis (b) rides with D2's fix or stands alone — same rows, different columns; D2 is a *format* change, axis (b) a *bound*. | ⏳ **Phase 1** |

## 4. Increment plan — provisional, re-cut at Phase 1 (C-21)

The plan's sketch, **amended by D-1**. `_modifications_lines` and `_checklist_lines` are **not**
symmetric (the former materialises two intermediate full lists, the latter none), so these are not
templated copies of one change.

| Inc | Theme | Files (≤5) |
|---|---|---|
| 1 | Producer-bounding seam for `_modifications_lines` — single pass, admission counters, **both axes**, truncation notice naming what was cut | `report_service.py` + its test file |
| 2 | Same for `_checklist_lines` — different shape, no intermediate lists to fuse | `report_service.py` + tests |
| 3 | **D2** — width predicate derived from `sys.get_int_max_str_digits()`, both sites bound **independently** (P-12: disjoint inputs), error re-routed out of the operator-rejection branch while **preserving fail-closed** | `report_service.py`, `app.py` + tests |
| 4 | Truncation-notice integrity + `R-TUI-097`/`R-TUI-098` requirement updates + the residual discharge | `REQUIREMENTS.md` + tests |

## 5. Known gate hazards in this area (from the plan §6 — all inherited, none discharged yet)

- **Vacuous acceptance is the house defect here.** batch-63 authored **five** vacuous criteria for
  **one** defect, three of them *after* vacuity was already that batch's identified theme. **C-40
  exists because of this exact area.** For every AT: answer *"can it go RED?"* **separately** from
  *"is it correct?"*, and **execute the reddening mutation**.
- **CI is structurally blind to newline-keyed defects** — `tui-ci` runs `ubuntu-latest` where the
  writer already emits LF.
- **The blocking `tui-ci` job installs plain `pytest`, so snapshot cells are SKIPPED there.** Only the
  advisory `continue-on-error` job exercises them. **Any citation of "CI green" as a gate must say
  this explicitly.**
- **Run counterfactual mutations in an export, never in a worktree another session reads** (batch-62
  cost an independent review four spurious failures that way).
- **Iteration budget.** This area hit the 3-iteration soft cap in **Phase 1 AND Phase 2** of batch-63
  and produced **14 gate blockers** in batch-62. On hitting the cap: **escalate to the operator, do
  not loop.**

## 6. Concurrency

| | |
|---|---|
| **My files** | `s19_app/tui/services/report_service.py` + its tests (+ `app.py` error-routing at Inc-3, + `REQUIREMENTS.md`) |
| **batch-73's files** | `s19_app/tui/changes/apply.py`, `tests/test_linkage_soundness.py` — **file-disjoint; do not invade** |
| **Shared at close** | `.dev-flow/BACKLOG-CODE.md` — **whoever closes second rebases** |
| **`state.json`** | PR #168 is now **MERGED** (`37f2a4b` on main), and batch-72 is closed (`current_phase 6`, `merged.pr 166`, `obsidian_synced true`). No batch-73 branch exists. Re-read immediately before every write regardless — last-writer-wins, no owner field. |

## 7. Test ledger

| | |
|---|---|
| Base (to be measured at Inc-1 entry) | *pending* |
| Ledger form | `post = base − D + A` |

## 8. Decision log (human-readable mirror of `state.json.decisions_log`)

| # | Phase | Date | Decision | Type |
|---|---|---|---|---|
| 1 | 0 | 2026-07-31 | **RC-1 re-verified against a MOVED base.** Plan authored at `6524afd`; main is `d81cb3d`. Rather than re-deriving every address blind, diffed the target module across the move: **empty**. All plan addresses inherited as valid, with the diff as evidence. | autonomous |
| 2 | 0 | 2026-07-31 | **Branch reuse.** Used the pre-cut worktree branch `claude/batch-74-s19-app-a693ff` (already at `origin/main` tip, clean) rather than cutting a second branch — RC-1's requirement is merge-base == tip, which holds. | autonomous |
| 3 | 0 | 2026-07-31 | **D-1 ruled: the producer bound is two-axis.** Driven by P-14 coming back FALSE. See §3. | autonomous, **flagged inline** |
| 4 | 0 | 2026-07-31 | **D-2 deferred to Phase 1 rather than taking the plan's "mirror `MAX_REPORT_ISSUES_PER_VARIANT`".** That constant is 200, and 200 < 415 silently re-baselines another batch's byte-identity golden. Measured before choosing (C-39). | autonomous |
| 5 | 0 | 2026-07-31 | Authorization asked fresh and granted: **full autonomy + merge**; recording **acknowledged + inline design-ruling flags**. | operator |

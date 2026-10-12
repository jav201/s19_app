# PLAN — s19_app — Batch 2026-10-11-batch-92

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-11-batch-92 |
| Objective | Kill the 7 layer inversions measured by the 2026-10-11 dependency radiography (AST census of `s19_app/` @ 983f898, `model.json` + `s19_app_modulos.pdf`): R1 move the pure renderer `tui/hexview.py` (477 LOC, 0 classes, no Textual import) to `s19_app/render/hexview.py`; R2 remove hexview's `range_index` re-exports so consumers import `range_index` directly; R3 move `safe_text` from `tui/screens_directionb.py` to `s19_app/utils.py`; R4 move `microbar` + style constants into a presentation-neutral module and (blocked) `css_class_for_severity` out of frozen `color_policy.py`. Behavior-preserving: full pytest suite green, TUI snapshots byte-identical. |
| Standing authorization | ASKED AT P0 GATE 2026-10-11 — pending operator answer (commission words: "Ok, me gusta, dale. Pero usa dev.flow full"). Default until answered: every gate is asked, merge NOT granted. |
| First gate | 2026-10-11 · `devflow-validate.py --brief` on the worktree: **exit 0 · 0 block · 321 notice · 44 n/a (mode full)**, after regenerating `.dev-flow/_derived/` (V20 ×4 = legitimate batch-90 corpus drift, batch-90's committed artifacts postdate the committed atlas). V7 printed no mismatch. |
| Premises / RC-1 | `origin/main` tip `c6b57ab` (2026-10-02) is contained in local `HEAD` `983f898` (`git log HEAD..origin/main` = 0; local ahead 1, the unpushed rev101 backlog close-out). RC-2: `origin` answered; newest commit 9 days old. **Premise 3 (suite green at base) is FALSE on this machine** — see §Premise evaluation in `01-requirements.md`. |

## Triggers

Evaluated at P0, 2026-10-11, over the opening spec. Families C and F re-evaluated at every gate; B at every increment cut.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | fired | creates `s19_app/render/` package; moves the `hexview` module boundary |
| A2 | fired | the diff touches ≥2 modules by construction (4 moves + consumers) |
| A3 | fired | import interface changes for every consumer of `tui.hexview` / `screens_directionb.safe_text` / `insight_style.microbar` |
| A4 | not fired | increments run sequentially in one lane — no parallel increment plan |
| B1 | fired | `grep -rln "render_hex_view\|hexview" tests/` → 9+ test files owned by earlier batches (`test_tui_directionb.py`, `test_tui_snapshot.py`, `test_report_service.py`, …) |
| B2 | fired | files move on disk (`tui/hexview.py` → `render/hexview.py`); reader census owed over the old path |
| B3 | fired | `tests/goldens/` (batch35/64/71) + `test_tui_snapshot.py` capture byte-identical render output of the touched sources |
| B4 | not fired | no new artifact is produced for another component to consume |
| C1–C7 | not fired | no auth, secrets, external integration, sensitive data, destructive DB, input surface or network change — a pure move |
| C8 | fired | the touched code renders file-derived bytes with markup/ANSI styling (`hexview`, `microbar`, severity CSS classes) — Phase-1 scan step owes a pass over the moved code |
| D1–D2 | not fired | no user-visible behavior change; no cross-technology prototype |
| E1 | fired | 4 READY stories + 2 REFINE ≥ 3 |
| E2 | not fired | no high-risk declaration; the batch is mechanical moves under a snapshot-pinned suite |
| E3 | not fired | not a client deliverable / regulated context |
| F1 | not fired | first gate of this batch ran clean (V7 silent) — bundle matches its manifest |
| F2 | not fired | backlog lane is under active refresh by batch-91 in the main checkout (2026-10-11) |

A1+A2+A3 fired ⇒ **ARQ turns on, and with it PDR and DDR** — `stations_active` = P0 · ARQ · P1 · P2 · PDR · P3 · DDR · P4 · P5 · P6.

## Where we are

**MERGED (2026-10-12).** PR #210 merged to `main` as **`a67407c`** after the final independent qa-reviewer PR-level pass came back CLEAN (`review-pr-merge-qa.md`). The batch record is publishing on the closeout branch `kimi/batch-92-closeout` (worktree `s19_app-b92`). All stations closed: P0 → ARQ → P1 (×2) → P2 (×2) → PDR → P3 (Inc-A/Inc-B) → DDR → P4 → P5; postmortem sealed (`05-postmortem.md`), 06-docs filled at P6. Carries routed to BACKLOG-CODE.md lane A (6 entries, incl. the suite-flakiness sharpening and US-92-5); batch-93 (memmap2) is unblocked and rebases onto the refactored tree per `COORDINATION-batch93-memmap.md`.

**Visual annex (rendered dependency map):** the 2026-10-11 radiography this batch worked from — `s19_app_modulos.png` / `.pdf` / `.excalidraw`, plus `model.json` and its generator — lives at `G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Diagramas/`. Cite it as the batch's visual annex (the record's own `06-docs/diagrams/` stays empty: no new surfaces to draw).

## Objective

Kill the 6 of 7 layer inversions the radiography measured (US-92-5 OUT — operator confirmed the `color_policy.py` freeze stands), so that the services layer stops importing `tui/` presentation modules. Behavior-preserving throughout.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| US-92-1 hexview → `render/hexview.py` | READY | kills 3 red arrows (load_service, report_service, diff_report_service) |
| US-92-2 range_index re-export removal | READY | app.py / `tui/__init__` import `range_index` direct; `range_index.py` itself untouched (frozen, respected) |
| US-92-3 `safe_text` → `utils.py` | READY | kills checks_view/issues_view → screens_directionb |
| US-92-4 `microbar` + `insight_style` constants → neutral format module | READY | kills validation_service → insight_style |
| US-92-5 `css_class_for_severity` out of `color_policy.py` | OUT | freeze stands per operator (2026-10-11: "si haz el freeze de color policy") → backlog lane A at close |
| US-92-6 suite runnable in fresh checkout | OUT | SATISFIED-EXTERNALLY at `b167828` (batch-91); worktree rebased onto `410cde5` |
| ARQ | pending | module map update for `render/` |
| P1 | pending | HLR→LLR + AT/TC derivation after the gate |

## Roadmap + increment plan

1. **Inc-1** — US-92-6 if adopted (test-environment fix: `tests/__init__.py` + flat-import unification), else first real move.
2. **Inc-2** — US-92-1 + US-92-2 (hexview move + range_index direct imports) — they share the same file set.
3. **Inc-3** — US-92-3 + US-92-4 (safe_text, microbar/constants).
4. **Inc-4** — US-92-5 only if the operator unfreezes `color_policy.py`.
5. Close: dependency census re-run (extract_model.py) showing 0 service→tui import edges; full suite green; snapshots byte-identical.

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-11 | batch-92 runs in worktree `s19_app-b92`, branch `kimi/batch-92-layer-inversions` | batch-91 owns the main checkout; single-slot rule (`stations/shared-batch.md` §Batch rollover) — two active batches take two checkouts |
| 2026-10-11 | mode `full` | operator commission: "usa dev.flow full" |
| 2026-10-11 | rollover done by hand with `devflow-init.py` internals (the script refuses an existing `.dev-flow/`) | flow ruling: rollover is a procedure, not a rename; the script's refusal is by design |
| 2026-10-11 | `color_policy.py` freeze STANDS — US-92-5 OUT to backlog lane A | operator: "si haz el freeze de color policy"; the freeze demands explicit words to lift, and none were given for the move |
| 2026-10-11 | coordination with batch-91 = option (a): wait for their commit, then rebase — discharged when `b167828` landed | recommended option, approved with the P0 gate; avoids editing the same test files twice |
| 2026-10-11 | roles run as spawned subagents carrying the flow's `agents/<role>.md` files | operator: "usa agentes kimi 2.8 para lo que convenga" — independent review per `full`, token-efficient (role reads its own files, returns conclusions) |

## Risks / watch-items

- **Residual edges declared, not hidden:** `render/hexview` keeps importing `tui/color_policy`/`tui.insight_style` constants until a later batch (US-92-5 freeze + the insight_style constants follow US-92-4); `change_service → color_policy` survives (freeze stands). The final census shows these as declared residuals.
- **`docs/ARCHITECTURE.md` vs batch-91's recent docs commit (`410cde5` rewrote docs/`):** the module-map write goes to `docs/ARCHITECTURE.md` (case-folds to `docs/architecture.md` on this volume); ARQ re-reads the current file before writing.
- If a new batch opens in the main checkout while batch-92 runs, the coordination file `Refactor_10_11_26/COORDINACION-batch92.md` declares this batch's file set.

## Conventions honored

- RC-1 (a)+(b): fetch + base-currency verified; per-story already-shipped greps run over committed HEAD.
- RC-2: origin answered, age recorded.
- Engine-frozen set untouched: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — no edit planned to any (US-92-5 is the REFINE exception awaiting ruling).
- Render-module guard (`docs/engineering-rules.md:190`): every gate runs the FULL `tests/test_tui_directionb.py`, not a `-k` subset.
- Evidence bytes at `artifact_homes.evidence`, `-text` marked.

## Out-of-scope carries

- app.py split (237 methods, 9 domain mixins) — the next batch; plan at `Refactor_10_11_26/PLAN-split-app.md`.
- US-92-5 if the freeze stands → BACKLOG-CODE.md lane A.
- TC-027 `_ENGINE_PATHS` gains `tui/color_policy.py` (frozen-guard coverage gap — PDR condition C3, harmless this batch because the operator freeze already pins the file) → BACKLOG-CODE.md lane A entry at close.
- The 333 unseeded canon ids (V22 notice) — batch-91's territory.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `python -m pytest tests/ -q --tb=no` (worktree, committed HEAD) | 2026-10-11 | **22 collection errors** — `tests` shadowed by `C:\Users\jjgh8\Github\mapper\tests` (editable `_editable_impl_mapper.pth`); with `tests/__init__.py` copied: 6 `from conftest import` + 9 flat `test_*` import modules fail |
| `python -m pytest tests/ -q --co` (main checkout, batch-91's uncommitted tree) | 2026-10-11 | 2765 collected, 0 errors — batch-91's in-flight import unification fixes the environment |

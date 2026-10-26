# PLAN — s19_app — Batch 2026-10-25-batch-99

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language.
> **Owed in.** `core` ✓ · `full` ✓
> Seeded by `/dev-flow-init` step 4 at both levels; the living plan is owed at every gate
> that follows (`/dev-flow` §Living plan is the rule's home).

> **Field guide:** `templates/guides/plan-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.
> **Two header labels are read literally and are never translated:** `Standing authorization` and `Last updated`; the field guide names their readers.

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).
**Create at batch open and update at every gate and significant checkpoint** — the
orchestrator presents the full plan in-conversation at each phase gate.

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-25-batch-99 |
| Objective | The read/write integrity batch: every written image, report and run record says what was and was not applied. Scope: the ten HIGH findings of INVESTIGATION-read-write-integrity-2026-10-22 (H-1 S0 as image data, H-2 PATCH always ok, H-3 shared staging race, H-4 editor undo vs image, H-5 A2L encode byte order, H-6 COMPU_TAB nearest/clamp, H-7 CRC over an empty region, H-8 truncated images load ok, H-9 export path containment, H-10 run records drop dispositions); project round-trip PH-3 (save-back deletes the work copy, Save project crashes); the Code-Wire data HIGHs CW-D-4 (Bytes field decimal tokens), CW-D-7 (MAC-only export phantom byte), CW-D-10 (RAT_FUNC direction); deeper tests of the CW-U-1 fix (Load project dialog) and its sibling; and a generated synthetic fixture corpus with an independent reader as the oracle. |
| Last updated | P6 · 2026-10-26 |
| Standing authorization | Operator commission 2026-10-25, quoted: "Arranca el siguiente batch de s19_app … el batch de integridad de lectura/escritura (RW H-1..H-10, PH-3, HIGHs de datos de CW, pruebas más profundas de CW-U-1, corpus de fixtures sintéticos como oráculo) … TÚ planeas (dev-flow full: P0/P1 requisitos, P2 revisión, plan como página HTML con el backlog abierto ordenado) y la IMPLEMENTACIÓN de cada incremento se delega a Kimi CLI con el modelo Kimi 2.8 … Revisión independiente (code-reviewer/qa) sobre lo que entregue Kimi. Autorización: autónomo con excepciones (parar en hallazgo HIGH o decisión del operador); commit y push a main en cada cierre". Read as: every gate is closed by the orchestrator under this authorization, except (a) a new HIGH finding and (b) an operator decision; both stop the batch. Merge: commit and push to `main` at each close. |
| First gate | `devflow-validate.py --brief .` at P0 open → exit 0, `0 block · 495 notice · 43 not applicable`; `V7` reports the bundle identity at the installed revision. |
| Premises / RC-1 | RC-1 (a): `git fetch origin`; `origin/main` = `HEAD` = merge-base = `307065f4b626459c04ca77736132e9e5ee444253`, so no rebase was needed and `base_ref` was stamped from it. RC-2: `git ls-remote --exit-code --heads origin main` answered `307065f…`, newest commit 2026-10-25 10:54 -0600. RC-1 (b): every candidate story was checked against `origin/main`. CW-U-1's dialog fix has shipped (batch-97 Inc-9), so US-151 takes only its deeper tests, the sibling and CW-U-3. Every other finding reproduces on `307065f` (01-requirements §2.7, P-1..P-21). |

## Triggers

| Id | Verdict | Probe output |
|---|---|---|
| A1 | not fired | judged — no app module is created; `tests/support/independent_reader.py` and `tests/fixtures/synth/` are test-side |
| A2 | fired | judged — the stories touch loaders (`core.py`, `hexfile.py`), changes (`changes/apply.py`, `workspace.py`), services (`change_service.py`, `flow_execution_service.py`, `flow_report_service.py`), the A2L codec (`a2l.py`), CRC (`operations/crc.py`) and Split/Join (`segment_split_view.py`, `segment_ops.py`): ≥2 modules |
| A3 | fired | judged — `ChainRunOutcome` gains fields read by `flow_screens.py` and the chain-set report; the memory-map contract of `get_memory_map` / `get_memory_ranges` changes for every consumer |
| A4 | fired (recorded late, at P5) | judged at P0 — sequential plan, and ARQ said "sequential, one worktree". At P3 the Kimi implementation sessions ran in parallel worktrees (`kimi/inc-*.log` overlap in time), with merges kept sequential. The trigger was not re-recorded at the time; corrected at P5 (`05-postmortem.md` §Record corrections) |
| B1 | fired | a `grep -rl` over `tests/` for `parse_new_bytes`, `save_patched_image`, `get_memory_ranges`, `ChainRunOutcome`, `compose_chain_set_report`, `list_projects`, `_load_from_item` → 50 files, many owned by other batches (e.g. TC-714 in `tests/test_changes_symbol_entries.py`) |
| B2 | not fired | judged — no artifact changes its on-disk location; staging names change inside `temp/`, which no reader globs by name |
| B3 | fired | a `grep -rlE` over `tests/goldens` for `flow_report`, `chain_set`, `CLEAN` → `tests/goldens/batch71/ac6-unscoped-flow-report.md` (the flow report composer changes under HLR-156) |
| B4 | fired | judged — written S19/HEX images are consumed by flash tools and by later flow steps; reports are consumed by readers |
| C1–C5, C7 | not fired | `devflow-scan-spec.py 01-requirements.md` → flags `token`, `session`, `user input`, `form`; none is auth, secrets, external integration, sensitive data, DB or network (answered in 01-requirements §6.3) |
| C6 | fired | the same scan → `security_required: true`; untrusted-file parsers and the A2L-name → path build (H-9) |
| C8 | fired | judged — HLR-156 paints refusal messages that can echo file content into lane cells and reports |
| D1 | fired | judged — lane cell status, the Bytes field help text, the status line and dialogs change what the user sees |
| D2 | not fired | judged — no prototype is ported; no TUI layout change |
| E1 | fired | judged — 11 stories, 11 planned increments |
| E2 | fired | judged — high risk declared: the tool writes flash images; the investigation's verdict is BLOCK for flash-producing use |
| E3 | not fired | judged — internal tool, no client deliverable or regulated context |
| F1 | not fired | from a bundle, `flow_hash` is not recomputed; `V7`'s bundle-identity line is the probe output (0 block) |
| F2 | not fired | judged — the backlog was reconciled at batch-97's close on 2026-10-25 (`BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 close*) |

## Where we are

P6 close (2026-10-26). All 14 increments are on `main`: 001–011 and 003b are the product changes, 012 the DDR test-fix unit, 013 the P4 suite fixes (tests only). P4 validation is PASS-WITH-NOTES with no HIGH (`04-validation.md`). The confirmation full run on the final tree `75f947a` finished: 12 failed / 3755 passed / 3 skipped / 3 xfailed = 3773, with 8 baseline ids and 4 intermittent test nodes, no product defect (`evidence/suite-triage-75f947a.md`). The post-mortem is written (`05-postmortem.md`), the backlog is reconciled and the close record is `05-close.md`. The closing validator run found record defects that no gate had run the validator on since P0; they are repaired at this gate (see *Gate notices*). Next: the deliverable commit, the evidence stamp, the close commit, the vault sync.

## Objective

Every image, report and run record the tool writes says what was and was not applied, and every loaded image holds only what its file declares. Scope: H-1..H-10, PH-3, CW-D-4, CW-D-7, CW-D-10, CW-U-1 deeper tests, CW-U-3, and the synthetic corpus as the oracle.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| P0 | done | DoR: US-141, 142, 144, 146, 148, 149, 151 READY; US-143 (D6), 145 (D5), 147 (D2–D4), 150 (D1) REFINE, resolved by the operator verdict D1–D10 (LED .5) |
| ARQ | done | `design/ARQ-batch-99.md`; `docs/architecture.md` batch-99 rows B99-I1..I12 + I2a |
| P1 | done | `01-requirements.md`; ledger LED .1–.8 |
| P2 | done | `02-review.md`, rounds 1–3 |
| PDR | approved | `design/PDR-2026-10-25-batch-99.md` |
| P3 | done | increments 001–011, 003b, 012 |
| DDR | approved | `design/DDR-2026-10-25-batch-99.md`, every condition discharged |
| P4 | done | `04-validation.md`, PASS-WITH-NOTES; Increment 013 (P4 suite fixes) merged `1a59d3b`; confirmation run `evidence/suite-full-75f947a.txt` |
| P5 | done | `05-postmortem.md` (architect + qa-reviewer), `05-close.md`, backlog reconciled, canon folded |
| P6 | in progress | `06-docs/` written; evidence stamp, close commit and vault sync next |
| US-141..US-152 | done | 12 of 12 observed black-box (AT-B99-01..14, one node each) |

## Roadmap + increment plan

Decision-free increments go first, so the operator's verdict does not block the start:

| Inc | Story | Findings | SOURCE files (≤4) | Gate on | As built (commit) |
|---|---|---|---|---|---|
| 1 | US-141 | corpus + independent reader | 0 (tests only) | — | 0 (tests only) — `a52e2be` |
| 2 | US-142 | H-1 | `core.py`, `render/hexview.py` | — | `core.py`, `render/hexview.py` — `c62c842` |
| 3a | US-144 | H-3, PH-3; placement LLR-155.1/155.2/155.3/155.4/155.7; the 14th path `changes/io.py:1586` (PDR C2) | `changes/apply.py`, `workspace.py`, `app.py`, `changes/io.py` | — | `changes/apply.py`, `changes/io.py`, `workspace.py`, `app.py` — `f1ba70c` |
| 3b | US-144 | D7 start check (LLR-155.5), D9 WRITE-OUT verify (LLR-155.6) | `flow_execution_service.py` | D7, D9 | `flow_execution_service.py`, `project_gather_service.py`, `app.py` — `4ee51a6` |
| 4 | US-146 | H-4 | `change_service.py` (+ `models.py`) | ARQ mem_map census | `change_service.py`, `app.py` — `c58b02d` |
| 5 | US-148 + LLR-155.8 | H-7, CRC staging; R23 confirmed (coverage count on the CRC region result) | `operations/crc.py`, `flow_execution_service.py` | — | `operations/crc.py`, `flow_execution_service.py`, `flow_screens.py` — `e7732f6` |
| 6 | US-149 | H-9, CW-D-7, B99-I2a group placement (PDR C3/PQ-1) | `segment_split_view.py`, `s19_app/segment_ops.py`, `workspace.py` | D8 for the `_<N>` clause | `segment_split_view.py`, `workspace.py` (`segment_ops.py` untouched) — `87dcd3a` |
| 7 | US-151 | CW-U-1 tests, sibling, CW-U-3 | `app.py` | — | `app.py`, `workspace.py` — `d62b0c1` |
| 8 | US-145 | H-2, H-10 | `flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py` | D5 | `flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py` — `7ffad92` |
| 9 | US-143 | H-8 | `core.py`, `hexfile.py`, `flow_execution_service.py` | D6 | `core.py`, `hexfile.py`, `flow_execution_service.py`, `app.py` — `725d474` |
| 10 | US-147, US-152 | H-5, H-6, CW-D-10 | `a2l.py` | D2, D3, D4 | `a2l.py`, `app.py` — `9d7fb18` |
| 11 | US-150 | CW-D-4 | `change_service.py`, `screens_directionb.py`, `window_help.py` | D1 | `change_service.py`, `screens_directionb.py`, `window_help.py` — `5021bb6` |
| 12 | DDR conditions | C-18 one node per AT, ledgers, private calls (DQ-1..DQ-4) | 0 (tests only) | DDR | 0 (tests only) — `c1d088a` |
| 13 | P4 suite fixes | safe_text import census (after Inc 6), Patch Editor snapshot cell (after Inc 11) | 0 (tests only) | P4 | 0 (tests only) — `1a59d3b` |

Each increment runs the same way:
1. Kimi K2.8 (`kimi-code/kimi-for-coding`, `display_name` "K2.8 Preview" in `~/.kimi-code/config.toml`) implements in an isolated git worktree, with `PYTHONPATH=<worktree>` so pytest imports the worktree's package (the `pip -e` trap).
2. `code-reviewer` reviews independently, plus `qa-reviewer`, or `security-reviewer` for Inc 6.
3. The orchestrator re-runs the headline numbers.
4. Commit and push to `main`.

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-25 | Batch number 99, not 98 | batch-98 is reserved for the flow-report batch (operator decisions 2026-10-25) |
| 2026-10-25 | The ten operator decisions D1–D10 go on one page (`design/plan-b99.html`), with the recommended option preselected | the commission's rule "stop on an operator decision"; review by consequences |
| 2026-10-25 | REFINE stories are derived provisionally on the recommended option and gated at P3 | P2 can review the whole contract once; a differing verdict becomes a ledger amendment plus a targeted P2 re-review |
| 2026-10-25 | CW-U-3 joins US-151 | without it the `_load_from_item` sibling fix cannot be observed through the surface (the list is always empty) |
| 2026-10-25 | Operator verdict D1–D10: the recommended option on all ten (`design/veredicto-b99.json`); applied in LED-2026-10-25-batch-99.5 | unblocks Inc 3b, 8, 9, 10, 11 |
| 2026-10-25 | Every byte oracle is the independent reader or the manifest | the repo's verify and diff share the S0 defect (P-3) |

## Risks / watch-items

- Re-pinning tests that assert today's wrong behaviour may mask a regression · likely · each re-pin is named in the packet's reverse census as old value → new value → requirement.
- The pip -e trap: worktree tests import the main checkout · certain without mitigation · `PYTHONPATH=<worktree>` plus a `__file__` probe in every Kimi brief and in the orchestrator's re-run.
- Kimi's weekly quota (exhausted earlier on 2026-10-25; a probe answered at batch open) · possible · fall back to Sonnet/Opus subagents per the operator's 2026-10-24 rule, and name the switch.
- The full suite takes about 2 h 20 · certain · run once per increment cut, one suite at a time.

## Conventions honored

- At most 4 SOURCE files per increment; tests are not capped.
- English in code, UI, commits and records; Spanish in chat.
- No operator name in the repo; region extraction is described only as memory-region extraction; `prototypes/` is never committed.
- CRLF is preserved in edited sources.

## Out-of-scope carries

- PH-1, PH-2, PH-4, PH-5, the Load-file picker, project load from Load, CW-U-2, CW-U-5/10/12/13, CW-D-13/14 → the Load+projects batch (`BACKLOG-CODE.md` §*read/write integrity investigation*, §*Code-Wire audits*).
- M-1..M-10 and L-1..L-7, except what HLR-155's D9 clause takes from M-4 → `BACKLOG-CODE.md` §*read/write integrity investigation*.
- CW-U-6..11, CW-D-2/6/8/9/12/16 → `BACKLOG-CODE.md` §*Code-Wire audits*.
- Enter-to-load in the Load project dialog (D10) → the Load+projects prototype round, if the operator keeps the recommendation.

## Gate notices and runtime absences

- **P0 gate run** (`devflow-validate.py --brief .`, exit 0, 0 block · 495 notice):
  - The template-placeholder NOTICEs (V34, V36–V38, V41, V43–V51, V54) come from seeded batch artifacts not yet written. Each closes when its station writes the artifact.
  - V42's deferral-marker notices sit in closed historical records and are not edited, because rewriting a sealed record is editing the past.
  - V52 (no design proposal) closes at PDR.
  - V53 is a census count, never a block.
  - V55 asked for the standing authorization to be copied into this header; it is copied above.
- **P6 closing gate run** (`devflow-validate.py --brief .`, 2026-10-26). The first closing run returned **99 block**. The validator had not been run at any gate between P0 and P6, so record defects accumulated unseen. That is a process gap, and it is carried to `BACKLOG-PROCESS.md` with the whole-tree-guards item. The 99 blocks were:
  - V59 ×79: 35 packet §2 rows with no `Traces to` id or a `Kind` outside the six, and 44 batch-touched files carried by no row. The message's "rebased after init" reading is a misfire on a trunk-pushed batch: all 32 commits in `307065f..HEAD` are this batch's. `base_ref` was **not** re-stamped. Each file got a row in the packet of the commit that touched it.
  - V20 ×4: stale atlases, regenerated with `--atlas --write`.
  - V4 ×4, V10, V12 ×2, V21 ×4: `01-requirements.md` wording, recorded in LED .9 with no behaviour change.
  - V26: retired LLR-157.3 had no block. It was restored as a retired historical heading and added to the canon with status `retired`.
  - V53, V56 ×2 and V1: a wrong anchor, two run claims citing no transcript, and a bare placeholder.
  - The repair was done by a general-purpose agent under the orchestrator's brief, touching `.dev-flow/**` only, with LLR-157.3 and the canon row done by the orchestrator. The canon-reading tests passed after the canon edit: `test_id_registry` plus the 7 files that read `REQUIREMENTS.md`, 131 passed and 2 xfailed.
  - **Re-run: exit 0, `0 block · 891 notice · 50 not applicable`.** The notices are the P0 families (V9, V13, V23, V41 on historical records), plus V56 on the inc-8 mutation rows. Those rows' stored files were overwritten in review round 1 and are left as recorded, not re-digested. Two more: V57 records predating the tree, normal at a close, and V62, which this rewrite clears.
- **Runtime absences:**
  - This runtime has the named reviewer roles (`architect`, `qa-reviewer`, `security-reviewer`, `code-reviewer`, `ux-reviewer`) as sub-agents, so reviews are independent.
  - The implementer is Kimi CLI, an external runtime. Its packets record `implemented by Kimi K2.8`, and no Kimi session reviews its own work.
  - Rules that cannot run from a bundle are recorded `not-run`: V15 (no canon tree here), V16 (the checkout table lives in the canon) and V17 (no hook is wired into a `settings.json` for the bundle). V30 runs half.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| investigation probes `rw-p01..p14`, `proj-p08` at `307065f` | 2026-10-25 | all exit 0; every finding reproduces (01-requirements §2.7) |
| full suite baseline at `a293213` (`evidence/baseline-pytest-a293213.txt`) | 2026-10-25 | **11 failed, 3617 passed, 3 skipped, 3 xfailed** in 1:54:17. Failing ids: `test_changes_file_notation_help::test_tc1802_…`, `test_tui_commandbar::test_at_b78_03_…`, `test_tui_diff_screen::test_tc024_…`, `test_tui_diff_screen::test_at_b78_32_…`, `test_tui_patch_editor_v2::test_at031b_…`, `test_tui_patch_editor_v2::test_tc328_…`, `test_tui_patch_layout::test_at063c_…`, `test_tui_report_filter_surface::test_at_056e_…`, `test_unified_write::test_tc018_existing_name_is_dedup_suffixed`, `test_window_usage_help::test_tc707_copy_matches_help_sections_md_verbatim`, `test_window_usage_help::test_tc707_numbering_generated_sequential` — every later full run is compared against this set |
| full suite, gate run at `e7732f6` (`evidence/suite-full-e7732f6.txt`) | 2026-10-26 | **14 failed, 3756 passed, 3 skipped, 3 xfailed** in 2:05:30. 9 baseline ids fail for the same causes (2 baseline ids now pass); 3 ordering or load flakes pass on re-run; 2 stale pins were re-measured in Increment 013. Triage: `evidence/suite-triage-e7732f6.md` |
| Patch Editor v2 flake comparison, base vs head (`evidence/flake-*.txt`) | 2026-10-26 | intermittent nodes fail on both trees; `at030c` is a single-pause test race (a patient probe always loads) → BACKLOG-CODE |
| qa-reviewer spot run on main `75f947a` (`evidence/p4-qa/qa-spot-b99-31bac78.txt`) | 2026-10-26 | 142 passed (the b99 files + import census + the re-pinned snapshot cell); collect-only 3773 |
| full suite, confirmation run on the final tree `75f947a` (`evidence/suite-full-75f947a.txt`) | 2026-10-26 | **12 failed, 3755 passed, 3 skipped, 3 xfailed** in 1:58:07 = 3773. 8 baseline ids; the two Increment 013 pins pass; 4 intermittent nodes, each failing on `a293213` too or passing in isolation on both trees. `at057b` is a single-pause test race made more frequent (10/15 vs 3/15; a patient probe delivers every step). Triage: `evidence/suite-triage-75f947a.md` |

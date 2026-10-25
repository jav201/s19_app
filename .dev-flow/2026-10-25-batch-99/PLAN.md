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
| Last updated | P1 · 2026-10-25 |
| Standing authorization | Operator commission 2026-10-25, quoted: "Arranca el siguiente batch de s19_app … el batch de integridad de lectura/escritura (RW H-1..H-10, PH-3, HIGHs de datos de CW, pruebas más profundas de CW-U-1, corpus de fixtures sintéticos como oráculo) … TÚ planeas (dev-flow full: P0/P1 requisitos, P2 revisión, plan como página HTML con el backlog abierto ordenado) y la IMPLEMENTACIÓN de cada incremento se delega a Kimi CLI con el modelo Kimi 2.8 … Revisión independiente (code-reviewer/qa) sobre lo que entregue Kimi. Autorización: autónomo con excepciones (parar en hallazgo HIGH o decisión del operador); commit y push a main en cada cierre". Read as: every gate is closed by the orchestrator under this authorization, except (a) a new HIGH finding and (b) an operator decision; both stop the batch. Merge: commit and push to `main` at each close. |
| First gate | `devflow-validate.py --brief .` at P0 open → exit 0, `0 block · 495 notice · 43 not applicable`; `V7` reports the bundle identity at the installed revision. |
| Premises / RC-1 | RC-1 (a): `git fetch origin`; `origin/main` = `HEAD` = merge-base = `307065f4b626459c04ca77736132e9e5ee444253`, so no rebase was needed and `base_ref` was stamped from it. RC-2: `git ls-remote --exit-code --heads origin main` answered `307065f…`, newest commit 2026-10-25 10:54 -0600. RC-1 (b): every candidate story was checked against `origin/main`. CW-U-1's dialog fix has shipped (batch-97 Inc-9), so US-151 takes only its deeper tests, the sibling and CW-U-3. Every other finding reproduces on `307065f` (01-requirements §2.7, P-1..P-21). |

## Triggers

| Id | Verdict | Probe output |
|---|---|---|
| A1 | not fired | judged — no app module is created; `tests/support/independent_reader.py` and `tests/fixtures/synth/` are test-side |
| A2 | fired | judged — the stories touch loaders (`core.py`, `hexfile.py`), changes (`changes/apply.py`, `workspace.py`), services (`change_service.py`, `flow_execution_service.py`, `flow_report_service.py`), the A2L codec (`a2l.py`), CRC (`operations/crc.py`) and Split/Join (`segment_split_view.py`, `segment_ops.py`): ≥2 modules |
| A3 | fired | judged — `ChainRunOutcome` gains fields read by `flow_screens.py` and the chain-set report; the memory-map contract of `get_memory_map` / `get_memory_ranges` changes for every consumer |
| A4 | not fired | judged at P0 — sequential plan; re-evaluated when ARQ returns its parallelisation verdict (monotonic once fired) |
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

P0 intake is done: 11 stories, 7 `READY` and 4 `REFINE` (D1, D2–D4, D5, D6). ARQ has been delegated to `architect` (module map and parallelisation verdict). P1 requirements are drafted: HLR-152..162, 36 LLRs, 13 ATs, and 21 premises re-run on `307065f`, all TRUE. The REFINE stories are derived provisionally on the recommended option, and they enter P3 only after the operator's verdict. Next: close ARQ, fill §2.8 and LLR-157.3 from it, then run P2 (architect, qa-reviewer and security-reviewer in parallel).

## Objective

Every image, report and run record the tool writes says what was and was not applied, and every loaded image holds only what its file declares. Scope: H-1..H-10, PH-3, CW-D-4, CW-D-7, CW-D-10, CW-U-1 deeper tests, CW-U-3, and the synthetic corpus as the oracle.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| P0 | done | DoR: US-141, 142, 144, 146, 148, 149, 151 READY; US-143 (D6), 145 (D5), 147 (D2–D4), 150 (D1) REFINE |
| ARQ | in progress | `architect` delegated: `docs/ARCHITECTURE.md` batch-99 section + `design/ARQ-batch-99.md` |
| P1 | drafted | `01-requirements.md` §2.7, §3, §4, IFC, §5 |
| US-141..US-151 | not started | see the roadmap |

## Roadmap + increment plan

Decision-free increments go first, so the operator's verdict does not block the start:

| Inc | Story | Findings | SOURCE files (≤4) | Gate on |
|---|---|---|---|---|
| 1 | US-141 | corpus + independent reader | 0 (tests only) | — |
| 2 | US-142 | H-1 | `core.py`, `render/hexview.py` | — |
| 3a | US-144 | H-3, PH-3; placement LLR-155.1/155.2/155.3/155.4/155.7; the 14th path `changes/io.py:1586` (PDR C2) | `changes/apply.py`, `workspace.py`, `app.py`, `changes/io.py` | — |
| 3b | US-144 | D7 start check (LLR-155.5), D9 WRITE-OUT verify (LLR-155.6) | `flow_execution_service.py` | D7, D9 |
| 4 | US-146 | H-4 | `change_service.py` (+ `models.py`) | ARQ mem_map census |
| 5 | US-148 + LLR-155.8 | H-7, CRC staging; R23 confirmed (coverage count on the CRC region result) | `operations/crc.py`, `flow_execution_service.py` | — |
| 6 | US-149 | H-9, CW-D-7, B99-I2a group placement (PDR C3/PQ-1) | `segment_split_view.py`, `s19_app/segment_ops.py`, `workspace.py` | D8 for the `_<N>` clause |
| 7 | US-151 | CW-U-1 tests, sibling, CW-U-3 | `app.py` | — |
| 8 | US-145 | H-2, H-10 | `flow_execution_service.py`, `flow_report_service.py`, `flow_screens.py` | D5 |
| 9 | US-143 | H-8 | `core.py`, `hexfile.py`, `flow_execution_service.py` | D6 |
| 10 | US-147, US-152 | H-5, H-6, CW-D-10 | `a2l.py` | D2, D3, D4 |
| 11 | US-150 | CW-D-4 | `change_service.py`, `screens_directionb.py`, `window_help.py` | D1 |

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
- **Runtime absences:**
  - This runtime has the named reviewer roles (`architect`, `qa-reviewer`, `security-reviewer`, `code-reviewer`, `ux-reviewer`) as sub-agents, so reviews are independent.
  - The implementer is Kimi CLI, an external runtime. Its packets record `implemented by Kimi K2.8`, and no Kimi session reviews its own work.
  - Rules that cannot run from a bundle are recorded `not-run`: V15 (no canon tree here), V16 (the checkout table lives in the canon) and V17 (no hook is wired into a `settings.json` for the bundle). V30 runs half.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| investigation probes `rw-p01..p14`, `proj-p08` at `307065f` | 2026-10-25 | all exit 0; every finding reproduces (01-requirements §2.7) |
| full suite baseline | 2026-10-25 (batch-97 close) | 3617 passed; non-baseline failures accounted for in batch-97 inc-7 |

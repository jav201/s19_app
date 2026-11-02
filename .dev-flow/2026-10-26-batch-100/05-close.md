# Batch close — s19_app — Batch 2026-10-26-batch-100

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language — the **prose**,
> and never a label.

> **Owed in.** `core` ✓ · `full` —

> **Field guide:** `templates/guides/close-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Conditional-gate discharge` · `New controls` · `Human perimeter` · `Human review ledger` · `Gated tree` · `Found before the batch` · `⏸ DEFER`
> **And the §6 DEPTH tokens — cell VALUES rather than field names, reserved for the same reason:**
> `light` · `rigorous` · `spot-check` · `none` · `✅` · `❌`. A CLOSED set, declared closed by the first
> revision that ships it — so the vocabulary a later promotion of `V54` to BLOCK will need already exists,
> instead of being introduced over a free-text field that six authors have by then written six ways.
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Notice convention.** `⚠` yellow = declare and continue · `✗` red = block · `✓` green = satisfied
> **with its citation**.

---

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `python "<HOME>/.claude/skills/dev-flow/scripts/devflow-validate.py" --brief "<HOME>/Github/s19_app-b100-close"` from the project root · 2026-11-01 · `455 block · 847 notice · 45 not applicable` — the 3 blocks naming `05-close.md` (V64 §3 citations) are repaired by this record; the remainder is owed at the close: V22 canon fold-back (`--fold-canon`), V59 `base_ref` re-stamp after the rebase, V20 atlas regeneration |
| Gated tree | `f72eef1efed1eca96d272f4e8f27d206e5e47b86` · dirty — `pyproject.toml`, `s19_app/version.py` (the `1.0.0rc1` version bump, release decision 2026-11-01) and the untracked gate evidence `evidence/batch-end/linux-gate-f72eef1-*.txt` (the close record itself excluded) |
| Requirements canon | `REQUIREMENTS.md` (`artifact_homes.requirements_canon` = `repo:REQUIREMENTS.md`) — the canon carries through HLR-162 (batch-99); batch-100's 42 HLRs (HLR-163…HLR-178, including HLR-171a/b, 172a/b, 173a–e, 174a–d, 175a–f, 176a–d, 177a–c) and their 349 live LLRs are the new ids the `devflow-init.py --fold-canon` step owes at this close |

**The gate run whose result this close reports.** The Linux full suite on `f72eef1` (`evidence/batch-end/linux-gate-f72eef1-summary.txt`, `-xdist8.log`, `-timing-serial.txt`): **18 failed / 5 027 passed / 205 skipped / 4 xfailed** in 3 756 s. The 18 split as **5 known pre-existing failures** (`tc1802`, `tc707_copy`, `tc707_numbering`, `at_056e_a2b`, `at_b78_03`) plus **13 one-second timing arms** that failed under the 8-way parallel load; the serial re-run passed **12 of 13**, and the 13th (`test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling`) passed **3 of 3 alone**. No new product defect was found by the gate run.

**⏸ DEFER** — the GitHub CI run **41372953464** on `f72eef1` is a post-close confirmation: operator ruling 2026-11-01 — close now, fix after if it finds anything.

**Close record for a `full` batch.** This project closes `full` batches with `05-close.md`, as batch-99 did. The post-mortem content a `full` close owes is in `05-postmortem.md` (architect + qa-reviewer), and `06-docs/` holds the P6 documents.

---

## 1 · What changed

**BLUF.** One Load dialog now offers everything that can be loaded — projects, work-area files, recent sources and a typed path — and Load opens projects. A project restores exactly what was saved or names every problem, and Save project writes the image the engineer actually sees (source plus every change-document entry), verified. A save-back becomes the project's active variant, so Load reopens where the engineer stopped. Nothing unsaved is replaced without one question. Project load, Save project and the A2L parse run on worker threads with a live progress line, a busy refusal and a quit question.

**Mechanism.** One placement function, `place_into_workarea`, owns byte-identical reuse, containment and staging. Save project writes through the emitter split (`save_patched`) and an independent reader verifies the bytes. The manifest carries `files` digests, `derived_from` and `active_document`; every in-project writer rewrites it. The frozen save plan (`plan_project_save`) is what the Save dialog paints and what the handler executes. Three workers with frozen request/result types carry project load, Save project and the A2L parse; a busy refusal guards 16 entry points. A per-user recent-sources store lives outside every work area (`%LOCALAPPDATA%\s19_app\recent_sources.json`). `tui/a2l.py` gained an optional progress callback under the operator's named frozen-engine crossing and returned to `_ENGINE_PATHS`.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| HLR-163 (byte-identical copies are reused) | v1 — first canon row, batch-100 | AT-B100-01 · TC-B100-01..03, -57, -62, -68 | pass |
| HLR-164 (Save project refuses unsafe names, leaves nothing behind) | v1 | AT-B100-02 · TC-B100-04..07 | pass |
| HLR-165 (a project load starts from an empty session) | v1 | AT-B100-03 · TC-B100-08..11 | pass |
| HLR-166 (focus lands on a named, visible, non-text widget) | v1 | AT-B100-04 · TC-B100-12, -13 | pass |
| HLR-167 (Save project saves source + change document, verified) | v1 | AT-B100-05 · TC-B100-14..17, -58, -59, -69, -70 | pass |
| HLR-168 (a save-back becomes the active variant) | v1 | AT-B100-06, -20 · TC-B100-18..20, -71 | pass |
| HLR-169 (Load opens what is valid and lists every problem) | v1 | AT-B100-07 · TC-B100-21..27, -60, -61 | pass |
| HLR-170 (the change document is saved and reopened) | v1 | AT-B100-08 · TC-B100-28..30 | pass |
| HLR-171 (Save as copies the whole project) | v1 | AT-B100-09, -10, -11 · TC-B100-31, -32, -33, -62 | pass |
| HLR-172 (recent sources are remembered per user) | v1 | AT-B100-12, -13 · TC-B100-34..39, -63 | pass |
| HLR-173 (one Load dialog lists everything that can be loaded) | v1 — supersedes batch-97 HLR-151 (Inc 9b) | AT-B100-14 · TC-B100-40..43, -63, -64, -66 | pass |
| HLR-174 (one question before an image-replacing route) | v1 | AT-B100-15 · TC-B100-44..46, -72 | pass |
| HLR-175 (the Save dialog shows exactly what the save will do) | v1 | AT-B100-16, -21 · TC-B100-47..49, -65 | pass |
| HLR-176 (a long action shows a progress line when it begins) | v1 | AT-B100-17 · TC-B100-50, -51, -73 | pass |
| HLR-177 (project load / Save / A2L parse run on workers) | v1 | AT-B100-18 · TC-B100-52..54 | pass |
| HLR-178 (the Load-result panel says which variant opened and lists the problems) | v1 | AT-B100-19 · TC-B100-55, -56 | pass |

The 26 sub-HLRs (HLR-171a/b, 172a/b, 173a–e, 174a–d, 175a–f, 176a–d, 177a–c) each carry their own arms in `04-validation.md` Layer A. Per-row verdicts there: `378` of `391` requirement rows pass on the Windows evidence; `13` rows (6 LLR, 7 HLR) are decided by the gate run, which this close reports as no new product defect (above).

**Visible behaviour change.** One Load dialog replaces the old Load file / Load project dialogs. The Save project dialog paints, before Save, exactly what will be written, renamed, kept or refused. A progress spinner with elapsed time and a moving bar shows on project load, Save project and A2L parse; a second request is refused while one runs, and quit asks first. The Load-result panel names the opened variant, why, and every problem.

**What worked, what didn't, root causes:** `05-postmortem.md` (Synthesis first, then Part A — architect — and Part B — qa-reviewer).

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|
| *(candidate, not minted)* QC-TM — a timing arm reports its margin and stops its clock on a product event | wall-clock 1 s bounds measuring the wrong interval, or hiding a real slowdown | R1-P1 (Save project at 0.75–1.0 s against a 1 s bound since Inc 12b) and R-1's TC-05 clock (`05-postmortem.md` Part B §7) |
| *(candidate, not minted)* QC-OR — a status oracle reads every line the action painted, not the newest | oracles that read only the newest painted line | R-3 (3 nodes) and CI12a-1 (AT-B100-01), both broken when 12a re-ordered the end line |
| *(candidate, not minted)* QC-BC — a behaviour census at every increment that re-orders an observable | a changed observable leaving a stale test in a module the selection never ran | CI11-4 (TC-59), R-2 (CSS arm), R-3 (12a) |
| *(candidate, not minted)* a gap list of unrun tests at every increment gate | a test neither in the increment's selection nor run by CI | R-2, the CSS arm, red from Inc 9b to fix round 2 and skipped on CI (`05-postmortem.md` Part A, Control lineage) |

**The four landings — record which ones actually happened. Command-but-not-template is *half-encoded*, and the missing half is the enforceable one:**

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** (`commands/…`) — the rule itself | n/a — no control minted | |
| 2 | its **artifact** (a template section) — a control with no output degrades to "I thought about it" | n/a — no control minted | |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | n/a — no control minted | |
| 4 | **committed and pushed**, manifest re-hashed and bumped | n/a — no control minted | |

- **New controls:** `none — no control minted at this close: four are proposed with measured origins (QC-TM, QC-OR, QC-BC in 05-postmortem.md Part B §7, and the gap list of unrun tests in Part A Control lineage); adoption is the next gate's decision`

---

## 3 · Working-file reconciliation (C-44)

Sweep run 2026-11-01: `git status --short` and `git log main --not --remotes` in `<HOME>\Github\s19_app-b100-close`, the only repository the batch touched. The flow bundle and the Kimi config were read, not edited.

| File | State | Evidence |
|---|---|---|
| `s19_app/**`, `tests/**` | ✅ committed **and landed** — pushed to `main` at each increment close (no PR, the standing authorization's Git answer) | the 16 increment merges, then the fix-round commits `dee0d96` (fix round 1), `677435e` (fix round 2), `d460190` (fix round 3, tests only) |
| `.dev-flow/2026-10-26-batch-100/**` (contract, ledger, review, PDR, packets, evidence, validation, post-mortem, UX inspection) and `docs/architecture.md` | ✅ committed **and landed** on `main` | the increment close commits, then `0063a78` (close part 1), `2451fb4` (close part 2), `365e018` (close part 3), and the deliverable commit of this close |
| `pyproject.toml`, `s19_app/version.py` | 📋 modified, not yet committed — the `1.0.0rc1` version bump of the release decision (2026-11-01) | `git diff` shows `0.1.0` → `1.0.0rc1` in both files; to land in the deliverable commit |
| `evidence/batch-end/linux-gate-f72eef1-*.txt` | 📋 untracked — the gate-run evidence this close reports | §0; to land in the deliverable commit |
| worktrees `s19_app-b100-fix1`, `s19_app-b100-fix2`, `s19_app-b100-fix3`, `s19_app-b100-close` | 🗑️ / active — each increment worktree was removed at its merge; `b100-close` is this record's worktree | `git log --oneline 1d677ba..HEAD` |
| `prototypes/` | 📋 left on purpose — untracked, never staged by rule | — |

- **Found before the batch:** `none — no tracked file was modified when the batch began`

### Conditional-gate discharge

- **Conditional-gate discharge:** `all discharged — the P2 gate closed conditionally (bounded round 3, conditions carried to PDR) and the PDR gate closed conditionally (approved with conditions); each was discharged and re-checked, except C-UX-9 (the Load dialog hint line), which stayed open and is routed to the backlog`

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|
| P2 round-3 bounded conditions (UX-22, UX C-1/C-2, ARCH C-1..C-5, SEC PDR-C1..C3, PDR-QA-1/2) | ✅ | `02-review.md` Round 3 ("approved", 0 HIGH open); folded into `design/PDR-2026-10-26-batch-100.md` |
| PDR conditions C-UX-1/C-QA-1 (the `a2l.py` named crossing), C-UX-2/4/7/8, C-QA-2/6, ARCH-PDR-1..5 | ✅ all | `design/PDR-2026-10-26-batch-100.md` §Conditions — contract applied by ledger entries LED .35–.48 before the increment each one names (`01-requirements-ledger.md`) |
| C-QA-3 (whole-tree guards + `-k census` at every increment gate) | ✅ with the recorded erosion at Inc 9b (3 modules run) | `increment-018.md:131-134`; `05-postmortem.md` Part A *The guard set shrank at Inc 9b* |
| C-UX-5 (a Phase-4 expert-inspection row) | ✅ | `04-ux-inspection.md` (G-001 discharged; `PASS-WITH-NOTES`, 0 blocker) |
| C-UX-9 (the Load dialog hint line, owed at Inc 9b) | ❌ — still open, routed to the backlog | `04-ux-inspection.md` UX-I-14 ("C-UX-9 is undischarged") |

---

## 4 · Backlog reconciliation — the carry-over contract

| Item | Move | Reference |
|---|---|---|
| 15 `✅ CLOSED` rows in the batch-100 section | ✅ marked CLOSED in place, each with its increment and evidence | `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-26 — batch-100 P2 round 1* (on `0063a78`) |
| The open batch-100 rows (59, listed below) | carried forward | same section |
| P4 gaps not yet routed to the backlog | carried forward | `04-validation.md` *Gaps detected*: G-005, G-007, G-008, G-013 |
| UX inspection findings | routed per the orchestrator ruling (2026-11-01) | `04-ux-inspection.md` §Routing proposal |
| Release decision (operator, 2026-11-01) | tag `v1.0.0-rc1` at this close; batch-101 "release hardening" takes the 51 user-guide findings and the 5 UX majors; v1.0.0 after batch-101 | `docs/user-guide/DOSSIER.md` §5 (branch `b100-release-assets`); `04-ux-inspection.md` |
| Header | refreshed: last refresh 2026-11-01, batch-100 close | `.dev-flow/BACKLOG-CODE.md` header |

**The 59 open `▸` rows in the batch-100 section** (`grep -c '^- \*\*▸'` over `### 🆕 Routed 2026-10-26 — batch-100 P2 round 1 (Load + projects)`), R1-P1 first:

`R1-P1` · `SR12b-7` · `SR12b-7b` · `OBS-F2-1` · `R2-CI` · `PR-6` · `SEC8a-2` · `R19` · `A-R14` · `R-12` · `tc_b97_64 (known CI flake)` · `A-01` · `pre-existing defect (Inc 5, open-project own-A2L save refusal)` · `B-12` · `SEC-3` · `explicit-root threading (workarea_root, Inc 1)` · `R3-4` · `hardening notes (Inc 1 round 4)` · `SEC7-4 (b)` · `R2-3 (Inc 7)` · `R2-1 (Inc 8a)` · `R2-2 (Inc 8a)` · `F7(b)/R-7` · `F4` · `F5 remainder` · `R2-1 (Inc 8b r2)` · `R2-2 (Inc 8b r2)` · `TOCTOU hand-off` · `OBS-8b-1` · `OBS-8b-2` · `OBS-8b-3` · `A3-15` · `A3-17` · `R12 cost` · `CR9-1` · `CR9-2` · `CR9-5 / SEC9-8` · `CR9-11` · `SEC9-5 (part)` · `OBS-9a-1` · `Q6` · `S9b-5` · `A9b-R3-3` · `_COLLIDING_PATH` · `CR9b-05` · `UX loss (9b linked A2L)` · `SEC9b-1 redirect` · `stale doc (architecture.md:670)` · `OBS-9b-1` · `Q7` · `Q8` · `S10-04 + SEC10-02` · `G-B F-4` · `A11-03` · `SE5-11-2` · `O-1` · `SE5-12a-2 / O-12a-1` · `SR12b-6` · `R2-F2`

The four not-yet-routed P4 gaps (`G-005`, `G-007`, `G-008`, `G-013`) and the UX backlog rows from `04-ux-inspection.md` (the 11 minors + 4 cosmetics, plus the UX-I-12 list-label half) are the orchestrator's routing at this close; the five UX majors (UX-I-01, UX-I-06, UX-I-10, UX-I-12 preview half, UX-I-13) and the UX-I-17 ruling move to batch-101's release-fix increment, as do the 51 user-guide findings.

---

## 5 · Batch metrics — the 13 keys of `core`

Extract, do not invent: a key the artifacts did not record goes `null`, and the key is never dropped.

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-10-26-batch-100
mode: full
verdict: PASS-WITH-NOTES
increments: 16
source_files_max: 5
notices_raised: 15
rework_returns: 35
triggers_fired: "A2,A3,B1,B4,C6,C8,D1,E1,E2"
tests_base_to_post: "3773 -> 5254"
new_control: "proposed: QC-TM, QC-OR, QC-BC (05-postmortem.md Part B §7) and Part A's gap list of unrun tests — adoption is the gate's decision"
open_items_next: 59
```

- `verdict: PASS-WITH-NOTES` — copied from `04-validation.md`'s `Result` line (the gate run on `f72eef1` closed with the 5 known pre-existing failures plus the 13 timing arms that pass serially / alone, so no new product defect).
- `increments: 16` — 15 planned + hotfix 3b = 16 packets (1–7, 3b, 8a, 8b, 9a, 9b, 10, 11, 12a, 12b).
- `source_files_max: 5` — Inc 8b, operator-approved on 2026-10-31; the only cap breach in the batch.
- `notices_raised: 15` — distinct NOTICE ids declared in `PLAN.md` §*Gate notices and runtime absences* (V34, V36, V37, V38, V41, V43–V51, V54).
- `rework_returns: 35` — P2 iterate rounds 2 + P3 code re-rounds (Inc 1–7 + 3b: 23 rounds over 8 packets) + 4 (8a–12b: 12 E5 rounds over 8) + E3 re-rounds 12 (20 rounds over 8) + 2 batch-end fix rounds (`05-postmortem.md` §8).
- `triggers_fired` — `state.json` `triggers.fired`; Part A finds A4 should have fired (stacked lanes, Record corrections).
- `tests_base_to_post` — collected nodes, Windows, `pytest --collect-only` (qa-reviewer): base 3 773 (`1d677ba`) → 5 254 (`570b4b5`).
- `new_control: proposed (…)` — none minted; four proposed with measured origins, adoption is the next gate's decision (§2).
- `open_items_next: 59` — open `▸` rows in the batch-100 section of `.dev-flow/BACKLOG-CODE.md` (§4), plus 4 not-yet-routed P4 gaps (G-005, G-007, G-008, G-013) and the UX backlog rows that batch-101's release hardening takes.
- Findings: P2 86 + 58 (3 rounds) · P3 code/security gates ≈237 raw (≈20 HIGH raw, 18 deduplicated) · E3 design-stage 47 MAJOR · E5 711 mutant rows (8a–12b) · battery 71 failed / 5 162 passed on `9e4dd3b`, 7 real after alone re-runs · 2 fix rounds + 1 fix round 3 (tests only).
- **Declared NOT done:** evaluation with real users (ISO 9241-210; "one operator"); an expert inspection in a real Windows Terminal (headless SVGs only — `04-ux-inspection.md` Limit); the whole suite on Windows after the fix rounds (the gated tree is covered by the Linux gate + partial runs, G-003); the posix arms confirmed only by CI.

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| Decision page `design/plan-b100.html` (D1–D7) | P0 approved (`state.json` decisions_log) | ✅ | `light` | the options not chosen; all seven answers took the recommended option (`design/veredicto-b100.json`) |
| Prototype verdict `design/veredicto-load-projects.json` (P-A..P-E) | P2 approved (`02-review.md`) | ✅ | `light` | the variants not chosen; every slot took the shown option |
| `01-requirements.md` contract | P2 approved, 3 rounds | ❌ | `none — the operator answered the decisions and rulings instead` | the contract text |
| Increment packets and code | reviewer verdicts in each packet §4b | ❌ | `none — read the status summaries instead` | not audited line by line |
| `04-validation.md`, `05-postmortem.md`, `05-close.md`, `04-ux-inspection.md` | qa-reviewer / ux-reviewer verdicts | ❌ | `none — written at the close; the operator reviews them at the close packet` | |

- **Human perimeter:** what to build and in what order; the iteration-cap rulings (the bounded passes and the "Lista exacta" redesign); the per-increment test-scope override (LED .75 and the 2026-10-31 override); the release decision (tag `v1.0.0-rc1` at this close and the batch-101 scope); whether the visible Load/Save/progress changes match the operator's real tools and data.
- **Human review ledger:** `human:operator — 2 artifact(s) reviewed, 0 rigorous · 3 declared not-reviewed` (depths read off the decision records by the close writer; the operator corrects them if they differ)

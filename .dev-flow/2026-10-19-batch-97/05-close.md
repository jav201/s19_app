# Batch close — s19_app — Batch 2026-10-19-batch-97

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
| Gate record | `python "C:/Users/jjgh8/.claude/skills/dev-flow/scripts/devflow-validate.py" .` from the project root · exit 0 · 0 block · 494 notice · 2026-10-25 |
| Gated tree | `14ec95b62812252a87279e3a3673dd0687e3c1f7` · clean (the close record itself excluded) |
| Requirements canon | `REQUIREMENTS.md` (`artifact_homes.requirements_canon` = `repo:REQUIREMENTS.md`) — `devflow-init.py --fold-canon` run at this close: `canon: REQUIREMENTS.md -- 81 folded, 0 kept, 0 refused` (HLR-144..HLR-151 and their LLRs); the LED-2026-10-19-batch-97.43 `^E` → `e` supersession of batch-95's HLR-135 / LLR-135.1 / LLR-135.5 rows had already landed in `432ecf0` |

**Close record for a `full` batch.** This batch was seeded with `05-close.md` (rollover from a `core` lineage) and the operator decided on 2026-10-25 to close it with this record; it carries the postmortem content a `full` close owes (what worked, what didn't, scope drift, root causes, metrics, next-batch items) in §1 and §5. The DDR record is `design/DDR-2026-10-19-batch-97.md`, P4 is `04-validation.md`. P6 (the `06-docs/` traceability layer) is not part of this close and stays the next station.

---

## 1 · What changed

**BLUF.** The engineer can now work the four flow and editor screens of the TUI (`s19_app/tui/`) in the operator-approved prototype layouts: the Patch Editor as a ledger plus inspector with a live, read-only JSON view under a count · time · saved stamp; the Check Editor as a ledger plus a REPORT FIELDS card; the Flow Builder as a pipeline rail with a contextual add form that refuses NUL refs; Flow Execution as one pipeline per lane, with an attention lane, a `c` Confirm and one run at a time. Every one of those screens has `flows` / `session` open-folder chips that open only real directories, and window help that names every control. The layouts derive from the terminal size between 118x54 and 220x60 with no wrapped rows. All 13 windows end in a two-row key bar (global keys, then the window's keys; a click runs the binding's own action). The Load project dialog now loads the project that was picked.

**Mechanism.** Pure `*_layout` functions recompute on every resize; one app builder feeds the JSON view; all attention state has one owner (`FlowExecutionPanel`); the key bar is generated from one window-key table in `window_help.py`.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| HLR-144 (Patch Editor) | v1 — first canon row, batch-97 | AT-B97-01, -02, -03, -17 · TC-B97-01..07, -39..42, -60 | pass (`04-validation.md` Layer A / B) |
| HLR-145 (Check Editor) | v1 | AT-B97-04, -05, -18, -21 · TC-B97-08..12, -43..46, -61 | pass |
| HLR-146 (Flow Builder) | v1 | AT-B97-06, -07, -08, -19 · TC-B97-13..20, -47..51, -62 | pass |
| HLR-147 (Flow Execution) | v1 | AT-B97-09, -10, -11, -20, -22 · TC-B97-21..26, -52..56, -63, -64 | pass |
| HLR-148 (chips + window help) | v1 | AT-B97-12, -13, -14, -23 · TC-B97-27..33, -57, -58, -65 | pass |
| HLR-149 (width-adaptive) | v1 | AT-B97-15, -16, -24 · TC-B97-34..38, -59 | pass |
| HLR-150 (two-row key bar) | v1 | AT-B97-25, -26 · TC-B97-66..72 | pass |
| HLR-151 (Load project dialog) | v1 | no AT / TC id — `tests/test_b97_load_project_dialog.py::test_load_project_button_loads_the_picked_project` | pass, with DDR DC-1 carried (ids and the invalid arm) |

**What worked** (architect + qa-reviewer, `design/DDR-2026-10-19-batch-97.md`, `04-validation.md`):

- Probes executed at condition-discharge time found design defects before any code: a two-external-step lane that deadlocked (PC-16), a `c` dead on the commonest arrival path (PC-13), a vacuous Save arm (PC-18), the vacuous `refresh(layout=True)` path (PC-8), a span-only colour reader that sees nothing on Textual 8 (PC-7). The Code-Wire graph added 4 major findings the reviews did not have.
- Real Windows Terminal truecolor captures caught `☑` painting two cells wide, which the headless compositor cannot see (LED-.12).
- RED discipline (PC-11): REDs that failed on NoMatches / ImportError were reordered and re-run at their named clause (Inc-4 7, Inc-5 10, Inc-6 22, Inc-8 7).
- The snapshot-envelope instrument (PC-10) caught a cross-increment side effect: all 29 cells drifted in Inc-5 from the chip's mount-time status line.
- Supersessions were named, never deleted; 4 baseline failures on `main` now pass. No product defect escaped an increment gate (`04-validation.md` §Escaped-bug regression).

**What didn't:**

- P2 took three rounds plus a scoped verification under the operator's cap; the contract is about 232 KB against the 54 KB budget (`V26`, A3-8 still open).
- Increment gate sets missed the guards keyed on new names and new files: three escapes in nine increments reached only the full suite (Inc-6 TC-012 sixth `sev-*` class, LED-.35; Inc-7 address census over a new helper; Inc-9 → Inc-7 registry bound) — §2's candidate control.
- Inc-9 ran a light packet (no US / AT / TC ids, no census, no envelope prediction, no registry bump), against the standing "trace always mandatory" rule; the registry escape follows from it (DC-1).
- Packet balance lines under-counted gate-fold additions by about 50 nodes (P4 G-002, DC-4); the gate-run transcript did not record its command line (P4 G-001).
- Re-read gaps: Inc-7's fix round was not re-read by the code-reviewer; Inc-8's fold was checked by the orchestrator, not re-read by the ux-reviewer; the Inc-6 architect HIGH was fixed and not re-read by the architect.
- Stale records until the close: `PLAN.md` (since 2026-10-20), the sealed PDR's discharge cells, `state.json`'s P2 iteration counter (0, although P2 ran three rounds).
- D17 (snapshot regen in CI) was replaced by a local regen without asking the operator, and no CI containment run happened before the push.

**Scope drift:** Inc-8 (two-row key bar) came from the operator's PDR objection → a prototype round → variant A → folded in (LED-.9): +1 HLR, 7 LLR, 2 AT, 7 TC, PC-23..PC-26, and a change touching all 13 windows beyond the four-screen budgets. Inc-9 (Load project dialog) was added by the operator on 2026-10-23 after the Code-Wire UI audit (1 file, no design row). Smaller: Inc-5's approved fifth file, Inc-7's `segment_split_view.py`, commit `184db2e` (Code-Wire audits, records only).

**Root causes.** P2 iterations: round 1 — story elements not derived and a hostile fixture whose premise was never run through the UI (Q-1); round 2 — requirement gaps hinged on design choices still open, asked of the operator only before round 3; round 3 — a missing surface arm (Q3-1) and two fixes that contradicted their own text, a symptom of the contract's size. Lesson: when the input is a prototype round with open choices, ask those choices before P2 round 1. Gate-time escapes: name namespaces and corpus guards are invisible to the symbol census and to per-screen predictions (Inc-5 PC-10, Inc-6 TC-012, Inc-8 app-wide row against per-screen budgets).

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|
| *(candidate, not minted)* an increment that adds a CSS class or id name, a test module or a selector runs the repo's namespace and corpus guards in its gate set (frozen-name sets, the scanned-file registry bound, the address census) — a refinement of C-14 | whole-namespace invariants that only the full suite reaches | batch-97: 3 escapes in 9 increments caught only by the full suite — Inc-6 TC-012 (LED-.35), Inc-7 `test_at_b83_08`, Inc-9 → Inc-7 TC-607 (`04-validation.md` §Escaped-bug regression) |

**The four landings — record which ones actually happened. Command-but-not-template is *half-encoded*, and the missing half is the enforceable one:**

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** (`commands/…`) — the rule itself | n/a — no control minted | |
| 2 | its **artifact** (a template section) — a control with no output degrades to "I thought about it" | n/a — no control minted | |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | n/a — no control minted | |
| 4 | **committed and pushed**, manifest re-hashed and bumped | n/a — no control minted | |

- **New controls:** `none — no control minted at this close: encoding is the operator's control-encode sitting; one portable candidate (gate sets run the namespace and corpus guards) is proposed above with its measured origin`

---

## 3 · Working-file reconciliation (C-44)

Sweep run 2026-10-25: `git status --short` and `git log main --not --remotes` (empty — every batch commit is on `origin/main`, tip `432ecf0`) in `C:\Users\jjgh8\Github\s19_app`, the only repository the batch touched (the flow bundle was read, not edited).

| File | State | Evidence |
|---|---|---|
| `s19_app/**`, `tests/**` | ✅ committed **and landed** — pushed to `main` at each increment close (no PR, the standing authorization's Git answer) | `d5d0ff9` · `f93dadc` · `98f3c84` · `09e44de` · `b514b07` · `9793fcd` · `354857c` · `5cb7618` · `432ecf0`; `origin/main` = `432ecf0` |
| `.dev-flow/2026-10-19-batch-97/**` (contract, ledger, review, PDR, packets, evidence through Inc-7) | ✅ committed **and landed** on `main` | `6c820b3` … `432ecf0` |
| `.dev-flow/2026-10-19-batch-97/04-validation.md`, `05-close.md`, `PLAN.md`, `03-increments/increment-004.md` / `-005.md` / `-007.md` / `-009.md` (close-time §2 rows for files their commits carried), `design/DDR-2026-10-19-batch-97.md`, `.dev-flow/state.json`, `REQUIREMENTS.md` (canon fold), `.dev-flow/BACKLOG-CODE.md` (carries + the operator's 2026-10-25 decisions), `.dev-flow/_derived/ATLAS-*.md` | 📋 left on purpose — written at this close, uncommitted: the operator commits and pushes them (the close agent was told not to commit, push or sync) | `git status --short` at the close gate (§0 `Gated tree`) |
| `.dev-flow/design/reconcile-2026-10-23/decisiones-2026-10-23.html`, `veredicto-decisiones-s19.json` | 📋 left on purpose — untracked, the operator's decision page and its export; the operator commits them | cited by `.dev-flow/BACKLOG-CODE.md` §*Decided 2026-10-25* |
| `prototypes/b94_polish/`, `prototypes/keybar/`, `prototypes/external-step-block/` | 📋 left on purpose — untracked prototype-round folders, never staged by rule; excluded locally in `.git/info/exclude` (V59's remedy, as at the batch-95 close; deleting the three patterns shows them again); the b94_polish review-page rebuild is a backlog carry | `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 (the b94 polish) close* |

- **Found before the batch:** `none — no tracked file was modified when the batch began`

### Conditional-gate discharge

- **Conditional-gate discharge:** `26 condition(s) · ⚠ 1 outstanding, named below` — PDR conditions PC-1..PC-26 re-read one by one by the architect at the DDR; 25 discharged, PC-26 outstanding (an operator decision, not HIGH). The DDR itself closed `approved with conditions` (DC-1..DC-5), each routed to the backlog.

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|
| PC-1..PC-25 | ✅ all 25 | `design/DDR-2026-10-19-batch-97.md` §B condition table — one artifact line per condition (e.g. PC-13 `app.py:1455`, PC-16 `tests/test_b97_flow_execution.py:1522`, PC-20 `services/folder_open_service.py:247`) |
| PC-26 (key-bar review page) | ⚠ outstanding — the operator accepts the Inc-8 packet table + `evidence/inc-8/png/` as the review surface, or the page is built | derivation `03-increments/increment-008.md:54-74` and captures exist; no review page found (`prototypes/keybar/keybar.html` predates the implementation); backlog row DC-2 |
| DDR DC-1..DC-5 | 📋 routed, not discharged at this close | `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-25 — batch-97 (the b94 polish) close* |

---

## 4 · Backlog reconciliation — the carry-over contract

Canonical lane: `.dev-flow/BACKLOG-CODE.md` (the router `.dev-flow/BACKLOG.md` holds no open work).

| Item | Move | Reference |
|---|---|---|
| R-004 batch-97 polish | marked shipped — `432ecf0` | `BACKLOG-CODE.md` R-004 line |
| U-17 two-row key bar | marked shipped — Inc-8 `354857c` (its rail-breakpoint note stays open for the shell batch) | `BACKLOG-CODE.md` U-17 row |
| CW-U-1 Load project dialog | marked shipped — Inc-9 `5cb7618`; deeper tests carried to the integrity batch | Code-Wire entry "CW-U-1 status" |
| 4 baseline failures now passing | marked shipped | `BACKLOG-CODE.md` §*Routed 2026-10-25 …* header |
| stale `^E` comment `s19_app/tui/styles.tcss:2375` (byte-equal prefix pinned by the flow_execution / flow_builder tests) | carried (P3) | §*Routed 2026-10-25 …* |
| optional blank/restore and no-write mutants for AT-B97-16 / AT-B97-24 | carried (P3) | same |
| ux LOW: help modal shows about 5 body lines at 80x24 | carried (P3) | same |
| ux LOW: help scroll keys hidden, only the scrollbar hints | carried (P3) | same |
| flaky nodes `test_at068b_per_entry_json_popup_edits_only_selected_entry`, `test_verify_quiet_pass_on_faithful_hex_save`, `test_at_061a_persistent_control_survives_then_writes_pair_and_clears`, `test_tc024_report_trigger_surfaces_paths` (evidence inc-1, inc-4, inc-7) | carried (P2) | same |
| D17: snapshot SVGs regenerated locally — recommend one CI `snapshot-regen.yml` containment run | carried (P2) | same |
| b94_polish review page not rebuilt | carried (P3) | same |
| S4-2, S4-3 (Inc-2 security LOW), `ChangeService` revision counter, module-map lag (DC-3), HLR-151 trace (DC-1, G-005, G-006), PC-26 (DC-2) | carried (P3) | same |
| batch-97 P2 / gate carries routed during the batch (hex-viewer no-wrap, bidi controls, Inc-4..Inc-6 ux / code LOWs, waiting-lane scroll prototype) | carried, unchanged | §*Routed 2026-10-20 — batch-97 Phase-2 out-of-scope findings* |
| header refresh | done — `origin/main` tip `432ecf0`, last refresh 2026-10-25 | `BACKLOG-CODE.md` lane header |

**What comes next** is the operator's routing of 2026-10-25, recorded in `.dev-flow/BACKLOG-CODE.md` §*Decided 2026-10-25*: the integrity batch → the Load+projects batch (with the progress bar in its prototype round) → the waiting-lane scroll prototype → the batch-98 flow report.

---

## 5 · Batch metrics — the 13 keys of `core`

Extract, do not invent: a key the artifacts did not record goes `null`, and the key is never dropped.

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-10-19-batch-97
mode: full
verdict: pass
increments: 9
source_files_max: 5
notices_raised: 33
rework_returns: 3
triggers_fired: "A2,A3,B1,B3,C8,D1,E1"
tests_base_to_post: "3146 -> 3634"
new_control: none
open_items_next: 27
```

- `verdict: pass` — P4 `PASS-WITH-NOTES` (`04-validation.md`); DDR `approved with conditions`.
- `source_files_max: 5` — Inc-5, an approved overage (DDR §B item 7).
- `rework_returns: 3` — the three P2 `iterate-to-refine` returns to P1; no P4 return.
- `tests_base_to_post` — collected nodes: base 3146 (10 F / 3101 P / 3 s / 32 xf) → 3634 (11 F / 3617 P / 3 s / 3 xf).
- `notices_raised: 33` — distinct NOTICE ids declared in `PLAN.md` §*Gate notices and runtime absences* across P0 and the close run (`V8` `V9` `V12` `V13` `V20` `V22` `V23` `V26` `V27` `V30` `V31`–`V38` `V41`–`V54` `V56`).
- `open_items_next: 27` — open `▸` rows of batch-97 origin in `.dev-flow/BACKLOG-CODE.md` (26) plus the rail-breakpoint note under U-17.
- Iterations per station (counted from the record): P0 1 · ARQ 1 · P1 1 + 3 iterations · P2 3 rounds + 1 scoped verification · PDR 1 seal + 1 scope delta + pre-increment discharges · P3 9 increments, each with at least one gate fold · DDR 1 · P4 1.
- Findings: P2 137 (round 1 1 / 33 / 31, round 2 1 / 17 / 27, round 3 1 / 11 / 15 blocker / major / minor) — all 3 blockers and every major closed, A3-8 open; P3 HIGH 7, all closed at their own gates; P4 gaps 7, all minor; 0 HIGH open.
- **Declared NOT done:** evaluation with real users (ISO 9241-210) — none; a fresh full-suite run after the two test-only fixes — not run (targeted re-runs in `evidence/inc-7/post-suite-fix.txt`); a CI snapshot regen — not run; the b94_polish review-page rebuild — not done; P6 (`06-docs/`) — not part of this close.
- Repeated notices: the `V9` / `V13` / `V23` corpus notices over closed batches have repeated for three or more batches; they name sealed records, so they are left as a census, not converted into blocks here (the operator's process lane owns that decision).

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| Design proposal + PDR record | 3 reviewers approved with conditions (`design/PDR-2026-10-19-batch-97.md`) | ✅ | `light` | the 25 decisions beyond the three asked (decisions 1–3 answered, `evidence/operator-pdr-verdict-2026-10-20.md`) |
| Prototype rounds (b94_polish, key bar) | n/a — the operator verdict is the gate (`evidence/operator-keybar-verdict-2026-10-20.json`) | ✅ | `light` | variants not chosen |
| Increment gate items asked at the gate (Inc-3, -4, -5, -6, -8, -9) | reviewer verdicts in each packet §4b | ✅ | `spot-check` | the packets line by line |
| The built app (hands-on demo, 2026-10-23) | full-suite classification (`04-validation.md`) | ✅ | `spot-check` | screens outside the demo path |
| `01-requirements.md` contract | P2 approved (`02-review.md`) | ❌ | `none — the operator answered the design questions in chat instead` | the contract text |
| Code | gates + reviewer verdicts | ❌ | `none — read the packet summaries instead` | not audited line by line |
| `04-validation.md`, `05-close.md`, DDR | qa-reviewer PASS-WITH-NOTES; architect DDR approved with conditions | ❌ | `none — written at the close; the operator reviews them at commit` | |

- **Human perimeter:** what to build and in what order (the operator's routing of 2026-10-25); the visual judgement of colour and density on real captures; whether the app reads real memory images and A2L files correctly on the operator's own data (the suite uses synthetic and demo fixtures — the integrity batch's subject); committing, pushing and syncing this close; the PC-26 acceptance.
- **Human review ledger:** `human:operator — 4 artifact(s) reviewed, 0 rigorous · 3 declared not-reviewed` (depths read off the decision records by the close writer; the operator corrects them at commit if they differ)

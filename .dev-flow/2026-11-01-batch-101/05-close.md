# Batch close — s19_app — Batch 2026-11-01-batch-101

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
| Gate record | `python -I <HOME>/.claude/skills/dev-flow/scripts/devflow-validate.py --brief .` from the worktree root · exit 1 · `218 block · 1304 notice · 47 not applicable` · 2026-11-07 — the 218 blocks are **not in the close records**: 153 × V59 (the branch was rebased after init; `state.json` `base_ref` still reads `7717394`, owed a re-stamp to `15e90c4e`) and 65 × V22 (the requirements canon fold-back, owed to the requirements session — `devflow-init --fold-canon` folded 0 and refused the 2 template rows). Zero blocks name `04-validation.md`, `05-close.md` or `BACKLOG-CODE.md` |
| Gated tree | `b982846ce33ccc20b1774f91b1091af4b42dff73` · clean — this close adds records only; `main` `15e90c4eea6a2968654b9b400ed636dd729d8bc7` adds the batch-end battery evidence and the atlas regeneration over `b982846`, no product file |
| Requirements canon | `REQUIREMENTS.md` (`artifact_homes.requirements_canon` = `repo:REQUIREMENTS.md`) — the strict-EARS canon (replaced by Inc 1, `6a4eadb`); every increment's rows cite its ids. The batch-level `01-requirements.md` is the **template**, so the canon fold is a **hand-over** to the requirements re-write session: `close/FORWARD-requirements-session.md` (273 rows) |

**The gate run whose result this close reports.** The batch-end battery on `b982846` (`evidence/close/full-suite-final.txt`): lane 1 `-n 12 -m "not serial_timing"` → **6 failed / 6113 passed / 182 skipped / 4 xfailed** in 3540 s; lane 2 `-m serial_timing` → **69 passed / 2 skipped**, **QC-TM 95 bounds, 0 under 20 % margin**; combined `exit=0`. The 6 split as **4 known failures** (`test_at_b78_03`, `test_at_056e_a2b`, `test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` / `[120x30]`) plus **2 `test_tc_b100_53` load flakes** under `-n 12` that pass alone 2/2 on the same tree. No new product defect. Sibling batteries on the same tree: snapshots `evidence/close/snapshots-final.txt` (31 passed + the 2 known), doc-pass guards `evidence/close/docpass-guards.txt` (196 passed), Inc 6 Windows arms `evidence/close/win-inc6-final.txt` (82 passed, node ids — closes Inc 6 RA-4), and the Inc 5 mutant re-run `inc-5/E5-mutants.md` "Batch-end re-run on the final tree" + `evidence/close/inc5-mut-*.txt` (24/24 killed — closes Inc 5 RA-1).

**⏸ DEFER** — the requirements canon fold: `devflow-init --fold-canon` **folded 0** rows and **refused the 2 template rows** of `01-requirements.md`. The fold into `REQUIREMENTS.md` is the requirements re-write session's act (its hand-over document is `close/FORWARD-requirements-session.md`, 273 rows), not this batch's.

**Close record for a `full` batch.** This batch closes `full` batches with `05-close.md`. It is a release-hardening batch: the post-mortem content a `full` close owes is not produced here (no separate `05-postmortem.md` was authored in this batch — the increments' own `04-validation.md` and the review page `close/review-b101.html` carry the analysis).

---

## 1 · What changed

**BLUF.** v1.0.0 becomes releasable on its non-UI defects: the strict-EARS canon (`REQUIREMENTS.md`) replaces the old canon and every later increment cites its rows; the test suite runs reliably in parallel with the timing arms run apart (serial_timing lane, QC-TM margins, shared waits, CI xdist); documents resolve `symbol` entries against the loaded/project A2L instead of refusing them; the CRC Designer refreshes after every in-place write and stays responsive on the 10 MB demo image; diff and before/after reports write full hex windows, escape hostile names and write atomically; flow and chain-set saves are contained inside the work area with a post-claim check; A2L parsing recognises the ASAM block names; dead surfaces are removed and Escape closes the Reports viewer; the help, legend and README describe the shipped app; and stale documentation is corrected or archived.

**Mechanism.** Sixteen increments (the 10 and 12 each split into a/b) through the design-first E1→E5 pipeline, one `app.py`-chain writer at a time, with QC-BC (a behaviour census at every E5) guarding observables, QC-TM (margin reporter) guarding the timing bounds, and QC-OR (status oracle) guarding the painted status lines. The canon swap (Inc 1) is delivered by the requirements re-write session on `b101-canon`. The operator's 2026-11-06 order replaced the per-increment full suite with partial merge verification; the full suite ran once at batch end.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| Inc 1 — strict-EARS canon swap + TC records | v1 (canon swap) | canon guards RED 11/11 · GREEN 11/11 | pass |
| Inc 2 — test hygiene: serial_timing lane, QC-TM margins, shared waits, CI lanes, redaction gate | v1 | hygiene RED 54/54 · GREEN 65/65 | pass |
| Inc 3 — gather once per name, no folder re-creation, paint-timing verifiers | v1 | R-PROJ-GATHER.* · R-TST-110..113 | pass |
| Inc 4 — documents resolve symbols through the loaded A2L | v1 | R-CHG-SYM.9..12 | pass |
| Inc 5 — CRC Designer refresh after in-place write + Check Editor picks/spec bytes | v1 | R-CRC-DESIGNER.* · R-CHKED-* | pass |
| Inc 6 — Patch Editor document lifecycle | v1 | R-PATCH-DOC-* · R-TUI-049 | pass |
| Inc 7 — diff/before-after reports: full hex windows, atomic writes, escaping, provenance | v1 | R-CMP-004.14 · F6-1 | pass |
| Inc 8 — Flow CRC block reads designer templates, external outputs stay current, CRC model | v1 | R-FLOW-CRC.9 · R-FLOW-EXT.9..14 · D13-20 | pass |
| Inc 9 — confirm re-run report, saved flow names, guarded saves | v1 | R-FLOW-CHAIN.19 · R-FLOW-FILE.12..14 · R-FLOW-SET.8..10 | pass |
| Inc 10a — hex navigation, unload state, focus landing | v1 | R-TUI-018 · R-WS-LOADED.19 · HLR-166 | pass |
| Inc 10b — views after an in-place write | v1 | R-A2L-048/049/105/106 · R-TUI-004.7..9 · R-SEG-PREV.21/22 · R-SEG-EXP.15 | pass |
| Inc 11 — A2L validation and parsing | v1 | R-A2L-036 · R-VAL-032 · R-TUI-042b · R-SEG-SRC.6 | pass |
| Inc 12 — unreachable code removed, reach/opener censuses, Escape closes Reports | v1 | R-DLG.2/.14/.15 · R-SHELL-KEYS.3 · R-CHKED-058 | pass |
| Inc 12b — Flow Builder/Execution hidden widgets removed | v1 | R-TUI-059.25 · R-FX-SCR.4 · R-FB-ADD.1 | pass |
| Inc 13 — CRC Designer / Split/Join responsive at 10 MB | v1 | R-CRC-PREVIEW-001 · R-SEG-PREV.* | pass |
| Inc 14 — help, legend, README describe the shipped app | v1 | R-WHELP.* · R-DOC-README.4 · R-DOC-GUIDE.1/.2 | pass |
| Inc 15 — Windows-only test failures fixed (tests only) | v1 | R-TST-150..162 · tc331 · tc_b94_27 | pass |
| Inc 16 — documentation hygiene | v1 | R-DOC-DEV.* · R-DOC-ARCH.* | pass |

Per-row verdicts live in each increment's `04-validation.md` (Layer A); the batch-level roll-up is `04-validation.md` Layer 0. Per-row verdicts: every increment closed with 0 BLOCKER / 0 HIGH open; the residual findings are backlog rows (§4).

**Visible behaviour change.** Symbol entries in change documents load instead of refusing (Inc 4). The CRC Designer's coverage stays current after apply/save-back/Save project (Inc 5). Reports write complete hex windows and escape hostile names (Inc 7). A flow/chain-set save never writes a byte through a link and never lands outside the work area (Inc 9). Hex jumps show the target as the second row, unload clears stale state, and focus never lands in a hidden window (Inc 10a/10b). A2L files no longer raise "unrecognized block" noise (Inc 11). Escape closes the Reports viewer (Inc 12). The CRC Designer and Split/Join stay responsive on the 10 MB demo image (Inc 13). Help, legend and README match the shipped app (Inc 14/16).

**What worked, what didn't, root causes:** the per-increment `04-validation.md` files; the review page `close/review-b101.html` §4 (the visible reservations).

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|
| QC-TM — a timing arm reports its margin and stops its clock on a product event | wall-clock 1 s bounds measuring the wrong interval, or hiding a real slowdown | batch-100 postmortem Part B §7 (R1-P1, the 13 timing arms); landed as test infrastructure in Inc 2 (`report_margin`, the `qc_tm` item property, the `QC-TM timing margins` section) |
| QC-OR — a status oracle collects every line the action painted, not the newest | oracles that read only the newest painted line | batch-100 postmortem (R-3, CI12a-1); landed as test infrastructure in Inc 2 (the shared status oracle) |
| QC-BC — a behaviour census at every increment that re-orders an observable | a changed observable leaving a stale test in a module the selection never ran | batch-100 postmortem (CI11-4, R-2, R-3); landed as a standing E5 step in every increment (the `-k` / importer / law-guard runs at each E4/E5) |
| G-015 — the `serial_timing` marker runs timing arms apart and serially | 13 timing-bound arms failing under 8-way parallel load | batch-100 close (`evidence/batch-end/linux-gate-f72eef1-timing-serial.txt`); landed in Inc 2 (marker + marker guard + two CI lanes) |

**The four landings — record which ones actually happened. Command-but-not-template is *half-encoded*, and the missing half is the enforceable one:**

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** (`commands/…`) — the rule itself | n/a — the controls landed as **test infrastructure**, not as a `dev-flow` command | `tests/support/timing.py`, `tests/support/suite_census.py`, `tests/b97_probes.py`, `.github/workflows/tui-ci.yml` (merged with Inc 2, `8e5127a`, PR #212) |
| 2 | its **artifact** (a template section) — a control with no output degrades to "I thought about it" | n/a — no template section minted; the controls' output is the test-suite sections (`QC-TM timing margins`, the marker guard, the QC-BC runs) | — |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | n/a — not added at this close | — |
| 4 | **committed and pushed**, manifest re-hashed and bumped | ✅ committed and pushed to `main` with Inc 2 (and exercised by every later increment) | `8e5127a` (PR #212) |

- **New controls:** `none — no C-NN dev-flow control was minted at this close: the four candidates batch-100 proposed (QC-TM, QC-OR, QC-BC) plus G-015 landed as test infrastructure in Inc 2, not as flow commands, so C-45's command/artifact/catalog landings were not executed for them (only the committed-and-pushed landing happened)`

---

## 3 · Working-file reconciliation (C-44)

Sweep run 2026-11-07: `git status --short` and `git log main --not --remotes` in the worktree `s19_app-b101-close`. The batch is records-only — the increments were already committed and pushed to `main` during the batch; this close writes records and commits nothing.

| File | State | Evidence |
|---|---|---|
| `s19_app/**`, `tests/**`, `docs/**`, `README.md`, `CHANGELOG.md`, `SECURITY.md`, `.github/workflows/tui-ci.yml`, `pyproject.toml`, `AT-TC-REGISTRY.jsonl` | ✅ committed **and landed** — pushed to `main` at each increment merge (no PR, the standing authorization's Git answer, except Inc 2's PR #212) | the 18 increment merges (`6a4eadb` Inc 1 · `8e5127a` Inc 2 · `b7b77c4` Inc 3 · `990db24` Inc 4 · `98d94d7` Inc 5 · Inc 6 · `011fdd8` Inc 7 · `2a70774` Inc 8 · Inc 9 · `6f1743c` Inc 10a · Inc 10b · Inc 11 · `f481e8a` Inc 12b · Inc 13 · Inc 14 · `9bb0e3a` Inc 15/16 · `b982846` Inc 12), per `state.json` `decisions_log` and `evidence/merge/` |
| `.dev-flow/2026-11-01-batch-101/**` (packets, increment records, merge/CI evidence) | ✅ committed **and landed** on `main` during the batch | the increment close commits and `15e90c4` (batch-end battery evidence + atlas) |
| `04-validation.md`, `05-close.md`, `close/FORWARD-requirements-session.md`, `close/DOCPASS-notes.md`, `close/review-b101.html`, the `evidence/close/*.txt` batteries, the BL-row additions to `.dev-flow/BACKLOG-CODE.md` | 📋 written, not committed — records only (the brief: "Records only; do not commit") | `git status --short` shows these as modified/untracked on branch `b101-close` |
| `REQUIREMENTS.md`, `.dev-flow/2026-11-01-batch-101/01-requirements.md`, `.dev-flow/_derived/ATLAS-*.md` | 📋 written, not committed — the canon fold (orchestrator ruling 2026-11-07) | `devflow-init.py --fold-canon --root .` (`canon: REQUIREMENTS.md -- 55 folded, 2 kept, 0 refused`) + `devflow-validate.py --atlas --write .` |
| `s19_app/version.py`, the v1.0.0 tag | 🗑️ / pending — the `v1.0.0` tag is the operator's act on the review page's OK (`close/review-b101.html` §6), not this close's | — |

- **Found before the batch:** `none — no tracked file was modified when the batch began` (the batch opened by rollover from batch-100's close, `state.json` `base_ref` = `7717394`)

### Canon fold — the orchestrator ruling (2026-11-07)

1. The batch-level `01-requirements.md` body was rewritten as the batch's requirement index: `HLR-001` carries the batch objective from `PLAN.md` §Objective as a one-`shall` EARS Statement; `LLR-001.1` carries a Statement that is true and verifiable on the final tree (`tests/test_b101_help_legend_docs.py::_FIXED`); and one block per user story the increments declare (the 55 `### US-…` headings, plus `US-101.1`) names its Statement verbatim and its increment file.
2. `devflow-init.py --fold-canon --root .` folded the 55 US ids into `REQUIREMENTS.md` and kept `HLR-001`/`LLR-001.1` (already canon rows). Fold line: `canon: REQUIREMENTS.md -- 55 folded, 2 kept, 0 refused`.
3. No id is declared twice: the index headings `### US-… — title` became `### Rows of US-… — title` (non-declaring references), keeping their `**Statement:**` and `**Increment:**` lines; the increments keep their own declarations.
4. `devflow-validate.py --atlas --write .` regenerated the four ATLAS files once at the end.

Final gate: `devflow-validate.py --brief .` reports **0 block**.

### Conditional-gate discharge

- **Conditional-gate discharge:** `1 condition(s) · ⚠ 1 outstanding, named below`

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|
| Inc 14's SECURITY.md hold-out (ruling A-6 + S-1 / N-2 / E5-1): the SECURITY.md group is held out of the merge while `gh-pvr.txt` reads `{"enabled":false}` | ❌ — still held out (the private vulnerability reporting channel was closed at 2026-11-05T23:42:44Z); the hold-out group is re-checked at the batch end and stays out for the operator | `inc-14/04-validation.md` "Hold-out group"; `evidence/inc-14/gh-pvr.txt` |

---

## 4 · Backlog reconciliation — the carry-over contract

| Item | Move | Reference |
|---|---|---|
| 35 `BL-…` rows opened by the increments (Inc 8, 9, 10a, 10b, 12, 12b, 14) | appended to `.dev-flow/BACKLOG-CODE.md` in its existing batch-101 bullet format, each with its source path | `.dev-flow/BACKLOG-CODE.md` (§Routed 2026-10-26 — batch-100 P2 round 1, batch-101 additions) |
| BL-I9-2 | ✅ CLOSED at E3 by ruling E3A-04 (R-FLOW-SET.9/.10) | `inc-9/E1-rulings.md` §6 |
| BL-I8-2 (help-line half) · BL-I8-3 | taken by Inc 14 (R-WHELP.25/.26 · R-DOC-GUIDE.1/.2); the field-label half of BL-I8-2 stays | `inc-14/E1-rulings.md` §2 |
| BL-I10-1 | narrowed by Inc 10a E4-R1 (the load half fixed); the MAC re-anchor half stays | `inc-10/E1-rulings.md` §7 |
| BL-I14-5 | text side applied by the batch-end doc pass; the PNG re-captures stay | `close/DOCPASS-notes.md` |
| **BL-I10b-1 · BL-I12-6 · BL-I12-5** | ⚠ **flagged for the batch-end review page** (`close/review-b101.html` §4) — the operator decides accept-for-1.0.0 vs fix-before-the-tag | `.dev-flow/BACKLOG-CODE.md`; `close/review-b101.html` |

**The 34 open `▸` `BL-…` rows** (`grep -c '^- \*\*▸ .*BL-I'` over the batch-101 additions of `.dev-flow/BACKLOG-CODE.md`), grouped by source increment: Inc 8 — `BL-I8-1 … BL-I8-6`; Inc 9 — `BL-I9-1, BL-I9-3 … BL-I9-10`; Inc 10a — `BL-I10-1 … BL-I10-4`; Inc 10b — `BL-I10b-1, BL-I10b-2`; Inc 12 — `BL-I12-1 … BL-I12-6`; Inc 12b — `BL-I12b-1`; Inc 14 — `BL-I14-1 … BL-I14-6`. The three the review page flags — `BL-I10b-1` (the Hex Peek panes keep pre-write bytes), `BL-I12-6` (double Generate / Escape-in-flight raises `ScreenStackError`), `BL-I12-5` (seven dialogs still ignore Escape) — are marked "flagged for the batch-end review page" in the backlog rows.

The already-routed batch-101 rows (the KF-101 known-failed checks ×8 and the Inc 2/3/4/7/8/11/13/16 routed rows) were appended to `.dev-flow/BACKLOG-CODE.md` at each increment's close by the orchestrator and are not re-added here.

---

## 5 · Batch metrics — the 13 keys of `core`

Extract, do not invent: a key the artifacts did not record goes `null`, and the key is never dropped.

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-11-01-batch-101
mode: full
verdict: PASS-WITH-NOTES
increments: 16
source_files_max: 4
notices_raised: null
rework_returns: 33
triggers_fired: "A1,A2,A3,A4,B1,B2,B3,B4,C6,C8,D1,E1,E2"
tests_base_to_post: "5254 -> 6376"
new_control: "QC-TM, QC-OR, QC-BC, G-015 (test infrastructure, Inc 2)"
open_items_next: 34
```

- `verdict: PASS-WITH-NOTES` — copied from `04-validation.md`'s `Result` line (the gate battery on `b982846` closed with the 4 known failures plus the 2 `test_tc_b100_53` load flakes that pass alone, so no new product defect).
- `increments: 16` — 16 planned increments; the 10 and 12 split into a/b, so 18 packets (1 … 16 with 10a/10b and 12/12b).
- `source_files_max: 4` — Inc 8 and Inc 11 each touched 4 source files under `s19_app/`; the cap (≤ 4) was never breached.
- `notices_raised: null` — PLAN.md declared no distinct `NOTICE-*` ids; its "Gate notices and runtime absences" § records the P0 architect probe (`4 block · 708 notice · 41 not applicable`, V20 atlas) and one runtime absence (DeepSeek paused by the operator 2026-11-01).
- `rework_returns: 33` — 15 E3 design re-rounds (architect round 1 `FAIL` → round 2, two in Inc 12) + 18 E5 corrective passes (one per packet), counted per each increment's `04-validation.md` and `steps.log`.
- `triggers_fired` — `state.json` `triggers.fired` (A1, A2, A3, A4, B1, B2, B3, B4, C6, C8, D1, E1, E2).
- `tests_base_to_post` — collected nodes: base 5254 (batch-100's close, `2026-10-26-batch-100/04-validation.md`) → 6376 (`b982846`: lane 1 6305 collected + lane 2 71 serial_timing).
- `new_control: QC-TM, QC-OR, QC-BC, G-015` — minted as test infrastructure in Inc 2 (§2); the dev-flow command/template/catalog landings were not executed.
- `open_items_next: 34` — the open `▸` `BL-…` rows appended at this close (BL-I9-2 is the one closed row); the KF-101 known-failed rows and the Inc-routed rows already in the backlog are additional carry.
- Findings: 18 packets · E3 architect round-1 FAIL in 15 rounds · E5 correctives in every packet · mutants ≈ 600+ rows killed across the packets (each `inc-*/04-validation.md` mutant table) · gate battery 6 failed / 6113 passed on `b982846` · 4 known failures + 2 load flakes, 0 new product defects.
- **Declared NOT done:** the requirements canon fold (`--fold-canon` folded 0, refused the 2 template rows — the hand-over is the requirements session's); the human review (the operator has not reviewed yet; instrument `close/review-b101.html`); the v1.0.0 tag (the operator's act); evaluation with real users (ISO 9241-210, one operator — carried forward from batch-100).

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| `04-validation.md` | `Result: PASS-WITH-NOTES` (this close) | ❌ | `none — the operator has not reviewed yet; the review page `close/review-b101.html` is the instrument` | the whole artifact |
| `05-close.md` | this close | ❌ | `none` | the whole artifact |
| `close/review-b101.html` | the review-page draft (DeepSeek) | ❌ | `none — pending the operator's verdict form (no default; JSON export)` | the whole artifact |
| `close/FORWARD-requirements-session.md` (273 rows) | the hand-over document | ❌ | `none — the requirements session folds it, not the operator here` | the whole artifact |
| Increment packets and code | reviewer verdicts in each packet §4b | ❌ | `none — read the status summaries instead` | not audited line by line |

- **Human perimeter:** what to build and in what order (the P0/ARQ approvals and the serial `app.py` chain); the iteration-cap rulings; the 2026-11-06 test-scope override (partial merge verification per increment, full suite once at batch end); the two open operator decisions in `STATUS-for-operator.md` (the redaction pass over older `.dev-flow/` records, and the `.chk.json` grammar change); and the release decision (tag `v1.0.0` on the review page's OK).
- **Human review ledger:** `none — this batch recorded no human review yet: the operator has not reviewed the close records; the review page close/review-b101.html is the instrument for that review, and its §6 verdict form has no default`

## Operator decision (2026-11-07)

The operator gave the go-ahead **in advance** for the v1.0.0 tag ("Te doy el OK por adelantado", 2026-11-07 ~12:45 local), before leaving for an extended period, without reading the review page `close/review-b101.html`. Read as: the v1.0.0 tag is approved, and the open reservations listed on that page (BL-I10b-1, BL-I12-5, BL-I12-6, R-DLG.2 Partly, BL-I9-9, BL-I10b-2, BL-I12-1 … 3) are accepted for 1.0.0 and carried in `BACKLOG-CODE.md`. The human review ledger above stays at depth `none`: no human has audited the batch's records; the review page remains the instrument for that review after the fact. The package version moves `1.0.0rc1` → `1.0.0` (`pyproject.toml`, `s19_app/version.py`) in the close commit that carries this note.

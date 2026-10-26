# P2 review — qa-reviewer — round 3 (bounded verification) — batch 2026-10-26-batch-100

**Mode: plan.** This round checks only that my open findings are closed. Those are R2-01..R2-14 (named `QA-R2-NN` in `02-review.md`) and the round-1 residuals QA-12 and QA-14. I checked them against the contract at `4e9c8f1`: `01-requirements.md`, ledger LED .14–.23, and the "Round 2" section of `02-review.md`. This is not a new full review. Nothing outside this file was edited.

**How the probes ran.** Every probe was executed by **qa-reviewer** on a `git archive 1d677ba` snapshot (`<scratch>/snap1d677ba`), using `s19env` Python 3.11.15 with `NO_COLOR` unset. The import probe printed `s19_app.__file__ = <scratch>\snap1d677ba\s19_app\__init__.py`. `git diff --stat 0c7ca1d 4e9c8f1 -- s19_app tests` is empty.

## Verdict

- **qa-reviewer: `approve`.** All 16 findings checked are closed: **0 open**, **0 HIGH**.
- **PDR conditions:** I noticed two items, neither a defect that blocks (PDR-QA-1, PDR-QA-2 below).
- **Re-runs:**
  - The corrected emit rule gives the 3 expected outcomes.
  - P-37 reproduces.
  - The 24-cell question table reproduces: 11 ask, 13 load, and the mutation counts 5 / 1 / 1 / 4.
  - The 1 000-entry recent cap arm fits (40 034 bytes).

## Closure table

| id | r2 severity | closure in the contract at `4e9c8f1` | status | executed check / note |
|---|---|---|---|---|
| R2-01 (QA-R2-01) | MAJOR | LLR-167.1 (the emit decision on data: re-derive the change document onto a copy, emit iff the data differs; a check document never counts), LLR-167.2, LLR-167.7 (`save_patched` split into `rederive_for_save` + `emit_and_verify`); §6.3 lists the round-2 rule as a deviation corrected here; LED .14 (R-TUI-012's "otherwise copies byte for byte" holds again); P-37, P-38 | **closed** | `emit_rule_r3.py` (the data decision emulated with `apply_change_document` on a copy of `case_01`): `check doc, 1 entry -> copy`; `change doc, same bytes -> copy`; `change doc, real change -> emit`. P-37 re-run: `save_patched(check doc): ok = False \| Patched image not saved - 1 entry blocked`. This is the RED of the round-2 rule. The TC arms in LLR-167.1 and LLR-167.2 cover all three cases plus TC-700. |
| R2-02 (QA-R2-02) | MAJOR | LLR-174.1: load kind = image replace / attach / project; an attach never asks; 24 cells; LED .17 | **closed** | `r3_tables.py`: `cells 24 ask 11 load 13`; drop D → 5 wrong cells, drop F → 1, drop W → 1, "attach asks on D" → 4. All four match the contract's negative controls. |
| R2-03 (QA-R2-03) | MAJOR | LLR-174.4 `_confirm_then_load`: one seam for the router, the Workarea pick (`app.py:9021`), the variant switch (`app.py:6736`, both `v` keys), and the dialog's project load, with an AST census of 0 bypasses; P-42; LED .17 | **closed** | The P-42 anchors match my round-2 reads. |
| R2-04 (QA-R2-04) | MAJOR | HLR-168, AT-B100-20 observable outcome (3 arms: S19, MAC, A2L; 5 keys JSON-equal; 0 absolute paths; the new `active_variant`; fresh-app panel, document and Execute scope); negative control "3 arms, each with 5 key comparisons"; §5.3 re-pins; LED .23 | **closed** | — |
| R2-05 (QA-R2-05) | MAJOR | AT-B100-21 compares the plan's rows with the written tree, at the plan's granularity, by full path and action (LLR-167.6: one row per top-level file, per sub-folder with its count, and for `project.json`), and checks the action words at 220 columns. The declared exception is `SaveProjectScreen.plan` (§3 preface, LLR-175.4). The painted ≡ plan link is TC-B100-65 (0 differences at 220 columns). LED .15 | **closed — exception accepted, with PDR-QA-1** | See *The AT-21 exception* below. |
| R2-06 (QA-R2-06), QA-14 | MAJOR | LLR-173.2: the dialog opens with the focus on `#load_path`; a printable key typed in the list goes to `#load_path`; `#load_ok` / `enter` / `alt+l` load the highlighted row only when `#load_list` had the focus last, otherwise the typed text; a negative control for a mutation that starts the focus on the list. §5.3 marks AT-01 and AT-12 "typed path, path field focused". LED .18 | **closed** | The typed-path ATs written before Inc 9b now survive it by construction. |
| R2-07 (QA-R2-07) | MINOR | LLR-165.2: stat-keyed caches are normalised without their mtime and with relative paths; the negative control names my probe; LED .23 | **closed** | — |
| R2-08 (QA-R2-08), QA-12 | MINOR | LLR-172.2: 1 000 distinct `C:\NNN.s19` → exactly the first 20, in order; 65 536 → parsed; 65 537 → `too large`; LED .21 | **closed** | `r3_tables.py`: 1 000 distinct entries = 40 034 bytes (default `json.dumps`) or 36 032 (compact), both ≤ 65 536. The arm can be built and is not vacuous. |
| R2-09 (QA-R2-09) | MINOR | HLR-169 AT-B100-07 paints `manifest damaged` in user terms ("a file path points outside the project"), with the internal code in the log only; LLR-169.9 threshold "0 `MANIFEST-` codes in painted problem text"; LED .22 | **closed** | — |
| R2-10 (QA-R2-10) | MINOR | HLR-163 narrowed to the two statuses that claim "added" or "written" (the variant append and the export); LED .20 | **closed** | — |
| R2-11 (QA-R2-11) | MINOR | §5.4 has a `_handle_save_dialog` row for the 7 files, with dispositions including TC-700 (a check document → byte copy plus `checks/`) and AT-B99-05 (now emits; `status.startswith("Project saved")` kept with the LLR-167.3 suffix); LED .23 | **closed** | — |
| R2-12 (QA-R2-12) | MINOR | HLR-177 threshold "the worker share measured above one timer tick at P3"; AT-B100-18 presses `l` "after the worker step is painted"; HLR-176 asks for ≥ 2 bar increases within the parse step; LED .19 | **closed** | — |
| R2-13 (QA-R2-13) | MINOR | LLR-164.3: L = 150; a 55-character name gives `150 + 1 + 55 + 53 = 259` → saved, and 56 characters give `260` → refused; LED .22 | **closed** | Arithmetic checked. 53 was verified in round 2 (`before_after_service.py:78-85`). |
| R2-14 (QA-R2-14), QA-20 | MINOR | PLAN corrected by the orchestrator (`322bbab`); LED .23 | **closed** | `grep -n "vars(app)" PLAN.md` → 0 hits at `4e9c8f1`. |

## The AT-21 exception (`SaveProjectScreen.plan`)

**Accepted.** The operator's P-C note asks that the summary never misstates what a save writes, and that claim needs two links:

1. **Painted ≡ plan.** TC-B100-65 checks it (painted rows = plan rows, 0 differences at 220 columns, plus an AST check that the painter reads only the plan). AT-21 also checks it black-box for the action words at 220 columns.
2. **Plan ≡ disk.** AT-21 checks it through the accessor.

**Why it is acceptable:**
- Black-box alone cannot do this. The preface lets painted rows be cut with `…` at 118 columns, and a full path cannot be recovered from a cut row.
- `plan` is public, read-only and NEW, so batch-99's QC-AT grep (`app._…`, private calls) still applies to every other AT unchanged.
- The exception is declared in one place (§3 preface) and named in the AT's shipped-surface line.

**Conditions for PDR (PDR-QA-1):**
- (a) `plan` returns an immutable value (a frozen dataclass, or a copy), so the AT cannot alter what the handler executes.
- (b) The AT only reads it after `alt+s` has been pressed by key. It never calls the planner or drives the save through it.
- (c) At 220 columns, the AT compares each painted row that is not cut by (landing name, action), not by action words alone. That way the black-box layer still observes the operator-facing content wherever it is visible.

## Noted for PDR (do not block)

- **PDR-QA-1:** the AT-21 accessor conditions (a)–(c) above.
- **PDR-QA-2:** LLR-167.1 leaves to PDR whether `image_differs_from_source` stays as a pre-check (§6.3). If it stays, it may only short-circuit toward *compute the data decision*, never decide copy on its own. Otherwise the save-back-then-Save arm (A-08) could copy the unpatched source. TC-B100-15 already has that arm, so it will catch a wrong choice.

## Evidence checklist (qa-reviewer, bounded round)

- [✓] Mode declared (plan).
- [✓] Each open finding is mapped to its closure, with the LLR and ledger id cited.
- [✓] The cheap re-runs are executed and attributed (executor: qa-reviewer, on the `1d677ba` snapshot).
- [✓] No new HIGH.
- [✓] No real PII or secrets. Paths are given as `<scratch>`.

Probe scripts (scratch, not committed): `<scratch>/qa-p2r1-scripts/emit_rule_r3.py`, `r3_tables.py`.

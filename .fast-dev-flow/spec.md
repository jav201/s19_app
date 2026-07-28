# Quick Spec — s19_app · batch-68 · N5: before/after + diff reports off the UI thread

- **Status:** open
- **Date:** 2026-07-28
- **Branch:** `claude/batch-68-report-worker` (base `488bf5d` = `origin/main` tip; RC-1 PASS, merge-base == tip)
- **Flow mode:** autonomous + self-merge (operator-granted THIS batch at kickoff; per-batch only, never carried)
- **Artifact language:** English (project default; conversation stays Spanish)
- **security_required:** false (see §6)

> **Flow choice CORRECTED after measuring, and stated rather than silently downgraded.** At the kickoff question I wrote *"probablemente `/dev-flow` por el riesgo"*. That was a guess made **before** reading the seams. Measured: the two handlers each wrap **one** pure composer call, the repo already ships a proven `@work(thread=True, exclusive=True)` template for exactly this in the same file, and the blast radius is **1 production file + 4 test files / 14 call sites**. A 6-phase V-model is not warranted by that shape, so this runs as `/fast-dev-flow`. If the seam had been tangled, the answer would have been the opposite.

---

## 1. Objective (1 line)

Move the before/after and A2B-diff report composition off the UI thread onto workers, so the TUI stops freezing outright during generation, and drive the existing progress bar at their seams.

---

## 2. User stories

- As an **operator**, I want the TUI to keep repainting while a before/after or diff report is generated, so that a slow report looks like work in progress instead of a hung application.
- As an **operator**, I want the progress bar to move during those two reports the way it already does for the project report, so that I can tell the difference between "still working" and "finished".

---

## 3. RC-1 verification — what disk says

1. **The freeze is real and total, not a missing indicator.** `app.py` has exactly **three** `@work` methods (`execute_scope`, `generate_report`, `load`). `action_before_after_report` and `on_ab_diff_panel_report_requested` are **not** among them, so `compose_before_after_report` / `generate_diff_report` / `generate_diff_report_html` all run on the UI event loop. The backlog framed N5's carry as "same `set_progress` pattern" — that understates it: you cannot drive a progress bar from the thread you are blocking.
2. **Both seams are clean and identical in shape.** Each handler does cheap validation (which may `set_status` and return early), then **one** heavy pure call, then logging + a status write. `compose_before_after_report` and the two diff generators are Textual-free emitter services.
3. **The template already exists in the same file.** `_start_generate_report_worker` is `@work(thread=True, exclusive=True, group="generate_report")`, marshals UI writes through `call_from_thread`, resets the bar to 0 on both the reject and crash arms, and calls `_log_report_event` **directly** from the worker — which is correct, not a latent bug: that method touches only `self.logger`, never a widget. Verified before copying the pattern.
4. **Blast radius measured:** 14 call sites over `test_before_after_report.py` (9), `test_report_logging.py` (2), `test_tui_directionb.py` (2), `test_loadfilescreen_input.py` (1). Every one currently assumes the work completed by the time the handler returned.

---

## 4. Acceptance criteria (observable)

**AC-1 — before/after composition leaves the UI thread.** When `action_before_after_report` runs, `compose_before_after_report` shall be invoked on a thread whose identity differs from the UI thread that dispatched the action. *(Falsifiable and RED pre-fix: today they are the same thread.)*

**AC-2 — diff composition leaves the UI thread.** Same for `generate_diff_report` **and** `generate_diff_report_html` — both are heavy and both must move, so the criterion binds each independently.

**AC-3 — the before/after bar moves and never sticks.** A successful before/after report shall drive `set_progress` to a kickoff value, then to `100`; a refused or crashed one shall reset it to `0`. No path may leave the bar at a mid-fill value.

**AC-4 — the diff bar moves and never sticks.** Same three arms for the diff path, including the **html-refused-after-md-succeeded** arm, which is a distinct early return in today's code.

**AC-5 — the reports are still correct.** The written `.md` / `.html` paths, the `set_status` text, and the `_log_report_event` outcome for every existing arm (ok / refused / html-refused) are unchanged once the worker completes.

**AC-6 — no regression.** Full non-slow suite green; 29 snapshot cells unchanged (this batch renders no new text).

---

## 5. Out of scope

- The project-report worker (`_start_generate_report_worker`) — already off-thread since batch-N5's first half; not touched.
- The remaining N5 carries: CRC compute-over-large-coverage progress, and A2L enrichment granularity (the A2L **load** path already drives 10/50/100 — measured during the batch-67 review, so that carry is smaller than written).
- Any progress *percentage* that claims to be a true completion fraction — the composers expose no step count, so the seams stay coarse like the project report's 15/55/100.
- The engine-frozen set and the frozen test files.

---

## 6. Security flags

`security_required: **false**` — no pattern fired. The scan hits on "report" and "file" are pre-existing write paths that this batch **relocates without changing**: same composer, same arguments, same destination, same containment. No new input is parsed, no new file is written, no new surface is exposed. The one genuine concurrency consideration is not a security one: `exclusive=True` per group prevents two overlapping generations of the same kind from interleaving their status writes.

---

## 7. Increments

| Inc | Content | Files (≤5) | AC |
|---|---|---|---|
| 1 | before/after → worker + progress; update its call sites | `app.py`, `test_before_after_report.py`, `test_report_logging.py`, new AT file | AC-1, AC-3 |
| 2 | diff (md + html) → worker + progress; update its call sites | `app.py`, `test_tui_directionb.py`, `test_loadfilescreen_input.py`, AT file | AC-2, AC-4 |

Close: full suite + snapshots (AC-6), backlog reconciliation, PR, merge on `tui-ci` green.

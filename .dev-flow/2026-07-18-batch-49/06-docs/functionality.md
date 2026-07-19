# Functionality — s19_app — Batch 2026-07-18-batch-49

## 1. Issues Report — visual-insight upgrade (US-082)
The existing **Issues Report** screen (rail key `5`) gains a MID insight layer matching the batch-47 cohort, with no change to issue data, grouping, paging, or filtering:
- **Severity-distribution strip** above the grouped list: `Errors N / Warnings M / Info K`, each with a proportional micro-bar and a severity colour (red/yellow/cyan). Reflects the whole-list distribution; reads 0/0/0 only when there are truly no issues.
- **Leading severity glyph** on each group header (`✗` errors / `⚠` warnings / `•` info).
- **Border-titled panes** (the grouped list and the hex peek).
- **Severity-coloured summary line** (plain text unchanged; only colour spans added).
All new surfaces are built markup-safe (`safe_text` / explicit `Text`), carrying only integer counts and author constants — no file-derived text.

## 2. Checks — new dedicated rail screen (US-083)
A new **Checks** screen joins the activity rail at key `9` (order: Workspace…Flow, **Checks**). It is a **read-only mirror of the last check run** (`_change_service.last_check_result`) — the check outcomes that previously lived only inside the Patch Editor's compact window now have a focused review surface:
- **Grouped list** — check entries grouped **failed → uncheckable → passed**, each row coloured by outcome (red/yellow/green via the shared severity policy), capped at 40 mounted rows with a truncation note.
- **Aggregate strip** — pass/fail/uncheckable counts with a proportional bar.
- **Hex peek** — selecting a row shows a focused hex+ASCII window around that entry's address.
- **Honest empty states** — *no file loaded* → the standard empty-state panel; *file loaded but no check run yet* → a distinct "No check run yet — run checks from the Patch Editor." note (never a misleading zeroed run).
- The screen refreshes when checks are run/undone in the Patch Editor and on navigation. It renders every file-derived string (check symbols, reasons) markup-safe.

## 3. What did NOT change
Engine/parsing/validation logic (untouched, engine-frozen); the Patch Editor's own checks window; check computation timing (still operator-triggered, never on file load); Issues paging/filtering.

## 4. How to use
- Load a file (`Ctrl+L`). Press `5` for the Issues Report — the severity strip summarises the error/warning/info balance at a glance.
- To review checks: open the Patch Editor (`6`), paste/open a check document, run checks; then press `9` for the dedicated Checks screen. Select any row to peek its bytes.

# fast-dev-flow spec — batch-34 reports lane (B-08 / B-09 / B-10)

- **Status:** closed 2026-07-10 (AC-1..AC-6 green; full suite 1244 passed / 0 failed; PR pending merge)
- **Created:** 2026-07-10
- **Branch:** `fix/batch-34-reports` @ `cc58397` (= origin/main after PRs #61/#62)
- **Route:** /fast-dev-flow (isolated module `services/diff_report_service.py` + one shared primitive; root causes pre-verified in the 2026-07-09 baseline review)
- **security_required:** true (see §6)

## 1. Objective

Make the diff / before-after reports human-inspectable: merge the repeated context windows that
contiguous changes currently produce (B-08), give the HTML report side-by-side before/after panes
with per-changed-byte highlights (B-09), and add ASCII companions to the linkage table's hex-only
Before/After cells (B-10).

## 2. User stories

- As an operator reading a before/after report of contiguous patches, I want ONE merged context
  window instead of near-identical windows repeated per change, so inspection doesn't require
  visually deduplicating pages of hex (B-08; my window limit: the current window size plus 5 lines).
- As an operator comparing before vs after in the HTML report, I want the A and B windows side by
  side with the changed bytes highlighted, so I can spot the exact deltas without line-by-line
  reading (B-09; the Markdown report keeps its ```diff blocks).
- As an operator reading the Change-entry linkage table, I want each Before/After byte run shown
  with its ASCII/UTF rendering beside the hex, so text-valued patches (version strings etc.) are
  recognizable at a glance (B-10).

## 3. Acceptance criteria (observable)

- [x] **AC-1 (B-08, MD):** When two changed runs sit within 5 hex rows (5×16 bytes) of each other,
  the generated Markdown report shall contain ONE merged `Image A/B window 0x…-0x…` block pair
  covering both runs (plus one grouped run heading naming both run ranges), where today it provably
  emits two overlapping window pairs — RED first. Runs farther apart than the 5-row bridge shall
  keep separate windows (boundary case at exactly 5 rows merges; 5 rows + 1 byte does not).
- [x] **AC-2 (B-08, primitive):** `compute_hexdump_windows` shall gain an optional
  `merge_gap_bytes=0` parameter — default behavior byte-identical (the project report's existing
  call sites and tests pass unmodified); with a positive gap, windows separated by ≤ gap bytes
  merge.
- [x] **AC-3 (B-09, HTML):** When the HTML report renders a merged/changed window, it shall emit
  the A and B panes side by side (a two-column flex/table row, headers "Before (A)" / "After (B)")
  and shall wrap exactly the hex tokens whose byte value differs between A and B in a highlight
  `<span>` (assert: a changed byte's token appears inside the span markup; an unchanged byte's
  token does not; the ASCII gutter stays `html.escape`-d).
- [x] **AC-4 (B-09, MD):** The Markdown report's ```diff blocks shall be unchanged in format
  (regression pin over a changed run).
- [x] **AC-5 (B-10):** When the linkage table renders a Before/After byte run, each cell shall
  carry the ASCII rendering beside the hex (format: `41 42 43 |ABC|` — reusing
  `changes/display.format_memory_value`'s ascii form), with the `(none - created into hole)` and
  `-` markers unchanged; in Markdown the ASCII part shall pass `_md_cell` (a byte run decoding to
  `|` must not break the table — RED-able via a pipe byte), and in HTML through `_esc`.
- [x] **AC-6 (regression):** The project report (`report_service`) output shall be byte-identical
  for its existing fixtures (its `compute_hexdump_windows` calls keep the default gap).

## 4. Validation strategy

Pytest in the same increment as each change; existing suites `tests/test_diff_report_service.py`
(+ `test_report_service.py` for AC-2/AC-6). RED-first where the AC captures live behavior (AC-1
duplicate windows; AC-5 pipe-byte MD breakage). Full suite `-m "not slow"` at close; no snapshot
surface is touched (reports are files on disk, not TUI screens). Manual smoke: generate one HTML
report from the example fixtures and eyeball the side-by-side pane.

## 5. Non-goals (OUT)

- The report window content/row format itself (`render_hex_view` reuse stays).
- PDF or other export formats; report_service (project report) visual changes beyond AC-2's
  parameter.
- B-07 (filter file) — awaiting operator spec; separate batch.
- Any TUI screen change.

## 6. Detected security flags

- [ ] Auth / identity
- [ ] Secrets / config
- [ ] External integrations
- [ ] Sensitive data
- [ ] Destructive DB
- [x] Input / attack surface (**escape/sanitize**: file-derived BYTE VALUES rendered as ASCII into
  Markdown tables and HTML — printable bytes include `|`, `` ` ``, `<`, `>`, `&`)
- [ ] Network / exposure

**`security_required`:** true

**Risk summary:** B-10 decodes loaded-image bytes to ASCII and embeds them in an MD table cell and
an HTML cell; B-09 builds new HTML around byte tokens and the ASCII gutter. A crafted image whose
patched bytes decode to `|`/backticks breaks the MD table; `<script>`-shaped bytes must never reach
HTML unescaped. Mitigations already in the module: `_md_cell` (S-F2) and `_esc` (html.escape) —
the batch's rule is that EVERY new interpolation passes one of them; hostile-byte ATs are mandatory
(pipe-byte MD case; `<b>`-shaped HTML case). A focused security mini-review gates Inc-2/3.

## 7. Increment plan (3 increments, ≤5 files each)

| Inc | Items | Files (est.) |
|---|---|---|
| 1 | AC-1/AC-2/AC-6 window grouping | report_service.py, diff_report_service.py, 2 test files |
| 2 | AC-3/AC-4 HTML side-by-side + highlights | diff_report_service.py, test file |
| 3 | AC-5 linkage ASCII cells | diff_report_service.py, test file |

**Interpretation note (operator-amendable):** the "+5 lines" limit is realized as a merge bridge —
run windows merge when the gap between them is ≤ 5 hex rows (80 bytes); this keeps merged windows
tight instead of bridging arbitrarily distant changes.

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-10 |
| Closed | 2026-07-10 |
| Promoted to /dev-flow | no |
| Notes | Reports lane of the 2026-07-09 baseline dispatch; follows batches 31–33 |

## 9. Close (filled in phase C)

### What changed
Three report improvements in 3 increments (+2 fold commits): (Inc-1/B-08) contiguous change runs share ONE merged context window — `compute_hexdump_windows` gained `merge_gap_bytes=0` (default byte-identical; project report untouched) and the diff report bridges up to 5 hex rows (`MERGE_GAP_ROWS`), emitting one grouped heading + one diff block + one A/B window pair per merged window. (Inc-2/B-09) HTML changed windows render side-by-side Before(A)/After(B) panes with exactly the differing bytes highlighted (hex tokens + ASCII gutter chars), built escape-then-wrap from structured tokens with a constant inline style (security F2/F3); MD ```diff blocks unchanged. (Inc-3/B-10) linkage Before/After cells render `HH HH |ascii|` via `format_memory_value`, with the new `_md_table_cell` backslash-first escape (security F1) scoped to byte cells; markers unchanged.

### How it was tested
- 10 new AC-mapped tests (AC-1 merge + 5-row boundary, AC-2 primitive incl. default identity, AC-3 highlight exactness + hostile `<b>&` gutter, AC-4 MD diff pin, AC-5 ASCII cells + hostile pipe/backslash-pipe/tag/LF byte set + markers); RED captured per increment via source-stash (3/2/2 failures respectively).
- Full suite: **1244 passed, 2 skipped, 3 xfailed (pre-existing), 0 failed; 31/31 snapshots** (no snapshot surface touched).
- Censused supersessions: the batch-24 default-kwargs MD+HTML goldens re-captured under the new renderer (kwarg-neutrality intent unchanged); the hex-only linkage pins in test_diff_report_service.py AND test_before_after_report.py rewritten to the AC-5 format — the second file was a census miss caught by the full-suite run (C-14 lesson class: sweep the e2e OBSERVERS).
- Manual smoke: deferred to operator eyeball of the first real HTML report (the AC-3 assertions cover the pane structure).

### Open risks / pending
- F4 (security review): a merged window larger than MAX_HEX_ROWS renders hexview's row-limit note — a display bound, not report truncation (pre-existing class for giant single runs; merging raises likelihood marginally). Recorded, not chunked.
- Process notes for the next post-mortem: (1) Inc-2 was briefly committed with a red test (pipe chain masked the exit code — second occurrence of the C-CAND-D lint/test-gate lesson); (2) the B-10 census missed the e2e observer file (C-14 class); (3) harness heredoc escape-collapsing corrupted test literals twice — Write-tool file transfer is the reliable path.

### Security flags — handling
`security_required: true` (input surface — file bytes rendered as ASCII into MD/HTML). Pre-code mini-review: OK-with-mitigations, all applied: F1 `_md_table_cell` backslash-first escape (+ the backslash-pipe counterfactual AT); F2 escape-then-wrap token construction (+ the `<b>&` AT incl. single-entity assert); F3 constant inline style, no file-derived attribute values; F4 bound confirmed (MAX_HEX_ROWS), wording note recorded. No backtick wrapping of cells.

### Suggested commit message
```
feat(reports): batch-34 — merged windows, side-by-side highlighted HTML, linkage ASCII (B-08/09/10)
```

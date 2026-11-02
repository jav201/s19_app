# S14 — A↔B compare & diff reports: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S14 (lines 6366–6596): R-TUI-028 (superseded), R-CMP-001 … 006, R-DIFF-LOADFAIL-001, R-BEFORE-AFTER-REPORT-001, and the "reusable substrate" note. Also the A2B Diff rows of S0's table (HLR-010 / LLR-010.1 / 010.2, LLR-143.2) and the items S8, S9 and S10 passed (`format_memory_value` used by the diff report, the before/after offer, the check-spec addendum, R-TUI-049.2).
Code: `s19_app/compare.py`; `tui/services/compare_service.py`, `diff_report_service.py`, `before_after_service.py`; `screens_directionb.py::AbDiffPanel` (`:7744-8929`); the S14 functions of `app.py` (`_compose_screen_diff` `:5316`, `_prefill_diff_*` `:5357-5403`, `_diff_*` and `on_ab_diff_panel_*` `:6021-6519`, `action_before_after_report` `:4314-4490`, the save-back offer `:3720-3734`); the `#diff_*` rules of `styles.tcss` (`:1453-1561`). Read directly, every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S14.7 (the diff report start and worker, `app.py:7461-7631`) and S14.9 (the before/after start and worker, `app.py:5369-5561`) verified at 570b4b5; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-COMPARE, CTX-DIFFSCREEN, CTX-DIFFREPORT, CTX-BEFOREAFTER.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Rows whose "Code today" starts with **NEW** describe behaviour the code has and the operator can observe but no requirement named (D14-5). Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first** (TUI rule).
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S14.md` (to be merged into `review/CODE-CHANGES.md`). Nothing is changed in the code yet.

---

## 1. How S14 was written before

- R-TUI-028: the batch-04 placeholder screen, kept "as historical record" after R-CMP-006 replaced it.
- R-CMP-001 … 006: six long rows from batch-09. Each mixes product behaviour with design (dataclass field sets, "imports no Textual", which module owns which regex, "the shared regex is not edited", "rail.py unmodified") and test lists.
- R-DIFF-LOADFAIL-001: one paragraph that is half requirement, half batch record (the escape, the test that missed it, the function that changed).
- R-BEFORE-AFTER-REPORT-001: one 25-claim sentence (trigger, files, five preconditions, two sanitisers, imports, logging) plus a paragraph of test ids.
- Nothing about the screen behaviour batch-78 built (run selection, window paging, the three size regimes, the overlay), nor the check-spec addendum (S0 HLR-010) or the flow-change attribution (S0 LLR-143.2), although the code does all of it.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-028 | A requirement for a placeholder that no longer exists, kept as history. | Deleted (D14-2). |
| R-CMP-001 | "returns a `ComparisonResult` carrying exactly the canonical field set", "imports no Textual and no parser": design. "Symmetric" and "deterministic" follow from the kind definitions. | Observable rows (S14.1); design out (D14-3). |
| R-CMP-002 | "parses each through the existing load path", "imports no Textual": design. The refusal texts are not given. | Rows with exact texts (S14.2). |
| R-CMP-003 | "the shared A2L/MAC artifacts" of the project: the code uses the A2L and the MAC loaded in the session, project or not. | "the loaded A2L / MAC" (D14-4). |
| R-CMP-004 | "Each format owns its own filename regex … `REPORT_FILENAME_REGEX` is not edited (G-4)", "performs no logging (F-S-07)": module placement. "`html.escape` applied to all embedded content" is true for HTML only; the Markdown file writes labels, paths and symbol names raw. | Observable rows; Markdown escaping is a defect (D14-10). |
| R-CMP-005 | "validated by `Path(input).expanduser().resolve()` then requiring `is_dir()`", "`sanitize_project_name` is not used": design. "No-silent-overwrite" holds only between seconds: the name is probed, then written, with no exclusive create; the project `reports/` folder is not checked for a link although the before/after report refuses one. | Rows with texts; D14-11. |
| R-CMP-006 | "`AbDiffPanel`", "execution exclusively through `compare_images` (never the engine directly)", "`rail.py` unmodified", "supersedes …": design and history. "Rich-coloured rendering" names no colour; the colours are not S3's palette. | Screen rows (S14.4, S14.5); colours prototype first (D14-20). |
| R-DIFF-LOADFAIL-001 | Function names, a widened return tuple, the out-of-band signal, the escaped bug's story. After a failed compare the screen still shows the bogus runs, and Report writes them. | Rows S14.2; Report refused after a failed compare (D14-13). |
| R-BEFORE-AFTER-REPORT-001 | 25 claims in one sentence; `ChangeSummary.saved_path stamped`, `_strip_ctl`/`_md_cell`, "imports no Textual". The offer text the operator reads ends in `(action: before_after_report)`. | One row per claim (S14.9); D14-14. |
| (nothing) | The A2B Diff layout: three size regimes, an overlay run list, two paging keys, a notice that names the failed axis. ~40 tests (`test_tui_diff_screen.py`), no requirement. | NEW rows R-DIFF-SCR (D14-5). |
| (S0 HLR-010) | The check-spec addendum lists `workarea/patches/` only; with a project open the Check Editor saves specs in `<project>/checks/`, so they never appear. | R-DIFF-CHK.1 (D14-17). |
| (S0 LLR-143.2) | "the input is an s19 that just passed through a flow": only the last Flow **Builder** run is checked; images written by Flow Execution lanes never get the attribution. | R-DIFF-FLOWCHG.1 (D14-18). |
| Substrate note | A design note about a future consumer and a test guard. | Out (D14-1). |

Context notes that would have carried behaviour (E6): none were written before. The ranges the screen and the reports print end one past the last byte; the Workspace prints the last byte (S5). Recorded as D14-16.

---

## 3. Context notes (informative)

### CTX-COMPARE · Two images, runs, usage (S14.1 … S14.3)

```text
image A, image B  The two images the operator compares.
source            An open-project variant (S11 CTX-PROJECT), or an external path the
                  operator types, resolved as S5 resolves a path input (S5 S5.3).
same file         Both sides name the same variant, or the same typed text, or two
                  external paths that resolve to one file.
run               A maximal run of consecutive addresses that share one kind.
kind              changed   mapped in both images, the bytes differ
                  only A    mapped in image A only (report: "only in A")
                  only B    mapped in image B only (report: "only in B")
                  An address mapped in both with equal bytes is in no run.
run range         Today: 0x<start>-0x<end>, <end> one past the last byte (D14-16).
statistics        Per kind: the number of runs and the number of bytes.
label             A variant's id, or an external file's name.
artifact usage    Per image and per artifact (the loaded A2L, the loaded MAC):
                    absent   no such file is loaded
                    used     at least one of its addresses lies in the image's ranges
                    unused   loaded; none of its addresses lies in the image's ranges
                  A2L address: a tag with an integer address. MAC address: a record
                  with an integer address.
usage summary     both · one (a2l) · one (mac) · none (by the "used" statuses).
load failure      A side whose file is not empty but whose image has no byte.
```

### CTX-DIFFSCREEN · The A2B Diff screen (S14.4 … S14.6)

```text
A2B Diff        Rail window (S6: position 8, key 7). Title "A2B Diff", then rows:
  row A         "A:", the A variant list, the "external path A" box
  row B         "B:", the B variant list, the "external path B" box
  check row     "Check spec:" and the check-spec list (S14.6)
  action row    Compare, Report, the box "report destination dir (no-project only)"
  status        One line, shown in full. At start: "Select two images and press Compare."
  run list      "Runs: <n>", "A artifacts: <summary>", "B artifacts: <summary>",
                "Keys: Up/Down move the selection", then one run row per shown run,
                then the cap line when runs were left out.
  windows       The image A window above the image B window.
  notice        Replaces the run list and the windows in the notice regime.
variant list    The open project's variant ids in variant order (S11), then
                "(external path below)"; with no open project, only the latter.
run row         <index, 3 wide> 0x<start, 8 hex>-0x<end, 8 hex> <changed|only A|only B>,
                coloured by kind.
display caps    At most 128 runs; runs are added while their bytes total at most
                2,097,152; the first run is always shown.
cap line        (showing <k> of <n> runs — full report is complete)
window          "Image A — Run #<i> 0x<start>-0x<end> <kind>" (B alike), then hex rows
                (S4 row format) from the 16-aligned address at or below start − 16 up
                to end + 16, grown to the window's height with the run centred; no
                address below 0.
page            The rows one window height shows; ] and [ move both windows a page.
regime          By terminal size, W columns × H rows:
  notice        W < 94 or H < 29
  wide          W ≥ 139 and H ≥ 29: the run list (26 columns) beside the windows
  narrow        94 ≤ W < 139 and H ≥ 29: the windows take the full width; the run
                list is an overlay 32 columns wide, hidden until f
notice text     "The A2B diff result windows need a larger terminal." then, one per
                failed axis, "  width <W> - needs at least 94 columns" and
                "  height <H> - needs at least 29 rows".
compare status  Compared <label A> vs <label B>: <n> runs.
                Compare refused: <reason>[; <reason>]
                Compare failed: <label>[, <label>] loaded no image (file has content
                but no valid records).
```

### CTX-DIFFREPORT · The diff report (S14.7 … S14.8)

```text
diff report     A Markdown file and an HTML file with the same content, written together.
file name       <ts>-diff-report.md and <ts>-diff-report.html; <ts> = UTC time as
                YYYYMMDDTHHMMSSZ. If the name exists: <ts>-<NN>-diff-report.md,
                NN = 01 … 99, the first free one.
destination     With an open project: <project>/reports/. With none: the folder typed
                in the report destination box.
sections        In this order:
  header        "# Diff report"; "Generated (UTC)"; "Tool version"; per image: label,
                [source kind and variant id], path, parse-errors=<n>; per image:
                "artifacts: summary=<s>; a2l=<status> (<covered>/<total>); mac=…"
  Statistics    Classification · Runs · Bytes, one row per kind.
  Runs          Start · End · Length · Classification · Symbols, one row per run; or
                "No differing runs - the images are identical."
  Hex windows   Each run ± 64 bytes; windows 5 rows (80 bytes) or less apart merge.
                Per window: "### Run <range> (<kind>)" ("Runs …, …" when merged); a
                diff block (A rows as "-" lines, B rows as "+" lines) when a member
                is changed; then the A window and the B window. "No differing runs
                to dump." when there is no run.
  Flow change attribution   S14.8, only for a flow-written image B.
  Checks        S14.6, only with a check spec loaded.
symbols         The names of the loaded A2L tags and MAC records whose address lies in
                the run, comma-separated; "-" when none.
HTML form       One page: inline style only, no script, no external resource; every
                embedded value HTML-escaped; run kinds in three colours; A and B side
                by side with the changed bytes highlighted.
report status   Diff report written: <md path>  |  <html path>
                Report refused: <reason>
                Diff report failed: <error type>: <message>
                HTML report refused: <reason>
diff report progress line  The progress line (S6) of a diff report: label
                `Writing the diff report`; steps 1 `Write Markdown`, 2 `Write HTML`.
```

### CTX-BEFOREAFTER · The before/after report (S14.9)

```text
before/after    A diff report (CTX-DIFFREPORT) of the loaded image's file (before, A)
report          against the saved patched file of the last save-back (after, B), with
                the stem before-after-report: <ts>-before-after-report.md / .html in
                <project>/reports/.
extra sections  After the header:
  provenance    "## Before/after provenance": original image (before), saved patched
                image (after), applied (UTC), change document or "(in-memory document)".
  linkage       "## Change-entry linkage": # · Type · Start · End · Disposition ·
                Linkage · Symbol · Before · After, one row per entry of the last apply;
                "No entries." when there is none.
bytes cell      "<hex bytes> |<ASCII>|"; "(none - created into hole)" when the entry had
                no prior bytes; "-" for no bytes.
  <hex bytes>   Two uppercase hex digits per byte, separated by one space.
  <ASCII>       One character per byte: the byte itself for 0x20 … 0x7E, "." for any
                other byte.
offer           A notification titled "Before/after report".
status          Before/after report written: <md path> | <html path>
                Before/after report refused: <reason>
                Before/after report failed: <error type>: <message>
before/after progress line  The progress line (S6) of a before/after report: label
                `Writing the before/after report`; one step, `Compose the report`.
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested** (test named), **Partly** / **No** with the decision; a leading **NEW** marks a row for behaviour no requirement named before (D14-5).

### S14.1 · Classifying two images (CTX-COMPARE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-001.1 | U | The system shall give every address mapped in either image exactly one kind of CTX-COMPARE or none. | Yes; tested (`test_classification_set_equality`, `test_classification_set_equality_random`). |
| R-CMP-001.2 | U | The system shall put no address that both images map with equal bytes into a run. | Yes; tested (`test_identity_empty_and_equal`). |
| R-CMP-001.3 | U | The system shall join consecutive addresses of the same kind into one run. | Yes; tested (`test_adjacency_merge_same_kind_merges`). |
| R-CMP-001.4 | U | The system shall start a new run where the kind changes. | Yes; tested (`test_adjacency_change_forces_boundary`). |
| R-CMP-001.5 | U | The system shall list the runs in ascending start address. | Yes; tested (`test_boundary_cases`). |
| R-CMP-001.6 | U | The system shall count, per kind, the runs and the bytes of its runs. | Yes; tested (`test_stats_byte_count_equals_run_lengths`, `test_stats_run_counts_match`). |
| R-CMP-001.7 | When | When the system compares two images of 819,200 mapped bytes each (200 ranges of 4,096 bytes), the system shall classify them within 2.0 s. | Yes; tested (`test_large_image_perf`, marked slow). |

### S14.2 · Sources, refusals and load failures (CTX-COMPARE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-002.1 | When | When the operator presses Compare, the system shall read both images from their files, not from the image loaded in the session. | Yes; tested (`test_variant_pair_matches_engine`). |
| R-CMP-002.2 | When | When a side names an open-project variant, the system shall read that variant's file. | Yes; tested (`test_variant_pair_reports_real_diff`). |
| R-CMP-002.3 | When | When a side names an external path, the system shall resolve it as S5 resolves a path input. | Yes; tested (`test_external_resolved_pair`). |
| R-CMP-002.4 | When | When the system reads an external image whose name ends in `.hex` or `.ihex`, ignoring case, the system shall parse it as Intel HEX. | Yes. |
| R-CMP-002.5 | When | When the system reads an external image whose name has any other ending, the system shall parse it as S19. | Yes. |
| R-CMP-002.6 | If | If both sides name the same file, then the system shall refuse the compare with the status `Compare refused: both sides are the same file.` | Partly: adds `— the B path was not updated (clipboard paste failed?)`, also for two equal variants (D14-12); tested (`test_tc1801_identical_paths_are_refused`, `test_tc1801_same_file_different_spelling_is_refused`). |
| R-CMP-002.7 | If | If no project is open and a side names a variant, then the system shall refuse the compare with the reason `No active project: cannot resolve variant '<id>'.` | Yes; untested. |
| R-CMP-002.8 | If | If a side names a variant that the open project does not have, then the system shall refuse the compare with the reason `Unknown project variant '<id>'.` | Yes; untested. |
| R-CMP-002.9 | If | If an external path names no file, then the system shall refuse the compare with the reason `Could not resolve external image path: <typed path>`. | Yes; tested (`test_external_unresolvable_returns_refused`, `test_at_016_3_unresolvable_path_refuses_without_crash`). |
| R-CMP-002.10 | If | If reading an image raises an error, then the system shall refuse the compare with the reason `<error type>: <message>`. | Yes; tested (`test_parse_failure_isolated_to_refused`). |
| R-CMP-002.11 | If | If both sides are refused, then the system shall show both reasons in one status, separated by `; `. | Yes; untested. |
| R-DIFF-LOADFAIL-001.1 | If | If a side is a load failure, then the system shall show the status `Compare failed: <label> loaded no image (file has content but no valid records).` | Yes; tested (`test_at_016_2_degenerate_image_is_flagged_not_silent`). |
| R-DIFF-LOADFAIL-001.2 | If | If both sides are load failures, then the system shall name both labels in that status, separated by `, `. | Yes; untested. |
| R-DIFF-LOADFAIL-001.3 | When | When a side's image has at least one byte, the system shall not report that side as a load failure. | Yes; tested (`test_at_016_4_legit_small_valid_image_is_not_flagged`). |
| R-CMP-002.12 | When | When a compare succeeds, the system shall show the status `Compared <label A> vs <label B>: <n> runs.` | Yes; tested (`test_at_016_1_two_wellformed_images_show_changed_runs`). |
| R-DIFF-LOADFAIL-001.4 | U | The system shall show the A2B Diff status as plain text, never as markup. | Yes (`screens_directionb.py:8126-8131`). |

### S14.3 · Artifact usage (CTX-COMPARE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-003.1 | When | When a compare succeeds, the system shall compute each image's artifact usage against the loaded A2L and the loaded MAC. | Yes; tested (`test_coverage_counts_match_hand_computed`, `test_usage_summary_all_four_outcomes`). |
| R-CMP-003.2 | If | If no A2L or no MAC is loaded, then the system shall give that artifact the status absent. | Yes; tested (`test_absent_artifacts_summary_none`). |
| R-CMP-003.3 | U | The system shall compute the runs without regard to the artifact usage. | Yes; tested (`test_artifact_context_applies_to_external`). |
| R-CMP-003.4 | When | When a compare succeeds, the system shall show each image's usage summary in the run list. | Yes; tested (`test_tc_b78_48_hostile_artifact_summary_renders_verbatim`). |

### S14.4 · The A2B Diff screen: selection, run list, windows (CTX-DIFFSCREEN)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-006.1 | When | When the A2B Diff is shown, the system shall fill both variant lists of CTX-DIFFSCREEN. | Yes (`app.py:5357-5387`, `:7468`). |
| R-CMP-006.2 | When | When the A2B Diff is shown, the system shall select the first entry of each variant list. | Yes (`screens_directionb.py:8377-8380`). |
| R-CMP-006.3 | When | When a side's variant list shows `(external path below)`, the system shall take that side from its external path box. | Yes (`screens_directionb.py:8529-8535`). |
| R-CMP-006.4 | U | The system shall show the variant ids in the variant lists as plain text, never as markup. | Yes (`screens_directionb.py:8373-8376`). |
| R-CMP-006.5 | When | When a compare succeeds, the system shall show the run list of CTX-DIFFSCREEN. | Yes; tested (`test_tc022_render_shows_runs_and_hex_windows`). |
| R-CMP-006.6 | If | If a compare has more runs than the display caps allow, then the system shall show the capped runs and the cap line. | Yes; tested (`test_tc029_display_caps_bound_on_screen_runs`, `test_at_b78_18_display_caps_and_notice_survive`). |
| R-CMP-006.7 | U | The system shall apply the display caps to the screen only, never to the report. | Yes; tested (`test_at_b78_31_written_report_is_complete_under_display_caps`). |
| R-CMP-006.8 | When | When a compare with at least one run succeeds, the system shall select its first run. | Yes; tested (`test_at_b78_17_exactly_one_entry_is_visibly_selected`). |
| R-DIFF-SCR.1 | When | When the operator moves the selection in the run list, the system shall show the selected run in both windows from its first page. | **NEW** · Yes; tested (`test_at_b78_20_selection_re_renders_both_windows`). |
| R-DIFF-SCR.2 | U | The system shall let Up and Down reach every shown run and no header line of the run list. | **NEW** · Yes; tested (`test_at_b78_15_every_run_reachable_by_keyboard`). |
| R-DIFF-SCR.3 | When | When a run is selected, the system shall show in each window the rows of CTX-DIFFSCREEN window. | **NEW** · Yes; tested (`test_at_b78_22_window_spans_the_run_plus_context`, `test_tc_b78_50_the_surplus_rows_are_split_around_the_run`). |
| R-DIFF-SCR.4 | U | The system shall show the same addresses on the same rows of the image A and image B windows. | **NEW** · Yes (`screens_directionb.py:8895-8897`). |
| R-DIFF-SCR.5 | If | If a compare has no run, then the system shall show the windows `Image A — no differing runs` and `Image B — no differing runs`. | **NEW** · Yes; tested (`test_tc_b78_23_zero_runs_keeps_the_no_runs_text`). |
| R-DIFF-SCR.6 | When | When the operator presses `]`, the system shall show the next page of both windows. | **NEW** · Yes; tested (`test_tc_b78_52_pagination_reaches_bytes_past_the_pane`). |
| R-DIFF-SCR.7 | When | When the operator presses `[`, the system shall show the previous page of both windows. | **NEW** · Yes; untested. |
| R-DIFF-SCR.8 | If | If the operator presses `]` on the last page or `[` on the first page, then the system shall keep the page shown. | **NEW** · Yes (`screens_directionb.py:8341`, `:8891`). |
| R-CMP-006.9 | U | The system shall show a run's range as its first and its last address, on screen and in the reports. | No: the end shown is one past the last byte (D14-16). |

### S14.5 · The A2B Diff screen: size regimes (CTX-DIFFSCREEN)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DIFF-SCR.9 | While | While the A2B Diff is in the wide regime, the system shall show the run list 26 columns wide beside the windows. | **NEW** · Yes; tested (`test_tc_b78_29_the_layout_flips_exactly_once`). |
| R-DIFF-SCR.10 | While | While the A2B Diff is in the narrow regime, the system shall give the windows the full width. | **NEW** · Yes; tested (`test_tc_b78_53_the_overlay_reserves_no_width`). |
| R-DIFF-SCR.11 | When | When the operator presses `f` in the narrow regime, the system shall toggle the run list over the windows. | **NEW** · Yes; tested (`test_tc_b78_53_the_overlay_reserves_no_width`). |
| R-DIFF-SCR.12 | When | When the run-list overlay opens, the system shall move the focus to the run list. | **NEW** · Yes (`screens_directionb.py:8295-8297`). |
| R-DIFF-SCR.13 | When | When the operator presses Escape with the run-list overlay open, the system shall close the overlay. | **NEW** · Yes; tested (`test_tc_b78_51_escape_dismisses_without_shadowing`). |
| R-DIFF-SCR.14 | When | When the run-list overlay closes, the system shall return the focus to the widget that held it before the overlay opened. | **NEW** · Yes (`screens_directionb.py:8299-8304`). |
| R-DIFF-SCR.15 | When | When the operator presses Escape with the run-list overlay closed, the system shall leave the key to the rest of the app. | **NEW** · Yes; tested (`test_tc_b78_51_escape_dismisses_without_shadowing`). |
| R-DIFF-SCR.16 | While | While the A2B Diff is in the wide or notice regime, the system shall ignore `f`. | **NEW** · Yes (`screens_directionb.py:8275-8276`). |
| R-DIFF-SCR.17 | While | While the A2B Diff is in the notice regime, the system shall ignore `]` and `[`. | **NEW** · Yes (`screens_directionb.py:8267-8274`). |
| R-DIFF-SCR.18 | While | While the A2B Diff is in the notice regime, the system shall show the notice text of CTX-DIFFSCREEN in place of the run list and the windows. | **NEW** · Yes; tested (`test_at_b78_29_notice_names_every_unsatisfied_axis`, `test_tc_b78_32_a_single_axis_failure_names_that_axis`). |
| R-DIFF-SCR.19 | When | When the terminal size changes, the system shall apply the regime of the new size. | **NEW** · Yes; tested (`test_tc_b78_30_a_resize_across_the_breakpoint_follows`). |
| R-DIFF-SCR.20 | When | When the regime changes while a run is shown, the system shall fit the windows to their new height. | **NEW** · Yes (`screens_directionb.py:8180-8187`). |

### S14.6 · Check spec for the report (from S0 HLR-010, LLR-010.1, LLR-010.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DIFF-CHK.1 | When | When the A2B Diff is shown, the system shall list in the check-spec list the `.json` files of the folder where the Check Editor saves check specs, by name, links left out. | Partly: lists `workarea/patches/` only; with a project open specs are saved in `<project>/checks/` (D14-17); tested (`test_tc_b94_15_dropdown_population`). |
| R-DIFF-CHK.2 | U | The system shall label a file ending in `.chk.json` as `<name> CHECK` and any other file as `<name> PATCH`. | Yes; tested (`test_tc_b94_15_dropdown_population`). |
| R-DIFF-CHK.3 | If | If the check-spec folder holds no `.json` file, then the system shall leave out the check row. | Yes (`screens_directionb.py:8115-8116`, `:8480-8484`). |
| R-DIFF-CHK.4 | When | When the operator picks `(no check spec)`, the system shall show the status `Check spec: none — the report gains no addendum.` | Yes. |
| R-DIFF-CHK.5 | If | If the picked file is a link or lies outside the check-spec folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.` | Yes. |
| R-DIFF-CHK.6 | If | If reading the picked file gives errors, then the system shall show the status `Check spec not loaded — <first three findings as [<code>] <severity>: <message>, separated by "; ">`. | Yes. |
| R-DIFF-CHK.7 | If | If the picked document is not a check document, then the system shall show the status `Check spec: '<name>' is a kind='<kind>' document, not a check spec — the report gains no addendum.` | Yes. |
| R-DIFF-CHK.8 | When | When a check spec loads, the system shall show the status `Check spec '<name>' loaded — <n> declared field(s) will ride the report.` | Yes; tested (`test_at_b94_12_writer_dropdown_report_chain`). |
| R-DIFF-CHK.9 | While | While a check spec is loaded, the system shall end each diff report with the section `## Checks`: `- Check spec: <name>`, `- Declared fields: <n> (0 byte changes — image never modified)` and the table # · Field · Address · Expected. | Yes; tested (`test_tc_b94_16_report_addendum`). |
| R-DIFF-CHK.10 | If | If the loaded check spec has no entry, then the system shall write `No declared fields.` in place of the table. | Yes. |
| R-DIFF-CHK.11 | U | The system shall name each declared field by the loaded A2L or MAC symbol at its address, or `entry <i>` when no symbol is there. | Yes (`diff_report_service.py:1527-1533`). |

### S14.7 · The diff report (CTX-DIFFREPORT)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-006.10 | If | If no compare has succeeded since the last refused or failed one, then the system shall refuse Report with the status `No comparison yet — press Compare first.` | Partly: only before the first compare; after a refused or failed compare Report writes the earlier or the failed pair (D14-13; re-verified at 570b4b5, `app.py:7496`). The first-compare arm: tested (`test_tc_b100_51_diff_report_without_a_comparison_begins_nothing`). |
| R-CMP-005.1 | While | While a project is open, the system shall write the diff report into `<project>/reports/`, creating the folder if it does not exist. | Yes; tested (`test_tc024_report_trigger_surfaces_paths`). |
| R-CMP-005.2 | While | While no project is open, the system shall write the diff report into the folder typed in the report destination box. | Yes; tested (`test_no_project_valid_directory_writes_one_file`). |
| R-CMP-005.3 | If | If no project is open and the destination box is empty, then the system shall refuse the report with the reason `No destination directory supplied for a no-project diff report - refusing to write (no implicit default).` | Yes; tested (`test_no_project_empty_path_refused`). |
| R-CMP-005.4 | If | If no project is open and the typed destination is not an existing folder, then the system shall refuse the report with the reason `Destination is not an existing directory: '<typed>' (resolved to <path>) - refusing to write.` | Yes; tested (`test_no_project_nonexistent_dir_refused`, `test_tc024_report_trigger_invalid_dest_refused`). |
| R-CMP-005.5 | If | If `<project>/reports/` is a link, then the system shall refuse the report with the reason `Reports destination is a symbolic link - refusing to write: <path>`. | No: only the before/after report checks it (D14-11). |
| R-CMP-005.6 | U | The system shall name the report files as CTX-DIFFREPORT file name. | Yes; tested (`test_filename_scheme_and_same_second_collision`, `test_html_filename_scheme_and_collision`). |
| R-CMP-005.7 | U | The system shall never replace an existing file with a report. | Partly: the name is probed, then written without an exclusive create (D14-11); tested (`test_collision_never_overwrites_existing_file`). |
| R-CMP-005.8 | If | If 100 report names for the same second are taken, then the system shall show the status `Diff report failed: FileExistsError: 100 diff reports already exist for second <ts>.md - refusing to overwrite an existing report`. | Yes; untested. |
| R-CMP-005.9 | When | When both report files are written, the system shall show the status `Diff report written: <md path>  \|  <html path>`. | Yes; tested (`test_tc024_report_trigger_surfaces_paths`, `test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome`). |
| R-CMP-005.10 | If | If writing the report raises an error, then the system shall show the status `Diff report failed: <error type>: <message>`. | Yes; tested (`test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome`, the HTML-raises arm). |
| R-CMP-005.11 | U | The system shall keep the screen responsive while it writes the diff report. | Yes (worker, `app.py:6428-6519`). |
| R-CMP-004.1 | U | The system shall write the sections of CTX-DIFFREPORT in their order. | Yes; tested (`test_report_sections_present_in_order`). |
| R-CMP-004.2 | U | The system shall list every run in the report, without any cap. | Yes; tested (`test_markdown_file_is_complete_no_truncation`). |
| R-CMP-004.3 | When | When a hex window holds a changed run, the system shall write its diff block. | Yes; tested (`test_changed_run_emits_diff_fenced_block`, `test_ac4_markdown_diff_block_format_unchanged`). |
| R-CMP-004.4 | U | The system shall merge two hex windows that are 5 rows or less apart. | Yes; tested (`test_ac1_boundary_five_rows_merges_six_does_not`). |
| R-CMP-004.5 | U | The system shall fill the Symbols column as CTX-DIFFREPORT symbols. | Yes; tested (`test_symbol_annotation_only_intersecting_run`, `test_annotation_absent_without_context`). |
| R-CMP-004.6 | If | If both images have no byte, then the system shall write `Memory maps unavailable - hex windows omitted.` in place of the hex windows. | Yes. |
| R-CMP-004.7 | U | The system shall write the HTML file as CTX-DIFFREPORT HTML form. | Yes; tested (`test_html_export_complete_and_safe`, `test_ac3_html_side_by_side_highlights_changed_bytes`). |
| R-CMP-004.8 | U | The system shall HTML-escape every value it embeds in the HTML file. | Yes; tested (`test_html_escapes_embedded_payload`, `test_ac3_hostile_gutter_bytes_escaped_in_html`). |
| R-CMP-004.9 | U | The system shall write image labels, paths and symbol names into the Markdown file as inert text. | No: written raw; a `\|` in a symbol breaks the run table (D14-10). |
| R-CMP-004.10 | U | The system shall write no report content to the log. | Yes; tested (`test_module_performs_no_logging`). |
| R-CMP-004.11 | U | The system shall write the diff report files as S12 R-TUI-097.1 states: UTF-8 with LF line ends on every host. | No: written in text mode, so Windows gets CR LF (D14-19). |
| R-CMP-004.12 | When | When both diff report files are written, the system shall log at INFO `report kind=diff source=<source> output=<md path>\|<html path> outcome=ok`, with <source> the open project's folder name, else the typed destination, else `-`. | **NEW** · Yes; untested (`app.py:6418-6420`, `:6511-6513`). |
| R-CMP-004.13 | If | If the diff report is refused or fails, then the system shall log at WARNING `report kind=diff source=<source> output=- outcome=<refused, refused (html) or failed: <error type>>`. | **NEW** · Yes; untested (`app.py:6476-6478`, `:6490-6492`, `:6501-6503`). |
| R-CMP-005.12 | U | The system shall write the A2B Diff report without the report filter (S12 CTX-RPT-FILTER). | Yes (`app.py:6390-6402`). |

**(from batch-100 HLR-176: LLR-176.2c)** The progress line's format, spinner, elapsed time and end rules are S6's.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CMP-005.13 | When | When the system starts a diff report, the system shall show the diff report progress line at step 1. | Yes; tested (`test_tc_b100_50_each_worker_action_begins_with_a_progress_line`). |
| R-CMP-005.14 | When | When the system has written the Markdown file of a diff report, the system shall move the diff report progress line to step 2. | Yes; tested (`test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome`: the bar reads 50 %). |
| R-CMP-005.15 | When | When a diff report ends, the system shall also write its report status to the status log. | Yes; tested (`test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome`). Before batch-100 the outcome showed on the A2B Diff screen only (D14-22). |

### S14.8 · Flow changes in the diff report (from S0 LLR-143.2)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DIFF-FLOWCHG.1 | When | When the operator writes a diff report whose image B is a file that the last flow run wrote, and that run recorded a change or a refusal, the system shall add the section `## Flow change attribution`. | Partly: only the last Flow Builder run counts; Flow Execution runs never do (D14-18); tested (`test_tc717_flow_produced_image_diff_references_all_flow_changes`). |
| R-DIFF-FLOWCHG.2 | If | If image B is not a file that the last flow run wrote, then the system shall leave the section out. | Yes; tested (`test_tc717_non_flow_b_renders_the_shipped_report_unchanged`). |
| R-DIFF-FLOWCHG.3 | U | The system shall write one row per change record of that run: change document · symbol or `-` · address · length · disposition · the runs its range overlaps. | Yes; tested (`test_tc717_flow_produced_image_diff_references_all_flow_changes`). |
| R-DIFF-FLOWCHG.4 | If | If an applied change overlaps no run, then the system shall write `(no diff)` in its runs cell. | Yes. |
| R-DIFF-FLOWCHG.5 | If | If a change was not applied, then the system shall write `—` in its runs cell. | Yes. |
| R-DIFF-FLOWCHG.6 | When | When a run overlaps no change of the flow, the system shall write the line `- 0x<start>–0x<end> <kind>: no flow change`. | Yes. |
| R-DIFF-FLOWCHG.7 | When | When the flow run recorded a refusal, the system shall write the line `- refused: <change document>[ symbol '<symbol>'][ @ 0x<address>] [<code>] <message>`. | Yes. |
| R-DIFF-FLOWCHG.8 | U | The system shall write the same attribution in the HTML file. | Yes; tested (`test_tc717_html_flow_change_attribution_pairs_the_markdown`). |

### S14.9 · The before/after report (CTX-BEFOREAFTER)

R-TUI-049.2 (S10) gives the Patch Editor's Write before/after report control the same effect as `b`.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-BEFORE-AFTER-REPORT-001.1 | When | When a save-back succeeds with a project open, the system shall show the offer `Before/after report ready - press b to write it to the project reports directory.` | Partly: the text ends in `(action: before_after_report)`, and the offer also shows with no project, where `b` is refused (D14-14). |
| R-BEFORE-AFTER-REPORT-001.2 | When | When the operator presses `b`, the system shall write the before/after report pair. | Yes; tested (`test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path`). |
| R-BEFORE-AFTER-REPORT-001.3 | When | When the system writes the before/after report, the system shall read the original image and the saved patched image from their files. | Yes; tested (`test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path`). |
| R-BEFORE-AFTER-REPORT-001.4 | If | If no change document has been applied this session, then the system shall refuse the report with the reason `No applied change summary - apply a change document and save the patched image first.` | Yes; tested (`test_tc_038_4_all_refusal_classes_write_no_files`). |
| R-BEFORE-AFTER-REPORT-001.5 | If | If the last apply has no saved patched image, then the system shall refuse the report with the reason `No saved patched image - the save-back was declined or refused.` | Yes; tested (`test_at_038b_declined_saveback_trigger_refuses_and_writes_nothing`). |
| R-BEFORE-AFTER-REPORT-001.6 | If | If no image is loaded, then the system shall refuse the report with the reason `No image loaded - the original (before) side is unavailable.` | Yes; tested (`test_tc_038_4_all_refusal_classes_write_no_files`). |
| R-BEFORE-AFTER-REPORT-001.7 | If | If the original image file no longer exists, then the system shall refuse the report with the reason `Original image no longer on disk: <path>`. | Yes; tested (`test_at_038c_missing_original_trigger_refuses_and_writes_nothing`). |
| R-BEFORE-AFTER-REPORT-001.8 | If | If the saved patched file no longer exists, then the system shall refuse the report with the reason `Saved patched image no longer on disk: <path>`. | Yes; tested (`test_tc_038_4_all_refusal_classes_write_no_files`). |
| R-BEFORE-AFTER-REPORT-001.9 | If | If the loaded image is not the image the patched file was saved from, then the system shall refuse the report with the reason `Stale change summary: the loaded image (<path>) is not the image the patched file was saved from (<path or unknown>) - re-apply and save in the current session.` | Yes; tested (`test_at_038d_stale_summary_cross_project_refusal_writes_nothing`). |
| R-BEFORE-AFTER-REPORT-001.10 | If | If the saved patched file lies outside the open project folder, or outside the work area with no project open, then the system shall refuse the report with the reason `Stale change summary: saved patched image <path> lies outside the current <project directory or work area> <folder>.` | Yes; tested (`test_tc_038_4_all_refusal_classes_write_no_files`). |
| R-BEFORE-AFTER-REPORT-001.11 | If | If no project is open, then the system shall refuse the report with the reason `No active project - the before/after report needs a project reports/ destination; use the manual A<->B Diff report (key 7) with an explicit destination instead.` | Partly: says `(screen 7)`; the A2B Diff is rail position 8 (D14-14); tested (`test_tc_038_4_no_project_refusal_names_manual_ab_path`). |
| R-BEFORE-AFTER-REPORT-001.12 | If | If `<project>/reports/` is a link, then the system shall refuse the report with the reason `Reports destination is a symbolic link - refusing to write: <path>`. | Yes; tested (`test_tc_038_3_symlink_reports_destination_refused`). |
| R-BEFORE-AFTER-REPORT-001.13 | If | If more than one refusal applies, then the system shall give the reason of the first in the order of rows .4 to .12. | Yes (`before_after_service.py:262-326`). |
| R-BEFORE-AFTER-REPORT-001.14 | If | If the system refuses the before/after report, then the system shall write no file. | Yes; tested (`test_tc_038_4_all_refusal_classes_write_no_files`). |
| R-BEFORE-AFTER-REPORT-001.15 | If | If the system refuses the before/after report, then the system shall show the status `Before/after report refused: <reason>`. | Yes; tested (`test_tc_b100_51_before_after_ends_once_and_logs_its_outcome`, refused arm). |
| R-BEFORE-AFTER-REPORT-001.16 | When | When both before/after files are written, the system shall show the status `Before/after report written: <md path> \| <html path>`. | Yes; tested (`test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path`, `test_tc_b100_51_before_after_ends_once_and_logs_its_outcome`). |
| R-BEFORE-AFTER-REPORT-001.17 | If | If writing the before/after report raises an error, then the system shall show the status `Before/after report failed: <error type>: <message>`. | Yes; untested. |
| R-BEFORE-AFTER-REPORT-001.18 | U | The system shall write the before/after report with the provenance and linkage sections of CTX-BEFOREAFTER. | Yes; tested (`test_provenance_and_linkage_render_in_both_formats`, `test_zero_entries_linkage_states_no_entries`). |
| R-BEFORE-AFTER-REPORT-001.19 | U | The system shall list every entry of the last apply in the linkage table, whatever its disposition. | Yes; tested (`test_provenance_and_linkage_render_in_both_formats`). |
| R-BEFORE-AFTER-REPORT-001.20 | If | If an entry had no prior bytes, then the system shall write `(none - created into hole)` in its Before cell. | Yes; tested (`test_ac5_markers_unchanged`). |
| R-BEFORE-AFTER-REPORT-001.21 | U | The system shall remove control characters from the provenance and linkage values in both files. | Yes; tested (`test_tc_038_3_ctl_symbol_renders_identically_in_md_and_html_pair`). |
| R-BEFORE-AFTER-REPORT-001.22 | U | The system shall escape `\|` in the Markdown linkage cells. | Yes; tested (`test_pipe_bearing_symbol_md_escaped_html_intact`, `test_ac5_hostile_bytes_keep_md_table_and_html_safe`). |
| R-BEFORE-AFTER-REPORT-001.23 | When | When a report filter is set (S12), the system shall apply it to the before/after report. | Yes; tested (`test_tc311_composer_forwards_matcher_filtered_output_both_formats`). |
| R-BEFORE-AFTER-REPORT-001.24 | U | The system shall fill the run table's Symbols column of the before/after report from the loaded A2L and MAC. | No: always `-` (D14-15). |
| R-BEFORE-AFTER-REPORT-001.25 | U | The system shall show only paths and reasons in the before/after status, never entry bytes. | Yes (`app.py:4466-4490`). |
| R-BEFORE-AFTER-REPORT-001.26 | U | The system shall keep the screen responsive while it writes the before/after report. | Yes (worker, `app.py:4399-4490`). |
| R-BEFORE-AFTER-REPORT-001.27 | If | If a report filter is set and its file cannot be read or parsed, then the system shall write no file and show the status `Before/after report refused: <findings, separated by "; ">`. | Yes (`app.py:4365-4377`). |
| R-BEFORE-AFTER-REPORT-001.28 | When | When the system writes an entry's bytes in the Before or After cell, the system shall write them as the bytes cell of CTX-BEFOREAFTER. | **NEW** · Yes; tested (`test_ac5_linkage_cells_carry_ascii_companion`; `diff_report_service.py:351-356`). From S8 D8-14. |
| R-BEFORE-AFTER-REPORT-001.29 | When | When both before/after files are written, the system shall log at INFO `report kind=before-after source=<loaded file name> output=<md path>\|<html path> outcome=ok`. | **NEW** · Yes; tested (`test_before_after_report_generation_logs_to_file`; `app.py:4467-4473`). |
| R-BEFORE-AFTER-REPORT-001.30 | If | If the before/after report is refused or fails, then the system shall log at WARNING `report kind=before-after source=<loaded file name> output=- outcome=<refused or failed: <error type>>`. | **NEW** · Yes; untested (`app.py:4453-4459`, `:4481-4483`). |
| R-BEFORE-AFTER-REPORT-001.31 | When | When the system starts a before/after report, the system shall show the before/after progress line. | Yes; tested (`test_tc_b100_50_each_worker_action_begins_with_a_progress_line`, `test_tc_b100_51_before_after_ends_once_and_logs_its_outcome`). From batch-100 HLR-176 (D14-22). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D14-1 | Batch records inside the rows: Status lines, test lists, "supersedes", the escaped-bug story, module and regex ownership, "imports no Textual", "rail.py unmodified", the substrate note. | Out of the requirements; they stay in the batch records. |
| D14-2 | R-TUI-028 describes the placeholder screen R-CMP-006 replaced. | Delete the row. |
| D14-3 | R-CMP-001 prescribes the result's field set and calls the output "symmetric" and "deterministic". Both properties follow from the kind definitions. | Observable rows only (S14.1). |
| D14-4 | Artifact usage is computed against the A2L and MAC loaded in the session (`app.py:6173-6182`), not "the project's". | Rows say "the loaded A2L / MAC" (R-CMP-003.1). |
| D14-5 | The chapter was incomplete: the run selection, window paging, three size regimes and the overlay (batch-78, ~40 tests in `test_tui_diff_screen.py`) had no requirement. | NEW rows R-DIFF-SCR.1 … .20. |
| D14-6 | S0's HLR-010 / LLR-010.1 / 010.2 (check-spec addendum) and LLR-143.2 (flow changes in the diff) describe this screen's report and no R-row covered them. | Rows R-DIFF-CHK, R-DIFF-FLOWCHG; S0 keeps pointers. |
| D14-7 | The before/after report refuses with no project open (`before_after_service.py:314-319`) and points to the manual A2B Diff report. | Keep (R-BEFORE-AFTER-REPORT-001.11). |
| D14-22 | Batch-100 HLR-176 (Inc 12a, `6057896`; the busy-line verdict of its prototype round) gave the diff and before/after reports the shared progress line in place of the fixed bar values 15 / 55 / 100 / 0 % (`app.py:7538`, `:7603`; `:5449`): the start paints its label at step 1, the diff worker moves to step 2 after the Markdown file, and every end writes the outcome to the status log and returns the bar to 0. The diff report's outcome reached only the A2B Diff screen before; it now also reaches the status log (`app.py:7590-7631`). The reports are not session actions: nothing refuses them as busy, and they refuse nothing. No S14 row named the old bar values. | Rows R-CMP-005.13 … .15 and R-BEFORE-AFTER-REPORT-001.31 (rule D-9: each report's start and steps here; the line's format and the end rules are S6's). Re-pinned tests keep their names (`test_ac4_diff_progress_never_sticks_mid_fill`, `test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path`). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D14-8 | `list_diff_reports`, `DIFF_REPORT_FILENAME_REGEX`, `DIFF_REPORT_HTML_FILENAME_REGEX` (`diff_report_service.py:117-127`, `:674-725`), `BEFORE_AFTER_REPORT_*_FILENAME_REGEX` (`before_after_service.py:73-81`) and `flow_change_census_complete` (`diff_report_service.py:1209-1255`) are used only by tests. | Delete them with their tests (not used). |
| D14-21 | `changes/display.py::format_memory_value` (passed by S8 D8-14) builds a hex, an ASCII and a decimal form; the linkage cells use the first two (`diff_report_service.py:355-356`), and nothing in the product reads the decimal form (`display.py:128`). | Delete the decimal form and its doctest (not used). The cell rule is R-BEFORE-AFTER-REPORT-001.28. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D14-10 | The Markdown diff report writes image labels and paths (`diff_report_service.py:875-882`) and symbol names (`:1008-1013`, `:872`) raw; a `\|` or a Markdown character in a name breaks the table or adds structure. The flow and check sections already use `md_safe`. | Inert text (R-CMP-004.9), the same escaper as the other sections. |
| D14-11 | The diff report picks a free name by probing (`:660-667`) and then writes it (`:1760-1761`, `:2641-2642`); two writers in one second can pick the same name. The project `reports/` folder is created and written with no link check (`:766-769`), while the before/after report refuses a linked `reports/` (`before_after_service.py:320-326`). | Claim the name with an exclusive create, as S0 HLR-155's placement does; refuse a linked `reports/` (R-CMP-005.5, .7). |
| D14-12 | The same-file refusal adds `— the B path was not updated (clipboard paste failed?)` (`app.py:6166-6171`), also when the operator picked the same variant twice. | `Compare refused: both sides are the same file.` (R-CMP-002.6). |
| D14-13 | After a refused compare the screen keeps the earlier result and Report writes it (`app.py:6183-6188`, `:6381-6384`); after a failed compare the bogus runs are kept as the last result (`:6215`) and Report writes them. | Report is refused until a compare succeeds (R-CMP-006.10). |
| D14-14 | The save-back offer ends in `(action: before_after_report)` (`app.py:3729-3734`), a developer name, and shows with no project open, where `b` is then refused. The no-project refusal says `(screen 7)`; the A2B Diff is rail position 8, key 7. | Offer text without the parenthesis, only with a project open; refusal says `(key 7)` (R-BEFORE-AFTER-REPORT-001.1, .11). |
| D14-15 | The before/after composer passes no A2L or MAC to the generators (`before_after_service.py:349-357`), so its run table's Symbols column is always `-`. | Pass the loaded A2L and MAC (R-BEFORE-AFTER-REPORT-001.24). |
| D14-16 | The run list (`screens_directionb.py:8728`), the window header (`:8899`), the report's End column (`diff_report_service.py:1010`) and the flow attribution (`:1159`, `:1179`) print the end as one past the last byte; the Workspace prints the last byte (S5 CTX-WORKSPACE). The report's Length column agrees with neither reading at a glance. | Print the first and the last address everywhere (R-CMP-006.9); same text width. |
| D14-17 | The check-spec list scans `workarea/patches/` only (`app.py:5403`, `:5427`, `:5507`); with a project open the Check Editor saves specs to `<project>/checks/` (S9 D9-15, S10 D10-25), so they never appear here. | List the folder the check save uses (R-DIFF-CHK.1), as S9 and S10 decided. |
| D14-18 | The flow-change attribution looks only at `_last_flow_run`, which only the Flow Builder's Run sets (`app.py:2895`, `:6408-6417`); images written by Flow Execution lanes, where flows now normally run, never get it. | Also check the files the last Flow Execution run wrote (R-DIFF-FLOWCHG.1). |
| D14-19 | The diff and before/after reports are written with `Path.write_text` (`diff_report_service.py:1761`, `:2642`), which writes CR LF on Windows; S12 R-TUI-097.1 asks every report file for LF on every host, and the flow and chain-set reports already go through S12's encoder. | Write through S12's encoder (R-CMP-004.11). |

**Prototype first** (visual; prototype round with real captures and your verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D14-20 | The run kinds are painted amber `#d9a35b`, red `#e06c75`, cyan `#4ec9d4` on screen (`screens_directionb.py:7862-7866`) and `#b58900`, `#dc322f`, `#268bd2` in the HTML report (`diff_report_service.py:131-135`): neither is S3's palette, and the legend (`k`) has no block for them. | Which palette colours mean changed / only A / only B, the same on screen and in HTML, and the legend block that explains them. |

**Passed to other groups**

- **S1**: add the A2B Diff to the safe-text views; the status shows file names with markup off but keeps control characters (`app.py:6211-6213`).
- **S6**: the A2B Diff rail position (8) and key (`7`).
- **S7**: the A2B Diff has no help section and no title row for the `?` chip (D7-27, D7-30); `f`, `[`, `]`, Escape belong in its key-bar row (CTX-KEYBAR lists them).
- **S9 / S10**: the check-spec folder must be the one the check save uses (D14-17).
- **S10**: R-TUI-049 (the before/after control) stays S10's; its effect is R-BEFORE-AFTER-REPORT-001.2.
- **S12** (absorbed): the report filter drives the before/after report and is ignored by the A2B Diff report (R-BEFORE-AFTER-REPORT-001.23, .27, R-CMP-005.12); the LF rule R-TUI-097.1 applies to the diff reports (D14-19).
- **S12**: diff, before/after, chain-set and flow-A2B reports are `.md` files in `<project>/reports/` that the Reports dialog lists after the project reports, in no order (`report_service.py:1457-1466`); R-TUI-097 (the shared encoder) is S12's and is cited, not rewritten.
- **S15**: the flow A2B block writes its report through this generator (`<ts>-flow-a2b.md`); S15 owns that row. Flow Execution must keep its last run's written files for D14-18.
- **S0**: pointers from HLR-010, LLR-010.1, LLR-010.2 and LLR-143.2 to S14.6 and S14.8; R-TUI-028 is deleted (D14-2).

---

**Received from later groups** (after all groups were written)

- S14.1 (S8: `format_memory_value`; the offer after a save-back) → row R-BEFORE-AFTER-REPORT-001.28 and the CTX-BEFOREAFTER "bytes cell" now defined here (it cited "S8 display form", which S8 D8-14 removed); D14-21 deletes the unused decimal form; the offer is D14-14.
- S14.2 (S9: the addendum built from a spec; the Addendum tab) → covered by S14.6 (R-DIFF-CHK.x); the Check Editor's Addendum tab stays S9's.
- S14.3 (S10: R-BEFORE-AFTER-REPORT-001 and the control's report) → covered by S14.9; S10 R-TUI-049.2 now cites R-BEFORE-AFTER-REPORT-001.2.
- S14.4 (S12: the filter and the shared log line) → the filter is covered by R-BEFORE-AFTER-REPORT-001.23, .27 and R-CMP-005.12; rows R-BEFORE-AFTER-REPORT-001.29, .30, R-CMP-004.12, .13 for the log line (`app.py:564-612`).
- S14.5 (S15: the flow-A2B report; the chain-set run's written files) → covered by CTX-DIFFREPORT (S15 R-FLOW-A2B.5) and R-DIFF-FLOWCHG.1 (D14-18); each Flow Execution lane keeps its last written files (`flow_screens.py:3455`).

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (4): R-CMP-005.13, .14, .15 (the diff report's progress line and its outcome in the status log), R-BEFORE-AFTER-REPORT-001.31 (the before/after progress line).
- Rows changed: none. Cells changed (tests named): R-CMP-006.10 (still Partly, D14-13), R-CMP-005.9, R-CMP-005.10 (untested → tested), R-BEFORE-AFTER-REPORT-001.15, .16. CTX-DIFFREPORT gains the `HTML report refused: <reason>` status, which the code paints at 093a7c0 and 570b4b5.
- Rows retired: none. Decisions added: D14-22. Decisions superseded: none.
- Re-checked, still open at 570b4b5: D14-13 (`app.py:7496`), D14-14 (the offer text, `app.py:4769-4770`), D14-15 (`action_before_after_report` changed only by the begin).
- Passed (scratch `passed-sweep.md`): S6 (the two report actions' labels and steps are named in CTX-DIFFREPORT and CTX-BEFOREAFTER).
- Consolidation: section 6 recounted after the lint fix (R-CMP-004.9, whose cell holds an escaped `\|`, was not counted before): 135 rows, 37 / 46 / 8 / 44 / 0. The S6 item (the two reports as long actions, the diff report's outcome as the newest message line) is already here (R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31). No row changed.

## 6. Counts

| | Old S14 | Strict |
|---|---:|---:|
| Requirement statements | 8 rows (1 superseded) + 1 note | 135 rows (25 NEW, 4 from batch-100; R-CMP-004.9 was not counted before the lint fix) |
| Statements the code contradicts or that are not product behaviour | 5 (028 superseded; 001/004/006 design; 003 "project" artifacts) | 0 |
| Rows by form: U / When / While / If / Where | — | 37 / 46 / 8 / 44 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 21 (8 follow the code or move, 2 remove, 10 correct a defect, 1 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", no repeated id.

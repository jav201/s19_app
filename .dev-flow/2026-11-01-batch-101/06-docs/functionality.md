# Functionality — s19_app — Batch 2026-11-01-batch-101

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (engineers and leads who use or maintain the tool). Purpose: understand what the tool now does differently, and what users will notice.

> **Owed in.** `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch.

## 🔑 At a glance (read first)

- **What this batch added:** the release-hardening pass for v1.0.0. One strict-EARS requirements canon; a test gate without false timing failures; documents that resolve `symbol` entries; the CRC Designer and Check Editor correct after every write and responsive at 10 MB; reports that write full hex windows, escape hostile names and write atomically; flow and chain-set saves contained inside the work area; quiet, ordered A2L parsing; dead surfaces removed and Escape closing Reports; and help/legend/README/developer docs that describe the app as shipped.
- **Capabilities:**
  - One requirements file, one strict-EARS sentence per row, one stable id per row (S0 … S17).
  - The `serial_timing` marker runs the timing arms apart and serially; QC-TM reports margins, QC-OR reads every painted line, QC-BC re-runs every node that asserts a changed observable; CI runs the same two lanes.
  - Change/check documents resolve `symbol` entries through the loaded (or project's) A2L; the per-entry JSON edit works on a symbol entry and says plainly when it cannot.
  - The CRC Designer recomputes after every in-place write (apply, save-back, Save project commit); the Check Editor keeps included parameters, expected bytes and spec entries; both stay responsive on the 10 MB demo image.
  - Before/after and diff reports are complete (whole hex windows), inert (escaped names), and atomic (a random staging name, then a rename).
  - A saved flow keeps its own name; a confirm re-run says so; flow and chain-set saves never write a byte through a link or outside the work area.
  - Hex jumps show their target as the second row; unload clears stale state; focus never lands in a hidden window; views follow in-place writes.
  - A2L files parse the ASAM block names without "unrecognized block" noise; each issue sits under its own severity, errors first; MEMORY_SEGMENT records read.
  - Dead surfaces (VariantHelpScreen, the view aliases, the issue-jump trio, the hidden Flow widgets) are removed; Escape closes the Reports viewer.
  - Help, legend, README, SECURITY.md, the 1.0.0 release notes and the user guide describe the shipped app.
- **How to use it:** the same TUI (`S19TuiApp`) and the same keys. Nothing a user already does is taken away; the changes remove noise (A2L unrecognized blocks, dead widgets), make views honest (coverage after a write, reports that are whole and inert), and make saves safe (contained in the work area). See *Detail* below for what each surface now does.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

> Behaviour below is stated as the contract states it. Each area names its story (`US-`), its requirement rows (`R-…`) and the increment that shipped it. The full per-requirement trace is `traceability-matrix.md`.

### The requirements canon (US-101.1 · R-DOC-CANON.1 … .11 · Inc 1)

The system keeps its requirements in one file, `REQUIREMENTS.md`, at the repository root. Each requirement is one table row with an id, a form and a sentence; the sentence is written in the form its row names, with the obligation word exactly once, and as one sentence. Ids are unique and grouped under modules S0 … S17 in order. The file `REQUIREMENTS.md` replaced is kept byte-for-byte in `docs/requirements/history/`, and the decisions behind each module's rows live in `docs/requirements/review/`. From Inc 1 on, every increment writes its rows straight into `REQUIREMENTS.md` in the strict format. The guard is `tests/test_requirements_canon.py` (RED 11/11 on the base, GREEN 11/11 after the swap).

### The test gate: timing arms, CI lanes, margins, oracles, census (US-TST-1 … US-TST-5 · R-TST-001 … .091 · Inc 2)

- **Timing arms run apart (US-TST-1).** The `serial_timing` marker registers with the description `a wall-clock timing arm; run apart and serially`, every timing arm carries it, and a guard fails when an arm lacks it or a non-arm carries it (R-TST-001 … R-TST-006). The release gate is the parallel lane `pytest -n 8 -m "not serial_timing"` followed by the serial lane `pytest -m serial_timing` (R-TST-007 … R-TST-009).
- **CI runs the same lanes (US-TST-2).** On a pull request CI runs `-m "not slow and not serial_timing"` then `-m "serial_timing and not slow"`; on a push it drops the `slow` excludes; the serial lane runs even when lane 1 fails; the six history arms never skip; lane 1 stops at 180 min on a push / 120 min on a pull request, and the `tui-ci` job at 240 min (R-TST-010 … R-TST-018, R-TST-090, R-TST-091).
- **Waits and post-press reads (US-TST-3).** Shared wait helpers bound by the wall clock (60 s default), yield the event loop, and let the app process one pause before the first check (R-TST-020 … R-TST-024). The post-press rule and the clock rule are written into the test conventions (R-TST-030 … R-TST-032, R-TST-047).
- **QC-TM margins.** Every upper timing bound passes through the margin reporter; a guard fails any bound that is not a reporter call; the reporter attaches `qc_tm` to the item so the call report, teardown report and junit carry it; the session prints a `QC-TM timing margins` section in ascending margin order, prefixing `LOW ` under 20 % (R-TST-040 … R-TST-046).
- **QC-OR status oracle.** Status oracles collect every line the app paints after a mark, in order and uncapped; a guard fails any file that added a newest-line wait over its baseline (R-TST-050 … R-TST-052).
- **QC-BC census.** When an increment changes the order or source of an observable, its gate greps `tests/` for every node that asserts it and runs them, whatever module they sit in (R-TST-060).
- **CI deferral and version goldens (US-TST-4, US-TST-5).** The batch's CI record lists each FAILED node of the deferred batch-100 run `41372953464` marked `known` or `new` (R-TST-070 … R-TST-072); report goldens hold the tool-version token, never a tool version, and substitute the package's version at run time (R-TST-080 … R-TST-082).

### Save project margin and the vanished folder (US-PROJ-SAVE-1, US-PROJ-SYNC-1, US-TST-PAINT-1 · Inc 3)

Save project keeps its time bound with room to spare (R-PROJ-001.13, R-PROJ-GATHER.12/.13, R-PROJ-ROLLBACK.9/.2; 5/5 on Windows and Linux under 0.8 s). A project whose folder was deleted outside the app is not silently brought back (R-PROJ-002.12 … .14). The panel and append timing arms measure what the app actually paints — the Load-result panel clock starts at the install stamp and stops at the paint stamp, the append clock stops at the outcome-line stamp, and the bound is 1 second (R-TST-110 … R-TST-113).

### Symbol resolution (US-SYM-1 … US-SYM-3 · R-CHG-SYM.9 … .13, R-TUI-058.9 · Inc 4)

Documents opened against the loaded A2L resolve their `symbol` entries through that A2L at all six session reads (R-CHG-SYM.9, .10, .13). A variant run uses the project's A2L and nothing implicit (R-CHG-SYM.11, .12). The per-entry JSON edit works on a symbol entry and says plainly when it cannot (R-CHG-SYM.9 alternative 4, R-TUI-058.9). The headless entry point `run_checks_for_project` is deleted.

### CRC Designer and Check Editor follow every write (US-CRC-FRESH-2, US-CHK-KEEP-1, US-CHK-SPEC-1 · R-CRC-PREVIEW-002.1/.5, R-CHKED-* · Inc 5)

The CRC Designer recomputes every result surface when the loaded image changes while it is displayed, and when it becomes displayed while its coverage is stale — an in-place write (a Patch Editor apply, a save-back, or a Save project commit) is an image change (R-CRC-PREVIEW-002.1, .5). The Check Editor keeps included every parameter the loaded A2L still lists, drops one it no longer lists, and keeps the field set unchanged on a Write (R-CHKED-010, .054, .055). A picked spec comes back as written: one field per entry, named parameters included in entry order, un-named entries as memory rows, expected bytes taken from the spec (R-CHKED-041.1 … .3, .025, .026, .027), and a moved/renamed/resized parameter demoted to a memory row keeping its spec entry (R-CHKED-056). The Check Editor's validation results clear after every in-place write (R-CHKED-057).

### Patch Editor document lifecycle (US-PE-LIFE-1 … US-PE-LIFE-4 · Inc 6)

The before/after offer appears only with a project (R-BEFORE-AFTER-REPORT-001.36). With a project, the Patch Editor, Check Editor and A2B Diff lists show `patches/<n>` and `checks/<n>` then the common library as `library/<n>`; every Write lands in the project home with a free-name claim and its status names the home (R-PATCH-DOC-DROPDOWN-001.*, R-CHKED-040, R-DIFF-CHK.*). The Checks tab shows the run the operator has now and resets after loads and in-place writes (R-CHKED-031, .034, .044). A replaced document starts clean — the before/after control and the save-back prompt hide when a document or image is replaced, not on Save project (R-TUI-049.3.1/.3.2, R-CHKS-009).

### Reports: whole, inert, atomic (US-BAR-1, US-HEXWIN-1, US-MDESC-1 · Inc 7)

The before/after report names itself (`# Before/after report`) and its inputs (the loaded A2L and MAC) (R-BEFORE-AFTER-REPORT-001.11, .24, .32 … .35). Every written report carries every hex window whole, uncapped (R-CMP-004.14, F6-1). Names and paths stay plain text in the Markdown report — a backslash before each Markdown character, a control/direction-override character as a visible replacement, and provenance lines byte-identical (R-CMP-004.9.1/.9.2, .15). Writes are atomic: a random staging name, then a rename, so an interrupted write leaves at most a safe-to-delete `.part` file.

### Flow CRC block, external steps, CRC model (US-I8-1 … US-I8-4 · Inc 8)

A Designer template given to a Flow CRC block is named as such, and a CRC config error names its field (R-FLOW-CRC.1/.3/.4, R-CRC-CONFIG-001.10 … .12, .16, .17). One CRC for one set of parameters, with the CRC model supporting `reverse` (R-CRC-ENGINE-002.2). A later block reads this run's copy of an external step's output; a confirmed external step whose relative log or output path climbs above the project folder stops the flow, and a relative output path reads under the project folder (R-FLOW-EXT.9 … .14).

### Flow and chain-set saves (US-I9-1 … US-I9-3 · Inc 9)

A confirm re-run's report says what ran — `Mode: confirm re-run` with the right chain list, never `sequential` (R-FLOW-CHAIN.19, .20). A saved flow keeps its own file stem as its name, cut to 64 characters; a chain-set keeps its own name (R-FLOW-FILE.12 … .14, R-FLOW-SET.9, .10). Flow and chain-set saves stay in the work area: the home guard refuses a linked home, an exclusive create with a post-claim check (regular file, one link, same file as the descriptor, real parent equals the approved home) and a cleanup that unlinks only its own claim (R-FLOW-FILE.11, R-FLOW-SET.7, .8, R-FB-SAVE.8, R-FX-SET.15).

### Hex navigation, unload, focus, in-place views (US-HEXNAV-1, US-UNLOAD-1, US-FOCUS-2, US-FRESH-3 · Inc 10a/10b)

A jump shows its target as the view's second row in the main, A2L and MAC views, and an image load resets the window; the go-to marker clears on paging, a new search, a jump or a load (R-TUI-018, R-TUI-040, R-SEG-OPEN.6/.7). An unload clears the stale load facts and question, and the status line describes what is loaded (R-WS-LOADED.13/.14/.16/.18 … .20). The focus never lands in a hidden window — landing per window, switch targets that keep the paging keys, and a re-homed focus after a load (R-SHELL-FOCUS.2 … .5, R-TUI-007.9). After an in-place write, the main/A2L/MAC hex panes, the A2L value column and the Split/Join window show the new bytes without moving the filter, page or cursor; the A2L refresh recomputes only the tags whose bytes changed (R-A2L-048/049/105/106, R-TUI-004.7 … .9, R-SEG-PREV.21/.22, R-SEG-EXP.15).

### A2L parsing and the Issues screen (US-I11-1 … US-I11-4 · Inc 11)

A valid A2L raises no "unrecognized block": the 62 ASAM block names are recognised and an IF_DATA block is skipped (R-VAL-032.1 … .3, R-A2L-036, R-A2L-034, R-A2L-121). The Issues screen shows each issue under its own severity, errors first, with the list running errors, warnings, info across pages (R-TUI-025.2/.6, R-TUI-042b.1/.5). A CURVE without axis points says so once (R-VAL-032.4). Every MEMORY_SEGMENT that states a base and a size is read (R-SEG-SRC.6).

### Dead surfaces removed, Escape closes Reports (US-I12-1 … US-I12-3, US-I12b-1 · Inc 12/12b)

Every dialog opens and every action runs from somewhere — `VariantHelpScreen`, the three view aliases, the dead issue-jump trio and `action_a2l_tag_find_next` are removed, and censuses guard that every dialog has an opener and every action a reach (R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058). Every widget of the Check Editor, Flow Builder and Flow Execution is shown in some state; the hidden Flow widgets (the hidden help sentences, grid canvas, numbered list, session line and kind dropdown) are removed with their painter family, and the block kind is panel state written only with a kind-options value (R-TUI-059.25, R-FX-SCR.4, R-FB-ADD.1). Escape closes the Reports viewer as Close does, while an open dropdown keeps its own Escape (R-DLG.2, R-DLG.15).

### Responsive at 10 MB (US-CRC-RESP-1, US-CRC-FRESH-1, US-SEG-RESP-1 · Inc 13)

The CRC Designer stays usable with the 10 MB demo image: a debounced shared recompute with a 150 ms quiet time, a 16 MiB coverage cap, a reflect table and an O(m log m) sweep, recomputing once per load and on display while stale (R-CRC-PREVIEW-001, R-CRC-DESIGNER-001.1/.2.1/.2.2/.007, R-CRC-PREVIEW-002.1 … .5). The Split/Join preview stays usable, with its state line conflict-first (R-SEG-PREV.2/.7/.20).

### Help, legend, README, security, release notes, user guide (US-HELP-1, US-LEGEND-1, US-README-1, US-SEC-1, US-REL-1, US-GUIDE-1 · Inc 14)

Each help window describes what its window does (R-WHELP.7 … .26). The Memory Map legend names the keys the map handles (R-TUI-062.10.1, R-LEGEND-011). The README describes the shipped app (R-DOC-README.2 … .4). SECURITY.md gives a private path to report a vulnerability and states which versions receive fixes (R-DOC-SECURITY.1, .2). The 1.0.0 release notes state what changed in written results (R-DOC-RELNOTE.1 … .14). The user guide describes no behaviour the system does not provide, and marks each row of its findings table that 1.0.0 fixes with `fixed in 1.0.0` (R-DOC-GUIDE.1, .2).

### Documentation hygiene (US-DOC-HYG-1 … US-DOC-HYG-3 · Inc 16)

A contributor finds only paths, links and commands that exist — repository documents name only existing paths, link only to existing files/folders, and present `s19tool` and CDFX only in their allowed shapes (R-DOC-REF.1 … .6). The developer documents describe the shipped app (R-DOC-DEV.1 … .11). Finished notes leave the living documents with their history kept — four finished handoff/notes documents are archived, `REQ-crc.md` and the stray example files are removed, the retired `.fast-dev-flow/` is removed with its citations, and the drive path is redacted (R-DOC-ARCH.*, R-DOC-ARCHIVE.*).

### Windows-only test fixes (US-TST-15, US-TST-16 · R-TST-150 … .164 · Inc 15)

The TC-331, TC-B94-27, AT-030c and TC-051 save-back arms that checked state after fixed pauses now wait through the shared `settled` helper on product observables, so a Windows serial run reports the product, not the host's clock (R-TST-150 … .164; tests only, 0 product files).

## Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `REQUIREMENTS.md` | the strict-EARS canon (Inc 1 swaps it; every later increment writes its rows here) |
| `tests/test_requirements_canon.py` | the canon-form guards (Inc 1) |
| `tests/support/timing.py`, `tests/support/suite_census.py`, `tests/b97_probes.py` | QC-TM margin reporter, QC-OR oracle, QC-BC census, shared waits (Inc 2) |
| `.github/workflows/tui-ci.yml` | the two CI lanes and history arms (Inc 2) |
| `s19_app/tui/app.py` | the serial chain owner — symbol reads, unload, focus, hex navigation, in-place refresh seams, Reports Escape (Inc 3, 4, 5, 6, 9, 10a, 10b, 12) |
| `s19_app/tui/workspace.py`, `s19_app/tui/services/project_gather_service.py` | gather once per name, no folder re-creation (Inc 3); flow-save containment (Inc 9) |
| `s19_app/tui/services/change_service.py` | symbol resolution, document lifecycle (Inc 4, 6) |
| `s19_app/tui/screens_directionb.py` | Check Editor, Patch Editor panels (Inc 5, 6, 12) |
| `s19_app/tui/crc_designer_view.py`, `s19_app/tui/segment_split_view.py` | CRC Designer and Split/Join recompute and responsiveness (Inc 5, 13) |
| `s19_app/render/…` + `diff_report_service.py`, `before_after_service.py` | whole/inert/atomic reports (Inc 7) |
| `s19_app/tui/flow_*`, `s19_app/tui/services/flow_*` | Flow CRC block, external steps, saves (Inc 8, 9, 12b) |
| `s19_app/tui/a2l.py`, `s19_app/tui/services/rules.py`, `s19_app/tui/issues_view.py` | A2L parsing and severity order (Inc 11) |
| `s19_app/tui/window_help.py`, `s19_app/tui/legend.py`, `README.md`, `SECURITY.md`, `docs/**`, `CLAUDE.md`, `PROJECT_RULES.md` | help, legend, README, security, release notes, user guide, doc hygiene (Inc 14, 16) |

Source budget: every increment stayed at or under 4 SOURCE files under `s19_app/`; Inc 8 and Inc 11 each touched 4 (the cap). The `app.py` chain is serial (3 → 4 → 5 → 6 → 9 → 10 → 12), one writer at a time.

### Usage / examples

```bash
# the batch's own verification surfaces (each increment's 04-validation.md commands)
pytest tests/test_requirements_canon.py        # Inc 1 (canon form)
pytest tests/test_b101_symbol_reads.py         # Inc 4 (symbol resolution)
pytest tests/test_b101_designer_writes.py      # Inc 5 / 13 (CRC Designer refresh + 10 MB)
pytest tests/test_b101_check_spec_keep.py      # Inc 5 (Check Editor picks / spec bytes)
pytest tests/test_b101_patch_lifecycle.py      # Inc 6 (Patch Editor lifecycle)
pytest tests/test_diff_report_service.py       # Inc 7 (reports)
pytest tests/test_b101_flow_ext_copy.py        # Inc 8 (Flow CRC block / external steps)
pytest tests/test_b101_flow_saves.py           # Inc 9 (flow saves)
pytest tests/test_tui_goto_marker.py           # Inc 10a (hex navigation)
pytest tests/test_b101_inplace_views.py        # Inc 10b (views after in-place writes)
pytest tests/test_b101_a2l_blocks.py           # Inc 11 (A2L parsing)
pytest tests/test_b101_reach_and_reports_escape.py  # Inc 12 (dead surfaces, Reports Escape)
pytest tests/test_b101_shown_widgets.py        # Inc 12 / 12b (widget reach)
pytest tests/test_b101_help_legend_docs.py     # Inc 14 (help / legend / README / docs)
pytest tests/test_b101_doc_hygiene.py          # Inc 16 (documentation hygiene)
pytest -m serial_timing                        # the timing lane, run apart and serially
```

These are the commands the increment records cite. This document did not re-run them. Run them from the repository root in the project environment; the pilot tests read painted text (no `NO_COLOR`).

### Risks / limitations (from the record)

- **No evaluation with real users.** The automated pilots prove the text is painted, not that an engineer reads it correctly (one operator; ISO 9241-210 carried forward from batch-100). The 37 UI rows are known failed checks (KF-101-*) by operator ruling.
- **Three residual visible gaps, accepted for 1.0.0:** BL-I10b-1 (Hex Peek panes keep pre-write bytes until re-selection), BL-I12-5 (seven dialogs still ignore Escape; R-DLG.2 `Partly`), BL-I12-6 (a Generate in flight under Escape / a double click raises `ScreenStackError`).
- **The SECURITY.md hold-out is still out.** The private vulnerability-reporting channel was closed at the time of the batch; the SECURITY.md group stays held out of the merge for the operator (Inc 14's conditional-gate discharge, still outstanding).
- **The canon fold is a hand-over, not done.** `devflow-init --fold-canon` folded 0 and refused the 2 template rows; the requirements session folds `close/FORWARD-requirements-session.md` (273 rows).
- **34 open backlog rows** are carried in `.dev-flow/BACKLOG-CODE.md`, grouped by source increment (Inc 8, 9, 10a, 10b, 12, 12b, 14).
- **The `app.py` serial chain** (≈ 20,500 lines, 7 increments) is a known structural risk; the ADR is owed before batch-102.

### Diagrams

- `06-docs/diagrams/merge-order.md`: the increment dependency graph and the merge order (1 ∥ 2; 3 ∥ 7 ∥ 8 ∥ 11 ∥ 13 ∥ 14; the serial `app.py` chain 3 → 4 → 5 → 6 → 9 → 10a → 10b → 12, with 12b ∥ 10a and 15 ∥ 16; the batch-end battery).
- `06-docs/diagrams/trace-overview.md`: the requirement-to-test trace (US → `R-…` row → test case → test node → evidence) and the two validation layers.
- `06-docs/diagrams/gate-battery.md`: the batch-end gate battery and the CI comparison that closed the batch.

### Record discrepancies

> Where a packet and the contract disagree, this document follows the contract (the canon rows). The disagreements found while writing it:

1. **Increment numbering.** The plan numbers 16 increments; the 10 and 12 each split into a/b, so the packets are `increment-001 … 016` plus `increment-010b` and `increment-012b` (18 packets). The same packets, the same content — only the split differs.
2. **The batch-level canon is a template.** The batch-level `01-requirements.md` carries `HLR-001` / `LLR-001.1` plus the user-story index; the per-increment `inc-<n>/01-requirements.md` files carry the `R-…` rows. The fold is the requirements session's act.
3. **Case counts moved at E5.** Several increments re-audited their case counts at E5 (e.g. Inc 8: 82 → 99; Inc 14: 69 → 74); this document cites the post-E5 figures, named in each `02-test-cases.md`.

### Evidence checklist — docs-writer
> Attach `docs-writer`'s completed evidence checklist (items in `agents/docs-writer.md`), ✓/✗ + one-line evidence.

- [x] Audience and purpose declared at the top of the doc. — ✓ header: technical stakeholder; understand the changes and what users will notice.
- [x] Structure follows the relevant template (or a justified deviation is noted). — ✓ the batch-100 `06-docs/functionality.md` shape, adapted to the canon-hosted `R-…` rows (deviation named in the header).
- [x] Code/CLI snippets actually run (or marked "untested"). — ✓ the commands are the increment records' own; marked above as not re-run by this document.
- [x] Assumptions listed. — ✓ behaviour is stated per the canon rows and the increment records; increment attribution from each `inc-<n>/01-requirements.md` and the packet headers.
- [x] Risks / limitations called out. — ✓ "Risks / limitations (from the record)".
- [x] Next steps stated. — ✓ `executive-summary.md` (presentation-builder) and `05-close.md` §Next.
- [x] Diagrams included where flow is non-trivial. — ✓ three Mermaid diagrams under `06-docs/diagrams/`.
- [x] No invented APIs / version numbers / metrics. — ✓ ids were read from `REQUIREMENTS.md` / `close/FORWARD-requirements-session.md` / the increment records; counts came from the per-increment `Count` lines; no number was estimated.

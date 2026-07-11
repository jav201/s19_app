# 01b — QA Strategy & Verification Plan · batch-35 (B-07)

> Phase 1 QA artifact. Binds to PLAN.md stories US-053..US-057 and design defaults D-1..D-5.
> Written in parallel with `01-requirements.md` (not read; architect to reconcile at the Phase-1 gate).
> Author: qa-reviewer. Status: strategy locked for Phase-2 review; TC/AT bodies are Phase-3 work.

---

## 0. Scope recap (one sentence each)

1. **Filter file** — operator JSON (`s19app-report-filter` v1.0) whitelisting symbols (fnmatchcase
   globs) and address ranges (end-exclusive) that restricts the before/after report (`b` key) and
   the project report; no filter = byte-identical output; invalid filter = refusal with named
   errors and zero files written; zero-match = loud "matched 0 of N" report; audit header names
   the filter and the hidden count.
2. **Patch-editor regroup** — patch-script vs check controls split into two labeled sections,
   all widget ids and the AT-032a help token span preserved.

---

## 1. Validation method per story

Layer A = white-box TCs on the mechanism (pure functions, service calls with `tmp_path`).
Layer B = black-box ATs through the SHIPPED surface: Textual Pilot (`App.run_test()`) driving the
REAL handler — `press("b")` for the before/after report (idiom: `tests/test_before_after_report.py:178`,
AT-038a), the real report dialog + generate control for the project report (idiom:
`tests/test_tui_report_seam.py:180`) — then **re-reading the file the handler wrote under
`<project>/reports/` and asserting content** (C-12 output-then-consume; never write the artifact
directly and assert on it).

| Story | Requirement area | Method | Layer A TC families | Layer B ATs (surface) |
|---|---|---|---|---|
| US-053 | Filter file parse + rejection diagnostics | **test** | TC-F1 parse happy/reject matrix (crc_config idiom: `(obj\|None, errors)`, never raises, one error per fault); TC-F2 match-engine unit matrix (globs, ranges, D-1 a/b/c) | AT-053a invalid filter → before/after `b` REFUSED, named error on status, `reports/` unchanged; AT-053b same refusal through the project-report generate control; AT-053c fnmatchcase discriminator (`cal_*` does NOT match `CAL_SPEED`) observed in the written report |
| US-054 | Filtered before/after report | **test** | TC-B1 composer-level filtering (rows/windows/checklist selection, D-5 filter-before-merge); TC-B2 audit-header composition + hidden-count math | AT-054a match/omit + audit header via `b` → reread md+html pair; AT-054b no-filter byte-identical golden (double-proof, §2.3); AT-054c zero-match → loud "matched 0 of N" report still written; AT-054d hostile symbol pattern escaped in md AND html |
| US-055 | Filtered project report | **test** | TC-P1 `generate_project_report` filtering of Modifications/Checklists/Memory-regions sections; TC-P2 audit header without markup/MD injection (report_service escapes — see §3.4) | AT-055a match/omit + header via the real dialog/worker → reread from `reports/`; AT-055b no-filter byte-identical golden (double-proof) |
| US-056 | Filter selection UX | **test** | TC-S1 `filters/*.json` scan (sorted, symlink-skip — `_scan_patch_change_files` idiom); TC-S2 free-path resolution via `resolve_input_path` | AT-056a NON-DEFAULT dropdown selection → generated output ≠ unfiltered output (C-10, §2.1); AT-056b hostile filename `[red]x.json` renders literally on status (C-17); AT-056c scope guard: with a filter selected, the A/B diff report output is byte-identical to unfiltered (diff stays always-complete) |
| US-057 | Patch-editor regroup | **test** + **inspection** | TC-R1 CSS/geometry budget assertions (C-13, patch_layout idiom) | AT-057a pilot queries BOTH section labels, asserts every id from §3.5 survives with correct parentage, presses `#patch_checks_run_button` and observes the same check-run outcome (press-through); AT-032a token-span regression rerun |
| cross | `filters/` subdir neutrality in workspace | **test** | TC-W1 `validate_project_files` ignores `filters/` (extends `tests/test_workspace_variants.py:92` reports/ pattern) | — (covered by TC; no user-visible surface of its own) |
| cross | Snapshot drift from regroup | **inspection** | — | xfail-until-canonical-regen plan §3.5.3 |

**Analysis-only items:** none. Every requirement area above lands as executable test or pinned
snapshot. Demo: Phase-4 operator demo replays AT-054a and AT-057a manually (script from the ATs).

---

## 2. C-10 checks at AT-authoring time (shift-left — owned here)

C-10 = a passing AT must be IMPOSSIBLE against a tree where the behavior is absent or defaulted.

### 2.1 Non-default selection discipline
- **AT-056a** must: create ≥2 filter files in `filters/`, select a NON-FIRST, non-default option in
  the dropdown, generate, and assert the written report **differs byte-wise from a same-session
  unfiltered run** AND contains the selected filter's name in the audit header. "Report exists and
  is non-empty" is banned as the pass condition — that passes today.
- **AT-054a/AT-055a** must use a fixture where the filter provably PARTITIONS the data: ≥1 entry
  that matches and ≥1 that does not, asserting BOTH presence of the matched row/window AND absence
  of the omitted one (match/omit pair, not match-only).

### 2.2 One AT per policy branch (each a distinct on-disk node, §4)
| Policy branch | AT | Discriminating assertion |
|---|---|---|
| filter selected vs none | AT-056a | selected output ≠ unfiltered output (byte diff) |
| none = default | AT-054b / AT-055b | byte-identical to pre-batch golden |
| valid vs invalid | AT-053a / AT-053b | refusal + named error + **0 files written** (`_report_names(...) == set()`, AT-038b idiom) |
| match vs zero-match | AT-054c | report IS written and contains the literal "matched 0 of N" notice with correct N |
| case-sensitive vs insensitive | AT-053c | `cal_*` filter omits `CAL_SPEED` (fails under fnmatch, passes only under fnmatchcase) |
| filtered surfaces vs exempt surface | AT-056c | A/B diff output unchanged under an active filter |

### 2.3 Golden double-proof (batch-24 control) for the byte-identical ATs
AT-054b / AT-055b compare post-implementation no-filter output against a golden that is
**independently re-derived at the base ref**, not captured from the implementation branch:
1. At RC-1 base (origin/main after PR #63 merge), run the same fixture through `b` /
   `generate_project_report` and record SHA-256 of the normalized report bodies
   (timestamp/identity lines normalized exactly as `test_report_omits_entropy_when_disabled_byte_identical`
   at `tests/test_report_service.py:1046` does — reuse its normalizer, do not fork one).
2. Pin those hashes in the AT with a comment naming the base SHA they were derived from.
3. Phase-4 re-derivation: an independent rerun at the base ref must reproduce the pinned hash
   before the AT counts as proven (two derivations, one from each side of the change).
Failure mode this kills: the implementation silently changing unfiltered output and the golden
being (re)captured from the already-changed tree.

### 2.4 RED-first classes (see §4 for the per-AT table)
- **Live-RED**: AT-053a/b/c, AT-054a/c/d, AT-055a, AT-056a/b, AT-057a — the control, branch, or
  section does not exist on today's tree; each must be run once pre-implementation and its failure
  message recorded in the ledger.
- **Guard-golden (not RED-provable)**: AT-054b, AT-055b, AT-056c pass trivially today; their proof
  is the §2.3 double-derivation, not a stash-RED. State this explicitly in each docstring so
  nobody fakes a RED for them.

---

## 3. Boundary and negative sets (concrete cases — cut only with written justification)

### 3.1 Glob semantics (fnmatchcase over A2L/MAC symbol names)
| # | Case | Expected | Home |
|---|---|---|---|
| G1 | exact name `CAL_SPEED` | matches only that symbol | TC-F2 |
| G2 | prefix `CAL_*` | matches `CAL_SPEED`, `CAL_X`; NOT `XCAL_SPEED` | TC-F2 |
| G3 | `*` alone | matches ALL symbols — **allowed, ceiling case**: output must equal the full symbol-matched set, audit header still present ("hid 0" or address-only omissions); NOT silently equal to no-filter (header differs) | TC-F2 + assertion inside AT-054a fixture variant |
| G4 | pattern matching nothing (`ZZZ_*`) | 0 symbol matches; combined with no address match → zero-match branch (AT-054c) | TC-F2 / AT-054c |
| G5 | case pin: `cal_*` vs `CAL_SPEED` | NO match (fnmatchcase) | TC-F2 + AT-053c |
| G6 | glob metacharacters IN the symbol name: A2L name `PAR[0]` or `MAP?_X` | **Hazard**: fnmatch treats `[`/`]`/`?` in the *pattern* as syntax; a literal filter entry `PAR[0]` is the pattern `PAR` + char-class `[0]` → matches `PAR0`, not `PAR[0]`. Pin the chosen semantics: exact-name entries are still fnmatch patterns (document it in the format spec + audit header docs) OR pre-escape via `glob.escape`-equivalent. Whichever D-decision lands, TC-F2 pins it with the `PAR[0]` fixture and a test asserting the documented outcome — do not leave it emergent | TC-F2 (named case) |
| G7 | unbalanced bracket pattern `CAL_[` | fnmatchcase treats as literal (Python behavior) — pin, don't assume | TC-F2 |
| G8 | duplicate patterns `["CAL_*","CAL_*"]` | accepted, no double-counting in hidden/matched counts | TC-F1 + TC-B2 |
| G9 | empty-string pattern `""` | named parse error (or pinned inert) — reject preferred; pin either way | TC-F1 |

### 3.2 Address ranges (start/end, end EXCLUSIVE)
| # | Case | Expected | Home |
|---|---|---|---|
| A1 | off-by-one pair: range `[0x1000, 0x1004)` vs entry at `0x1004` | NO match; entry at `0x1003` → match (paired assertions in one TC) | TC-F2 |
| A2 | range end == entry start (exclusivity at the seam) | NO match — the discriminating half of A1 | TC-F2 |
| A3 | `start == end` (empty range) | **pin it**: reject with named error (preferred — an inert range is operator confusion) or documented-inert; TC asserts the chosen branch | TC-F1 |
| A4 | `start > end` | named parse error, generation refused | TC-F1 + covered by AT-053a fixture |
| A5 | hex `"0x80040000"` and int `2147745792` forms | both accepted, equivalent match result | TC-F1/F2 |
| A6 | 32-bit ceiling: end `0x100000000` (exclusive top) legal; `0x100000001` or start ≥ 2^32 | pin: ceiling accepted, beyond → named error | TC-F1 |
| A7 | overlapping ranges `[0x1000,0x2000)` + `[0x1800,0x2800)` | union semantics; matched/hidden counts count each item once | TC-F2 + TC-B2 |
| A8 | negative start `-1` | named error | TC-F1 |
| A9 | D-5 interaction: two matched entries whose merged window (batch-34 `merge_gap_bytes`) would span an EXCLUDED entry between them | filtering selects entries BEFORE window merge → merged window computed over the filtered pair only; the excluded entry's own window absent; pin whether gap-context bytes still render (they are context, not entries — expected: yes, context rows may cover the gap, but no linkage/modification row for the excluded entry) | TC-B1 (named case) + visible in AT-054a fixture |
| A10 | range exactly covering one merged-window boundary row | window included iff intersection with matched address set is non-empty; boundary row membership pinned | TC-B1 |

### 3.3 Parse rejections (crc_config style: collect ALL faults, one named error each, never raise)
| # | Case | Expected |
|---|---|---|
| P1 | unknown top-level key (`"exclude": ...`) | named error citing the key |
| P2 | `format` ≠ `s19app-report-filter` / missing | named error |
| P3 | `version` ≠ `"1.0"` / missing / int not string (pin type) | named error |
| P4 | `include.symbols` not a list (string, dict) | named error |
| P5 | non-string element in symbols (`[42]`) | named error naming index |
| P6 | `include` present but empty `{}` / both lists empty | **pin**: reject ("filter includes nothing") preferred over matches-nothing — an operator who wrote an empty include almost certainly erred; if inert-allowed instead, it must route to the AT-054c zero-match loud path, never a silent full report |
| P7 | `include` missing entirely | named error (envelope incomplete) |
| P8 | oversized file (> size cap; reuse `READ_SIZE_CAP_BYTES` pre-read idiom) | named error, file never fully read |
| P9 | pattern-count / range-count ceilings (pin caps, e.g. mirrors crc/changeset caps) | named error above cap; at-cap accepted (boundary pair) |
| P10 | address entry not an object / missing `start` or `end` / extra key inside | named error each |
| P11 | not-JSON / empty file / BOM / non-UTF-8 bytes | named error, no exception escapes |
| P12 | duplicate `start/end` pair entries | accepted (union) or named warning — pin |
| P13 | multi-fault file (P1+P4+A4 together) | ALL errors collected and surfaced, not first-only |

All P-cases: TC-F1 in `tests/test_report_filter.py`; AT-053a/b use a representative multi-fault
file and assert the refusal surfaces at least one NAMED error (not a generic "invalid filter").

### 3.4 Hostile inputs (C-17 — confirmed real: `set_status` → `Label.update` interprets markup, app.py:8880/8896, no call site escapes today)
| # | Case | Required behavior | Home |
|---|---|---|---|
| H1 | filter FILENAME `[red]x[/red].json` in `filters/` | selected + surfaced on status line ("filter: …") rendered LITERALLY — every new `set_status` call site added by this batch escapes (`rich.markup.escape` or `markup=False` surface); assert the literal bracket text appears in the rendered label (AT-038-style status capture) | AT-056b |
| H2 | same filename echoed into the md/html audit header | passes through `_md_cell`/`_esc` discipline of diff_report_service (backslash-first, batch-34) — html shows `&#91;red&#93;`-class escaping, md cell shows escaped pipes/backslashes | AT-056b (extend assertions to the written pair) |
| H3 | symbol PATTERN containing `\|`, backticks, `<b>`, `[bold]` echoed into the audit header / "matched 0 of N" notice | before/after report: `_md_cell` + `_esc` (existing discipline). **Project report: `report_service` does NOT escape today** — strategy: the audit-header writer in report_service must either (a) route its interpolations through the same `_esc`/`_md_cell` helpers (import or lift them), or (b) emit filter names/patterns only inside fenced code spans with backtick-doubling. TC-P2 pins whichever the architect picks; AT-054d observes the before/after side black-box | TC-P2 + AT-054d |
| H4 | hostile pattern that ALSO matches a symbol (`*` + markup suffix trick, e.g. `[bold]*` matching literal-bracket names) | no crash, counts correct, rendering literal | TC-F2 |
| H5 | filter free-path input pointing outside the project (traversal `..\..\x.json`) | resolved via `resolve_input_path`; pin containment behavior — reading an out-of-project filter is allowed (it's an input, like change-sets) or refused; either way no write outside `reports/` ever occurs | TC-S2 |

### 3.5 Regroup (US-057) — survival set, press-through, snapshot plan

**3.5.1 Widget-id survival list** (from `s19_app/tui/screens_directionb.py:1848-1898`, plus the
entry-pane ids the census file pins). Every id below must exist post-regroup; AT-057a queries each:
`patch_doc_file_select`, `patch_doc_path_input`, `patch_doc_load_button`,
`patch_doc_validate_button`, `patch_doc_apply_button`, `patch_doc_save_button`,
`patch_checks_run_button`, `patch_doc_controls`, `patch_checks_help`, `patch_doc_file_row`,
`patch_paste_text`, `patch_paste_parse_button`, `patch_paste_controls`, `patch_paste_row`,
`patch_pane_changefile` (id census baseline: `tests/test_tui_patch_editor_v2.py:67` region).
AT-057a additionally asserts the NEW section labels exist and that `patch_checks_run_button` and
`patch_checks_help` share the checks-section container while the four script buttons share the
patch-script container (parentage, not just existence).

**3.5.2 Behavior press-through.** AT-057a (or a sibling TC if it bloats) presses
`#patch_checks_run_button` through Pilot after loading a check document and asserts the same
check-run outcome as the existing checks ATs — the regroup must be layout-only. The AT-032a token
span in `#patch_checks_help` is re-asserted verbatim (existing pins at
`tests/test_tui_patch_editor_v2.py:1803-1850` and `:2161-2186` stay green — survival, §5).

**3.5.3 Snapshot drift + xfail plan.** The patch scaffold carries TWO cells (80x24 floor +
120x30), `tests/test_tui_snapshot.py:504` (`_TWO_SIZE_SCAFFOLDS = ("patch", "map")`). The regroup
moves the right-pane layout → BOTH patch cells drift. Plan: mark exactly those two cells
`xfail(strict=False)` with a batch-35 comment (batch-22/25/33 precedent documented in the same
file at `:456-503`), regen ONLY in canonical CI post-merge per `reference_snapshot_regen_env`.
Map/diff and non-patch cells must stay green — any additional drift is a scope violation, not a
regen candidate.

**3.5.4 Layout pin collision.** `tests/test_tui_patch_layout.py:290-325` pins `#patch_doc_controls`
as a grid-size-3 grid — after Run-checks moves out it holds 4 buttons; the pin on grid-ness likely
survives but the test's intent comment ("5 buttons don't clip") is stale → EXTEND/SUPERSEDE per
§5, with a new geometry assertion covering both sections at 80-col floor (C-13 budget).

---

## 4. C-18 realization plan — every AT → exactly ONE on-disk node

New Layer-A file: **`tests/test_report_filter.py`** (mirrors `tests/test_crc_config.py`) — TC-F1,
TC-F2, TC-S1, TC-S2. New Layer-B surface file only if AT-056* don't fit an existing home:
**`tests/test_tui_report_filter_surface.py`** (mirrors `tests/test_tui_crc_surface.py`).

| AT | One on-disk node (target file) | RED class | RED evidence to record |
|---|---|---|---|
| AT-053a | `tests/test_before_after_report.py` | live-RED | no filter selector exists → selection step fails / refusal never surfaces |
| AT-053b | `tests/test_tui_report_seam.py` | live-RED | same, project-report dialog has no filter control |
| AT-053c | `tests/test_before_after_report.py` | live-RED | filtering absent → `CAL_SPEED` row present under `cal_*` filter attempt |
| AT-054a | `tests/test_before_after_report.py` | live-RED | omitted row still present; no audit header |
| AT-054b | `tests/test_before_after_report.py` | guard-golden | §2.3 double-proof (base-ref hash pinned pre-impl) |
| AT-054c | `tests/test_before_after_report.py` | live-RED | no "matched 0 of N" notice exists |
| AT-054d | `tests/test_diff_report_service.py` (renders via generators) or `test_before_after_report.py` — pick ONE at Phase-3, record choice | live-RED | hostile pattern not escaped / header absent |
| AT-055a | `tests/test_tui_report_seam.py` | live-RED | project report shows all sections unfiltered |
| AT-055b | `tests/test_report_service.py` (beside `:1046` byte-identical idiom) | guard-golden | §2.3 double-proof |
| AT-056a | `tests/test_tui_report_filter_surface.py` | live-RED | dropdown id absent → query fails |
| AT-056b | `tests/test_tui_report_filter_surface.py` | live-RED | status line absent / markup interpreted |
| AT-056c | `tests/test_tui_report_filter_surface.py` | guard-golden | A/B diff already unfiltered today; proof = golden + code-inspection that diff path receives no filter |
| AT-057a | `tests/test_tui_patch_editor_v2.py` | live-RED | section labels absent |

Rules: no AT body duplicated across files; TC families live in the file named in §1; if Phase-3
splits an AT, the split gets a suffixed id (AT-054a1) and its own single node. The Phase-3 ledger
records, per live-RED AT, the pre-implementation failure output (inline paste at the gate).

---

## 5. Supersession census (change-first) — pins this batch plausibly moves

| # | Pin (file:line) | What it pins | Disposition |
|---|---|---|---|
| 1 | `tests/test_tui_patch_layout.py:290-325` (+ intent at `:13,:19,:185`) | `#patch_doc_controls` is grid-size-3 and the 5-button grid doesn't clip | **SUPERSEDE/EXTEND** — Run checks leaves the grid; re-pin as 4-button script grid + new checks-section geometry at 80-col floor; record supersession note in the test docstring |
| 2 | `tests/test_tui_patch_layout.py:38` | `patch_pane_changefile` in the pane census | **SURVIVES** (pane id preserved per US-057 AC) |
| 3 | `tests/test_tui_patch_editor_v2.py:67` | widget-id census incl. `patch_checks_run_button` | **SURVIVES** — explicit regression rerun; extend census with new section-label ids |
| 4 | `tests/test_tui_patch_editor_v2.py:1803-1850, 2161-2186` | AT-032a `#patch_checks_help` token span + Run-checks wiring | **SURVIVES** (locked pin; regroup is layout-only) |
| 5 | `tests/test_tui_snapshot.py:504` two patch cells (80x24 + 120x30) | patch scaffold pixels | **DRIFT → xfail(strict=False)** until canonical-CI regen (§3.5.3) |
| 6 | `tests/test_report_service.py:187` `test_full_report_content` | full project-report content, unfiltered | **SURVIVES** (no-filter byte-identical contract) and is drafted as the AT-055b golden anchor — if it goes red, the batch broke its own headline invariant |
| 7 | `tests/test_report_service.py:1046` byte-identical-when-disabled | normalizer + byte-identical idiom | **SURVIVES**; reuse its normalizer for §2.3 |
| 8 | `tests/test_before_after_report.py:178-448` AT-038a-d | `b`-key trigger → reread pair; refusal → 0 files | **SURVIVES**; AT-053a/054* copy its status-capture + `_report_names` helpers rather than fork |
| 9 | `tests/test_before_after_report.py:451+` TC-038-3 composer happy path | `compose_before_after_report` signature/behavior | **EXTEND** — D-1(c) adds `a2l_records`/`mac_records` (and a filter arg) to the composer; keyword-with-default keeps existing calls green; TC asserts default-path equivalence |
| 10 | `tests/test_tui_report_seam.py:394` dialog fits 80/120 cols | report-dialog geometry | **EXTEND** if the filter dropdown+path row lands in that dialog (open Phase-1 siting item) — C-13 geometry budget re-run at both widths |
| 11 | `tests/test_tui_report_seam.py:562` save-without-regions byte-identical | manifest byte neutrality | **SURVIVES** (filter selection is per-run, never persisted) |
| 12 | `tests/test_diff_report_service.py` (all; e.g. `:184,:479,:504`) | A/B diff generator content + write/refusal discipline | **SURVIVES** untouched — diff stays complete; AT-056c adds the guard |
| 13 | `tests/test_workspace_variants.py:92` reports/ storage neutrality | subdir neutrality pattern | **EXTEND** with the `filters/` twin (TC-W1) |
| 14 | C-14 e2e observers (rglob over workarea): `tests/test_before_after_report.py:665`, `tests/test_tui_patch_editor_v2.py:398,578,609,928,986,1280-1448`, `tests/test_tui_crc_surface.py:585`, `tests/test_change_service.py:150` | "nothing unexpected written" sweeps | **SURVIVE**, but audit at Phase-3: any sweep with a narrow pattern (`*-before-after-report.*`) stays valid; sweeps asserting an EMPTY workarea region must not trip over new `filters/*.json` fixtures — place fixture filters inside the project dir per test, and rerun the full sweep set in the census check |

No other test greps as pinning before/after full content byte-wise; the linkage-cell pins were
already superseded to the AC-5 format in batch-34 (commit 25a04b0) and are compatible.

---

## 6. Test-count ledger base

```
python -m pytest --collect-only -q   →   1270 tests collected in 0.53s
```
(tree: worktree @ 79699a5, branch feat/batch-35-report-filter, 2026-07-10.)
Phase-3 ledger tracks: base 1270 → +N new (each named) → −0 deleted (supersessions are in-place
edits with docstring notes) → final. Any deletion needs a census row above authorizing it.

---

## 7. Exit criteria for the batch's QA gate

- Every AT in §4 exists at its single node; live-RED ones have recorded pre-impl failures.
- §2.3 double-proof completed for AT-054b/AT-055b (base-ref hash independently re-derived).
- Full suite green except exactly the two §3.5.3 xfail patch snapshot cells.
- Census rows 1, 9, 10, 13 dispositions executed and noted in-test.
- No engine-frozen module diffs (guard tests `tests/test_engine_unchanged.py` green).
- C-17 checks H1-H3 green; grep confirms no new unescaped `set_status` interpolation call site.

## 8. Three highest-risk QA gaps (Phase 2 watch-list)

1. **D-1(c) symbol→address expansion.** `CAL_*` pulling in windows via A2L/MAC record addresses
   requires new composer plumbing (`a2l_records`/`mac_records`) that does not exist; the risk is
   (a) intersect-vs-contain ambiguity in "address range intersects the record's address" and
   (b) the plumbing perturbing the no-filter default path and silently breaking the byte-identical
   contract. The §2.3 double-proof is the tripwire; the architect must pin intersect semantics in
   01-requirements before TC-F2 can be written.
2. **report_service escaping gap (H3).** diff_report_service has `_md_cell`/`_esc`; report_service
   escapes NOTHING today. The audit header + zero-match notice inject operator-file-derived text
   into a second renderer with no discipline — if the architect doesn't name the escape mechanism
   for report_service, TC-P2 has no expected value and the C-17 hole ships. Also every new
   `set_status` call site (filter name, counts) must escape — the funnel at app.py:8880 interprets
   markup and nothing escapes there today.
3. **D-5 × batch-34 merged windows (A9).** Filter-before-merge is decided, but the boundary case —
   two matched entries whose merge gap spans an excluded entry — has undefined context-row
   semantics (do gap context rows covering the excluded entry's bytes render?). If left emergent,
   the "whitelist" claim is false in a way no golden catches. Needs an explicit pinned answer and
   the A9 TC before implementation starts.

---

## Evidence checklist (qa-reviewer, Phase 1)

- [x] Acceptance criteria use Given/When/Then — AT seeds in §1/§2 are G/W/T-shaped (Given fixture partition, When real control pressed, Then reread artifact asserts); full G/W/T bodies are Phase-3 per node.
- [x] Test cases have explicit Expected, not vague "works" — every §3 row names the expected branch (`tests/…` homes named).
- [x] Edge cases include empty, boundary, invalid, error — §3.1-3.3 (G9/A3 empty, A1/A2/A6/P9 boundary, P1-P13 invalid, AT-053a error surface).
- [x] Regression checklist exists — §5 census, 14 rows with file:line.
- [x] Exit criteria stated — §7.
- [x] No real PII / secrets — fixtures only (`CAL_*`, `filters/*.json` synthetic).
- [x] Test results section left blank — no execution claimed; only `--collect-only` (1270) was run, output quoted in §6.
- [x] Layer B black-box — every output-producing story has a shipped-surface AT (Pilot `b` / dialog / dropdown → reread `reports/`), with boundary (A1/A9) and negative (AT-053a, AT-054c, AT-056b) evidence; §1 table.
- [x] Bidirectional surface-reachability — inputs (filter file, dropdown, free path, hostile names) AND outputs (md+html pair, project report, status line, refusal) each exercised through the handler, not only service APIs; §1 + §4.
- [x] No unfilled template — no `<...>` placeholders remain; AT/TC ids are assigned, not templated.

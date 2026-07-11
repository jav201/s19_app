# 04 — Validation · batch-35 · Report filter file + patch-editor regroup

> Phase 4 artifact. Author: qa-reviewer. Tree: `feat/batch-35-report-filter` @ `428470a`
> (Inc-0..6 committed). Base: `79699a5` == `origin/main` (PR #63 IS merged — the memory
> flag "operator said Merged / GH showed OPEN" is resolved; the local `main` ref is stale
> at `f79834e` (batch-33) — every diff below was therefore run against BOTH `79699a5`
> and `origin/main`, identical results). Executed 2026-07-11.

## BLUF

**Verdict: PASS — all three §Objective exit axes (Coverage / Certainty / Evidence) are met.**
Layer A: 25/25 LLRs have their named TC/AT nodes ON DISK (file:line verified by grep, not
intent) and green in this phase's own full-suite run. Layer B / C-18: 17/17 §5.2 ATs map to
exactly one distinct on-disk node each, all driven through the shipped surfaces, each with
recorded counterfactual evidence (live REDs, move-aside RED, golden perturbation REDs, or
scratch-counterfactual REDs — two ATs carry an honestly-declared weaker class, see §3).
Full fast suite re-run by this reviewer: **1335 passed, 2 skipped, 21 deselected, 4 xfailed,
1 xpassed — exit 0** — the exact declared Inc-5/Inc-6 state. Snapshot suite alone:
**33 passed, 1 xfailed, 1 xpassed**. Engine-frozen set: **0 diffs** vs base and vs
`origin/main`; guard test green. Both byte-identity goldens re-proven live by an independent
Phase-4 perturbation re-derivation (§7). The deferred 4096-pattern perf item was MEASURED
(no longer assumed): parse 3 ms; ceiling-worst-case resolve ≈1.8 s (§5-item 4). No blocker.
Open items are all Phase-6/post-merge owed work (§9): REQUIREMENTS.md ledger rows, operator
format docs, canonical snapshot regen, ubuntu CI run as the cross-platform proof, S-F7
backlog, batch-29 stash.

One process deviation, recorded: the mandated single blocking foreground full-suite call was
killed by the harness's hard 10-minute tool cap at ~85% (the suite takes ~11.3 min on this
machine); evidence in §6 is from ONE complete detached run whose own captured output was
read — no stitching, no re-run.

---

## 1. Layer A — LLR → on-disk node table (functional, white-box)

Every node below was located by grepping the exact test-function name on disk (Glob/grep,
never signed from increment-report intent). "Green" = this phase's own full-suite run (§6).

| LLR | Named verification | On-disk node(s) (file:line) | Green |
|---|---|---|---|
| LLR-053.1 | TC-307, TC-308 | `tests/test_report_filter.py:57` `TestTc307ValidRoundTrip` (6 tests, incl. hex/int equivalence :74, single-byte :80, 2^32 boundary :85, D-10 empty include :90, file round-trip :101); `:117` `TestTc308RejectionMatrix` (16 tests incl. N-fault ≥N diagnostics :222, `CAL_[` accepted :254) | ✓ |
| LLR-053.2 | TC-309 (+ TC-317 swap) | `tests/test_report_filter.py:265` `TestTc309ReadPathAndCeilings` — cap pre-read :268, at-cap :284, unresolvable :295, dir-as-non-regular :303, symlink-at-read-time :310, non-UTF-8 :327, malformed/empty/non-object JSON :338/:344/:350; swap cases in `tests/test_tui_report_filter_surface.py:1193` (TC-317) | ✓ |
| LLR-053.3 | TC-309 ceilings | `tests/test_report_filter.py:356` symbols 4096/4097 boundary-exact, `:369` addresses ditto | ✓ |
| LLR-053.4 | TC-310 | `tests/test_report_filter.py:396` `TestTc310TruthTable` (8-combo param + fnmatchcase pin :428); `:435` `TestTc310ExtentPins` (F-1 tail byte :438, extent-END negative twin :447, Q-9 byte_size None/0/non-positive :460, MAC-point vs A2L-extent :471); `:490` `TestTc310MetacharacterPins` (F-2 `PAR[0]` equality :493, glob meaning :498, Q-10 bracket :504) | ✓ |
| LLR-053.5 | AT-053a | `tests/test_tui_report_filter_surface.py:782` (joined both-surfaces node) + Generate-half TC guard `tests/test_tui_report_seam.py:1523` (docstring declares itself TC-level; C-18 note inside) | ✓ |
| LLR-053.6 | AT-053b, AT-056b | `tests/test_tui_report_filter_surface.py:860`, `:509`; plus the S-F1 exit grep executed in §4 (0 call sites) | ✓ |
| LLR-053.7 | TC-310 + AT-053a | `tests/test_report_filter.py:512` `TestTc310NeverRaise` (hostile record shapes :515, hostile args :537, None collections :547) + surface `:782` (refusal precedes any write, 0 files both surfaces) | ✓ |
| LLR-054.1 | TC-311 | `tests/test_before_after_report.py:972` (matcher forwarded, both formats), `:1028` (no-filter generator kwargs shape == today's) | ✓ |
| LLR-054.2 | TC-312 | `tests/test_diff_report_service.py:1249` (restrict both formats), `:1283` (A9 merged-window-spans-excluded-run), `:1332` (zero-match/refusal wording disjoint), `:1371` (audit header first-block fixed format) | ✓ |
| LLR-054.3 | TC-312/TC-314 + AT-054c/AT-055c | nodes above + `tests/test_report_service.py:1367`/`:1431`; `tests/test_tui_report_filter_surface.py:1071` (AT-054c); `tests/test_tui_report_seam.py:1487` (AT-055c) | ✓ |
| LLR-054.4 | AT-054b (golden) | `tests/test_before_after_report.py:881` + goldens `tests/goldens/batch35/at054b-before-after-report.{md,html}`; double-proof §7 | ✓ |
| LLR-054.5 | inspection + TC-313 + AT-056e | inspection EXECUTED §4 (A2B kwargs `app.py:3311-3318` — no `report_filter`, 0 hits); `tests/test_diff_report_service.py:1431` (TC-313); `tests/test_tui_report_filter_surface.py:716` (AT-056e) | ✓ |
| LLR-055.1 | TC-315 + AT-055a | `tests/test_report_service.py:1497` (wrong-type ValueError, None default, matcher accepted); `tests/test_tui_report_seam.py:1430` (Generate flow) | ✓ |
| LLR-055.2 | TC-314 | `tests/test_report_service.py:1367` (three surfaces, F-02 symbol-branch checklist row, end-exclusive boundary `[0x0FFE,0x1000)` vs `0x1000`), `:1465` (no-kwarg == `report_filter=None` byte equality + no-header pin) | ✓ |
| LLR-055.3 | AT-055b (golden) | `tests/test_tui_report_seam.py:1292` + golden `tests/goldens/batch35/at055b-project-report.md`; double-proof §7 | ✓ |
| LLR-055.4 | TC-318 (both halves) + AT-053b | diff half `tests/test_diff_report_service.py:1407`; report half `tests/test_report_service.py:1541`; black-box observer `tests/test_tui_report_filter_surface.py:860` | ✓ |
| LLR-056.1 | TC-316 | `tests/test_tui_report_filter_surface.py:1136` (sorted, symlink skipped, absent dir → `[]`, `validate_project_files` filters/-subdir regression — verified in-body: creates `filters/` with 2 json + 1 txt and calls the real validator) | ✓ |
| LLR-056.2 | AT-056a/b/c | `tests/test_tui_report_filter_surface.py:313`, `:509`, `:587`; C-15 probe executed at Inc-4 entry (raw label PARSED as markup; `rich.markup.escape` chosen — increment-004 §top) | ✓ |
| LLR-056.3 | AT-056a + AT-056a3 | `:313`, `:456`; F-09 funnel re-verified by this reviewer: `app.py:960` init, `:1903` b-key consult, `:2486` Generate consult, resets `:4832` (project create/save) + `:7143` (`_apply_prepared_load`) — matches the Inc-4 citation | ✓ |
| LLR-056.4 | TC-317 + AT-056d | `tests/test_tui_report_filter_surface.py:1193` (relative resolve, missing/symlink typed refusals, BOTH S-F2 swap classes); `:639` (typed-path arm through the surface) | ✓ |
| LLR-056.5 | AT-056a2 | `tests/test_tui_report_filter_surface.py:388` (both regimes; strengthened by the `e15b744` dock-overlap guard assertion at `:441-444`) | ✓ |
| LLR-057.1 | AT-057a + TC-319 | `tests/test_tui_patch_editor_v2.py:2269`; `tests/test_tui_patch_layout.py:351` | ✓ |
| LLR-057.2 | existing AT-032a/AT-052a unmodified | `tests/test_tui_patch_editor_v2.py:1780` (AT-032a), `:2148` (AT-052a), `_CHECKS_HELP_TOKEN` at `:1775` — file has **0 deleted lines vs base** (git diff, §4), so 0 edits to their bodies | ✓ |
| LLR-057.3 | AT-057b + existing suite | `tests/test_tui_patch_editor_v2.py:2350`; existing patch suites green in the full run with 0 un-censused edits (deletion audit §4) | ✓ |
| LLR-057.4 | TC-320 + snapshot run | `tests/test_tui_snapshot.py:825`; observed snapshot state §6 matches §6.5 amendment #21 exactly (1 xfailed = patch-120x30 real drift, 1 xpassed = patch-80x24 defensive mark) | ✓ |

**25/25 LLRs covered by on-disk, green nodes.** No LLR is signed from intent.

---

## 2. Layer B — C-18 reconciliation: 17 ATs → exactly one on-disk node each

| AT (§5.2) | One on-disk node | Counterfactual evidence (cited from increment reports) | Class |
|---|---|---|---|
| AT-053a | `test_at_053a_invalid_filter_refuses_both_surfaces_zero_files` — `tests/test_tui_report_filter_surface.py:782` | Inc-4 §4 live RED `NoMatches '#report_filter_select'`; PLUS the Inc-3 Generate-half live RED: "a refused run must write ZERO report files, got ['20260711T021512Z-report.md']" — the pre-change tree silently wrote a full report | live-RED |
| AT-053b | `test_at_053b_hostile_valid_filter_proceeds_sanitized_everywhere` — `:860` | Inc-6 §4 CF-2 scratch counterfactual: both file-side sanitizers neutered → "raw control byte reached 20260710T120000Z-before-after-report.html" RED. Honestly-declared residual vacuity on NTFS filename arm (ctl/`<`/`>` unrepresentable in Windows filenames) — CF-2 is the strongest constructible; position/literal-name/table-integrity assertions are live directly | scratch-CF (declared weaker) |
| AT-054a | `test_at_054a_bkey_filtered_pair_keeps_match_omits_unmatched` — `:996` | Inc-4 §4 live RED: "the md must carry the audit header" — b-key wrote an UNFILTERED pair despite the designated filter | live-RED |
| AT-054b | `test_at_054b_no_filter_bkey_report_pair_byte_identical_to_golden` — `tests/test_before_after_report.py:881` | Inc-0 §4 golden double-proof: XOR-perturbation of each golden → RED (`At index 1949 diff: b'.' != b'/'` md; `index 2438` html) → restore → green; **re-derived independently by this reviewer at Phase 4, §7** | guard-golden (double-proven ×2) |
| AT-054c | `test_at_054c_bkey_zero_match_writes_pair_with_loud_notice` — `tests/test_tui_report_filter_surface.py:1071` | Inc-4 §4 live RED: "the loud zero-match notice must replace the filtered section bodies" | live-RED |
| AT-055a | `test_at_055a_generate_surface_filtered_report_with_audit_header` — `tests/test_tui_report_seam.py:1430` | Inc-3 §4 live RED: `assert '- Project: proj' == '## Report filter applied'` (header absent, first block wrong) | live-RED |
| AT-055b | `test_at_055b_no_filter_generate_report_byte_identical_to_golden` — `:1292` | Inc-0 §4 perturbation RED (`At index 1360 diff: b')' != b'('`) → restore → green; re-derived §7 | guard-golden (double-proven ×2) |
| AT-055c | `test_at_055c_generate_surface_zero_match_notice` — `:1487` | Inc-3 §4 live RED: `'- Filter file: matches-nothing.json' in ...` failed | live-RED |
| AT-056a | `test_at_056a_dropdown_selection_filters_both_triggers` — `tests/test_tui_report_filter_surface.py:313` | Inc-4 §4 live RED `NoMatches '#report_filter_select'` | live-RED |
| AT-056a2 | `test_at_056a2_selector_row_and_generate_visible_at_both_regimes` — `:388` | Inc-4 §4 live RED `NoMatches '#report_filter_row'`; ADDITIONAL liveness: post-implementation it correctly caught the geometry-ladder rung-1 failure (Inc-4 §4 "First implementation pass was 12/1") | live-RED (double) |
| AT-056a3 | `test_at_056a3_project_switch_resets_selection_next_report_unfiltered` — `:456` | Inc-4 §4 live RED `NoMatches '#report_filter_select'` | live-RED |
| AT-056b | `test_at_056b_hostile_filename_populates_and_renders_literally` — `:509` | Inc-4 §4 live RED `NoMatches`; plus the Inc-4 C-15 probe proving the raw-label failure mode is REAL on textual 8.2.8 (brackets consumed, styled render) | live-RED |
| AT-056c | `test_at_056c_fresh_default_blank_dropdown_full_report_golden` — `:587` | Inc-4 §4 live RED `NoMatches` (selector absent); byte-equality arm anchored to the double-proven AT-055b golden | live-RED + golden anchor |
| AT-056d | `test_at_056d_typed_path_valid_filters_missing_refuses` — `:639` | Inc-4 §4 live RED `NoMatches '#report_filter_path'` | live-RED |
| AT-056e | `test_at_056e_a2b_diff_report_byte_identical_despite_selection` — `:716` | Inc-4 §4 live RED `NoMatches` (selection step impossible pre-batch); leak-detection arm is the byte-compare vs a no-filter A2B run + the §4 kwargs inspection | live-RED + inspection |
| AT-057a | `test_at057a_two_labeled_sections_ids_and_parentage` — `tests/test_tui_patch_editor_v2.py:2269` | Inc-5 §4 live RED `NoMatches '#patch_script_section_label'` | live-RED |
| AT-057b | `test_at057b_regroup_wiring_and_binding_regression` — `:2350` | GREEN-by-design on both sides of the compose move (pure regression pin of pre-batch behavior; declared in Inc-5 §4 — "must be green on both sides"). No counterfactual constructible without breaking the very wiring it guards | regression pin (declared) |

**17/17 — no AT realized in parts; no node hosts two ATs.** The Inc-3 Generate-half node
(`test_tc_generate_refusal_half_...`, seam:1523) still exists ALONGSIDE the joined AT-053a
node — its docstring declares it TC-level and its planned "extend or supersede at Inc-4"
became "keep as redundant white-box guard". Not a C-18 violation (the AT maps to exactly one
node); recorded as a minor redundancy for a future hygiene pass.

Counterfactual-weak flags (none blocking): AT-053b (residual NTFS vacuity, declared +
CF-proven), AT-057b (regression-pin class, declared). Both declarations live in the
increment reports and test docstrings — nothing silent.

---

## 3. Bidirectional surface-reachability matrix

Every named input dimension and output deliverable, with the node exercising/observing it
THROUGH the shipped handler (key `b` → `action_before_after_report`; `ReportViewerScreen`
Generate → `_trigger_generate_report` → worker; patch screen; A2B report surface):

**Inputs**

| Input dimension | Shipped-surface node | Unit twin |
|---|---|---|
| Filter via dropdown (non-default) | AT-056a (:313) — both triggers byte-differ | — |
| Filter via typed path (valid) | AT-056d (:639) | TC-317 resolve |
| Typed path missing | AT-056d refusal arm | TC-317 |
| No filter / none default | AT-056c (:587), AT-054b, AT-055b | — |
| Invalid filter (bad envelope) | AT-053a (:782) — BOTH surfaces, 0 files | TC-308 matrix |
| Hostile filename | AT-056b (:509) status/overlay; AT-053b (:860) written files | TC-318 both halves |
| Hostile patterns (markup, ctl, header-forge) | AT-053b | TC-318, TC-310 metachar pins |
| Zero-match filter | AT-054c (:1071) b-key; AT-055c (seam:1487) Generate | TC-312/TC-314 zero-match |
| Ceilings 4096/4097 | unit only — TC-309 boundary-exact | (surface refusal plumbing proven by AT-053a on the shared parse→refuse funnel; a ceiling fault takes the identical path — accepted, noted) |
| Symlink / swap (TOCTOU) | TC-317 both swap classes reach the read-time refusal the surface consumes; symlink arms RAN locally (not skipped) | TC-309 symlink |
| Project switch (reset) | AT-056a3 (:456) | — |
| Empty include lists (D-10) | routes to zero-match surface nodes | TC-307 :90, D-10a pin :560 |

**Outputs / deliverables**

| Deliverable | Observed through the shipped surface by |
|---|---|
| Before/after MD+HTML pair (filtered) | AT-054a — match kept, unmatched absent from BOTH formats, header + real filename |
| Before/after pair (unfiltered byte-identity) | AT-054b golden (canonical form per §6.5 #19) |
| Project report (filtered) | AT-055a — filtered sections + header via real `#report_generate` |
| Project report (unfiltered byte-identity) | AT-055b golden |
| A2B diff report EXEMPTION | AT-056e — byte-identical to no-filter run under an active selection |
| Audit header (position, counts) | AT-054a/AT-055a black-box; TC-312 :1371 / TC-314 white-box; AT-053b exactly-once anti-forgery |
| Zero-match notice | AT-054c + AT-055c (wording disjoint from refusal — Q-12 asserted in AT-054c) |
| Status confirmation (filename, literal) | AT-056b + AT-053b (b) through the `markup=False` log labels |
| Status refusals (kind-prefixed) | AT-053a (both kinds), AT-056d (path faults) |
| Dropdown options (populate, sort, hostile literal) | AT-056b overlay render; AT-056a/AT-056c option states; TC-316 scan |
| Section labels + parentage (US-057) | AT-057a pilot queries; TC-319 compose census |
| Buttons still wired (US-057) | AT-057b real `button.press()` per button + `b` binding |

Every output-producing story has a black-box deliverable observation — the Phase-4 blocker
condition ("story with no black-box deliverable observation") does not fire.

---

## 4. Methods other than test — inspections EXECUTED this phase

All commands run by this reviewer at `428470a` on 2026-07-11:

1. **Engine-frozen diff (0-diff contract):**
   `git diff 79699a5 --stat -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py
   s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py`
   → **empty (0 diffs)**. Same vs `origin/main` → empty. Guard test run: §6.
   (Note: `git diff main` initially showed a 2-line SVG delta — root-caused to the STALE
   local `main` ref at batch-33 `f79834e`; the delta is batch-33's own canonical regen
   commit `cc58397` (PR #62) present on the branch side. Not a batch-35 diff.)
2. **LLR-054.5 A2B kwargs inspection:** `grep -n generate_diff_report s19_app/tui/app.py`
   → call sites `app.py:3319/:3325` with kwargs dict `:3311-3318` =
   `mem_map_a/mem_map_b/project_dir/dest_input/a2l_records/mac_records` — **no
   `report_filter` key. 0 hits.** Numeric threshold met.
3. **S-F1 exit grep:** `git diff main -- s19_app/ | grep '^+' | grep -E
   'notify\(|set_file_status\('` → **2 hits, both docstring PROHIBITION mentions
   (`never notify()/set_file_status`), 0 call sites.** Every filter-derived string routes
   through the markup-inert `set_status` funnel.
4. **Analysis — 4096-pattern perf deferral (§6.3 risk 6): MEASURED, no longer assumed.**
   Scratch measurement against the shipped module (ceiling-max filter: 4096 patterns +
   4096 ranges, 195 KB JSON; 5000 A2L + 2000 MAC records):
   `parse: 0.003s · resolve: 1.844s · classify 10k items: 9.286s`.
   Residual statement: the pathological square (ceiling filter × thousands of report items)
   costs seconds ON THE UI THREAD (the `b` path is synchronous — S-F3); a realistic
   operator filter (tens of patterns, tens-to-hundreds of items) is milliseconds. Bounds
   hold: 4 MiB cap + 4096/4096 ceilings + once-per-run resolve. Accepted residual;
   recommend a backlog note ("ceiling-size filters stall the UI for seconds") for the
   operator format docs — no code action owed this batch.
5. **Analysis — cross-platform proof:** all local evidence is Windows; the ubuntu CI run on
   the PR is the pending cross-platform proof (canonicalization designed for both — CRLF
   undo is a near-no-op on Linux; TC-316/317 symlink arms RAN locally and always run on CI).
   OPEN until the PR pipeline is green (§9).
6. **Existing-pin edit audit (for §8 / LLR-057.3):** deletion counts vs base `79699a5` —
   `test_tui_patch_layout.py: 0 · test_before_after_report.py: 0 · test_tui_report_seam.py:
   0 · test_tui_patch_editor_v2.py: 0 · test_report_service.py: 0 · test_tui_snapshot.py: 1
   (the censused marks-sum line) · test_diff_report_service.py: 1 (pre-existing F401 import)
   · conftest.py: 1 (pre-existing `typing.Any` F401)`. **0 un-censused edits.**

---

## 5. Census disposition verification (01b §5 → what actually happened)

| 01b row | Predicted | Actual (verified this phase) | Verdict |
|---|---|---|---|
| 1 — grid-3 pin `test_tui_patch_layout.py:290-325` | SUPERSEDE/EXTEND | **SURVIVED UNMODIFIED** (0 deleted lines vs base; green with 4 buttons). 02-review had already corrected the 01b over-caution ("test body asserts layout+columns only"); LLR-057.1 acceptance encoded it | ✓ corrected-and-held |
| 2 — `patch_pane_changefile` pane census | SURVIVES | survives (0 deletions, suite green) | ✓ |
| 3 — editor_v2:67 id census | SURVIVES + extend | survives; Inc-5 added the NEW `_PRESERVED_REGROUP_IDS` census instead of editing the old one (pure append) | ✓ |
| 4 — AT-032a token span + wiring pins | SURVIVES (locked) | survives — 0 deletions; `_CHECKS_HELP_TOKEN` still at `:1775` and asserted at `:1806/:1871` | ✓ |
| 5 — two patch snapshot cells | both DRIFT → xfail | **1 drifted (120x30), 1 did not (80x24 — below-fold render)**; both keep `strict=False` marks per the LOCKED LLR wording; ratified as §6.5 amendment #21; observed run state matches (§6) | ✓ deviation ratified |
| 6 — `test_full_report_content` | SURVIVES | survives (0 deletions in `test_report_service.py`, green) | ✓ |
| 7 — `:1046` byte-identical normalizer | SURVIVES; **reuse its normalizer** | survives; the reuse instruction was NOT followed — Inc-0 built `_canonical_report_bytes` (run-root masking + CRLF undo, a wider environment class than the `:1046` timestamp normalizer handles). Deviation ratified as §6.5 #19/#20 (canonical-form amendment); on THIRD use the helper was factored into `tests/conftest.py` (Inc-4) | ✓ deviation ratified |
| 8 — AT-038a-d | SURVIVE; copy helpers | survive — 0 deletions; AT-054b drives the AT-038a chain and copies its helpers (Inc-0 §1) | ✓ |
| 9 — TC-038-3 composer pin | **EXTEND** (records + filter kwargs) | **SURVIVED UNMODIFIED** — D-9 killed the record-kwargs plan (F-01); the composer gained ONE default-absent kwarg, so the pin needed no edit. The kwargs-shape contract landed as NEW node TC-311 (`:1028`) instead — stronger than the predicted extend | ✓ superseded by better design |
| 10 — seam:394 dialog-geometry pin | EXTEND if selector lands in that dialog | selector DID land there; the pin was NOT extended — geometry is covered by the NEW dedicated node AT-056a2 (both regimes, TC-024.6 idiom) + the `e15b744` dock-overlap guard; old pin still green | ✓ discharged via new node |
| 11 — seam:562 manifest byte-neutrality | SURVIVES | survives (selection never persisted — LLR-056.3 stores only the path in app state) | ✓ |
| 12 — diff_report_service A/B pins | SURVIVE untouched | survive (1 deleted line = pre-existing F401 import only); AT-056e guard added as planned | ✓ |
| 13 — workspace_variants:92 filters/ twin | EXTEND `test_workspace_variants.py` | `test_workspace_variants.py` NOT touched; the `validate_project_files`-ignores-`filters/` regression landed INSIDE TC-316 (`test_tui_report_filter_surface.py:1136` — verified in-body: real `filters/` dir + real validator call) | ✓ coverage present, different home |
| 14 — C-14 e2e observer sweep | SURVIVE; audit at Phase 3 | **Sweep re-run this phase**: `grep -rn 'rglob(\|.glob(' tests/*.py` — every workarea/reports observer uses a NARROW pattern (`*-before-after-report.*` :665, `changes*.json` editor_v2:398, `*-crc.s19` crc_surface:585, `roundtrip*.json` change_service:150, `*.s19`/`*.hex`/`CON*` editor_v2, `patches/*.json`); none asserts an empty region a `filters/*.json` fixture could trip; all filter fixtures live in per-test project dirs of NEW tests. **No observer missed** | ✓ |

---

## 6. Full-suite gate evidence (this reviewer's own runs)

**Process deviation, recorded:** the mandated single blocking foreground call
(`python -m pytest -q -m "not slow"`, timeout 600000 ms) was killed by the harness's hard
10-minute tool cap at ~85% (this machine needs ~11.3 min). Evidence below is from ONE
complete detached run of the identical command whose own captured output was read
(`scratchpad/full-suite-phase4.log`) — a single run, no stitching, no parallel duplicate.

Full fast suite tail (exact):

```
1335 passed, 2 skipped, 21 deselected, 4 xfailed, 1 xpassed, 1 warning in 664.67s (0:11:04)
PYTEST_EXIT=0
```

Expected per §6.5 #21 / Inc-6 ledger: `1335 passed, 2 skipped, 21 deselected, 4 xfailed,
1 xpassed`, exit 0 — **EXACT MATCH** (the 1 warning is the standing snapshot-report
warning, present in every recorded increment run).

Snapshot suite alone (`python -m pytest tests/test_tui_snapshot.py -q`):

```
33 passed, 1 xfailed, 1 xpassed, 1 warning in 42.28s
SNAP_EXIT=0
```

Expected `33 passed, 1 xfailed, 1 xpassed` (31-cell oracle: 29 green + patch-120x30 xfailed
+ patch-80x24 xpassed, plus fixture-provenance + 2 CV-04 boundary tests + TC-320) —
**EXACT MATCH**.

Engine-frozen guard (`python -m pytest tests/test_engine_unchanged.py -q`):

```
1 passed in 0.06s
GUARD_EXIT=0
```

---

## 7. §5.3 batch acceptance checklist

| §5.3 criterion | ✓/✗ | Citation |
|---|---|---|
| 100% of LLRs covered by ≥1 TC/AT with a pass result; 0 blocker failures | ✓ | §1 table (25/25), §6 run (0 failures) |
| Every US has ≥1 passing AT observing its outcome through the shipped surface with boundary + negative evidence | ✓ | §2 + §3; US-053: AT-053a/b; US-054: AT-054a/b/c; US-055: AT-055a/b/c; US-056: AT-056a/a2/a3/b/c/d/e; US-057: AT-057a/b. Boundary: TC-309 ceilings, TC-314 end-exclusive, AT-056a2 80x24; negative: AT-053a, AT-054c, AT-056b/d |
| Both byte-identity goldens pass under the declared pin with the double-proof executed and recorded | ✓ | Inc-0 §4 (perturbation REDs at offsets 1949/2438/1360, restore→green) + **this reviewer's independent Phase-4 re-derivation** (executed 2026-07-11, after the §6 suite run, goldens restored via `git checkout` and verified clean): XOR 0x01 at the Inc-0 offsets → `at054b-...md` @1949 and `at055b-...md` @1360 → `2 failed` with the exact LLR-054.4/055.3 drift assertions; `at054b-...html` @2438 → `1 failed` (HTML assert reached and RED); restore → `2 passed in 4.08s`, exit 0 — all three equality assertions independently re-proven live. Structural note: the goldens were captured AT the base revision (Inc-0 was test-only; no product code existed), so capture == base output by construction — the 01b §2.3 hash-pinning variant was superseded by the canonical LLR-054.4 procedure (equality + perturbation RED), ratified §6.5 #19 |
| 0 diffs vs main in the engine-frozen set; guard green | ✓ | §4 item 1 (empty diff vs `79699a5` AND `origin/main`); guard run §6 |
| Full suite green except the declared patch snapshot xfail set | ✓ | §6 tail == the §6.5 #21 declared state (4 xfailed = 3 pre-existing + patch-120x30; 1 xpassed = patch-80x24 defensive mark) |
| Existing AT-032a/AT-052a/AT-038* pass with 0 un-censused edits | ✓ | git log since base: `test_tui_patch_editor_v2.py` touched only by Inc-5 `c8dc2fa` (pure append, 0 deletions); `test_before_after_report.py` by `92df3f4`/`58d7c7e` (0 deletions); §4 item 6 deletion audit; all green in §6 |

---

## 8. Ledger reconciliation

`post = base − D + A`, collected-node basis (01b §6 base: **1270 collected** @ `79699a5`):

| Step | A (added, named) | D | Running collected |
|---|---|---|---|
| base @ 79699a5 | — | — | 1270 |
| Inc-0 | +2 (AT-054b, AT-055b) | 0 | 1272 |
| Inc-1 | +56 (TC-307..310, `tests/test_report_filter.py`) | 0 | 1328 |
| Inc-2 | +9 (TC-311×2, TC-312×4, TC-313, TC-318-diff, D-10a pin) | 0 | 1337 |
| Inc-3 | +7 (TC-314×3, TC-315, AT-055a, AT-055c, Generate-refusal TC) | 0 | 1344 |
| Inc-4 | +13 (AT-053a, AT-054a/c, AT-056a/a2/a3/b/c/d/e, TC-316, TC-317, TC-F1) | 0 | 1357 |
| Inc-5 | +4 (AT-057a/b, TC-319, TC-320) | 0 | 1361 |
| Inc-6 | +2 (AT-053b, TC-318-report) | 0 | 1363 |

**Verified by execution this phase: `python -m pytest --collect-only -q` → `1363 tests
collected`.** D = 0 throughout (no node deleted; the 3 deleted LINES are censused non-node
lines, §4 item 6). Not-slow arithmetic: 1363 − 21 slow-deselected = 1342 run =
**1335 passed + 2 skipped + 4 xfailed + 1 xpassed** — matches §6 exactly.
Xfail/xpass re-bucketing trail: 3 xfailed (pre-batch, unchanged Inc-0..4) → Inc-5 moved the
two patch snapshot cells out of "passed": 120x30 → 4th xfailed (real drift), 80x24 →
1 xpassed (no local drift under its mandated `strict=False` mark) — declared in §6.5 #21.

---

## 9. Gaps / open items (none blocks this gate)

1. **REQUIREMENTS.md ledger rows** `R-RPT-FILTER-001` / `R-TUI-045` — verified ABSENT
   (`grep R-RPT-FILTER\|R-TUI-045 REQUIREMENTS.md` → 0 hits). Owed in Phase 6 docs.
2. **Operator format docs** (envelope, extent semantics F-1, F-2 over-match note, Q-10
   bracket note, F-10 annotation divergence, ceiling-perf note from §4 item 4) — verified
   ABSENT (`grep -rl "s19app-report-filter" --include=*.md` outside `.dev-flow/` → 0 hits).
   Owed in Phase 6.
3. **Post-merge canonical snapshot regen** (snapshot-regen.yml @ textual 8.2.8) for the
   patch cell(s) + retirement of BOTH batch-35 marks — standing procedure.
4. **ubuntu CI run** — the pending cross-platform proof for the canonical-form goldens and
   symlink arms (§4 item 5).
5. **S-F7 (pre-existing, out of batch):** `report_service.py` interpolates
   `entry.linkage_symbol` raw (~:703) — byte-identity locks it this batch; backlog follow-up
   per 02-review.
6. **Parked batch-29 stash** — verified still present (`stash@{0}: On
   claude/batch-29-clip-cap-datatable-retire: batch-29 post-merge bookkeeping`), untouched
   by this batch (each increment recorded no-stash-use). Operator's call to drop or apply.
7. **Minor hygiene (future batch):** consolidate the `_zero_match_notice`/ctl-strip/
   `_filter_display_name` twins (pinned equal by TC-F1 `test_tui_report_filter_surface.py:1332`);
   collapse the two per-file `_canonical_report_bytes` twins onto the conftest helper; the
   redundant Generate-half TC beside the joined AT-053a (§2 note).
8. **Stale local `main` ref** — points at batch-33 `f79834e` while `origin/main` = `79699a5`;
   harmless here (all checks re-run vs base/origin) but worth a `git fetch`+update before
   RC so guard tests that diff against `main` compare the right tree.

---

## 10. Verdict (exit axes)

- **Coverage — MET.** 25/25 LLRs → on-disk green nodes (§1); 17/17 ATs → single nodes
  through shipped surfaces (§2); bidirectional matrix has no empty cell requiring code
  action (§3; the ceilings-through-surface cell is unit-level by accepted design).
- **Certainty — MET.** 13/17 ATs live-RED-proven, 2 golden-guards double-proven twice
  (Inc-0 + this phase's independent re-derivation), 2 declared weaker classes with the
  strongest constructible counterfactuals recorded (§2); the last "assumed" analysis item
  (4096 perf) is now measured (§4).
- **Evidence — MET.** Every claim above carries an executed command, file:line, or quoted
  run output from THIS phase; the one process deviation (tool-cap-forced detached suite
  run) is declared in §6 with the single-run provenance.

**Phase-4 gate: PASS.** Owed next: Phase 5/6 per PLAN (post-mortem, docs: REQUIREMENTS.md
rows + operator format docs), then PR + canonical regen.

---

## Evidence checklist (qa-reviewer, Phase 4)

- [x] Acceptance criteria use Given/When/Then — G/W/T lives in 01 §3 acceptance blocks; this phase verified their realization (§1/§2).
- [x] Test cases have explicit Expected — every §1 row cites the numeric threshold met; §6 quotes exact tails.
- [x] Edge cases include empty, boundary, invalid, error — §3 inputs matrix (empty include/zero-match, 4096/4097 + end-exclusive boundaries, bad envelope, symlink/swap/missing).
- [x] Regression checklist exists — §5 (14 census rows verified) + §4 item 6 edit audit.
- [x] Exit criteria stated — §10 axes.
- [x] No real PII / secrets — synthetic fixtures throughout; S-F1 grep §4.
- [x] Test results NOT left blank — this is the phase that runs them; all results in §6 are this reviewer's own executions.
- [x] Layer B black-box — §2/§3: every output-producing story observed through the shipped surface with boundary + negative evidence.
- [x] Bidirectional surface-reachability — §3 both directions, node named per cell.
- [x] No unfilled template — no placeholders remain (run-evidence slots filled from the executed runs).

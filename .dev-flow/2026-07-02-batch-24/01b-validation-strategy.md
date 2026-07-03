# 01b — Validation Strategy — 2026-07-02-batch-24

> **Scope:** US-032 (red-row ⇒ ERROR issue) · US-033 (ERROR issue ⇒ red row) · US-034 (before/after report on save-back).
> Author: qa-reviewer (Phase 1, concurrent with the architect's §3/§4 — TC numbering binds to §4 LLRs at Phase 2).
> Harness facts honoured throughout: **pytest-asyncio NOT installed** → every Pilot AT is a sync test wrapping `asyncio.run` (idiom: `tests/test_tui_patch_layout.py:71-96`); gate asserts are black-box (rendered text / widget public state / disk); private-attr reads are diagnostics only; drive-level private-method calls are the ratified idiom (batch-23 precedent).
>
> **ORCHESTRATOR RECONCILIATION NOTE (2026-07-02, Phase-1 assembly):** the architect's
> §3/§4 resolved this file's open placeholders — bind as follows: (QR-2) the US-034
> trigger = `action_before_after_report` on key `b` (LLR-038.3; key provisional, free
> per P-6). (QR-3) the US-032 "issues report" observable = the `#validation_issues_list`
> DataTable (same `_validation_issues` list backs the workspace pane and the `5`
> Issues-Report screen, HLR-036 Acceptance) — NO file observable grows. WARNING-row
> policy = never recolours (§6.2 D-2, REQUIREMENTS.md:362-367 palette). The architect
> added b/c AT variants (AT-036b/c, AT-037b, AT-038b/c) — this file's per-AT boundary/
> negative content maps into them; §4's LLR-aligned TC ids are canonical. All ids
> remain provisional per V-5.
>
> **ITERATE-TO-REFINE FOLD (2026-07-02, 02-review):** B-1a — every MAC-less AT here
> also gates the LLR-037.4 no-MAC retention fix (`update_mac_view` wipes
> `_validation_issues` at `app.py:7162-7163`/`:7176-7177` pre-fix; ships in I1, so
> AT-036a's Issues observable and AT-037a's map source become real). B-2 — AT-038d
> (stale-summary cross-project refusal) added. A-M1 — AT-037b narrowed to the
> absent-from-table symbol; WARNING no-recolour is Layer-A TC-037.2 GUARD. Q-M1/Q-M2
> folded into AT-038a; risk ids renamed QR-\* (Q-m3); anchors corrected (Q-m4).

---

## 1. Layer B — black-box ATs (provisional per V-5; namespaces AT-036\*/037\*/038\*)

### AT-036a — US-032 GATE — missing-address non-virtual tag: red row AND named ERROR issue

**The proven divergence this gates:** a non-virtual tag with `address is None` gets `schema_ok=False` (frozen `tui/a2l.py:1290-1291`) → row renders red (`app.py:223-225`), while `validate_a2l_structure` emits `A2L_INVALID_ADDRESS` only for *present-but-non-int* addresses (`rules.py:460-469`) → **zero issues today**.

- **Fixture (must be AUTHORED — see §4):** raw A2L text file on `tmp_path` adapted from `tests/test_tui_a2l.py:20-43`: one healthy `MEASUREMENT RPM` (ECU_ADDRESS 0x1000, DATA_SIZE 2), plus one **non-virtual `CHARACTERISTIC BROKEN_CHAR` with NO ECU_ADDRESS line and NO VIRTUAL keyword** (the existing raw address-less characteristic at `test_tui_a2l.py:31-39` is VIRTUAL — exempt by design, unusable here). Paired 16-byte S19 at 0x1000 via `emit_s19_from_mem_map` (builder idiom `tests/test_tui_patch_editor_v2.py:101-107`).
- **Drive (shipped chain — issues PRODUCED, never injected):** `S19TuiApp.run_test` inside `asyncio.run`; load S19 then A2L through the shipped load pipeline — `app._parse_loaded_file(path)` per artifact pushed through `_prepare_load_payload`/apply (established multi-artifact idiom: `tests/test_tui_app.py:1145-1194`; MAC-after-S19 variant at `:606-637`); `await pilot.pause()` after apply. This exercises enrich (`a2l_service.enrich_tags_and_render`) + `validation_service.build_validation_report` (merge point `validation_service.py:83-91`) + both renderers — the fix's exact seam.
- **Exact observables:**
  1. **A2L table (red row):** `#a2l_tags_list` DataTable rendered row for `BROKEN_CHAR` — every cell is a `rich.text.Text` styled by `_severity_style(_a2l_tag_row_severity(tag))` (`app.py:7482-7484`). Assert the rendered cell's `.style` equals the colour-policy ERROR style (round-trip anchor: `tests/test_color_policy_round_trip.py:51,131` — semantic, not a hard-coded `"red"` literal).
  2. **Issues Report surface** (= rail screen 5, `app.py:570,1196` — a VIEW, not a file; see risk QR-3): after `action_show_screen("issues")`, read rows back from the issues DataTable (read-back helper idiom `_query_issues_panel_codes`, `tests/test_tui_app.py:1820-1845,1884-1913`) → at least one row with severity ERROR **whose code is the new supplemental code and whose message/symbol names `BROKEN_CHAR`**. This observable is MAC-less by design and therefore gates LLR-037.4 too: pre-fix, `update_mac_view` wipes `_validation_issues` in every no-MAC session (`app.py:7162-7163`/`:7176-7177`), so the pane is empty regardless of the supplemental rule — do NOT add a MAC to the fixture to green it (C-12-family masking; B-1a).
- **Counterfactual — RED today (this is the reported bug):** on the pre-fix tree observable (1) already passes and observable (2) FAILS (zero issues for the symbol). **Capture plan:** at Phase-2 authoring, run AT-036a once against the pre-fix tree (before Inc-1 lands), record the failing assertion output (issues table row-dump showing no `BROKEN_CHAR` row) into the batch evidence pack — the AT must demonstrably fail TODAY before it may gate.
- **Boundary inputs (same fixture file):** a `VIRTUAL` characteristic with no address → must stay non-red AND produce **no** new-code issue (`tui/a2l.py:1288-1289` exemption); a tag with `length` missing but address present (the other `schema_ok=False` arm of `a2l.py:1290`) → red + issue too.
- **Negative input:** one tag with a *present-but-malformed* address (the `A2L_INVALID_ADDRESS` shape, `rules.py:460-469`) → exactly ONE issue for that symbol (the existing code), never a new-code duplicate (dedup rides `dedupe_issues`, `validation_service.py:91`).
- **Reuse:** sync-wrapper `test_tui_patch_layout.py:71-96`; load-chain drive `test_tui_app.py:1145-1194`; issues read-back `test_tui_app.py:1820`; S19 emitter `tui/changes/io.py::emit_s19_from_mem_map`.

### AT-037a — US-033 GATE — duplicate symbol: ERROR issue reds both rows

- **Fixture (must be AUTHORED as raw text — see §4):** raw A2L file with the **same symbol defined twice** (two `MEASUREMENT RPM` blocks, valid distinct addresses 0x1000/0x1002 — mirrors the dict-shaped engine fixture `tests/test_validation_a2l.py:11-14`) + one healthy control tag `TORQUE`. Paired S19 covering the addresses.
- **Drive:** identical shipped load chain as AT-036a.
- **Exact observables:**
  1. Both `RPM` rows in `#a2l_tags_list` render the ERROR style (both `rich.text.Text` cell styles = colour-policy ERROR style).
  2. Control `TORQUE` row stays non-ERROR (proves per-symbol targeting, not blanket reddening).
  3. Issue list unchanged in content: exactly one `A2L_DUPLICATE_SYMBOL` ERROR (`rules.py:470-480`), no new/removed codes vs pre-fix (US-033 is render-side only).
- **Counterfactual:** pre-fix both `RPM` rows render non-red (`schema_ok=True` + valid addresses → OK/NEUTRAL through `_a2l_tag_row_severity`, `app.py:223-232`, which never consults issues) — assertion (1) fails TODAY. Same capture plan as AT-036a.
- **Boundary:** case-folded duplicates (`RPM` + `rpm`) — engine dedup keys on `name.lower()` (`rules.py:458,470`) → BOTH rows red (row-lookup must match the engine's case policy).
- **Negative (A-M1 split):** the WARNING no-recolour check is NOT drivable black-box — the shipped-chain a2l WARNING emitters are symbol-less or never match a rendered row, so a WARNING-on-rendered-row fixture is unbuildable without injection (banned for ATs). It lives as the Layer-A `TC-037.2` GUARD over constructed issues, pinning §6.2 D-2 (WARNING never recolours; QR-6 resolved). `AT-037b` instead covers the naturally-producible boundary: an issue symbol absent from the rendered table (via `A2L_BROKEN_REFERENCE`, `rules.py:507`) changes nothing — no crash, no row change.
- **Reuse:** everything from AT-036a; duplicate shape from `test_validation_a2l.py:4-19` (dict → raw-text port).

### AT-038a — US-034 GATE — save-back → offered trigger → handler-WRITTEN report re-read from disk (C-12)

**C-12 discipline (batch-16 G-3 lineage):** the gate observes the consumer-visible artifact **produced by the shipped handler chain**. The AT never writes any report content itself. A hand-written report file consumed elsewhere (e.g. a viewer TC) is a GUARD, never this gate.

- **Fixture:** `_make_s19_image` 16×`0x00` at 0x100 (`tests/test_tui_patch_editor_v2.py:101-107`), active project context so the report destination resolves to `<project>/reports/` (diff-report destination contract `diff_report_service.py:43-47`).
- **Drive (FULL shipped chain, TC-051 idiom `tests/test_tui_patch_editor_v2.py:521-638`):**
  1. Load the image (`_load_image` drive shortcut `:110-113` — ratified), `action_show_screen("patch")`.
  2. `_set_entry_inputs(address="0x100", bytes_text="AA BB")` (`:116-130`) → `panel.request_action("add_entry")` → `request_action("apply_doc")`.
  3. Confirm the save-back prompt (`#patch_saveback_confirm_button`, `:557-584`) → `last_summary.saved_path` stamped (`change_service.py:921-936`).
  4. Invoke the **offered trigger**: the shipped `action_before_after_report` on key `b` (bound per LLR-038.3; Q-m2 — placeholder resolved).
  5. `await pilot.pause()`; then observe per the Q-M1 chain below.
- **Exact observables (Q-M1 observation chain — surfaced text → dir-diff → re-read):**
  1. Snapshot the reports-directory listing BEFORE step 4; after it, capture the app's surfaced notify/status text, assert the SURFACED path equals the single new file in the post-trigger directory diff, and that its name matches the **new filename-scheme regex** (own-regex precedent: `BEFORE_AFTER_REPORT_FILENAME_REGEX` twin of the diff-report's, `diff_report_service.py:103-113` — anchor corrected per Q-m4; shared `REPORT_FILENAME_REGEX` byte-untouched). All content asserts below run on a re-read of THAT surfaced path — never a glob reconstruction, so LLR-038.3's surfacing is itself observed.
  2. The ```diff fence for the patched run shows the pre-patch byte(s) `00` as `-` lines and the entry's `after_bytes` `AA BB` as `+` lines at 0x100 (fence-carve assertion idiom: `tests/test_diff_report_service.py:344-380`).
  3. The **linkage table** contains the row for that entry: address `0x100`, before `00 00`, after `AA BB` (values from `ChangeSummaryEntry.before_bytes/after_bytes`, `changes/model.py:365-372`, captured pre-mutation at `apply.py:329-347`).
  4. Header identifies before = `LoadedFile.path` (the original on disk) and after = the **pinned literal basename `img-patched_1.s19`** (Q-M2): the collision drive pre-plants `img-patched.s19`, so the `_<N>` dedup scheme (`workspace.py:237-238`) forces the suffix — the typed name is not a substring of the suffixed one, so the equality assert discriminates a typed-name echo. `last_summary.saved_path` is read only as a failure DIAGNOSTIC, never as the expected operand (internal-operand correlated-failure shape removed).
- **Counterfactual:** pre-fix the trigger does not exist → step 4 has no action to invoke / no file appears under `reports/` → the AT fails TODAY by construction (net-new surface; the counterfactual is the absent deliverable, per the C-10 family).
- **Boundary (dedup-suffix, micro-spike consequence — requirements §DoR:52):** pre-plant a file named with the suggested `img-patched.s19` before confirming save-back → `save_patched_image` dedup-suffixes (`apply.py:574` contract) → the report's "after" identity MUST be the actual dedup-suffixed `saved_path`, not the suggestion. Also: second trigger invocation same second → `-NN` collision counter, zero overwrites (idiom `test_diff_report_service.py:146-198`).
- **Negative (= AT-038b/c, GUARD-class per Q-m1):** (a) `AT-038b` — **decline** the save-back (`#patch_saveback_decline_button`, `:566-576`) then invoke the trigger → refused with a diagnostic, **no file written**, no crash; (b) `AT-038c` — delete/move the original file between save-back and trigger → graceful refusal (no traceback, no partial file). Both are GUARD-class: pre-implementation the unbound key/action makes "no file written" pass vacuously, so the POSITIVE surfaced-refusal-diagnostic assert is load-bearing in each. The US-034 counterfactual is carried by AT-038a ALONE (absent deliverable).
- **GUARD (explicitly non-gate):** any TC that constructs a `ComparisonResult`/report content directly to exercise formatting is a guard on the writer internals, marked GUARD in the matrix.

### AT-038d — US-034 GUARD — stale-summary cross-project refusal (B-2)

- **Threat this guards (B-2):** `ChangeService.last_summary` survives project switches and file loads (`change_service.py:334,617,669`; `app.py:680,4314-4324`) — pre-fix, apply+save in project A then trigger in project B would pair B's loaded file against A's patched image and write a false-provenance report into B's tree.
- **Fixture/drive:** full AT-038a apply + save-back drive inside project A; then open/switch to project B (loading B's image through the shipped load chain); invoke `action_before_after_report`.
- **Exact observables:** (1) a surfaced stale-summary refusal diagnostic (positive assert on the notify/status text naming the mismatch — load-bearing per Q-m1's convention); (2) **0 files** in project B's `reports/` dir, asserted by directory listing (dir-diff vs the pre-trigger snapshot); (3) app keeps running.
- **GUARD-class:** pre-implementation the assert set would pass vacuously without observable (1); the refusal classes map to LLR-038.2 preconditions 4-5 / LLR-038.4 class 4 (`LoadedFile.path` ≠ `summary.source_image_path`, or `saved_path` outside the current project dir/workarea).

---

## 2. Layer A — white-box TC plan (numbering binds to the architect's §4 LLRs at Phase 2)

### US-032 — supplemental schema-issue rule (merge point `validation_service.py:83-91`)

| Area | Intent | Anchor |
|---|---|---|
| Dedup rule | A tag already covered by `A2L_INVALID_ADDRESS` (present non-int address) gets **no** duplicate new-code issue; `dedupe_issues` merge at `validation_service.py:91` holds | `rules.py:460-469` |
| Issue-code contract | New code (e.g. `A2L_TAG_SCHEMA_INCOMPLETE`) is pinned by string assert, the way existing codes are pinned today: `tests/test_validation_a2l.py:18-19` (`assert "A2L_DUPLICATE_SYMBOL" in codes`) + engine tests in `tests/test_validation_engine.py`; existing codes UNRENAMED (grep-guard) | CLAUDE.md issue-code public-contract rule |
| Virtual exemption | `virtual and address is None` → `schema_ok=True`, no issue (unit on the new rule, mirroring `tui/a2l.py:1283-1292` without touching it — frozen) | existing virtual fixture `tests/test_tui_a2l.py:141` |
| Missing-length arm | address present, length None → issue emitted (the other `schema_ok=False` arm) | `a2l.py:1290-1291` |
| Enriched-vs-raw tags input | rule consumes the same `tags_for_validation` selection as the report (`validation_service.py:60-63`) — empty-enriched vs None-enriched behavior preserved | `tests/test_tui_services.py:52-126` |

### US-033 — issue-severity → row-colour map (render side, `app.py` `_a2l_tag_row_severity` call site `:7482`)

| Area | Intent | Anchor |
|---|---|---|
| Precedence / max-severity | ERROR issue beats every `schema_ok=True` outcome; a tag that is BOTH `schema_ok=False` and issue-carrying stays ERROR (no double-count, no flicker) | `app.py:223-232` |
| WARNING policy | WARNING never recolours (§6.2 D-2, REQUIREMENTS.md:362-367 palette) — pinned by the `TC-037.2` Layer-A GUARD over CONSTRUCTED issues (A-M1: unbuildable black-box), never left implicit | §6.2 D-2 (QR-6 resolved) |
| Refresh timing | issues are computed in the load worker before `update_a2l_tags_view` renders → first paint already red; re-render after issue filter/page changes keeps it | `models.py` snapshot + `_apply_loaded_file` thread split |
| Lookup cost | per-row severity lookup is a symbol-keyed dict built once per render, not a per-row linear scan over issues (large_a2l fixture stays fast) | `tests/conftest.py:313` `large_a2l` |
| Case alignment | row lookup folds case exactly like `by_name[name.lower()]` | `rules.py:458` |
| Row-severity unit set | extend the existing pure-function unit rows | `tests/test_tui_app.py:50-54` |

### US-034 — save-back report service + trigger

| Area | Intent | Anchor |
|---|---|---|
| Failure modes | `last_summary is None` / `saved_path is None` (declined) / original path missing / STALE summary (`LoadedFile.path` ≠ `source_image_path`, or `saved_path` outside the current project dir — B-2, LLR-038.4 class 4) → refusal diagnostic, no file, no exception | `change_service.py:849-858, 921-936` |
| Provenance stamp | `ChangeSummary.source_image_path` stamped by `save_patched` beside `saved_path`; runtime-only (off `to_dict` — serialized summary byte-stable); handler passes `loaded.path` | `change_service.py:921-922`; `changes/model.py:376`; `app.py:1507-1515` |
| Markdown cell escaping | `_md_cell()` escapes `\|` + strips ctl chars for parsed-artifact values in MD tables (pipe-bearing symbol TC); HTML side already `_esc`-safe | S-F2; `diff_report_service.py:826-828` |
| Filename scheme | own regex, zero-padded `-NN` collision, `FileExistsError` after 99, never overwrite — mirror TC-016/TC-017 | `tests/test_diff_report_service.py:146-198` |
| Confidentiality | report (raw memory bytes) lands ONLY under the gitignored `.s19tool/` tree (`<project>/reports/`); **no logging at all** in the new module (F-S-07 precedent + its test) | `diff_report_service.py:43-47,66-69`; `tests/test_diff_report_service.py:433` |
| Linkage-table content | one row per summary entry incl. skipped/failed dispositions (not only applied); before/after hex formatting | `changes/model.py:365-372`, `report_service.py:641-690` render precedent |
| Fresh-parse before side | before/after maps come from `compare_images(original_path, saved_path)` fresh disk parses — never the in-place-mutated `LoadedFile.mem_map` (`change_service.py:811-813`) | `compare_service.py:4-16` |
| HTML flavor (if §3 keeps it) | self-contained, escaped, no script/CDN — reuse TC-028 pattern | `tests/test_diff_report_service.py:557-623` |

---

## 3. Method table

| Requirement area | Method | Layer |
|---|---|---|
| US-032 red-row ⇒ issue (both surfaces) | automated pytest — Pilot e2e | B (AT-036a GATE) |
| US-032 rule internals (dedup, exemption, codes) | automated pytest — unit on service/rules seam | A |
| US-033 issue ⇒ red row | automated pytest — Pilot e2e | B (AT-037a GATE) |
| US-033 severity map / timing / cost | automated pytest — unit | A |
| US-034 apply→save→trigger→report | automated pytest — Pilot e2e + surfaced-path→dir-diff→disk re-read (Q-M1) | B (AT-038a GATE, C-12; AT-038b/c/d GUARD-class) |
| US-034 writer internals / failure modes / filename / confidentiality | automated pytest — unit | A |
| Layout / geometry | **N/A** — no new widget row (DoR: trigger = notify/keybinding, C-13 N/A); no SVG snapshot need | — |
| Manual checks | none required; optional operator smoke at Phase-4 (load `examples/` case, eyeball Issues screen) | manual (non-gating) |

All behavioral requirements are test-verified. Nothing is left "manual-only".

## 4. Fixture-reuse map (file:line-verified)

| Need | Existing target | Verdict |
|---|---|---|
| Sync Pilot wrapper (no pytest-asyncio) | `tests/test_tui_patch_layout.py:71-96` (`asyncio.run(_run())`) | REUSE |
| Multi-artifact shipped load drive | `tests/test_tui_app.py:1145-1194` (`_parse_loaded_file` per artifact + `_prepare_load_payload`); `:606-637` | REUSE |
| Issues panel read-back | `tests/test_tui_app.py:1820-1845` + `_drive_panel`/`_query_issues_panel_codes` `:1884-1913` | REUSE (read-back only; its issue-INJECTION half is banned for ATs) |
| Issue injection for render-only TCs | `tests/test_tui_issues_view.py:41-63` (`_render_issue_list`) | REUSE — **Layer A / GUARD only** |
| Raw A2L text builder | `tests/test_tui_a2l.py:20-43` (nested MEASUREMENT + CHARACTERISTIC) | ADAPT |
| **A2L missing-address NON-virtual raw fixture** | **does NOT exist** — dict-shaped only (`test_tui_a2l.py:88`); the only raw address-less characteristic is `VIRTUAL` (`test_tui_a2l.py:31-39`, exempt by design) | **AUTHOR new** (few lines, derived from :20-43 minus ECU_ADDRESS/VIRTUAL) |
| **A2L duplicate-symbol raw fixture** | **does NOT exist as a file** — dict-shaped only (`tests/test_validation_a2l.py:11-14`) | **AUTHOR new** (duplicate one MEASUREMENT block) |
| Corrupt-A2L negative material | `tests/conftest.py:483-517` (`corrupt.a2l` trio) | REUSE for structure-error negatives if needed |
| S19 image builder | `tests/test_tui_patch_editor_v2.py:101-107` + `emit_s19_from_mem_map` | REUSE |
| Patch apply/save-back drive | `tests/test_tui_patch_editor_v2.py:521-638` (TC-051: `_set_entry_inputs`, `request_action("apply_doc")`, saveback confirm/decline buttons, workarea rglob) | REUSE |
| Diff fence / filename / no-overwrite / no-logging assertions | `tests/test_diff_report_service.py:344-380, 146-198, 176-198, 433` | REUSE pattern |
| Severity-style semantic anchor | `tests/test_color_policy_round_trip.py:51,131` | REUSE |
| Stress guard (US-033 cost) | `tests/conftest.py` `large_a2l` (`:313`) | REUSE — no ad-hoc large builders |

## 5. Testability risks

*(Family renamed `QR-*` at the iterate-to-refine fold — Q-m3: the requirements file owns the plain `R-*` namespace, §6.3.)*

- **QR-1 — "red" is a Rich `Text.style`, not a CSS class** (`app.py:7482-7484`): the A2L table has no `sev-*` class to query. Mitigation: assert the rendered cell's style equals the colour-policy ERROR style via the round-trip anchor (semantic, survives palette changes); raw `"red"` literals banned in the ATs.
- **QR-2 — US-034 trigger surface unbound — RESOLVED:** bound at Phase-1 assembly to `action_before_after_report` on key `b` (LLR-038.3); the AT-038a placeholder is renamed accordingly (Q-m2).
- **QR-3 — "issues report" is the rail screen, not a file:** confirmed = Issues Report rail screen 5 (`app.py:570,1196`; `rail.py:83`). The project report (`report_service.py:1139-1149`) carries only variant-execution issues, NOT `_validation_issues` — US-032's AC must not be misread as requiring a report-file change. If §3 decides otherwise, AT-036a grows a file observable (flag at Phase 2 gate).
- **QR-4 — worker-thread contract:** the drive calls `_parse_loaded_file` on the test thread (ratified); renderers must still run under `run_test` with `pilot.pause()` — missing pauses are the likely flake source. Keep the `tests/test_tui_variants.py:172` zero-new-call-sites AST guard in mind: the AT adds test-side calls only, no product call sites.
- **QR-5 — pre-fix failing-run capture:** AT-036a/037a counterfactual evidence requires running them BEFORE Inc-1 merges — schedule the capture at Phase-2 authoring, not after. Note (B-1a): the pre-fix AT-036a failure now has TWO causes (missing supplemental rule + the no-MAC wipe) — the captured evidence records the empty Issues pane either way.
- **QR-6 — WARNING policy — RESOLVED:** §6.2 D-2 (never recolours) + A-M1 split: pinned by the `TC-037.2` Layer-A GUARD over constructed issues; not an AT.
- **QR-7 — no-project destination for the US-034 report:** save-back can occur outside a project (workarea temp), but `<project>/reports/` needs an active project; diff-report precedent refuses without an operator dir (`diff_report_service.py:48-56`). Resolved policy = refuse naming the manual A↔B path (§6.2 D-3); negative TC pins it (TC-038.4).
- **QR-8 — engine-frozen guard:** US-032/033 fixes must land at `validation_service.py` / `app.py` only; any diff in `tui/a2l.py`, `validation/` (frozen set) trips `tests/test_engine_unchanged.py`. `validation/` IS frozen: **the new issue code must therefore be emitted from the TUI-side supplemental rule** (per requirements §2.6 seam note), NOT by editing `rules.py`. TC placement follows.

## 6. QA evidence checklist (Phase-1 state)

- [✓] Acceptance criteria use Given/When/Then equivalents — each AT states fixture (Given) / drive (When) / exact observables (Then), §1.
- [✓] Test cases have explicit Expected, not vague "works" — byte values, code strings, style anchors named per AT/TC (§1, §2).
- [✓] Edge cases include empty, boundary, invalid, error — virtual-exempt, dedup-suffix, decline-path, missing-original, case-fold, collision `-NN` (§1 boundary/negative rows).
- [✓] Regression checklist exists — issue-code pinning (`test_validation_a2l.py:18-19`), `REPORT_FILENAME_REGEX` untouched (`test_diff_report_service.py:224`), engine-frozen guard (QR-8), `_parse_loaded_file` call-site AST guard (`test_tui_variants.py:172`), row-severity unit set (`test_tui_app.py:50-54`).
- [✓] Exit criteria stated — all three GATE ATs pass on the post-fix tree AND their counterfactuals demonstrably failed on the pre-fix tree (captured evidence); full `pytest -q` green; 0 frozen-set diffs.
- [✓] No real PII / secrets — synthetic RPM/TORQUE fixtures, public example data only (F-S-07 continuation).
- [✓] Test results section left blank — nothing executed in Phase 1; no fabricated results.
- [✓] Layer B black-box — every output-producing story gated through the shipped surface: Pilot-rendered tables (US-032/033) and handler-written file on disk (US-034, C-12); counterfactual + boundary + negative per AT.
- [✓] Bidirectional surface-reachability — inputs (A2L file, patch entries, save-back prompt) exercised through the handler; outputs (A2L rows, Issues screen, report file) observed through the shipped surface, not the service API alone.
- [✗→Phase-2] No unfilled template — ONE deliberate placeholder remains and is named: TC↔LLR numbering (binds to §4 at Phase 2). The US-034 trigger action id (QR-2) resolved at the Phase-1 fold (`action_before_after_report`); nothing else is templated.

## 7. Test-results section (blank — to be filled at Phase 3/4 by execution)

| AT/TC | Run | Result | Evidence |
|---|---|---|---|
| AT-036a (pre-fix counterfactual) | | | |
| AT-036a (post-fix) | | | |
| AT-037a (pre-fix counterfactual) | | | |
| AT-037a (post-fix) | | | |
| AT-038a | | | |
| AT-038b/c/d (refusal GUARDs) | | | |
| Layer A suite | | | |

# Increment 001 — HLR-001…011 · `Editors split + Patch Editor rework + .chk.json`

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development
> language — the **prose**, and never a label. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`. The normative RULES below are
> language-independent.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/increment-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `SOURCE files` · `Instrument RED-proof` · `Correction population` · `Mutation verdicts` · `Emitted-form assertion` · `Reverse census` · `RED counterfactual` · `Independent review` · `Evidence files` · `Traces to` · `File` · `Kind` · `source` · `test` · `doc` · `config` · `generated` · `fixture` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Where this lives:** the **repo**, next to the diff it describes —
> `.dev-flow/2026-10-12-batch-94/03-increments/increment-001.md`. It is not synced to the vault.

> **Notice convention.** `⚠` yellow = notice: does not block, obliges you to DECLARE the reason here.
> `✗` red = block. `✓` green = satisfied **with its evidence cited**. A notice repeated for three
> consecutive batches becomes a rule or is retired.

> **A table you may delete.** A table whose `| **Field** |` row reads `none — <reason>`, or whose question one line of the gate checklist answers, may be deleted, its field row kept: `stations/core-runbook.md` §*A minimal increment packet* is a one-function change written that way.

| Field | Value |
|---|---|
| Batch | `2026-10-12-batch-94` |
| Increment | `001` |
| Lane (if the batch forked) | `none — single-lane trunk batch` · `n/a` (§2.8 fork preconditions, the declared empty; one worktree, one lane) |
| Requirement(s) | `US-001 · US-002 · US-003 · HLR-001…011` · `LLR-001.1…011.2` (the realized Inc-001 subset) |
| Acceptance | `AT-B94-01` · `AT-B94-03` through `AT-B94-13` (12 black-box) · `TC-B94-01…03` · `TC-B94-06…17` (14 white-box) · unit layer-0: none minted standalone — the six layer-0 candidates host inside the named TCs (`design-proposal.md` §5) |
| Agent | `software-dev` |
| Date | `2026-10-13` |

---

## 1 · What changed

*(BLUF: state the outcome first, then the mechanism. Name the shipped surface the user reaches.)*

**BLUF.** The rail grew 10→11 with a new `Check Editor` entry bound to `=` (probe-verified at the
PDR, `evidence/pdr_rail_key_probe.txt`); selecting it mounts the NEW `CheckEditorPanel` (the ce_a
collector), selecting `6` still mounts the reworked Patch Editor. The user-facing surface of
Inc-001: two distinct build editors, a `.chk.json` check-spec file type that round-trips through
the shipped v2 writer/reader and feeds the A2B Diff report through a new dropdown + `## Checks`
addendum, and a Patch Editor reworked per the operator's six annotations. Realized stories:
**US-001, US-002, US-003 → HLR-001…011.** 24 test nodes minted (one AT = one on-disk node per
C-18): AT-B94-01, AT-B94-03…13 and TC-B94-01…03, TC-B94-06…17.

**What landed, annotation by annotation (US-002's six annotations, all realized):**

1. **Expanded JSON text-editing space** — the `JsonHighlightTextArea` editor is the panel's
   primary edit surface (pe_b doctrine: entries table top-anchored, editor beneath), not the old
   capped `patch_win_json` side pane (HLR-003, AT-B94-03 / TC-B94-09).
2. **Edit-JSON + validate merges into the entries table** — valid text merges 100% of declared
   entries in document order; invalid text surfaces the collected issues and leaves the table
   byte-identical (HLR-004, AT-B94-04/05 / TC-B94-01).
3. **Dirty guard on Load** — `LoadGuardScreen` popup (NEW modal, `screens.py` idiom) with
   accept-loss / cancel branches; dirty flag writers exactly w1–w4 (table-edit→set, text-edit→set,
   save→clear, load-success→clear, the R-3 census) (HLR-005, AT-B94-06/07 / TC-B94-10).
4. **Variant selector removed** — `patch_variant_select`, `VariantSelected`,
   `VariantHelpRequested` and the app-side routing retired; single-document editing; a stale
   `VariantSelected`-shaped post is a no-op (HLR-006, AT-B94-08 / TC-B94-11; **0 live variant
   symbols** in the editor surfaces).
5. **Apply applies the loaded changes** — the Apply control is presented as "Apply loaded changes"
   and applies exactly the loaded document's entries through the existing gate (HLR-007,
   AT-B94-09 / TC-B94-02/12).
6. **Load / Refresh file semantics** — Load reads the adjacent path input; Refresh repopulates the
   dropdown from the folder scan and never mutates the loaded document (HLR-008, AT-B94-10 /
   TC-B94-03; the realized Refresh **supersedes** the legacy refresh-load conflation — the C-65
   sweep is recorded in §6).

**Plus the check-spec chain (US-003):** the Check Editor assembles a `kind="check"` v2 document
over the existing machinery (`write_change_document` / `parse_change_document` /
`run_check_document`) and writes it under a `.chk.json` name whose double suffix survives
`_safe_name`; `CHECK_SPEC_SUFFIX` / `is_check_spec_name` / `list_change_documents` make the suffix
a first-class listing predicate; the A2B Diff `AbDiffPanel` dropdown lists check specs
distinguished from patch files; loading one adds the declared parameters/locations to the report
through the NEW `_check_addendum_lines` producer (`## Checks` addendum, C-42 emitted form pinned
by TC-B94-16). **The ce_a no-apply doctrine:** the struck-APPLY ghost is an inert `Static` —
**0 actionable apply controls** per the C-ux-2 pin (`editor_bench.NOTES.md:70-72`); the apply
gate over a check spec is the executed negative control (`blocked: 2`, `mem_map` untouched,
`evidence/p1_probe_chk_roundtrip.txt`). C-12 chain: AT-B94-11's writer → the written file →
AT-B94-12's dropdown reader → the report producer (HLR-009/010/011, AT-B94-11/12/13,
TC-B94-06/07/13/14/15/16/17).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

One row per file. `Kind` is one of `source` · `test` · `doc` · `config` · `generated` · `fixture`; `Traces to` names the US/HLR/LLR (or `R-<AREA>-<NNN>`) ids the file serves, and `doc` rows leave it empty.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/screens_directionb.py` | source | HLR-001 · HLR-003…009 · HLR-011 · LLR-001.1/001.2 · LLR-003.1 · LLR-004.1/004.2 · LLR-005.1/005.2 · LLR-006.1/006.2 · LLR-007.1/007.2 | `PatchEditorPanel` pe_b rework (expanded editor, dirty flag w1–w4, LoadGuard accept/cancel, variant retirement, apply-loaded-changes) + NEW `CheckEditorPanel` (ce_a collector, struck-APPLY ghost, write/validate) + NEW `LoadGuardScreen` modal + `AbDiffPanel` check-spec dropdown |
| `s19_app/tui/changes/io.py` | source | HLR-009 · HLR-010 · LLR-009.1 | `CHECK_SPEC_SUFFIX` / `is_check_spec_name` / `list_change_documents` — the `.chk.json` suffix predicate and suffix-distinguished folder listing; `_safe_name` preserves the double suffix (TC-B94-13) |
| `s19_app/tui/services/diff_report_service.py` | source | HLR-010 · LLR-010.2 | `_check_addendum_lines` — the `## Checks` report addendum (producer-side `md_safe` scrub; empty arm renders the header + `No declared fields.`, never an error) |
| `s19_app/tui/app.py` | source | HLR-001 · HLR-002 · HLR-005 · HLR-008 · HLR-010 · LLR-001.2 · LLR-002.1/002.2 · LLR-005.2 · LLR-008.1/008.2 | rail tuple 10→11 with the `=` `Binding` (show=False) + `check_editor` routing; dirty-load guard handler posting `LoadGuardScreen`; Refresh repopulate semantics (folder scan → dropdown, loaded document untouched); check-spec folder scan for the dropdowns |
| `tests/test_tui_check_editor.py` | test | HLR-001 · HLR-009 · HLR-011 · LLR-001.1/001.2 · LLR-009.3 · LLR-011.1/011.2 | NEW — AT-B94-01, AT-B94-11, AT-B94-13, TC-B94-06, TC-B94-07, TC-B94-17 |
| `tests/test_tui_patch_editor_b94.py` | test | HLR-003…008 · LLR-003.1 · LLR-004.1/004.2 · LLR-005.1 · LLR-006.1/006.2 · LLR-007.1/007.2 · LLR-008.1/008.2 | NEW — AT-B94-03…10, TC-B94-01…03, TC-B94-09…12 |
| `tests/test_tui_check_chain_b94.py` | test | HLR-009 · HLR-010 · LLR-009.1 · LLR-010.1/010.2 | NEW — AT-B94-12, TC-B94-13…16 (the C-12 writer→reader→report chain) |
| `tests/test_tui_patch_variant.py` | test | HLR-006 · LLR-006.1 | rewritten — 25 retired-id hits re-asserted to observe the retirement (R-6 rewrite group) |
| `tests/test_tui_patch_big.py` | test | HLR-006 · HLR-011 · LLR-006.1 · LLR-011.1 | rewritten — 7 hits incl. the C-17 hostile test over the removed widget |
| `tests/test_tui_patch_layout.py` | test | HLR-003 · HLR-006 · LLR-003.1 · LLR-006.1 | rewritten — 4 hits |
| `tests/test_tui_patch_chips.py` | test | HLR-006 · LLR-006.1 | rewritten — 1 hit |
| `tests/test_tui_patch_card.py` | test | HLR-006 · LLR-006.1 | rewritten — 1 hit |
| `tests/test_tui_patch_editor_v2.py` | test | HLR-006 · LLR-006.1 | rewritten — the `#patch_variant_select` widget census re-derived (1 hit) |
| `tests/test_tui_snapshot.py` | test | HLR-006 · LLR-006.1 | rewritten — docstring/census hit; 3 passed + 29 xfailed (predicted=observed per-cell) |
| `tests/test_tui_commandbar.py` | test | HLR-006 · LLR-006.1 | rewritten — the :2151 docstring census |
| `tests/test_tui_variants.py` | test | HLR-006 · LLR-006.1 | census reconciliation only — 3 tests re-derived to observe the retirement; the app-level project-variant machinery it guards is NOT retired (kept pair, R-6) |
| `tests/test_tui_directionb.py` | test | HLR-001 · HLR-002 · LLR-002.1/002.2 | guard-host census constants moved with the landing increment (10→11, LLR-002.2) + `test_tc_042_10` from_markup scan extended to `screens_directionb.py` (C-17, architect finding 3) |
| `tests/test_id_registry.py` | test | HLR-002 | corpus census `EXPECTED_SCANNED_TEST_FILES` 170→173, measured (this increment's 3 new files + the RC-1 union) |

| Count | Value |
|---|---|
| **SOURCE files** | **`4` / 4** |
| Test files | `14` (uncapped) — 3 new · 8 rewritten (R-6 group) · 2 census-constant moves · 1 census reconciliation |
| Doc files | `0` (outside the count) |

- ⚠ **At exactly 4 source files:** the increment's deliverables are contract-bound to four different
  modules — the panels' R9 home (`screens_directionb.py`), the v2 grammar's io home (R10), the
  report producer the addendum must emit from (LLR-010.2 names `generate_diff_report`), and the
  sole legal rail/routing/scan site (`app.py`). The rail tuple and the `=` binding are composed in
  `app.py`, and the panel geometry lives inline in `screens_directionb.py` — **no 5th SOURCE file
  existed to cut**; the `LoadGuardScreen` modal is private to the panel that posts it, composed
  inside `screens_directionb.py` per the `screens.py` modal idiom rather than adding a file.
- ✗ If a file belongs to another lane's file set, stop: lanes may not share a file. — n/a, one lane.

---

## 3 · How to test

```bash
# the 24 minted batch-94 nodes (ONE complete run per file set)
python -m pytest tests/test_tui_check_editor.py tests/test_tui_patch_editor_b94.py tests/test_tui_check_chain_b94.py -q
# the guard host (rail census 11, from_markup extension, 184 passed at gate)
python -m pytest tests/test_tui_directionb.py -q
# the R-6 rewrite group + reconciliation
python -m pytest tests/test_tui_patch_variant.py tests/test_tui_patch_big.py tests/test_tui_patch_layout.py tests/test_tui_patch_chips.py tests/test_tui_patch_card.py tests/test_tui_patch_editor_v2.py tests/test_tui_snapshot.py tests/test_tui_commandbar.py tests/test_tui_variants.py -q
# the corpus census
python -m pytest tests/test_id_registry.py -q
# the 23-arm mutation battery (full) and the fold-round re-verification
python -B .dev-flow/2026-10-12-batch-94/evidence/inc001_battery.py
python -B .dev-flow/2026-10-12-batch-94/evidence/inc001_battery.py 05,06
# the F1 popup stack-drain probe
python .dev-flow/2026-10-12-batch-94/evidence/inc001_fold_popup_probe.py
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** (cyclomatic ≥3, or crosses a declared module boundary) | `core` · `full` | none minted standalone — the six layer-0 candidates (validate-merge handler, dirty-flag writer set, `_safe_name` suffix, folder-scan branch, check-spec assembly, stale-message no-op) host inside TC-B94-01/09/10/11/13/15 per `design-proposal.md` §5 | hosted arms all green (see layer A) |
| **A · white-box** `TC-B94-01…03,06…17` ↔ LLR | `core` · `full` | 14 ids (15 node instances — TC-B94-09 parametrized ×2) | 14/14 ids green in the battery baseline (ONE run, 27 node-runs incl. the ATs, tail read: `27 passed`) |
| **B · black-box** `AT-B94-01,03…13` ↔ story, through the shipped surface | `core` · `full` | 12 ids (one AT = one node, C-18) | 12/12 green — battery baseline + the fold-round strengthened assertions (arms 05/06) |

**Evidence digest — the increment's verification runs** (counts as returned by the implementer's
session; the stored transcripts cited in *Evidence files* below are the battery and probe
artifacts):

- `tests/test_tui_directionb.py` — **184 passed** (the guard host at the 11-entry census; includes
  `tc031` after the rebase, run (a) below).
- editors + variants set — **51 → 52 passed** (51 at fix-round close; 52 after the fold round added
  the strengthened AT-B94-06/07 stack-drain and ux#3 assertions).
- patch family suite — **74 passed**; commandbar + registry — **58 passed**; snapshot file —
  **3 passed + 29 xfailed, predicted=observed per-cell**.
- batch-95 trio on the union tree — **65 passed** (the RC-1 mid-session rebase unioned both lanes'
  additions; the corpus census reconciles at 173).
- open_folder chips file — **45 green**.
- **The frozen dual-guard at the increment cut:** TEST-file guard **PASS**; SOURCE guard vs the
  increment's cut base **CLEAN — executed empty diff** (no source file outside the increment's four
  was touched). Note: `main`'s batch-95 `a2l.py` landed mid-session; the guard arms go green on the
  rebased union tree — run (a) proved **184 passed incl. tc031** on it.

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | the strongest kill per family, each by position and operation: **routing** — the `=` binding's `show_screen` target repointed to the patch screen (arm 01 → AT-B94-01 RED); **geometry** — the reworked entries table's height collapsed so the editor leaves the viewport (arm 02 → AT-B94-03, TC-B94-09 RED); **guard** — the dirty-load guard's `if self._dirty:` branch disabled (arm 05 → AT-B94-06 RED) and the cancel branch flipped to dismiss-with-loss (arm 06 → AT-B94-07 RED); **retirement** — a variant-reacting handler inserted into the reworked panel (arm 17 v2 → TC-B94-11 RED); **report addendum** — the `## Checks` heading spelling drifted (arm 22 → TC-B94-16 RED); **primitive** — the `safe_text` scrub table dropped ESC from the C0 range (arm 23 → TC-B94-17 RED) |
| Instrument | project code: own hand through the battery runner — `python -B .dev-flow/2026-10-12-batch-94/evidence/inc001_battery.py` (a script in the project's stack; field guide §`Mutation verdicts`) |
| Where it ran | **this tree** (`C:/Users/jjgh8/Github/s19_app-b94`), run by the orchestrator's increment session at Phase 3 — the same session that wrote the code; no other lane's tree |
| Transcript | `.dev-flow/2026-10-12-batch-94/evidence/inc001_battery.txt` (full battery + fix-round banners) and `inc001_battery_fold_round.txt` (fold-round arms 05/06) |
| Restore proven by | **file hash returned to its pre-mutation value** — every arm prints `after: <sha256> restore-ok=True` and the verdict table prints `restore-hash OK` (e.g. `app.py` restored to `6db01493…`, `screens_directionb.py` to `9b8f5ada…`, `diff_report_service.py` to `8bf29221…`); `git status` was not accepted as proof |
| Bytecode cache | cleared — the runner invokes `python -B` (C-46) |
| Arms resolved at baseline | 28 b94 nodes resolved via `pytest --collect-only` across the 3 new files; **27 node-runs** planned and run in ONE baseline run — the count asserted up front, TC-B94-09's two size params counted as two node-runs |
| Verdict granularity | **per resolved node id** — the transcript's `VERDICT TABLE` prints one row per arm→node with its own verdict; the process exit code is never the verdict |
| Arms that stayed GREEN | **none finally.** First pass: 5 SURVIVED node-runs (arms 01/02's routing-blind and geometry-blind censuses, 08, 15) + arm 17 CRASH/BAD — all re-asserted/re-declared in FIX ROUND A and killed; fold round: arms 05/06 re-verified RED against the strengthened tests. Final ledger: 23/23 arms RED |

| Field | Value |
|---|---|
| **RED counterfactual** | the mutations above — each by position and operation, one per family — made THIS increment's own new assertions fail on their resolved nodes (AT-B94-01/03/06/07, TC-B94-11/16/17 named as the family kills; all 23 arms in the verdict table) · transcript: `evidence/inc001_battery.txt` (+ `inc001_battery_fold_round.txt`), runner `python -B evidence/inc001_battery.py` · restore digests returned each file to its pre-mutation bytes (`restore-ok=True` per arm; `app.py` `6db01493…`, `screens_directionb.py` `9b8f5ada…`, `io.py` `81a12157…`, `diff_report_service.py` `8bf29221…`, `utils.py` `28b8096d…`, `apply.py` `09a447ab…`, `check.py` `3cd29ed5…`, `change_service.py` `90fb3678…`) |

| Field | Value |
|---|---|
| **Mutation verdicts** | 23 arms, finally **23/23 RED, 0 SURVIVED open, 0 CRASH open** — per resolved node, by position and operation (C-56: no corrupted tokens spelled here; the transcript holds the literals): arm 01 `app.py` `=` binding target flip → AT-B94-01 RED, TC-B94-07 (first pass SURVIVED — routing-blind census; FIX ROUND A re-asserted it to the rail-target observation → RED); arm 02 `screens_directionb.py` entries-table height collapse → AT-B94-03 RED, TC-B94-09[size0/1] (first pass SURVIVED — geometry-blind; re-asserted → RED); arms 03/04 `app.py` validate-merge drop / invalid-merge arm → AT-B94-04/05 RED; arm 05 dirty-guard branch disabled → AT-B94-06 RED; arm 06 cancel flips to loss → AT-B94-07 RED; arm 07 variant controls left composed → AT-B94-08 RED; arm 08 `apply.py` skip counted as applied → AT-B94-09 (first pass SURVIVED — zero skips produced; re-declared over the loaded-doc/no-image arm → RED); arm 09 empty-path guard drop → AT-B94-10 RED; arm 10 an actionable apply control added to the ce composition → AT-B94-11 + TC-B94-06 RED; arm 11 the diff-check wiring dropped → AT-B94-12 RED; arm 12 hostile render via markup construction → AT-B94-13 RED; arm 13 validate-merge row drop → TC-B94-01 RED; arm 14 the `kind != "change"` gate bypassed → TC-B94-02 RED; arm 15 Refresh re-loads the document → TC-B94-03 (first pass SURVIVED — prefill idiom shared the call; re-declared → RED); arm 16 the load-success dirty-clear dropped → TC-B94-10 RED; arm 17 a variant-reacting handler inserted → TC-B94-11 RED (v1 inserted `on_message`: **SURVIVED, recorded as data** — Textual dispatches to `on_<snake-name>`, never `on_message`; the authoring-time anchor had also been retired with HLR-006 and came back CRASH/BAD — anchor count 0 — the original assertion was inert per C-40; v2 inserted the retired shape's real handler → RED); arm 18 the legacy bare-Apply label survives → TC-B94-12 RED; arm 19 `_safe_name` suffix reduction → TC-B94-13 RED; arm 20 the check runner skips verdict rows → TC-B94-14 RED; arm 21 the folder scan drops `*.chk.json` → TC-B94-15 RED; arm 22 the addendum heading drifts from its pinned spelling → TC-B94-16 RED; arm 23 the scrub table drops ESC → TC-B94-17 RED. Restore discipline: every arm hash-proven (`restore-hash OK`). Transcripts: `evidence/inc001_battery.txt` (23 arms + FIX ROUND A banners + arm-17 v1/v2 + the 3-arm spot-check + final suite tail) and `evidence/inc001_battery_fold_round.txt` (arms 05/06 re-verified RED after the F1 fold) |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| the b94 suite itself (the 24 minted nodes) | the five first-pass inert arms — assertions blind to their real subjects (routing-blind census, geometry-blind census, a mutation producing zero observable skips, a shared prefill call) | they stayed GREEN under exactly the mutations they claimed to certify — the suite reported its own blindness (C-40); after the FIX ROUND A re-assertions every one of them reported RED in `inc001_battery.txt` |
| the battery runner | arm 17 v1's non-applying anchor (the authoring-time anchor had been retired with HLR-006) | `CRASH/BAD (anchor count 0, expected 1)` — the runner reported that nothing was measured, not a pass; the arm was re-declared to the realized subject |
| the fold popup probe | the pre-fold build's duplicate `push_screen(LoadGuardScreen(), …)` (two stacked modals — the F1 defect) | the probe observes the screen stack: two stacked `LoadGuardScreen` instances before answer / a survivor left after it; post-fold it prints `PROBE: PASS — exactly one popup, stack drains empty (both arms)` (`inc001_fold_popup_probe.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | `3` instruments — the minted-node suite (blindness exposed by the 5 inert arms, then RED-proven after the fix), the battery runner (BAD-anchor reporting, arm 17 v1), the popup probe (pre-fold duplicate-push FAIL state, post-fold PASS) — each shown able to report FAILURE before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the A2B diff report's `## Checks` addendum (`_check_addendum_lines` → `generate_diff_report`) | TC-B94-16 runs the shipped producer over the public fixtures and pins the Phase-3 paste, fixed parts: `## Checks` / `- Check spec: \`baseline.chk.json\`` / `- Declared fields: 2 (0 byte changes — image never modified)` / `\| # \| Field \| Address \| Expected \|` + the `|---|---|---|---|` rule; 100% of the declared names present in the emitted table | GREEN at baseline; arm 22 (heading spelling drift) → `AssertionError: assert '## Check specs' == '## Checks'` — RED (KILLED), restore-hash OK (`inc001_battery.txt`); the empty arm emits the header + `No declared fields.`, never an error |
| the v2 check-spec document (the C-12 producer arm, AT-B94-11 → AT-B94-12) | `write_change_document` emits the spec **written by the panel's own writer**; `parse_change_document` re-reads it; the emitted bytes begin `"format": "s19app-changeset"`, `"version": "2.0"`, `"kind": "check"` (the 315-byte form pasted in `p1_probe_chk_roundtrip.txt`) | re-read `kind == "check"`, 2 entries, 0 blocking errors; `run_check_document` one verdict per entry (`pass` / `uncheckable` with reason `outside`); `apply_change_document` over it → `counts = {'applied': 0, …, 'blocked': 2}`, `mem_map untouched: True` — `PROBE OK` |
| the diff report base form (lineage of the addendum paste) | `p1_probe_diff_report_emitted.py` runs `generate_diff_report` and pastes the first 30 emitted lines verbatim (`- Image A: prg [external] path=… parse-errors=0`, `- Image B: sample [external] …`) | 442-line report written; the provenance-addressable lines printed verbatim; `PROBE OK` (`p1_probe_diff_report_emitted.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | `3` artifacts — the `## Checks` addendum (TC-B94-16, pinned spelling + name/address/expected columns), the `.chk.json` v2 document (the writer→reader→report C-12 chain for AT-B94-11/12), the diff report base form (`p1_probe_diff_report_emitted.txt` lineage) — each asserted against the bytes its producer emitted |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| battery runner (23 arms, fix/fold rounds, hash restores) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_battery.py` | `9cd9e467ee1ca7f5472f1c0c65399530881771b21b59197c88ace975395b687b` |
| main battery transcript — 23 arms, FIX ROUND A banners, arm-17 v1/v2, spot-check, final suite tail | `.dev-flow/2026-10-12-batch-94/evidence/inc001_battery.txt` | `64336b10c0514cae798afb260d6ba3048c51f2e9eea1b9f58baea411580c745a` |
| fold-round re-verification of arms 05/06 | `.dev-flow/2026-10-12-batch-94/evidence/inc001_battery_fold_round.txt` | `045adce63c6e9b5c282d1d01d83cf084009ea96305752c5b8478e1b7f98cf908` |
| F1 popup probe runner (stack-drain, both arms) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_fold_popup_probe.py` | `0d7e888fc767f50eaf6d9c585dfa472b2a033fbf8c9f4eac66d418a61205191b` |
| F1 popup probe output — `PROBE: PASS — exactly one popup, stack drains empty (both arms)` | `.dev-flow/2026-10-12-batch-94/evidence/inc001_fold_popup_probe.txt` | `f1b7eb8bd0d8551bf97e8f6e6ea312a818ed9484e8e89bbca46f5798cd6ffb72` |
| v2 check-spec round-trip probe (writer/reader/runner + apply-gate negative control) | `.dev-flow/2026-10-12-batch-94/evidence/p1_probe_chk_roundtrip.py` | `fbc349f3198f975f8e0176c83fee6a984f7f620c86b50d3574500cfd7e8292e6` |
| round-trip probe output (315-byte emitted form; `blocked: 2`; `PROBE OK`) | `.dev-flow/2026-10-12-batch-94/evidence/p1_probe_chk_roundtrip.txt` | `03332561f3320536bbcc6b7bea4e597d7c846a52e427c9d0007cae4b49eb02ee` |
| diff-report emitted-form probe runner | `.dev-flow/2026-10-12-batch-94/evidence/p1_probe_diff_report_emitted.py` | `af1febb9213d769ae558bdd1b2411aa2d54ae14230567451957629207263695f` |
| diff-report base form paste (30 header lines verbatim) | `.dev-flow/2026-10-12-batch-94/evidence/p1_probe_diff_report_emitted.txt` | `581cdb77e7b5a174e3fa424e1cea4025e313e5e2b29d959b6eae93112afc28cb` |
| base rail census probe (10 entries, no Check Editor — the RED side of AT-B94-01) | `.dev-flow/2026-10-12-batch-94/evidence/p1_probe_rail_census.py` / `.txt` | `547af7813f72404401f66e524ed801418f4046dd10daf36f803c1c52c481a22a` / `ddd4e5d98499952433c17917c60204460514b7aef0ebc9c05d9079bbdd4d9c69` |
| R-1 rail-key probe (`=`/`]` runtime resolution, no collision) | `.dev-flow/2026-10-12-batch-94/evidence/pdr_rail_key_probe.py` / `.txt` | `b86143598b461c72469a28ad5e869d0aa7d8c5a71f4eb770f806ee777100a409` / `a721166a47215fbb06a6dacdbfb8c4a4146cb7ee8d4b73d9835c8b350ea83a03` |
| boxed workspace budgets (74×12 @80×24 · 96×18 @120×30 · 136×28 @160×40) | `.dev-flow/2026-10-12-batch-94/evidence/p1-pilot-measurements.txt` | `ce79223e18fb35628a1750e0bf1b746265472e771ac554a98be561ffbdbd0555` |
| suite transcript — the FULL guard host `test_tui_directionb.py`, one complete run (184 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_suite_directionb.txt` | `7ed768f4fe7e495a07684e5098a5e835316b548615061076811b8f723759934b` |
| suite transcript — editors + variants five-file run (52 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_suite_editors.txt` | `9435bb5997198e48b16f665d101d80d40dd278789a86251408270b74a8caae0f` |
| suite transcript — the patch-family rewrite group (74 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_suite_patch_family.txt` | `fb986e6a49b5e0cbca6f48225752b3f0e30502d73ffac556557331c56c8552b7` |
| suite transcript — commandbar + id-registry guards (58 passed) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_suite_commandbar_registry.txt` | `8016f1b24811f76a97d536372a837d72ed8a9ff9292d0102294f3c4f8dd5ae5f` |
| suite transcript — snapshot matrix (3 passed + 29 xfailed, per-cell census) | `.dev-flow/2026-10-12-batch-94/evidence/inc001_suite_snapshot.txt` | `2c4bb70e05eaf469332f1c2656167ff54c7267faa6d3a04c7c2d1f6f87c156ba` |

| Field | Value |
|---|---|
| **Evidence files** | `17` rows at `repo:.dev-flow/2026-10-12-batch-94/evidence/` (10 single-path artifacts + 2 probe pairs cited by their `.py`/`.txt` homes + 5 suite transcripts — 24 paths total), each cited with the SHA-256 of its stored bytes as listed above — digests re-derived from the bytes at those paths after the fold round. The §4 evidence-digest suite figures (184 / 52 / 74 / 58 / 3+29 / 65 / 45) are corroborated by the five stored per-run transcripts `inc001_suite_{directionb,editors,patch_family,commandbar_registry,snapshot}.txt` (one complete run each, tails read from their own output, counts exact); the stored, hash-cited proof of the increment's RED/restore discipline is the battery + probe set above (the 27-node battery baseline is itself ONE complete run with its tail in `inc001_battery.txt`) |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | `yes` — (1) 0 actionable apply controls in the Check Editor surface; (2) 0 live variant symbols/handlers in the editor surfaces; (3) 0 markup-parsed constructions of file-derived text in the touched render modules; (4) 0 writes when a check spec meets the apply path |
| If the result is an ABSENCE, what made the search wide enough | (1) the census queries **actionable controls** (buttons/inputs carrying an apply action) across the whole composed panel, not a marker list — the struck-APPLY ghost is a `Static`, outside the actionable set by construction (the C-ux-2 pin: "apply action" = actionable controls only); (2) the census greps the retired id family across product code AND the observer tests (R-6, 9 files); (3) `test_tc_042_10` scans the touched modules' sources for `from_markup` / `markup=True`; (4) the apply gate's `kind != "change"` branch is exercised, not read |
| Guard labelled as protecting a CONCLUSION, not a behaviour | TC-B94-06 (0-apply composition census — its docstring names the struck-APPLY ghost as inert by design); AT-B94-08 / TC-B94-11 (variant absence + stale-message no-op); AT-B94-13 / TC-B94-17 (hostile payload, 0 spans / 0 control bytes); the executed `p1_probe_chk_roundtrip` apply-gate probe |
| Conjunctive criteria: one mutation per conjunct | no conjunctive criterion — each absence above is a single conjunct with its own arm (arms 10, 07/17, 12/23, 14 respectively) |
| Synthetic instance of the absent case | (1)/(2): arm 17 v2 INSERTED the retired handler and arm 10 ADDED an actionable apply control — each synthetic instance tripped its census (TC-B94-11 / TC-B94-06 RED); (3): the batch-77 hostile payload is the synthetic markup-bearing instance (AT-B94-13); (4): a `kind="change"` document through the same gate is the synthetic writable instance — TC-B94-02's blocked arm |
| **Positive control for every probe that returned an ABSENCE** | the same unmodified probe on the known-present case: the ghost Static **renders** (visible struck "Apply" text, AT-B94-11's surface census passes with it present — presence and actionability are distinguished, not lumped); the app-level project-variant machinery is the known-present variant case and `test_tui_variants.py`/`test_variant_execution.py` still exercise it green (uniformity avoided: the editor census and the app-level census return different, expected answers); plain printable names render unchanged through `safe_text` (identity on printable text); a `kind="change"` doc applies and writes (the gate's positive arm) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rl PatchEditorPanel tests/ s19_app/` (guard host + patch family) | 19 files at the increment's run — every hit re-validated against the retirement: the R-6 group re-asserted (§2 table), the kept pair reconciled (`test_tui_variants.py` 3 tests re-derived to observe the retirement per the Inc-001 cut reconciliation; `test_variant_execution.py` byte-untouched — verified: no commit in `7972eda..5698947` touches it) |
| B2 file moved on disk | n/a — this increment moves no file (the `flow_screens.py` B2 move is Inc-002's) | no readers of a stale path; 0 moved files |
| B3 byte-identical golden captures this source | `grep -rl "flow_" tests/goldens/**/*.md` (the R-7 sweep; exit 1 recorded as superseded in the design) | the byte-identity goldens capture the flow-report producers — Inc-002/003's concern; 0 goldens capture this increment's four sources |
| B4 artifact produced here is consumed elsewhere | who reads the `.chk.json` artifact and the suffix listing: `app.py` (folder scan + dropdown) → `AbDiffPanel` (load) → `diff_report_service._check_addendum_lines` (report); `list_change_documents` also feeds the Patch Editor dropdown (patch + check files, suffix-distinguished labels) | the C-12 consumer chain enumerated; consumers in-batch, no outside-lane reader |
| A3 interface consumed by another module changed | the retired `VariantSelected`/`VariantHelpRequested` family: consumers outside the owning module = `app.py` routing — retired in the SAME commit (0 surviving live refs, supersession sweep below); the ce write/validate message family's consumers (`app.py` service handlers) enumerated at IFC Part B | no frozen interface changed inside a lane — the one contract amendment (the message family's freeze) is THIS trunk batch's own PDR freeze, authorized at `69d62cd` |
| did-NOT-fire probes (C-48) | `git diff <cut-base>..HEAD -- s19_app \| grep -c RECOGNIZED_A2L_BLOCKS` → **0** (the engine stays frozen — Inc-004's subject, D-1); same probe over `BLOCK_PATCH` → **0** (the flow machinery is Inc-002's subject) | named, with their probes: neither frozen surface was touched by this increment |
| supporting censuses | R-6 variant census: `grep -rln "patch_variant\|VariantSelected\|VariantHelpRequested" tests/` → 9 files, two groups — 7 rewritten / pair kept (above); R-4 B2 census (Inc-002's input, C-2-corrected membership): `grep -rl "FlowBuilderPanel\|screen_flow" tests/ s19_app/` → 11 files — `+s19_app/tui/screens_directionb.py` (the definition site) and `−tests/test_flow_crc_block.py` (block machinery, 0 hits), count 11 unchanged, re-verified at this cut; `from_markup` source census extended per C-17 to `screens_directionb.py` (`test_tc_042_10`); `safe_text` consumer census — 11 files over the touched render surfaces; `read/write/parse_change_document` observer sets enumerated (additive io surface — `CHECK_SPEC_SUFFIX`/`is_check_spec_name`/`list_change_documents` break no reader) | every hit re-validated; no hit left unowned |

| Field | Value |
|---|---|
| **Reverse census** | `8` probes run of B1 · B2 · B3 · B4 · A3 (+3 supporting censuses): B1 19 files (guard host + patch family, each re-validated) · B2 no move (0 readers) · B3 0 goldens over these sources · B4 the `.chk.json` consumer chain enumerated (app scan → dropdown → addendum) · A3 retired-message consumers retired in-commit, ce message family enumerated at IFC Part B — **the did-NOT-fire probes named per C-48: `RECOGNIZED_A2L_BLOCKS` 0 hits (engine, frozen) · `BLOCK_PATCH` 0 hits (flow machinery, untouched)** |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population — the assertion category | Enumeration method (the command) | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the variant machinery retires from the editor (HLR-006) | every observer of the retired id family across the suite | `grep -rln "patch_variant\|VariantSelected\|VariantHelpRequested" tests/` (R-6 census, run at PDR BEFORE the first edit) | 9 files | 8 (the rewrite group, §2) | the do-not-touch pair: `test_tui_variants.py` (app-level project-variant machinery is NOT retired — 3 tests re-derived, not deleted) and `test_variant_execution.py` (byte-untouched, group-kept by rule) |
| Apply presents as "Apply loaded changes" (HLR-007/LLR-007.2) | every apply-label/action site in the panel + the actions table | grep census over `screens_directionb.py` + `app.py` for the bare/legacy apply wording | panel + `PATCH_ACTIONS_V2` | all enumerated sites | none — 0 legacy bare labels survive (TC-B94-12 census; arm 18 RED on survival) |
| the rail census moves with the landing increment (LLR-002.2) | the guard-host census constants + `RAIL_ENTRIES` | `SCREEN_IDS`/`SCREEN_KEYS`/`EXPECTED_RAIL` read against the composed rail | 3 constants + 1 table | all, in the landing commit | none — a census updated early green-lights nothing; AT-B94-02 still mints at Inc-003 |

| Field | Value |
|---|---|
| **Correction population** | `3` corrections, each enumerated with its command before its first site was edited (R-6 grep census at PDR; the apply-label grep; the rail-census read) — the sites left are named with their reason above |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|-------------------|-------------|------------------------------|----------------------|
| `patch_variant_select` / `VariantSelected` / `VariantHelpRequested` | 0 live refs in `s19_app/` (hits only inside the retirement-observing tests and the stale-message no-op TC) | yes — surviving refs are absence assertions / the no-op arm | `screens_directionb.py` (panel compose, post-rework); `app.py` (routing retire); TC-B94-11 |
| `_refresh_patch_variant_select` / the variant re-sync chain | 0 refs (deleted with the selector; the load/refresh seam no longer chains it) | yes | `app.py` post-fold; `git show 7972eda --stat` |
| legacy bare-"Apply" wording | 0 labels survive; "Apply loaded changes" wording only | yes | TC-B94-12 census; arm 18 |
| the refresh-load conflation (Refresh reusing the load path) | 0 — Refresh repopulates the dropdown from the folder scan and sets status "Patch Editor: file list refreshed."; the loaded document is NOT re-read (C-65 sweep recorded) | yes | `app.py` `refresh_doc` branch; arm 15 re-declaration |

### Signed-balance test ledger

`post = base − deleted + added` → `173 = 170 − 0 + 3`  ✓ reconciles — the measured corpus census
(`tests/test_id_registry.py`: 170 → 173, the 3 NEW files; fold rounds add none). The 8 rewrites
post as in-place deletions/additions inside files already in the corpus; `test_variant_execution.py`
carries zero balance change (byte-untouched).

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean |

Review record:

- **First pass: BLOCK — BLOCK-UNTIL: F1.** F1 (HIGH): the dirty-load guard handler pushed
  `LoadGuardScreen` **twice** — a duplicate `push_screen` after the first answer callback (two
  stacked modals; the second survived the first's answer). Execution-proven by the popup probe;
  AT-B94-06/07 could not see it (they answered the top modal and passed).
- **Fold round:** F1 fixed in product code — the duplicate `_answer` closure + second
  `push_screen` deleted from `app.py` (13 lines, commit `5698947`); the fold re-froze the tree and
  the battery arms 05/06 re-verified RED (`inc001_battery_fold_round.txt`); the probe re-run prints
  `PROBE: PASS — exactly one popup, stack drains empty (both arms)`; **closing pass: clean.**
- **Majors discharged in place in the fold:** F2 (ux#3 — the dirty-indicator **render** assertion;
  the flag was only ever read internally) and F3 (ux#6 — the help-panel one-liner for the `=`
  binding).
- **Minors F4–F7 discharged:** F4 the containment-arm attribution note; F5 the count fix; F6 the
  tokens assertion; F7 the count wording — **F7's correction: 23 arms** (the battery's final
  ledger, not 22).

---

## 5 · Risks

*(What could break that this increment does not cover. Be specific enough to act on.)*

- **C-1 / C-2 — carried to Inc-002:** TC-B94-22's RED counterfactual must re-arm over the
  patch→CRC→write-out chain (C-1); the R-4 11-file census membership (C-2-corrected:
  `+screens_directionb.py` definition site, `−test_flow_crc_block.py`) re-runs at the Inc-002 cut
  (`V43`, `__pycache__` excluded). Both discharge at Inc-002's gate.
- **C-3 — carried to Inc-003:** AT-B94-02 pins the pilot sizes (12 entries ≤ 21 rows at 80×24).
- **Assumption register (design §5):** A2 (fb_a canvas inside 96×18) and A6 (template/provenance
  forms until the C-42 pastes) verify at Inc-002; A3 (fx_a two-lane layout) at Inc-003; **A4**
  (unmodified `=`/`]` delivery by the operator's real terminal — unmeasurable headlessly,
  `run_test` injects in-process) stays field-verification debt: every acceptance is authored
  key-independent per R-1, but the operator should confirm the two bindings hands-on. **A5**
  (no shared mutable service state across chains) verifies at Inc-003 (AT-B94-21's error arm).
- **Settle-robustness follow-up:** `test_tui_patch_editor_v2.py`'s settle timing is a latent
  flake source (see §6) — test-hygiene, recommended lane-A carry.
- **RC-1 — main moved again:** at this gate the batch tip is **behind `main` by 1** (main's
  batch-95 work landed mid-session); the increment itself is proven on the rebased union tree
  (184 passed incl. tc031, run (a)). The next RC-1 reconciliation **rides Inc-002's cut** — do not
  re-stamp between increments.

---

## 6 · Pending items / spec deviations

*(Anything surfaced and not closed here. Every line lands in the canonical backlog at batch close — if the increment surfaced it, the backlog owns it.)*

- **R-6 cut reconciliation:** `test_tui_variants.py` was re-derived at the cut (3 tests) to
  observe the retirement — the kept pair's reconciliation landed per file, not by silent
  reassignment (design §2 R-6).
- **Refresh supersession:** the realized Refresh repopulates the dropdown from the folder scan
  and never touches the loaded document — superseding the legacy refresh/load conflation; the C-65
  sweep is recorded (§4 supersession table).
- **LLR-004.2 confirm guard:** the realized Edit-JSON confirm path adds an explicit confirm guard
  at the merge boundary (invalid text surfaces the collected issues and leaves the table
  byte-identical) — a tightening beyond the contract's letter, recorded.
- **US-065 title pin re-point:** an older acceptance pinned a window title the rework changed;
  the pin was re-pointed to the new title (test-side, recorded).
- **Review defect fixes A/B/C:** the review rounds' discharged findings — round A: the five inert
  battery arms re-asserted to their real subjects (C-40, test-only, product frozen);
  round B: the fold-round majors F2/F3 + minors F4–F7 discharged in place; round C: the closing
  pass clean. Folded in `494bfe9` / `5698947`.
- **Latent chip-class note (C-30-scoped):** a latent chip CSS-class defect was noted during the
  fold; scoped under C-30, NOT fixed in this increment — carried to the backlog.
- **editor_v2 settle-robustness follow-up (owner: lane A — recommended):** the v2 editor suite's
  settle timing is a test-hygiene flake risk; it does not gate this increment's evidence (the
  suite was green at every run) but should be hardened outside the batch's scope. Recommendation:
  **lane A carries it** (test-hygiene, not a batch-94 requirement).

---

## 7 · Suggested next task

**Increment 002 — Flow Builder fb_a + templates** (US-005; HLR-013…016; AT-B94-15…18;
TC-B94-04,20…25): the `FlowBuilderPanel` fb_a rework at its new `flow_screens.py` address (the B2
move — the R-4 census above is its input), the A2B diff block with flow-output-or-file bindings,
template save/reload — discharging C-1 (TC-B94-22 re-arm) and C-2 (R-4 re-run) at its gate. The
next RC-1 reconciliation rides this increment's cut (§5).

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4 — §2; the ⚠ at-cap reason declared (rail tuple composed in `app.py` + inline geometry in `screens_directionb.py`; no 5th file existed) |
| 2 | Tests written in this same increment | all | ✓ | 3 NEW files mint the 24 nodes with the product change (§2; commit `7972eda`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` ‹one complete run owned by the orchestrator ~ Layer 0› | ✓ | no standalone layer-0 nodes — the six candidates host inside TC-B94-01/09/10/11/13/15 (design §5); one complete run owned by the orchestrator = the battery baseline, ONE run, `27 passed`, tail read from `inc001_battery.txt` |
| 4 | **RED counterfactual** declared — the mutation that made this increment's OWN new assertion fail, where its transcript is stored, and the restore digest, or `none` (C-20/C-40; read by `V44`) | `core` · `full` ‹RED counterfactual mandatory ~ RED counterfactual› | ✓ | §4 field — six family kills named (arms 01/02/05+06/17v2/22/23); transcript `evidence/inc001_battery.txt`; runner `python -B evidence/inc001_battery.py`; restores hash-proven per arm |
| 5 | **Reverse census** declared — the five probes run with their commands and verdicts, the ones that did NOT fire named with their probe, or `none` (C-26/C-48; read by `V43`) | `core` · `full` ‹reverse census of the touched symbol ~ Reverse census› | ✓ | §4 field — 8 probes (B1 19 files · B2 no move · B3 0 goldens · B4 chain enumerated · A3 retired in-commit) + R-6 9-file / R-4 11-file censuses; did-NOT-fire named: `RECOGNIZED_A2L_BLOCKS` 0 · `BLOCK_PATCH` 0 |
| 6 | `code-reviewer` passed — a HIGH blocks; the verdict, the reviewer and each HIGH's resolution are declared in **§4b** (`ABSENT` is the empty state there, not a value) | `core` · `full` ‹RED counterfactual mandatory ~ code-reviewer› | ✓ | §4b — first pass BLOCK-UNTIL F1 (duplicate `push_screen`, HIGH, probe-proven) → fixed, re-frozen, arms 05/06 re-verified RED, closing pass clean |
| 7 | No file from another lane touched | all | ✓ | single-lane trunk batch (§2.8 declared empty); SOURCE guard vs the cut base executed CLEAN (empty diff) |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `RECOGNIZED_A2L_BLOCKS` 0 hits · `BLOCK_PATCH` 0 hits in the increment diff; the message-family freeze is this batch's own PDR act (`69d62cd`), not a lane edit |
| 9 | Coverage claims verified **on disk**, not from intent | all | ✓ | counts read from the stored transcripts' tails (`27 passed` battery baseline; probe outputs); digests re-derived from the bytes at the evidence home (§4 Evidence files) |
| 10 | Load-bearing emptiness declared, with its synthetic instance (C-55) | all | ✓ | §4 — 4 absences, each with its guard + synthetic instance (arms 17v2/10 inserted-instance controls; the batch-77 payload; the `kind="change"` positive arm) |
| 11 | **Mutation verdicts** declared — **per arm**, inert arms named, registry ids cited, or `none` (C-40 rider; read by `V37`) | all | ✓ | §4 field — 23 arms per resolved node, finally 23/23 RED; the inert first-pass arms named (01/02 censuses, 08, 15, 17v1 SURVIVED recorded as data) with their discharges; transcripts cited |
| 12 | **Instrument RED-proof** declared — every instrument shown able to report a FAILURE before its first PASS was believed, or `none` (C-57) | all | ✓ | §4 field — 3 instruments (suite blindness exposed then RED-proven; runner's BAD-anchor report; popup probe pre-fold FAIL state) |
| 13 | **Correction population** declared — enumerated with its method before the first site was edited, or `none` (C-14) | all | ✓ | §4 field — 3 corrections, each with its enumeration command and its sites-left reasons |
| 14 | **Emitted-form assertion** declared — per artifact emitted, the assertion run against the EMITTED form and what it returned, or `none` (C-42; read by `V38`) | all | ✓ | §4 field — 3 artifacts (`## Checks` addendum pinned by TC-B94-16; the `.chk.json` C-12 chain; the base report form paste) |
| 15 | **Independent review** names somebody — in one of the forms §4b publishes; a cell naming nobody is empty (`V36`). §4b is the grammar's one home | all | ✓ | §4b cell — `code-reviewer — spawned as a generic agent with agents/code-reviewer.md · clean` |
| 16 | **Evidence files** declared — every cited artifact at the home `artifact_homes.evidence` names, cited with the digest of its STORED bytes, or `none` (C-59; read by `V41`) | all | ✓ | §4 field — 12 artifacts under `repo:.dev-flow/2026-10-12-batch-94/evidence/`, each with its SHA-256; the digest-transparency note on the suite-run figures is recorded in the field itself |

# PDR — qa-reviewer (tester's lens) — s19_app — Batch 2026-10-25-batch-99

**Mode:** `plan`. Every result named below is `planned`. Nothing was executed for this review. It is an `inspection` of the design proposal, the contract and the code at HEAD `b2c4464`.

| Field | Value |
|---|---|
| Reviews | `design/design-proposal-b99.md` §5 (proposed test cases) and §7 (forward applicability), checked against `01-requirements.md` §3–§5 as of LED-2026-10-25-batch-99.3 |
| Lens | `qa-reviewer`, PDR plan mode (`stations/p3-implementation.md` §PDR) |
| Not redone | the Phase-2 findings in `design/P2-qa.md` |
| **Verdict** | `approved with conditions` (PQ-1..PQ-8 below; each one can be discharged on its own, and each names its owning increment) |

**Why it is not `approved`:** the drivers exist and the oracle design is sound. But three proposed test cases can pass at HEAD, or under their declared mutant, unless a fixture or an assertion is pinned: TC-B99-31's pair arm, TC-B99-33's help arm, and the A2L corpus arms. In addition, the new group-placement function has no producing increment.

**Why it is not `rejected`:** every gap is a brief, fixture or assertion amendment inside an increment that already exists. None of them changes a design characteristic.

---

## 1 · Conditions

| # | Sev | Where | Finding | Discharge (what must be true when the artifact is re-read) | Owner |
|---|---|---|---|---|---|
| PQ-1 | major | A3-1 · PLAN roadmap Inc 3 / Inc 6 · proposal §2, §4 · `docs/ARCHITECTURE.md:573` | **`place_group_into_workarea` (B99-I2a) has no producing increment.** It is NEW in `tui/workspace.py`. Inc 6's SOURCE list is `segment_split_view.py` and `segment_ops.py`. Inc 3 owns `workspace.py`, but its scope does not name B99-I2a. ARCHITECTURE says Inc 6 "consumes" it. The proposal's §2 workspace row, which each Kimi brief quotes (§7), exposes only `copy_into_workarea` and the reserved tuple. The §4 rows B99-I2 and B99-I2a are malformed: the I2 consumer and frozen cells sit inside the I2a row. | PLAN names the increment that writes `place_group_into_workarea`. Either Inc 3 adds it, or Inc 6 adds `workspace.py` (3 SOURCE files, within budget). The §2 workspace row lists it under *exposes*, and §4 has one well-formed row each for I2 and I2a. | orchestrator, before the Inc-3 brief |
| PQ-2 | major | A3-1 · LLR-160.4 · TC-B99-31 | **The declared mutant "per-file `_<N>`" turns RED only with a half-pair already on disk.** With no `_1` file present, two independent claims both land on `_1`, so the mixed-pair threshold cannot fail. | TC-B99-31 carries three arms, each RED under its mutant:<br>(a) `<name>.bin` and `.addr` exist with different bytes, plus an orphan `<name>_1.addr`. Expected: `<name>_2.bin` + `<name>_2.addr`. The per-file mutant gives `_1.bin` + `_2.addr`.<br>(b) The BIN is identical but the `.addr` differs (another base). Expected: a new `_1` pair, never a reused `.bin` beside a `_1.addr`. Mutant: per-file reuse.<br>(c) A forced failure on the second `os.replace`. Expected: `WorkareaPlacementError`, both claims removed, 0 zero-byte files, first files intact. Mutant: skip claim removal.<br>All files are read by the independent reader. | the increment that writes the function (PQ-1); the tests land with it |
| PQ-3 | minor | LLR-155.7 · TC-B99-39 | **The delete-only-owned census misses the new writer.** The census names four writers. `place_group_into_workarea` also deletes claims and staging, and it is outside the census. | Either TC-B99-39's AST census includes `place_group_into_workarea` (a ledger line, because LLR-155.7 enumerates the writers), or the ledger records why it is excluded. | same increment as PQ-2, plus an orchestrator ledger line |
| PQ-4 | major | A3-2 · LLR-158.1..158.3 · `kimi/BRIEF-inc-1.md` §3 | **The corpus A2L is under-specified, so A2L test cases can pass at HEAD or vacuously.** The Inc-1 brief does not pin the COMPU_TAB contents or the byte-order declarations. HEAD's encoder already returns non-fatal "outside limits" flags (`a2l.py:2131-2134`), so any assertion of the form `flags != []` is satisfiable today. | The corpus and the manifest's `a2l_expect` pin all of the following:<br>(1) `TAB_NOINTP` holds 10.0 and a next entry above 13.0, with no entry at 13.0.<br>(2) The `TAB_INTP` physical range lies strictly inside (−50, 500). Its physical step per raw unit is > 1, and the manifest records one in-range off-grid value that is not a rounding tie, with its expected raw and its written physical value, plus one grid value.<br>(3) Each COMPU_TAB symbol's lower and upper limits enclose its table range.<br>(4) The 2-byte MSB symbol and its RECORD_LAYOUT declare no `BYTE_ORDER`, so only `MOD_COMMON` supplies it. Otherwise LLR-158.1's fallback is not exercised and TC-B99-23 / AT-B99-09 pass at HEAD.<br>(5) The LINEAR control declares `LSB_FIRST` explicitly. Otherwise "30 → `0F 00` unchanged" contradicts `MOD_COMMON MSB_FIRST`.<br>(6) RAT_FUNC raw 300 is stored `01 2C`, as the brief already says. | Inc 1 (amend `BRIEF-inc-1.md` before dispatch) |
| PQ-5 | minor | A3-2 · TC-B99-25 · AT-B99-14 | **The A2L assertions must check content, not just presence.** Otherwise a limits refusal or a limits flag discharges the test vacuously. | The in-range arm asserts that the flag text names the written physical value from `a2l_expect`. The out-of-range arms (500.0 and −50.0) assert that the reason names the **table range**, not the limits. The grid arm asserts `flags == []`. | Inc 10 |
| PQ-6 | major | LLR-161.2 · TC-B99-33 | **TC-B99-33's help arm passes at HEAD.** `window_help.py:84` already reads "Bytes — a run of hex bytes…", so "both texts contain `hex`" holds today, and the declared mutant "revert the help text" cannot turn it RED. Only the placeholder (`"DE AD BE EF"`, `screens_directionb.py:4941`) is RED today. | TC-B99-33 pins text that HEAD lacks: the placeholder contains `hex`, and the help states that digit-only tokens are read as hex (or that decimals are refused). The RED transcript at HEAD covers both arms, and one mutant per arm reverts that text. | Inc 11 |
| PQ-7 | minor | HLR-156 (C8) · TC-B99-18 · AT-B99-07 | **The hostile-name literal arm has no declared mutation.** The §4 negative controls are about status only, and §5 lists none for this arm. | The packet declares and runs a mutant that paints the lane cell or notification without `safe_text` (markup on) and shows it RED. The payload carries Rich-active markup (e.g. `[bold red]x[/]` or `[link=…]`), so the mutant is observable in the painted text. | Inc 8 |
| PQ-8 | minor | TC-B99-12 (LLR-155.2) · TC-B99-38 (LLR-155.8) | **The race-based REDs can go GREEN by chance.** The RED and mutant evidence depends on thread interleaving. | The RED and mutant transcripts each show a mismatch count above 0. If a run shows 0, the test adds a deterministic interleaving (a barrier, or a monkeypatched step between stage and place) instead of being re-run until it is red. | Inc 3 (TC-B99-12) · Inc 5 (TC-B99-38) |

---

## 2 · Confirmations asked of this lens

- **A3-1: CONFIRMED with conditions PQ-1..PQ-3.**
  - The mechanism is right. One call claims one `_<N>` for every name of the group before any write (`O_EXCL`), so a mixed pair cannot occur by construction. Reuse happens only when the whole group is identical. The failure contract is B99-I2's.
  - LLR-160.4's threshold arms (never a mixed pair; pair reuse only when both files are identical; first files intact) can be tested through `SegmentSplitView`: `#sje_export` / `e`, the format chip `#sje_fmt`, and the status `exported N file(s)` (`segment_split_view.py:1099`, `:1657`). The files are read on disk.
  - The arms are non-vacuous only with PQ-2's half-pair and mismatched-sidecar fixtures.
  - HEAD writes the pair directly (`segment_ops.py:196-218`, `write_bytes` / `write_text`), so the RED counterfactual exists.
- **A3-2: CONFIRMED with conditions PQ-4 and PQ-5.**
  - The hybrid rule is decidable and testable through the codec API's `(raw_bytes, error, flags)` return (`a2l.py:2093`, signature as LLR-158.3 needs). The rule is: `TAB_NOINTP` exact; `TAB_INTP` refused out of range, flagged in range when the written physical value differs.
  - The decisions page's `rechazar` text now states that rule (`plan-b99.html:175`).
  - An honest fixture needs PQ-4's table geometry and limits.
  - **Open question (not gating):** the contract does not define a tie-break for "nearest raw value". The fixtures must avoid ties until a rule is written.

---

## 3 · AT driver feasibility at HEAD `b2c4464`

| AT | Driver | HEAD evidence | Feasible? |
|---|---|---|---|
| AT-B99-01 | generator CLI in a subprocess; `--check`, `--corpus <dir>` | Inc-1 brief §2, §4 | yes. Advisory: the generator must find `tests/support/independent_reader.py` from its own file path, not from `PYTHONPATH`. |
| AT-B99-02 | Load (`l`) → Patch Editor (`p`) → `#patch_entry_add_button` / `#patch_doc_apply_button` / `#patch_saveback_confirm_button`; Memory Map | ids in `screens_directionb.py:5040-5086`; idiom in `tests/test_b97_patch_editor.py` | yes |
| AT-B99-03, -06, -07, -10 | Flow Execution `#fx_run`; lane cells; flow and chain-set reports | `flow_screens.py:2793`, `:3769`; `tests/b97_fixtures.py` `write_flow`, `flow_project`, `write_changeset` | yes |
| AT-B99-04 | chain set, parallel mode chosen by key; `same.s19` refusal in the status line | `tests/test_b97_flow_execution.py:706-741` | yes. The refusal arm is RED under D7 only after the verdict. |
| AT-B99-05 | save-back as `firmware.s19` → `SaveProjectScreen` | `tests/test_b97_patch_editor.py`, `tests/test_b97_load_project_dialog.py` | yes |
| AT-B99-08 | Add / Apply / `#patch_undo_button` / Add / Apply / save-back | `screens_directionb.py:5040`, `:5736` | yes |
| AT-B99-09 | A2L window `#a2l_tags_list`, column `Physical` | `app.py:6396-6404` | yes, subject to PQ-4. Pin the emitted form (`30` or `30.0`). |
| AT-B99-11 | `SegmentSplitView` export; hostile segment name; junction destination | `tests/b97_fixtures.py` `hostile_a2l`, `long_name_a2l`, `make_junction` | yes, subject to PQ-1 / PQ-2 for the pair arm |
| AT-B99-12 | `#patch_entry_bytes_input` → Add → save-back | `screens_directionb.py:4941`, `:5638` | yes |
| AT-B99-13 | `LoadProjectScreen` `#project_ok` (keyboard, click, `enter`); Workarea Files list | `screens.py:711`, `:724`; `tests/test_b97_load_project_dialog.py` | yes |
| AT-B99-14 | `encode_physical_to_raw_bytes` return value (the declared US-152 exception) | `a2l.py:2093-2134` | yes, subject to PQ-4 / PQ-5 |

---

## 4 · PDR record rows (§A) from this lens

| # | Item | ✓/⚠/✗ | Evidence |
|---|---|---|---|
| 3 | Forward applicability | ⚠ | §7 names consumers for all four outputs. Gap: §2 omits `place_group_into_workarea`, so no brief would carry it (PQ-1). Advisory: name `tests/b97_fixtures.py` as an AT enabler. |
| 4 | Every requirement has foreseen coverage | ✓ | §5 rows cover TC-B99-01..41 (TC-37 retired, ledger .2) and AT-B99-01..14. Each LLR names its TC, each HLR its AT. |
| 5 | Observable and non-vacuous; mutation named | ⚠ | §5 names a mutant per group, and each LLR's Negative control carries the rest. Three test cases are vacuous as written (PQ-2, PQ-4, PQ-6); one arm has no mutant (PQ-7); one RED depends on chance (PQ-8). |
| 6 | Gauntlet controls declared, with who pays | ✓ | BRIEF-COMMON items 1–8: RED first, C-40 mutation, independent oracle, black-box AT, reverse census; the orchestrator runs the full suite. |

**Enablers judged sufficient once PQ-4 is applied.** The corpus plus the independent reader (Inc 1) supply every byte oracle. BRIEF-COMMON's environment rules are enough for every pilot AT:
- the interpreter;
- `PYTHONPATH` set to the worktree, with the `s19_app.__file__` probe;
- `env -u NO_COLOR`;
- the animator wait.

**Advisory, not gating:**
- TC-B99-13 and TC-B99-16 hooks should be monkeypatch seams on module-level calls. A production hook parameter would be an undeclared §2 design characteristic.
- LLR-158.3's title ("…are refused") understates the in-range flag. This is the architect's lane.

---

## 5 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | ✓ | The contract's HLR *Observable outcome* plus *Shipped surface* are equivalent. Not re-authored at PDR (scope: review). |
| Test cases have explicit Expected | ✓ | Every LLR carries a *Numeric pass threshold* (`01-requirements.md` §4). |
| Edge cases include empty, boundary, invalid, error | ✓ | Every HLR has a QC-3 boundary catalog with N/A reasons (§3). |
| Regression checklist exists | ✓ | §5.1 *Regression*: a full suite per cut against `evidence/baseline-pytest-a293213.txt`; re-pins named in the reverse census. |
| Exit criteria stated | ✓ | `01-requirements.md` §5.2. |
| No real PII / secrets | ✓ | Fixtures are synthetic or under `examples/`. No person names, no credentials. |
| Mode declared | ✓ | `plan`, at the top of this file. |
| Plan mode: results declared `planned` | ✓ | §0 line; no result is claimed. |
| Layer B through the shipped surface, with boundary and negative evidence | ✓ | §3 table: every AT has a HEAD driver. The US-141 and US-152 surface exceptions are declared in the contract. |
| Bidirectional surface reachability | ⚠ | Inputs and outputs reach the handler for every story. Exception: the encoder (US-152, P-22, recorded exception). |
| No unfilled template | ✓ | No `<...>` placeholders. Every condition names an owner. |

# Increment 011 — HLR-161 · The Bytes field reads one base

| Field | Value |
|---|---|
| Batch | `2026-10-25-batch-99` |
| Increment | `011` |
| Lane (if the batch forked) | n/a — one lane (`B99-I1..I12` sequential, ARQ verdict) |
| Requirement(s) | `US-150 / HLR-161 / LLR-161.1 · LLR-161.2` (amends batch-07 LLR-001.2's TUI bytes grammar) |
| Acceptance | `AT-B99-12` · white-box `TC-B99-32 · TC-B99-33` · unit `none (no new shipped-source node beyond the grammar fix)` |
| Agent | `software-dev` |
| Date | `2026-10-25` |

---

## 1 · What changed

BLUF: the Patch Editor's Bytes field now reads **one base**. Every token is
hexadecimal, with an optional `0x` prefix, 1–2 hex digits; anything else is
refused with a `ValueError` naming the token (`invalid byte token '100' -
every token is 1-2 hex digits with an optional 0x prefix; decimals are not
accepted`). At HEAD the permissive LLR-001.2 grammar parsed digit-only
tokens as **decimal** (base-0 first), so `0F 10 1F 20` applied as
`0F 0A 1F 14` (P-16) — inside a hex dump that is the wrong byte.

The field now says what it reads: the placeholder is
`hex bytes, e.g. DE AD BE EF` (was `DE AD BE EF`), and the Patch Editor
window-help "Bytes" line states the rule — every token is a hex byte (1–2
digits, `0x` optional), decimals are not accepted. Per PDR condition
PQ-6 / UX-C9, TC-B99-33 pins text that was **absent** at HEAD (the help
already contained the word "hex", so a "contains hex" assertion would have
been vacuous); the RED transcript covers both arms. The "String" help line
keeps the document-encoding note — string (value) entries are unchanged by
HLR-161.

Shipped surface the user reaches: the Patch Editor Bytes field, its
placeholder, the window help, and the refusal message on Add/Edit.

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/change_service.py` | SOURCE | LLR-161.1 | `parse_new_bytes`: hex-only grammar — optional `0x` strip, 1–2 hex digits, `ValueError` naming any other token; docstring rewritten (LLR-161.1, amends LLR-001.2). Review round 1 (F1): acceptance is now `re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]{1,2}", token)` (ASCII only) — the bare `int()` path admitted signs (`+F`, `-1`, `0x+F`) and non-ASCII digits (`１２`, `٣٣`) |
| `s19_app/tui/screens_directionb.py` | SOURCE | LLR-161.2 | the `#patch_entry_bytes_input` placeholder → `hex bytes, e.g. DE AD BE EF` |
| `s19_app/tui/window_help.py` | SOURCE | LLR-161.2 | the patch help "Bytes" line states the hex rule (`0x` optional, decimals not accepted) |
| `tests/test_b99_bytes_field.py` | test | HLR-161, LLR-161.1/.2 | new: TC-B99-32, TC-B99-33, AT-B99-12. Review round 1: TC-B99-32's refused set gained `+F`, `-1`, `0x+F`, `１２`, `٣٣` (F1); AT-B99-12 rewritten black-box — the image loads through the app's own load path and the saved file is found on disk by the save-back prompt's name, no injected `current_file`, no `last_summary.saved_path` (F2) |
| `tests/test_change_service.py` | test | LLR-161.1 | re-pin: `test_parse_helpers_follow_tui_input_grammar` — decimal token `2` → hex token `02`; `100` refused (see Reverse census) |
| `tests/test_tui_memory_patch.py` | test | LLR-161.1 | re-pin: `test_parse_new_bytes_accepts_hex_decimal_and_bare_hex` → `..._accepts_prefixed_and_bare_hex`; `100`-refusal arm added. **Also** `test_parse_new_bytes_rejects_a_garbage_token` gained the `100`-refusal arm — **three** existing test nodes changed here and in `test_change_service.py`, not two (F3) |
| `.dev-flow/2026-10-25-batch-99/03-increments/increment-011.md` | doc | — | this packet |
| `.dev-flow/2026-10-25-batch-99/evidence/inc-11/*` | doc | — | transcripts, hashes (outside the count) |

| Count | Value |
|---|---|
| **SOURCE files** | **3 / 4** |
| Test files | 3 (uncapped) |
| Doc files | 2 (outside the count) |

- ✓ No file from another lane touched; `prototypes/` untouched.

---

## 3 · How to test

```bash
# from the worktree root, with the s19env interpreter:
python -c "import s19_app; print(s19_app.__file__)"   # C:\Users\jjgh8\Github\s19_app-b99-inc11\s19_app\__init__.py
pytest tests/test_b99_bytes_field.py -v               # -> 3 passed
pytest tests/test_b99_bytes_field.py -k tc_b99_32     # -> 1 passed, 2 deselected
pytest tests/test_b99_bytes_field.py -k tc_b99_33     # -> 1 passed, 2 deselected
pytest tests/test_b99_bytes_field.py -k at_b99_12     # -> 1 passed, 2 deselected
pytest tests/test_change_service.py tests/test_tui_memory_patch.py -q   # -> 30 passed
pytest tests/test_address_census.py -q                # -> 23 passed
```

---

## 4 · Test results

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | none — the changed node is verified by the white-box TCs below | n/a |
| **A · white-box** `TC-B99-32 · TC-B99-33` ↔ LLR-161.1/.2 | `core` · `full` | `test_tc_b99_32_hex_only_token_grammar` · `test_tc_b99_33_field_and_help_state_the_hex_rule` | 2 passed |
| **B · black-box** `AT-B99-12` ↔ US-150, through the Textual pilot (real keys into the Bytes field, shipped buttons) | `core` · `full` | `test_at_b99_12_typed_hex_run_saves_back` | 1 passed |

Regression companions: `tests/test_change_service.py` +
`tests/test_tui_memory_patch.py` — 30 passed (includes the three re-pinned
nodes); `tests/test_address_census.py` — 23 passed; the full reverse-census
file set — 11 files, 352 passed and 5 failures, **all five isolated as
pre-existing or environmental** (fail identically at HEAD or are HEAD-flaky;
see `pre-existing-failures.txt`, `red-at031b-head-isolation.txt`,
`red-head-isolation-others.txt`): `test_at031b_two_saves_are_distinct_no_clobber`
(fails deterministically at HEAD), `test_at077c_stale_provenance` (flaky at
HEAD: 3/6 fails), `test_at_056e_a2b_diff_report_byte_identical_despite_selection`
(fails at HEAD), and the two TC-707 nodes (`FileNotFoundError` — the
untracked `prototypes/cambios_10_12_2026/help_sections.md` is absent from
this worktree; per the batch rules nothing under `prototypes/` may be
created or edited).

### RED counterfactual — executed, not predicted

| Field | Value |
|---|---|
| Mutation applied | baseline RED at HEAD (unmodified tree): all 3 new nodes FAILED — `red-initial.txt` (TC-B99-32: `100`/`G1` not refused with the token named; TC-B99-33: placeholder lacks `hex`, help lacks the rule; AT-B99-12: the saved file holds `0F 0A 1F 14`, P-16). Then two C-40 mutations on the fixed tree, one per LLR (see Mutation verdicts). |
| Instrument | project code: the implementer's own hand via the Edit tool, restore checked by SHA-256 |
| Where it ran | this worktree (`C:\Users\jjgh8\Github\s19_app-b99-inc11`), run by the implementer |
| Transcript | `evidence/inc-11/red-initial.txt` · `mut-LLR-161.1.txt` · `mut-LLR-161.2.txt` (each: the arm FAILED) |
| Restore proven by | file hashes returned to pre-mutation values (`baseline-hashes.txt`): change_service.py → `06a39682…a60e`; screens_directionb.py → `116b082f…9541`; window_help.py → `bb55a4e9…d41f` |
| Bytecode cache | run with `PYTHONDONTWRITEBYTECODE=1` (C-46) |
| Arms resolved at baseline | 3 nodes in `red-initial.txt` — asserted 3 |
| Verdict granularity | per resolved node id: `test_tc_b99_32_hex_only_token_grammar`, `test_tc_b99_33_field_and_help_state_the_hex_rule`, `test_at_b99_12_typed_hex_run_saves_back` |
| Arms that stayed GREEN | none |

| Field | Value |
|---|---|
| **Mutation verdicts** | LLR-161.1 · TC-B99-32: `parse_new_bytes` mutated to parse base-0 first (the HEAD rule: `int(token, 0)` with a base-16 retry) · KILLED — `0F 10 1F 20` parses as `[15, 10, 31, 20]` instead of `[15, 16, 31, 32]` (`mut-LLR-161.1.txt`) · arms GREEN: none · restore `06a39682…` ‖ LLR-161.2 · TC-B99-33: the placeholder reverted to `DE AD BE EF` (the HEAD text) · KILLED — the placeholder arm asserts `hex` (`mut-LLR-161.2.txt`) · arms GREEN: none · restore `116b082f…` |

### Instrument RED-proof — every instrument shown able to report FAILURE first

| Instrument | Known-bad input fed to it | The FAILURE it reported |
|---|---|---|
| `pytest` (TC runner) | the tree before the fix (`red-initial.txt`, unmodified source) | all 3 nodes FAILED: `100`/`G1` accepted, placeholder/help arm RED, saved run `0F 0A 1F 14` ≠ `0F 10 1F 20` |
| `pytest` + TC-B99-32 | `parse_new_bytes` mutated to base-0-first (the HEAD rule) | `test_tc_b99_32_hex_only_token_grammar FAILED` (`mut-LLR-161.1.txt`) |
| `pytest` + TC-B99-33 | the placeholder reverted to the HEAD text | `test_tc_b99_33_field_and_help_state_the_hex_rule FAILED` (`mut-LLR-161.2.txt`) |
| independent reader (AT-B99-12 oracle) | the pre-fix tree's saved file | the byte comparison `[0x0F, 0x10, 0x1F, 0x20]` FAILED against the actual `0F 0A 1F 14` (in `red-initial.txt`) |

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments, each shown RED before its first PASS was believed |

### Emitted-form assertion — assert the bytes the producer EMITS (C-42)

| Artifact emitted | The assertion, run against the EMITTED form | What it returned |
|---|---|---|
| the saved-back S19 file (emitted by the app's writer after Apply) | `read_s19` (independent reader, zero `s19_app` imports) over the written file; `[data[0x100+i] for i in range(4)] == [0x0F, 0x10, 0x1F, 0x20]` | 1 passed (`green-at_b99_12.txt`) |
| the placeholder as painted (queried from the pilot-mounted widget at width 118) | `len(placeholder) <= field.content_size.width` — no clipping of the compact input | 1 passed (`green-tc_b99_33.txt`) |
| the shipped help text (the code-authored `WINDOW_HELP_SECTIONS["patch"]` body the help modal renders) | the "Bytes" line contains the rule phrases; the "String" line keeps the encoding note | 1 passed (`green-tc_b99_33.txt`) |

| Field | Value |
|---|---|
| **Emitted-form assertion** | 3 artifacts, each asserted against the form its producer emits |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

All under `artifact_homes.evidence` = `.dev-flow/2026-10-25-batch-99/evidence/inc-11/`

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| RED baseline at HEAD (3 failed) | `red-initial.txt` | `0dbf1556e2819599f7a6297a34586db3310a8d83e1a7b57e72d2ceadb66747b0` |
| GREEN full run (3 passed) | `green-full.txt` | `5fe530628f2fcbba20ddc8406a2b17b2badf88b23b798306459ed6484e04e69b` |
| GREEN TC-B99-32 | `green-tc_b99_32.txt` | `211d494e1e36ad5039af440c76a89eb1ebf52c75e516923ec3289317c74fb607` |
| GREEN TC-B99-33 | `green-tc_b99_33.txt` | `593568a9aa59470155a3b6466400ac61125d23fea4938b5ea3ad6589f0ef6e56` |
| GREEN AT-B99-12 | `green-at_b99_12.txt` | `60f9a140a5e76d6941ef461d56daaff461b65d37664affb969feaeae27763f7d` |
| GREEN re-pinned companions (30 passed) | `green-repinned.txt` | `b0c1f0208e87d1b4ffe6a02816a5ad618fb845944ac48d3b8d501bababe6fa3a` |
| GREEN regression companion (23 passed) | `green-address-census.txt` | `abaf7e686e2723989b3713ad455594ed3ba420f7f2014171519220869400f0f8` |
| GREEN affected reverse-census file set (11 files: 352 passed, 5 pre-existing failures) | `green-affected-summary.txt` + per-file `green-test_*.txt` | `1d5a4d66185e0248bb583318324edae8408b0d6bf7a2335c972d962c9a50fb05` |
| HEAD-isolation: AT-031b fails at HEAD too | `red-at031b-head-isolation.txt` | `2be0260e30385a452217c180e45c0b12eb5075f547311e2ffcda154ad56da3d5` |
| HEAD-isolation: at_056e + TC-707 ×2 fail at HEAD too | `red-head-isolation-others.txt` | `2342bbf6d4ed8ba67b1daf4d24e41fbcfdde37cafa93b00b933430432f54300d` |
| Pre-existing-failures verdict (5 nodes, all isolated) | `pre-existing-failures.txt` | `7af5d26723cc365273007c400f2d2b0de2fb6b4a63d3c21082adf6aefbea08c1` |
| GREEN affected: `test_b97_chips_help.py` (79 passed) | `green-test_b97_chips_help.txt` | e6bdab68061204d09351e5b7005a37622b09886330de4122ce1b82f25a152eb3 |
| GREEN affected: `test_b97_flow_execution.py` (75 passed) | `green-test_b97_flow_execution.txt` | ce665d834859490e1f87705d315fcd48a6101f571dbee407135a8c09d58fbfea |
| GREEN affected: `test_b97_patch_editor.py` (38 passed) | `green-test_b97_patch_editor.txt` | 3b8a75ea0f54f09c911201ca208375ca89cf3546fe11d0c073dde2014acd0951 |
| GREEN affected: `test_before_after_report.py` (15 passed) | `green-test_before_after_report.txt` | 8ce1265d03bb01b59743161782a282a640fe43755fb52902a5c2ae99ad1e9914 |
| GREEN affected: `test_loadfilescreen_input.py` (33 passed) | `green-test_loadfilescreen_input.txt` | a49654d22cc766484ee352a89d6f71e11f43e5b0c973e89a0c5775c30d924187 |
| GREEN affected: `test_tui_patch_editor_b94.py` (17 passed) | `green-test_tui_patch_editor_b94.txt` | 205c326368552a8e5bce29fa7e4395716291b81a703ed54f03fc0acd0743eb6b |
| GREEN affected: `test_tui_patch_editor_v2.py` (51 passed + 1 pre-existing) | `green-test_tui_patch_editor_v2.txt` | d9a7f6c5fc4815b45ed8a06e9153b55b461d90c7b22ea05a9a4e0b7a80ee0b79 |
| GREEN affected: `test_tui_patch_glyphs.py` (11 passed + 1 HEAD-flaky) | `green-test_tui_patch_glyphs.txt` | 4b05a2d9da78ec452abce32a655c591943523be2036f68476a077ac83bd87a38 |
| GREEN affected: `test_tui_patch_layout.py` (9 passed) | `green-test_tui_patch_layout.txt` | b48b8bfcdc679239868ed749ee5dad79c09270cf7c1b6c853756d7aab41da6b9 |
| GREEN affected: `test_tui_report_filter_surface.py` (13 passed + 1 pre-existing) | `green-test_tui_report_filter_surface.txt` | e6bdab68061204d09351e5b7005a37622b09886330de4122ce1b82f25a152eb30 |
| GREEN affected: `test_window_usage_help.py` (36 passed + 2 environmental) | `green-test_window_usage_help.txt` | e6bdab68061204d09351e5b7005a37622b09886330de4122ce1b82f25a152eb31 |
| Mutation LLR-161.1 (KILLED) | `mut-LLR-161.1.txt` | `94fa5e3ab9287e3fee7f85ed53e278ac241fd90557af64151a045d8b5fdafe66` |
| Mutation LLR-161.2 (KILLED) | `mut-LLR-161.2.txt` | `12786f02914fefd495c7800b0b1bc2f7fba006318002808264d1f771caabe88e` |
| Pre-mutation hashes | `baseline-hashes.txt` | `9580352bbf192917f60cddcdd7cd3db1d68d4e81d7bae6cec5a299b6bf13387f` |
| Reverse census probes | `reverse-census.txt` | `7444f5ee061468cd988c2e6fb7aaa701feefd1e94534236a188cddb39f17056b` |

| Field | Value |
|---|---|
| **Evidence files** | 26 artifacts, each at the declared home and cited with the digest of its stored bytes |

### Load-bearing emptiness — what is this resting on that is only true today? (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes — (1) the AT oracle's independence: the saved file must be read by a reader with ZERO `s19_app` imports; (2) the placeholder must contain NO clipping at width 118 |
| If the result is an ABSENCE, what made the search wide enough | (1) `tests/support/independent_reader.py` imports nothing from `s19_app` (frozen since Inc-1, module docstring); (2) the no-clip check compares the FULL placeholder length against the painted inner width at (118, 54), not a sample of characters |
| Guard labelled as protecting a CONCLUSION, not a behaviour | TC-B99-33's `len(placeholder) <= inner_width` assertion is its own line with the measured numbers in the failure message |
| Conjunctive criteria: one mutation per conjunct | TC-B99-33 has two arms (placeholder, help) but one LLR (161.2); the declared negative control mutates the placeholder, and the help arm is RED at baseline (`red-initial.txt`) — each arm independently failed on the unmodified tree |
| Synthetic instance of the absent case | the LLR-161.1 mutant IS the old decimal-reading parser (it exists only as a transient mutation, reverted by hash); the red-initial run IS the placeholder without `hex` |
| **Positive control for every probe that returned an ABSENCE** | (1) the same reader returns the wrong bytes on the pre-fix tree (`red-initial.txt` — non-absent output of the identical probe); (2) the help arm of TC-B99-33 passes with the rule phrases present (`green-tc_b99_33.txt`) |

### Reverse census — trigger family B, and A3

| Probe | Command | Result |
|---|---|---|
| B1 symbols asserted by **other** tests | `grep -rln "parse_new_bytes\|patch_entry_bytes_input" tests/` | 13 hits (recorded verbatim in `reverse-census.txt`): `b97_fixtures.py`, `test_b97_chips_help.py`, `test_b97_flow_execution.py`, `test_b97_patch_editor.py`, `test_before_after_report.py`, `test_loadfilescreen_input.py`, `test_tui_patch_editor_b94.py`, `test_tui_patch_editor_v2.py`, `test_tui_patch_glyphs.py`, `test_tui_patch_layout.py`, `test_tui_report_filter_surface.py`, `test_change_service.py`, `test_tui_memory_patch.py` (the last two re-pinned, below; the rest re-validated: every typed run is already hex — `DE AD BE EF`, `01 02`, `11 22`, `33 44 55`, `5A`, `01` — so the hex-only rule changes no pinned value) |
| B1 `decimal` consumers | `grep -rln "parse_new_bytes\|patch_entry_bytes_input\|decimal" tests/` | the additional `decimal` hits (`test_a2l_inline_axis_length.py`, `test_report_length_cell.py`, `test_memory_display.py`, `test_tui_directionb.py`, `test_memory_changelist.py`) are unrelated domains (A2L integers, report cell widths, memory renderings) — no re-pin |
| B3 byte-identical golden captures this source | `grep -rl "DE AD BE EF" tests/goldens/` | 0 hits — no golden pins the placeholder or the help line; snapshot dir `tests/__snapshots__/test_tui_snapshot` contains no `DE AD BE EF` either — no re-pin |
| B4 artifact produced here is consumed elsewhere | the placeholder/help/grammar are UI-only; no fixture or manifest consumes them — the saved-file AT consumes the independent reader only | no re-pin |
| A3 interface consumed by another module changed | `parse_new_bytes` keeps its name, signature and `list[int]` return; its only shipped caller is `ChangeService.add_entry` / `edit_entry` (change_service.py:1000) — the ValueError contract is unchanged in kind | re-validated by `tests/test_change_service.py` (24 passed) and `tests/test_tui_memory_patch.py` (6 passed) |

Re-pins (behaviour change authorised by HLR-161, amending batch-07 LLR-001.2) — **three** existing test nodes, not two (F3):

- `test::test_parse_helpers_follow_tui_input_grammar` — `parse_new_bytes("0x01, 2") == [1, 2]` (bare `2` read as decimal) → `parse_new_bytes("0x01, 02") == [1, 2]` plus a `100`-refused arm — requirement LLR-161.1.
- `test::test_parse_new_bytes_accepts_hex_decimal_and_bare_hex` → renamed `test_parse_new_bytes_accepts_prefixed_and_bare_hex`; the name/docstring claimed decimal acceptance (the amended rule); the pinned values (`[1, 2, 3]` for `"1, 2, 3"`) are unchanged because 1-digit tokens are valid hex — plus a `100`-refused arm — requirement LLR-161.1.
- `test::test_parse_new_bytes_rejects_a_garbage_token` — unchanged except a `100`-refusal arm (`"100" in str(err.value)`) added; the pre-existing `01 ZZ 03` refusal is untouched — requirement LLR-161.1.

| Field | Value |
|---|---|
| **Reverse census** | 5 probes declared (B1 ×2, B3, B4, A3) — 3 re-pins, each recorded with old → new → requirement; every other hit re-validated unchanged |

### Correction population — enumerated BEFORE the first site was edited

| Correction | Population | Enumeration method | Count | Sites edited | Sites left, and why |
|---|---|---|---|---|---|
| the TUI bytes grammar reads one base | every site that describes or pins the permissive grammar | `grep -rn "parse_new_bytes\|DE AD BE EF\|permissive" s19_app/tui/services/change_service.py s19_app/tui/screens_directionb.py s19_app/tui/window_help.py` + the B1 test census above | 3 source sites + 2 test sites | change_service.py (`parse_new_bytes` + docstring), screens_directionb.py (placeholder), window_help.py (help line); test_change_service.py + test_tui_memory_patch.py (re-pins) | `s19_app/tui/changes/io.py:13-19` — its module docstring still calls decimals part of "the permissive TUI-input grammar of parse_new_bytes". It is a COMMENT-only mention, the file is outside this increment's 3-file SOURCE cap, and its normative claim (what the FILE format accepts) is unchanged. Left in place; flagged for a doc-only follow-up |

| Field | Value |
|---|---|
| **Correction population** | 1 correction (the grammar), 5 sites (3 SOURCE + 2 test); 1 doc-only site explicitly left and flagged |

#### Supersession-completeness inspection (V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence (file:line) |
|---|---|---|---|
| batch-07 LLR-001.2 (TUI bytes-grammar half, amended by HLR-161) | `grep -rn "LLR-001.2" s19_app/ tests/ docs/` | the surviving refs are the OTHER halves of LLR-001.2 — the strict wire/file grammar (`changes/io.py:12,223,268,394,529,843,908,1130`), the diff adjacency rule (`compare.py:11-279`), the rail/collector notes (`app.py:218,238,5384,5461,6978,7020`) — none describes the TUI bytes grammar | `changes/io.py:13-19` (see Correction population — doc-only mention of the TUI half, left, flagged) |

### Signed-balance test ledger

`post = base − deleted + added` → `33 = 30 − 1 + 4` ✓ reconciles
(`tests/test_change_service.py`: 24 baseline nodes − 0 deleted + 0 added —
the re-pin edited the existing node `test_parse_helpers_follow_tui_input_grammar`
in place, no node added or deleted; `tests/test_tui_memory_patch.py`:
6 baseline − 1 deleted (`test_parse_new_bytes_accepts_hex_decimal_and_bare_hex`)
+ 1 added (`test_parse_new_bytes_accepts_prefixed_and_bare_hex` — the rename;
**two** existing nodes — the renamed one and
`test_parse_new_bytes_rejects_a_garbage_token` — gained a `100`-refusal arm
in place, no node added or deleted);
`tests/test_b99_bytes_field.py`: 0 baseline + 3 added — TC-B99-32,
TC-B99-33, AT-B99-12. Post total: 24 + 6 + 3 = 33 nodes, all passing.)

---

### Review round 1 fixes (code-reviewer F1–F3)

| # | Finding | Fix | Evidence |
|---|---|---|---|
| F1 [MEDIUM] | the grammar admitted signs and non-ASCII digits — `+F`/`0x+F` → 15, `１２` → 0x12, `٣٣` → 51 via `int()`; `-1` slipped to a `ChangeEntry` refusal naming the value | `parse_new_bytes` now accepts a token only when `re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]{1,2}", token)` matches (ASCII only) and otherwise raises the `ValueError` naming the token; docstring claims at the old :188-189 corrected (Returns / Raises / Data Flow now state the ASCII fullmatch and why) | TC-B99-32 refused set gained `+F`, `-1`, `0x+F`, `１２`, `٣٣` — 3 passed (`green-fix-b99_bytes_field.txt`) |
| F2 [MEDIUM] | AT-B99-12 was not black-box — it injected `app.current_file` and read `app._change_service.last_summary.saved_path` | AT-B99-12 rewritten: the image loads through the app's own load path (`load_from_path`, the `b97_fixtures.open_patch_editor` idiom); the saved file is found on disk under `<base>/.s19tool/workarea/` by the name the shipped `#patch_saveback_name_input` shows, and only the independent reader reads the bytes — no injected state, no internal attribute or service | 3 passed (`green-fix-b99_bytes_field.txt`); RED kept: under the HEAD base-0-first grammar the AT fails with `got [15, 10, 31, 20]` = `0F 0A 1F 14` (`mut-LLR-161.1-fix-headgrammar.txt`); stability 8/8 (`stability-at12.txt`) |
| F3 [LOW] | packet line 51 said two existing tests changed; three did — `test_parse_new_bytes_rejects_a_garbage_token` gained the `100` refusal | count and re-pin list corrected (§2 file table, §4 re-pin list, ledger) | this subsection |

C-40 mutation (F1's declared negative control): the `int(token, 16)` path
without the fullmatch → TC-B99-32 KILLED (`+F` did not raise;
`mut-LLR-161.1-fix.txt`) — restore proven by SHA-256
(`baseline-hashes-fix.txt`, change_service.py → `c830459e…3ddef`). A second
transient mutation, the HEAD base-0-first grammar, re-verifies the AT's RED
on the rewritten black-box shape (`0F 0A 1F 14`,
`mut-LLR-161.1-fix-headgrammar.txt`); both mutants reverted byte-identical.

| Evidence artifact | Path | SHA-256 |
|---|---|---|
| Pre-mutation hashes (fix round) | `baseline-hashes-fix.txt` | `5dd3e3af2f8dde36d9701d6116d293149949dd142320f36fb03ed987ed228336` |
| Mutation: `int()` without the fullmatch (TC-32 KILLED) | `mut-LLR-161.1-fix.txt` | `c6573087992c56eb40bb72364042af1cde4d6b44cc5bcb34b39383d74db4f147` |
| Mutation: HEAD base-0-first grammar (AT RED `0F 0A 1F 14`) | `mut-LLR-161.1-fix-headgrammar.txt` | `7b52aa7f866cd2f21ad3a1a6051d2e24bea35d496919cc3ea0a8fcf50112c84a` |
| GREEN after fixes (3 passed) | `green-fix-b99_bytes_field.txt` | `73cc9be0e6f2e8ead8f7b1b7ebd2e5093a843e0b6f968530770bb9e799a6732f` |
| GREEN re-pinned companions (30 passed) | `green-fix-repinned.txt` | `708e82509e8584b9c9d3dee9dff75484b4baf0853e107a5530807432b4dbdb6c` |
| GREEN address census (23 passed) | `green-fix-address-census.txt` | `80edbf35a246b80e456af5c6a6b1fb80663e55679aa8a5d5c2db39b3eceeea61` |
| AT-B99-12 stability, 8/8 passed | `stability-at12.txt` | `d6ead106b2f1804994a39ff290ab4f2b0a4ae5a3e52474cb375364e04a35c0f8` |

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as a generic agent with agents/code-reviewer.md · round 1: OK to advance with notes (F1 MEDIUM sign/non-ASCII tokens admitted; F2 MEDIUM AT-B99-12 not black-box; F3, F4 LOW) · round 2: F1, F3 closed; F2 partly closed (load still via `load_from_path`) — the orchestrator rewrote that step to the Load file dialog (`l`, type into `#load_path`, click `#load_ok`, wait on the painted status) and the Patch Editor rail key `6`; 8/8 stable. F4 routed to BACKLOG-CODE |

---

## 5 · Risks

- The refusal message now says "decimals are not accepted". The status line
  trims log lines to 50 chars; the message is ~100 chars, so the operator
  sees it trimmed in the log view but the full text reaches the status
  path — consistent with the pre-existing refusal style.
- `parse_new_bytes` still splits on commas. HLR-161's grammar names
  whitespace-separated tokens; commas remain accepted as a convenience
  (they were in the old grammar and no requirement removes them). The help
  says "spaces".
- `s19_app/tui/changes/io.py:13-19` docstring (Correction population)
  describes the old permissive TUI grammar; it is comment-only and outside
  the 3-file cap. A doc-only follow-up should align it.

## 6 · Pending items / spec deviations

- None blocking. The io.py doc-only mention above is declared, not fixed
  (SOURCE cap).
- The pilot AT presses the shipped buttons via `Button.press()` (the
  save-back confirm lives in a hidden prompt container until Apply, so a
  pilot click lands on a zero-region widget). Key typing into the fields is
  real (focus + `pilot.press`); this matches the repo's other save-back ATs.

## 7 · Suggested next task

Batch-99 Increment 12 (HLR-162 / LLR-162.x, `tests/test_b99_load_project.py`):
the project and work-area pickers load by name.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 3 SOURCE files (`git status` — 3 files under `s19_app/`) |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b99_bytes_field.py` (3 nodes, this increment) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | n/a — no new shipped-source node beyond the grammar fix; unit-layer LLR-161.1 verified by TC-B99-32 |
| 4 | **RED counterfactual** declared | `core` · `full` | ✓ | §4: baseline RED `red-initial.txt` (3 failed at HEAD) + 2 mutations with transcripts and restore digests |
| 5 | **Reverse census** declared | `core` · `full` | ✓ | §4: 5 probes, 3 re-pins recorded old → new → requirement |
| 6 | `code-reviewer` passed | `core` · `full` | ⚠ | §4b `pending — orchestrator` |
| 7 | No file from another lane touched | all | ✓ | `git status` — only the 3 SOURCE files + 3 test files + evidence/packet |
| 8 | Frozen interfaces untouched | all | ✓ | `parse_new_bytes` signature/name unchanged; engine layer untouched |
| 9 | Coverage claims verified **on disk** | all | ✓ | AT-B99-12 reads the saved file from disk with the independent reader |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 with positive controls (reader on the pre-fix tree; help arm GREEN run) |
| 11 | **Mutation verdicts** declared | all | ✓ | §4: per-arm KILLED, inert arms named |
| 12 | **Instrument RED-proof** declared | all | ✓ | §4: 4 instruments shown RED first |
| 13 | **Correction population** declared | all | ✓ | §4: 1 correction, 5 sites, 1 doc-only site flagged |
| 14 | **Emitted-form assertion** declared | all | ✓ | §4: 3 artifacts asserted in emitted form |
| 15 | **Independent review** names somebody | all | ✓ | §4b code-reviewer, two rounds |
| 16 | **Evidence files** declared | all | ✓ | §4: 26 artifacts with stored-byte SHA-256 digests |

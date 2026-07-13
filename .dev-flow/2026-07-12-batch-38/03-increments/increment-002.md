# Increment 002 — US-066 (B-17) — Defensive WARNING for A2L address > 0xFFFFFFFF

Story: **US-066 / HLR-066 (R-TUI-055)** · LLRs 066.1 / 066.2 / 066.3 · ATs AT-066a / AT-066b · TCs TC-333 / TC-334 / TC-335.

## 1. What changed
- Added a TUI-side supplemental producer `supplemental_a2l_oversized_address_issues(tags_for_validation)` in `services/validation_service.py` (sibling of `supplemental_a2l_row_issues`). For each effective A2L tag whose `address` is an `int` strictly `> 0xFFFFFFFF`, it emits one `ValidationIssue(code="A2L_ADDRESS_EXCEEDS_32BIT", severity=WARNING, artifact="a2l", symbol=<name or None>, address=<addr>)` naming the tag. A tag whose address is `<= 0xFFFFFFFF`, `None`, or non-`int` produces nothing.
- Merged the producer into **both** branches of `build_validation_report` (MAC-only and primary-backed), right after the existing `supplemental_a2l_row_issues` merge, before `dedupe_issues`. The WARNING therefore reaches `ValidationReport.issues` → `update_validation_issues_view` → `GroupedIssuesPanel` regardless of session kind. Return signature unchanged.
- The WARNING `message` embeds the file-derived tag name as a **plain literal** (no Rich markup). C-17 safety is delivered by the unchanged render sink (`IssueRow` composes `symbol`/`address`/`message` through `safe_text`; `ValidationIssue.__post_init__` scrubs control/ANSI from `message`). No render code and no sanitizer touched.
- Tests: 2 black-box ATs + 3 white-box TCs (5 new nodes).

## 2. Files modified (4 — within the ≤5 cap)
- `s19_app/tui/services/validation_service.py` — new producer + merge into both branches + docstring update. **NOT frozen** (confirmed).
- `tests/test_validation_service_supplemental.py` — TC-333/334/335 (white-box).
- `tests/test_tui_a2l.py` — AT-066a (black-box, app load handler) + local drive/read-back helpers.
- `tests/test_tui_a2l_issue_recolor.py` — AT-066b (black-box, C-17 hostile-input) reusing the file's `_drive_load`/`_issue_rows`/`_assert_within_cap` helpers.

(Frozen set `validation/*`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, `core.py`, `hexfile.py`, `range_index.py` untouched.)

## 3. How to test
```
python -m pytest tests/test_tui_a2l.py::test_at_066a_oversized_a2l_address_warns_naming_tag \
  tests/test_tui_a2l_issue_recolor.py::test_at_066b_oversized_hostile_tag_name_renders_safely \
  tests/test_validation_service_supplemental.py -k "oversized or 333 or 334 or 335" -q
# Full-file regression:
python -m pytest tests/test_tui_a2l.py tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py -q
# Frozen guards + snapshots:
python -m pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k tc031 tests/test_tui_snapshot.py -q
python -m ruff check s19_app/tui/services/validation_service.py tests/test_tui_a2l.py tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py
```

## 4. Test results
- **RED-first (pre-implementation):** AT-066a, TC-333, TC-335, AT-066b — **4 failed** (no `A2L_ADDRESS_EXCEEDS_32BIT` produced; producer symbol did not exist). Captured.
- **GREEN (post-implementation):** all 5 new nodes pass. Full-file regression on the 3 touched test files: **37 passed**.
- **Engine-frozen guards:** `test_engine_unchanged.py` (1 passed) + `test_tui_directionb.py -k tc031` (3 passed). 0 frozen diffs.
- **Snapshots:** 32 passed, 2 xfailed. The 2 xfailed cells are **Increment-1's US-065** copy drift (owned in `test_tui_snapshot.py`, an Increment-1 file). **Increment-2 introduces no snapshot drift** — no widgets/CSS/modals added; the WARNING appears only when an oversized-address A2L is loaded, which no snapshot fixture does.
- **ruff:** clean on all touched files.

## 5. Risks
- R-A (issue-code contract): `A2L_ADDRESS_EXCEEDS_32BIT` is a new public code. C-26 census (below) confirms no existing test asserted A2L issue counts on a >32-bit fixture — none existed. Low.
- The producer fires in every session with a non-empty tag list. Because no pre-existing fixture carries a >32-bit tag address, no existing issue set changes. Low.

## 6. Pending items
- Phase-4 reconciliation of provisional TC/AT node ids to the on-disk names above.
- No canonical snapshot regen owed by this increment.

## 7. Suggested next task
- Increment 3 — US-067 (B-18) variant-selector info/help modal (new button + `ModalScreen`, C-16 real click, C-23 pilot-measured geometry; predicts snapshot xfails).

---

### A-1 finding (tag address is an `int` in both branches)
**Confirmed.** Both branches of `build_validation_report` derive `tags_for_validation` from the same source (enriched tags, else `a2l_data["tags"]`). The parser sets `tag["address"]` via `int(token, 0)` (`tui/a2l.py:984` ECU_ADDRESS, `:333` inline) → a genuine `int` (or `None`). The producer guards `isinstance(address, int)`, so the positive branch is non-vacuous and `None`/string addresses are safely skipped. The AT-066a fixture uses `ECU_ADDRESS 0x100000000` (parsed to int `4294967296`), not a string — the guarded `> 0xFFFFFFFF` comparison is exercised for real (TC-335 pins the non-int/None cases → 0 issues).

### RED→GREEN + boundary evidence (AT-066a)
- RED: with no producer, the load produced only pre-existing `CROSS_A2L_S19_OUT_OF_RANGE` warnings, **0** `A2L_ADDRESS_EXCEEDS_32BIT` → assertion failed.
- GREEN: exactly one `A2L_ADDRESS_EXCEEDS_32BIT` WARNING, `symbol == "BIG_TAG"`, message contains `BIG_TAG`.
- Boundary (same load + TC-335): sibling `EDGE_TAG` at `0xFFFFFFFF` produces **no** oversize WARNING; `0x100000000` produces exactly one. TC-335 also pins `None`/string/absent address → 0.

### AT-066b hostile-input result
- Brackets **verbatim**: the `[red]evil[/red]` warning's message and its rendered `.issue-detail` `.plain` both contain `[red]evil[/red]` literally.
- `[link=...]` **verbatim**: `[link=file:///etc]` survives literally in message + rendered detail (no OSC-8 parse).
- ANSI **neutralized (not verbatim)**: the ANSI-named tag's warning message contains neither the raw `\x1b` nor the `[31m` remnant (stripped by `__post_init__`), while the readable `ANSI_`/`HACK` text remains.
- **No crash / no MarkupError** — reaching the rendered `.issue-detail` asserts proves compose/mount raised none.

### C-26 reverse census
- `A2L_ADDRESS_EXCEEDS_32BIT` and `supplemental_a2l_oversized_address_issues` appear **only** in the new Increment-2 tests.
- No existing A2L fixture carries a tag address `> 0xFFFFFFFF` (grep of `0xFFFFFFFF`/`0x1_0000_0000` across `tests/` hits only CRC-config values and a report-filter range — no A2L tag address). **No existing count/absence assertion moved.**

### Ledger
- `post = base(1367) − D + A` with **D = 0, A = 5** (AT-066a, AT-066b, TC-333, TC-334, TC-335) → Increment-2 contributes **+5** nodes.

### Snapshot cells
- **None owed by Increment-2.** The 2 xfailed cells are Increment-1's (US-065).

### `git diff --name-only` (0 frozen)
```
.dev-flow/state.json
s19_app/tui/screens_directionb.py        # Increment-1
s19_app/tui/services/validation_service.py   # Increment-2 (NOT frozen)
tests/test_tui_a2l.py                    # Increment-2
tests/test_tui_a2l_issue_recolor.py      # Increment-2
tests/test_tui_directionb.py             # Increment-1
tests/test_tui_snapshot.py               # Increment-1
tests/test_validation_service_supplemental.py  # Increment-2
```
0 files in the engine-frozen set.

### ruff
Clean on all Increment-2 files.

---

**POST-GATE FIX (freeze):** AT-066a relocated from frozen `tests/test_tui_a2l.py` to non-frozen `tests/test_tui_a2l_issue_recolor.py`; `test_tc032` now green; net test count unchanged (moved, not added).

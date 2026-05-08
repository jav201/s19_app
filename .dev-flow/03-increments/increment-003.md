# Increment 3 — issue-message scrubbing + 500-char truncation (LLR-002.3)

**Phase:** 3 — Implementation
**Increment:** 3 of N
**Date:** 2026-05-05
**Branch:** `claude/lucid-margulis-a63fd4`
**LLR target:**
- LLR-002.3 — `ValidationIssue.message` strips control characters and ANSI CSI sequences and truncates to 500 chars.
- Closes Phase 2 finding **S-005** (log-injection vector via embedded `\n[CRITICAL] cleared by admin\n`).
- Folds in Phase 2 deferral **Q-N02** (TC-090 split into TC-090.a / TC-090.b).
- Folds in iter-2 minor **S-N03** (rationale: rules needing detail beyond 500 chars must emit multiple `ValidationIssue` records — captured in the helper docstring).
- Folds in iter-2 minor **A-N04** (TC-090 numeric-block placement; doc-only — see §6).

## 1. What changed

- Added a private helper `_scrub_issue_message(message, max_length=500)` to `s19_app/validation/model.py`. Strips ANSI CSI escape sequences (`\x1b[...]`) first, then ASCII control characters (`\x00`–`\x1f` plus `\x7f` — covers `\n`, `\r`, `\t`, BEL, etc.), then truncates with the suffix marker `…[truncated]`. The marker counts toward `max_length`, so the returned string is always `<= max_length`. Idempotent on already-scrubbed and already-truncated input (re-truncation does not double the marker).
- Added `__post_init__` to `ValidationIssue` that calls `_scrub_issue_message(self.message)`. Centralising at construction time scrubs all 17 existing call sites (10 in `rules.py` + 7 in `engine.py`) at once with no per-rule changes.
- Added `class TestIssueMessageScrubbing` to `tests/test_validation_engine.py` with **6 new tests**, split per Q-N02:
  - **TC-090.a — control-char + ANSI scrub** (3 tests):
    - `test_strips_embedded_newlines_from_symbol_name` — the S-005 log-injection vector (`foo\n[2026-05-05] CRITICAL: cleared by admin\n`).
    - `test_strips_carriage_return_tab_and_bell` — `\r`, `\t`, BEL (`\x07`), and `\x01`.
    - `test_strips_ansi_csi_sequences` — `\x1b[31mRED\x1b[0m` → `RED`.
  - **TC-090.b — 500-char truncation** (2 tests):
    - `test_message_at_cap_passes_through_unchanged` — exactly 500 chars, no marker.
    - `test_oversize_message_truncated_with_marker_within_cap` — 600 chars truncated to ≤500 with marker, plus an idempotency assertion.
  - **Negative case** (1 test): `test_benign_message_passes_through_unchanged`.

  Each TC-mapped test method carries a `# TC-090.a` or `# TC-090.b` comment naming its TC ID. Tests assert both directly against the helper and through `ValidationIssue(message=…).message` to verify the `__post_init__` wiring.

No call site in `rules.py` or `engine.py` was modified — the centralised `__post_init__` approach makes File 3 (call-site routing) unnecessary.

## 2. Files modified

| File | Change |
|---|---|
| `s19_app/validation/model.py` | Added `import re`, the module-level regexes `_ANSI_CSI_RE` / `_CONTROL_CHAR_RE`, the constants `_TRUNCATION_MARKER` / `_DEFAULT_MESSAGE_MAX_LENGTH`, the `_scrub_issue_message` helper (full PROJECT_RULES.md docstring), and `ValidationIssue.__post_init__` calling it. `CoverageMetrics` and the rest of the module untouched. |
| `tests/test_validation_engine.py` | Added imports `from s19_app.validation.model import ValidationIssue, _scrub_issue_message` and the new `TestIssueMessageScrubbing` class with 6 test methods at the end of the file. Existing 3 tests untouched. |
| `.dev-flow/03-increments/increment-003.md` | This review packet. |

File count: **3** (within the ≤5 cap; aim of "1 product file + 1 test file + packet" met).

## 3. How to test

```bash
pytest -q tests/
```

Targeted run for the new class:

```bash
pytest -v tests/test_validation_engine.py::TestIssueMessageScrubbing
```

Direct helper sanity probe (optional):

```bash
python -c "from s19_app.validation.model import _scrub_issue_message; print(repr(_scrub_issue_message('foo\\n[CRITICAL] cleared\\n')))"
# expected: 'foo[CRITICAL] cleared'
```

## 4. Test results

Run on Windows 11 / Python 3.11 (system) / pytest:

```
$ python -m pytest -q tests/
......ss................................................................ [ 38%]
........................................................................ [ 76%]
.............................................                            [100%]
187 passed, 2 skipped in 4.79s
```

- **187 passed** (was 181; net +6 from the new `TestIssueMessageScrubbing` class).
- **2 skipped** (TC-047 NTFS-junction probe on non-Windows runners + the other pre-existing skip — unchanged).
- **0 failed.**
- No previously-passing test required modification — no test in the existing suite pinned a `ValidationIssue.message` byte string that would have been altered by the scrubber.

Targeted run:

```
$ python -m pytest -v tests/test_validation_engine.py::TestIssueMessageScrubbing
…
test_strips_embedded_newlines_from_symbol_name        PASSED
test_strips_carriage_return_tab_and_bell              PASSED
test_strips_ansi_csi_sequences                        PASSED
test_message_at_cap_passes_through_unchanged          PASSED
test_oversize_message_truncated_with_marker_within_cap PASSED
test_benign_message_passes_through_unchanged          PASSED
6 passed
```

## 5. Risks

- **Hidden message-text assertions elsewhere.** The full-suite run (187 passing, 0 failing) is the primary defence — no existing test asserted on a message containing scrubbable characters. If a future test pins a message body that contains `\n` / `\t` / `\r` / a NUL byte / an ANSI sequence it will need to update its expected value to the scrubbed form. This is the documented contract going forward.
- **Marker character set.** `…[truncated]` uses a non-ASCII ellipsis (`…`, U+2026, 1 character / 3 bytes UTF-8). The TUI Issues panel and the rotating logger both handle UTF-8; if a downstream consumer ever expected pure-ASCII messages they would observe the ellipsis. Trade-off: clearer marker vs. ASCII-purity. If pure ASCII becomes a requirement, `...[truncated]` is a one-character swap.
- **Idempotency vs. legitimate trailing marker text.** A message that legitimately ends in the literal string `"…[truncated]"` AND exceeds 500 chars will be re-truncated by stripping that suffix once before re-applying. This is intentional (idempotency) but means a rule cannot use that literal as plain content. Acceptable: the marker is reserved for the scrubber.
- **Non-`str` `message`.** The helper raises `TypeError` rather than coercing. If any rule ever passes a non-string by mistake, construction now fails loudly instead of producing a stringified-object message. Defensive but a behaviour change at the boundary; the test suite confirms no current rule does this.

## 6. Pending items

- **Q-N02 closure.** TC-090 has been split into TC-090.a (control-char + ANSI scrub) and TC-090.b (500-char truncation) in this increment's test code (each method tagged with a comment). The `01-requirements.md` §5.2 row currently still reads `TC-090`; doc-edit deferred to a Phase 1 light iteration or Phase 6 docs (consistent with the deferral schedule recorded in `02-review.md` §Deferrals for Q-N02 — "record split in the increment 4 packet" — increment-003 is the implementation increment that lands LLR-002.3).
- **A-N04 closure (partial).** A-N04 asked for TC-090 to be renumbered into the LLR-002.x block (suggested TC-015). After the Q-N02 split, TC-090.a/b live in the same numeric range. The renumber-to-TC-015 suggestion is still open as a doc-only minor and is folded with the §5.2 doc update mentioned above. Test code carries the `TC-090.a` / `TC-090.b` IDs as written; if §5.2 is later renumbered, the test comments are a one-line update.
- **S-N03 closure.** Rationale is captured verbatim in the `_scrub_issue_message` docstring: *"Rules that need detail beyond `max_length` characters shall emit multiple `ValidationIssue` records rather than rely on truncation (per LLR-002.3 / S-N03)."* No code enforcement needed beyond the cap itself.
- **S-N02 (256 MB cap rationale)** — out of scope for this increment; belongs to increment 1 (LLR-005.3) which already landed.
- **Q-N04 fixture-build allocation note (R-9)** — closed by increment 2.

## 7. Suggested next task

**Increment 4 — LLR-002.1 + LLR-008.x audit matrices and severity round-trip parametrised test** (`tests/test_color_policy_round_trip.py` plus the audit-matrix scaffolding under `.dev-flow/03-increments/`). Touches `s19_app/tui/color_policy.py` only if a divergence is found; primarily test + matrix work, well within the ≤5-files cap.

Alternative: **increment that lands the §5.2 doc edits** — fold the TC-090 → TC-090.a/b split into `01-requirements.md` and the A-N04 renumber. Pure documentation, ≤1 file, can be combined with any other doc-only fold-in deferred to Phase 6.

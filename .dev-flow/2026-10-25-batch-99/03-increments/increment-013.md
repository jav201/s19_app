# Increment 013 — batch-99 P4 suite fixes (tests only)

| Field | Value |
|---|---|
| Brief | `kimi/BRIEF-inc-13.md` + `kimi/BRIEF-COMMON.md` |
| Base | `47d1973` (detached worktree `s19_app-b99-inc13`) |
| Mode | tests-only increment — **no SOURCE file changed** (`git status --porcelain -- s19_app/` empty, re-verified at handoff) |
| Conditions discharged | F-1 re-pin (safe_text import census, LLR-160.2 measured-in), F-2 re-pin (patch-comfortable-120x30 snapshot, LLR-161.2 placeholder), C-40 mutation checks for both: F1 = the set entry removed → RED, F2 = the old SVG restored → RED (both reverted) |

## 1 · What changed

The full suite on `e7732f6` (`evidence/suite-full-e7732f6.txt`) had two
failures the batch caused on purpose; neither is a product defect. Both are
test re-pins:

1. **F1 — safe_text import census.** Inc-6 (`87dcd3a`, LLR-160.2) made
   `s19_app/tui/segment_split_view.py` render raw segment names and refusal
   messages through `safe_text` (the C-17 fold the census exists to track),
   but `MEASURED_SAFE_TEXT_CONSUMERS` in `tests/test_import_census.py` was
   never updated. Added `"s19_app.tui.segment_split_view"` to the set and
   extended the comment above it with one sentence in the batch-94 style
   (batch-99 Inc-6, LLR-160.2, measured in). No other set touched.
2. **F2 — Patch Editor snapshot placeholder.** Inc-11 (`5021bb6`, LLR-161.2)
   changed the Bytes placeholder from `DE AD BE EF` to
   `hex bytes, e.g. DE AD BE EF`, but the
   `test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` cell was
   never regenerated. Regenerated only that one cell with `--snapshot-update`
   and proved by SVG visible-text extraction that the only changed row is the
   Bytes placeholder row (`snapshot-text-diff.txt`).

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `tests/test_import_census.py` | test | LLR-160.2 | `MEASURED_SAFE_TEXT_CONSUMERS` += `s19_app.tui.segment_split_view`; comment sentence (LLR-160.2, measured in) |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg` | fixture | LLR-161.2 | single cell regenerated for the LLR-161.2 placeholder |
| `evidence/inc-13/*` | doc | — | evidence: RED/GREEN/mutation transcripts + snapshot text diff |

| Count | Value |
|---|---|
| **SOURCE files** | **0 / 4** — none: `git status --porcelain -- s19_app/` empty |

## 3 · How to test

```
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 \
  PYTHONPATH=<worktree> python -m pytest -p no:cacheprovider \
  tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py \
  tests/test_address_census.py
```
(import probe first: `python -c "import s19_app; print(s19_app.__file__)"` —
prints `C:\Users\jjgh8\Github\s19_app-b99-inc13\s19_app\__init__.py`.)

## 4 · Test results

- RED (unmodified tree): `test_tc653_safe_text_import_census` fails
  `extra=['s19_app.tui.segment_split_view']` (`red-tc653.txt`);
  `test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` fails
  (`red-snapshot.txt`).
- GREEN: `tests/test_import_census.py` 2 passed (`green-tc653.txt`);
  `tests/test_tui_snapshot.py` full file 33 passed / 29 snapshots passed,
  zero cells failing (`green-snapshot.txt`); `tests/test_id_registry.py`
  13 passed (`green-id-registry.txt`); `tests/test_address_census.py`
  23 passed (`green-address-census.txt`). No other snapshot cell fails,
  matching the `c62c842` bisect baseline in `evidence/suite-triage-e7732f6.md`.

### RED counterfactual

Both nodes were run against the unmodified tree first and failed with the
expected discriminating assertions (transcripts above); neither test passes
before the fix.

### Instrument RED-proof

Not applicable — no instrument (source) change in this increment; the two
re-pins are the oracle themselves.

### Emitted-form assertion

Not applicable — no emitted artifact change; the snapshot SVG is the only
fixture byte change and its visible-text diff is pinned in
`snapshot-text-diff.txt` (30 rows before, 30 rows after, exactly one changed
row: the Bytes placeholder `DE AD BE EF` → `hex bytes, e.g. DE AD BE EF`).

### Evidence files

| File | sha256 |
|---|---|
| `evidence/inc-13/red-tc653.txt` | 136e208a4038948a3b1dec6341bd0d37b4f626ad4b7764849c296724d7e98805 |
| `evidence/inc-13/red-snapshot.txt` | 6f09a0751f1fa48dddab6e40176ea210a563c22f1f572181176bfdd34372ed14 |
| `evidence/inc-13/green-tc653.txt` | 007b36bb5dc5d15ebe7964acadfc10cc9021adefee329c1e77231fa18f8b3d48 |
| `evidence/inc-13/green-snapshot.txt` | bbf039d46da172279395ca6b7d2ff2c274fd7af45a7018cb1cb4856b13551cbd |
| `evidence/inc-13/green-id-registry.txt` | 10ea027a5a888bf32406aeb871eaef08d420cb9234259096509cb5147623f61a |
| `evidence/inc-13/green-address-census.txt` | e6130d7fcfee514aed5791969b8826bee829073876654ffb9e407b08cf2b6cf6 |
| `evidence/inc-13/mut-F1.txt` | d9d796404dc89161d4929c3c3a73e7fb9fb7c16f5ac62f4602888808d1ee81e0 |
| `evidence/inc-13/mut-F2.txt` | 125d736b5cec4f4b81a74a3c293afe3221a2b54a4ddac463815fadd9ea1d6f63 |
| `evidence/inc-13/snapshot-text-diff.txt` | a08bb1e1e32b4d82c8f13e070b20f2830395eef011d76f86cc36dc2be4fcd39a |

### Load-bearing emptiness

`git status --porcelain -- s19_app/` is empty (re-verified at handoff) — zero
SOURCE files changed, as the brief requires.

### Reverse census

- `grep -rln MEASURED_SAFE_TEXT_CONSUMERS tests/`: only
  `tests/test_import_census.py` (definition + its own assertion) — no other
  consumer pinned the old set.
- `grep -rn "DE AD BE EF|hex bytes" tests/`: the placeholder string appears in
  many tests as patch-entry data, not as placeholder pinning. The only test
  pinning the placeholder text itself is
  `tests/test_b99_bytes_field.py::test_tc_b99_33_field_and_help_state_the_hex_rule`
  (TC-B99-33, LLR-161.2, Inc-11's own TC), which already asserts the NEW
  placeholder (`"hex" in placeholder`) and passed on `e7732f6` — consistent
  with the regenerated snapshot, no re-pin needed.
- The snapshot SVG is consumed only by the textual-snapshot plugin via
  `tests/test_tui_snapshot.py`; no other cell was regenerated.

Re-pin ledger:
- `tests/test_import_census.py::test_tc653_safe_text_import_census` (`MEASURED_SAFE_TEXT_CONSUMERS`) — set of
  5 → set of 6 (adds `s19_app.tui.segment_split_view`) — LLR-160.2 measured-in
  (batch-99 Inc-6).
- `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` — SVG cell
  Bytes row `DE AD BE EF` → `hex bytes, e.g. DE AD BE EF` — LLR-161.2
  (batch-99 Inc-11).

### Correction population

Both failures from `evidence/suite-full-e7732f6.txt` are addressed; no other
failures existed in the triage (`evidence/suite-triage-e7732f6.md`), so the
correction population is exactly {F1, F2}.

### Signed-balance test ledger

No test defs added or deleted (`grep -c "^def test_"` unchanged:
`tests/test_import_census.py` 2 → 2, `tests/test_tui_snapshot.py` 33 → 33).
Net **0 defs**; collected-node count unchanged. No new test module, so
`EXPECTED_SCANNED_TEST_FILES` needed no bump (`tests/test_id_registry.py`
13 passed).

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | code-reviewer — spawned as an independent agent · OK to advance, with notes · no HIGH; MEDIUM F1 (red-tc653 sha256) and LOW F2–F5 (packet text) fixed in this packet by the orchestrator; re-pins checked against 87dcd3a/LLR-160.2 and 5021bb6/LLR-161.2; SVG diff = placeholder text + 2 implied rects only; 48 passed / 29 snapshots on 47d1973+diff |

## 5 · Risks

- The regenerated SVG could in principle drift in non-text ways (ids, classes);
  the text-diff check covers the visible contract, and the full snapshot file
  (33 cells) is green, so no other cell drifted.
- `tests/test_import_census.py` is LF in HEAD and in the worktree (351 lines,
  0 CRLF); the `mut-F1` round-trip left it LF. The regenerated SVG came out
  CRLF and the orchestrator normalised it to LF, as `.gitattributes` requires
  for `tests/__snapshots__/**/*.svg` (0 CRLF after).

## 6 · Pending items / spec deviations

None. Both brief items done exactly as specified; no other snapshot cell
touched; no source touched; nothing committed (working tree left for the
orchestrator).

## 7 · Suggested next task

Orchestrator: independent review of this increment, then re-run the full suite
on the merged tree to confirm `suite-full` is fully green (F1 and F2 were the
only failures on `e7732f6`).

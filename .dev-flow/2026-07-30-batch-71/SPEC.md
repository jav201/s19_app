# batch-71 — AC-6's byte-golden (`/fast-dev-flow`)

- **Route:** `/fast-dev-flow` — test-only, two files, no production code.
- **Branch:** `claude/ac6-byte-golden-batch-71`, cut off `origin/main` `6d1b316`. **RC-1 PASS** (HEAD = merge-base = `origin/main`, tree clean).
- **Flow revision:** `2026.07.28-rev1` · `flow_hash 0127a2767ff11c8a` — verified current (C-45 PULL).
- **Approval:** **autonomous until the PR** — asked at THIS kickoff, not inherited from batch-70.
- **Ids:** `AT-212`, `TC-509` — measured prior max `AT-211` / `TC-508`, restricted to `*.py`/`*.md`.

## Objective

Close the one carry batch-70 left on its own headline claim. `R-TUI-099` says *"a run left at the
default scope shall be unchanged from the single-image path."* batch-70 shipped that with a
**structural** guard only and recorded the missing byte-golden as an explicit non-claim. Close it
with a real one.

## §2.7 Premise evaluation (C-43)

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | `f1f3987` is the commit immediately before FB-P2 merged, so it is the correct pre-change baseline. | premise | ✅ TRUE | `git log --format="%h parent=%p" -1 b457ef8` → `b457ef8 parent=f1f3987`. | The golden is captured from that tree. |
| P-2 | **A byte-golden of the report COMPOSER would prove AC-6.** | hypothesis | ❌ **FALSE** | `git diff --stat f1f3987 origin/main -- s19_app/tui/services/flow_report_service.py` → **0 lines**. The composer is byte-untouched, so a golden over it **cannot fail**. | **BLOCKS the obvious design.** The golden is taken **end-to-end through `run_flow`** instead — see P-3. |
| P-3 | The unscoped path *was* edited, so an end-to-end golden has teeth. | premise | ✅ TRUE | `git diff --stat f1f3987 origin/main -- …/flow_execution_service.py` → **+263 / −5**. Two deletions are on the unscoped SOURCE path: `ctx.project_dir, block.image_ref,` and `if block.file_type == WRITE_FMT_HEX:`, now routed through `_bound_source_ref`. | The golden drives `run_flow` over **every block kind**. |
| P-4 | The project has a golden convention to reuse rather than invent. | premise | ✅ TRUE | `tests/goldens/{batch35,batch64}/` exist; `_GOLDEN_DIR = Path(__file__).parent / "goldens" / "batchNN"`; `.gitattributes:9` → `tests/goldens/** text eol=lf`; shared comparator `conftest.canonical_report_bytes` (`tests/conftest.py:970`). | Followed exactly; comparator **reused, not forked**. |
| P-5 | The produced report is location-independent (no host path can reach it). | premise | ✅ TRUE | Captured golden scanned: 0 hits for `[A-Za-z]:[\\/]`, `/(Users\|home)/`, `AppData\|Temp`, `<RUN-ROOT>`; 0 CRLF; 710 bytes. | Safe to commit and to compare in Linux CI. |
| P-6 | `AT-212` / `TC-509` are free. | premise | ✅ TRUE | Census over `*.py`/`*.md` **excluding the new file** (else it measures itself): prior max `AT-211` / `TC-508`. | Allocated. |

**Gate rule applied.** One ❌ — P-2 — and it **changed what got built**, before any code. A golden aimed
at the composer would have been a textbook vacuous check: green forever, proving nothing.

## What ships

| File | Role |
|---|---|
| `tests/goldens/batch71/ac6-unscoped-flow-report.md` | 710-byte golden, captured by driving the fixture on a detached worktree at **`f1f3987`** |
| `tests/test_flow_report_ac6_golden.py` | `AT-212` byte-identity · `TC-509` fixture-coverage guard · `TC-509b` stored-blob LF/shape guard |

The capture and the comparison build the **same fixture**, so a drift in the fixture cannot be
mistaken for a drift in the product.

## Falsifiability — executed, not asserted

`AT-212` passed on first run, which on its own proves nothing. It was driven **RED on a copy of the
fixed tree** with a mutation representing the exact regression AC-6 exists to catch — the variant
dimension leaking into the default path (`flow_name=f"{flow.name} [{ctx.variant}]"` in `run_flow`'s
REPORT branch):

```
>       assert produced == golden, (
E       AssertionError: the unscoped flow report drifted from the pre-FB-P2 golden.
E         --- produced ---
E         # Flow report — ac6 unscoped golden \[None\]
```

It fails **on the byte assertion**, with the drift shown inline.

## Verification

| | |
|---|---|
| New nodes | 3 — `AT-212`, `TC-509`, `TC-509b` |
| Collected | 2355 → **2358** (`+3`, exact — no auto-parametrised surprise) |
| Flow suite (`-k flow`) | **208 passed** |
| Frozen guards (C-27, both arms) | `test_engine_unchanged.py` **1 passed** · `test_tui_directionb -k tc031/tc032/engine` **6 passed** |
| Lint | `ruff check tests/test_flow_report_ac6_golden.py` → **All checks passed** |
| Production code touched | **none** — `git diff --stat origin/main -- s19_app/` empty |

## Self-catches

| # | Caught | Where |
|---|---|---|
| 1 | **P-2** — a golden over the composer cannot fail; the composer is byte-untouched | before any code |
| 2 | The carry's proposed baseline (`origin/main`) is **circular** — it already contains the change under test. Captured from `f1f3987` instead | before any code |
| 3 | The capture script's warm-up run wrote no report (no REPORT block), so its `len(reports) == 2` assertion was wrong; and its `sys.path` pointed at the scratch dir, not the repo | writing the capturer |
| 4 | The id census reported max `AT-212`/`TC-509` — **it was measuring the new file itself.** Re-run with `--exclude`, the true prior max is `AT-211`/`TC-508` | id allocation |
| 5 | **A leak-check predicate that did not test what its label claimed.** `od -c \| grep -c '\r'` reported *17 CR bytes* in the stored blob. In BRE the pattern collapses to the letter `r`, so it counted `od` output lines containing an "r". Re-measured with `git cat-file -p :<path> \| tr -cd '\r' \| wc -c` → **0**. | staging |

**#5 is the one worth keeping.** Two project rules met in a single command: *a predicate must test what
its LABEL claims*, and *assert the stored blob, not the file you handed git*. The second half was
right — checking `git cat-file` rather than the working file is correct, and the blob is what CI
reads. The first half was wrong, and it produced a confident, specific, entirely fictional number.

## What this does NOT close

- **The other two batch-70 non-claims stand:** the fused document's `O(V × ~6 lines)` heading
  overshoot outside the byte budget, and per-variant caps bounding rows rather than bytes. Untouched.
- **The golden pins ONE flow shape.** It covers every block *kind*, but not every ordering, gating
  mode or failure path. A regression that only manifests on, say, an aborting SOURCE would not move
  these bytes.

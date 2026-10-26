# HANDOFF-fix — batch-99 Increment 6, review round 1 (F1–F7) — COMPLETE

## What was done
Fixed all seven review findings from the code-reviewer + security-reviewer
pass, per `.dev-flow/2026-10-25-batch-99/kimi/BRIEF-inc-6-fix.md`, on top of
the reviewed (uncommitted) inc-6 tree. No commits made.

- **F1 (HIGH)** — `_PlacedExportPath` `Path` subclass removed (crashed on
  Python 3.12+: `__init__` skipped `super()` → `_raw_paths` unset →
  `.name` AttributeError after the files were placed). Replaced with a plain
  `@dataclass PlacedExport(path, action)`; the status handler and all tests
  read the new surface.
- **F2** — the collision refusal reason now carries only sanitised final
  names plus each raw name through `safe_text` clipped to 80 (ESC/300-char
  names can no longer reach the notice or the status); the pair uses the
  row's own `other_part` instead of an index-0 rebuild.
- **F3** — the part-way failure message is truthful:
  `Export stopped: <reason>. Already written: A, B; reused: C`, and
  `ExportWriteError.written` lists only `wrote`-action paths.
- **F4** — the plan-time length pass measures every final path with the
  worst-case `_99` suffix AND every private staging path
  (`<root>/temp/.staging/stage-XXXXXXXX/<name>`); `_EXPORT_SUFFIX_ROOM`
  reserves two digits so N ≥ 10 stays inside the 200-char basename cap.
- **F5** — the payload is staged via `workspace._private_stage_dir`
  (LLR-155.1), not the system `%TEMP%`; the `tempfile` import left the view.
- **F6** — `dest_dir = self._dest_dir()` moved inside the try: a junctioned
  project home renders the painted refusal instead of crashing the app.
- **F7** — each placement failure branch pins `failed_path = claim_path`
  before its rollback loop (the loop rebinds `claim_path` to the group's
  last claim) and names `failed_path` in the message. The loop variable
  keeps its name because the TC-B99-39 source census binds `claim_path` to
  the `O_EXCL` claim.

## Verification (all transcripts in `evidence/inc-6/`, sha256 in
`sha256-fix.txt`)
- Import proof: both interpreters import this worktree (import-check line
  preserved in the session; `s19_app.__file__` under the worktree).
- **RED**: `red-fix-f1-py312.txt` — 3.12 AttributeError (`_raw_paths`)
  before the fix; every new arm's docstring records its RED shape.
- **GREEN 3.11 (s19env)**: export 24, staging 23, split-window 56,
  address-census 23, id-registry 13 — all passed.
- **GREEN 3.12.13 (mapperenv, Textual 8.2.8)**: export 24 passed — the F1
  proof end-to-end. (pytest 8.4.2 installed into mapperenv for this run.)
- **Mutations (C-40)**: F1 mutant (subclass restored) KILLED on 3.12;
  LLR-160.1, LLR-160.4, LLR-160.5 re-run (they touch changed code) — all
  KILLED; LLR-160.2/160.3 not re-run (their code is untouched). Every
  mutant reverted; both source files hash-equal to the fix-round baseline
  (`baseline-hashes-fix.txt`, `revert-fix-muts.txt`).
- **Reverse census**: `tests/test_segment_split_window.py` (8 nodes) and
  the export tests re-pinned to the `PlacedExport` surface; TC-B99-28
  boundary re-pinned 194/`_1` → 193/`_99` (F4). TC-B99-39 census kept
  green (F7 fixed via `failed_path`, not a rename).

## State of the tree
- SOURCE (2/3): `s19_app/tui/segment_split_view.py`,
  `s19_app/tui/workspace.py`. `segment_ops.py` untouched.
- Tests: 8 new arms in `tests/test_b99_export.py` (no new module — the
  scanned-file count stays 210); `tests/test_segment_split_window.py`
  re-pinned to the dataclass surface. `tests/test_b99_staging.py` and
  `tests/test_id_registry.py` carry only the previous session's changes.
- Packet: `increment-006.md` gained the §6b "Review round 1 fixes"
  subsection with the evidence table; §4b stays `pending — orchestrator`.
- CRLF preserved in `segment_split_view.py` (2127/2127 lines);
  `workspace.py` is LF by pre-existing convention.
- Final source digests:
  `segment_split_view.py a7559269a96e8d418be8dce449589903a703d932854520f987c03d1a78b69114`,
  `workspace.py de7564027c8a4d09ef2319f95751f5fb4de5cd7ae584e2d2e3c46bd847bbf5d7`.

## Left for the orchestrator
1. Independent review (§4b) of the fix round and the increment gate.
2. The full suite (about 2 h 20).
3. The commit.

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/segment_split_view.py, s19_app/tui/workspace.py, tests/test_b99_export.py, tests/test_segment_split_window.py, .dev-flow/2026-10-25-batch-99/03-increments/increment-006.md (§6b), evidence/inc-6/* (13 new transcripts + sha256-fix.txt).
Tests added: 8 arms — F2 collision scrub/clip/index, F4 over-long second segment (0 files) + `_99` boundary re-pin, F5 private staging, F3 part-way message (unit + painted-status pilot), F6 junctioned-home refusal (pilot), F7 failing-member name.
RED/GREEN: RED = F1 on 3.12 (`_raw_paths` AttributeError) + 8 new arms' recorded RED shapes; GREEN = 24 export (3.11 AND 3.12) + 23 staging + 56 split-window + 23 address-census + 13 id-registry.
Mutations: 4 run, 4 KILLED (F1 subclass-on-3.12, LLR-160.1 bypass, LLR-160.4 per-file `_<N>`, LLR-160.5 collision-in-write-loop), all reverted and hash-verified against the fix-round baseline.
Open questions: none — LLR-160.2/160.3 mutants intentionally not re-run (untouched code); §4b review and the full suite are the orchestrator's.

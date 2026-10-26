# Kimi brief — batch-99 Increment 6 · review fixes (code-reviewer + security-reviewer)

Read `BRIEF-COMMON.md` from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`). Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc6` (uncommitted, on `f1ba70c`). Do not commit. Source budget: `segment_split_view.py`, `segment_ops.py`, `workspace.py`.

**Two interpreters this time.** Run `tests/test_b99_export.py` on BOTH:
- `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe` (3.11);
- `C:\Users\jjgh8\anaconda3\envs\mapperenv\python.exe` (3.12.13, Textual 8.2.8).

Set `PYTHONPATH=<worktree>` for both. The project declares `requires-python >= 3.11`.

- **F1 [HIGH, both reviewers] — `_PlacedExportPath` (a `Path` subclass, `segment_split_view.py:≈565-573`) breaks on Python 3.12+.** Its `__init__` does not call `super().__init__`, so `_raw_paths` is unset and `.name` raises `AttributeError`. On 3.12 an export places its files and then crashes the app (the status line at `:≈2035`, outside the handler's try; `:≈906-908`). Remove the subclass: return plain `Path`s and carry wrote/reused separately (a small dataclass or an `actions` list). Prove it with `tests/test_b99_export.py` GREEN on 3.12 and a RED transcript on 3.12 before the fix.
- **F2 [MEDIUM, both] — the collision reason embeds raw segment names, unscrubbed and unclipped** (`:≈857-860`, `:650`, `:1995`). Control bytes such as ESC and 300-character names reach the notice and the status. Put only the sanitised names, plus each raw name through `safe_text`, clipped to 80 characters, in the reason. Add a TC arm with an ESC byte and a 300-character name in a colliding pair. Also fix `:860`, which passes index 0 instead of the row's index (LOW).
- **F3 [MEDIUM, code] — the part-way failure is untested, and its message contradicts itself** (`:≈908`: "…Nothing written. — files already written: X", where X may include reused files). Word it truthfully, e.g. `Export stopped: <reason>. Already written: A, B; reused: C`. Add a TC that forces a failure on the second file and asserts the painted status names the first.
- **F4 [MEDIUM, both] — the path-length check misses real paths.** The 260 check at `:≈845` skips the `_<N>` suffix, and the staging paths (`:≈869`, then `<workarea>/temp/.staging/tmp*/…`) are longer than the final path. Check every final path including the worst-case `_<N>`, and every staging path, at plan time. Also handle `_<N>` with N ≥ 10, which yields a 201-character basename (LOW): reserve the suffix width in the 200 cap. Add an arm where a 300-character name as the SECOND segment refuses before anything is written (0 files).
- **F5 [LOW, security] — the payload is staged in system `%TEMP%`,** not in the work area's own staging folder (LLR-155.1). Stage it through the work area's private staging helper (`_private_stage_dir` in `workspace.py`).
- **F6 [LOW, security]** — `:≈1968` calls `_dest_dir()` outside the try, so a junctioned project home crashes the app instead of showing a refusal. The bug predates this increment, but the fix is one line: move the call inside the try and add an arm.
- **F7 [LOW, code]** — `workspace.py:≈916/977/992`: the loop variable `claim_path` shadows the failing name in the error messages. Rename it so each message names the real path.

After the fixes:
1. Run `tests/test_b99_export.py` on 3.11 and 3.12, plus `tests/test_b99_staging.py`, `tests/test_segment_split_window.py`, `tests/test_address_census.py` and `tests/test_id_registry.py` on 3.11.
2. Re-run the mutations that touch changed code, plus a new one for F1 (restore the subclass → 3.12 RED).
3. Update the packet with a "Review round 1 fixes" subsection.
4. Finish with `HANDOFF-fix.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.

Keep test runs targeted: the previous session hit the 90-minute timeout.

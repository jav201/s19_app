# Kimi brief — batch-99 Increment 1 · review fixes (code-reviewer findings F1–F5)

Read `BRIEF-COMMON.md` first. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc1`, on branch `b99-wip` (Inc-1 is committed there as `e4c4324`). Do not commit; leave the changes in the working tree.

The independent code review returned **changes required**. Fix exactly these findings:

- **F1 [HIGH] — `LSB_FIRST` is not an ASAM BYTE_ORDER token.** The tokens are `MSB_FIRST`, `MSB_LAST`, `BIG_ENDIAN` and `LITTLE_ENDIAN` (`s19_app/tui/a2l.py:280-286` returns `None` for `LSB_FIRST`). In `tests/fixtures/synth/generate.py` (≈ line 186) and the generated `synth_a2l.a2l` (≈ line 97), the LINEAR control must declare `BYTE_ORDER MSB_LAST` on its RECORD_LAYOUT or tag, and stay little-endian (`0F 00`) under the `MSB_FIRST` module. Update the manifest's `byte_order` for that symbol to `MSB_LAST`. The contract was amended to match (LED-2026-10-25-batch-99.4, LLR-158.1 in `01-requirements.md`). Fix the packet's "canary" text (≈ line 260) accordingly.
- **F2 [MEDIUM] — COMPU_TAB blocks must follow the ASAM grammar** (`generate.py` ≈ 158–165). Remove the stray Format/Unit pair `"%6.2" ""`. `DEFAULT_VALUE` follows the value pairs and is quoted where the grammar requires it. Model the block on the COMPU_TAB layout in a real ASAP2 example: search `examples/` for `/begin COMPU_TAB` (the reviewer cited an ASAP2 demo file at line ~2965; find it with `grep -rn "begin COMPU_TAB" examples/ tests/`) and follow that exact field order: name, long identifier, conversion type, number of pairs, the pairs, then an optional `DEFAULT_VALUE`.
- **F3 [MEDIUM] — the limits must not equal the table ranges** (`generate.py` ≈ 179, 182). Widen the COMPU_TAB symbols' lower/upper limits strictly beyond the table ranges (e.g. −10..100 and 0..30), so a later test can tell "outside the table range" apart from "outside the limits". Update `a2l_expect` if any recorded value depends on them.
- **F4 [LOW] — `_hex_content` (≈ line 92) duplicates the reader's 02/04 address arithmetic,** so the HEX manifest check is common-mode. Add a test in `tests/test_b99_corpus.py` that pins the HEX files' extents LITERALLY (hard-coded expected `(start, end)` address runs written by hand from the spec, including the type-02 wrap case and the 64 KiB boundary case), not computed by the generator.
- **F5 [LOW] — evidence hygiene.** Rewrite `SHA256SUMS.txt` in the evidence folder with LF line endings, exclude the sums file from its own list, and hash the files exactly as committed (`git show HEAD:<path> | sha256sum` style, or note explicitly that hashes are of the working-tree bytes and why).

After the fixes:
1. Regenerate the corpus and re-run `python tests/fixtures/synth/generate.py --check`.
2. Re-run `tests/test_b99_corpus.py` and `tests/test_address_census.py`, saving transcripts as `green-fix-*.txt`.
3. Re-run the three C-40 mutations, plus one for F4 (break the reader's segment wrap → the new literal test goes RED).
4. Update the packet `.dev-flow/2026-10-25-batch-99/03-increments/increment-001.md`: add a "Review round 1 fixes" subsection listing F1–F5 with what changed, and update the Evidence files table.

Finish with `HANDOFF-fix.md` in the worktree root, ending with `__KIMI_UNIT_DONE__` and a 5-line summary.

# Kimi brief — batch-99 Increment 6 · US-149 / HLR-160 · exports stay inside their destination and invent no byte

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-160, LLR-160.1, 160.2, 160.3, 160.4, 160.5; TC-B99-28..31, 41; AT-B99-11. Design: `design/design-proposal-b99.md` §4 rows B99-I2a and B99-I6.

PDR conditions (`design/PDR-2026-10-25-batch-99.md`): **C3/PQ-1, PQ-2, PQ-3, UX-C10, UX-C11**. Read the detail in `design/PDR-architect.md`, `PDR-qa.md` and `PDR-ux.md`. D8 is provisional on `sufijo` (next free `_<N>`). The orchestrator confirms the operator's verdict before this increment starts; if the verdict differs, this brief is amended.

## SOURCE files (max 3)
`s19_app/tui/segment_split_view.py`, `s19_app/segment_ops.py`, `s19_app/tui/workspace.py`.

## What to build
1. **One sanitiser** (LLR-160.1):
   - keep ASCII `[A-Za-z0-9_-]` only, and map every other character to `_`;
   - prefix `_` to Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9` including the superscript digits `¹²³`, `CONIN$`, `CONOUT$`; case-insensitive, compared before any extension);
   - cap the segment part at 100 characters, and clip the stem so the final basename (`_<N>` and extension included) is ≤ 200;
   - an empty result becomes `segment_<index>`.

   The same name builds the BIN `.addr` sidecar.
2. **Plan-time pass** (LLR-160.5): compute every final name, sidecars included; compare them case-folded; check full path length. Refuse the whole export before any byte is written, naming the colliding segments or the refused name.
3. **Containment** (LLR-160.2): before any `mkdir`, pass the destination home through the shipped guard `_check_home_contained` (`project_gather_service.py:200`; call it from `segment_split_view`), anchored to the work-area root. Resolve each final path inside it, and refuse an existing link or reparse point at a final name. The refusal renders the segment name literally (`safe_text`, `notify(..., markup=False)`), clipped to 80 characters, next to the sanitised name.
4. **Byte source** (LLR-160.3): take bytes from the image's declared `ranges`, never from MAC placeholder entries, so a MAC-only session writes header-only S19/HEX.
5. **Group placement B99-I2a** in `workspace.py`: `place_group_into_workarea(sources: Sequence[Path], destination: Path, *, max_size_bytes: int | None = None) -> list[Path]`. It uses one private staging dir and claims one `_<N>` for EVERY name of the group with `O_EXCL` before writing any. Then it runs `os.replace` per file. It reuses the group only when every file is byte-identical and non-empty. On any failure it rolls back every own claim and placed file, and raises `WorkareaPlacementError`. `segment_ops` writes into the staging dir and NEVER imports `tui.workspace`; `segment_split_view` calls the function. Single files go through `copy_into_workarea`.
6. **Status** (UX-C11): lead with the outcome (`Export refused: …` / `Exported 3 files: …`), use the words `wrote` / `reused`, name the actual `_<N>` names, and on a part-way failure name the files already written.

## Tests — `tests/test_b99_export.py`
- TC-B99-28 (sanitiser over the full hostile set in HLR-160's threshold).
- TC-B99-29 (containment; junction destination — on Windows create one with `mklink /J` via `subprocess`, skip with a stated reason if not permitted; existing-symlink-at-final-name arm).
- TC-B99-30 (MAC-only → 0 data records, independent reader).
- **TC-B99-31** (`_<N>`):
  - changed bytes → `<name>_1`; BIN pair → `<name>_1.bin` + `<name>_1.addr`;
  - **PQ-2:** an orphan `_1.addr` fixture already present → the pair takes `_2` for both (the per-file `_<N>` mutant goes RED only with this fixture);
  - a mismatched-sidecar reuse arm → not reused;
  - a forced-failure arm → rollback leaves 0 own files;
  - identical bytes → reused.
- TC-B99-41 (plan-time collisions `SegA`/`sega`; one refused name; an over-long path → 0 files).
- **PQ-3:** extend TC-B99-39's delete census (in `tests/test_b99_staging.py`) to cover `place_group_into_workarea`.
- **UX-C10:** one hostile-name TC for the export file / segment-name sink (`[red]x[/red]`, `[@click=app.quit]` → 0 markup spans).
- **AT-B99-11** (pilot, Split/Join/Export window):
  - an A2L segment `x/../../../ESCAPED` → the file lands inside the destination under a sanitised name, and nothing appears outside;
  - a MAC-only export → no data record;
  - a second export after a patch → `<name>_1`, the status names it (UX-C11), the first file is intact.

  RED on today's tree (P-11).
- Mutations: bypass the sanitiser; a destination-rooted containment check; MAC placeholders as data; per-file `_<N>`; the collision check inside the write loop. Revert each one.

## Reverse census
`grep -rln "segment_split_view\|write_split_join_export\|write_bin_with_sidecar\|segment_ops\|splits" tests/`. Re-pin only what HLR-160 changes.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-006.md`, REQ-ID `HLR-160`.

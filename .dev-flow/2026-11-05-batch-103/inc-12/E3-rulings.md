# Inc 12 — E3 rulings (orchestrator, claude-opus-5-5, 2026-11-07)

Authority for the E3 correction pass. Sources: `E3-architect.md` (FAIL: 1 MAJOR, 4 MEDIUM, 3 MINOR, 1 LOW, 1 INFO) and `E3-security.md` (FAIL: 1 MAJOR, 1 HIGH, 1 MEDIUM, 3 MINOR, 1 INFO). Neither lens asks for a redesign. Every finding is ruled below; "accept" means apply the finding's fix column as written, unless the ruling says otherwise.

## Security

| Finding | Ruling |
|---|---|
| E3S-01 MAJOR | **Accept.** New row **R-TUI-042a.6** (If), in the finding's wording: before the cut, each character of a tag name outside U+0021 … U+007E is shown as U+FFFD; the cut is then plain slicing, O(*w*). Threshold and cases: the 4,000 / 16,000 × U+200B tail, a combining-mark tail and an ESC tail, each within the row's bound on one call; a plain ASCII name painted unchanged (negative control: the raw-name `cell_len` loop → the 16,000 case exceeds the bound → RED). Same rule as READ.66 and R-A2L-DEF.137; cite both. Update `_shorten_tag_name` in the graph. |
| E3S-02 HIGH | **Accept, folded into Inc 12** (the card is what Inc 12 asks the operator to trust for the full name). New row **R-TUI-042a.7** (If): a file-derived value of the tag detail card holding ESC or U+009B → the screen output holds neither; every file-derived value of `_a2l_detail_card_text` and `_card_field` built with `safe_text`. Add the node change to the graph (same file, `app.py`; the slice stays one source file). Re-point AT-069b as the fix column says. Mutant "raw `Text.append`" → RED goes to E5's table. |
| E3S-03 MEDIUM | **Accept** (with E3A-04). Correct E2-7 and "What else the operator sees" with the measured counts; AT-B103-I12-2 adds ASAP2_Demo_V171 at 80×50, labelled "shortened names can read alike; the Address and the card tell them apart". No new row. |
| E3S-04 MINOR | Closed by R-TUI-042a.6. Record that, nothing else. |
| E3S-05 MINOR | **Ruled with E3A-07: removal.** See E3A-07. |
| E3S-06 MINOR | **Accept.** AT-069c stays on the Tag cell, with payloads placed where they fit and one across the cut; exact shortened text, no spans, no control character. Mutant `Text.from_markup` → RED to E5's table. |
| E3S-07 INFO | Accept the note: the no-loop note cites the run-time pin `textual>=8.2.8,<9`. |

## Architecture / UX

| Finding | Ruling |
|---|---|
| E3A-01 MAJOR | **Accept (1)–(4).** (1) I-12.1 names b101 Inc 10b's `_repaint_a2l_tag_cells` as a consumer that passes the name width (the one-line change is made at the rebase). (2) New case R-TUI-042a.5/7 as written. (3) **Sequencing:** Inc 12's E4 starts only on `batch-103` rebased onto a `main` that holds b101 Inc 10b. (4) The fit's rewrite step becomes the in-place `_repaint_a2l_tag_cells()`. |
| E3A-02 MEDIUM | **Accept.** Cases R-TUI-042a.5/8 and /9 as written; R-TUI-042a.5 threshold → 15/15 with /7. AT-B103-I12-1 wording as written. |
| E3A-03 MEDIUM | **Accept.** Pin the class chain in I-12.2: `class A2LTagTable(_CopyRowTable)` once Inc 1b lands (or the handler in `A2LTagTable` itself). Append one note to `../inc-1b/E1-rulings.md` beside D-3: R-COPY.4/3's expected result is the row's tag's full name (`_a2l_row_key_to_tag`), and Inc 1b's E5 regression set includes R-TUI-042a.5/6. |
| E3A-04 MEDIUM | **Accept, no floor.** D-1 A's reason is restated as measured (all but 46 tracked tags distinct at *w* = 34, all but 293 at *w* = 14, fails at *w* ≤ 12). If the operator objects at AT-B103-I12-2, the remedy is layout (Inc 7, PLAN backlog 5), not Inc 12. |
| E3A-05 MEDIUM | **Accept, routed.** Record beside BL-I11-3 / PLAN backlog 5 for Inc 7. Add the left edge to E1's "Not decisions" sentence. One mid-scroll capture in AT-B103-I12-2, labelled "exists on `e07fb00` at the pane edge". |
| E3A-06 MINOR | Accept with E3A-01 (4): the cursor / `scroll_x` / `scroll_y` save-restore and `move_cursor` leave the node. |
| E3A-07 MINOR | **Accept removal** (over E3S-05's "at most 17 digits"). Reason: an address above 2^64 − 1 is not a memory address; reading it as one is a reader defect, and the operator rules A2L reading as the high-risk area. Inc 11 addendum row **R-A2L-READ.69** (If): "If a tag's address word is above 0xFFFFFFFFFFFFFFFF, then the system shall give the tag no address." Mirror R-A2L-READ.38's form and cases: `ECU_ADDRESS 18446744073709551616` and `ECU_ADDRESS 99999999999999999999` give no address, `ECU_ADDRESS 18446744073709551615` keeps it; negative control: the check removed → the 20-digit word gives an address → RED. Check the id is unused across `inc-*/` first. With it, CTX *Address* "at most 16 hexadecimal digits" stays true; I-12.4 pins both bounds (Address cell ≤ 18 characters, Length cell ≤ 7) as Inc 11 outputs R-TUI-042a.4 relies on. |
| E3A-08 MINOR | Accept. |
| E3A-09 LOW | Accept: add the termination sentence to the fit node's contract. |
| E3A-10 INFO | — |

## Questions routed from E2

- **E2-4:** (a), as both lenses agree.
- **E2-5:** accept both texts; at 118 columns with a scrollbar and a 64-bit address *w* is 29, not 31 — correct it.
- **E2-6:** the red list is complete for its files; add b101 Inc 10b's and Inc 1b's tests to it.
- **E2-7:** no floor.

## After the correction

E3 round 2, both lenses, on the corrected records only (the changed rows, nodes and cases, plus R-A2L-READ.69 in Inc 11). Inc 12's E4 waits for the rebase in E3A-01 (3).

## Round 2 rulings (2026-11-07, orchestrator claude-opus-5-5)

Both lenses FAIL, with no redesign asked and round-1 findings closed as ruled.
- Architect: E3A-11 MAJOR, E3A-12 MEDIUM, E3A-13/-14 MINOR, E3A-15/-16 LOW, E3A-17 INFO.
- Security: E3S-08 MAJOR, E3S-09 MEDIUM, E3S-10/-13 MINOR, E3S-11/-12 LOW.

**One rule for file text on this screen**, which settles E3A-11 against E3S-10:
- **The Tag cell shows a *painted tag name*.** A new CTX term, like canon's *painted name*: each character outside U+0021 … U+007E shown as U+FFFD, then the middle cut of .3 / .5. The Tag cell of the tag table becomes a scoped exception to R-TUI-103a and R-TUI-103.1, recorded as a canon note beside CTX-TEXT's *painted-name views*.
  - **Why:** the cell is a fixed-width cell for A2L identifiers, and the projection keeps the cut O(*w*). A name holding such a character is already a parse error after Inc 11 (READ.4), and 0 of 234,654 tracked and 0 of 256,568 corpus names change.
  - The older gap E3A-11 names, the middle cut against 103a's "every other character", is covered by the same note.
- **The detail card stays a full safe-text view.** It follows canon R-TUI-103, R-TUI-103.1 and R-TUI-103a for every file-derived value: controls removed, each run of break characters shown as one space, every other character unchanged. **E3S-10 is rejected:** the card is the faithful view, and the card and the cell differ only on names that are already parse errors.
- **E3A-12 + E3S-08:** every file value of the card goes through **one helper** that meets R-TUI-103, R-TUI-103.1 and R-TUI-103b. That covers the header, `_card_field`, unit, conversion and limits. Use the house helper if `utils.py` has one for 103.1; otherwise `safe_text` after mapping each break run to one space.
  - R-TUI-042a.7 becomes the whole control class for the card: C0, DEL, C1 per CTX-TEXT, not ESC and U+009B only.
  - Split it to **R-TUI-042a.7.1** (no control character) and **R-TUI-042a.7.2** (each break run as one space).
  - Cases cover every site: name, display identifier, description, unit, conversion and the two limit words, with ESC, U+009B, U+009D and U+0090.
  - E5's table gets one mutant per append site.

**E3S-09: add a Name line.** When the card's header shows the display identifier, the card also shows the tag's name on a line of its own.
- The Tag cell now cuts names, and on V171 the card shows the display identifier for 64 of the 88 look-alike rows, so without this the full name would be visible nowhere for them.
- New row **R-TUI-042a.8** (When), cases with and without a display identifier, negative control "no Name line → V171's 64 rows show no full name". This is inside the slice (`_a2l_detail_card_text`).
- The operator sees it in AT-B103-I12-2's captures; reword its label to "the Address tells them apart; the card shows the full name".

**Accepted as written:**
- **E3S-11:** project only the two slices, so the cost is O(*w*).
- **E3S-12:** AT-069c's oracle and call shape go in the E2-6 note.
- **E3A-13 = E3S-13:** READ.69 gets a CHARACTERISTIC header-address case. In Inc 11, threshold 3/3 → 4/4, and the node `_number_word` takes its example and coverage row.
- **E3A-14:** Inc 10b's 7 tests are named in the E2-6 red list and re-pointed: Tag column by its label, rows by the row key's tag. Pin .5/7's input as one Patch Editor apply of one byte, through `patch_apply`.
- **E3A-15:** reword the "only grows" premise and add the two edges.
- **E3A-17:** add the superseded line to `E1-slice.md`.
- **E3A-16:** done by the orchestrator. PLAN row 12 holds the E4 sequencing, and the two `.pyc` files are out of the index.

**Next:** a narrow Opus correction, then round 3 on the changed rows only, both lenses.

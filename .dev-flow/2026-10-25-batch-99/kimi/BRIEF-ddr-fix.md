# Kimi brief — batch-99 DDR fixes (tests only)

Read `BRIEF-COMMON.md` (this worktree, `.dev-flow/2026-10-25-batch-99/kimi/BRIEF-COMMON.md`), then `design/DDR-software-dev.md` and `design/DDR-qa.md`. Worktree `C:\Users\jjgh8\Github\s19_app-b99-ddr`, branch `b99-ddr` at `bab3bff` (all 12 increments merged). **No SOURCE file may change**: tests and the increment packets only. Do not commit.

1. **C-18 (HIGH) — one joined node per AT.** AT-B99-03, -04, -08 and -11 are each spread over 2–5 nodes. For each AT, write ONE node named `test_at_b99_NN_<outcome>` that drives every named outcome of the AT, in sequence, through the shipped surface (copy the AT text from the HLR's "Observable outcome" in `01-requirements.md`). Rename the other nodes off the `at_b99` id to TC sub-arms of the TC they serve:
   - **AT-03 (HLR-154):** load the cut S19 → the status leads with the defect and the issues panel names it; then the flow over it → SOURCE failed, nothing written. The hostile-name arm becomes `test_tc_b99_10_hostile_name_renders_literally`.
   - **AT-04 (HLR-155):** the duplicate-name set is refused with nothing written, then the distinct-name set runs in parallel and each file holds its lane's marker, all in one node.
   - **AT-08 (HLR-157):** keep `test_at_b99_08_save_back_keeps_editor_image` as the AT; rename the mismatch arm to `test_tc_b99_22_verify_mismatch_status_still_names_entries`.
   - **AT-11 (HLR-160):** one node covering the hostile segment name staying inside, the MAC-only export with no data record, and the second export after a patch taking `_1`. Rename the part-way-failure arm to `test_tc_b99_41_part_way_failure_status_names_the_first_file` and the junctioned-home arm to `test_tc_b99_29_junctioned_project_home_shows_refusal`.

   Run each joined AT 8 times for stability.
2. **DQ-2..DQ-4 — private calls in ATs.** Remove `_handle_load_project`, `Button.press()` and `Input.value =` from AT-B99-04, AT-B99-09 and AT-B99-12. Use the Load project dialog (rail key, click the row, click `#project_ok`), `pilot.click("#id")` and `pilot.press(*text)`. The idiom is in `tests/test_b99_s0.py` (AT-B99-02).
3. **LOW — a lane carrying both riders.** Add `test_tc_b99_18_lane_line_carries_patch_and_crc_riders` in `tests/test_b99_patch_truth.py`: a flow with a partial PATCH and a partial CRC; the painted lane log line carries both notes.
4. **MEDIUM — ledger counts.** The packets' signed-balance test ledgers sum to 126 new nodes while 142 are on disk (Inc 5 −3, Inc 6 −8, Inc 9 −5). Count each increment's nodes on disk (`grep -c "^def test_" tests/test_b99_<file>.py` and its re-pinned files) and correct those three packets' ledger lines, citing the count command.
5. **DQ-6** — the qa reviewer ran the PQ-2(c) and PQ-6 help-arm mutants in a scratch copy, and their transcripts are not in evidence. Re-run both: PQ-2(c), in `tests/test_b99_export.py`, the mismatched-sidecar reuse arm with reuse forced; PQ-6, in `tests/test_b99_bytes_field.py`, the help text reverted. Revert each by hash and save the transcripts as `evidence/ddr/mut-PQ2c.txt` and `mut-PQ6.txt`.

Run `tests/test_b99_*.py`, `tests/test_address_census.py` and `tests/test_id_registry.py`, and save `evidence/ddr/green-b99.txt`. Write `evidence/ddr/README.md` mapping each change to its DDR condition. Finish with `HANDOFF.md`, ending with `__KIMI_UNIT_DONE__` and a 5-line summary.

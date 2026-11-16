# Inc 10 — E3 rulings: each finding, its ruling, where it landed (2026-11-12T22:59:28-06:00)

Review: `E3-review.md` (security-reviewer, Opus 5.5, one round, design + security lens; verdict FAIL — 0 BLOCKER, 2 MAJOR, 8 MINOR). Rulings: the orchestrator (Opus 5.5). Correction: one agent (architect, `claude-opus-5-5`), targeted edits, records only (no product or test code). Base `287b9dc3`, branch `b103-inc10`. E3 closes by ruling after this pass, with no round 2 (§5: no interface another increment uses changed).

Files changed by the correction: `01-requirements.md`, `02-test-cases.md`, `E1-slice.md` (§1, §2, new §6), `E2-rulings.md` (E2-2, E2-14, new §6 "E3 correction and E4 notes"), `codewire/graph-inc10.md` (section "E3 correction" under Findings); new data `data/x64u_make.py`, `data/x64u.s19`, `data/x64u.hex`, `data/x64u-base-emitter.hex`, `data/x64u_make_transcript.txt`.

## 1. Findings → rulings → where they landed

| Id | Sev | Ruling (orchestrator) | Landed |
|---|---|---|---|
| E3-1 | MAJOR | **Accepted**, option A: an entry change hides the save-back prompt (the stale apply line and `Write file` are removed, not guarded). | Row **R-PE-EXPORT.17** (E): "When the operator adds, edits or removes an entry, the system shall hide the save-back prompt." Threshold 4/4, negative control the base arms (4/4 RED) and one arm without the hide (its case RED), US-I10-1 · US-103-06. Cases **R-PE-EXPORT.17/1** (Add), **/2** (Edit), **/3** (Remove), **/4** (per-entry Edit JSON, §4 C-1). Knock-on: R-PE-EXPORT.3's threshold and cases **R-PE-EXPORT.3/1, /2, /3** re-show the prompt through I-10.1 (`show_save_prompt`) after their entry change, before the zero apply; **AT-I10-3** proves R-PE-EXPORT.17 then .5. Graph: node `S19TuiApp.on_patch_editor_panel_action_requested` (the `add_entry` / `edit_entry` / `remove_entry` arms call `hide_save_prompt` after the service call), new changed node `S19TuiApp._apply_entry_json_edit`, entity `[Outside: entry change]`, edges to `PatchEditorPanel.hide_save_prompt` "when: an entry is added, edited or removed" and "when: the per-entry edit is ok"; owner **G2** (`app.py`). |
| E3-2 | MAJOR | **Accepted inside Inc 10.** No Intel HEX data record crosses a 64 KiB boundary; `changes/io.py` becomes the 4th source file. Third-party tool interop (objcopy, srec_cat) is **not verified** at E3 or E4: it goes to E5 as a runner check (`objcopy -I ihex` and `srec_cat` reading `data/x64u.hex` and the file the system writes from `data/x64u.s19`). | Row **R-HEX-EMIT-001.11** (E): "When the system writes an image as Intel HEX, the system shall end each type-00 record at or before the 64 KiB address boundary that follows the record's first address." Observable: for every type-00 record, load offset + data length ≤ 0x10000 (no record's address + length crosses a multiple of 0x10000). Threshold 2/2; negative controls: the base loop (`:10FFF800…`) and the cap inside the fixed 16-step loop (bytes 0x00010000 … 0x00010007 lost) — each RED. Fixture ***x64u*** (32 bytes `00` … `1F` at 0x0000FFF8) with the expected lines as data: `data/x64u.s19`, `data/x64u.hex`, `data/x64u-base-emitter.hex`, script `data/x64u_make.py` (stdlib only, imports nothing from `s19_app`), transcript `data/x64u_make_transcript.txt` (RESULT ok). Cases **R-HEX-EMIT-001.11/1** (S19 source), **/2** (HEX twin). Graph: node `emit_intel_hex_from_mem_map` changed (the row loop, about two lines), interface **I-10.6** (signature unchanged, output contract), edge `render_patched_image` → `emit_intel_hex_from_mem_map`; group **G3 engine** = `changes/io.py`. `E1-slice.md`: totals 4 of 4 source files, §6 file-group split G1 / G2 / G3. |
| E3-3 | MINOR | **E4 addendum**: E4 measures every tab with the prompt shown, the A2L tab included. | `E2-rulings.md` §6, note **E4-N1** (G-T1 tester, first). |
| E3-4 | MINOR | **Backlog** (not in Inc 10). | §2, BL-I10-E3-4. |
| E3-5 | MINOR | **Fix now**: I-10.2 drops the `"s19"` default (as E2-2 did for I-10.1); E2-14's silent fallback becomes explicit. | Interface **I-10.2**: `SaveBackDecision(filename: Optional[str], bytes_per_line: int = 32, output_format: Optional[str] = None)`. Node `SaveBackDecision.__init__` (in, func, a negative example). Node `on_patch_editor_panel_save_back_decision`: the rule stated — the write's kind is `event.output_format` whenever the loaded kind is `s19` or `hex`; a value outside the engine's emitter table (`None` included) is passed on and the engine refuses it with its existing `CHG-HEX-SAVE-UNSUPPORTED` issue (R-CHG-003.16's refusal, no file); never the loaded kind in its place. `E2-rulings.md` E2-14 marked replaced; note **E4-N5** (unit guard). No new message text, so no new row (§4 C-7). |
| E3-6 | MINOR | **Fix now**: trailing whitespace in the typed name is taken before the suffix rewrite. | Row **R-PE-EXPORT.14** extended ("in any letter case and together with any whitespace after it"; threshold 4/4; a second negative control); **R-PE-EXPORT.15** reworded to agree ("without its trailing whitespace", §4 C-4). Case **R-PE-EXPORT.14/4**: `firmware-patched.s19 ` → Intel HEX → name box `firmware-patched.hex`, written `firmware-patched.hex`. Node `_set_saveback_format`: rule `\.(s19|hex)\s*\Z` (re.IGNORECASE; `\s` on a `str` is the whitespace `str.strip()` removes, as the engine's `apply.py:923`), example and negative example. |
| E3-7 | MINOR | **Backlog**. | §2, BL-I10-E3-7. |
| E3-8 | MINOR | **Backlog, HIGH priority**. | §2, BL-I10-E3-8. |
| E3-9 | MINOR | **Backlog**. | §2, BL-I10-E3-9. |
| E3-10 | MINOR | **Backlog**. | §2, BL-I10-E3-10. |

## 2. Backlog (not in Inc 10)

| Id | Priority | Item (one line; the reviewer's finding id) |
|---|---|---|
| BL-I10-E3-4 | normal | E3-4: below 118 × 54 the dock can sit off screen after Apply; a row (E) "When the system shows the save-back prompt, the system shall scroll the Patch Editor so that `Write file` lies inside the screen" (free id: R-PE-EXPORT.18), one `scroll_visible` call in `show_save_prompt`. |
| BL-I10-E3-7 | normal | E3-7: the sanitizer F-S-01 lets through `:` (an NTFS alternate data stream; needs a Windows runner probe), `Cc` / `Cf` characters (e.g. U+202E), a name that is only the suffix (`.s19` → `.hex`, a dot-file) and the reserved names `COM¹`–`COM³`, `LPT¹`–`LPT³`, `CONIN$`, `CONOUT$`; one `If` row and case each. |
| **BL-I10-E3-8** | **HIGH** | E3-8: the S0 header is built from the typed full path, not the written bare name (`_synth_s0_header_from_filename(event.filename)`, `app.py:5407`), so a typed `C:\Users\<user>\Desktop\fw.s19` writes the home folder's account name into a firmware file that may be shipped (personal data leaving the system); after Inc 10 every HEX → S19 export at width 32 takes this path. Raises **D8-28** to a privacy item. |
| BL-I10-E3-9 | normal | E3-9: a conversion silently drops metadata (S19 → Intel HEX: S0 data and entry address; Intel HEX → S19: a type-05 start address, entry address 0); tell the operator, or carry them (D8-29). |
| BL-I10-E3-10 | normal | E3-10: the readers accept addresses past 0xFFFFFFFF; a type-02 source is read without the 64 KiB wrap; a mismatched save still becomes the project's active variant; a verify `OSError` after the write is not caught (crash after the file landed). |
| BL-I10-E3-Q3 | question | E3-Q3: does variant execution (`_execute_one_variant`, S19 only) refuse an active `.hex` variant cleanly after an S19 → Intel HEX export into a project? |

## 3. The E2 open items (the reviewer's answers, ruled)

| Item | Ruling |
|---|---|
| E3-Q1 (A2L tab with the dock) | Measured at E4 first: E3-3 → E4-N1. No runner probe before E4 (the result changes thresholds, not the graph). |
| E3-Q2 (scroll into view) | E3-4 → backlog. R-PE-EXPORT.17 is now taken (E3-1); the free id for it is R-PE-EXPORT.18. |
| E3-Q3 (a converted file as the project variant) | Accepted, no row; the variant-execution question goes to the backlog (BL-I10-E3-Q3). |
| E3-Q4 (hostile names, allow-list) | The allow-list holds twice (handler, engine). Gaps: E3-5 and E3-6 fixed now; E3-7 and E3-8 to the backlog. |
| E3-Q5 (hidden Width chip inert to clicks) | Confirmed by reading textual 8.2.8 (R); R-PE-EXPORT.10/1 – /2 prove it at E4. |
| E3-Q6 (the `conflict` cases) | Confirmed: no Inc 10 test asserts today's empty S0 at width 16 or terminator address 0. E4 note **E4-N2** (terminator by tag only; never an empty S0 for a source with S0 data). |
| E3-Q7 (Format is selector state) | Confirmed (R): `Write file` is refused by `_refuse_if_busy()` before `hide_save_prompt`; the prompt and the chosen format survive the refusal. |

## 4. Found during the correction (not in the review)

- **C-1 (E3-1, a fourth path).** Besides the three arms, `S19TuiApp._apply_entry_json_edit` (the per-entry Edit JSON popup, available on a pasted document) edits an entry and did not hide the prompt (R, `app.py:5990-6052`). R-PE-EXPORT.17's wording covers it, so it is in the graph (changed node, owner G2) with case /4. Checked and needing nothing: the A2L bulk add changes no document (`screens_directionb.py:5485`); the whole-document Edit JSON re-enters through `parse_paste`, which already hides the prompt (`app.py:5208`); `ChangeService.add_entry` / `edit_entry` / `remove_entry` have no other caller in `s19_app/`.
- **C-2 (E3-2, the reviewer's one-line fix loses bytes).** Capping `row_end` inside the existing `for row_start in range(start, end, 16)` makes a short row (0xFFF8, 8 bytes) and then jumps to 0x10008, so 0x00010000 … 0x00010007 are never written. The node says the next row starts where the last ended; that mutant is a second negative control of R-HEX-EMIT-001.11.
- **C-3 (E3-2, the id).** The reviewer's `R-HEX-EMIT-001.4` is a canon row ("ascending address order", `REQUIREMENTS.md:3652`); the family ends at `.10`, so the new row is **R-HEX-EMIT-001.11** (unused: `grep` over the repository's `.md` files).
- **C-4 (E3-6, a contradiction avoided).** With `.14` alone extended, `firmware-patched.s19 ` would both be renamed (.14) and kept (.15: "does not end with `.s19`"); .15 now reads the text without its trailing whitespace.
- **C-5 (E3-1, R-PE-EXPORT.3 now unreachable through the controls; R, not proven).** Every change between two applies now hides the prompt (an entry change by .17; paste, undo, redo, load by `_hide_replaced_document_controls`), and the same document on the same image applies the same entries again (skipped depends on the image's ranges, which only a load changes; blocked depends on the document). So a zero apply with the prompt shown is reachable only through I-10.1, which is how its cases now reach it. Kept, as ruled; a candidate to retire at the canon fold ("prefer removing over guarding"). No action taken.
- **C-6 (E3-2, known before).** The defect is audit item I-M-7 (`../design/AUDIT-spec-verification-gaps-2026-10-23.md:68`: "HEX row crosses 64 KiB without ELA"); R-HEX-EMIT-001.11 closes it.
- **C-7 (E3-5, no new text).** The explicit rule reuses the engine's existing refusal (`CHG-HEX-SAVE-UNSUPPORTED`, R-CHG-003.16) rather than a new status, which would need its own row with an exact text; the case is unreachable from the panel (I-10.5) and is tested as a unit guard (E4-N5).

## 5. Interface check — E3 closes by ruling

| Interface | After this pass | Another increment affected? |
|---|---|---|
| I-10.1 `show_save_prompt` | unchanged | no |
| I-10.2 `SaveBackDecision` | `output_format: Optional[str] = None` (default `"s19"` dropped) | no: produced by G1 and read by G2 only; no other increment posts or reads it (`grep` over `.dev-flow/2026-11-05-batch-103/`: only Inc 10's probes) |
| I-10.3 `hide_save_prompt` | signature unchanged; new callers (the entry arms, `_apply_entry_json_edit`) | no interface change. Note for Inc 8 / Inc 9 (W2, Patch Editor staging sheet): R-PE-EXPORT.17 binds any new path that adds, edits or removes an entry — it must hide the prompt too. |
| I-10.4 dock ids (Inc 8 / 9 build on them) | unchanged | no |
| I-10.5 output-format values | unchanged | no |
| I-10.6 `emit_intel_hex_from_mem_map` (new line) | signature unchanged; output changes only for a range whose 16-byte rows from its start would cross a 64 KiB boundary | no interface change; its unchanged callers (Save project, flow WRITE-OUT, segment split / join) write correct records for such ranges from now on |

No interface another increment uses changes, so E3 closes by ruling with no round 2. Both MAJOR rulings are visible in the requirements diff (R-PE-EXPORT.17, R-HEX-EMIT-001.11) and in the graph (the `hide_save_prompt` edges, node `emit_intel_hex_from_mem_map`).

## 6. Evidence of this stage

- Fixture script run on this PC (data derivation only, no test, no `s19_app` import): `data/x64u_make_transcript.txt`, RESULT ok — 0 crossing records in `x64u.hex`, 1 in `x64u-base-emitter.hex`, all three files decode to the image.
- Code-Wire lint on the corrected graph (`python -I <code-wire>/tools/codewire_lint.py codewire/graph-inc10.md`, Code-Wire `v3.1.0-8-gb6cd30d` = the `v3.2.0` commit):

```
not read=0 nodes=20 entities=13 edges=36
lint exit=0
```

- Not run: no test, extractor or runner probe (records only; the operator's PC runs no tests). The extractor's drift list is unchanged in kind: the two new changed nodes have no `was:` signature change, and I-10.2's new form is PROPOSED like the rest of it until E4.

## Re-map to a95d0ea9 (relevo-8, 2026-11-13)

The file:line citations above are `287b9dc3`'s. Their `a95d0ea9` places, the census and the row changes of the re-map are in `E1-slice.md` §7 and `E1-rulings.md`, section "Re-map to a95d0ea9 (relevo-8)". Nothing above is rewritten (PP-06).

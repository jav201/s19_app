# Audit — Code-Wire lens on the information (data read/write) flows of s19_app (2026-10-23)

**Tree:** `main` @ `9793fcd`, run in the detached worktree `C:\Users\jjgh8\Github\s19_app-cwaudit-data` (kept as evidence; it holds the `cwaudit/` thread tests and 35 `# node:` marks written by `codewire_marks.py`). The live tree was not touched. Nothing was committed or staged.
**Method:** Code-Wire v2.6 (`code-wire` main `dd39f91`, exported to a scratch copy; the tools ran from that copy). `docs/Notation-Grammar.md` on branch `e7` was read as reference only. Reverse direction, thread-first variant (risk flows, literal threads on real `examples/` data, recordings with `cw_record_plugin.py`, C16 with `codewire_examples.py`). C15 (`codewire_extract.py`) and C2–C10 (`codewire_coherence.py`) ran once as lists, not as gates.
**Scope:** six data flows. UI screens are out of scope (a sibling audit covers them), except where a data flow ends in a status line.
**Inputs read:** `INVESTIGATION-read-write-integrity-2026-10-22.md` (cited as I-H-n / I-M-n), `INVESTIGATION-project-roundtrip-2026-10-23.md` (P-H-n / P-M-n), `AUDIT-spec-verification-gaps-2026-10-23.md`, the batch-97 PDR annex `CODEWIRE-PDR.md`, the pilot graph `piloto-s19-parche/grafo-parche.md`.
**Resource rule:** only single thread-test files ran (7 runs, each < 12 s, no xdist, no full suite).

All outputs: `C:\Users\jjgh8\Github\s19_app\.dev-flow\design\codewire-audit-2026-10-23\data\`.

---

## 1. Verdict

1. The Code-Wire lens found **9 new defects** that neither investigation reports: **3 HIGH** (wrong bytes written with a clean status), **3 MEDIUM**, **3 LOW**. It also extended 2 known defects to new paths, and it re-observed 6 known HIGH defects on real example data.
2. **HIGH, new:** the Patch Editor Bytes field reads digit-only tokens as decimal inside a hex dump (CW-D-4). RAT_FUNC conversions run in the wrong direction on encode and on decode (CW-D-10). Split/Export writes a MAC placeholder byte as image data after the confirm said "0 B of source" (CW-D-7).
3. Each new HIGH came from a literal thread whose data carries its own oracle: the case_02 README patch target, the A2L's own comment text, and the plan text versus the written file.
4. **Requirements versus code:** 8 mismatches or conflicts (§3). Two requirements conflict (R-TUI-012 versus LLR-015.3 on project save), and one requirement mandates the data loss (TC-215).
5. **Code-Wire missed** the defects that need adversarial inputs: the parallel race, path traversal, the empty CRC region, the 64 KiB boundary and duplicate JSON keys. The investigations missed defects that ordinary data shows when one value is followed through each node.
6. The C2–C4 lists and the C15 drift list found no defect (§4). For v2.6, the thread and recording core is worth its cost, and the coherence structure is not, as the batch-97 annex also says.

---

## 2. Findings

Severity follows the integrity investigation's rubric. HIGH = a silent wrong or missing byte in a written file, or an `ok` that hides it. MEDIUM = a real integrity, persistence or honesty gap that needs a specific path. LOW = hygiene or fidelity. Line numbers are HEAD `9793fcd` (unmarked). "Thread evidence" quotes the recorded value (`data/recordings/`).

| ID | Finding | File:line | Thread evidence (recorded literal) | Req status | Known? |
|---|---|---|---|---|---|
| **CW-D-4** (HIGH) | The Patch Editor Bytes field (placeholder `DE AD BE EF`) parses each token base-0 first and falls back to base-16 only on failure. A digit-only token is read as **decimal**. A hex dump that is typed or pasted becomes mixed-base, silently. | `s19_app/tui/services/change_service.py:210-223` (`int(token, 0)` then `int(token, 16)`); placeholder `screens_directionb.py:4941` | T2 t2b: `"0F 10 1F 20"` → `0F 0A 1F 14`. T2 t2a: the README text "05182025" typed as its hex dump `30 35 31 38 32 30 32 35` at `0x80010005`. The saved file line is `S31580010000444154453D1E231F26201E20233B415338`, the status is `Saved + verified: p16.s19`. | LLR-001.2 (batch-07) allows "decimals" in the TUI grammar. It does not say how an all-digit token reads. The docstring promises "paste a hex-dump fragment directly". **Ambiguous (class 2).** | **NEW** |
| **CW-D-10** (HIGH) | RAT_FUNC runs in the wrong direction, both ways. ASAP2 RAT_FUNC gives INT = f(PHYS). The code computes PHYS = f(raw) on decode and inverts that on encode. The example A2L says the opposite in its own text: `"rational function with parameter set for impl = f(phys) = phys * 10"`. LINEAR (`phys = f(int)`) is correct. | `s19_app/tui/a2l.py:1736-1744` (decode), `:1766-1798` (`_invert_rat_func`) | T4 t4a: `RAT_FUNC_DIV_10`, physical 30 km/h → entry bytes `03 00` (the file says raw 300 = `2C 01`). Physical 25 is refused: `the converted raw value 2.5 is not integral` (valid: 250). T4 t4b: raw 300 → physical `3000.0` (the file says 30). Control: `LINEAR_MUL_2` 30 → `0F 00`, 300 → 600 (correct). | `REQUIREMENTS.md:217-228` ("apply rational polynomial from coefficients", no id, no direction). LLR-141.1 checks encode against decode, and both share the error. **Ambiguous + circular oracle.** The ASAM MCD-2 MC text is not in the repo: confirm against it before the fix. | **NEW** |
| **CW-D-7** (HIGH) | Split/Join/Export on a MAC-only session. The plan reads `ranges` (empty), so the confirm says "1 empty file — 0 B of source". The writer reads `mem_map`, which holds one placeholder `0x00` per MAC address. It writes that byte as image data. | plan `segment_split_view.py:335` (`src` = ranges, `:1121`); writer `:549-552` (empty test on `mem_map` keys), `:1119`; placeholder `app.py:9657` | T6 t6b: plan `{packed 0, empty True}`. Written `firmware_locality_00.s19` = `S0030000FC`, **`S306800000000079`** (`0x00` at `0x80000000`), `S70500000000FA`. The MAC declares no value. | LLR-136.6: "with the confirm, the empty file (… header-only for S19/HEX) writes". **Req ↔ code mismatch.** | **NEW** |
| CW-D-12 (MEDIUM) | The chain-set report writes absolute host paths (user name, temp layout) in a shareable record. The flow report, the other report writer, redacts paths by rule AMD-8. The rule was not carried to the second writer. TC-B94-30 pins the emitted form. | `flow_execution_service.py:1620-1621` | T3 t3b: `Chain laneA input 1: firmware\.s19 [bound] path=`C:\Users\…\AppData\Local\Temp\…\workarea\P\firmware.s19``. The flow report shows only `out\.s19`. | LLR-020.2 "record the input files" (silent on form). AMD-8 (batch-60) is scoped to the flow report. **Missing clause.** | **NEW** |
| CW-D-13 (MEDIUM) | Save project refuses any save into a folder that already holds an A2L while an A2L is loaded, even when it is the **same** A2L. The MAC check compares names; the A2L check does not. After Load project an A2L is always loaded, so a project with an A2L can never be re-saved. The folder is created before the check. | `app.py:7936-7939` (refusal), `:7918` (mkdir first); MAC check `:7930-7935` | T5 t5a: second save of `P` with `batch ["patch.json"]` → status `Project already has an A2L file.`, `project.json` keeps `batch []`. A default re-save after Load project ends the same way. | LLR-017.3 (batch-16) specifies the assignment UI **for re-saving an existing project**. The guard implements the "single A2L" rule (LLR-005.1, code comment `:7929`), but it also refuses the same A2L, which the MAC guard allows. **Req ↔ code mismatch.** | **NEW** (the investigations never re-saved a project that held an A2L) |
| CW-D-14 (MEDIUM) | Load project reads `batch`/`assignments` and drops them. `SaveProjectScreen` starts with nothing selected. A default re-save therefore writes them empty, and the status is `Project saved + manifest verified`. | `app.py:8222-8227` (keeps only regions + active variant); `screens.py:572-590` (SelectionLists with no preselection) | T5b: save → `batch ['patch.json']`. Load read → `batch [".../Q/patch.json"]`. Re-save → `batch []`, `assignments {}`, status `Project saved + manifest verified`. | LLR-017.3: "empty fields ⇒ batch==[]". The requirement allows the loss; nothing says a re-save keeps the composition. **Class 2.** | **NEW** |
| CW-D-6 (LOW) | A save-back at 16 bytes/line writes an empty S0 header. The source header text is lost. | `app.py:3368-3373` | T2 t2a: `p16.s19` line 1 `S0030000FC`; `p32.s19` line 1 `S00E00004341534530325F47415053E9`. | LLR-015.2 / TC-215: "16-mode S0 empty". **Req and code agree; the requirement mandates the loss.** | **NEW** |
| CW-D-8 (LOW) | Every Split and Join file has an empty S0 and a terminator at address 0: the source S0 and the entry point are dropped. `emit_image` receives neither. | `segment_ops.py:464-533`; `segment_split_view.py:534-542` | T6 t6a: `firmware_range_01.s19` = `S0030000FC … S70500000000FA`. Source: S0 `CASE01_BASIC`, entry `0x80000000`. T6c (join): term `('S7', 0)`. | LLR-137.2 (emit through the shipped emitters), silent on S0/entry. | Terminator: extends **I-M-1** to a third writer. S0 drop: **NEW** |
| CW-D-16 (LOW) | A COMPU_METHOD whose unit is `""` gets its format text as its unit. | `a2l.py:821-871` (cause not traced) | T1 t1d: case_01 `firmware.a2l:32` `CM_IDENT "%6.2" IDENTICAL "%6.2" ""` → method `{unit "%6.2"}`. | `REQUIREMENTS.md:217-228` (no unit clause). | **NEW** (display only) |
| CW-D-2 (MEDIUM) | A plain Load file of a different image (no project) keeps the previous MAC and A2L. The status names only the new file. | `app.py:9823-9850`, `:10572` | T1 t1d: case_02 `other.s19` carries case_01 `BLOCK_A 0x80000000`, which is outside every case_02 range. Status `Loaded other.s19`, notes `[]`. | "primary-reload-preserving-MAC" is assumed in LLR-066.7. No requirement says when to keep or drop it. | Extends **P-H-2** (same root, Load-file route) |
| CW-D-9 (HIGH, known root) | The Split `ranges` tab offers the phantom S0 range as row `range_00`. Split exports the header text as an image file. | `segment_split_view.py:1125-1130` | T6 t6a: `firmware_range_00.s19` = `S10F00004341534530315F4241534943B2` (`CASE01_BASIC` at `0x0`). | as I-H-1 | New sink of **I-H-1** |
| CW-D-1 | S0 header bytes are data at `0x0`. The case_01 README says "two used ranges"; the loader gives 3. | `render/hexview.py:60-66` | T1 t1a: `mem_map 0x0: 0x43`; ranges `[[0,12], …]`. T3 t3a report: `**Before CRC:** 0x00000000–0x0000000C`. | — | **I-H-1** |
| CW-D-3 | A file cut after line 5 of 9 loads with `errors []` and `entry_point None`. | `core.py:241-290` | T1 t1b: last range ends `0x80000050`. | — | **I-H-8** |
| CW-D-5 | Undo changes the document, not the image. The save writes the undone bytes, and verify reports `verified`. | `change_service.py:834-864` | T2 t2a: entries `[]` after undo; `p16.s19` holds `S31580010080DEADBEEF…`; `verified`. | — | **I-H-4** |
| CW-D-11 | The PATCH status ignores the dispositions. The lanes and both reports drop the skipped entries. | `flow_execution_service.py:487-506`, `:1341-1372` | T3 t3a: `skipped-outside 1` → `applied 1 entry` / `Status: CLEAN`, with no `0x80000100` line. T3 t3b: laneB `applied 0 entries` → `✓ ok`. | — | **I-H-2, I-H-10** |
| CW-D-15 (clean) | Declared regions round-trip through save → load. | `app.py:8226-8227` | T5 t5a: `declared_regions [{name "cal", start 2147483648, end 2147483664}]` after Load. | R-RPT-REGION-PERSIST-002 | Closes a "not probed" row of the round-trip investigation (§5) |

**Re-observed and not repeated as rows:** I-H-1 in the save-back (`S310000000004341534530325F47415053E7` = S0 text as an S3 record at `0x0`, T2) and in WRITE-OUT (T3). I-M-1 (`S7 0`) in all writers. P-H-1 framing: four writers read three different sources of the same image. The save-back, Split and the flow read `mem_map` or the file on disk; Save project reads `current_file.path` (graph F5, entity `[Data: S19TuiApp.current_file]`).

**Counts:** 16 rows. 9 NEW (3 HIGH, 3 MEDIUM, 3 LOW). 2 extend known defects to new paths (CW-D-2, CW-D-9). 4 re-observe known defects (CW-D-1, -3, -5, -11). 1 clean result (CW-D-15).

---

## 3. Requirements ↔ code mismatches

| # | Requirement | Code | Kind | Finding |
|---|---|---|---|---|
| RM-1 | LLR-136.6 (batch-95): a confirmed zero-coverage file writes **header-only** for S19/HEX | It writes a data record from the MAC placeholder map | mismatch | CW-D-7 |
| RM-2 | LLR-015.3 (batch-14): "the patch-editor save-back flow **and the project save flow** shall each expose a {16,32} selector … and pass the chosen width + captured header through to the emitter" | Save project has no selector and no emitter: it copies the work copy (`app.py:7943-7944`). TC-219/220 test only the save-back and the service | mismatch, with no test (class 3). It conflicts with **R-TUI-012** ("Saving a project must copy the loaded file"). If the code followed LLR-015.3, Save project would write the in-memory map, and P-H-1 would not exist | P-H-1 root |
| RM-3 | LLR-017.3 + D-NEWPROJ (batch-16): the assignment UI is for re-saving an existing project | The re-save is refused whenever the project holds an A2L and an A2L is loaded | mismatch | CW-D-13 |
| RM-4 | `REQUIREMENTS.md:217-228` RAT_FUNC "apply rational polynomial from coefficients" (no id, no direction) | phys = f(raw), contrary to the ASAP2 convention and to the example file's own text | ambiguous requirement; circular verification (LLR-141.1) | CW-D-10 |
| RM-5 | LLR-001.2 (batch-07): the TUI grammar accepts "decimals", "0x" and commas | All-digit tokens are decimal, even inside a hex dump | ambiguous requirement | CW-D-4 |
| RM-6 | AMD-8 (batch-60): "absolute host paths never leak into a shareable record" (flow report) | The chain-set report (LLR-020.2, batch-94) writes them, and TC-B94-30 pins the form | clause not carried to a second writer | CW-D-12 |
| RM-7 | LLR-015.2 / TC-215: "16-mode S0 empty" | The code drops the S0 as specified | requirement mandates data loss | CW-D-6 |
| RM-8 | LLR-017.3: "empty fields ⇒ `batch==[]`" | The re-save overwrites a saved composition with empty lists | requirement allows silent loss; no "keep on re-save" clause | CW-D-14 |

`req:` coverage of the 35 graph nodes: 31 trace to an id. Four are `to trace`: `parse_mac_file`, `S19TuiApp._load_mac_file`, `_apply_compu_method`, and the COMPU_METHOD section, which has no id. The MAC loader has no requirement that defines its placeholder map, and that map is the root of CW-D-7.

---

## 4. Method feedback

### 4.1 What Code-Wire caught that the investigations did not, and the reverse

- **Caught by Code-Wire only:** CW-D-4, -7, -10, -12, -13, -14 (MEDIUM or higher), plus -6, -8 (S0), -16 and the two extensions CW-D-2 and CW-D-9. Each came from writing **one literal value through every node** on data that holds its own oracle:
  - the README patch target (CW-D-4);
  - the A2L long identifier `impl = f(phys)` (CW-D-10);
  - the plan text `0 B of source` against the written record (CW-D-7);
  - a saved batch against a re-saved one (CW-D-13, -14);
  - two writers of the same record kind (CW-D-12).
- **Caught by the investigations only:** I-H-3 (parallel lanes with the same output name), I-H-5 (`MSB_FIRST`, not re-threaded here), I-H-6, I-H-7, I-H-9, I-M-7, I-M-8, I-M-9, P-H-3, P-H-5, P-M-4..7. Each needs an adversarial or crafted input: a race, `../`, an empty region, a 64 KiB crossing, a duplicate key or a 300-character name. A thread on real example data does not produce these. The T3 chain set used two distinct output names and could not show I-H-3.
- **Both:** I-H-1, -2, -4, -8, -10, P-H-1, P-H-2.

### 4.2 MF items (v2.6)

| Id | Observation | Effect | Proposal |
|---|---|---|---|
| MF-1 | The value came from threads on data that **carries its own oracle**. Examples: the README patch targets, the A2L comment text, and the plan text against the written file. | positive | §3.1 rule 1 ("choose the item that leads to the result of interest") could also ask: "prefer an input whose expected value is stated outside the code (a README, a spec comment, a datasheet)". |
| MF-2 | The pilot thread (`grafo-parche`, AC-1) used `prg.s19`, the one example of 16 with no S0 record. The thread method repeated the fixture blind spot of the test suite (audit class 5). | negative | The thread rule should say why the item is representative, and name the input classes it does not cover. |
| MF-3 | C16 cannot anchor floats: `haystack` collects int and str leaves only. The F4 physical values (`30.0`, `3000.0`) had to go into parentheses, so the core evidence of CW-D-10 is not machine-checked. | gap | Compare float anchors with a tolerance. |
| MF-4 | C16 turns every `\` into `/` in all recorded strings. A Markdown-escaped report (`patch\.json`) then never matches. | false drift (2 lines) | Normalise only path-like strings, or match both forms. |
| MF-5 | C16 sees inputs, the output, modified inputs and files. It does not see a status line, a notification or a write to a `[Data: …]` entity. For an app handler (`out: None`), the main effect cannot be checked: 3 lines went to prose. | gap; this is where CW-D-13/-14 live | Let the recorder snapshot, after the call, the attributes that `modify:` names on `self` (for example `current_file.mem_map`, `_declared_regions`) and a declared status sink. |
| MF-6 | The recorder truncates: 40 items per dict, and `CW_MAX` 3 calls by default. Addresses beyond item 40 of a map cannot be anchored (here only the `files` view saved the check). The decode call needed `CW_MAX 300`, which gave a 1.2 MB trace. | cost | Add a per-node filter that keeps the keys and calls named by the thread lines. |
| MF-7 | C15 lifting showed `verify_written_image → S19File.__init__`: the verify step calls the same reader as the loader. This is structural evidence of the shared-oracle blind spot (I-H-1, audit G2). | positive | Add a rule: a node with "verify" in its `func:` whose lifted calls include the reader of the data it checks gets a "shared oracle" note. |
| MF-8 | CW-D-7 came from asking which **field** each reader takes from `[Data: S19TuiApp.current_file]`: the plan reads `ranges`, the writer reads `mem_map`. The v2.6 edge `entity ──▶ node` names the entity, not the field. | partial | Allow `[Data: X].field ──▶ node`, so that two readers of different fields show as two sources of truth. |
| MF-9 | Coherence on a reverse slice: C2 46 open, C3 16, C4 9. The extractor gave 17 C15 divergences and 12 contract drifts. All of them were graph omissions except MF-7. No defect. | cost with no return | Confirms annex M-9: for an audit, run them as lists only. |
| MF-10 | `req:` holds internal requirement ids only. The decisive oracles here were external: the ASAP2 convention, the README and the example file text. | gap | Add an optional `oracle:` field, or allow an external spec reference in `req:`. |
| MF-11 | The recorder needs graph files at record time, before the graphs exist, so a placeholder list was needed. A missing blank line silently merged two blocks (the second `module:` won). A node then went unrecorded, with no error. | friction, silent | Make the parser warn when a block has a repeated key. |
| MF-12 | `codewire_marks.py` takes one `--graph` and removes the marks of earlier runs, so a merged node file was needed. | friction | Accept a repeated `--graph`. |

### 4.3 Cost (rough; no timer ran)

- About 3 hours of agent time and about 0.4 M tokens.
- Approximate split of the time:
  - reading inputs and the method: 20 %;
  - code reading and the node cut: 20 %;
  - thread tests and recordings: 25 %;
  - writing the graphs and the C16 anchor loops: 25 %;
  - the extractor and coherence runs: 10 %.
- The C16 loops cost about 15 line rewrites. About half of them were tool limits (MF-3/4/5), not drift.
- 53 example lines, 53 ok, 0 drift (`data/examples-report.md`).

---

## 5. Not checked

- **Intel HEX:** `examples/` has no `.hex` file. No HEX thread ran; I-H-8, I-M-7 and I-M-8 are cited, not re-run.
- **A2L decode beyond RAT_FUNC and LINEAR.** Not run: TAB_VERB (`unknown_method`, honest), `MSB_FIRST` (I-H-5), CURVE/MAP, and the `long_identifier` of methods whose text is on the next line (recorded as `null`, not judged).
- **Code paths:** variant execution (the C15 lift shows that the Patch Editor handler reaches `variant_execution_service.save_patched_image`; I-M-10 covers it); CDFX; the before/after report; the A2L JSON export; `crc_designer_view`; the flow funnel; CHECK edge cases; flowsets and check sets in projects.
- **UI and environment:** real key presses. The handlers were called directly, and `action_patch_undo`'s screen gate was bypassed by calling `ChangeService.undo`, the body after the gate. Not covered: dialogs, concurrency, platforms other than Windows.
- **Assumption on the re-save payload:** CW-D-14 and CW-D-13 assume that the payload equals the `SaveProjectScreen` default. This comes from a code read of `screens.py:572-590`; the screen itself was not driven.
- **Assumption on ASAP2:** CW-D-10 relies on the ASAP2 convention, which is not in the repo, and on the example file's own text. Confirm against ASAM MCD-2 MC.
- **C17 (language) and the views:** C17 was not run on the graphs. No views or diagrams were generated (no gate for an audit).

## 6. Files

| Path (under `C:\Users\jjgh8\Github\s19_app\.dev-flow\design\codewire-audit-2026-10-23\data\`) | Content |
|---|---|
| `graph-f1-load.md` … `graph-f6-split-join.md` | 6 graphs, v2.6 format B, 35 nodes, with `## Findings` |
| `examples-report.md` | C16 over all graphs and 7 recordings (53 lines, 0 drift) |
| `coherence-report.md` | C2–C10 lists |
| `extract/diff-report.md`, `extract/extract.json` | extractor C15 and contract drift (marks in the worktree) |
| `recordings/trace-t*.json`, `recordings/run-*.log` | recordings and run logs |
| `threads/` | copies of the thread tests and helpers (they run from `s19_app-cwaudit-data/cwaudit/` with `run_rec.sh`) |

Worktree (kept): `C:\Users\jjgh8\Github\s19_app-cwaudit-data` (detached at `9793fcd`, plus `cwaudit/` and 35 mark comments).

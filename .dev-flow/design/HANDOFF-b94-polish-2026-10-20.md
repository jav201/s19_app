# HANDOFF — 2026-10-20 — b94 polish: implementation brief for the four batch-94 screens

> ## ⚠ WHICH HANDOFF THIS IS
>
> **This is the implementation brief the next `/dev-flow` session reads and executes.** It closes
> the PROTOTYPE round in `prototypes/b94_polish/` (operator verdict received 2026-10-20, see §1)
> and turns it into requirements, acceptance criteria and an increment order. Evidence lives in the
> prototype folder (§7); nothing is re-argued here that the page already shows.
>
> Written by the prototyping session, 2026-10-20. Nothing in `s19_app/` was edited. The only
> commit from this round is `51ee191` (backlog, unrelated to this brief). The prototype folder is
> untracked and stays untracked until the operator decides otherwise.
>
> **Coordination:** a second reviewer (Kimi) is reviewing *all* screens in parallel. This brief
> covers **only** the four batch-94 screens (Patch Editor, Check Editor, Flow Builder, Flow
> Execution) plus the cross-screen rules the operator stated while reviewing them (§3). The same
> overlap rule as `COORDINACION-batch92.md` applies to `screens_directionb.py`, `flow_screens.py`
> and `app.py`: the second editor rebases.

---

## 1 · Operator verdict (binding)

Source: `prototypes/b94_polish/veredicto-b94-polish.md` (pasted verbatim) and the chat.

| screen | choice | condition attached by the operator |
|---|---|---|
| Patch Editor | **A — Ledger + inspector** (`variants/pe_A.py`) | the JSON document must be *consultable*, not necessarily always visible; either live-updating or an explicit generate/update action; loading an existing JSON from the patches folder must keep populating the viewer (shipped behaviour); legends and help in every window |
| Check Editor | **A — Ledger + inspector** (`variants/ce_A.py`) | — |
| Flow Builder | **A — Pipeline rail** (`variants/fb_A.py`) | — |
| Flow Execution | **A — Pipeline rail** (`variants/fx_A.py`) | — |

History, so nobody reopens it: a first export on 2026-10-20 read C / C / C for Check Editor,
Flow Builder and Flow Execution. The operator then **changed his mind to A on all four** ("Sí,
cambié de opinión"). A is the direction. Objections: none. "Me gustan bastante."

Answers to the open questions on the page (chat, 2026-10-20):

- **Run may be the second bright element** (closes F11 in `NOTES.flows.md`).
- **CRC family accent → burnt orange.** Amber stays exclusive to "waiting for a human"
  (batch-96 doctrine, `_flows_kit.py:45`).
- **Terminal size is variable and large.** The operator scales the window until density reads
  best; his example is ≈220x60. 118x54 is the minimum reference, ~220x60 the large one.
- **Hard rule from his example:** a hex-viewer row (A2L viewer, Hex View) must never wrap into
  two lines. Those screens are outside this brief; the rule is recorded in §3 R-8 as a
  cross-screen rule and routed to the backlog for the other screens.
- **Folder-open buttons must be visible on every screen** where files are being worked on:
  "es un problema adivinar y buscarlos, sobre todo para usuarios nuevos."

---

## 2 · What the prototypes are, and what porting means

The variants are **monkeypatches over a copy of `main` at `ad10fb5`** (`appcopy/`), sub-shape A
of `tui-design/PROTOTYPE.md`: every shipped widget is re-yielded **at its shipped `id`**, the
panel is re-composed, CSS is appended at app level, and the real services run behind it (the
flow-execution captures come from a real Run). They prove the layout against production
rendering; they are **not** code to import. Porting = re-composing the four shipped panel classes
in the real tree so that they look like the variant, with the variant's CSS moved into
`styles.tcss`, and the traps in §5 resolved properly instead of overridden.

Nothing from `prototypes/` is promoted as-is (operator rule). The harness **is** reused: it
re-captures the real implementation against the chosen variant at both sizes (§7).

---

## 3 · Requirements

Ids are local to this brief (`R-n`). The batch gives them dev-flow ids on intake.

### R-1 · Patch Editor = pe_A
Left ≈60 %: the entries table, full height, one bordered frame. Right ≈40 %: inspector with the
before→after hex strip of the highlighted row as hero, the labelled entry form and the entry
chips; tab chips **Inspector / JSON / Checks** flip a `ContentSwitcher`. Docked foot: file row
(one line) + document controls (one line).

Operator condition (binding):
- **R-1.1** The JSON tab shows the **current document**, generated from the editor state, not an
  empty editor. Either it refreshes on every entry change, or the tab carries a visible
  **`Update JSON`** action and a stamp "generated from N entries · HH:MM". Pick one in the
  design step and say why; the operator accepts either.
- **R-1.2** `Load` of an existing `.json` from the patches folder keeps populating the table
  **and** the JSON tab (today the JSON editor never receives the loaded document — the shipped
  defect behind the 40-row void in the baseline).
- **R-1.3** Legend + help: the window help entry (`WindowHelpChip("patch")`) describes the three
  tabs, the hex strip, and every chip; the inspector carries a one-line legend for the strip
  colours.

### R-2 · Check Editor = ce_A
Left ≈68 %: the A2L parameter table full height with **Address always visible**. Right: the
REPORT FIELDS card (collected fields as a compact ledger: ☑ per picked parameter, ▪ per memory
row), then the memory-row table with labelled add inputs; tab chips **Fields / JSON / Addendum**.
Docked foot: spec row + `Validate · Write .chk.json · struck APPLY ghost · field count · hint`.
The no-apply doctrine stays.

- **R-2.1** Header gets the folder chip and a help chip (today `app.py:3082` is a bare Label;
  the Check Editor is the only batch-94 screen with neither). Family = `checks`
  (`.chk.json` lives beside the patches), already supported by `folder_open_service`.
- **R-2.2** Optional, not chosen by the operator: the `Fmt · Unit` column from `ce_C` made the
  names readable at 118; ce_A truncates long names. Offer it in the design step; do not add it
  unasked.

### R-3 · Flow Builder = fb_A
One full-width horizontal pipeline of block cards joined by cables (hero); contextual add form
(kind chip strip + only the inputs that kind needs; EXT-STEP gets the two-row measured config);
numbered list and grid canvas hidden; one-row copy/paste strip; funnel as one `Variables (n)`
chip; session dir on the identity ribbon; foot = `Run · Clear · Save… · Load…`.

- **R-3.1** Run is the bright chip (operator's answer).
- **R-3.2** Folder chip for the **flows** folder (new family, see R-7).
- **R-3.3** The external-step inputs (instruction, log, output) must not truncate at either size
  — they are fixed-width today and truncate identically at 118 and 220 (main and variants).

### R-4 · Flow Execution = fx_A
One pipeline per lane, stacked; each cable carries the upstream block's run-status glyph
(▓ done · ░ queued · ✗ failed · ◇ notices); the SOURCE card carries the rebind input inline.
Paused-at-external-step doctrine exactly as approved in batch-96: waiting card amber, `□` on the
cable into it, two RED pending lines (log, output file) under the lane header, `#fx_confirm_<i>`
inside the lane row, `log + output file: REQUIRED` above the run log while any lane waits. Top:
one ribbon row (set identity · Import… · mode · Run) and one set row (name · Save Set · saved
sets · Load Set). Run log below.

- **R-4.1** Run bright; the mode control is two words, not a 70-cell Select.
- **R-4.2** Folder chip for the **session** dir (new family, R-7) and a help chip (the shipped
  header has neither: `app.py:2438`).
- **R-4.3** Run-log strings in English (fx_A translated the shipped Spanish in place; the port
  changes the shipped strings, with the tests that pin them).

### R-5 · Colour
- **R-5.1** CRC family accent = burnt orange. Proposed token `#cf6a2d` (survives rich's
  quantisation: saturated, far from the `s<0.15` grey drop). Replace `#d9a35b` for `crc` in the
  flows kind table and anywhere the CRC family colour is painted; **amber `#d9a35b` stays only
  for the wait state**. Verify in a real capture that CRC and a waiting card are distinguishable
  side by side (the paused scenario has both).
- **R-5.2** One bright element per screen **plus Run**. Nothing else filled.

### R-6 · Legends and help on every window
Each of the four screens: a `WindowHelpChip` with an entry that names every chip, tab and key
of the new layout; a one-line legend wherever a glyph vocabulary is used (cable glyphs, ☑/▪,
hex strip colours). Batch-96's own follow-up ("document the `d` action in window help") is the
A2L screen's, not this brief's.

### R-7 · Folder-open chip on every screen that works on files
Shipped today (`OpenFolderChip` + `titled_header`, HLR-139): Patch Editor (`patch`), Checks
(`checks`), CRC Designer (`templates`). Missing in this brief's screens: **Check Editor**
(`checks`, exists), **Flow Builder** (`flows` — new family: the project's flows dir, the same dir
`Save…/Load…` use), **Flow Execution** (`session` — new family: the dir `set_session_dir`
receives; dimmed chip when no project is active, exactly like the shipped chips). New families
go through `folder_open_service._family_homes` / `CHIP_FAMILIES` / `resolve_chip_target` —
the single place the mapping lives (LLR-139.1) — never ad-hoc `Popen`.

### R-8 · Width-adaptive layouts, no wrapped rows
- **R-8.1** Column widths and panel splits are **derived from the available width** at mount
  and on resize. 118x54 is the minimum (nothing may overflow horizontally, Run above the fold);
  ≈220x60 is the large reference (no half-screen voids caused by fixed 118 widths).
- **R-8.2** No table row, ledger row or log row may wrap into a second line. Truncate with an
  ellipsis on the side that keeps the discriminating part (file names: keep the tail; parameter
  names: keep the tail; addresses: never truncate).
- **R-8.3** Known fixed-width leftovers measured at 220x60 (page §7): ce_A Parameter column
  truncated with ~60 free columns and Fmt column cutting units; pe_A ledger 6 rows in a 40-row
  frame (acceptable: a ledger grows with the document); fb_A pipeline cards fixed at 24 cells
  (acceptable) but result zone void; fx matrix/lanes fixed; external-step inputs fixed width;
  main's canvas `_CANVAS_COLS` is a module constant (F2).
- **R-8.4** Cross-screen rule for the backlog, outside this brief: hex-viewer rows (A2L viewer,
  Hex View) never wrap. Route as a P2 item under the operator's statement; Kimi's full-screen
  review is the natural owner.

### R-9 · English everywhere the user reads
UI strings, help entries, log lines, legends. Spanish only in the chat with the operator.

---

## 4 · Acceptance (what "done" looks like)

For each screen, at **both** 118x54 and 220x60, headless (`run_test`) and by real capture:

1. **No horizontal overflow** in any container of the screen (`scroll_x` max = 0 on the panel
   and its children) and **no row wraps** (every DataTable/ledger line renders on one row —
   assert via `export_screenshot()` or the row count of the rendered strip).
2. **Run visible without scrolling** on Builder and Execution; `Validate`/`Write` on Check
   Editor; the file row and document controls on Patch Editor.
3. **Folder chip present and resolving** on the four screens (`resolve_chip_target` returns the
   expected dir for `patch`, `checks`, `flows`, `session`; dimmed when there is no project).
4. **Help chip present** on the four screens with a non-empty entry naming every chip.
5. **Patch Editor JSON tab** shows the loaded document after `Load`, and reflects an added entry
   after `Add` (live) or after `Update JSON` (explicit) — one test per chosen mechanism.
6. **Colour:** a paused lane and a CRC card in the same capture render in two different hues;
   no filled element other than the hero and Run.
7. **Real captures** of the implementation at both sizes sit next to the chosen variant's
   captures in `prototypes/b94_polish/png/` and the page is rebuilt (`build_html.py`) so the
   operator judges before/after in one place (revision-en-un-solo-sitio).

Tests must encode *why* (engineering rule 9): e.g. the no-wrap test cites the operator's hex
example; the chip test cites "guessing folders is a problem for new users".

---

## 5 · Integration traps the prototypes hit (resolve, do not override)

From `prototypes/b94_polish/NOTES.editors.md` and `NOTES.flows.md`; the port must fix these in
the shipped code rather than copy the variants' no-op overrides.

Editors:
- **E-1** `PatchEditorPanel.on_mount` / `on_resize` call `_apply_window_geometry`, which adds the
  five table columns a second time and forces `height = 3` on the table and the 30/28-cell file
  select/path widths; `CheckEditorPanel.on_mount` also adds columns twice. The variants
  `prevent_default()`; the port removes the double work.
- **E-2** `app.py:6848` re-applies `panel._apply_window_geometry(workspace_rows - 2)` on every
  show of the patch screen. The new layout must not depend on it; delete or retarget.
- **E-3** `styles.tcss` leaks into any re-layout: `#patch_win_script { width: 2fr }`,
  `#patch_doc_entries_table { height: 10 }`, `#patch_doc_entry_buttons` /
  `#patch_doc_controls { layout: grid }` (the cause of the baseline's broken chip stacks).
  Replace, do not add on top.
- **E-4** `.patch-chip` is scoped to `#patch_editor_panel`; the Check Editor needs the same
  1-row chip shape (variant: `ed_common.CE_BASE_CSS`).
- **E-5** The panel holds no document name and no kind (`refresh_entries` gets rows + mem_map
  only); the identity ribbon needs them passed in.
- **E-6** The JSON editor never receives the loaded document (R-1.2).

Flows:
- **F-1** `_plc_block` paints IO text without clipping to the 24-cell block.
- **F-2** Four blocks on one canvas band need ≥112 painted cells; `_CANVAS_COLS` is a module
  constant (process-global). fb_A hides the canvas, so this only matters if the canvas stays
  reachable; decide and record.
- **F-3** No cable across a band wrap (`_wire_bend` returns when the next block is left of the
  previous one). Same caveat as F-2.
- **F-5** The shipped palette offers 3 of 6 kinds; fb_A adds `flow_palette_source / check /
  write_out`; `on_button_pressed` already accepts any `flow_palette_<kind>`.
- **F-6** The canvas renderer has no per-block status input; fx_A carries status on its own
  cable strip (approved).
- **F-7** `FlowExecutionPanel` has no lane selection API (fx_A does not need one; record).
- **F-8** Per-block run status is only on the retained record (`last_run_record`) and
  `render_run` assumes outcome *i* belongs to lane *i*.
- **F-10** Real Run writes outputs into the demo workarea; keep the demo project out of tests
  that assert on disk state.

---

## 6 · Suggested increment order (4 source files max each; tests uncapped)

| inc | scope | source files (expected) |
|---|---|---|
| 1 | Check Editor → ce_A + chip + help (R-2, R-6, R-7 part) | `screens_directionb.py`, `styles.tcss`, `app.py`, `window_help.py` |
| 2 | Patch Editor → pe_A + JSON tab mechanism + geometry cleanup (R-1, E-1..E-6) | `screens_directionb.py`, `styles.tcss`, `app.py`, `window_help.py` |
| 3 | Folder families `flows` + `session` (R-7) and CRC colour token (R-5) | `folder_open_service.py`, `open_folder_chip.py`, flows colour site, `styles.tcss` |
| 4 | Flow Builder → fb_A (R-3, F-1/F-5) | `flow_screens.py`, `styles.tcss`, `app.py`, `window_help.py` |
| 5 | Flow Execution → fx_A (R-4, F-6/F-8, English log) | `flow_screens.py`, `styles.tcss`, `app.py`, `window_help.py` |
| 6 | Width sweep 118 + 220 (R-8), captures, page rebuild (acceptance 1, 2, 7) | whatever the sweep finds; mostly tests |

Each increment ends with the real capture of that screen at both sizes dropped into
`prototypes/b94_polish/png/` as `impl.<scenario>.png` / `impl.<scenario>.220.png` and a
review packet. The operator judges on the page, not in chat.

---

## 7 · Evidence and tooling (all under `C:\Users\jjgh8\Github\s19_app\prototypes\b94_polish\`)

- `b94_polish.html` — the review page: baseline findings, brief, the 12 variants at 118x54,
  batch-96 section, verdict form, **§7 the 220x60 pass**, method.
- `veredicto-b94-polish.md` — verdict + round-2 answers + 220x60 summary.
- `DESIGN-BRIEF.md`, `NOTES.editors.md`, `NOTES.flows.md` — the builders' briefs and findings.
- `variants/pe_A.py`, `ce_A.py`, `fb_A.py`, `fx_A.py` (+ `ed_common.py`, `_flows_kit.py`) —
  the chosen layouts, as monkeypatches over `appcopy/` (= `git archive` of `ad10fb5`).
- `png/` — captures: `baseline.<scenario>.png`, `<variant>.png` (118x54),
  `baseline.<scenario>.220.png`, `pe_A.220.png`, `ce_A.220.png`, `fb_A.220.png`,
  `fb_A.ext.220.png`, `fx_A.220.png`, `fx_A.paused.220.png` (220x60), plus the C variants
  at both sizes for reference.
- Harness:
  ```
  # headless selftest of a scenario (grid from P4R_SIZE, default 118x54)
  set PYTHONUTF8=1 & set NO_COLOR=
  python run_real.py --scenario check-editor --variant ce_A --selftest
  set P4R_SIZE=220x60 & python run_real.py --scenario flow-execution-paused --variant fx_A --selftest

  # real Windows Terminal capture (PrintWindow -> PNG)
  powershell -NoProfile -File capture.ps1 -Scenario check-editor -Variant ce_A -OutPng png/ce_A.png
  powershell -NoProfile -File capture.ps1 -Scenario check-editor -OutPng png/impl.check-editor.220.png -Cols 220 -Rows 60 -SettleSeconds 14

  # rebuild the review page after adding captures
  python build_html.py
  ```
  To capture the **implementation** instead of `appcopy`, point `run_real.py` at the real tree
  (replace the `sys.path` insert of `_APP_COPY` with the repo root) or refresh `appcopy/` from the
  branch under review with `git archive`. Scenarios: `patch-editor`, `check-editor`,
  `flow-builder`, `flow-builder-ext`, `flow-execution`, `flow-execution-paused`.
  Python: `C:\Users\jjgh8\anaconda3\envs\s19env\python.exe`; clear `NO_COLOR` before any run.

---

## 8 · Out of scope, decided

- ce_C's `Fmt · Unit` column and fx_C's matrix as a density mode: recommended by the
  prototyping session, **not chosen**. Offer, do not build unasked.
- The eight Code-Wire pilot findings: separate lane, already in `BACKLOG-CODE.md` (`51ee191`).
- Hex-viewer no-wrap rule on A2L viewer / Hex View: backlog item, Kimi's review (R-8.4).
- Batch-96 follow-ups (real file picker on the external-step confirm, `d` in window help,
  2-D map grid, external-axis encode): untouched.

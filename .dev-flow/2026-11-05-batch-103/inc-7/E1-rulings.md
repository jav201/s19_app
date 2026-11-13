# Inc 7 — E1 rulings: scope, canon changes, decisions, interfaces, capture verdicts

Base `2dbd7d5a` (branch `b103-inc7`). Rows: `01-requirements.md`. Slice: `E1-slice.md`. Cases: `02-test-cases-{L,V,AT}.md`. Graph: `codewire/graph-inc7.md` (E2). Every decision below is **PROPOSED — awaiting orchestrator ruling**; the rows, cases, slice and graph follow each recommendation, and each decision names the rows it changes, so a different ruling is cheap to apply.

## 0. Evidence (`evidence-e1/`; every transcript is tool output)

| File | What it shows |
|---|---|
| `i7e1-pilot.py`, `-transcript.txt` (P1) | <runner>, Python 3.11.18, textual 8.2.8, the exact clone of `b103-inc7` (`s19_app.__file__` printed first), isolated `HOME` `…/runner_iso`, no clipboard. §1 case 08 (462 names); §2 the dropdown rankings of the G2 scenes with the shipped I-3 (`0017` → 5, `cuvre_00` → 20 at limit 20 and 60 unlimited, `0042 val` → 2); §3 the G2 list resolved (12 pasted, 9 found, 2 missing, 1 duplicate); §4 closest names (`MAP_0024`, `CURVE_0071` → none; `VALUE_002` → 3); §5 a 65,536-character paste (4,906 / 2,048 names; parse + resolve 1.1–1.2 ms; 10 closest-name rankings 24.0 ms over 13,990 names); §6 Textual's parser: `ESC p` → `alt+p`, `ESC a` → `alt+a`, **`ESC f` → `ctrl+right`**, the kitty forms `CSI 112;3u` / `102;3u` / `97;3u` → `alt+p` / `alt+f` / `alt+a`; §7 a box-level tab binding runs before the app's focus move |
| `i7e1-app-pilot.py`, `-transcript.txt` (P2) | the real app headless on case 08 at 118×54 and 220×60: text-mode columns (`Address`, `Length`, `Tag`, …; `fixed_columns = 2`), the shipped cells of the 9 found names, mode counts (`all` 462, `invalid` 0, `inmem` 402), pane widths (hex view 42 columns at 118, 78 at 220: **every hex row wraps in two at both widths**, the hex row is 81 characters), and a two-line value in the filter box (kept as one substring) |
| `i7e1-run.sh` | the runner wrapper (HT-02 environment, `timeout 900`, closed stdin) |
| `i7e3r1-layout-pilot.py`, `-transcript.txt` (P3, E3R1) | <runner>, the exact clone of `b103-inc7` at `1d47d12f` (product tree = `2dbd7d5a`), `HOME` …`/runner_iso`, `uptime` before and after (load 7.4–8.1 on 16 cores: sizes only, no timing). The A2L Explorer body and the tags-pane children at 80×24 (74×9; table region 1 row = header, **0 body rows on base**), 120×30 (96×15; 5 rows), 80×54 (74×39), 118×54 (112×39) and 160×40 (136×25; 15 rows); the tags pane spends 9 lines beside the table. Sizes the E3A-10 rows. Runner: `i7e3r1-run.sh` |
| `trace_check-e3r1.txt` (E3R1) | the skill's `trace_check.py` on the corrected records, run on <runner> |
| `i7e1-id-census.txt` (C) | `R-A2L-LIST`, `CTX-A2L-LIST`, `AT-B103-I7`, `BL-I7-` unused in the tree, the s19w review folder and 60 s19_app worktrees |

Scripts on the host and here are byte-identical (sha256 `e6da3f7e…` pilot, `1dbcded5…` app pilot, `3b35b87f…` runner).

## 1. Scope

**In:** av_A's list-aware filter, av_C's paste window with live status (no named sets), the similarity dropdown under the filter box and under the add line, all as the approved `av_mix` scene shows them; the carries of Inc 4 (split a paste into names and rank each one, E3S-01; off-thread ranking with stale results dropped; limit ≤ 20; display obligations 1–6 of I-3; closest names only for a bounded set, E3S-05); PLAN backlog 5 (hex rows wrap at 118) through the approved layout (D-2).

**Out (with reason):**
- Named label sets — the operator's reading (PLAN "Readings confirmed", "No named label sets").
- Changing I-3's matcher or its rows — Inc 4 owns them; Inc 7 consumes I-3 unchanged.
- Changing I-5 (`parse_parameter_list`) — consumed as is; `a2l_parameter_picker.py` is not in the slice (the brief listed it as expected; no change is needed, D-1).
- Check/Patch Editor filters by similarity — BL-I4-1, not this plan row.
- Inc 12's backlog item (snap a horizontal scroll to column starts, E3A-05) — not shown in the approved scenes; stays in PLAN backlog 5 (BL-I7-1).

## 2. Changes to existing canon rows (each restated in `01-requirements.md`)

| Row | Change | Reason |
|---|---|---|
| R-A2L-007.1, .6, .7, .8 | scoped to text mode (`… while the viewer is in text mode …`) | In list mode a filter mode marks a found row hidden instead of removing it (R-A2L-LIST.005: the scene's `◐ hidden` status), and the text is a list, not a substring. Unchanged behaviour in text mode. |
| R-A2L-007.2 | scoped to text mode | D-3 A: in field `all` a text with two or more names is a list text, as the scene's code decides. |
| R-PASTE.1, R-TUI-043.4, R-PASTE.29 | an exception for the A2L Explorer filter box when the paste holds two or more names (E3R1: "a single line with a space counts", and only while the filter field is `name` or `all` — E3A-01 (4), E3A-12) | D-5 A: the approved scene turns a multi-line paste into a list (`scn_av.py` scene av-list); today every paste route keeps only the first line (`os_clipboard_input.py:943`, `:1094`), which is exactly the "today" figure the operator compared against (G2 page Fig. 2.11). |
| R-TUI-042a.4 | scoped to text mode | D-4 A: list mode shows `#`, `Tag`, `Status`, … (the scene's table), whose fixed columns are `#` and `Tag` (R-A2L-LIST.010). |
| R-TUI-037.1, .2 | ~~retired~~ **changed at E3R1**: scoped to the *short body* (less than 180 columns wide, and less than 110 wide or less than 32 rows high) | D-2 A replaces them at 118×54 (stacked body, R-A2L-LIST.080) and 220×60 (R-A2L-LIST.081). E3A-10: below 118×54 the stacked layout leaves the table no row (P3: 160×40 → a 25-row body, hex pane 14 → 0 table rows), so the short body keeps the pre-Inc-7 split; the tc019 tests run at short bodies and stay valid (`E1-slice.md` §5.3). |
| R-TUI-069.6 | changed: 8 lines above the hex view at 180 columns or more | D-2 A: the scene's wide card has `max-height: 8`; in the stacked body the card sits left of the hex box (R-A2L-LIST.080); in the short body it keeps its old 5 lines (R-A2L-LIST.082, E3R1). |
| R-TUI-069.7 | changed (E3R1, E3A-11): "longer than 5 lines" → "longer than the detail card's height" | the 5-line figure is wrong in the wide body (8 lines) and the stacked body (14 rows high). |
| R-B102-A2L-003 (cited, not restated) | its empty summary `No A2L tags match '<filter>'.` stays, except for R-A2L-LIST.025's case (mode ≠ All with matches under All) | the scene's code paints that summary; the fold at batch end adds the exception sentence. |

Notes, not decisions:
- The scene's mode line can say `kept from an earlier A2L load`; Inc 5 (R-A2L-REFRESH.009) resets the mode to All at every A2L transition, so the text can never show. It has no row.
- The scene's list table formats Physical with 6 significant digits (`347190`); R-A2L-LIST.014 reuses the shipped text-mode cells (`347190.0`, P2 §1), so the two tables agree. Shown at the capture verdict (CV-5).
- A one-name list applied from the paste window becomes a text-mode filter of that name (R-A2L-LIST.053/2): the list definition needs 2 names, as the scene's code has it.

## 3. Decisions — every one PROPOSED — awaiting orchestrator ruling

| # | Question | Options and consequences | Recommendation and reason |
|---|---|---|---|
| D-0 | Size: 85 active rows (75 new, 10 changed) against a cap of about 80 | **A** one increment, two file groups (D-1). **B** split: Inc 7a (list filter, paste window, dropdown: 80 rows, 4 files: `styles.tcss` moves to 7b) and Inc 7b (layout: R-A2L-LIST.080, .081, R-TUI-037.1/.2, R-TUI-069.6; `styles.tcss` + compose; ~6 rows). **C** split along the window boundary: 7a viewer list mode, 7b paste window + dropdown. | **A**, flagged: 85 is 5 over "about 80"; most of the excess is one-sentence message rows the approved scenes fix (.043–.045, .067), and the slice has 40 functions and the E2 graph 42 nodes, 2 over the cap of about 40 (`codewire/graph-inc7.md` E2-1). B leaves the approved layout for later while the operator approved it as one screen; it is the fallback if the orchestrator holds the cap strictly. |
| D-1 | Source files and groups | **A** 5 files, two groups: **G-L** `s19_app/tui/a2l_label_list.py` (new) + `s19_app/tui/os_clipboard_input.py` (the I-1 hook, D-5); **G-V** `s19_app/tui/app/a2l_view.py`, `s19_app/tui/app/compose_screens.py`, `s19_app/tui/styles.tcss`. `a2l_parameter_picker.py`, `navigation.py`, `core.py`, `shared.py` unchanged. **B** the paste window in `screens.py` (4,340 lines): one more god-file edit, no gain. | **A.** Each group ≤ 4 files (skill rule). The new module holds widgets that need no app internals (list resolution, the dropdown, the two boxes, the paste window; the list-aware detail card subclass lives in G-V's `a2l_view.py`, E2-1, because the new module may not import the app package) and reaches the app only through the interface I-7 (§4). `navigation.py`'s `on_input_changed` already calls `_schedule_a2l_filter_refresh` (`navigation.py:1497`), so the dropdown hangs off G-V's function; the mode buttons already call `_refresh_a2l_filtered_tags` (`core.py:1108-1116`), so no handler moves. |
| D-2 | The pane layout | **A** the approved scene's layout: below 180 columns the hex pane (14 rows) sits under the tags pane with the card left of an 86-column hex box; from 180 the tags pane is left of a 90-column hex pane. Retires R-TUI-037.1/.2, changes R-TUI-069.6; every hex row (81 characters) is whole at 118 and 220 (P2 §3: today it wraps at both). Inc 12's R-TUI-042a.5 cases read *w* from the measured table width, so the rows hold; their expected forms at 80–118 change because the table is wider (E4 re-derives them from the measured width, never typed). **B** keep 4/7 \| 3/7 and add only the list rows: hex rows keep wrapping (PLAN backlog 5 open). **C** = D-0 B. | **A.** DF-04: the captures the operator approved show this layout; it also closes PLAN backlog 5's wrap, which the operator raised in the superseded export's q2 note. Capture verdict CV-1. |
| D-3 | Which filter fields make a list text a list | **A** `name` or `all`, as the scene's code (`_list_tokens`): in field `all` a two-word search (`synthetic demo`) becomes a list of two names and finds none. **B** `name` only: field `all` keeps today's multi-word substring search; a pasted list in field `all` gives 0 rows. | **A.** It is the approved design's rule, and the G2 page told the operator that a space separates names in the viewer's box (effect (2)). The cost is the field-`all` two-word search, which the scene did not show — capture verdict CV-2 shows both. |
| D-4 | The list-mode table's columns against Inc 12's R-TUI-042a.4 (Address and Length first and fixed) | **A** the scene's order `#`, `Tag`, `Status`, `Kind`, `Address`, `Len`, `Physical`, `Unit`, `Limits`, the shipped `fixed_columns=2` then fixing `#` and `Tag`; R-TUI-042a.4 scoped to text mode. **B** Inc 12's rule in both modes: `Address`, `Len`, `#`, `Tag`, `Status`, …; a missing row starts with two blank cells. | **A.** Both are operator approvals; G2 is the later one and showed this table (rule 7: the more recent; the capture CV-3 confirms). A missing row has no address, so B leads every missing row with blanks; under a horizontal scroll A keeps the row's identity in view. |
| D-5 | How a multi-name paste reaches the filter box (all three routes) | **A** an additive hook in I-1: `OsClipboardInput._take_paste(text: str) -> bool` (default `False`), called by `_on_paste` and `action_paste` with the capped text before the first-line cut; the list-aware filter box overrides it. **B** the filter box re-implements `action_paste` (the read cascade, the internal fallback, the warning) from I-1's private names: about 25 duplicated lines that can drift. **C** only the terminal paste route (the scene's code): Ctrl+V — the route Windows Terminal uses under the kitty protocol (`os_clipboard_input.py:15-20`) — keeps one line, today's Fig. 2.11. | **A.** One hook, two call sites, no change for any other box; I-1's owner is the orchestrator (PROPOSED interface change, §4). C fails the approved scene on the operator's platform. |
| D-6 | The dropdown title with a limit of 20 (I-3 obligation 6) | **A** `<k> of <n> similar names`, <n> written `20+` at 20 (`cuvre_00` → `8 of 20+ similar names`; the scene said `8 of 60`). **B** `<k> similar names`, no total. **C** a count call in I-3: an interface change and a new budget row in Inc 4's module. | **A.** The nearest to the approved text that keeps R-A2L-MATCH.40's bound; C reopens Inc 4. CV-4. |
| D-7 | The paste window opened in list mode | **A** prefilled with the viewer's names, one per line (the hint `alt+p edit the list` promises it). **B** always empty (the scene's code). | **A.** The hint is approved text; B makes it false. CV-6. |
| D-8 | How many missing names get closest names in the paste window | **A** the first 10 in pasted order, then the line `  similar names are shown for the first 10 missing names` (new text). **B** every missing name (the scene; unbounded: 1,636 rankings for the P1 §5 paste). **C** the first 3. | **A.** E3S-05 asks for a bound; 10 rankings cost 24.0 ms over 13,990 names (P1 §5); the line keeps the cut visible (fail loud). CV-7. |
| D-9 | The missing line's length | **A** at most 20 names of each kind, then ` +<k>` (the ribbon's ` +<k>` form). **B** every name (the scene). | **A.** A 65,536-character paste can hold 1,636 missing names (P1 §5). CV-8. |
| D-10 | The empty closest-names text | **A** `none (digits must match exactly)` for every missing name with no ranked name, as approved. **B** that text only when the name holds a digit, `none` otherwise. | **A.** It is approved text (G2 page effect (1) explains it). For a name with no digit the hint is imprecise; noted as BL-I7-2 for the batch end. |
| D-11 | The keys alt+p, alt+f, alt+a | **A** as approved; P1 §6: Textual maps the kitty forms to all three, but a legacy `ESC f` arrives as `ctrl+right`, so alt+f needs a terminal that sends the kitty form (Windows Terminal with Textual's driver enables it, `os_clipboard_input.py:15-20`). A real-terminal pilot **P-1** confirms each key on Windows Terminal before E4 ends; the button stays the mouse route. **B** a second key for the apply (e.g. ctrl+enter). | **A**, pending P-1. If P-1 fails for alt+f, B is the ruling to take; R-A2L-LIST.053 then gains that key. |
| D-12 | The detail card of a missing row | **A** `✗ <name>  not in this A2L`, `pasted #<p>`, then `closest …` from I-3 (limit 3) off the UI thread (the scene's card used `difflib`). **B** no `closest` line. | **A.** It is the scene's card; I-3 replaces `difflib` (Inc 4 §Relation). Not in any capture: CV-9. |
| D-13 | When the prepared name list is built | **A** in `update_a2l_view`, keyed on `_a2l_view_generation` (I-4), on a worker; a rebuild only when the generation differs. **B** on the first keystroke (a 1.8 s stall at 50,000 names, Inc 4 B4). | **A.** I-3's consumer note: once per load generation, off the UI thread. |
| D-14 | The module | **A** `s19_app/tui/a2l_label_list.py` (Textual widgets beside `a2l_parameter_picker.py`; its pure part — resolution and the text builders — has no Textual import at module level of those functions). **B** two modules: `services/label_list.py` (pure) + widgets: 6 files, a third group. | **A.** Under the cap; P3 (≤ 300 lines per module) is deferred (DF-05). |
| D-15 | Canon home | **A** S2.5 (The A2L Explorer), a new block "List of labels", plus the context note CTX-A2L-LIST; R-A2L-LIST rows cite S2.8 (CTX-A2L-MATCH). | **A.** The rows are screen behaviour of the A2L Explorer. |

## 4. Interfaces

| Id | State | Form | Producer → consumers |
|---|---|---|---|
| I-1 | **pinned additive change** (D-5 A, §9); **placement re-pinned at E3R1** (E3S-03, E3A-16) | `OsClipboardInput._take_paste(self, text: str) -> bool`: both paste routes call it after the 65,536-character cap (in `action_paste` also after the empty-text check `:1075-1093`) and before the first-line cut, **only when `self.restrict` is not set**, with `_strip_paste_controls(text, multiline=True)` of the capped text; `True` means the box took the paste and nothing more is inserted; the default returns `False` (every other box unchanged). | Inc 1a → Inc 7 (G-L's `ListAwareFilterInput`); Inc 8/9 inherit the placement |
| I-3 | consumed, unchanged | `build_label_index(names) -> LabelIndex`, `rank(query, index, limit) -> list[LabelMatch]` (`inc-4/codewire/graph-inc4.md`); limit 20 for the dropdown, 3 for closest names | Inc 4 → Inc 7 |
| I-4 | consumed, unchanged | `_a2l_view_generation` is the key of the prepared name list; the common refresh calls `update_a2l_view` | Inc 5 → Inc 7 |
| I-5 | consumed, unchanged | `parse_parameter_list(text) -> list` | existing → Inc 7 |
| I-7 | **pinned (§9), re-pinned at E3R1** (E3A-03), new, inside the increment (G-L ↔ G-V; the orchestrator copies it to `interfaces.md` before E4) | the whole code block of `codewire/graph-inc7.md` §Interfaces: constants (incl. `TEXT_CELL_LABELS`, `PREVIEW_MAX`, the body thresholds), `resolve_label_list` and `LabelListResolution.rows` (no back-reference), the keyed `LabelRanker` and its worker rules, `LabelSuggestBox`, `ListAwareFilterInput`'s constructor and actions, the `LabelListHost` protocol (`a2l_open_label_list`), `LabelListPasteModal` (dismiss callback), `A2LExplorerBody`'s constructor and child ids. ~~the message `LabelListApplied`~~ — struck at E3R1 (E3A-03 (c)): the graph never defined it; the dismiss callback is the one route back | G-L → G-V |

## 5. Capture verdicts needed (operator, real Windows Terminal captures; batched with Inc 8 and Inc 9)

| CV | Element | Rows | What the capture must show (118×54 and 220×60 unless named) |
|---|---|---|---|
| CV-1 | the pane layout (D-2), and below the reference sizes (E3R1, E3A-10) | .080–.083, R-TUI-037.1/.2, R-TUI-069.6/.7 | list mode with a hex jump; every hex row on one line. **Plus 80×24, 120×30, 160×40 and 80×54** (the short body: the pre-Inc-7 split kept, the card ≤ 5 lines, table rows shown). At the **80×24 floor** the body is 9 rows and base already shows 0 table rows (P3: the table region is its header); Inc 7 adds 2–4 chips lines, so the table has no row there in either mode: the operator rules whether that floor is accepted or the chips must fold (a new design, not in E3R1) |
| CV-2 | field `all` with a two-word text (D-3) | .006/3, R-A2L-007.2 | `synthetic demo` in field `all` → list mode, 2 missing |
| CV-3 | the list-mode table: columns, glyphs, status words, fixed `#`/`Tag` (D-4) | .009–.016 | the G2 list; also 80×54 scrolled right |
| CV-4 | the filter box's dropdown: rows, spans, rule tags, title `8 of 20+ similar names`, key lines (D-6) | .060, .063–.067 | `cuvre_00`; `0017`; `zzzz` (empty form) |
| CV-5 | the chips lines and mode line (text and list mode), missing line, the empty-with-mode summary | .017–.025 | G2 list; `VALUE` text; mode Invalid with `VALUE_0002` |
| CV-6 | the paste window: title, add line, label, preview (5 and 7 columns), note, buttons, prefill in list mode (D-7); the preview's more line (E3R1, E3S-01) | .040–.048, .053, .078 | alt+p from list mode; a 4,906-name paste → 200 rows + `  +4706 more names (the counts above cover all 4906)` |
| CV-7 | the similar lines and the 10-name cut line (D-8, D-10) | .049–.051 | the G2 list; a list with 11 missing names |
| CV-8 | the missing line's ` +<k>` cut (D-9) | .024 | 25 missing names |
| CV-9 | the detail card of missing, duplicate and hidden rows (D-12) | .027–.030 | `MAP_0024`, #10, mode Invalid |
| CV-10 | the add line's dropdown and enter → append | .061, .057 | `0042 val` |
| CV-11 | hostile names painted literally; long operator texts cut (E3R1, E3S-02/-06/-09) | .076, .077, .019, .025, .066 | a fixture A2L with `[red]` + controls and a bidi control; a 300-character missing name; a 1,024-character tag in the dropdown; a 300-character filter text in field `unit` |

Plus the real-terminal key pilot **P-1** (D-11): alt+p, alt+f, alt+a, tab, Esc and ↑/↓ reach the app in Windows Terminal with the dropdown open and with the paste window open (isolated `LOCALAPPDATA`, no clipboard write; every window closed after).

## 6. Deviations from the brief and the common briefs (recorded, not decided)

- **The approved scenes are not in the named archive.** `G:\…\s19_app-prototypes-2026-11-05\b103_ux\` holds round 1 only (`variants/av_{A,B,C}.py`, `veredicto-b103.json` of 2026-11-05). Round 2 — the one G2 approved — lives in the main clone's untracked `prototypes/b103_ux/round2/` (`b103_ux_r2.html`, `scn_av.py`, `variants/av_mix.py`, `_av_common.py`, `png/av_mix.*`). I read both, read-only; nothing was copied into the repository; they are cited by name only. The archive should take a copy of round 2 (BL-I7-3, the orchestrator's).
- **py_compile.** The E1 common brief allows `python -m py_compile` on the PC; s19-RULES HT-01 (later) forbids it. I used `ast.parse` only (rule 7: the later rule).
- **Runner clone and scratch.** As the brief overrides: my own clone under `~/work/zq-i7/` from a bundle of `b103-inc7`, never `~/work/s19_app` or `/tmp`.
- **Model name in records.** The common brief's `dev-flow-v3-beta` is replaced by the skill `dev-flow` (brief §Rules).

## 7. Backlog proposed (batch end)

- **BL-I7-1** — Inc 12's E3A-05 (a horizontally scrolled cell cut on its left with no mark) remains in PLAN backlog 5; the approved layout does not touch it.
- **BL-I7-2** — `none (digits must match exactly)` is imprecise for a missing name without a digit (D-10 B is the fix).
- **BL-I7-3** — archive round 2 of the b103 prototypes next to round 1 (outside the repository).
- **BL-I7-4** — a filter-box paste is capped at 65,536 characters by I-1; a longer list is cut silently at the cap (I-1's existing behaviour). A visible notice belongs with PLAN backlog 4's "64 KiB bulk notice". E3R1 (E3S-05): the joined box value may then exceed the cap (65,535 characters of one-character names → 98,302); accepted and stated in R-A2L-LIST.033/5, since every text derived from it is capped or paged.
- **BL-I7-5** (E3R1, E3A-15) — `_refresh_a2l_dependent_views` refreshes the paste window only when it is the top screen; a screen pushed above it (a notice) skips the refresh. Fix: refresh every `LabelListPasteModal` in `app.screen_stack`. The orchestrator copies it to PENDING.
- **BL-I7-6** (E3R1, E3A-10) — at the 80×24 floor the table shows no row in either mode (base already none, P3); folding the chips lines there is a new design, for the operator's CV-1 verdict.

## 8. What E1 could not check

- Real Windows Terminal key delivery for alt+p / alt+f / alt+a (P-1, D-11); only Textual's parser was run (P1 §6).
- The page-render half of R-A2L-LIST.035 (P1 times parse + resolve only).
- The scenes' visual details at 80 columns: no approved capture exists at 80; the rows cite 118 and 220.
- Whether the operator reads `8 of 20+` as intended (CV-4) and accepts the field-`all` consequence of D-3 (CV-2).

## 9. Orchestrator rulings

Orchestrator claude-opus-5-5, 2026-11-13T12:46-0600 (from `date`). These rulings override the PROPOSED rows above.

**Not visible to the operator (decided and recorded, DF-02):**

| D | Ruling | Reason |
|---|---|---|
| D-0 | A | One increment. The excess (85 rows against about 80, 42 nodes against about 40) is mostly single-sentence message rows that the approved scenes fix. Splitting off the approved layout would ship one approved screen in two halves. |
| D-1 | A | Two groups of at most 4 files each. Ordering constraint: `app/a2l_view.py` also receives the P-002 teardown guard (Inc 1b round 2, carried to batch-modular). The guard lands on the Inc 7 base before E4, so the two increments never write the file in parallel (DF-10). |
| D-5 | A | The I-1 additive hook `OsClipboardInput._take_paste(text) -> bool`, default `False`, is **pinned by the orchestrator** (the owner of I-1). It changes the Windows paste routes, so Inc 7 E5 must re-run the WinCI clipboard job and compare its FAILED set with the last Inc 1b WinCI run. |
| D-13 | A | Builds once per load generation, off the UI thread (I-3 consumer note). |
| D-14 | A | One new module. P3 is deferred (DF-05). |
| D-15 | A | Canon home S2.5. |

**Interfaces:** I-7 is pinned as written in `codewire/graph-inc7.md` §Interfaces (re-pinned at E3R1, `E3-rulings.md` E3A-03; I-1's placement re-pinned at E3R1, E3S-03). I-3, I-4 and I-5 are unchanged.

**Visible to the operator (provisional, DF-09):** D-2, D-3, D-4, D-6, D-7, D-8, D-9, D-10, D-11 and D-12 are **provisional on option A**. E3 and E4 proceed on these options. Each one is only final after the operator's real-capture verdict (CV-1 … CV-11).
- **D-4 is a conflict between two operator approvals:** Inc 12's R-TUI-042a.4 (Address and Length first) and the later G2 list table. Option A takes the later one (rule 7). The operator rules on CV-3 with both shown.
- D-11 also needs pilot P-1 on Windows Terminal before E4 ends. If alt+f fails, option B applies.

**E3 is due** (DF-03): Inc 7 changes the shared interface I-1 and takes operator text. One architecture and security pass.

**Backlog:** BL-I7-1 … BL-I7-4 go to the batch close (PENDING). For BL-I7-3, the archive copy of the round-2 prototypes is an orchestrator task outside the repository.

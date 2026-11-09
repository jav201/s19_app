# Batch-101 close — documentation pass notes

Scope: `README.md` and `docs/user-guide/*.md` only. In-app help text
(`s19_app/tui/window_help.py`) is out of scope. Nothing committed. Law guards
read first and left untouched: `tests/test_docs_canon.py`,
`tests/test_b101_doc_hygiene.py`, `tests/test_b101_help_legend_docs.py`.

---

## Item 1 — key spelling (`^K` vs painted `^k`)

The app paints the command-bar / key-bar palette hint as a caret plus the
lowercase letter. Proof, read from source (nothing imported):

- `App.get_key_display` (Textual) turns the `ctrl` modifier into `^` and then
  appends `format_key(key)`; for `Binding("ctrl+k", …)` the key is the lowercase
  `k`, so the footer paints `^k` (and `^d`, `^l`, `^s`, `^p`, `^q`, `^z`, `^y`).
- `tests/test_b97_key_bar.py` pins row 1 as `^k Palette · ^d Density · ^l Load ·
  ^s Save project · x Operations · ? Help · q Quit · ^p`; the density snapshot
  SVGs paint `^k … ^p`.

The `Ctrl+<letter>` spelling in README's key tables is a different, intentional
notation (guarded by `tests/test_docs_canon.py`, which requires `Ctrl+P`,
`Ctrl+Q`, … as single-key cells) and was left as-is.

Changed (all caret tokens uppercase → lowercase):

- `README.md:132-133` — row-1 key-bar sentence:
  `^K`→`^k`, `^D`→`^d`, `^L`→`^l`, `^S`→`^s`, `^P`→`^p`.
- `docs/user-guide/DOSSIER.md` — 15 lines, same mapping plus `^Q`→`^q`,
  `^Z`→`^z`, `^Y`→`^y`:
  - line 87 `bar paints them (`^k` = Ctrl+K)` (was `^K`)
  - line 88 `(`^k`), whose entries…` (was `^K`)
  - line 105 feature 6 `| `^k` |` (was `^K`)
  - line 106 feature 7 `^k` → Viewer settings (was `^K`)
  - line 107 feature 8 `^k` → Split / Join / Export (was `^K`)
  - line 109 feature 10 `^d` (was `^D`)
  - line 124 feature 25 `^l` / `l` (was `^L`)
  - line 126 feature 27 `^s` / `s` (was `^S`)
  - line 128 feature 29 `^p` (key bar "palette") (was `^P`)
  - line 129 feature 30 `q` (also Textual `^q`) (was `^Q`)
  - line 133 W01 Reach `^l` / `l` (was `^L`)
  - line 329 W11 feature 20 Undo `^z` (was `^Z`)
  - line 330 W11 feature 21 Redo `^y` (was `^Y`)
  - line 518 W21 Reach `^k` → "Split / Join / Export" (was `^K`)
  - line 543 W22 Reach `^s` / `s` (was `^S`)

Not changed: the guide chapters already use lowercase caret tokens (`ch01`,
`ch02`, `ch08`, `ch14`, `ch15`, `ch19`, `ch20`, and DOSSIER line 68). The quoted
prompt string "press Ctrl+L (or 'l')" (DOSSIER line 100, `ch01-start.md` line 21)
is the app's own painted text and is not caret notation, so it stays.

---

## Item 2 — captures taken before 1.0.0

The six captures the guard pins (`_CAPTURES_BEFORE`) already carry the note
beside their caption:

- `ch06-memory-map.md` `ch06-05` (line 56)
- `ch08-patch-editor.md` `ch08-09` (line 103) and `ch08-20` (line 183)
- `ch17-flow-builder.md` `ch17-05` (line 66)
- `ch19-help-palettes-settings.md` `ch19-01` (line 17, the note is split over
  three lines, which the guard's whitespace-normalised read accepts)
- `ch21-html-reports.md` `ch21-02` (line 43)

Two more captures show pre-1.0.0 behaviour only because of Inc 4's fix and were
marked as part of Item 3's rewrite (see below): `ch08-02`, `ch08-03`.

No capture was removed or re-taken; the PNG files under `docs/user-guide/img/`
are untouched.

---

## Item 3 — Inc 4 stale guide text (documents resolve symbols with the loaded A2L)

Shipped behaviour (from `inc-4/01-requirements.md` R-CHG-SYM.9 … .12): the six
session reads (Patch Editor file load, paste, whole-document Edit JSON,
per-entry Edit JSON, Check Editor Spec pick, A2B Diff check-spec pick) resolve a
`symbol` entry against the A2L the session holds; a variant run (Execute scope /
project report) resolves against the project's A2L file and nothing implicit.
A Patch Editor load of `demo_patch.changes.json` with the A2L loaded reports
`Loaded change: 7 entries, 0 error(s)`.

Changed:

- `docs/user-guide/ch08-patch-editor.md`
  - line 11 (intro bullet): `… (5 entries), because the Patch Editor refuses
    symbol entries (finding F-01);` → `… (5 entries); the captures were taken
    before 1.0.0, when the Patch Editor refused symbol entries (finding F-01);`
  - lines 44-53 (§8.2): heading `A change-set with symbol entries is refused` →
    `A change-set with symbol entries resolves them`; body now states the whole
    7-entry load with the A2L loaded, and the old refusal is quoted only in the
    `(capture taken before 1.0.0: …)` note.
  - lines 55-61 (§8.3): heading `The faults on the Checks tab` → `The faults the
    refusal left`; the faults are now attributed to the pre-1.0.0 refusal via the
    capture note, so the section does not contradict §8.2.
- `docs/user-guide/ch17-flow-builder.md` line 121: `… the symbol entries were
  left out (finding F-01).` → `… the symbol entries were left out in the captured
  run (before 1.0.0 the Patch Editor refused symbol entries, finding F-01).`
- `docs/user-guide/DOSSIER.md` line 710 (F-01 row): the false claim
  `Project Execute scope does resolve them.` → `Project Execute scope does not
  resolve them either (a variant run passes no A2L, so the change document is
  blocked).` The Kind cell and the rest of the finding stay (they record what was
  seen).
- `docs/user-guide/DOSSIER.md` line 775 (§7 inputs): `Chapter 8 (refused, F-01)`
  → `Chapter 8 (resolved in 1.0.0, F-01)`, to match the rewritten §8.2.

Already done, no change needed:

- `docs/user-guide/ch10-check-editor.md` — its F-01 sentence ("A spec with
  `symbol` entries (`demo_check.chk.json`) is refused the same way as in the
  Patch Editor (F-01)") was removed by Inc 5's corrective pass (commit `22cfd4c8`,
  C-8). The file has no remaining F-01 / symbol-refusal text.

---

## Item 4 — Inc 14 interfaces I-8 … I-16

Read against `inc-14/codewire/graph-inc14.md` (the "text at risk" table) and the
current `README.md`, `CHANGELOG.md`, `docs/user-guide/*.md`, `DOSSIER.md`.

- **I-8 (Inc 4, F-01/T-04):**
  - `DOSSIER.md` F-01 false claim — fixed in Item 3.
  - `README.md` "Projects and variants" block (12, Execute scope) — still true
    (it does not claim either way about symbols); no change.
  - **Not done — listed:** `CHANGELOG.md` `## 1.0.0` has no `###` line stating
    the Inc 4 behaviour change (a variant run resolving symbols against the
    project's A2L). The graph's owner action was "Inc 4 appends one `###` line",
    but no such line is present. Per the brief ("list any it does not mention; do
    not invent new sections") this is recorded here rather than added.
  - **Not done — listed:** the graph's other I-8 action, "the batch-end pass
    marks F-01 by named supersession of the pinned set", is blocked by the law
    guard `tests/test_b101_help_legend_docs.py`: its `_FIXED` set (17 ids) does
    not contain F-01 and `test_r_doc_guide_2_2_no_other_row_marked` asserts the
    marked set equals exactly that pinned set. Adding the mark would fail the
    guard; the brief's guard note forbids adding/removing a `fixed in 1.0.0`
    mark. F-01 stays unmarked.
- **I-9 (Inc 5/6):** `README.md` Check Editor Write sentence already states the
  shipped home (project `checks/` with a project, common `.s19tool/workarea/
  patches/` without; `library/<n>` in the Spec list). Guarded by
  `test_r_doc_readme_4_1_no_stale_claim`; no change.
- **I-10 (Inc 9):** `README.md` "Flow Execution" sentence "Each run writes a
  chain-set report" is still true — Inc 9 kept one report per confirm re-run
  (R-FLOW-CHAIN.19), it only corrected the `Mode` line. No change.
- **I-11 (Inc 10):** Split / Join and A2L in-app help steps — out of scope
  (in-app help text).
- **I-12 (Inc 11):** A2L and Split / Join in-app help steps — out of scope.
- **I-13 (Inc 12):** `ch16-reports.md` §16.1 Close row (`button / esc`) and
  `ch18-flow-execution.md` §18.9 (`Close or esc`) already state the shipped
  Escape close. Guarded by `test_r_doc_guide_1_passages_describe_1_0_0`; no
  change.
- **I-14 (Inc 13):** `README.md` "CRC Designer" block already states the
  "recomputes 150 ms after the last keystroke" debounce. No change.
- **I-15 (pinned step counts):** lives in `tests/test_window_usage_help.py`, not
  in the docs; out of scope.
- **I-16 (later merges):** `CHANGELOG.md` first heading is `## 1.0.0`. Verified;
  no change.

---

## Files edited

- `README.md`
- `docs/user-guide/DOSSIER.md`
- `docs/user-guide/ch08-patch-editor.md`
- `docs/user-guide/ch17-flow-builder.md`

Not edited (verified already correct / out of scope): `CHANGELOG.md`,
`docs/user-guide/ch10-check-editor.md`, `docs/user-guide/ch06-memory-map.md`,
`docs/user-guide/ch16-reports.md`, `docs/user-guide/ch18-flow-execution.md`,
`docs/user-guide/ch19-help-palettes-settings.md`,
`docs/user-guide/ch21-html-reports.md`, and the three law-guard test files.

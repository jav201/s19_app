# E4 implementation notes — user-guide unit (Inc 14)

Unit: G2 documents (user-guide passages and DOSSIER §5 rows). Files owned: `docs/user-guide/ch06-memory-map.md`, `ch16-reports.md`, `ch17-flow-builder.md`, `ch18-flow-execution.md`, `ch19-help-palettes-settings.md`, `ch21-html-reports.md`, `docs/user-guide/DOSSIER.md`. No other file was edited.

All texts were copied from `codewire/graph-inc14.md` under `[I/O: docs/user-guide passages]` (/1 … /11) and `[I/O: docs/user-guide/DOSSIER.md §5]`. Every file kept its CRLF line endings (verified with `file` after editing).

## What changed per file

### ch06-memory-map.md
- §6.5 (base :54-56): rewritten to the graph /1 text — the "Map keys" line now quotes the 1.0.0 line (`↑↓ move · click / ↵ inspect · double-click open hex · Esc close`), with the capture note `(capture taken before 1.0.0: it shows the earlier line `↑↓ / j k select · … double-click / ↵ open hex`, finding F-16)`.

### ch16-reports.md
- §16.1 Declared regions (base :20-22): rewritten to graph /2 — "It holds the regions saved with the project; the demo project has none, so it is empty."
- §16.2 (base :33-36): rewritten to graph /3 — "… as the window's help says." (the `*.md` + `*.html` pair claim and finding F-41 removed).

### ch17-flow-builder.md
- §17.5 (base :59-64): rewritten to graph /4 — CRC block now names a CRC config vs a Designer template; cause `crc config invalid: CRC config is structurally invalid: a CRC Designer template is not a CRC config - it has no regions or groups`; capture note for the earlier `… 'reverse'` cause.
- §17.11 later block (base :175-179): rewritten to graph /5 — "reads this run's copy" and the ` · read <copy> in place of <ref>` summary, marked fixed in 1.0.0.

### ch18-flow-execution.md
- §18.9 "If the output changes on the next run" (base :178-182): rewritten to graph /6 — 1.0.0 reads the `_1` copy; the before-1.0.0 behaviour is kept as the parenthetical capture note.

### ch19-help-palettes-settings.md
- §19.1 (base :16-19): rewritten to graph /7 — the "Some steps do not match the app yet" / folders.html text replaced by the capture note for step 5 (folders.html board → work area's common folders).

### ch21-html-reports.md
- Intro (base :23-24): graph /10 — "are Markdown only (finding F-44)." (dropped F-41 from the shared finding).
- §21.1 Header (base :40-44): graph /8 — artifact lines against the loaded A2L/MAC (`a2l=used (…)`), title "Before/after report", capture note.
- §21.1 Runs (base :53-55): graph /9 — Symbols column filled from the loaded A2L and MAC, capture note.
- §21.2 new paragraph at the end: graph /11 — the `.md` escaping consequence (`CAL\_A`, `img\.s19`, paths stay as written, plain-text search).
- §21.5 (base :141): graph /10 — "Markdown only." (dropped the F-41 parenthetical).

### DOSSIER.md §5
- Kind cell of rows F-16, F-28, F-30, F-37, F-38, F-41, F-42, F-49 gains ` · fixed in 1.0.0` (8/8, interface I-6). F-43 and F-44 keep `limitation` (unmarked). Finding and Evidence cells unchanged.

## Deviations from the graph

- ch21 §21.2 new paragraph (/11): the inline `[A-1]` tag inside the graph's quoted text ("… so a Markdown reader shows both exactly [A-1]; …") was **omitted**. It is a traceability marker, not user-facing prose — the parallel CHANGELOG (c) wording puts the ruling citation *outside* the quoted text, and no other guide passage carries a ruling id inline. The sentence otherwise matches the graph exactly and satisfies case R-DOC-GUIDE.1/11 (present `` `CAL\_A` ``, `paths stay as written`, `a plain-text search`; absent `names and paths carry a backslash`).

No other deviation: every other passage is copied character for character, with only the original file's 80-column wrapping re-applied.

## py_compile result

None — this unit edits Markdown documents only, no `.py` files, so no `py_compile` was run (and per operator rule `pytest` / `import s19_app` were not run).

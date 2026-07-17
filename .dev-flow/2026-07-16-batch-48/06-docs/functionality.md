# Patch Editor BIG — What You Can Now Do (batch-48)

> **Audience:** a firmware analyst using the `s19tui` Patch Editor. **Purpose:** understand the new read-outs this batch added and what they mean. **Scope:** everything below is **display only** — nothing here re-parses, re-validates, or changes what a patch does. The same change-sets apply exactly as before.

---

## BLUF

The Patch Editor's three windows used to be structurally correct but visually anonymous — you had to read a button's label to know what a run would target, cross-reference a separate panel to see whether an entry passed its check, and generate a report **after** applying to see what a patch would overwrite. This batch closes those gaps in place. **The headline is a live before/after card: select an entry row and you immediately see the bytes currently in the image at that address next to the bytes the entry would write — before you apply anything.**

Every window now titles and describes itself, each entry row carries its own pass/fail glyph, the CHECKS window shows a run's outcome at a glance, the pasted JSON is colour-differentiated with a fill gauge, and a history strip tells you whether a step back is available and which key takes it.

---

## By story

### US-P1 — Windows that describe themselves; entries you can read by role; a scope line (HLR-075)

- **Window titles + live subtitles.** The three windows now carry a border title — **`¹PATCH SCRIPT`**, **`²CHECKS`**, **`³JSON EDIT`** — and a subtitle that reflects live state: the SCRIPT window's subtitle shows the **entry count** (and updates the moment you add or remove an entry), the CHECKS window shows the **run state**, the JSON window shows the **schema**. You no longer have to infer which window is which.
- **Entries table colour roles.** Each entry row now reads by role: the **Kind** cell is purple, the **Address** cell is cyan, and the **value/bytes** cell is bright. The columns are unchanged (still five) — this is colour, not new structure.
- **Variant + scope line.** A readable line now shows `Variant <id> · Scope <label>` — the active variant and the execution scope a run would target. Previously the scope was legible only from a button's own label; now you can see what a run would hit without decoding a button.
- **A pre-existing crash/injection hole is closed here too.** The entries table used to hand raw, file-derived change-set text to Textual's cell formatter, which interpreted markup in it — so a change-set whose values contained bracket sequences could inject styling, inject a link, or crash the table with a `MarkupError`. Every cell is now rendered as literal text: hostile content displays verbatim in every column and nothing crashes.

### US-P2 — A pass/fail glyph on every entry row (HLR-077)

After you run checks, each entry row's **Kind** cell leads with a glyph carrying that entry's verdict:

| Glyph | Meaning |
|---|---|
| `✓` | passed |
| `✗` | failed |
| `◐` | uncheckable (e.g. the entry's address is outside the loaded image) |
| `·` | no current check result |

You read per-entry pass/fail directly on the row — no cross-referencing the CHECKS panel. The glyph is a leading span **inside** the Kind cell, not a new column, so the table's shape is unchanged.

**It never lies about a stale run.** The glyph is shown only when the last check run is still current for **both** the live change-set document **and** the loaded image. If you edit, add, or remove an entry — or load a different firmware image — every glyph reverts to `·` rather than mislabelling a row against a run it no longer describes.

### US-P3 — A CHECKS pass/fail strip (HLR-078)

The CHECKS window now shows a summary strip above its results: **`✓P · ✗F · ◐U`** counts (passed / failed / uncheckable) plus a **proportional bar**. You judge a run's outcome at a glance instead of counting rows. With no run loaded — or after an undo clears the last result — the strip is cleared.

### US-P4 — Coloured JSON + a paste-cap gauge (HLR-079)

- **Colouring.** The pasted change-set JSON is now colour-differentiated by structure (keys / strings / numbers render in distinct styles), applied in place in the paste area, so you can read the structure of what you pasted. (No new dependency was added to do this — the colouring is applied through Textual's own highlight map.)
- **Paste-cap gauge.** A gauge reads **`N KB / 64KB`** — how much of the 64 KB paste budget you have used — in a distinct MAGENTA colour reserved for the "capacity/budget" role, escalating as you approach the cap. You see the limit **before** you hit truncation.
- Hostile pasted text is rendered literally: bracket sequences, ANSI, and unclosed markup all display as the characters you pasted, with no styling applied and no crash.

### US-P5 — The live before/after card (HLR-080) — the headline

Select any entry row and a card shows, side by side:

- **Before** — the bytes **currently in the loaded image** at that entry's address, and
- **After** — the bytes the entry **would write** (its declared patch bytes).

This lets you see exactly **what a patch would overwrite before you commit to applying it** — something previously obtainable only by generating a report *after* an apply.

Two contracts worth knowing:

- **It is strictly read-only. It applies nothing.** Selecting rows — any number of times — leaves both the loaded image and the change-set document unchanged. The card is a preview; the apply path is elsewhere and unaffected.
- **An unmapped address is shown honestly.** If an entry's address is not present in the loaded image, the "before" side shows a distinct placeholder — never a fabricated `00`. Absent-from-image and zero-in-image are different facts, and the card keeps them different.

### US-P6 — A history strip (HLR-081)

A strip shows your position in the undo/redo history — how many steps back and forward are available, against the 20-step bound (e.g. `↶ N back ↷ N fwd N/20`) — plus the **`ctrl+z`** / **`ctrl+y`** key hints that move you. Previously you could only infer this from whether two buttons were enabled. With no history, the strip shows its empty state.

---

## What did NOT change

- **No parsing, validation, or apply behaviour changed.** Every value shown is one the system already computed; the engine (the frozen parser/validation set) is byte-identical.
- **No new keybindings, input surfaces, or files.** The card and strips are read-outs; they add no way to act, only ways to see.
- **The change-set schema, the paste cap, and the check logic are untouched** — the gauge *displays* the 64 KB cap, it does not change it.

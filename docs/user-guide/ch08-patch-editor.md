# Chapter 8 — Patch Editor

**Windows:** Patch Editor (W11), Edit entry JSON (W13), Edit change-set JSON (W12),
Unsaved changes will be lost (W14), Select variant (W23).
**How to get there:** `6`, or the sixth rail glyph.
**Demo inputs:** `firmware.s19` + `firmware.a2l`; the case change-set
`demo_patch.changes.json`; two documents written for this guide from the case
documents (in the scratch copy, never in the case folder):

- `guide_patch_nosym.changes.json` — `demo_patch.changes.json` without its two
  `symbol` entries (5 entries); the captures were taken before 1.0.0, when the
  Patch Editor refused symbol entries (finding F-01);
- `guide_check_mixed.chk.json` — a check document with 2 pass, 2 fail and 1
  uncheckable entry, built from the case check documents (symbol entries removed)
  plus one entry outside the image.

The last part uses project `demo` with the case change-set assigned to its variants.

## What the Patch Editor is for

You build or load a **change-set** (a list of byte or text changes at addresses),
check it against the loaded image, apply it, and write the patched image to a new
file. The same window runs **check documents**, which hold expected values instead
of changes.

## Step by step

### 8.1 The empty editor

![Empty editor](img/ch08-01-patch-empty.png)

- **Identity ribbon** — the document name and kind (`draft · change`).
- **PATCH SCRIPT** (left) — the list of entries (Kind, Address, Value / bytes,
  Status, Linkage).
- **Inspector** (right) — three tabs: **Inspector** (BEFORE → AFTER bytes, entry
  form, document tally), **JSON**, **Checks**.
- **File row** — the dropdown of change files in the common `workarea\patches\`
  folder, a typed-path field, **Load**, **Refresh**.
- **Document row** — **Validate**, **Apply loaded changes**, **Save**, then the
  glyph legend (`✓` passed, `✗` failed, `◐` uncheckable, `·` not checked, `--` byte
  not in the image).
- Header: `?` help and **📂 Open patches/** (opens the folder in the file manager).

### 8.2 A change-set with symbol entries resolves them

![Symbol entries refused](img/ch08-02-patch-symbol-entries-refused.png)

Picking `demo_patch.changes.json` in the dropdown loads it at once. With
`firmware.a2l` loaded, its two entries that name an A2L `symbol` are resolved to
their tags, so the document loads whole (*Loaded change: 7 entries, 0 error(s)*).
(capture taken before 1.0.0: it shows the earlier refusal — the two symbol
entries dropped with `CHG-SYMBOL-UNRESOLVED … no A2L context is declared` although
the A2L was loaded, finding F-01)

### 8.3 The faults the refusal left

![Declaration faults](img/ch08-03-patch-declaration-faults.png)

The **Checks** tab lists the declaration faults in full. (capture taken before 1.0.0:
these are the faults of the two refused symbol entries; with the A2L loaded 1.0.0
resolves them and this tab stays clear)

### 8.4 Load a clean change-set

![File loaded](img/ch08-04-patch-file-loaded.png)

`guide_patch_nosym.changes.json`: 5 entries, all `inside` the image. The DOCUMENT
tally reads `5 entries · 5 inside · 0 partial · 0 outside · 0 faults`.

### 8.5 BEFORE → AFTER

![Before after card](img/ch08-05-patch-before-after-card.png)

Move through the ledger with ↑ ↓. The card shows the bytes at the entry's address
as they are (`was`) and as they will be (`now`), with the changed bytes in colour —
here the text `CAL_MODE=7` at `0x00C00192`, 10 bytes changed.

### 8.6 Validate

![Validate](img/ch08-06-patch-validate.png)

**Validate** checks the document against the image: *Validate: 5 entries, 0
error(s), 0 warning(s)*.

### 8.7 Apply

![Applied](img/ch08-07-patch-applied-inspector.png)

**Apply loaded changes** writes the entries into the loaded image (*Apply: 5
applied, 0 skipped, 0 blocked*); the Linkage column now names how each entry links
to the A2L. On the Inspector tab nothing else changes: the save prompt that Apply
opens is on the **JSON** tab (finding F-04).

### 8.8 Save the patched image

![Save prompt](img/ch08-08-patch-apply-save-prompt.png)

On the JSON tab: **Save patched image as** (suggested `firmware-patched.s19`),
**Width** (32 or 16 bytes per S19 line), **Write file**, **Don't save**.

### 8.9 Written

![Image written](img/ch08-09-patch-image-written.png)

**Write file** writes and re-reads the file: *Saved + verified:
firmware-patched.s19*. Without a project no before/after offer is shown (8.10).
(capture taken before 1.0.0: it shows the earlier offer toast)

### 8.10 The before/after report needs a project

![Before after refused](img/ch08-10-patch-before-after-report.png)

Without a project the save-back shows no before/after offer (finding F-05);
**Write before/after report** (or `b`) is still refused: the report needs the
project's `reports\` folder. Section 8.19 writes it inside a project.

### 8.11 A pasted document

![Parsed paste](img/ch08-12-patch-parsed-paste.png)

The JSON tab shows the loaded document read-only and, below it, the **paste
buffer** (an example change-set to start from, with a size gauge). **Parse pasted**
loads the buffer as the document (`draft`, 2 entries). For a pasted or typed
document the history is on: `↶ 3 back ↷ 0 fwd`, **Undo**, **Redo**.

### 8.12 Add an entry by hand

![Typed entry](img/ch08-13-patch-typed-entry-added.png)

On the Inspector tab type an **Address** and either a **String** (text in the
document's encoding) or **Bytes** (hex tokens, e.g. `DE AD BE EF`), then **Add**.
**Edit** replaces the entry at the typed address; **Remove** deletes it.

### 8.13 Undo and redo

![Undo](img/ch08-14-patch-undo.png)

`^z` takes back the last edit (the `DEMO` entry is gone); `^y` brings it back. Undo
and Redo are off for a document loaded from a file.

### 8.14 Edit one entry as JSON

![Entry JSON](img/ch08-15-patch-entry-json-modal.png)

**Edit JSON** on the Inspector tab opens the highlighted entry as JSON; **Confirm**
applies the edit, **Cancel** keeps the entry.

### 8.15 Edit the whole buffer as JSON

![Change-set JSON](img/ch08-16-patch-changeset-json-modal.png)

**Edit JSON** on the JSON tab opens the paste buffer full size.

### 8.16 Save the document

![Save document](img/ch08-17-patch-save-document.png)

**Save** writes the change-set file: *Saved change-set to changes.json* (the name is
chosen by the app; in a project it lands in the project's `patches\`, or `checks\`
for a check document).

### 8.17 Loading over unsaved edits

![Load guard](img/ch08-18-patch-load-guard.png)

With unsaved edits, **Load** asks first: **Accept loss and load** or **Cancel**
(default, also `esc`). The buttons sit at the top of an oversized box (finding F-17).

### 8.18 Run a check document

![Run checks](img/ch08-19-patch-run-checks.png)

After accepting, `guide_check_mixed.chk.json` is loaded (kind `check`). **Checks**
tab → **Run checks**: *3 passed, 1 failed, 1 uncheckable* against the patched image.
Each result line shows expected and actual bytes; the ledger rows get `✓` `✗` `◐`.
The Checks window (Chapter 11) shows the same run.

### 8.19 In a project: the before/after report

![Before after in project](img/ch08-20-patch-before-after-report-project.png)

After loading project `demo`, applying `guide_patch_nosym.changes.json` and writing
the patched image, the image becomes a new project variant
(`demo:firmware-patched (1/3)`) and **Write before/after report** writes
`reports\<time>-before-after-….md` in the project. The Checks tab shows no
stale run after the project load: the earlier check run ended with it (finding
F-40). (capture taken before 1.0.0: it shows the earlier run's results)

### 8.20 Execute over variants

![Scope all variants](img/ch08-21-patch-scope-all-variants.png)

**Scope** cycles which variants **Execute scope** runs over (active variant / all
variants). Execute scope runs the change files **assigned to each variant in the
project** (here the case change-set, assigned in `project.json`), not the document
open in the editor.

![Execute scope](img/ch08-22-patch-execute-scope.png)

The log lists each variant: *Variant 'firmware': ok - 1 change, 0 check* …
*Execute: scope 'all' finished - 3 variant(s), 0 error(s)*.

### 8.21 Select the variant

![Select variant](img/ch08-23-select-variant.png)

`v` opens **Select variant**: the project's variants, the active one marked;
**Activate** switches the loaded image, **Cancel** keeps it.

## Features of these windows

| Feature | How | Capture |
|---|---|---|
| Ledger, ribbon, tabs | ↑ ↓, click / `space` on a tab | 8.1, 8.4 |
| BEFORE → AFTER card | highlight | 8.5 |
| Address / String / Bytes, Add / Edit / Remove | type, buttons | 8.12 |
| Edit JSON (entry / buffer) | buttons | 8.14, 8.15 |
| Paste buffer, Parse pasted | button | 8.11 |
| Undo / Redo + history strip | `^z` `^y`, buttons | 8.11, 8.13 |
| File dropdown, typed path + Load, Refresh | select / type | 8.2, 8.17 |
| Load guard | Load with unsaved edits | 8.17 |
| Validate / Apply / Save | buttons | 8.6, 8.7, 8.16 |
| Save patched image as, Width, Write file, Don't save | after Apply (JSON tab) | 8.8, 8.9 |
| Write before/after report | button / `b` | 8.10, 8.19 |
| Checks tab: faults, Run checks, glyphs | button | 8.3, 8.18 |
| Scope / Execute scope | buttons | 8.20 |
| Select variant | `v` | 8.21 |
| Open patches/ | header chip (opens the file manager) | text |

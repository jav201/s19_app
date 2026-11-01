# Chapter 17 — Flow Builder

**Windows:** Flow Builder (W25), Save flow as (W26), Load flow (W27), Discard unsaved
flow edits? (W28).
**How to get there:** `8`, or the ninth rail glyph. Flows need an open project.
**Demo inputs:** project `demo`, with `patches\guide_patch_nosym.changes.json`,
`checks\guide_check_mixed.chk.json`, and a CRC template `templates\demo-crc32.crc.json`
saved from the CRC Designer in the same session.

## What the Flow Builder is for

A flow is a chain of blocks that runs on an image: load it, patch it, check it, stamp
a CRC, write it out, compare it, or stop for a human step. Flows are saved in the
project's `flows\` folder and can run many at once in Flow Execution (Chapter 18).

## Step by step

### 17.1 The empty builder

![Flow builder](img/ch17-01-flow-builder.png)

- **Ribbon** — the flow name and *saved / unsaved*, the block summary, and the
  session folder (the open project).
- **chain** — the cards, in run order, joined by cables.
- **add block** — one chip per kind: LOAD, PATCH, CHECK, CRC, WRITE-OUT, A2B-DIFF,
  EXT-STEP; below it the fields of the chosen kind and **+ Add**.
- **copy block #**, **Copy**, **Paste**, **Variables (n)**.
- **Run**, **Clear**, **Save…**, **Load…**, the result area and the glyph legend.
- Header: `?` and **📂 Open flows/**.

### 17.2 The first block

![Load block](img/ch17-02-flow-load-block.png)

Pick **LOAD**, type the image file (relative to the project, `firmware.s19`), **+
Add**. The card shows what goes in and what comes out.

### 17.3 A full chain

![Chain built](img/ch17-03-flow-chain-built.png)

PATCH (change doc), CHECK (check doc, gating *advisory* — a failed check is reported
but the chain goes on; *block-own-op* also stops the check's own output), CRC (CRC
template), WRITE-OUT (output file) and A2B-DIFF (image A `firmware.s19`, image B
`#5`, the output of block 5). The chain scrolls sideways when it is wider than the
window.

### 17.4 Variables

![Variables](img/ch17-04-flow-variables.png)

**Variables** opens the editor: a name of capitals, digits and `_` and its value.
**+ Add var** declares it; a change document writes it as `${BOOST}`.

### 17.5 Run

![Run result](img/ch17-05-flow-run-result.png)

**Run** runs the chain on the project and lists each block's verdict: `source ok`,
`patch ok — applied 5 entries`, `check notices — passed=3 failed=1 uncheckable=1`,
then `crc error — CRC config is structurally invalid: 'reverse'`. The CRC block
cannot read the template the CRC Designer saves (finding F-28), so the chain ends
**FAILED** there.

### 17.6 Save the flow

![Save dialog](img/ch17-06-flow-save-dialog.png)

**Save…** asks for a name (sanitised to letters, numbers, `-`, `_`) and writes
`flows\demo_flow.json`; an existing name shows an overwrite notice first.

### 17.7 Copy and paste a block

![Copy paste](img/ch17-07-flow-copy-paste.png)

Type a block number in **copy block #** (empty = last), **Copy**, then **Paste**: the
block is appended (*pasted: patch*, 7 blocks) and the flow is *unsaved* again.

### 17.8 Load a flow

![Load dialog](img/ch17-08-flow-load-dialog.png)

**Load…** lists the saved flows. **Import…** opens the system file dialog (outside the
terminal, not captured) and copies the picked file into `flows\`.

![Discard question](img/ch17-09-flow-discard-question.png)

Loading over unsaved edits asks first: **Discard** or **Cancel**.

![Loaded](img/ch17-10-flow-loaded.png)

The saved six-block flow is back, marked *saved*.

### 17.9 An external step

![External step fields](img/ch17-11-flow-external-step-fields.png)

**Clear** empties the chain. **EXT-STEP** is a step done by a person or a command
outside the app: *mode* Manual (an instruction) or Terminal (a command), the
*instruction*, the *log* file it must leave (required) and the *output file*
(absolute path preferred).

![External step added](img/ch17-12-flow-external-step-added.png)

When a run reaches this card it waits until someone confirms it in Flow Execution.

## Features of these windows

| Feature | How | Capture |
|---|---|---|
| Kind chips and their fields, + Add | click, type | 17.2, 17.3, 17.9 |
| Gating advisory / block-own-op | dropdown | 17.3 |
| A2B inputs (file or `#n`) | type | 17.3 |
| External step: mode, instruction, log, output | select, type | 17.9 |
| Variables editor | Variables, + Add var | 17.4 |
| Copy / Paste a block | buttons | 17.7 |
| Run + per-block verdicts | button | 17.5 |
| Save… / Load… / Import… / Discard | buttons | 17.6, 17.8 |
| Clear | button | 17.9 |
| saved / unsaved, glyph legend, Open flows/ | — | 17.1 |

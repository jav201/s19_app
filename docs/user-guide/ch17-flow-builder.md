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
**+ Add var** declares it; a change document writes it as `${BOOST}`. Section 17.10
shows the variables (the *funnel*) at work.

### 17.5 Run

![Run result](img/ch17-05-flow-run-result.png)

**Run** runs the chain on the project and lists each block's verdict: `source ok`,
`patch ok — applied 5 entries`, `check notices — passed=3 failed=1 uncheckable=1`;
then the CRC block stops: it names the template the CRC Designer saved, and a CRC
block reads a CRC config, not a Designer template. Its cause is `crc config invalid:
CRC config is structurally invalid: a CRC Designer template is not a CRC config - it
has no regions or groups` (finding F-28), and the chain ends **FAILED** there.
(capture taken before 1.0.0: it shows the earlier cause `… 'reverse'`)

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

### 17.10 Variables in a change document (the funnel)

The variables table of a flow — called the *funnel* in the code — lets one change
document serve several flows. A change document writes a placeholder `${NAME}` where a
value should go; when a flow runs, its PATCH block reads the document's text, replaces
every exact `${NAME}` token with the value the flow declares, and only then parses and
applies the document. The document file on disk is never changed.

The demo document `guide_patch_funnel.changes.json` was derived (in scratch, for the
guide) from the case change-set `demo_patch.changes.json`: the first entry's bytes at
`0x00800000` became `${BOOST}` and the string at `0x00C00192` became
`CAL_MODE=${MODE}`; the symbol entries were left out (finding F-01). It sits in the
project's `patches\` folder.

![One variable](img/ch17-13-funnel-one-variable.png)

The flow is LOAD `firmware.s19` → PATCH `patches/guide_patch_funnel.changes.json` →
WRITE-OUT `tune_a.s19`. Only `${BOOST} = AA 55 AA 55` is declared so far — a value may
hold several byte tokens, because the replacement is plain text.

![Undeclared variable](img/ch17-14-funnel-undeclared-notice.png)

**Run** with `MODE` missing does not fail: the PATCH block ends with **notices** and the
line *funnel: ${MODE} is not declared in the flow — the placeholder stays intact*; the
run as a whole reads **NOTICES**. The undeclared placeholder is written into the image
literally (`CAL_MODE=${MODE}`), so read the notices before you use the output.

![Run clean](img/ch17-15-funnel-run-ok.png)

After **+ Add var** `MODE` = `1` the same Run is **CLEAN**. The output is
`tune_a_1.s19`: a write-out never overwrites a different file — the name already held
the image of the first run, so the next free `_1` name was taken (a byte-identical file
would have been reused instead).

![Second flow](img/ch17-16-funnel-flow-b.png)

**Save…** stores the variables with the flow (`flows\tune_a.json` holds
`"funnel": [["BOOST", "AA 55 AA 55"], ["MODE", "1"]]`). The demo then builds two more
flows on the same document: `tune_b` (`BOOST = 11 22 33 44`, `MODE = 2`, output
`tune_b.s19`, shown here after **Save…**) and `tune_c` (`BOOST = CA FE CA FE`,
`MODE = 3`, an EXT-STEP before its WRITE-OUT `tune_c.s19`). **Clear** empties the chain
*and* the variables, so each flow is built from the start. Chapter 18.8 runs the three
flows side by side.

### 17.11 Run a terminal command and use its output

**What the EXT-STEP block does, from the code** (`flow_model.ExternalStepBlock`,
`flow_execution_service.run_flow`):

- It has a **mode**: *Terminal* (the default; the text field is a **command**) or
  *Manual* (the field is an **instruction** for a person). The two modes behave the same
  way at run time; the mode only changes the wording.
- **The app never runs the command.** It shows it, and the run **pauses** at the block
  (*paused - waiting for a human: command '…'*). A person runs the command in a
  terminal of their own.
- The **log** file is mandatory evidence; the **output file** is the file the step
  must leave behind (an absolute path is preferred, because it is usually outside the
  project). Both are checked only when the step is confirmed.
- The run can only go on in **Flow Execution** (Chapter 18.9): **Confirm** / `c`
  re-runs the lane from that block. The Flow Builder shows the pause but has no
  Confirm (finding F-50).
- On confirm the app checks that the log exists, then that the output exists, copies
  the output into the session folder (the open project's folder; a name already taken
  by a different file gets the next free `_1`, `_2`, …), lists the copy under *Written
  files* of the run, and continues with the next block. The image passes through the
  step unchanged.
- **Using the output in a later block:** there is no wiring for it — no `#n` reference,
  no binding and no `${NAME}` variable points at an external step's output. A later
  block can only name the copy **by its file name**, relative to the project, as any
  other ref (finding F-48). When a later run produces a different output, the copy is
  stored as `<name>_1…`, and a later block of the same run that names the output reads
  this run's copy; its summary ends ` · read <copy> in place of <ref>` (finding F-49,
  fixed in 1.0.0).

**The demo: a command that writes a change document, which the next block applies.**
In project `demo`, with a folder `C:\Users\Public\s19demo\bench` for the bench files:

1. `8` (Flow Builder). **LOAD**, image file `firmware.s19`, **+ Add**.
2. **EXT-STEP**. *mode* stays **Terminal**. Fill the three fields:
   - *command* — one line of PowerShell that writes a one-entry change document and a
     log:

     ```powershell
     '{"format":"s19app-changeset","version":"2.0","kind":"change","encoding":"utf-8","value_mode":"text","entries":[{"type":"string","address":"0x00C001B0","value":"BENCH=OK"}]}' | Set-Content C:\Users\Public\s19demo\bench\step_patch.changes.json; 'step done' | Set-Content C:\Users\Public\s19demo\bench\step.log
     ```

   - *log* — `C:\Users\Public\s19demo\bench\step.log`
   - *output file* — `C:\Users\Public\s19demo\bench\step_patch.changes.json`

   ![Terminal step fields](img/ch17-17-terminal-step-fields.png)

   **+ Add**.
3. **PATCH**, change doc `step_patch.changes.json` — the *file name* the copy will have
   in the project folder, not the bench path. **+ Add**.
4. **WRITE-OUT**, output file `terminal_out.s19`, **+ Add**.
5. **Run**. The run stops at block 2 with **PAUSED – WAITING FOR A HUMAN**; the
   verdict repeats the command, the log and the output that are pending; PATCH and
   WRITE-OUT are *skipped (waiting on external step)*.

   ![Builder run paused](img/ch17-18-terminal-step-builder-run.png)

6. **Save…** as `terminal_step`, then continue in Flow Execution (Chapter 18.9).

## Features of these windows

| Feature | How | Capture |
|---|---|---|
| Kind chips and their fields, + Add | click, type | 17.2, 17.3, 17.9 |
| Gating advisory / block-own-op | dropdown | 17.3 |
| A2B inputs (file or `#n`) | type | 17.3 |
| External step: mode, instruction, log, output | select, type | 17.9 |
| Variables editor | Variables, + Add var | 17.4, 17.10 |
| Variables in a change document (`${NAME}`), undeclared-variable notice | Run | 17.10 |
| External step, Terminal mode: command, log, output, pause | EXT-STEP, Run | 17.11 |
| Copy / Paste a block | buttons | 17.7 |
| Run + per-block verdicts | button | 17.5 |
| Save… / Load… / Import… / Discard | buttons | 17.6, 17.8 |
| Clear | button | 17.9 |
| saved / unsaved, glyph legend, Open flows/ | — | 17.1 |

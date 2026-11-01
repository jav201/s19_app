# Chapter 18 — Flow Execution

**Window:** Flow Execution (W29). **How to get there:** `]`, or the tenth rail glyph
(inside the A2B Diff panel `]` pages the diff instead — Chapter 9).
**Demo inputs:** project `demo` and two flows saved in it for this chapter:
`bench_a` (LOAD firmware.s19 → PATCH → EXT-STEP → WRITE-OUT `firmware-bench.s19`)
and `bench_b` (LOAD firmware_v2.s19 → PATCH → WRITE-OUT `firmware-bench-v2.s19`).

## What Flow Execution is for

It runs several saved flows as **lanes**, one per flow, sequentially or in parallel,
pauses a lane at an external step until a person confirms it, and saves the whole
set of lanes with their inputs.

## Step by step

### 18.1 The empty window

![Empty](img/ch18-01-flow-execution-empty.png)

- Ribbon — the set name and *saved / unsaved*, the session folder, **Import…**,
  the mode switch **sequential · parallel**, **Run**.
- *set name*, **Save Set**, *saved sets* dropdown, **Load Set**.
- The lanes area, the run log (newest 8 lines) and the glyph legend.
- Header: `?` and **📂 Open session** (the project folder).

### 18.2 Import a flow

![Import](img/ch18-02-flow-execution-import.png)

**Import…** opens the Load flow dialog; pick a flow and **Load**. Each import adds a
lane.

### 18.3 Two lanes

![Two lanes](img/ch18-03-flow-execution-two-lanes.png)

Each lane shows its cards and cables, all *not run*.

### 18.4 Bind an input

![Bind](img/ch18-04-flow-execution-bind.png)

A LOAD card holds an *image file* field and **Bind**: type another file and press
**Bind** to change that lane's input for the next run (here `bench_b` is bound to
`firmware.s19`). The mode was switched to **parallel** for this run (click the word,
or Enter / space on the switch).

### 18.5 Run: a lane waits for a person

![Waiting](img/ch18-05-flow-execution-waiting.png)

**Run** starts both lanes. `bench_b` finishes (*done · wrote firmware-bench-v2.s19*).
`bench_a` stops at its external step: the card is highlighted, the lane head says
*waiting for a human at #3*, the `▪` lines list what is owed (the log, the output
file), the cable glyphs show which blocks ran, and the line above the log reads
*log + output file: REQUIRED for bench_a · press c to confirm*. **Confirm** appears
beside the lane.

### 18.6 Confirm

![Confirmed](img/ch18-06-flow-execution-confirmed.png)

After the person has done the step and the log and output file exist, press `c` (or
**Confirm**): the lane runs on from that step (*re-run after confirming the external
step*) and ends *done · wrote result.txt, firmware-bench.s19*. The output file is
copied into the session folder.

### 18.7 Save the set

![Set saved](img/ch18-07-flow-execution-set-saved.png)

Type a *set name* and press **Save Set**: *saved flowsets/bench_set.json* — the lanes,
their bound inputs and last outputs. **Load Set** with a set picked in *saved sets*
restores it.

## Features of this window

| Feature | How | Capture |
|---|---|---|
| Import… a lane | button | 18.2, 18.3 |
| sequential / parallel | click, Enter, space | 18.4 |
| Run, lane states, cable glyphs, run log | button | 18.5, 18.6 |
| Image file + Bind per lane | type, button | 18.4 |
| REQUIRED line, Confirm | `c` / button | 18.5, 18.6 |
| Set name, Save Set, saved sets, Load Set | type, buttons | 18.7 |
| Open session, `?`, legend | chips | 18.1 |

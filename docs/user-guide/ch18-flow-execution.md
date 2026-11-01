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

### 18.8 Parallel lanes with different variables

This worked example runs the three flows built in Chapter 17.10 — `tune_a`, `tune_b`,
`tune_c`: one change document with `${BOOST}` and `${MODE}`, different values per flow
— as three lanes at the same time.

**What belongs where.**

| Level | What it holds | Where it is stored |
|---|---|---|
| per flow | the blocks, their refs, and the variables (funnel) | `flows\<name>.json` |
| per lane | which flow the lane runs, its bound inputs (Bind), its last outputs | the set, `flowsets\<name>.json` |
| per run | the mode (sequential / parallel), the run log, the chain-set report, a confirm of an external step | the screen and `reports\<time>-chain-set-report.md` |

A lane cannot change a flow's variables: to run the same document with other values,
save another flow (as here) and import it as its own lane. Two lanes of the *same*
flow differ only by their bound inputs, and must not write the same output file — the
run is then refused (*lanes … both write '…' — give each lane its own output*).

![Three lanes](img/ch18-08-fx-three-lanes-parallel.png)

**Import…** three times (`tune_a`, `tune_b`, `tune_c`), click **parallel**, and bind
lane `tune_c` to `firmware_v2.s19` (its flow reads `firmware.s19`): the binding belongs
to the lane; the flow file is unchanged.

![Parallel, one waiting](img/ch18-09-fx-parallel-waiting.png)

**Run**: all three lanes start at `00:00.000`. `tune_a` and `tune_b` finish (*done ·
wrote tune_a_1.s19*, *wrote tune_b.s19*) while `tune_c` stops at its external step
(*waiting for a human at #3*; the REQUIRED line names it). Each lane substituted its
own flow's values.

![Parallel, done](img/ch18-10-fx-parallel-done.png)

After the bench log and result file exist, `c` confirms: `tune_c` re-runs from block 3
and writes `tune_c_result.txt` and `tune_c.s19`. The confirm writes a second chain-set
report for that lane alone, which records the mode as *sequential* (finding F-45).

![Set saved](img/ch18-11-fx-tune-set-saved.png)

**Save Set** as `tune_set` stores the three lanes with their inputs (`tune_c` keeps
`firmware_v2.s19`) and their outputs. The variables are not in the set; they stay in
each flow file.

![Diff lane A vs lane B](img/ch18-12-diff-lane-a-vs-b.png)

The substitution is visible in the written images. A2B Diff (Chapter 9) of
`tune_a_1.s19` against `tune_b.s19` — both made from `firmware.s19` by the same
document — finds exactly **2 runs**. Run #0 at `0x00800000`: `AA 55 AA 55` against
`11 22 33 44`, the two `${BOOST}` values.

![Diff, the MODE run](img/ch18-13-diff-lane-a-vs-b-mode.png)

Run #1 at `0x00C0019B`, one byte: `CAL_MODE=1` against `CAL_MODE=2`, the two `${MODE}`
values. Every other byte of the two images is identical.

## Features of this window

| Feature | How | Capture |
|---|---|---|
| Import… a lane | button | 18.2, 18.3 |
| sequential / parallel | click, Enter, space | 18.4, 18.8 |
| Parallel lanes with per-flow variables, per-lane bindings | Import…, Bind, Run | 18.8 |
| Run, lane states, cable glyphs, run log | button | 18.5, 18.6 |
| Image file + Bind per lane | type, button | 18.4 |
| REQUIRED line, Confirm | `c` / button | 18.5, 18.6 |
| Set name, Save Set, saved sets, Load Set | type, buttons | 18.7 |
| Open session, `?`, legend | chips | 18.1 |

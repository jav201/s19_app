# Inc 9 — Confirm re-run report, saved flow names, flow and chain-set saves inside the work area: requirements (E1)

Batch 2026-11-01-batch-101, increment 9. Base: `98d94d7` (branch `b101-inc9` = main). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Findings: F-45, F-46 (DOSSIER §5), D15-18 (P0 ruling, PLAN.md; CODE-CHANGES S15), and the BACKLOG-CODE row routed by Inc 16 (E3 ruling A16-4: the `flow_screens.py` docstring). Scope, decisions and reasons: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc9.md`.

Form column: U = ubiquitous, E = event (`When`), N = unwanted (`If … then`). "Base" column: what `98d94d7` does today. B = the E1 pilot on the base tree (Linux, Python 3.11, `evidence-e1/i9e1-pilot-transcript.txt`); R = read in the code, not run.
Row status: **canon** = the row's text is unchanged, the code is made to meet it; **changed** = the canon row's wording is corrected here (`E1-rulings.md` §2); **new** = a new canon row (id checked unused in `REQUIREMENTS.md`, in every increment folder of the batch and in the requirements re-write session's files).
Decisions the orchestrator rules on are in `E1-rulings.md` §3. The rows below follow the recommended option of each (D-1 C, D-2 yes, D-3 cut, D-6 yes).

## User stories

### US-I9-1 — a confirm re-run's report says what ran (F-45)
As the operator, when I confirm an external step in Flow Execution, I want the chain-set report that the re-run writes to say it is the confirm re-run of that one lane, so that the reports folder never records a sequential set of one chain that I never ran.

### US-I9-2 — a saved flow keeps its own name (F-46)
As the operator, I want a flow file to hold the name it is saved under, also after Clear and on a name clash, and Clear to start a flow with the default name, so that no file, lane report or Builder screen shows the name of another flow.

### US-I9-3 — flow and chain-set saves stay in the work area (D15-18)
As the operator, I want a flow save and a chain-set save to refuse a `flows/` or `flowsets/` folder that is a link or lies outside the work area, and never to write through a link that has the name of the file, so that no save lands outside the work area.

## Definitions (additions and changes to CTX-CHAIN, CTX-FLOWFILE and CTX-FLOWREPORT; terms only)

- **Confirm re-run** (CTX-CHAIN, new). The run of one lane that a confirm starts (S15 R-FLOW-CHAIN.9, S16 R-FX-WAIT.5, `c` or Confirm). It is not a run of the chain set.
- **Mode of the chain-set report** (CTX-FLOWREPORT, changed: the chain-set report line `Mode` now lists its values). `sequential` or `parallel` for a run of the set (the switch's mode); `confirm re-run` for a confirm re-run. Line form: `- **Mode:** <mode>`.
- **File stem** (CTX-FLOWFILE, new). A flow file's or chain-set file's name without `.json`: the saved name, with its `_<N>` when a clash gave one.
- **Link** (CTX-FLOWFILE, new; as Inc 6's "Linked folder"). A symbolic link, or a Windows junction or other reparse point.
- **Passes through a link** (CTX-FLOWFILE, new). The home folder itself, or a folder between it and the work area, is a link (the walk of the shared destination guard of S11 R-MAN-WRITE-001.5).
- **Exists** (CTX-FLOWFILE, new; as R-FLOW-FILE.2 and R-FLOW-SET.3 use it). The home folder holds an entry of that name: a file, a folder or a link, also a link whose target is missing.
- **Status texts** (exact, new): `Flow not saved - the project's flows folder is a link or is outside the work area.` and `Chain set not saved - the project's flowsets folder is a link or is outside the work area.` (style of S11 R-PROJ-DOC.9 and S16 R-FB-SAVE.6, R-FX-SET.4).

## Requirements

### F-45 — the report of a confirm re-run (US-I9-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-FLOW-CHAIN.19 | E | When a lane's confirm re-run ends, the system shall write a chain-set report of that lane alone into `<project>/reports/`. | 1/1: a parallel set of 3 lanes (`patch_chain`, `flash_chain`, `patch_chain_b`; `flash_chain` waits at block 3) — the confirm adds exactly 1 `*-chain-set-report.md`, with `- **Chains:** 1` and 1 Chain ledger row, naming `flash_chain` | write no report for a confirm re-run (option A of D-1) → 0 new reports → RED | US-I9-1 | new (the confirm's report that S16 R-FX-RUN.14 already names) | **Yes** (B: 1 new report, `Chains: 1`, 1 ledger row) |
| R-FLOW-CHAIN.20 | U | The system shall record the line `- **Mode:** confirm re-run` in the chain-set report of a confirm re-run. | 2/2: the confirm's report in a parallel set and in a sequential set each hold `- **Mode:** confirm re-run` and 0 lines `- **Mode:** sequential`; the Run's report of the parallel set keeps `- **Mode:** parallel` (1/1, R-FLOW-CHAIN.14) | record the mode the lane was dispatched in (`sequential`, the base) → RED | US-I9-1 | new | **No** (B: `- **Mode:** sequential` after a parallel Run) |

### F-46 — the name in a flow file, and Clear (US-I9-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-FLOW-FILE.12 | E | When the operator saves a flow under a file stem of at most 64 characters, the system shall write that file stem as the flow file's `name`. | 4/4: Save as `tune_b` after Clear of the loaded `patch_chain` → `"name": "tune_b"`; a second save as `tune_b` → the second file's `name` equals its file stem; `Nightly Release!  ` → `"name": "NightlyRelease"`; a 64-character stem → the whole stem | serialize the flow's display name (the base) → the first case gives `patch_chain` → RED | US-I9-2 | new | **No** (B: `flows/tune_b.json` holds `"name": "patch_chain"`; the clash file `tune_b_2.json` holds `"name": "tune_a"`) |
| R-FLOW-FILE.13 | N | If the file stem of a flow being saved is longer than 64 characters, then the system shall write the first 64 characters of the file stem as the flow file's `name`. | 2/2: a 65-character stem and a 64-character stem with a clash suffix (`<64>_2`) each give a 64-character `name` that is the stem's start, and each file loads with 0 findings | write the whole stem → the load gives `FLOW-BAD-FIELD` (`flow name exceeds 64 characters`) → RED | US-I9-2 | new | n/a — the base writes the display name; a display name over 64 characters gives a file that loads with `FLOW-BAD-FIELD` (B) |
| R-FB-RUN.8 | E | When the operator presses Clear, the system shall name the flow `flow`. | 2/2 after loading `patch_chain` and pressing Clear: the ribbon starts `Flow: flow`; Save… opens with `flow` in the name box | keep the name on Clear (the base) → `Flow: patch_chain` → RED | US-I9-2 | new (D-2: the ribbon text after Clear changes from the stale name to `flow`) | **No** (B: ribbon `Flow: patch_chain`, name box `patch_chain`) |

### D15-18 — flow and chain-set saves inside the work area (US-I9-3)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-FLOW-FILE.11 | N | If the flows home passes through a link or resolves to a folder outside the work area, then the system shall save no flow file. | 2/2: `flows/` a link to a folder outside the work area, and `flows/` a link to another folder of the same project → 0 files written in the link's target and 0 new entries in `flows/`; control: a plain `flows/` saves 1 file | call no guard before the write (the base) → the file lands in the outside folder → RED | US-I9-3 | changed (adds "passes through a link or": the shared guard refuses every link, Inc 6 E3 ruling S-3) | **No** (B: `flows/x.json` written into the outside folder) |
| R-FLOW-SET.7 | N | If the flowsets home passes through a link or resolves to a folder outside the work area, then the system shall save no chain-set file. | 2/2: as R-FLOW-FILE.11 for `flowsets/` | as R-FLOW-FILE.11 → RED | US-I9-3 | changed (as R-FLOW-FILE.11) | **No** (B: `flowsets/s.json` written into the outside folder) |
| R-FLOW-FILE.14 | N | If a link in the flows home has the name of a flow file that the save would write, then the system shall write no file through that link. | 2/2: a link `flows/z.json` whose target is missing, and one whose target is an existing file outside the work area → Save as `z`: 0 files created or changed at the target, the link unchanged, and 1 new plain file `flows/z_<N>.json` (R-FLOW-FILE.2, "exists") | test the name with a check that follows links and write without an exclusive create (the base) → the missing target is created → RED | US-I9-3 | new (D-6) | **No** (B: a link `flows/z.json` to a missing target outside: the save creates that file) |
| R-FLOW-SET.8 | N | If a link in the flowsets home has the name of a chain-set file that the save would write, then the system shall write no file through that link. | 2/2: as R-FLOW-FILE.14 for `flowsets/` | as R-FLOW-FILE.14 → RED | US-I9-3 | new (D-6) | **No** (R: `save_chain_set` has the same `exists()` test and `write_text`, `flow_persistence_service.py:1500-1508`) |
| R-FB-SAVE.8 | N | If a flow is not saved because its flows home passes through a link or resolves outside the work area (S15 R-FLOW-FILE.11), then the system shall show the status `Flow not saved - the project's flows folder is a link or is outside the work area.` | 1/1 through Save… and the dialog's Save: the status line holds exactly that text | show the empty-name status (R-FB-SAVE.6) for this refusal → RED; let the refusal escape the handler → RED | US-I9-3 | new | **No** (R: the save lands outside and the result area shows `✓ saved flows/<name>.json`) |
| R-FX-SET.15 | N | If a chain set is not saved because its flowsets home passes through a link or resolves outside the work area (S15 R-FLOW-SET.7), then the system shall show the status `Chain set not saved - the project's flowsets folder is a link or is outside the work area.` | 1/1 through Save Set: the status line holds exactly that text | show the R-FX-SET.4 status for this refusal → RED | US-I9-3 | new | **No** (R: the save lands outside and the ribbon shows `· saved`) |

### Acceptance

The acceptance cases `AT-I9-1` … `AT-I9-3` of `02-test-cases.md` drive the app through its keys and dialogs: the Chapter 18.8 confirm in a parallel set (R-FLOW-CHAIN.19, .20), the Chapter 17.10 Clear and Save (R-FB-RUN.8, R-FLOW-FILE.12), and a save into a linked `flows/` and `flowsets/` (R-FLOW-FILE.11, R-FLOW-SET.7, R-FB-SAVE.8, R-FX-SET.15).

## Counts

11 rows: 9 new (R-FLOW-CHAIN.19, R-FLOW-CHAIN.20, R-FLOW-FILE.12, R-FLOW-FILE.13, R-FLOW-FILE.14, R-FLOW-SET.8, R-FB-RUN.8, R-FB-SAVE.8, R-FX-SET.15), 2 changed (R-FLOW-FILE.11, R-FLOW-SET.7). Context-note changes: CTX-CHAIN (confirm re-run), CTX-FLOWREPORT (Mode values), CTX-FLOWFILE (file stem, link, passes through a link, exists, status texts). A16-4 has no row (a docstring is not behaviour; `E1-rulings.md` D-8).

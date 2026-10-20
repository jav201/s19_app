# Code-Wire overview of batch-97 (high level)

This file is the index of the batch graphs. It is not a graph source. The method says that the overview is a view that a tool generates from the text (C14). The view is `views/overview.svg` (and `.png`), and `views/gen_views.py` generates it.

## Flows and why they are in the graph

Code-Wire nodes are functions with a domain step. Most of batch-97 is layout (CSS splits, widget trees, colours), and layout has no function contract. So the graph covers five flows only.

| Flow | Graph file | Why it is a flow | Decisions and interfaces |
|---|---|---|---|
| Patch Editor document to JSON view and stamp | `graph-patch-json.md` | a document goes through a serialiser to a view, under a stamp with two triggers | D1, D2, D3, D4, I-2/I-3 |
| Open-folder chip | `graph-chip-open.md` | a family goes to a target, a guard and an open seam or a refusal | I-1, D9 |
| NUL or unsafe ref refusal | `graph-nul-refusal.md` | a ref goes from three loaders to one shared guard | I-6 |
| Waiting lane confirmed by key | `graph-confirm-key.md` | a key goes to a confirmation, a re-run and a repaint | D10, D13, D14, D15, I-7 |
| Width derivation | `graph-width.md` | D21 declares pure functions of width, so they are real contracts | D5, D21, D22 |

Some design items are not in the graph: the widget trees of §3, the TCSS sections (D23) and the help bodies (D25). The glyph vocabularies (D7) are constants. The mode toggle (D13) is a widget, and D8 removes a branch. None of them has a domain step.

## Node count by status

The status is a review fact, not a graph field. `views/gen_views.py` reads it from `extract/marks.json` and from the example markers. NEW = no def at `7d823a7`. CHANGED = a `synthetic` example on a node with code, or a signature drift. `views/status.json` has the list.

| Flow | NEW | CHANGED | SHIPPED | Total |
|---|---|---|---|---|
| patch-json | 2 | 6 | 9 | 17 |
| chip-open | 2 | 5 | 2 | 9 |
| nul-refusal | 0 | 7 | 3 | 10 |
| confirm-key | 2 | 5 | 2 | 9 |
| width | 8 | 4 | 0 | 12 |
| **batch** | **14** | **27** | **16** | **57** |

## Links between flows

- `confirm-key` and `nul-refusal` share `run_chain_set`. A NUL ref bound to a lane reaches the shared guard through `run_flow` and `_chain_inputs`.
- `patch-json` and `width` share the before/after card: `refresh_entries` repaints it, and the layout gives it its byte count.
- `chip-open`, `nul-refusal` and the shipped `scoped_home` share `_path_traverses_reparse_point`, the reparse-point walk.
- `chip-open` and `confirm-key` share `[Data: S19TuiApp active project]` and `[Interface: status line]`.

The annex `CODEWIRE-PDR.md` has the rule verdicts, the drift table and the findings.

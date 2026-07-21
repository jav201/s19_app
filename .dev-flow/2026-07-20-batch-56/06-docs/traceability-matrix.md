# 06 — Traceability matrix · batch-56 (alignment-aware padding sizing)

> No gaps: every US → HLR → LLR → TC (functional) AND US → AT (behavioral). Scale note: for a one-function parser change the Phase-6 executive-summary/diagrams are disproportionate; this matrix + the functionality note below are the docs deliverable (recorded as an autonomous scope call).

## Functionality (technical-stakeholder view)
A CURVE/MAP CHARACTERISTIC's on-disk byte `length` (shown in the A2L view, used for the byte-range memory check) is derived by `_record_layout_full_span` summing its RECORD_LAYOUT components × inline axis counts. Before batch-56, any RECORD_LAYOUT that declared an `ALIGNMENT_*` directive was force-`None` (grey, never wrong but never checkable). batch-56 models the ASAM alignment semantics: each component's start offset is aligned up to the alignment declared for its datatype's size-class (`_DATATYPE_ALIGNMENT_DIRECTIVE`), via a cumulative-offset walk. **Layout-local only** — module-wide `MOD_COMMON` defaults are not honored (R-A), which preserves every pre-existing (packed) oracle by construction. **No trailing record pad** (R-C) — the span is the last data component's end offset (a single object's data footprint, not an array stride). Full-span-or-None safety is retained: an unmodeled directive, unknown datatype, absent axis count, malformed/non-positive alignment, or an over-cap offset all yield `None`.

## Behavioral chain (US → AT)
| US | Outcome | AT (all through `parse_a2l_file`) |
|----|---------|-----------------------------------|
| US-A56 | alignment-declaring CURVE/MAP sizes correctly; packed/demo/external unchanged | AT-113 (16/packed 13 + consumer), AT-114 (demo 25/51/12/None, 0 drift — anchor), AT-115 (R-A isolation), AT-116 (unmodeled→None), AT-117 (pad=0→10), AT-118 (over-align→16), AT-119 (R-C→17), AT-120 (DoS→None), AT-122 (hostile value→None) |
| US-P2b56 | frozen guards pass; merged==main | AT-121 (post-merge PR-B) |

## Functional chain (US → HLR → LLR → TC)
| HLR | LLR | Touched symbol | TC |
|-----|-----|----------------|-----|
| HLR-A56 (R-A2L-016) | LLR-A56.1 walk | `_record_layout_full_span`, `align_up` | TC-144, TC-146, TC-150 |
| | LLR-A56.2 map+collector | `_DATATYPE_ALIGNMENT_DIRECTIVE`, `_ALIGNMENT_DIRECTIVES`, `_collect_declared_alignments` | TC-143, TC-145 |
| | LLR-A56.3 packed no-regression | (alignment-free branch) | TC-147 |
| | LLR-A56.4 MOD_COMMON excl + full-span-or-None | `_record_layout_full_span`, `_collect_declared_alignments` | TC-148 |
| | LLR-A56.5 fail-closed (incl. non-positive + DoS) | `_collect_declared_alignments`, `align_up` | TC-149 (+ TC-145/146 negatives) |
| | LLR-A56.6 unfreeze | `_ENGINE_PATHS` ×2 | TC-152 |
| | LLR-SUP56.1 supersede TC-133b | `test_tc133b_...` | TC-151 |
| HLR-P2b56 (R-A2L-017) | LLR-P2b56.1 re-freeze | `_ENGINE_PATHS` ×2 | TC-153 (PR-B) |

## Requirements-traceability (REQUIREMENTS.md)
- `R-A2L-016` (this batch) → `s19_app/tui/a2l.py::_record_layout_full_span` → `tests/test_a2l_alignment_sizing.py` — status **Automated**.
- `R-A2L-017` re-freeze → guard files → PR-B — status **Automated (post-merge)**.
- AMD-2 prose appended to `REQUIREMENTS.md` CURVE/MAP length section.

## Evidence
- Gate suite `_gate_run.txt` (1794 passed; 19 pre-existing snapshot-only failures, non-batch-56). Frozen dual-guard 7/7. Independent code-review APPROVE. 0 orphans, 0 UNREALIZED (C-18).

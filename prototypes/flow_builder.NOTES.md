# Prototype verdict — Flow Builder state model

**Prototype:** [flow_builder.prototype.py](flow_builder.prototype.py) — runnable logic
prototype (`python prototypes/flow_builder.prototype.py`). Stubs all S19 parsing; models
only block-threading semantics. Extends the shipped tracer (`flow_model.py` +
`flow_execution_service.py`, SOURCE→PATCH→WRITE-OUT) with LOAD-notices, CHECK, CRC,
config/template inputs, flow save/load, and variant reuse.

## Questions put on trial + what the prototype showed

| # | Question | Finding (driven by hand) |
|---|----------|--------------------------|
| Q1 | Load validates integrity but must NOT block downstream | **Needs a new `notices` block status** + a WARN/STOP severity split. Integrity findings on `warn.s19` surface as WARN notices, flow still runs to WRITE-OUT. Only an unresolvable image (`missing.s19`) is a STOP → chain dies. ✅ works |
| Q2 | CHECK is read-only, output "None, pass s19 along" | **The key asymmetry:** a CHECK failure records a block error but does NOT break the image → downstream WRITE-OUT still runs and produces a file (Case B). Contrast LOAD/PATCH failure, which breaks the image → downstream SKIPPED (Cases A/C). ✅ works |
| Q3 | CRC reads whole image, writes CRC back, may GROW ranges | **The ADR §7 seam holds in the linear model.** `crc32_append` writes outside the loaded range → working image grows `0x8000-0x8FFF` → `+ 0x9100-0x9103`, and the later WRITE-OUT picks up the grown image. Confirms ADR §7 option (a): split CRC into a pure inject-stage that returns extended `(mem_map, ranges)` + the shared write-out. CRC-before-any-PATCH is a WARN notice, not a crash. ✅ works |
| Q4 | External file → import into project on Load | Modeled as a `external=True` flag + provenance string. Structurally fine; the real import (copy-into-workarea + containment) is reused, not rebuilt. ✅ shape ok |
| Q5 | Same saved flow, different input (variant reuse) | `X <variant>` reruns the identical flow with a source override → same blocks, `variant2.s19` in, same notices/CRC/output. This is the automation payoff. Flow (de)serializes through a v2 `flow.json` envelope (`json` command shows it). ✅ works |

## OPEN design forks (operator to decide — they change /tui-design + /dev-flow output)

1. **Whole-flow status when a read-only (CHECK) block errors but the image is still
   produced.** Prototype currently demotes the whole flow to ERROR on *any* block error
   (Case B shows ERROR even though the file was written). "Notify don't block" argues for a
   distinct **`completed-with-issues`** flow outcome (amber), separate from **`failed`** (red =
   no/broken output). — DECISION NEEDED.
2. **Is CHECK always advisory, or should it be gate-able?** Prototype makes CHECK failure
   never abort. But "patch → verify → only then write" is a real intent. Option: a per-CHECK
   `gating: advisory | block` flag. — DECISION NEEDED.
3. **CRC = one template-driven block (as prototyped) vs CRC-as-a-sub-flow** (your backlog:
   "craft the CRC with blocks as well" — fill-gaps → poly → endianness → write-back). The
   prototype does the single-block version; the sub-flow is nested-flow architecture. Which
   ships first? — DECISION NEEDED (prototype recommends single-block now, sub-flow as a later
   batch, since the single block already exposes every config knob via the template).

## Decision (operator, 2026-07-19)

1. **Flow status:** adopt `completed-with-issues` (amber) distinct from `failed` (red). It
   **must be reflected in any generated report** when a report is produced.
2. **Check gating:** per-block gating flag adopted — BUT the guiding invariant is **the chain
   is never blocked**; a *block* can mark *itself* blocked only when *its own operation is
   invalid*. The validation/blocking rules are **highly user-visible**, so `/dev-flow` must
   spec them with maximum clarity/visibility — cautious, explicit, no hidden chain-killing.
3. **CRC:** ship the **single template-driven block now**. CRC-as-a-sub-flow (blocks like the
   Flow Builder, but for CRC internals) is a **later batch — to be done very thoroughly.**

## Screen prototype (TUI design pass, 2026-07-19)

[flow_builder.screen.prototype.html](flow_builder.screen.prototype.html) — full-screen HTML mock
of **Direction A "Pipeline Ledger"** (operator-chosen), static (no-JS) so it renders anywhere. Shows
the SAME screen at **two regimes** (operator asked for the dense/wide common case):
- **Wide · high-density (~150 cols, smaller type)** — pipeline gains per-block `inputs` / `Δbytes` /
  `ranges after` columns (the running footprint evolving down the chain) + a right **Run-detail pane**
  (status counts, full check table, produced artifacts) + a 96-cell ribbon with address ticks.
- **80×24 floor** — the constrained fallback; detail columns + right pane collapse to vertical-only.
Same Direction A, responsive — not a second design. Signature element = the **twin memory ribbon**
that visibly grows on CRC (state 3). App's live tokens (`sev-*` + `accent-calm`). CRC + Save/Load
carry `batch-51`/`batch-52` tags (shown for the vision; not in batch-50).

**Block separators (operator request 2026-07-19):** each block is divided by a horizontal rule with
the flow arrow centered on it (`──── ▼ ────`) so a human reads each block as a discrete object while
still seeing flow direction. In the real Textual build → a `Rule`/border between block widgets, tone
`$rule #1b233a`. Carry into batch-50 UI LLRs.

## Dev-flow kickoff decisions (2026-07-19)

- **3-batch split APPROVED:** batch-50 = CHECK + notices/`completed-with-issues` status model +
  LOAD integrity-notices + Direction A UI. batch-51 = CRC (template library + address-space growth,
  ADR §7 split). batch-52 = flow.json save/load + external→import + variant reuse. Backlog: PKI
  binary-region extraction · CRC-as-sub-flow ("be very thorough") · multi-image scope.
- **Autonomy:** batch-50 runs autonomous + may self-merge (final PR-level qa gate). Decision-log
  protocol confirmed. (Per-batch; re-ask at batch-51/52 kickoff.)
- **HELD at the prototype boundary (operator):** advance to the prototype phase ONLY; do NOT run
  `/dev-flow-init`. Wait for the in-progress **`claude/a2l-cleanup-batch-7dcd53`** batch to land
  first. batch-49 is also `awaiting-sync` (run `/dev-flow-sync`).

**Next:** when the a2l-cleanup batch lands, start batch-50 via `/dev-flow` (Direction A + the
prototype-validated model as inputs). Delete this prototype dir once the model is folded in.

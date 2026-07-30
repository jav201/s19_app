# batch-70 — what the feature does

**Audience:** an operator using the Flow Builder, and the next engineer to touch it.

## Using it

1. Open the Flow Builder (rail **8**) with a project loaded that declares several image variants.
2. Compose the flow as before — the SOURCE block's own ref is what an unscoped run uses.
3. Pick a **scope** next to Run:

| Option | Runs over |
|---|---|
| **This image** *(default)* | today's single-image path, completely unchanged |
| **All variants** | every variant the project declares |
| **Assigned variants** | only variants holding a non-empty manifest assignment |

4. Press **Run**. The result pane shows the rolled-up banner, the line that inverts it
   (`3 variant(s): 2 ok / 0 issues / 1 error`), one node per variant, and the path of the single
   fused report.

A variant scope with no declared variants renders an error card rather than quietly running one
image — *"it ran, over something you did not ask for"* is the worse failure.

## What the fused report contains

```
# Fused flow report — <flow name>
- Generated / Status / Variants executed / Outcome counts

## Variant summary          <- one row per variant, ALWAYS emitted
| Variant | Status | Blocks | Findings |

## Variant details
### <variant_id>            <- one section per variant, ALWAYS emitted
- Status / Footprint / Wrote
| # | Block | Status | Summary |   <- capped per variant
- **[SOURCE #1]** (warn) …          <- capped per variant
> **Cut in `<variant_id>`:** findings: 25 omitted (cap 60 per variant).
```

Three properties are worth knowing because they are deliberate:

- **The status is the worst across variants, and the counts that invert it are printed beside it.** A
  single word over N images hides exactly what you opened the report to see.
- **Caps are per variant, not per document.** One pathological image cannot evict another's evidence.
- **Every cut is named with its dropped count.** A silent truncation in an evidentiary document reads
  as "covered everything".

## What it deliberately does not do

- **It does not write one report per variant.** With a REPORT block in the flow, each variant's report
  is *deferred* — the block still shows in that variant's ledger as `deferred to the fused report`,
  and one fused document is written instead. N files would re-create the manual collation this
  feature exists to remove.
- **It does not touch the flow file.** Binding N images to a flow is a property of the *run*; the
  saved flow stays a reusable recipe.
- **It does not accept a path list.** The image set comes from the project's own variant machinery, so
  a flow can never name an image outside the project.

## For the next engineer

The binding point is `run_flow`'s signature, `FlowContext`, and the SOURCE branch of
`flow_execution_service` — **not** the CRC handler's `OperationInput`, whose `variant_id` is
operations-kernel reporting metadata and has nothing to do with this.

The per-variant image ref is derived as `path.relative_to(project_dir).as_posix()` and passed through
the **reused** `_resolve_manifest_entry`. It is relative on purpose: that seam **rejects absolute refs
by design**, so the descriptor's own path would fail every variant. Do not "fix" this by bypassing
the seam — the shared containment boundary is the point, and multi-image multiplies any escape.

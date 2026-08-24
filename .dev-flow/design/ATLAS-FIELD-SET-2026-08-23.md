# Atlas field set — FROZEN BY EXECUTION, not asserted (handoff §9 action 1)

> **Written 2026-08-23.** Discharges action 1 of `HANDOFF-atlas-ifc-2026-08-22.md` §9 under the
> D-VII ruling (`DECISION-D-VII-2026-08-23.md`: hybrid — the Atlas is the DERIVED plane).
> Every figure below is re-derivable by ONE command; if it disagrees, **the command is right**:
>
> ```bash
> cd <worktree>                      # dev-flow-68a67d
> python tools/atlas_probe.py        # 1.7 s; byte-identical across two processes (verified)
> ```
>
> `tools/atlas_probe.py` is a DISCOVERY PROBE, not the shipped `--atlas`. It imports the canon
> validator by path and derives every IFC figure from `_ifc_corpus()` and the real rule
> functions (§5.1: never a second parser). **Delete it when `--atlas` lands in
> `devflow-validate.py` (rev42+).**

## 1 · The corpus at the cut (all from the probe run)

| | |
|---|---|
| IFC | 2 FLOW (9 nodes, all owned) + 1 COMPONENT (5 OUTPUTs) — all in batch-85's record |
| requirement files | 62 × `01-requirements.md` · 519 declared US/HLR/LLR heading ids |
| registry | 1,372 rows — LIVE 893 · BURNED 422 · RESERVED 36 · RETIRED 21 |
| batch dirs | **67 matching the pattern + 1 that does not** (`2026-07-23-batch-n8`) |
| regeneration cost | **1.73 s** wall, full derivation incl. the V13 tree scan |

## 2 · What IS derivable today — the frozen minimum field set

| Atlas file | Field set the corpus can populate NOW | Source |
|---|---|---|
| `ATLAS-IFC.md` | per FLOW declaration: `(id, src:line)` + per node `(fn, owner)`; per COMPONENT declaration: `(id, src:line, parent, inputs)` + per OUTPUT `(id, value, address, cardinality, consumers, owner)` — output field census measured 6/6 fields present on all 5 OUTPUTs; **one row per declaration, never `{id: comp}`** (§5.4) | `_ifc_corpus()` + real rules for STATUS |
| `ATLAS-TRACE.md` | per AT/TC id: `(id, status, conforming, origin [, provenance file:line])`; per US/HLR/LLR id: `(id, realms that mention it)` — **location only, no state** (see §3.3) | registry + tree scan |
| `ATLAS-BATCHES.md` | per batch dir: `(dir, presence/absence of 01/02/03-increments/04/05-postmortem/05-close/state.json/PLAN.md)` — presence is derivable for **all** dirs; anything richer is not (see §3.4) | `os.walk`, sorted |
| `ATLAS-ORPHANS.md` | the four joins measured: 1,010 US/HLR/LLR in batches never in `REQUIREMENTS.md` · 5 in `REQUIREMENTS.md` in no batch · 553 registry ids never mentioned by `tests/` · 291 corpus heading ids not in `REQUIREMENTS.md` — **plus the mandatory UNPARSED census (§5.3), 54 items today** | joins of the above |

## 3 · CANNOT-PRODUCE — the one-way doors, each now a measured fact

1. **No `surface` field exists anywhere in the corpus.** A per-surface Atlas grouping is not
   derivable. **Decide before surface #2 is authored** (§4.1's one-way door): either add
   `surface :` to the COMPONENT field set in `ifc-template.md`, or accept grouping by source
   file. Retrofit cost today: 1 record. After 26 more: 27 records.
2. **950 of 1,372 registry rows have no `provenance`** (0 of the ones that do dangle).
   TRACE renders those ids state-only, no file:line. Backfill is possible but is authored
   work, not derivation.
3. **US/HLR/LLR have no registry and no status field anywhere.** TRACE can say *where* a
   requirement id is mentioned, never *what state it is in*. A state column for requirement
   families would require a new authored source — that is canon-plane work under D-VII, not
   Atlas work.
4. **§4.2's declared source for `ATLAS-BATCHES` covers a fraction of history:** `state.json`
   exists for 4/67 batches, a parseable `**Date:**` header for 7/59 postmortems, 8 batches
   have no postmortem at all (1 is `05-close.md` — closed unfinished). **BATCHES must key on
   artifact presence/absence** — the only field derivable across all 68 dirs — with the
   richer fields rendered opportunistically where they exist. Backfilling 63 `state.json`
   files is authored work and nobody has asked for it.

## 4 · Canon-parser findings the shipped `--atlas` must carry (rev42 scope)

- **P1 — `_parse_ifc` has no block terminator.** Measured: `project_row`'s `owner` field
  absorbed **801 chars** of trailing document prose (`01-requirements.md:371` — §5.5's quoted
  verdicts are indented, and indented lines after the last item keep feeding its last key,
  straight through the closing fence). No rule misfires today because V11 never reads `owner`
  — but an Atlas rendering `owner` verbatim would print the contamination as data. The probe's
  mitigation (scalar-field absorption census: flag any newline in `id/address/cardinality/owner`,
  render first line + `[+ABSORBED]`) is the pattern; fixing the canon parser instead touches
  5 rules + arms and is a rev42 decision.
- **P2 — a pattern-keyed batch walk silently drops nonconforming dirs.** Measured:
  `2026-07-23-batch-n8` — invisible to `batch-\d+` keying. The census must list what the
  pattern rejects (this is §5.3 applied to BATCHES).
- **P3 — the handoff's "149 `R-*`" figure is false as written.** `REQUIREMENTS.md` carries
  no `R-*` namespace (27 unique `R-\d+` matches tree-wide, mostly prose collisions); its id
  families are US (67 stems) · HLR (74) · LLR (82). The Atlas points into `REQUIREMENTS.md`
  by US/HLR/LLR, not by `R-*`. (`CLAUDE.md`'s "R-* requirement" wording inherits the same
  fiction — flagged, not fixed here.)

## 5 · Answered by measurement (closes handoff §9 items)

| §9 item | Answer |
|---|---|
| 1 — freeze field set by execution | **Done — this document.** §4/§5 of the handoff stop being a hypothesis for the IFC pane; §2 above is the frozen set |
| 4 — time the regeneration | **1.73 s** full, incl. V13 tree scan. Under the ~10 s line ⇒ `V20` regenerates fully at every gate; no mtime degradation needed |
| 0 — D-VII | Ruled hybrid, see `DECISION-D-VII-2026-08-23.md` |

## 6 · Still open before `--atlas` ships

- **D-III** (third artifact-selection semantics) — still BLOCKING adoption, per §7.
- **§5.4 synthetic colliding-id corpus** — build two synthetic batches with one colliding
  COMPONENT id and assert the renderer emits both rows; do it before surface #2 exists.
- **rev42**: `--atlas [--write]` + `V20` digest guard + arms in `--selftest`, authored in the
  canon (`~/.claude/docs/tools/devflow-validate.py`), never in `skills/dev-flow/` (§10.2).
- The `surface` field decision (§3.1 above) — cheapest today, priced per record thereafter.

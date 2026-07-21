# Phase-2 Cross-Review — Architect Lens — Batch 58 (CRC Algorithm Designer view + engine prereqs)

**Reviewer:** architect · **Date:** 2026-07-20 · **Artifact:** `.dev-flow/2026-07-20-batch-58/01-requirements.md`
**Governing design:** `docs/crc-algorithm-designer/01-requirements.md` (approved) · **Base keel:** `84180b4` (#110)
**Evidence base:** real checkout `C:/Users/jjgh8/OneDrive/Documents/Github/s19_app`, branch `feat/batch-58-crc-designer-view`.

---

## 1. Verdict (BLUF)

**PASS — no blocker. The artifact is approvable to Phase 3 as-is.** All 11 stories are correctly scoped and derived US→HLR→LLR; both traceability chains (behavioral US→AT and functional US→HLR→LLR→TC) are present and complete. Every HLR/LLR statement is normative `shall`; **no `should`/`debería` appears inside any HLR/LLR** (the four `must` tokens all live in assumptions/rationale/risks, which is legal). All four claimed keel-API bindings match the on-disk API. The two open questions the author flagged are resolved below — neither forces iterate-to-refine.

- **Blockers: 0** · **Major: 0** · **Minor: 2**
- No re-open of Phase 1 required. Proceed to Phase 3 with the two minors folded into the increment plan.

---

## 2. Findings

| # | Severity | Location | Finding |
|---|----------|----------|---------|
| F1 | minor | `01-requirements.md` LLR-V1.1 (line 366) + numeric threshold (line 369) | The LLR enumerates the additive edits as `_compose_screen_crc_designer` + `SCREEN_CONTAINER_IDS` + `RAIL_ENTRIES` + reuse of `action_show_screen`, but does **not** name the required new `Binding(...)` in `BINDINGS` (app.py:1285-1321), and does not surface that numeric keys **1-9 are fully exhausted** (app.py:1313-1321). Yet the pass threshold asserts "activating the CRC Designer **rail key** shows `#screen_crc_designer`" — a keyboard action that the rail item alone does not provide (click-routing works without a key; keyboard access needs a Binding). Mitigated: §6.2 D-4 and LLR-V1.1 already flag "Rail-key assignment and 10th-entry glyph — assumed — verify per-regime in Phase 3." Recommendation: at Phase 3 pin the BINDINGS edit site and the key choice (see Adjudication 2). |
| F2 | minor | `01-requirements.md` LLR-E5.1 (line 330) | Cites `CrcTemplate` source at `crc_designer_model.py:109`; actual definition is `class CrcTemplate:` at **:110** (off-by-one citation). The other three symbols in the same line are exact (`parse_template` :504, `emit_template` :625, `read_template` :672). Cosmetic; reconcile at Phase 3/4 line-pin. |

No completeness, contradiction, or normative-keyword blocker found.

---

## 3. Adjudication of the author's flagged open questions

### Adjudication 1 — Story count 11 vs 10: **CONFIRM 11 is correct and complete.**
The tasking brief said "10 stories" but the design enumerates 3 remaining engine items (design §6 **E4/E5/E6** — E1/E2/E3/E7/E8 already shipped in the batch-57 keel #110) plus 11 view requirements (**R-CRC-DSN-001..011**). The spec collapses the 11 view reqs into 8 stories with full coverage: V1=R-001+R-006, V2=R-002, V3=R-003, V4=R-004, V5=R-005+R-007, V6=R-008+R-009, V7=R-011, V8=R-010 — every R-CRC-DSN view req is claimed by exactly one story. With E4/E5/E6 that is **11 stories total, all in scope, none missing, none duplicated.** The "10" in the brief was imprecise; the spec correctly flags this (line 101). No action.

### Adjudication 2 — Rail 10th-screen key/glyph/wiring: **the design-doc claim is ACHIEVABLE but INCOMPLETELY stated; concrete recommendation below.**
Grounded in the real code:
- `RAIL_ENTRIES` is a **fixed frozen 9-tuple** (`rail.py:79-89`); `Rail` defaults to it (`rail.py:234`).
- Numeric keys **1-9 are all bound** to `show_screen('<key>')` in `BINDINGS` (app.py:1313-1321). **No 1-9 slot is free.**
- `action_show_screen` is **fully data-driven** — it iterates `SCREEN_CONTAINER_IDS.values()` to hide-all-then-show-one (app.py:5273-5276). So the design doc's "**no new `action_show_screen` handler**" claim is **literally TRUE** — that method needs zero change.
- Click-routing is also data-driven: `RailItem.on_click` → `Rail.Selected` → `on_rail_selected` (app.py:5371) → `action_show_screen`. A 10th rail item is clickable/routable with **no key binding at all**.

But a 10th screen is **not** "just a `.hidden` toggle" — it requires **three additive edits**, and keyboard access needs a fourth:
1. `RAIL_ENTRIES` — append a 10th `RailEntry` (`rail.py`).
2. `SCREEN_CONTAINER_IDS` — add `"crc_designer": "screen_crc_designer"` (app.py:5174).
3. `_compose_screen_crc_designer` mounting `#screen_crc_designer` (`db-screen hidden`) into `#workspace_body`.
4. **A new `Binding` for keyboard access** — and since 1-9 are exhausted it **cannot be 1-9**.

**Concrete recommendation (Phase 3):**
- **Key:** `"0"` — the natural 10th digit, preserves the numeric-rail mental model, currently unbound. Add `Binding("0", "show_screen('crc_designer')", "CRC Designer", show=False)` to `BINDINGS`.
- **Glyph:** `⊕` (U+2295, circled plus) — semantically exact: CRC accumulation **is** XOR / mod-2 polynomial division (design §3.1). ASCII fallback: `R` (for cRc) — avoid `#`/`@`/`M`/`X` which read as the existing Workspace/MAC/Map glyphs and the `x` Operations action.
- **Label:** `"CRC Designer"`.
- **Wiring:** `RailEntry("crc_designer", "⊕", "R", "CRC Designer")` appended to `RAIL_ENTRIES`; the dict + Binding + compose method above. **No `action_show_screen` change, no `on_rail_selected` change** (both data-driven).
- This is a shared-chrome change → **triggers the C-22/C-28 snapshot census** (rail glyph/route snapshots + workspace baselines) → expect a canonical-CI snapshot-regen closeout PR. The spec already anticipates this (R-2, §6.3). The rail docstring/comments hard-code "nine" (`rail.py:6-13,74-78,182-183`) and will need updating to "ten" — enumerate at Phase 3.

Net: the claim holds, but the artifact should pin edit #4 (the Binding) and the key-1-9 exhaustion. Filed as F1 (minor, already partly flagged).

### Adjudication 3 — `sanitize_project_name` binding (LLR-V5.2): **RESOLVED — binding is solid, downgrade the R-5 caution.**
Real definition: `def sanitize_project_name(name: str) -> Optional[str]:` at **`s19_app/tui/workspace.py:329`**. It is **already imported into `app.py` at line 164** (`sanitize_project_name,`) and already used at `app.py:5976` (`cleaned = sanitize_project_name(payload.project_name)`). Because the CRC Designer view lives inside `app.py`, the symbol is already in the module namespace — **import-reachable with zero new import**. R-5's "assumed — verify symbol file:line at Phase 3" is now satisfied; no risk remains. LLR-V5.2 can bind directly to `workspace.sanitize_project_name` (`workspace.py:329`).

### Adjudication 4 — the four claimed keel-API bindings: **ALL CONFIRMED accurate on-disk.**
1. **`crc_template.py` facade re-export** — CONFIRM. No `crc_template.py` exists under `operations/` (absent from the operations grep). Source symbols exist: `parse_template` (`crc_designer_model.py:504`), `emit_template` (:625), `read_template` (:672), `CrcTemplate` (:**110**, spec cites :109 — see F2). The facade-as-NEW claim (D-1) is correct; a2l-facade convention applies cleanly.
2. **`encode_word`/`decode_word` NEW in `crc.py`** — CONFIRM. `crc.py` has only `encode_le` (:480), `decode_le` (:514), `encode_le32` (:542), `decode_le32` (:569) — **no `encode_word`/`decode_word`**. A4 pre-state is accurate; both are genuinely NEW. `decode_le` at :514 (cited by LLR-E4.2) confirmed.
3. **`parse_job` flat up-convert + `emit_job` NEW** — CONFIRM. `parse_job` (`crc_designer_model.py:554`) currently accepts only inline `algorithm` / `algorithm_ref` then requires `data["targets"]`; a flat `crc_config` (no algorithm/ref/targets) hits `else: raise ValueError("job needs an 'algorithm' object or an 'algorithm_ref'")` (line 605) → caught → **exactly one** "structurally invalid" error. Matches the spec's verified pre-state ("currently returns 1 error"). No `def emit_job` exists (grep). Both the up-convert branch and `emit_job` are genuinely the remaining engine work (D-3/A3 accurate).
4. **`store_word` big-encode / no big-decode** — CONFIRM. `store_word` (`crc_designer_model.py:290`) does `(value & mask).to_bytes(store_width, store_endianness)` — supports `"big"` and `"little"` for **encode**. There is **no big-endian decode anywhere** (`decode_le` is little-only). A4's claim ("big encode exists as `store_word`; no big DECODE exists anywhere") is exactly right; the E4 codec must add the big-endian decode path. `store_word` cited at :290 confirmed.

---

## 4. Cross-checks (completeness / contradiction / derivation / normative)

- **US→HLR→LLR derivation:** every US has exactly one parent HLR; every HLR decomposes into ≥1 LLR that binds to a real (or explicitly-NEW) symbol with a file:line. Chains are acyclic and complete. ✓
- **Dual traceability:** behavioral table (§5.2, US→observable outcome→shipped surface→AT) covers all 11 US; functional table (HLR/LLR→method→TC) covers all HLRs. Both first-class. ✓
- **Normative keyword hygiene:** every HLR/LLR statement uses `shall`. **No `should`/`debería` inside any HLR/LLR** (grep). The four `must` tokens are in A1 (assumption), two informative rationales, and R-4 (risk) — all non-normative. **No blocker.** ✓
- **Frozen-set safety:** planned files (`crc.py`, `crc_designer_model.py`, NEW `crc_template.py`, `app.py`, `rail.py`, CSS, NEW tests) — none intersect the frozen set (`core/hexfile/range_index/validation/a2l/mac/color_policy` + frozen test files). ✓
- **Preview-only guard (US-V8):** the negative AT-058-09 + inspection is a genuine falsifiable oracle (0 grep hits for the write symbols + `mem_map` object-identity). Well-formed. ✓
- **Scope boundary vs design §9:** out-of-scope set (checksum discriminator, `serialization.align`, reflected-poly entry, MOD_COMMON, multi-image) matches the design's deferred list. No scope creep. ✓

---

## 5. Evidence checklist

- [✓] Constraints stated explicitly — §2.4 (frozen set, orchestration-only, C-17, geometry, shared-chrome census) all present.
- [✓] At least 2 alternatives considered — engine location decisions D-1..D-4 weigh facade-vs-relocate, `crc.py`-vs-model placement; rail key/glyph alternatives adjudicated here.
- [✓] Recommendation has rationale tied to constraints — rail key `0`/glyph `⊕` grounded in real keymap exhaustion (app.py:1313-1321) + CRC=XOR semantics (design §3.1).
- [✓] Risks listed — §6.3 R-1..R-6 (framework fidelity, snapshot census, frozen census, geometry, name-binding, RK-3 carry); this review adds F1/F2.
- [✓] Cost/latency estimated where relevant — N/A (no runtime cost surface; engine is table-less bitwise with LUT already shipped E7). Noted.
- [✓] Diagram — N/A for a requirements review; the rail wiring is enumerated as a 4-edit list (Adjudication 2).
- [✓] What would change the recommendation is stated — if Phase-3 pilot shows Textual reactive recompute diverges from the prototype loop (R-1), the C-16 flags convert to concrete rework; if key `0` collides with a future binding, fall back to a letter key (e.g. `g`).
- [✓] Two-layer requirements — every story has a first-class Acceptance (black-box) block + `AT-NNN`; BOTH chains exist (§5.2). Verified present for all 11.

**All items ✓ — gate is not blocked.**

---

## 6. Recommendation to the orchestrator

**Approve Phase 1 → advance to Phase 3.** Carry the two minors into the Phase-3 increment plan:
- **F1:** pin the new `Binding("0", "show_screen('crc_designer')", ...)` edit in `BINDINGS`, add the 10th `RAIL_ENTRIES`/`SCREEN_CONTAINER_IDS` entries, update the "nine"→"ten" rail docstrings, and run the C-22/C-28 snapshot census (expect a regen closeout PR).
- **F2:** correct the `CrcTemplate` citation to `crc_designer_model.py:110`.
- Downgrade R-5 (`sanitize_project_name`): binding is proven (`workspace.py:329`, already in `app.py` namespace).

No iterate-to-refine back to Phase 1 is warranted.

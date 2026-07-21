# Phase-2 Cross-Review — QA / Testability lens — batch-58 (CRC Algorithm Designer view + engine prereqs)

> Reviewer: qa-reviewer · Date: 2026-07-20 · Artifact under review: `.dev-flow/2026-07-20-batch-58/01-requirements.md`
> Governing design: `docs/crc-algorithm-designer/01-requirements.md` (§7 R-CRC-DSN-*, §8 AT table).
> Keel verified against real source: `crc_kernel.py`, `crc_designer_model.py`, `crc.py`, `crc_config.py`, existing tests.

---

## BLUF (verdict)

**CHANGES REQUESTED — 3 BLOCKERS, 5 MAJORS, 5 MINORS.** The **engine half (E4/E5/E6)** is testable and realizable as specced — the oracles exist and are pinned (`DUMMY_CONFIG_TEXT` @ `crc_config.py:47` carries 2 regions + 1 two-span group with `reverse=true`/`poly=0x04C11DB7` → seed KAT `0xCBF43926`; `compute_group_crc`/`compute_region_crc` present @ `crc.py:419/210`; `parse_template`/`emit_template`/`read_template` are real, collect-don't-abort). The **view half** carries three ATs that **can pass while the feature is broken** (vacuous / shipped-surface-bypass), which is a blocker under the AT-authoring controls the tasking cited. None of the blockers is unbuildable — each is a wording/coverage fix, not a redesign. Engine LLRs may proceed to Phase 3; the view ATs must be sharpened first.

The batch's own self-flag (11 stories enumerated vs "10" tasked) is a scope-count note, not a coverage gap — all 11 stories have ≥1 AT in the traceability table.

---

## Per-AT testability table

| AT | Story | Realizable through shipped surface? | Non-vacuous? | Verdict |
|----|-------|-------------------------------------|--------------|---------|
| AT-CRC-DSN-010 | US-E6 | Yes — `parse_job(DUMMY_CONFIG_TEXT)` up-convert; seed algo `compute==0xCBF43926` | Yes (oracle pinned) | OK |
| AT-058-01 | US-E6 | Yes — `parse_job(emit_job(job))==job` | Yes | OK (see m1: `output_address` mapping under-specified) |
| AT-CRC-DSN-014 | US-E4 | Yes — `encode_word`/`decode_word` new in `crc.py`; big=`04 03 02 01`, little==`encode_le` | Yes | OK |
| AT-CRC-DSN-015 | US-E5/V5 | Yes — facade over `read_template`; malformed → `(None,[1 error])` | Yes | OK |
| AT-CRC-DSN-012 | US-E5 | Yes — template round-trip (headless idiom already exists) | Yes | OK |
| AT-058-02 | US-V1 | Yes (Pilot preset select) | **Weak** — must assert delta from seed default | MAJOR M2 / M1 |
| AT-CRC-DSN-011 (pilot) | US-V2 | Yes | **Weak** — "7 presets" hand-counted | MAJOR M1 |
| **AT-CRC-DSN-016** | US-V2 | Yes | **NO — can pass while reactive wiring broken** | **BLOCKER B3** |
| AT-058-03 | US-V3 | Yes — ASCII==hex==`kat()` | Yes | OK |
| **AT-058-04** | US-V4 | **Bypass risk** — `preview_text` unbound to rendered widget | **NO** | **BLOCKER B1** |
| **AT-058-05** | US-V5 | **Missing** — no Save→Load round-trip *through the view* | n/a | **BLOCKER B2** |
| AT-058-06 | US-V5 | Yes — asserts `plain` verbatim AND no spans (good) | Partial — sink set hand-listed | MAJOR M3 |
| AT-058-07 | US-V6 | **Fixture unnamed** — needs exact §3.2 image loadable | Yes if fixture exists | MAJOR M5 |
| AT-CRC-DSN-013 / 013b | US-V6 | Yes headlessly (oracles pinned in `test_crc_designer_model.py`) | Yes | OK |
| AT-CRC-DSN-017 / AT-058-08 | US-V7 | Yes — `evaluate_target` probe-confirmed (`refused=True crc=None conflicts=(32778,)`) | Yes | OK |
| AT-058-09 | US-V8 | Yes — mem_map object-identity + grep negative | Yes (identity assert is robust) | OK (m5) |

---

## Findings

### BLOCKERS (AT-authoring control violated — AT can pass while feature is broken)

**B1 — HLR-V4 / LLR-V4.1 / AT-058-04 — C-12 output-then-consume bypass.**
The threshold is `parse_template(preview_text)[0] == current_template`, but `preview_text` is not bound to the **rendered preview widget's displayed content**. As worded it is satisfiable by `parse_template(emit_template(t))` — a direct-write bypass that never proves the operator-visible pane shows round-tripping text; the AT would pass with an empty or stale preview widget. **Fix:** the pilot must query the mounted preview widget via Pilot (`app.query_one("#crc_json_preview")…`) and feed *that text* to `parse_template`.
*Failure scenario:* preview widget wired to the wrong reactive / never refreshed → operator sees stale JSON, but `parse_template(emit_template(t))` still equals `t` → green test, shipped bug.

**B2 — HLR-V5 / US-V5 / AT-058-05 — C-12: no Save→Load round-trip through the shipped surface.**
The Save path (LLR-V5.2) and Load path (LLR-V5.1) are tested **separately**; the only produce-then-consume identity is headless (`read_template(emit_template(seed))` in `test_crc_designer_model.py`). No AT drives **Save through the view** to write a `*.crc.json`, then **Load that same file through the view**, asserting the form repopulates equal. **Fix:** add one pilot AT: edit form → Save handler → assert file on disk → Load handler on that path → assert form fields == pre-save.
*Failure scenario:* Save writes a field the Load handler mis-maps (e.g. `store_endianness`) → each unit test green, the actual authoring loop loses data.

**B3 — HLR-V2 / LLR-V2.1 / AT-CRC-DSN-016 — centerpiece live-recompute is under-constrained (C-16 + "same interaction").**
The threshold asserts the *end-state* verdict (MATCH after presets, MISMATCH after a break, NO-EXPECTED after clearing `check`) but does not assert a **transition observed within one field-change event**. A test that programmatically sets a field then re-queries the verdict recomputes on query and passes **even if no reactive/`on_changed` handler is wired** — exactly the "live" claim under test. **Fix:** drive the mutation via a real Textual event (Pilot focus + type / value change), capture verdict text **before and after that single event**, and assert `before == MATCH and after == MISMATCH` with **no Run/submit action between**.
*Failure scenario:* verdict is computed only in a `compose`/manual-refresh path, not on-change → operator edits a field and the verdict silently goes stale; the as-specced AT still passes.

### MAJORS

**M1 — AT-CRC-DSN-011 (pilot) + AT-058-02 — C-31 input-set-is-an-oracle.** Both hand-count "the 7 presets." Derive the set from `crc_kernel.PRESETS` and guard completeness (`assert len(PRESETS) >= 7`) so adding an 8th preset cannot silently drop pilot coverage. (The headless `test_crc_kernel.py` already parametrizes over `PRESETS` — mirror that in the pilot.)

**M2 — AT-058-02 — C-10 must drive a non-default and assert change.** The seed default is CRC-32/ISO-HDLC, so an AT that selects CRC-32 and confirms fields==CRC-32 is vacuous. At least one case must select a **non-seed** preset (e.g. CRC-8/SMBUS) and assert the form **changed** (width `32 → 8`, poly `0x04C11DB7 → 0x07`), not merely that fields equal the selection.

**M3 — AT-058-06 / LLR-V5.3 — C-17 sink set is hand-listed (markup-sweep rule, memory 1d).** The AT enumerates 4 sinks (name, aliases, loader error, diagnostics) but the **JSON-preview pane** and the **populated form fields** are *also* file/template-derived render sites (a template named `[bold]x[/]` loaded from disk flows into the preview text and the form). LLR-V5.3's *statement* is general ("every template/file-derived string"), so the requirement is sound — but the AT must **sweep every template-derived render widget** in `#screen_crc_designer` (query all `Static`/`Label`/preview widgets), asserting `plain` verbatim and no spans, rather than testing 4 named strings. Note: `Input` widgets render plain and are safe; the risk is any `Static`/`Markdown`/markup-enabled preview.

**M4 — coverage gap vs governing design R-CRC-DSN-007.** The design mandates **three** warn conditions; batch-58 tests only one (check-mismatch, LLR-V5.2). Unspecified: (a) `store_width < ceil(width/8)` → silent truncation of detection strength (a real hazard — `_build_target` accepts `store_width 1..8` regardless of `width`); (b) `intra_gap/join="fill"` with no `pad_byte`. Either add ATs or justify the cut. (b) is plausibly cuttable — `pad_byte` defaults to `0xFF` in `_build_target:477`, so "no pad_byte" may be unreachable; **(a) is not cuttable** and should get an AT.

**M5 — AT-058-07 realizability — the §3.2 image fixture is unnamed.** Asserting the *specific* oracles `concat=0x9C5BCBBD` / `fill=0x2A8A3950` **through the view** requires the exact two-range image (`0x8000–0x8008` + `0x8010–0x8018`) be loadable as `current_file.mem_map`. No fixture or `LoadedFile`-injection idiom is named for the pilot. Name it (an `examples/` S19 whose mem_map yields that window, or the documented headless-`LoadedFile` construction) — otherwise the pilot can only assert "two distinct values shown," not that they are correct.

### MINORS

**m1 — LLR-E6.1** does not state how `output_address` populates up-converted `CrcTarget`s. `DUMMY_CONFIG_TEXT` regions and the group each carry `output_address`, and `CrcTarget` requires the field; specify the mapping (region/group `output_address` → target `output_address`).

**m2 — LLR-V5.2 / R-5** — `sanitize_project_name` is unbound (`assumed — verify at Phase 3`); the "name normalized" threshold cannot be pinned until the symbol is bound (file:line).

**m3 — 11-vs-10 stories** (self-flagged §2.6). Confirm scope count at Phase-2. No coverage impact: all 11 stories appear in the §5.2 behavioral table with ≥1 AT.

**m4 — AT-058-09 write-symbol grep list** is hand-listed. Keep the `mem_map` **object-identity** assertion as the primary guard (robust, listing-independent); treat the grep as a supplementary white-box check.

**m5 — HLR-E4 threshold** — `decode_word(data, *, endianness)` infers width from `len(data)`; confirm the round-trip `decode_word(encode_word(v, store_width=w, ...)) == v & ((1<<8w)-1)` is asserted per `w∈{1,2,4,8}` (LLR-E4.2 states it — good; just ensure the TC enumerates all four widths × both endiannesses, not one).

---

## Evidence checklist

- [x] Acceptance criteria use Given/When/Then equivalent — HLRs use EARS + explicit Observable/Shipped-surface/Deliverable blocks. Evidence: `01-requirements.md` §3 HLR blocks.
- [x] Test cases have explicit Expected, not vague "works" — every HLR carries a Numeric pass threshold (e.g. `concat=0x9C5BCBBD`). Evidence: HLR-V6 line ~257.
- [x] Edge cases include empty/boundary/invalid/error — every HLR has a Boundary catalog. Evidence: HLR-E4..V8 "Boundary catalog" lines.
- [x] Regression checklist exists — LLR-E4.3 (LE wrappers byte-identical), LLR-E6.2 (evolved+fixtures unchanged), §5.3 (0 frozen-set diffs, existing CRC suites unchanged). Evidence: LLR-E4.3/E6.2.
- [x] Exit criteria stated — §5.3 batch acceptance criteria.
- [x] No real PII/secrets — `DUMMY_CONFIG_TEXT` is explicitly FAKE (`crc_config.py:43`); KAT is public catalogue.
- [x] Test-results section left blank (this is a plan review, nothing executed as passing).
- [x] **Layer B (black-box):** every output-producing story observed through the shipped surface — **PARTIAL:** view Save/Load (B2), JSON preview (B1), live verdict (B3) are not yet observed through the shipped surface as specced. Engine stories (E4/E5/E6) OK.
- [x] **Bidirectional surface-reachability:** input dims + output deliverables exercised through the handler — **PARTIAL:** M5 (image-loaded per-policy preview) needs a named fixture to reach the output through the view.
- [x] **No unfilled template:** the artifact has no `<...>` placeholders; TC/AT ids are provisional-until-Phase-4 by design (§5.2), acceptable at Phase-2.

---

## Recommendation

Resolve **B1/B2/B3** (wording/coverage, no redesign) and fold **M1–M5** before the Phase-3 increment gate. The engine LLRs (E4/E5/E6) are green to build now — oracles verified present in-tree. Re-open §6.4 reconciliation log if any HLR threshold changes as a result.

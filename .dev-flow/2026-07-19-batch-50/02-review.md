# 02 — Cross-agent review · batch-50 (A2L length cleanup + a2l.py re-freeze)

**BLUF — Phase-2 does NOT pass as written.** F841 and P-2 are sound and need no change. **P-1b, as specified, collides with a pre-existing parser limitation: the A2L parser only reads single-line CHARACTERISTIC/AXIS_DESCR headers, so on the real ASAM demo file (and any multi-line A2L) P-1b derives *nothing* — `char_type`, `record_layout_name`, and `MaxAxisPoints` are all `None`/unreachable.** The internal P-1b logic (component summer + axis resolver + post-walk pass) is correct and implementable, but its headline acceptance ("demo STD_AXIS CURVE → 25 B green") is **unrealizable** without a much larger multi-line-header parsing change. This is a scope-defining fork that needs an operator decision → `iterate-to-refine`, direction TBD by operator.

Triple review (architect + qa-reviewer + security-reviewer) ran in parallel; findings reconciled with an orchestrator draft-time execution probe (the decisive evidence). **Tally: 2 blockers, 8 majors, ~7 minors, 0 security blocker/major.**

---

## 0. The central finding (orchestrator draft-time execution — decisive)

Ran the shipped parser over `examples/case_00_public/ASAP2_Demo_V161.a2l`:
- **49 of 50 CHARACTERISTICs** parse to `char_type=None`, `length=None`, `record_layout_name=None`. Only 1 parses (`ASAM.C.VIRTUAL.ASCII`).
- The two target CURVEs (`ASAM.C.CURVE.STD_AXIS`, `ASAM.C.CURVE.COM_AXIS`): `char_type=None`, `record_layout_name=None`, `matrix_dim=None`, `axis_meta=[{'header_tokens': ['STD_AXIS']}]` (MaxAxisPoints=8 **not** captured).

**Root cause:** `parse_characteristic_header` (`a2l.py:324-330`) requires all 7 mandatory params on **one** line (`len(parts) < 7 → return None`). The ASAM demo (and much real-world A2L) uses **multi-line** headers. **This is pre-existing** — P-1's scalar-VALUE derivation (PR #93) also silently no-ops on the demo; it only ever fired on crafted single-line-header fixtures (`tests/test_a2l_record_layout_length.py::_CASE_01_A2L`). MEASUREMENTs parse (24/25) because their header format is single-line-parseable in this file.

**Consequence:** to make P-1b work on real multi-line A2L requires (1) multi-line CHARACTERISTIC header parsing (`char_type`/deposit/address), (2) multi-line + comment-stripped AXIS_DESCR body parsing (MaxAxisPoints + external flag), (3) the component summer, (4) the post-walk pass. Items (1)–(2) touch the core header parser and affect ALL 50 chars + 25 meas — well beyond a "tight cleanup." Alternatively P-1b is validated only on synthetic single-line-header A2L (P-1 precedent), delivering **no** real-world/demo win.

---

## 1. Findings by reviewer

### security-reviewer — 0 blocker / 0 major (verdict: OK to ship without a byte-size cap)
- **F1 (MEDIUM, flag-only accepted):** R2 unbounded `range(byte_size)` in `_extract_raw_bytes` (`a2l.py:834-844`, only guard `byte_size<=0` at `:830`) is a **pre-existing, local self-DoS** — confirmed live today via the scalar `el×matrix` path (`:754-755`, untrusted unbounded `MATRIX_DIM`). P-1b broadens *reach* (CURVE/MAP), not the maximum blast. No remote/exec/exfil surface. Flag-only OK for batch-50.
- **F2 (LOW — OPERATOR DECISION):** P-2 re-freeze closes the cheap window to add the R2 cap; a later cap needs another a2l.py unfreeze. Cheapest safe bound = one clamp at `_extract_raw_bytes:830` (`MAX_A2L_DECODE_BYTES ≈ 1–16 MiB`) covering BOTH paths, landing in PR-A before PR-B re-freeze.
- **F3 (LOW — fold into LLRs):** impl guardrails — use `DATATYPE_SIZES.get(dt)` not subscript (subscript raises `KeyError`, not fail-closed); length-guard `header_tokens[3]` before indexing (`IndexError`).
- F4 (C-17 markup) / F5 (R3 refuse-rescale) / F6 (F841): confirmed sound, no action.

### architect — 2 blockers / 2 majors
- **BLOCKER-1:** `header_tokens[3]` unreachable — AXIS_DESCR body is multi-line; `axis_meta` (`a2l.py:1063`) captures only the first body line → `['STD_AXIS']`. **Compounding:** `build_section_tree` (`:136-167`) never strips `/* */` block comments, so a naive flatten yields `header_tokens[3]=="/*"`. Needs comment-aware, positional, full-body tokenization. → AT-090 (gate-blocking) fails on the fixture.
- **BLOCKER-2:** `AXIS_PTS_REF` external detection (body line 6, `:3354`) equally unreachable from first-line-only `axis_meta`. A `STD_AXIS`-labelled body with an external `AXIS_PTS_REF` would be undetectable. Fold with B-1: enrich `axis_meta` with an `is_external`/`axis_pts_ref` flag from the full body.
- **MAJOR-1:** component `1/2/3` are ASAM **position indices, not counts** — datatype is token[2], token[1] discarded. LLR-P1b.1 must state this (else a reader sums `1×1+2×1+3×2=9`); TC-090 must add a position-as-count mutation.
- **MAJOR-2:** AT-093 MAP number: `146` is synthetic `[8,8]`; the real inline MAP `ASAM.C.MAP.STD_AXIS.STD_AXIS` (`:3539`, axes 4 & 5) spans `1+1+4+5+4·5·2=51`. Pin the exact value to the chosen fixture.
- MINOR: C-26 census short one symbol (the axis_meta build site `:1061-1069` is itself modified, not read-only); R2 routing correct; structural ordering / F841 / P-2 sequencing confirmed sound.

### qa-reviewer — 6 majors / 4 minors (observation path confirmed real)
Path verified: `enrich_tags_and_render` → `_tag_schema_and_applicability` (`a2l.py:1301`) → `_a2l_tag_row_severity` (`app.py:342`) → `css_class_for_severity`; classes `sev-ok`/`sev-info`/`sev-neutral` exist in `SEVERITY_CLASS_MAP`.
- **M1:** AT-092 `reason==""` is **wrong** — out-of-image reason is `"characteristic address not in S19"` (`validate_a2l_tags:1366`). Assert `length==25 ∧ sev-info ∧ memory_checked ∧ ¬in_memory`; drop `reason==""`. Real counterfactual = grey→white / None→25 (pre-fix), not the artificial ERROR mutation.
- **M2:** AT-093 `Π(dims)×el` (=128) contradicts the full-span summer (=146/51) — a FNC-only shorthand would pass a naive FNC-only summer. Assert the exact full Σ.
- **M3:** C-31 oracle guards disjointness but **not completeness/non-emptiness** — `ALL_AXIS_KINDS`/`_EXTERNAL_AXIS_KINDS` don't exist in source (0 grep hits) → risk of a hand-list. Add live constants + `ALL == _DERIVABLE | _EXTERNAL` completeness guard + `len(S_declined)>0` non-empty guard.
- **M4 (C-12):** length is produced at **parse** (walk ending `a2l.py:1091`), UPSTREAM of `enrich_tags_and_render`. The acceptance surface must name `parse_a2l_file` as the chain head; each AT must start from a raw/synthetic A2L string (never a hand-built tag) so the pass actually runs — else it's a consumer-contract guard masquerading as the AT.
- **M5:** gate-blocking AT-090 pinned to brittle fixture literal (`25` + line number). Use a synthetic in-test A2L where 25/146 are computable from the string; locate demo tags **by name** not line; keep the demo as ONE corroborating AT, not the primary oracle.
- **M6:** no black-box malformed-input AT — R1 fail-closed/injection is only white-box. Add a malformed CURVE (garbage FNC dt / non-numeric MaxAxisPoints) through `parse_a2l_file`→enrich asserting it stays grey without raising.
- minors: m1 AT-091 default-on-both-sides (teeth depend on M3 + the paired AT-090); m2 compose colour via the real severity funcs with `{}` issue map; m3 pin a mem_map per AT for the Green/White split; m4 add a MATRIX_DIM 1-D boundary case.

---

## 2. Consolidated gate verdict

**BLOCKERS present → `iterate` required (cannot pass Phase-2 as written).** The unmet axis is **Certainty** (the gate-blocking AT-090 cannot observe the deliverable through the shipped surface on real A2L — the parser doesn't populate the fields P-1b keys on) and **Coverage** (the C-12 chain head is mis-named; the C-31 set can rot; the malformed-input black-box AT is absent).

**But the iterate DIRECTION is a scope decision only the operator can make**, because it changes what the batch delivers in the real world and its size:
- **(A) P-1b on single-line-header A2L only** (P-1 precedent): implement the summer/resolver/post-walk pass, validate on synthetic single-line-header A2L (25/146 computable from the string) + one demo corroborator. Correct, safe, small — but delivers **no** win on the multi-line demo file (stays grey); the feature fires only on single-line-header A2L. Fold all AT/oracle fixes (M1–M6, MAJOR-1/2, F3).
- **(B) P-1b + multi-line-header support** (real-world win): also fix multi-line CHARACTERISTIC header + comment-stripped AXIS_DESCR parsing. Delivers the demo win but is a **core-parser change** touching all 50 chars/25 meas — high regression surface, big baseline shift, arguably its own story. Beyond "tight cleanup."
- **(C) Defer P-1b; ship F841 + P-2 only this batch.** F841 (clean one-line delete) in PR-A, P-2 re-freeze in PR-B. P-1b (with proper multi-line support) becomes a dedicated future batch. Cleanest "don't half-ship a safety-critical parser feature that doesn't fire on real files."

Orthogonal secondary decision (only if A or B): **security F2** — add the R2 byte-size cap now (PR-A, before the P-2 re-freeze window closes) or defer.

F841 and P-2 are unaffected and remain READY under all three options.

## 3. Recommended folds (once direction is chosen)
- All options: correct AT-092 (M1), AT-093 exact-Σ (M2), C-31 completeness/non-empty guards + live `ALL_AXIS_KINDS`/`_EXTERNAL_AXIS_KINDS` (M3), name `parse_a2l_file` as the chain head + synthetic-A2L-first ATs (M4/M5), add malformed-input black-box AT (M6), state position-index-not-count in LLR-P1b.1 + mutation TC (MAJOR-1), `.get()`/index-guard hardening (F3), C-26 census += axis_meta build site.
- Option B additionally: new LLRs for multi-line CHARACTERISTIC header parsing + comment-stripped AXIS_DESCR body extraction; re-baseline the "1/50 parse" expectation; expanded regression coverage.

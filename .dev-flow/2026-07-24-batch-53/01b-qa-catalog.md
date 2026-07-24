# 01b — QA Catalog · batch-53 (FB-P1 flow.json persistence)

Phase 1 (Requirements), authored in parallel with the architect. Method + AT/TC
catalog + the C-31 security-battery oracle design. **The security-load path is the
load-bearing surface — its ATs are non-vacuous, through-surface, with a stated RED
counterfactual.** Test-results columns are left BLANK (Phase 4 fills them).

Legend — **method** ∈ {test (automated), demo (runnable prototype/e2e), inspection
(source/static guard), analysis}. **Layer** ∈ {A = white-box on the service; B =
black-box through the SHIPPED surface (app pilot / render() / on-disk artifact)}.
Provisional execution nodes are V-5 (may shift at Phase-3 entry); pass thresholds are
numeric; the counterfactual is what goes RED before the fix.

---

## 1. Requirement → validation-method map

| Req | Statement (one line) | Method | Layer | AT / TC |
|---|---|---|---|---|
| R-P1-1 | Serialize→deserialize preserves every shipped block kind field-by-field | test | A | AT-P1-01 / TC-P1-01..06 |
| R-P1-2 | ReportBlock (ref-less) round-trips exactly | test | A | AT-P1-02 / TC-P1-07..08 |
| R-P1-3 | Load re-validates EVERY embedded READ ref through `_resolve_manifest_entry` | test | A | AT-P1-03 / TC-P1-10..16 (battery) |
| R-P1-4 | Any finding ⇒ whole-flow reject `(None, findings)`, never partial | test | A | AT-P1-04 / TC-P1-17 |
| R-P1-5 | File gate: size-cap + parse guards before `dict_to_flow`, never raises | test | A | AT-P1-05 / TC-P1-18..20 |
| R-P1-6 | Schema-version gate: exactly int 1 (future/string/bool/absent reject) | test | A | AT-P1-06 / TC-P1-21..24 |
| R-P1-7 | Strict keys + unknown-kind + missing-ref + bad-enum reject | test | A | AT-P1-07 / TC-P1-25..29 |
| R-P1-8 | `output_name` WRITE-target shape pre-check (no sep/`..`/abs/hidden) | test | A | AT-P1-08 / TC-P1-30..31 |
| R-P1-9 | Save writes `flows/<sanitized>.json`; name via `sanitize_project_name` | test | A/B | AT-P1-09 / TC-P1-32..33 |
| R-P1-10 | Import COPIES external file into `flows/` via `copy_into_workarea`, then Load reads what the handler wrote | test | B | AT-P1-10 / TC-P1-34..35 |
| R-P1-11 | Hostile import destination (outside any workarea) is REFUSED | test | A | AT-P1-11 / TC-P1-36 |
| R-P1-12 | Rejected load: quarantine card renders in `sev-error`, PAINTED + visible | test | B | AT-P1-12 / TC-P1-37..38 |
| R-P1-13 | Rejected load: current blocks list + name strip UNTOUCHED | test | B | AT-P1-13 / TC-P1-39 |
| R-P1-14 | Bracket-bearing finding message renders LITERALLY (C-17) | test | B | AT-P1-14 / TC-P1-40..41 |
| R-P1-15 | Dirty glyph `●`/saved `✓` state transitions | test | B | AT-P1-15 / TC-P1-42..44 |
| R-P1-16 | No `from_markup` in the new persistence service / new render path | inspection | A | AT-P1-16 / TC-P1-45 |
| R-P1-17 | "Every flow generates its report" (RB-model — SPLIT, see §5) | test | A/B | AT-P1-17 / TC-P1-46 (shape-pending) |

Execution node (all Layer-A): `pytest tests/test_flow_persistence_service.py -q`
(new). Layer-B UI: additions to `tests/test_tui_directionb.py` (the C-34 guard host)
run via `pytest tests/test_tui_directionb.py -q`. Full-suite gate: `pytest -q`.

---

## 2. AT / TC catalog (Given / When / Then)

### AT-P1-01 — Round-trip fidelity, all 5 shipped kinds (R-P1-1)
- **Given** a `Flow` holding one of each of `SourceBlock`, `PatchBlock`, `CheckBlock`, `CrcBlock`, `WriteOutBlock` with non-default enum values (`file_type=hex`, `gating=block-own-op`, `fmt=hex`)
- **When** `dict_to_flow(json.loads(json.dumps(flow_to_dict(flow))), project_dir)`
- **Then** returns `(flow', [])` with `flow'.name`, `flow'.schema_version`, and **every block field** equal to the original — assert `list(flow'.blocks) == list(flow.blocks)` AND per-block `image_ref/file_type/change_doc_ref/check_doc_ref/gating/config_ref/output_name/fmt` field-by-field (C-31: non-default enums so a serializer that drops a field and lets the dataclass default backfill goes RED).
- **Type:** test · Layer A · node `test_flow_persistence_service.py::test_roundtrip_all_kinds`
- **Pass:** 1/1 equality on all 6 TCs (TC-P1-01 source, -02 patch, -03 check, -04 crc, -05 write_out, -06 full pipeline).
- **Counterfactual (RED):** serializer emits `gating` but loader ignores it → reloaded `CheckBlock.gating == advisory` ≠ `block-own-op` → field assert fails. A "non-empty / not-None" oracle would stay GREEN here — that is the vacuity this AT forbids.

### AT-P1-02 — ReportBlock ref-less round-trip (R-P1-2 / D2)
- **Given** a `Flow` containing a `ReportBlock` (kind `"report"`, **no `*_ref`**, plus whatever options the architect settles — e.g. `fmt`/`output_name?`)
- **When** serialize→deserialize
- **Then** the report block round-trips exactly; the ref-validation loop is a NO-OP for it (no `MANIFEST-*` finding raised against a block that has no read ref); if it carries an optional `output_name`, that field passes through the V7 WRITE-shape pre-check.
- **Type:** test · Layer A · TC-P1-07 (bare report block), TC-P1-08 (report block with option field)
- **Pass:** `(flow', [])`, `flow'.blocks[-1]` is a `ReportBlock` with options equal.
- **Counterfactual:** the strict-keys check (V5) rejects the report block because `_KIND_SPEC` was never extended for `kind="report"` → `FLOW-UNKNOWN-KIND` → RED. (This AT is the guard that the D2 model change actually threads the loader.)
- **⚠ F-finding gate dependency:** the option set is architect-pending — see F-1.

### AT-P1-03 — Security-rejection battery, whole-flow fail-closed (R-P1-3) **[LOAD-BEARING]**
- **Given** the C-31 hostile-input SET (§3) — each a deep-copy of a known-good envelope mutated at exactly one hostile axis
- **When** `dict_to_flow(payload, project_dir)` (and `load_flow_json` for the file-level cases)
- **Then** EACH returns `flow is None` AND `len(findings) >= 1` AND the expected finding `code` is present AND **no embedded path was opened** (no filesystem side-effect; the guard is pre-`open`).
- **Type:** test · Layer A · TCs below, driven by the derived oracle set (§3)
- **Pass:** every case in the derived set REJECTED-CLOSED with the mapped code; **0 leaked**.

| TC | Hostile axis | Expected code |
|---|---|---|
| TC-P1-10 | `image_ref` absolute Windows `C:\…` | `MANIFEST-PATH-ESCAPE` |
| TC-P1-11 | `change_doc_ref` absolute POSIX `/etc/passwd` | `MANIFEST-PATH-ESCAPE` |
| TC-P1-12 | `config_ref` `../../other/secrets.json` traversal | `MANIFEST-PATH-ESCAPE` |
| TC-P1-13 | ref through a REAL NTFS junction pointing outside | `MANIFEST-PATH-ESCAPE` (reparse arm) — SKIP-ENV if `mklink /J` unavailable, and SKIP is a **logged xfail-reason**, never a silent pass |
| TC-P1-14 | unknown `kind: "shell"` | `FLOW-UNKNOWN-KIND` |
| TC-P1-15 | unknown extra field `extra_hook` (strict keys) | `FLOW-BAD-FIELD` |
| TC-P1-16 | missing required ref | `FLOW-BAD-FIELD` |

- **Counterfactual (RED):** loader `resolve()`s a ref but forgets the `is_relative_to` check → TC-P1-12 returns a non-None Flow → `flow is None` assert fails. TC-P1-13 is the one that fails if the reparse-walk arm is dropped and only `resolve()` is trusted (junction whose target escapes but whose string looks local).
- **C-12 note:** the junction case (TC-P1-13) must build a REAL junction on disk and drive the loader over it — a mocked `is_reparse_point` would make the AT vacuous.

### AT-P1-04 — Never a partial pipeline (R-P1-4)
- **Given** an envelope with 4 valid blocks and 1 hostile block (traversal ref at index 2)
- **When** `dict_to_flow`
- **Then** returns `(None, findings)` — NOT a Flow with the 4 good blocks. Assert the return is `None` even though `len(findings) == 1` and 4 blocks validated cleanly.
- **Type:** test · Layer A · TC-P1-17
- **Counterfactual:** loader returns `Flow(blocks=good_blocks)` alongside the finding (manifest-style degrade-to-partial) → RED. This distinguishes the flow loader (fail-whole) from the manifest reader (degrade-to-empty-batch) — the contract difference the prototype notes call out.

### AT-P1-05 — File gate: size-cap + parse guards (R-P1-5)
- **Given** (a) a `>1 MiB` file, (b) a `{not json` file, (c) an unreadable path
- **When** `load_flow_json(path, project_dir)`
- **Then** `(None, [finding])` with `FLOW-SIZE-CAP` / `FLOW-JSON-PARSE` / `FLOW-JSON-PARSE` respectively; **never raises** (`JSONDecodeError`/`RecursionError`/`UnicodeDecodeError`/`OSError` all caught); size probed BEFORE parse (a 2 MiB malformed file trips SIZE-CAP, not PARSE).
- **Type:** test · Layer A · TC-P1-18 (oversize), -19 (malformed), -20 (unreadable)
- **Pass:** exit code — no exception escapes; correct code each.
- **Counterfactual:** `json.load` on the oversize file OOMs / raises before the size check → RED (order matters: the SIZE-CAP is a pre-parse DoS guard).

### AT-P1-06 — Schema-version type-strict gate (R-P1-6)
- **Given** `schema_version` ∈ {`99`, `"1"`, `True`, absent}
- **When** `dict_to_flow`
- **Then** each → `(None, [FLOW-SCHEMA-UNSUPPORTED])`. Assert `True` (a bool, which `isinstance(True, int)` accepts) is rejected via the explicit `isinstance(v, bool)` arm.
- **Type:** test · Layer A · TC-P1-21 future-int, -22 string, -23 bool, -24 absent
- **Counterfactual:** loader uses `int(version)` coercion → `"1"` passes → RED; or forgets the bool arm → `True` passes as version 1 → RED.

### AT-P1-07 — Per-block strict validation (R-P1-7)
- **Given** (a) unknown kind, (b) unknown extra key on a valid kind, (c) missing required ref, (d) empty-string ref, (e) invalid enum (`gating: "chain-kill"`)
- **When** `dict_to_flow`
- **Then** each rejects with `FLOW-UNKNOWN-KIND` / `FLOW-BAD-FIELD` (×3 for b/c/d) / `FLOW-BAD-FIELD` (enum).
- **Type:** test · Layer A · TC-P1-25..29
- **Counterfactual:** loader accepts unknown keys (permissive `**kwargs`) → additive-field forgery passes without a schema bump → RED.

### AT-P1-08 — WRITE-target shape pre-check (R-P1-8)
- **Given** `output_name` ∈ {`..\..\escape.s19` (traversal), `/abs/x.s19` (absolute), `.hidden` (hidden), `sub/x.s19` (separator)}
- **When** `dict_to_flow`
- **Then** each → `FLOW-UNSAFE-OUTPUT-NAME`; a plain `prg_patched.s19` passes.
- **Type:** test · Layer A · TC-P1-30 (four hostile), -31 (one benign passes — the negative control that proves the check is not blanket-rejecting)
- **Counterfactual:** the pre-check only tests `..` and misses a bare separator `sub/x.s19` → RED on the separator sub-case.

### AT-P1-09 — Save round-trips through the sanitiser (R-P1-9)
- **Given** a raw name `"Nightly Release!  "`
- **When** `save_flow_json(flow, raw_name, project_dir)` then `load_flow_json(saved, project_dir)`
- **Then** file lands at `flows/NightlyRelease.json` (name via `sanitize_project_name`), reloads to a Flow equal to the original; a name that sanitises to `None` returns `None` (no write).
- **Type:** test · Layer A/B · TC-P1-32 (happy), -33 (un-sanitisable name → no file created)
- **Counterfactual:** save writes the raw name verbatim → a `../`-bearing name escapes `flows/` → RED (the sanitiser is the write-side containment).

### AT-P1-10 — Import: COPY then Load-what-was-written (R-P1-10) **[C-12 output-then-consume]**
- **Given** an external `flow.json` outside the workarea
- **When** the Import handler calls `copy_into_workarea(external, project_dir/"flows")`, THEN `load_flow_json(imported, project_dir)`
- **Then** the loaded Flow is read from the file the HANDLER WROTE (`imported.parent == project_dir/"flows"`), not from the external source path; the external file is never loaded in place.
- **Type:** test · Layer B (through the copy→load chain) · TC-P1-34 (import + load), -35 (dedup: second import of same name → `_1` suffix, both loadable)
- **Counterfactual (RED):** handler loads `external` directly and only copies as a side-effect → assert `imported.parent == flows/` still passes but a test that mutates the external file AFTER copy and asserts the loaded content matches the COPY (not the post-copy external) catches the shortcut. **This is the C-12 discriminator — observe the consumer over the handler-produced artifact, not the input.**

### AT-P1-11 — Hostile import destination refused (R-P1-11)
- **Given** a destination directory OUTSIDE any `.s19tool/workarea/` root
- **When** `copy_into_workarea(external, hostile_dest)`
- **Then** raises `WorkareaContainmentError`; nothing is written.
- **Type:** test · Layer A · TC-P1-36
- **Counterfactual:** import handler picks its own dest without the containment guard → file lands anywhere → RED.

### AT-P1-12 — Quarantine card PAINTED in sev-error (R-P1-12) **[C-32 painted-result]**
- **Given** a rejected load (≥1 finding) driven through the app pilot (`async with app.run_test()`), Flow rail active, a hostile `flows/vendor_flow.json` selected
- **When** the Load handler runs and mounts the quarantine card into `#flow_result`
- **Then** the card widget (i) is present, (ii) `"sev-error" in card.classes`, (iii) `card.region.area > 0` (VISIBLE, not `display:none`, not zero-area), (iv) each finding line reads through `_render_line`/painted surface. Colour axis: read the class + the live `SEVERITY_CLASS_MAP`/CSS binding, NOT a hex literal (C-37).
- **Type:** test · Layer B · TC-P1-37 (card present + classed + visible), -38 (one line per finding, count matches)
- **Pass:** `region.area > 0` AND class present AND `line_count == len(findings)`.
- **Counterfactual (RED per C-32):** a content-only oracle reading `Static.render()` stays GREEN on a `display:none` or zero-area card; the `region.area > 0` arm is the one that catches it. Discharge: in authoring, flip the card to `display:none` in a throwaway and confirm the new oracle goes RED before trusting green.

### AT-P1-13 — Blocks list + name strip untouched on reject (R-P1-13)
- **Given** a panel with 3 valid blocks, name strip showing `Flow: current ✓`
- **When** a hostile load is rejected
- **Then** `#flow_blocks` painted content is IDENTICAL to pre-load (assert the `.plain` of the blocks Static verbatim, 3 lines), and the name strip still reads `current` — nothing from the hostile file reached the blocks list.
- **Type:** test · Layer B · TC-P1-39
- **Counterfactual:** loader mutates `self._blocks` as it parses and only discards on the final aggregate → a partially-mutated blocks list paints → RED. (Pairs with AT-P1-04 at the UI layer.)

### AT-P1-14 — Bracket-bearing finding renders literally (R-P1-14) **[C-17 hostile-input]**
- **Given** a hostile flow whose rejection produces a finding message containing file-derived brackets, e.g. a ref `sensor[red]patch.json` echoed into the finding text, or an `output_name` `x[link=file:///etc]` 
- **When** the quarantine card paints that finding line
- **Then** the line renders the `[`/`]` LITERALLY: assert the painted `.plain` contains the verbatim substring `[red]` (or `[link=…]`) AND the line's `render().spans` carry NO injected markup span (`spans == []` for the injected style) AND **no `MarkupError` was raised** during mount (Textual `Content.from_markup` vs rich `Text.from_markup` grammars differ; `[link=…]` can *raise* at a `Select`, so a crash-only assert is insufficient — assert plain-verbatim AND no-span AND no-crash).
- **Type:** test · Layer B · TC-P1-40 (`[red]` style token), -41 (`[link=…]` link token)
- **Counterfactual (RED):** the finding is mounted via `Static(msg)` (markup on) or `Text.from_markup(msg)` → either the bracket is swallowed into a span (plain loses `[red]`) or a `MarkupError` crashes the mount → RED on the plain-verbatim OR the no-crash arm.
- **⚠ C-32 confounder:** the `spans == []` absence assert is VACUOUS on a card that painted nothing — so this AT MUST co-assert `region.area > 0` (borrowed from AT-P1-12) and `.plain` non-empty. Absence-only is a false green.

### AT-P1-15 — Dirty / saved glyph transitions (R-P1-15 / D1)
- **Given** a freshly loaded/saved flow (name strip `Flow: <name> ✓`)
- **When** (a) a block is Added/Cleared, (b) Save completes, (c) a valid Load completes
- **Then** (a) glyph → `●` (dirty), (b) glyph → `✓` (saved) + status `✓ saved flows/<name>.json`, (c) glyph → `✓` with the loaded name. Read the PAINTED glyph off the name-strip widget's rendered line (C-32), not a pre-layout attribute; glyph is the primary cue, colour secondary (C-10).
- **Type:** test · Layer B · TC-P1-42 (add→dirty), -43 (save→saved), -44 (load→saved+name)
- **Counterfactual:** dirty state tracked in a bool but the glyph render not refreshed → painted glyph still `✓` after Add → RED (asserting the model bool would be the vacuous version C-32 forbids).

### AT-P1-16 — No markup-injection sink in new code (R-P1-16) **[C-17 static guard]**
- **Given** the new `flow_persistence_service.py` source and the new quarantine-card render path in `screens_directionb.py`
- **When** the source-scan guard runs (extend `test_tc_042_10` family)
- **Then** `"from_markup" not in <module>_source` for the persistence service; the quarantine render path uses `safe_text(...)` + `markup=False` on every file-derived line.
- **Type:** inspection · Layer A · TC-P1-45
- **Counterfactual:** a later edit introduces `Text.from_markup(finding.message)` → the source scan trips RED. This is the C-34 guard-host coverage — the UI increment MUST run the FULL `test_tui_directionb.py` at its gate.

### AT-P1-17 — "Every flow generates its report" (R-P1-17 / D2) — SHAPE-PENDING
- See §5 — dual testing shapes catalogued; final AT text blocked on the architect's RB-model choice (F-1).

---

## 3. C-31 security-battery oracle design (input-set-is-an-oracle)

**The threat:** a hand-listed battery rots. A reviewer adds a new hostile axis to the
loader's rejection logic but forgets to add the matching case; or removes a rejection
arm and no test notices. The input set must be **derived and guarded** so a dropped
hostile case goes RED on its own, never "hand-listed-and-forgotten".

**Design — two coupled guards:**

1. **Derive the battery from a single declared table, not scattered literals.** The
   test module owns one `HOSTILE_CASES: list[HostileCase]` where `HostileCase =
   (id, mutate_fn, expected_code)`. The round-trip good-envelope is the fixture; each
   case is `deepcopy(good)` then `mutate_fn`. The test parametrizes over the table —
   adding a row is the only way to add a case, and every row MUST assert reject-closed
   + code. (This is the same shape the prototype's `battery` list proved.)

2. **Couple the battery to the loader's own surface so a NEW arm without a case fails.**
   Two mechanisms, pick per architect:
   - **(preferred) Reject-arm census.** The loader exposes its finding-code vocabulary
     (`_KIND_SPEC` keys + the `FLOW_*` code constants + the reused `MANIFEST_*` codes).
     A meta-test asserts **every rejecting code constant is exercised by ≥1 battery
     row** — `assert set(expected_codes_in_table) >= set(REJECTING_CODES)`. Add a new
     `FLOW-*` reject code to the loader without a battery row → the census goes RED.
     This is the "input set is an oracle" discharge: the code vocabulary IS the oracle
     of completeness.
   - **(backstop) Enum/kind coverage.** For each `kind` in `_KIND_SPEC` and each enum
     value domain, assert both a valid and an invalid case exist in the table — a new
     block kind with no hostile row → RED.

3. **The junction case is environment-gated, never silently skipped.** TC-P1-13 SKIPs
   only when `mklink /J` is unavailable, and the skip emits a **reason string logged in
   the test report** (`pytest.skip("mklink /J unavailable — reparse arm unverified")`).
   A skip is a visible unverified-axis, not a green.

**Why this is non-vacuous:** the census fails when the loader grows a rejection path
the battery doesn't cover — the exact "dropped hostile case goes RED" property C-31
demands. A plain parametrized list without the census would let a new reject arm ship
untested and stay GREEN.

**Negative controls (prove the battery isn't blanket-rejecting):** the good envelope
(AT-P1-01) and the benign `output_name` (TC-P1-31) MUST load clean — without them a
loader that rejects everything passes the whole battery vacuously.

---

## 4. Coverage-default audit (per qa-reviewer standard)

| Default case | Covered? | Where |
|---|---|---|
| Golden path | ✓ | AT-P1-01/02 round-trip, AT-P1-09 save, AT-P1-10 import |
| Alternative valid paths | ✓ | non-default enums (AT-P1-01), report block (AT-P1-02), import-dedup (TC-P1-35) |
| Empty / null / zero | ✓ | empty blocks array, missing ref (AT-P1-07), un-sanitisable name (TC-P1-33) |
| Boundary | ✓ | 1 MiB size-cap (AT-P1-05), 64-block cap, 64-char name (see F-2), 64th vs 65th block |
| Invalid / malformed | ✓ | malformed JSON (AT-P1-05), bad schema type (AT-P1-06), strict keys (AT-P1-07) |
| Unauthenticated / wrong-role | n/a | no auth surface (local TUI, work-area sandbox) — **justified cut**, not silent |
| Network / error state | n/a→adapted | no network; the analogue is the untrusted-loader battery (AT-P1-03) + unreadable-file (TC-P1-20) |
| Regression on adjacent feature | ✓ | see §6 regression checklist |

---

## 5. Report block — dual testing shape (RB-model unresolved; F-1)

The operator phrasing "cada flow debe generar su reporte" is not yet a testable
predicate — it depends on the architect's model choice. **Both shapes are catalogued
so Phase 4 can bind whichever lands:**

- **Shape A — explicit-and-optional (author-added block).** AT: a flow WITHOUT a
  report block is a valid flow that loads/runs; a flow WITH a `ReportBlock` round-trips
  it (AT-P1-02) and run produces a report artifact. Predicate: "a report block, when
  present, round-trips and emits." The "every flow" clause is then a UI/authoring
  nudge, not a loader invariant → NOT a reject condition.
- **Shape B — implicit-always (auto-terminal report).** AT: `dict_to_flow` of an
  envelope with NO report block yields a Flow whose executable form ends with an
  (implicit) report; serialize emits it (or canonicalises it); "every flow" IS an
  invariant → a test asserts the terminal report exists on every loaded flow.

**These are mutually exclusive at the assertion level** — Shape B's "reject/append a
flow lacking a report" would FAIL Shape A's "a flow without a report is valid". The AT
cannot be authored non-vacuously until the model is chosen. **→ F-1.**

---

## 6. Regression checklist (existing flows the change could break)

- [ ] Flow Builder **Run** (R-TUI-059) still composes + runs — Save/Load/name-strip added to the same panel must not break `on_flow_builder_panel_run_requested` or the ledger render (`render_result`).
- [ ] `render_result` quarantine-card path shares `#flow_result` with the run ledger — a rejected load then a Run (or vice-versa) must `remove_children()` cleanly (no stale card under a run result).
- [ ] `_resolve_manifest_entry` is REUSED, not forked — the manifest loader's own tests (`variant_execution_service` battery) must stay green; no signature change to the shared guard.
- [ ] `copy_into_workarea` reused with a tighter size arg (1 MiB) — the existing 256 MB project-copy path must be unaffected (default arg preserved).
- [ ] `flow_model.py` gains `ReportBlock` — the `FlowBlock` Union widens; `run_flow` / `render_result` `isinstance` chains must handle (or explicitly skip) the new kind without an unhandled-block crash (C-38: a widget/type-union widen sweeps every `isinstance(block, ...)` site).
- [ ] `workspace.py` NOT edited — `validate_project_files` must still skip the new `flows/` subdirectory (project cardinality rules unaffected).
- [ ] Full `tests/test_tui_directionb.py` guard host (markup source-scan `test_tc_042_10`, rail/screen census) runs on the UI increment (C-34).

## 7. Exit criteria (Phase-4 gate)

- All AT-P1-01..16 pass; AT-P1-17 bound to the chosen RB-model and passing.
- Security battery (AT-P1-03) **0 leaked**; the C-31 reject-arm census green; junction case verified OR its skip-reason logged.
- No `MarkupError` and no bracket-swallow on any file-derived line (AT-P1-14).
- Full `pytest -q` green (0 regressions vs the Phase-3-entry base); the render-increment full guard-host run clean (C-34).
- security-reviewer PR-pass 0-HIGH (untrusted loader) — separate gate, not discharged here.

---

## 8. F-findings (block the Phase-1 gate until resolved)

- **F-1 (BLOCKS AT-P1-17 acceptance).** "Every flow generates its report" cannot be
  made a non-vacuous predicate until the architect settles the RB-model
  (explicit-optional vs implicit-always). The two shapes have mutually exclusive
  assertions (§5). **Resolution needed at the Phase-1 gate** (matches PLAN OQ RB-model).
  Until then AT-P1-17 is shape-pending, not authored.
- **F-2 (soft — confirm before test-asserting).** The caps (1 MiB / 64 blocks /
  64-char name — PLAN OQ-4) are "arbitrary but generous". They become public
  test contract the moment AT-P1-05 and the boundary TCs assert them. **Confirm the
  numbers at the gate** so a later cap change isn't a silent contract break. Not a
  blocker if the gate ratifies the prototype's values.
- **F-3 (advisory — OQ-1 finding-code contract).** AT-P1-03 asserts `MANIFEST-*`
  codes verbatim (reuse-not-fork). If the architect wraps them as `FLOW-REF-*` at the
  collection boundary (OQ-1), the battery's `expected_code` column and the §3 census
  must re-point in lockstep. Flag so the code choice and the test contract move
  together — either is testable, but they must agree.
- **F-4 (advisory — OQ-3 dirty-guard).** AT-P1-15 covers glyph state but NOT a
  confirm-on-Load-over-unsaved-edits modal (OQ-3). If the gate adopts the confirm
  modal, add AT-P1-18 (Load over dirty flow → confirm modal → cancel keeps edits /
  accept replaces). Currently un-catalogued because the behavior is unresolved.

---

## 9. Control verdicts

- **C-10 (non-default + per-branch): PASS.** AT-P1-01 forces non-default enums so a
  field-drop can't hide behind a dataclass default; the security battery (AT-P1-03)
  hits every rejection BRANCH (absolute / traversal / reparse / unknown-kind /
  strict-key / missing-ref / bad-enum / schema-type / size-cap / parse) individually,
  each with its own expected code — not one collapsed "rejects bad input" proxy. Glyph
  cue is primary, colour secondary (AT-P1-15).
- **C-12 (output-then-consume): PASS.** AT-P1-10 observes Load over the file the Import
  handler WROTE (`copy_into_workarea` output), with the mutate-external-after-copy
  discriminator that a "loads the input directly" shortcut fails. AT-P1-12 observes the
  quarantine card the reject handler PRODUCED, not the pre-render finding list.
- **C-17 (untrusted-render markup-safety): PASS.** AT-P1-14 asserts a bracket-bearing
  file-derived finding renders literally (plain-verbatim AND no-injected-span AND
  no-MarkupError-crash), co-asserted with `region.area > 0` so the absence-of-span is
  not vacuous. AT-P1-16 static-scans the new modules for `from_markup`. Both the rich
  `Text.from_markup` and Textual `Content.from_markup` grammars are named as distinct
  risks.
- **C-31 (input-set-is-an-oracle): PASS.** §3 derives the battery from one declared
  table and GUARDS completeness with a reject-arm census keyed to the loader's own code
  vocabulary — a new reject arm without a case goes RED. Negative controls prevent the
  blanket-reject vacuity. The junction skip is a logged unverified-axis, not a green.
- **C-32 (assert-the-painted-result): PASS.** AT-P1-12/13/14/15 all read the PAINTED
  surface (`region.area`, `_render_line`, painted `.plain`/glyph), never a pre-layout
  proxy; each carries a stated mutate-your-own-oracle RED counterfactual. C-37 folded
  in for the colour axis (read the class + live style binding, not a hex literal).

**Evidence checklist (this catalog):** ✓ Given/When/Then · ✓ explicit Expected +
numeric pass · ✓ empty/boundary/invalid/error covered · ✓ regression checklist (§6) ·
✓ exit criteria (§7) · ✓ no real PII/secrets (synthetic hostile fixtures only) · ✓
results columns BLANK (not run — Phase 4) · ✓ Layer-B through the shipped surface (app
pilot render / on-disk artifact) with boundary + negative evidence · ✓ bidirectional
surface-reachability (every input axis via the loader, every deliverable — saved file,
imported file, painted card — observed through the handler) · ✓ no unfilled template
placeholders EXCEPT AT-P1-17 which is EXPLICITLY shape-pending on F-1.

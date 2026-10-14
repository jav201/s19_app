# Review — s19_app — Batch 2026-10-13-batch-95

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`). *(This batch: `en` — English stands.)*
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer` by trigger family C (always in `full`).

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/review-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

## ✅ Verdict (read first)

- **Gate:** `approve` → Phase 3  /  `iterate-to-refine` → Phase 1 (blockers present, or a requirement-defect major)
- **Out-of-scope findings:** `2` named and routed below  /  `none`

- **Findings:** `0` blocker · `0` major · `3` minor
- **shall/should check:** ✓ clean  /  ✗ misuse (blocker)
- **Two-layer (blockers):** ✓ every story has an `AT` · output reqs name deliverable+observation · both trace chains complete · ATs are genuinely black-box  /  ✗ `<which>`
- **Census (change-first):** done — best-effort + gate-confirmed  /  ⚠ incomplete   (NEVER stamp "VERIFIED COMPLETE")
- **Security:** ✓ no findings  /  ⚠ `<N>` findings
- **Evidence checklists (architect / qa / security):** ✓ all complete  /  ✗ `<missing>`

> If gate = `approve` and every line is ✓, the Detail below is reference. Any blocker/⚠ → read the matching part.

**Coordinator lens (P2 self-review):** the contract is the round's record re-derived, not
re-imagined. Every number traces to an executed measurement (§2.7, P-1..P-15, all TRUE); the
three verdicts stand behind each HLR; the two places where the commission and the round diverge
(the cross-platform seam, the change-3 surface reading) are recorded in the ledger with both
sides preserved. **Approve**, with the observations below handed to P3 as declared open items.

---

## Amendment review — change 5 (A2L-referenced changes), contracted mid-P3

> Same coordinator lens, applied to `LED-2026-10-13-batch-95.2`. The amendment lands after P2
> (increment 001 running; increments 002–004 not launched) — this block is the P2-record's
> amendment counterpart, not a rewrite of it.

- **Gate:** `approve` (amendment) → increments 002–004 carry the amended scope
- **Findings:** `0` blocker · `0` major · `2` minor (below)
- **shall/should check:** ✓ clean — HLR-141/142/143 + LLR-141.1..143.2 statements are EARS-normative (`shall`); the operator's quotes live in the Rationale/Statement quote pins, verbatim
- **Premises:** P-16..P-23 executed at the amendment — shipped-code readings with `file:line`, no document-only citations (§2.7, now 23/23 TRUE)
- **Two-layer:** US-133 carries AT-302/303/304 (black-box through the Patch Editor, the Flow Builder run, the report/diff); every amendment LLR names its TC block (TC-712..718); both trace chains complete
- **Registry:** AT-302..304 / TC-712..718 appended at the numeric high-water (AT-301 → AT-302, TC-711 → TC-712; TC-1728 BURNED does not drag the mark); uniqueness + contiguity validated; `reserved_by: batch-95`

**Coordinator lens (amendment):** the amendment is the operator's words re-derived against the
shipped code, not paraphrased into convenience. The wire-leniety premise (P-19) is the
amendment's load-bearing fact — it is why the `symbol` form rides **alongside** the address and
why the canonical writer keeps the resolved address (the shipped v2.0 reader applies a canonical
symbol entry unchanged). The operator's key law — *"todos los cambios del flujo deben
referenciarse"* — pins LLR-143.2 verbatim, with the no-diff listing so a change that produces no
diff is still referenced. The one honest net-new piece (the physical→raw encode direction) is
named as such (P-17), composed on shipped COMPU_METHOD tables, with its conversion limbs handed
to P3 as recorded open items.

| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| m4 | coordinator | minor | LLR-141.1 · P-17 | The physical→raw encode direction is net-new composition on shipped COMPU_METHOD tables; the conversion limbs (unknown conversion, value outside limits) are undefined at contract time | P3 defines + records the limbs (flag vs refuse) in the inc-003 increment packet; §6.3 of the contract records the risk | open → P3 |
| m5 | coordinator | minor | LLR-142.2 | The no-project A2L home is the `.s19tool\workarea\` containment root — broad, by design (no shipped COMMON A2L home exists) | P3 validates the guard refuses references outside the containment root on the no-project arm (TC-715); a dedicated library lands in BACKLOG only if the operator asks | open → P3 |

**Out-of-scope findings (named and routed):**
- **OOS-3 · a per-family COMMON A2L folder.** No shipped home exists; the containment root
  serves. Routed to `BACKLOG.md` if the operator ever wants a dedicated A2L library.
- **OOS-4 · a contract-mandated symbol-reference usage-help section.** `help_sections.md` is
  operator-editable copy; the amendment leaves it to the operator.

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| m1 | coordinator | minor | HLR-138 · LLR-138.1-138.3 | The "used by this project" gather predicate is deliberately undefined at P1 — over-gathering copies the whole COMMON library into every project; under-gathering breaks the self-contained snapshot | P3 defines the predicate (referenced change-sets, check runs, templates), records it in the increment packet, and the AT-299 used-set count asserts against THAT recorded predicate | open → P3 |
| m2 | coordinator | minor | HLR-139 · LLR-139.3 | The cross-platform seam's macOS/Linux arms cannot be executed on this Windows box; only the Windows arm + the failure path are runnable here | the seam TC spies `subprocess.Popen` and asserts the argv per platform arm; the non-Windows arms are verified by argv construction, and the operator's other boxes are the live check | open → P3 |
| m3 | coordinator | minor | §6.3 | The round's dir is throwaway; the oracle frames are referenced by path — a cleanup would silently void the P4 oracles | P4 re-captures the three frames from `tui_prototype.py shot` if the dir moved, and pins the batch's own copies in `evidence/` | open → P3 |

**Out-of-scope findings (named and routed):**
- **OOS-1 · the `.addr` sidecar (LLR-137.2).** Enters via the round's OQ#2 recommendation, not a
  verdict-sheet ruling. Routed to the operator at the P2 gate: strike it here if unwanted —
  the BIN stays flat-bytes either way (ruling Q2's pattern acceptance).
- **OOS-2 · XCP `IF_DATA SEGMENT` extraction.** The recon named it; no tab needs it. Out of
  scope by the contract; routed to `BACKLOG.md` if the operator ever asks.

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a finding nobody raised. Write your own rows in the table above.

```text
| *(example)* F1 | architect | blocker / major / minor | | | | open / fixed |
```

### shall / should check
> Any modal `should` / `debería` inside an HLR/LLR statement is a writing error → blocker.

✓ clean — every HLR/LLR statement is EARS-normative (`shall`); `should` appears only in the
rationale/guidance prose, where informality is allowed (0 occurrences inside statements —
re-checked at P2 after the P1 authoring pass).

### Two-layer acceptance review (blockers)
> (a) every story has a black-box `AT`; (b) every output-producing requirement names its observable deliverable + observation method; (c) BOTH traceability chains complete (behavioral US→AT→outcome + functional US→HLR→LLR→TC); (d) each `AT` is genuinely black-box — drives the surface, asserts the outcome, references NO internal symbol.

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-129 → HLR-135/136/137 | yes (AT-296/297/298) | yes — the rendered screen + the files on disk, observed through `App.run_test` + the destination folder | yes | yes — DOM + on-disk bytes only; the engine internals are Layer-A TCs | ✓ |
| US-130 → HLR-138 | yes (AT-299) | yes — the on-disk project tree + untouched commons, observed after `^S` | yes | yes — the save action + the file system only | ✓ |
| US-131 → HLR-139 | yes (AT-300) | yes — the OS file manager call (seam spy) + the chip states, observed per press | yes | yes — presses + spy only | ✓ |
| US-132 → HLR-140 | yes (AT-301) | yes — the modal content + dismiss, observed per window | yes | yes — the affordances + the modal only | ✓ |

### Supersession census (change-first)
> Planned new/moved/edited files checked against EVERY guard family (behavioral-placeholder · structural/placement · AST-composition · frozen-module). State reservations; the increment gate is the completeness guarantee, not this census.

Planned file footprint at P1 (the P3 increments detail it in `03-increments/`): a new screen
module + `styles.tcss` additions (the screen, the chips, the modal content) · `app.py` (the
save-gather, the chip wiring, the palette entry, the HelpPanel-untouched help wiring) ·
`s19_app/tui/a2l.py` (the extractor hardening — existing consumers `a2l.py:1448/1676` +
`a2l_parse.py` preserved) · `s19_app/tui/changes/io.py` (the new emitters — existing emitters
untouched) · new test modules for the TC block. Families run at P1: **frozen-module** (the
shipped emitters, the HelpPanel binding, the rail census, the `o`-key idiom — all named
preserved in the LLRs) · **AST-composition** (the extractor's signature/address frozen per the
IFC Part B consumers). **Reservation:** the behavioral-placeholder and structural families are
best-effort at P1 — no code exists yet; the I-gate at each increment is the completeness
guarantee (per the template's own rule).

### Security review summary
not run — `core` mode; trigger family C did not fire at P1. Surface reasoning recorded for P3:
the batch adds no network surface, no new parsers beyond the A2L token hardening (strictly
more robust), one `subprocess.Popen` seam whose argv is a fixed opener + a resolved directory
(never a shell string — LLR-139.3's negative control), and file writes confined to the
change-1 homes + the export destination. The gather's COPY is containment-safe by construction
(`WorkareaContainmentError` precedent, `app.py:6797-6799`).

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer
> Attach each reviewer's completed evidence checklist (items in their agent files), ✓/✗ + one-line evidence.

- **architect:** ✓ the round's record read in full (README · OPEN_QUESTIONS · the three verdict
  JSONs · design_notes · tui_prototype · the three final frames · help_sections · folders.html ·
  the mock's gap table); ✓ the contract pins the rulings + the graft, and says the mock is
  superseded (§1.2, §6.2, ledger); ✓ the IFC's Part B names the extractor's real consumers
  (re-grepped at P1); ✓ every threshold is a measured quantity with its method (118/100/6/1 MiB/0.5).
- **qa-reviewer:** ✓ 15/15 premises TRUE with executed evidence (no document-only citations in
  the evidence column); ✓ the two-layer table complete; ✓ each AT names its counterfactual;
  ✓ the boundary catalog ticks are input classes with a TC/AT each, not decoration; ✓ the id
  reservation matches the registry's high-water parse (AT-296..301 / TC-682..711; TC-1728
  BURNED does not drag the mark).
- **security-reviewer:** not run (core; family C not fired) — the summary above stands in; the
  checklist items owed when a `full` pass runs are the seam argv + the gather containment limbs.

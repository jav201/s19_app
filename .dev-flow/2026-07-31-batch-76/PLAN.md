# batch-76 — PLAN (living compendium)

**Batch:** `2026-07-31-batch-76` · **Requirement:** `R-TUI-102` · **Language:** English
**Route:** `/dev-flow` (full V-model), entering at **Phase 3 (Implementation)**.
**Spec (the plan — NOT re-authored):** `.dev-flow/2026-07-31-batch-75/01-requirements.md`, **revision 2**.

---

## §0 Where we are

batch-75 produced the **spec only** — descoped by operator ruling before Inc-1. batch-76 is the
implementation that was left owing, registered as a **P0** in `.dev-flow/BACKLOG-CODE.md`.
Phases 0–2 are **inherited, not re-run**: the requirement was derived, blocked on 4 blockers, and
re-gated as revision 2. This batch executes **§8 Inc-0 … Inc-3**.

> **Standing correction applied at intake:** the spec is a *hypothesis set*, not law (C-43 tier 2).
> Eight false premises have come out of this area, **four of them from inside the batches that wrote
> them**. Every premise this batch gates on is re-executed here, not cited.

---

## §1 RC-1 + flow currency (Phase 0)

| Check | Result |
|---|---|
| `git fetch` before reading anything | ✅ done — local `main` was **34 commits behind** (`e47b7da`) after the repo move |
| `origin/main` tip | **`291bb76`** ✅ matches the stated base |
| Branch | `claude/batch-76-r-tui-102-impl`, cut fresh off `origin/main` |
| merge-base == tip | ✅ `291bb76` == `291bb76` |
| Tree clean | ✅ tracked-clean; `prototypes/out/` untracked — **pre-existing, reported as found, not swept** (C-44) |
| Repo path | `C:\Users\jjgh8\Github\s19_app` (moved out of OneDrive) |
| Batch number | **76 claimed** — verified free: no `.dev-flow/2026-*-batch-76`, no `origin/*batch-76*` branch |
| Flow revision | `2026.07.28-rev1`, `flow_hash 0127a2767ff11c8a`, controls C-1…C-45 (inherited from batch-75's Phase-0 verdict: enforceable surface byte-exact; only the untracked `dev-flow-lessons` catalog diverges, non-blocking, already carried to Lane B) |
| Toolchain entry gate | ✅ Python **3.14.4** · pytest **8.4.2** · ruff **0.15.17** |

---

## §2 Standing authorization — asked fresh at kickoff (2026-07-31)

Authorization is **per-batch and NEVER inherited** — not from the launch prompt, not from the spec,
not from `state.json`. Asked via `AskUserQuestion` at kickoff; operator answers, verbatim labels:

| # | Question | Answer (verbatim) |
|---|---|---|
| Q1 | Autonomy + merge authority | **"Autonomous + merge authorized"** |
| Q2 | TC-610 / G4 collision resolution | **"Amend TC-610 (Recommended)"** |
| Q3 | Subagents for independent review | **"Use subagents as the flow says"** |

**Merge precondition (binding).** After the PR is opened and CI is green, a **final independent
`qa-reviewer` pass over the WHOLE merged diff vs `main`** must run — dual traceability intact · 0
engine-frozen diffs · no cross-increment regression · every gate carry discharged — and come back
clean. **A HIGH finding blocks the merge and returns to the operator.**

**Decision recording.** Every decision taken autonomously instead of asking is recorded in §8 below,
in `state.json.decisions_log`, in `05-postmortem.md`, and carried to the vault at `/dev-flow-sync`.

**Q3 note.** The session harness carries *"Do not call the Agent tool unless the user requested it."*
The operator has now explicitly requested it, so the flow's independent-review property is restored:
`code-reviewer` at each increment gate, `qa-reviewer` at Phase 4 and at the merge gate, with **C-33
liveness polling** (a hung agent never notifies).

---

## §3 Premise re-execution (C-43) — executed against `291bb76`, not cited

Everything below was **run**, not read across from batch-75's table.

### §3.1 Re-verified HELD

| # | Proposition | Executed evidence |
|---|---|---|
| **P-1** | `emit()` accounts, never gates | `grep -c` → **1** `.fits(` (`:1785`) vs **2** `.consume(` (`:1750`, `:2547`). The single gate is inside `_hexdump_section`'s **block loop** and covers neither `put` nor `emit`. |
| **P-21** | `_hexdump_section`'s `put()` does not gate | `:1750` = `budget.consume(_line_bytes(batch))` with no `fits` guard above it. |
| **P-5/P-6** | the `Length` sites, and `_format_length`'s absence | Both inline sites reproduce at **`:1356`** and **`:1582`** exactly as specced; `_format_length` → **0 hits**. |
| **P-12** | the generator writes once, at the end | `:2591` single `target.write_bytes(...)` — fail-closed by construction. |
| **P-22** | `LLR-102.x` are live ids | `:608` (`LLR-102.2`), `:622` (`LLR-102.1`) — confirming the revision-2 renumber to `HLR-108/109/110` was necessary. |
| **Inc-3 site** | the re-attribution target | `app.py:4155` `generate_project_report` sits **inside** the `try` whose `except ValueError` at `:4158` sets **`Report rejected:`** at `:4164`. Progress resets at `:4163` and `:4176` both already present (`AT-263` is correctly a PIN). |

`report_service.py` measures **2592 lines** at `291bb76` — the backlog's own warning that every line
number in it is stale in both directions is honoured: all addresses above were re-derived.

### §3.2 NEW — **P-26, FALSE.** A ninth false premise, and it is not batch-75's

> **Proposition (from `BACKLOG-CODE.md`, the AT/TC-registry Lane-A close note):** *"Because it is
> SPEC-ONLY those ids stay `RESERVED` — they convert to `LIVE` when its Inc-0…Inc-3 write the nodes."*

❌ **FALSE.** The conversion the note promises is **forbidden by the guard that shipped with it.**

| Limb | Executed | Result |
|---|---|---|
| TC-610 forbids the conversion | flipped **AT-250** `RESERVED`→`LIVE` in the registry, ran `test_tc610` | **RED** — `AssertionError: AT-250 must be RESERVED for batch-75` (`test_id_registry.py:530`) |
| G4 compels the conversion | inserted `- Validation: … (AT-250)` at `REQUIREMENTS.md:64`, ran `test_tc603_g4` | **RED** — `REQUIREMENTS.md:64 asserts AT-250 (RESERVED) as a live verifier under heading 'Reading', which is not a declared exempt anchor` |

**Both mutations restored and verified by SHA-256 returning to its pre-mutation value** (`git status`
alone would have been insufficient), guard back to **13 passed**:
`AT-TC-REGISTRY.jsonl` → `6b848519…b1125` · `REQUIREMENTS.md` → `12754289…7ac2`.

**The two guards are mutually unsatisfiable for this batch's own work.** The spec's §8 has every
increment editing `REQUIREMENTS.md`; R-TUI-102's verifier column names `AT-250…AT-263`. Writing it
forces LIVE (or G4 reddens); LIVE reddens TC-610.

**Disposition — operator ruling Q2: amend TC-610.** It becomes *reserved-or-spent-by-its-owner*:
an id in the block is `RESERVED`, **or** `LIVE` and spent by the batch that owns the reservation;
the unspent remainder must still be reserved, and nothing in the block may be `reserved_by` a
stranger. That preserves the guard's actual purpose — **no foreign minting inside the block** — and
stops it firing on the legitimate work *its own docstring says it exists not to fire on*:
> *"A guard that fires on legitimate work is worse than no guard, because it teaches everyone to
> wave it through."* — `test_id_registry.py:521-522`

`tests/test_id_registry.py` is **not** in the frozen `_ENGINE_TEST_FILES` set, so it is editable.

### §3.3 Carried UNDECIDABLE — resolved at Inc-1, never assumed (spec §2.3 + §10)

| # | Proposition | Plan |
|---|---|---|
| **P-16** | Can the preamble be refused under the shipped budget? | execute at Inc-1. **If TRUE, `LLR-108.8` flips to an explicit exemption and the allowance grows — a requirement-strength change, surfaced at the gate, never absorbed.** |
| **P-17** | Does capping the truncation appendix drift a shipped golden? | execute at Inc-1. Today's note count is 3→4; a cap above that is inert. |
| **P-25** | Does the per-variant reservation floor starve a single-variant report? | execute at Inc-1 against the **shipped example projects**. |

---

## §4 Increment plan (spec §8 — ≤5 files each)

| Inc | Scope | Files | Owns | Status |
|---|---|---|---|---|
| **Inc-0** | Pre-flight golden capture from the **shipped** producer (C-12) | `tests/goldens/batch76/` | enables `AT-256` | ⏳ |
| **Inc-1** | `emit` + `put` gating · per-variant reservation · aggregated disclosure · capped round-robin appendix · derived allowance | `report_service.py`, `tests/test_report_document_bound.py` (new), `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl`, `tests/test_id_registry.py` | **AT-250…AT-256** · TC-552…TC-561 | ⏳ |
| **Inc-2** | `_format_length` + both call sites | `report_service.py`, `tests/test_report_length_cell.py` (new), `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` | **AT-257…AT-259** · TC-562…TC-569 | ⏳ |
| **Inc-3** | Error re-attribution | `app.py`, `tests/test_tui_report_attribution.py` (new), `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` | **AT-260…AT-263** · TC-570…TC-572 | ⏳ |

**Ordering is load-bearing and must not be inverted.** Inc-2 precedes Inc-3 because once
`_format_length` lands, the natural `Length`-driven `ValueError` disappears; Inc-3 must then
**inject** its fault, which makes `AT-260` a **general** attribution test rather than one welded to
the D2 bug.

**D2 (US-B75-2) — re-triaged P3 (hardening) 2026-07-31**, unreachable through any shipped path
(both construction sites bounded by `MF_RUN_LENGTH_CEILING` → 7 decimal digits vs a 4300 limit).
**It stays in scope** (its ATs are already gated and the cheap moment to ship hardening is with the
file open) — but if iteration pressure forces a sacrifice, **Inc-2 is the candidate, never Inc-1/F4.**

---

## §5 Conventions honored

- **Frozen set — OFF LIMITS:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
  `tui/mac.py`, `tui/color_policy.py` + the frozen TEST files (`_ENGINE_TEST_FILES`).
  **`markdown_safety.py` is additionally not edited** (spec P-4). Dual guard (C-27): both the frozen-
  SOURCE and frozen-TEST-file guards run at every increment, not one.
- **Every behavioural change ships its `AT-NNN` shown RED before the fix**; the counterfactual is
  executed on a **COPY of the fixed tree**, recording the **substituted expression** (C-40, and the
  batch-73 lesson that "drop the clamp" names no unique mutant).
- **Two vacuity classes checked, not one:** the vacuous *predicate* (catalogued) **and the vacuous
  *fixture*** — a correct predicate that cannot fail because the fixture never exercises what it
  asserts. The new class is why `AT-252` was blocked in revision 1, and `TC-552` is its guard.
- **C-39:** every number re-derived before it is gated on. Nothing inherited.
- **≤5 files per increment.** **No `.dev-flow/state.json` edit without re-reading it immediately
  first** — last-writer-wins, no owner field.
- **Every phase produces its artifact or declares in writing why it does not** (batch-74 reached
  MERGE with no `04-validation.md` and no `06-docs/`, and `/dev-flow-sync` caught it, not the gate).

---

## §6 Risks / watch-items

| # | Risk | Mitigation |
|---|---|---|
| R-1 | **Iteration cap.** This area hit the 3-iteration cap in Phase 1 **and** Phase 2 across **three** batches (b63, b74, b75). | Budgeted. On hitting the cap I **escalate to the operator — no looping, no self-rescoping.** |
| R-2 | The spec is a hypothesis, and this area's premises fail from *inside* the batch that writes them. | Every premise re-executed here (§3); P-26 already found. |
| R-3 | `report_service.py` is 2592 lines and `app.py` is 11 654 — context pressure was part of why b75 was descoped. | Increments are file-scoped and read surgically; checkpoints at every gate. |
| R-4 | Golden drift from the appendix cap (P-17) and from any emitted-form change. | C-24 report-golden census before each increment closes. |
| R-5 | A parallel session may own `state.json`. | Re-read immediately before every write. |

---

## §7 Out-of-scope (fenced, with reasons — not silently dropped)

| Item | Disposition |
|---|---|
| `_applied_regions` — the third unbounded producer | **Operator-FENCED.** A whole-report *residency* acceptance is **unsatisfiable** until it is bounded; the spec's non-claim (a) says so in writing. This batch bounds the **produced file**, and claims nothing about peak memory. |
| **D-11** host-path redaction | **Not in scope.** Withdrawn at batch-62 after 3 integrity defects; non-claim (g) already records that `HLR-110` widens the traceback aperture deliberately. |
| `screens.py:1717-1719` — a **non-integer** `context_bytes` makes Generate silently do nothing | Spec §10 m-4, adjacent defect → **`BACKLOG-CODE.md`** at close. |
| `R-TUI-101` wording carve-outs | **Declared STILL OPEN** by batch-75 (it never edited `REQUIREMENTS.md`). Discharged in this batch's close **or** restated openly as owed. |

---

## §8 Decision log

| # | Date | Decision | Autonomous? | Notes |
|---|---|---|---|---|
| D-1 | 2026-07-31 | Claim batch number **76** | autonomous | Verified free: no artifact dir, no remote branch. |
| D-2 | 2026-07-31 | Force-checkout over 5 untracked `prototypes/*` files | autonomous | Proven **byte-identical** to their `origin/main` blobs by `git hash-object` before acting — zero information at risk; they were untracked only because local `main` predated the commit adding them. `prototypes/out/` left in place and reported. |
| D-3 | 2026-07-31 | Follow the **spec's** AT range (`AT-250…263`), not the launch prompt's (`AT-256…263`) | autonomous | The prompt's start is off by six; all of `AT-250…279` are `RESERVED` in the registry, so neither reading mints anything unregistered. Flagged to the operator. |
| D-4 | 2026-07-31 | **Amend TC-610** to resolve the P-26 collision | **OPERATOR** (Q2) | Not autonomous — escalated because it changes a shipped guard. |
| D-5 | 2026-07-31 | Phases 0–2 inherited, not re-run | autonomous | The launch prompt is explicit: *"Es el plan; NO escribas otro."* Premises re-executed regardless (§3). |

---

## §9 Test ledger

| Gate | Base | −D | +A | Post | Reconciled |
|---|---|---|---|---|---|
| baseline `291bb76` | — | — | — | *(to be measured at Inc-0)* | ⏳ |

`tests/test_id_registry.py` baseline at intake: **13 passed**.

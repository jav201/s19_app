# PLAN — batch-86 · IFC retrofit surface #2 (clean start)

> Living compendium. Updated at every gate and checkpoint. Mode **core** · autonomous
> (no merge — stops at "PR opened, CI green") · artifacts in **English**.

## Where we are

- **Station:** P0 (intake) — in progress.
- **Trial batch:** this is the FIRST batch run under flow rev42–rev44 (Atlas + V20 · selector
  taxonomy · coherence V21–V23). Part of its purpose is to exercise that machinery end to end.

## Objective

Author the IFC record for a SECOND surface, clean-start, applying the batch-85 format lessons:

1. **Pair-based thresholds** — any reacher/census threshold stated over `(output_id, file)`
   pairs, never a file-set projection (batch-85 defect #1).
2. **Split heterogeneous populations** — one address unites one population; distinct row
   kinds get distinct outputs (defect #12 / D-A: the five-output union erased which invariant
   moved; the recommendation there was SIX outputs, not four).
3. **Scoped statements** — every Statement carries an explicit scope rule; no repo-wide
   predicates with frozen historical hits (defect #7).

Plus: `SURFACE:` field (rev42 template), canon mirror seeded for the new ids (V22's backlog
must NOT grow), Atlas regenerated at every gate (V20), per-surface cost to n=2 with dispersion.

## Base and flow currency (RC-1 · C-45)

| | |
|---|---|
| `origin/main` tip | `a112eeb` — merge-base equals it; branch `claude/batch-82-lane-a-scoping` (PR #199) |
| flow | `2026.08.24-rev44`, `flow_hash 70ac33486b32d024`; validator `0 block · 233 notice · 15 n/a` at open |
| suite base | `s19env` (conda, Python 3.11.15 + pytest + pytest-textual-snapshot 1.1.0): 2714/2735 collected (21 deselected); full not-slow baseline run in progress, ledger base recorded when it lands |

## Story (intake)

**US-86-1.** As the operator auditing s19_app's addressability, I want the IFC record
(Part A + Part B) of a second surface — selected by measured evidence — authored to the
corrected format, so that a second surface becomes contractually addressable, the pilot's
`PARENT` can be balanced (V12 verdict instead of "NOT checked"), and the per-surface cost
gains a second data point.

- **INVEST:** Independent (no other batch touches these artifacts) · Negotiable (record
  details fixed at Phase 1) · Valuable (audit + V12 live + n=2 cost) · Estimable (pilot's
  measured cost record, LLR-85.7) · Small (one surface record + canon mirror; **0 product
  code**) · Testable (validator verdicts + Atlas + suite-neutral evidence).
- **Black-box acceptance criteria (behavior level, refined into AT-B86-* at Phase 1):**
  - When the record lands, `devflow-validate` reports **verdicts** (not SKIP) for
    V10–V14/V19/V21 over the new component, with 0 BLOCK attributable to it.
  - When the Atlas is regenerated, the new component renders one-row-per-declaration and
    V20 reports `atlas current`.
  - When the canon is re-read, the batch's new ids are reflected (V22's unreflected-id
    aggregate does NOT grow).
  - The whole-suite gate run is byte-neutral on product behavior (0 source files touched).
- **Classification: READY.**

## Surface-selection hypothesis (to be CONFIRMED by probe at Phase 1)

The pilot declared `PARENT : screen_workspace` and **left it undeclared** — V12 reports
"balancing NOT checked" on the corpus today. Declaring the workspace surface as #2 is the
selection that turns an existing degraded verdict into a real one. Phase-1 probes must:
identify the class/file that IS the workspace (candidate: the Direction-B workspace in
`s19_app/tui/screens_directionb.py` — also already named by V13 as an undeclared reacher of
`#loaded_slots`), enumerate its addressable outputs and their reachers, and record the
decision with the probe transcripts. **If the probe refutes the hypothesis** (e.g. the
workspace is not independently addressable), fall back to the next evidence-ranked surface
and record why.

## Triggers (id · verdict · probe)

| id | verdict | probe |
|---|---|---|
| A1–A4 | not fired | no module created/moved; planned diff = `.dev-flow/**` + `REQUIREMENTS.md` only; `docs/ARCHITECTURE.md` untouched (its own D-IV gap is a known carry, not this batch) |
| B1 | not fired | no code symbol edited; `grep -rl` n/a (0 source files planned) |
| B2 | not fired | no file moves |
| B3 | not fired | no golden-captured source touched |
| **B4** | **FIRED** | the record IS an artifact another component consumes (validator + Atlas). C-12 discharge: the acceptance runs the real consumers — `devflow-validate` + `--atlas` — over the handler-produced record, never a hand-fed copy |
| C (security) | not fired | no auth/secrets/external writes/markup-mode changes in planned diff |
| D (interaction) | not fired | no user-visible change |
| E (size) | not fired | 1 story, not a client deliverable |
| F (flow currency) | not fired | rev44 current (V7 green), lane-A backlog refreshed this session |
| ARQ / PDR / DDR | not activated | mode core = by trigger; no A-family trigger fired. "No architecture change" declared with the empty map diff |

## Decision log (mirrors state.json)

| # | date | decision |
|---|---|---|
| D-86-1 | 2026-08-24 | Batch opened autonomous/no-merge; operator words recorded in state.json |
| D-86-2 | 2026-08-24 | Mode core (batch-85's C-50 reasoning applies unchanged) |
| D-86-3 | 2026-08-24 | Surface-selection hypothesis = the pilot's undeclared PARENT; confirmation by probe is Phase 1's first task |

## Risks / watch-items

- The workspace surface may be larger than the pilot (more outputs) — cost record must not
  extrapolate from n=1 (LLR-85.7's own caveat).
- Editing batch-85's record (e.g. adding consumers to clear its V13 notices) is **D-II
  territory and OUT of scope** — surface #2 is a NEW record; any pilot amendment is its own
  decision, recorded if proposed.
- Every gate regenerates the Atlas (V20) — banner carries flow_version, so a mid-batch flow
  bump would invalidate it; none is planned.

## Test ledger

Base: pending the in-flight s19env baseline run (2714 selected). This batch plans **0 source
files**; ledger target `post = base − 0 + A` where A = any new census/guard tests Phase 1
derives (may legitimately be 0 — the validator, not pytest, is this batch's primary oracle).

## Out of scope (recorded so it cannot creep)

- D-II (salvage vs re-author the pilot record) — open decision, untouched.
- The remaining 25 surfaces; the C3 seeding backlog beyond this batch's own ids.
- `docs/ARCHITECTURE.md` path-prefix gap (D-IV) — carried.
- rev45+ flow changes of any kind.

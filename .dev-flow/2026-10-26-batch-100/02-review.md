# Review — s19_app — Batch 2026-10-26-batch-100

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer` by trigger family C (always in `full`).

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/review-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

## ✅ Verdict (read first)

- **Gate:** `iterate-to-refine` → Phase 1 (round 1: every reviewer returned `iterate-to-refine`; blockers present). Round 2 of the contract is applied; **round 2 re-review pending.**
- **Out-of-scope findings:** 1 named and routed below (A-01's writer routing → `BACKLOG-CODE.md` §*Routed 2026-10-26 — batch-100 P2 round 1*); QA-20 routed to the orchestrator (PLAN).

- **Findings:** 6 blocker · 45 major · 35 minor (86 in all: ux 25, security 16, qa 27, architect 18). After round 2: 84 fixed, 1 routed (QA-20), 1 open (S-16, operator acceptance).
- **shall/should check:** ✓ clean — round-2 contract: 85 `Statement` lines, 0 modal `should` (executed regex over `- **Statement:**` lines).
- **Two-layer (blockers):** ✓ every story has an `AT` (21 ATs over 16 stories) · output reqs name deliverable+observation · both trace chains complete (`devflow-validate --brief`, V10/V21) · ATs are genuinely black-box (§3 preface bans `app._…` access and private calls; QA-01's `vars(app)` comparison is TC-B100-09)
- **Census (change-first):** done — best-effort + gate-confirmed (§5.4 of the contract, 35 test sources)
- **Security:** ⚠ 16 findings (0 HIGH): 15 fixed in round 2, S-16 open for the operator. Scan re-run on the round-2 contract: flags `token`, `session`, `permission`, `secret`, `hash`, `form`, `escape`, `expose`; `security_required: true`; each answered in the contract's §6.3.
- **Evidence checklists (architect / qa / security / ux):** ✓ all complete — in each reviewer file under `design/` (`P2-architect-r1.md`, `P2-qa-r1.md`, `P2-security-r1.md`, `P2-ux-r1.md`).

> If gate = `approve` and every line is ✓, the Detail below is reference. Any blocker/⚠ → read the matching part.

---

## Detail (reference)

### Reviewers' verdicts (round 1)

| Reviewer | File | Verdict | HIGH · MAJOR · MINOR |
|---|---|---|---|
| ux-reviewer | `design/P2-ux-r1.md` | `iterate-to-refine` | 2 · 14 · 9 |
| security-reviewer | `design/P2-security-r1.md` | `iterate-to-refine` | 0 · 9 · 7 |
| qa-reviewer | `design/P2-qa-r1.md` | `iterate-to-refine` | 3 · 14 · 10 |
| architect | `design/P2-architect-r1.md` | `iterate-to-refine` | 1 · 8 · 9 |

Dispositions: `design/P2-dispositions-r1.md` (the operator's prototype verdict §1, the orchestrator's rulings §2 and §4, the increment changes §3). Every finding is closed with its reviewer's closure unless a ruling says otherwise; the `Disposition` column names each exception.

### Findings
| ID | Reviewer | Severity | Disposition | Where closed | Ledger | Status |
|----|----------|----------|-------------|--------------|--------|--------|
| UX-01 | ux-reviewer | blocker | accepted — reviewer's closure | LLR-167.5, LLR-174.1, LLR-175.4 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| UX-02 | ux-reviewer | blocker | accepted — reviewer's closure | HLR-176, HLR-177 | LED-2026-10-26-batch-100.11 | fixed (round 2, re-review pending) |
| UX-03 | ux-reviewer | major | accepted — reviewer's closure | LLR-166.1 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-04 | ux-reviewer | major | accepted — reviewer's closure | HLR-166, LLR-166.1 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-05 | ux-reviewer | major | accepted — reviewer's closure | LLR-173.2 (VS-PA-6) | LED-2026-10-26-batch-100.2 | fixed (round 2, re-review pending) |
| UX-06 | ux-reviewer | major | accepted — reviewer's closure | LLR-173.5 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-07 | ux-reviewer | major | accepted — reviewer's closure | §3 refusal-token table | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-08 | ux-reviewer | major | accepted — reviewer's closure | LLR-169.6, LLR-178.2 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| UX-09 | ux-reviewer | major | accepted — reviewer's closure | HLR-178, LLR-178.1, LLR-178.3 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| UX-10 | ux-reviewer | major | accepted — reviewer's closure | §3 preface, LLR-173.6 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-11 | ux-reviewer | major | accepted as ruled: ask only when something would be lost | LLR-174.1 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| UX-12 | ux-reviewer | major | accepted — reviewer's closure | LLR-174.2 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| UX-13 | ux-reviewer | major | accepted — reviewer's closure | §3 preface, LLR-173.2, LLR-174.2, LLR-175.3 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-14 | ux-reviewer | major | accepted — reviewer's closure | LLR-168.3 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| UX-15 | ux-reviewer | major | closed by the verdict (outcomes stated) | HLR-174, HLR-176, HLR-177 slot lines | LED-2026-10-26-batch-100.2 | fixed (round 2, re-review pending) |
| UX-16 | ux-reviewer | major | accepted — reviewer's closure | §5.1 | LED-2026-10-26-batch-100.12 | fixed (round 2, re-review pending) |
| UX-17 | ux-reviewer | minor | accepted — reviewer's closure | LLR-172.5 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-18 | ux-reviewer | minor | accepted — reviewer's closure | LLR-173.7 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-19 | ux-reviewer | minor | accepted — reviewer's closure | LLR-169.9 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| UX-20 | ux-reviewer | minor | accepted — reviewer's closure | HLR-178 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| UX-21 | ux-reviewer | minor | accepted — reviewer's closure | LLR-175.1, LLR-175.4 | LED-2026-10-26-batch-100.4 | fixed (round 2, re-review pending) |
| UX-22 | ux-reviewer | minor | accepted — reviewer's closure | §3 refusal-token table | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-23 | ux-reviewer | minor | accepted — reviewer's closure | LLR-173.4 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| UX-24 | ux-reviewer | minor | accepted — reviewer's closure | HLR-173 (VS-PA-2) | LED-2026-10-26-batch-100.2 | fixed (round 2, re-review pending) |
| UX-25 | ux-reviewer | minor | accepted — reviewer's closure | LLR-170.2 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| S-01 | security-reviewer | major | accepted — reviewer's closure | LLR-172.5 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-02 | security-reviewer | major | accepted — reviewer's closure | LLR-171.4, AT-B100-11 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-03 | security-reviewer | major | accepted — reviewer's closure | LLR-171.1 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-04 | security-reviewer | major | accepted — reviewer's closure | LLR-164.1 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| S-05 | security-reviewer | major | accepted — reviewer's closure | LLR-164.4 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| S-06 | security-reviewer | major | accepted — reviewer's closure | LLR-172.6, LLR-173.3, LLR-178.2 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| S-07 | security-reviewer | major | accepted — reviewer's closure | LLR-172.2, LLR-173.4 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-08 | security-reviewer | major | accepted; caps 1 MiB and 1 000 records; the panel paints every problem (§1 P-E supersedes '+K more') | LLR-169.4 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-09 | security-reviewer | major | accepted — reviewer's closure | LLR-169.8 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-10 | security-reviewer | minor | accepted — reviewer's closure | LLR-169.4, LLR-169.5 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-11 | security-reviewer | minor | accepted — reviewer's closure | LLR-170.1 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| S-12 | security-reviewer | minor | accepted — reviewer's closure | LLR-172.1, LLR-172.2 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-13 | security-reviewer | minor | accepted — reviewer's closure | LLR-172.6, LLR-173.3 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| S-14 | security-reviewer | minor | accepted — reviewer's closure | LLR-164.3 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| S-15 | security-reviewer | minor | accepted; free-space check, no file-count cap ruled (§6.3) | LLR-171.1 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| S-16 | security-reviewer | minor | OPEN — answered in §6.3, awaiting the operator's acceptance | §6.3 | LED-2026-10-26-batch-100.6 | open |
| QA-01 | qa-reviewer | blocker | accepted as amended by A-07 (the set stays derived) | LLR-165.2 | LED-2026-10-26-batch-100.8 | fixed (round 2, re-review pending) |
| QA-02 | qa-reviewer | blocker | accepted — reviewer's closure | LLR-172.6, LLR-173.3 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| QA-03 | qa-reviewer | blocker | accepted — reviewer's closure | LLR-174.1, LLR-174.2 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| QA-04 | qa-reviewer | major | accepted — reviewer's closure | LLR-164.2 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| QA-05 | qa-reviewer | major | accepted, with a stated deviation: `copy_into_workarea` keeps its `Path` return (§6.3) | LLR-163.1, LLR-163.6 | LED-2026-10-26-batch-100.9 | fixed (round 2, re-review pending) |
| QA-06 | qa-reviewer | major | superseded by A-06 (dispositions §2/§4): Save project uses `save_patched` | LLR-167.2 | LED-2026-10-26-batch-100.4 | fixed (round 2, re-review pending) |
| QA-07 | qa-reviewer | major | accepted — reviewer's closure | LLR-169.9 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| QA-08 | qa-reviewer | major | accepted — reviewer's closure | LLR-169.6, LLR-178.2 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| QA-09 | qa-reviewer | major | accepted — reviewer's closure | HLR-167 (AT-B100-05) | LED-2026-10-26-batch-100.4 | fixed (round 2, re-review pending) |
| QA-10 | qa-reviewer | major | accepted; rebuilt on the S-02 junction RED path | HLR-171 (AT-B100-11), LLR-171.4 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| QA-11 | qa-reviewer | major | accepted — reviewer's closure | LLR-169.7 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| QA-12 | qa-reviewer | major | accepted — reviewer's closure | LLR-172.2 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| QA-13 | qa-reviewer | major | accepted — reviewer's closure | LLR-176.2 | LED-2026-10-26-batch-100.11 | fixed (round 2, re-review pending) |
| QA-14 | qa-reviewer | major | accepted — reviewer's closure | §5.3 | LED-2026-10-26-batch-100.12 | fixed (round 2, re-review pending) |
| QA-15 | qa-reviewer | major | accepted — reviewer's closure | §5.4 | LED-2026-10-26-batch-100.12 | fixed (round 2, re-review pending) |
| QA-16 | qa-reviewer | major | accepted — reviewer's closure | §3 preface, HLR-176, HLR-177 | LED-2026-10-26-batch-100.11 | fixed (round 2, re-review pending) |
| QA-17 | qa-reviewer | major | closed by the verdict (fill-only options) | slot lines of HLR-173 to HLR-178 | LED-2026-10-26-batch-100.2 | fixed (round 2, re-review pending) |
| QA-18 | qa-reviewer | minor | accepted — reviewer's closure | LLR-164.3 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| QA-19 | qa-reviewer | minor | accepted — reviewer's closure | LLR-170.2 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| QA-20 | qa-reviewer | minor | routed — PLAN is the orchestrator's file | PLAN (orchestrator) | — | routed |
| QA-21 | qa-reviewer | minor | accepted — reviewer's closure | LLR-174.1 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| QA-22 | qa-reviewer | minor | accepted — reviewer's closure | LLR-164.1 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| QA-23 | qa-reviewer | minor | accepted — reviewer's closure | LLR-173.1, Part B `load_dialog` | LED-2026-10-26-batch-100.12 | fixed (round 2, re-review pending) |
| QA-24 | qa-reviewer | minor | accepted — reviewer's closure | §5.1 | LED-2026-10-26-batch-100.12 | fixed (round 2, re-review pending) |
| QA-25 | qa-reviewer | minor | accepted — reviewer's closure | HLR-163 (AT-B100-01) | LED-2026-10-26-batch-100.9 | fixed (round 2, re-review pending) |
| QA-26 | qa-reviewer | minor | accepted — reviewer's closure | LLR-176.3 | LED-2026-10-26-batch-100.11 | fixed (round 2, re-review pending) |
| QA-27 | qa-reviewer | minor | accepted — reviewer's closure | LLR-163.3 | LED-2026-10-26-batch-100.9 | fixed (round 2, re-review pending) |
| A-01 | architect | blocker | accepted, option (b); routing filed in BACKLOG-CODE | LLR-169.5, §1.2, BACKLOG-CODE | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-02 | architect | major | accepted — reviewer's closure | LLR-168.3 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-03 | architect | major | accepted — reviewer's closure | LLR-168.3, AT-B100-20 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-04 | architect | major | accepted — reviewer's closure | LLR-169.4 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| A-05 | architect | major | accepted — reviewer's closure | LLR-169.9 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-06 | architect | major | accepted; reverses the QA-06 ruling | LLR-167.2 | LED-2026-10-26-batch-100.4 | fixed (round 2, re-review pending) |
| A-07 | architect | major | accepted — reviewer's closure | LLR-165.1, LLR-165.2 | LED-2026-10-26-batch-100.8 | fixed (round 2, re-review pending) |
| A-08 | architect | major | accepted; two predicates kept separate | LLR-167.1, LLR-167.5 | LED-2026-10-26-batch-100.3 | fixed (round 2, re-review pending) |
| A-09 | architect | major | accepted — reviewer's closure | LLR-164.2 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| A-10 | architect | minor | accepted — reviewer's closure | LLR-164.3 | LED-2026-10-26-batch-100.5 | fixed (round 2, re-review pending) |
| A-11 | architect | minor | accepted — reviewer's closure | ledger (LLR-015.3, R-TUI-012) | LED-2026-10-26-batch-100.13 | fixed (round 2, re-review pending) |
| A-12 | architect | minor | accepted — reviewer's closure | LLR-170.2 | LED-2026-10-26-batch-100.10 | fixed (round 2, re-review pending) |
| A-13 | architect | minor | accepted — reviewer's closure | LLR-169.2 | LED-2026-10-26-batch-100.6 | fixed (round 2, re-review pending) |
| A-14 | architect | minor | accepted — reviewer's closure | LLR-171.2 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-15 | architect | minor | accepted — reviewer's closure | LLR-169.2, LLR-170.1 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-16 | architect | minor | accepted — reviewer's closure | LLR-178.1 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |
| A-17 | architect | minor | accepted — reviewer's closure | LLR-177.1 | LED-2026-10-26-batch-100.4 | fixed (round 2, re-review pending) |
| A-18 | architect | minor | accepted — reviewer's closure | LLR-169.5, LLR-178.1 | LED-2026-10-26-batch-100.7 | fixed (round 2, re-review pending) |

### shall / should check
> Any modal `should` / `debería` inside an HLR/LLR statement is a writing error → blocker.

Round-2 contract: 85 `- **Statement:**` lines, 0 matches of `\bshould\b` (executed, 2026-10-26).

### Two-layer acceptance review (blockers)
> (a) every story has a black-box `AT`; (b) every output-producing requirement names its observable deliverable + observation method; (c) BOTH traceability chains complete (behavioral US→AT→outcome + functional US→HLR→LLR→TC); (d) each `AT` is genuinely black-box — drives the surface, asserts the outcome, references NO internal symbol.

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-153 to US-168 | yes (AT-B100-01 to AT-B100-21) | yes | yes (V10/V21, ATLAS-TRACE) | yes, after round 2 (QA-01, QA-16) | ✓ pending round-2 re-review |

### Supersession census (change-first)
> Planned new/moved/edited files checked against EVERY guard family (behavioral-placeholder · structural/placement · AST-composition · frozen-module). State reservations; the increment gate is the completeness guarantee, not this census.

The contract's §5.4 lists, per touched symbol, the test sources it reaches and each disposition (35 sources). Whole-tree guards at every gate: `pytest tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_address_census.py tests/test_batch91_registry_hygiene.py tests/test_engine_unchanged.py`. Reservation: 29 snapshot cells rebaseline in Inc 9b, 11 and 12a, each named in its packet. Best-effort + gate-confirmed.

### Security review summary
`security-reviewer`, round 1: 0 HIGH · 9 MAJOR · 7 MINOR, verdict `iterate-to-refine` (`design/P2-security-r1.md`). Round 2 closes S-01 to S-15 in the contract (LED .5, .6, .10); S-16 (absolute paths in `.s19tool/recent_sources.json` travel with a shared `.s19tool`) stays open for the operator's acceptance. **Round 2 re-review pending.**

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer · ux-reviewer
> Attach each reviewer's completed evidence checklist (items in their agent files), ✓/✗ + one-line evidence.

Each checklist is in its reviewer file, section *Evidence checklist*: `design/P2-architect-r1.md`, `design/P2-qa-r1.md`, `design/P2-security-r1.md`, `design/P2-ux-r1.md`. Their ✗ items (qa: three; architect: two; ux: six) are the findings above, closed or open as the table shows.

## Round 2 — re-review pending
The P1 author applied the dispositions as round 2 of `01-requirements.md` (ledger entries LED-2026-10-26-batch-100.2 to .13). The four reviewers re-read the round-2 contract; their verdicts land here as round 2.

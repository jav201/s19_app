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

## Round 2 — re-review results and round-3 closures

The four round-2 reviews (`design/P2-security-r2.md`, `P2-ux-r2.md`, `P2-qa-r2.md`, `P2-architect-r2.md`) re-read the contract at `0c7ca1d`. Every reviewer returned `iterate-to-refine`. Of the 86 round-1 findings, 77 closed; the rest are carried below with the round-2 findings. The P2 iteration cap was reached, and the operator chose a **bounded round 3**: the author applies `design/P2-dispositions-r2.md`, then each reviewer verifies only the closure of its own open findings. The operator also decided S-16 (the recent list per user at `%APPDATA%\s19_app\recent_sources.json`).

| Reviewer | Round-2 verdict | Open after round 2 (HIGH · MAJOR · MINOR) |
|---|---|---|
| security-reviewer | `iterate-to-refine` | 0 · 3 new + S-02, S-08 carried · 6 new + S-16 |
| ux-reviewer | `iterate-to-refine` | 1 · 10 (incl. UX-05 carried) · 7 (incl. UX-07, UX-22 residuals) |
| qa-reviewer | `iterate-to-refine` | 0 · 6 · 8 (QA-12, QA-14, QA-20 continue as R2-08, R2-06, R2-14) |
| architect | `iterate-to-refine` | 1 · 6 · 7 |

**Open findings closed in round 3:** 58 (2 blocker · 27 major · 29 minor). Ids: security round-2 findings are written `S-R2-NN` and QA round-2 findings `QA-R2-NN` to keep the two `R2-` sequences apart. The coordinator's alignment with the architect's B-07 rows (ARQ §8 / §8.1, `docs/architecture.md` B100-I13..I22) is applied in the same round: containment ships with the placement at Inc 1, `derived_from` is written at Inc 7, the base-not-in-project wording, the B100-I5 pre-check left to PDR, both flow callers on the default path mode, and Inc 10's optional `screens_directionb.py`.

| ID | Reviewer | Severity | Origin | Disposition | Where closed | Ledger | Status |
|----|----------|----------|--------|-------------|--------------|--------|--------|
| S-R2-01 | security-reviewer | major | new | accepted; the guard ships with the placement at Inc 1 (coordinator alignment) | LLR-171.4, LLR-163.1, LLR-164.2 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-02 | security-reviewer | major | new | accepted — reviewer's closure | LLR-163.1 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-03 | security-reviewer | major | new | accepted — reviewer's closure | LLR-169.4, LLR-173.4 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-04 | security-reviewer | minor | new | accepted with the ruling: device names checked on the raw name too (`con.txt` refused, unlike the reviewer's closure) | LLR-164.1 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-05 | security-reviewer | minor | new | accepted — reviewer's closure | LLR-169.8, LLR-172.2 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-06 | security-reviewer | minor | new | accepted — reviewer's closure | LLR-171.1 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-07 | security-reviewer | minor | new | accepted — reviewer's closure | LLR-164.2 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-R2-08 | security-reviewer | minor | new | accepted — reviewer's closure | LLR-172.2, §6.3 | LED-2026-10-26-batch-100.21 | fixed (round 3, bounded verification pending) |
| S-R2-09 | security-reviewer | minor | new | accepted — reviewer's closure | LLR-164.4, LLR-177.1 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| S-02 | security-reviewer | major | carried | accepted — reviewer's closure | LLR-171.4 (inside `place_into_workarea`) | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-08 | security-reviewer | major | carried | accepted — reviewer's closure | LLR-169.4 (every array capped) | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| S-16 | security-reviewer | minor | carried (operator) | operator decision: per-user store `%APPDATA%\s19_app\recent_sources.json` | LLR-172.1, §6.3 (per-user store) | LED-2026-10-26-batch-100.21 | fixed (round 3, bounded verification pending) |
| UX-05 | ux-reviewer | major | carried | accepted — reviewer's closure | LLR-173.2 | LED-2026-10-26-batch-100.18 | fixed (round 3, bounded verification pending) |
| UX-07 | ux-reviewer | minor | residual | accepted — reviewer's closure | §3 token table | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| UX-22 | ux-reviewer | minor | residual | accepted — reviewer's closure | §3 token table | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| UX-26 | ux-reviewer | blocker | new | accepted; `derived_from` written at Inc 7, base-not-in-project wording (coordinator alignment) | LLR-168.4, LLR-178.1 | LED-2026-10-26-batch-100.16 | fixed (round 3, bounded verification pending) |
| UX-27 | ux-reviewer | major | new | accepted — reviewer's closure | LLR-167.8, LLR-174.1 | LED-2026-10-26-batch-100.17 | fixed (round 3, bounded verification pending) |
| UX-29 | ux-reviewer | major | new | accepted — reviewer's closure | LLR-176.1 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| UX-30 | ux-reviewer | major | new | accepted — reviewer's closure | HLR-176, LLR-176.1 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| UX-31 | ux-reviewer | major | new | accepted — reviewer's closure | LLR-178.3 | LED-2026-10-26-batch-100.16 | fixed (round 3, bounded verification pending) |
| UX-32 | ux-reviewer | major | new | accepted; AT-B100-21 reads the plan (declared exception, §3 preface) | HLR-175, LLR-175.4 | LED-2026-10-26-batch-100.15 | fixed (round 3, bounded verification pending) |
| UX-33 | ux-reviewer | major | new | accepted — reviewer's closure | LLR-175.4, LLR-167.6 | LED-2026-10-26-batch-100.15 | fixed (round 3, bounded verification pending) |
| UX-34 | ux-reviewer | major | new | accepted — reviewer's closure | HLR-177, LLR-177.1 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| UX-35 | ux-reviewer | major | new | accepted — reviewer's closure | HLR-164, §3 token table | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| UX-36 | ux-reviewer | major | new | accepted — reviewer's closure | LLR-173.6, LLR-173.4 | LED-2026-10-26-batch-100.18 | fixed (round 3, bounded verification pending) |
| UX-37 | ux-reviewer | minor | new | accepted — reviewer's closure | LLR-173.2 | LED-2026-10-26-batch-100.18 | fixed (round 3, bounded verification pending) |
| UX-38 | ux-reviewer | minor | new | accepted — reviewer's closure | LLR-178.2 | LED-2026-10-26-batch-100.16 | fixed (round 3, bounded verification pending) |
| UX-39 | ux-reviewer | minor | new | accepted — reviewer's closure | LLR-178.3 | LED-2026-10-26-batch-100.16 | fixed (round 3, bounded verification pending) |
| UX-40 | ux-reviewer | minor | new | accepted — reviewer's closure | LLR-178.1 | LED-2026-10-26-batch-100.16 | fixed (round 3, bounded verification pending) |
| UX-41 | ux-reviewer | minor | new | accepted — reviewer's closure | §3 token table, LLR-171.1 | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| QA-R2-01 | qa-reviewer | major | new | accepted (with B-01): the emit decision on data | LLR-167.1, LLR-167.2, §6.3 | LED-2026-10-26-batch-100.14 | fixed (round 3, bounded verification pending) |
| QA-R2-02 | qa-reviewer | major | new | accepted — reviewer's closure | LLR-174.1 | LED-2026-10-26-batch-100.17 | fixed (round 3, bounded verification pending) |
| QA-R2-03 | qa-reviewer | major | new | accepted — reviewer's closure | LLR-174.4 | LED-2026-10-26-batch-100.17 | fixed (round 3, bounded verification pending) |
| QA-R2-04 | qa-reviewer | major | new | accepted — reviewer's closure | HLR-168 (AT-B100-20) | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| QA-R2-05 | qa-reviewer | major | new | accepted; AT-B100-21 reads the plan (declared exception, §3 preface) | HLR-175, LLR-167.6, LLR-175.4 | LED-2026-10-26-batch-100.15 | fixed (round 3, bounded verification pending) |
| QA-R2-06 | qa-reviewer | major | new | accepted — reviewer's closure | LLR-173.2, §5.3 | LED-2026-10-26-batch-100.18 | fixed (round 3, bounded verification pending) |
| QA-R2-07 | qa-reviewer | minor | new | accepted — reviewer's closure | LLR-165.2 | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| QA-R2-08 | qa-reviewer | minor | new | accepted — reviewer's closure | LLR-172.2 | LED-2026-10-26-batch-100.21 | fixed (round 3, bounded verification pending) |
| QA-R2-09 | qa-reviewer | minor | new | accepted — reviewer's closure | HLR-169 (AT-B100-07), LLR-169.9 | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| QA-R2-10 | qa-reviewer | minor | new | accepted — reviewer's closure | HLR-163 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| QA-R2-11 | qa-reviewer | minor | new | accepted — reviewer's closure | §5.4 | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| QA-R2-12 | qa-reviewer | minor | new | accepted — reviewer's closure | HLR-177, HLR-176 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| QA-R2-13 | qa-reviewer | minor | new | accepted — reviewer's closure | LLR-164.3 | LED-2026-10-26-batch-100.22 | fixed (round 3, bounded verification pending) |
| QA-R2-14 | qa-reviewer | minor | new | closed by the orchestrator (PLAN) | PLAN (orchestrator, `322bbab`) | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| B-01 | architect | blocker | new | accepted — reviewer's closure | LLR-167.1, LLR-167.2, §6.3 | LED-2026-10-26-batch-100.14 | fixed (round 3, bounded verification pending) |
| B-02 | architect | major | new | accepted — reviewer's closure | LLR-174.4 | LED-2026-10-26-batch-100.17 | fixed (round 3, bounded verification pending) |
| B-03 | architect | major | new | accepted — reviewer's closure | LLR-169.8, §5.4 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| B-04 | architect | major | new | accepted — reviewer's closure | LLR-167.7, LLR-167.6 | LED-2026-10-26-batch-100.14 | fixed (round 3, bounded verification pending) |
| B-05 | architect | major | new | accepted — reviewer's closure | LLR-163.7 | LED-2026-10-26-batch-100.15 | fixed (round 3, bounded verification pending) |
| B-06 | architect | major | new | accepted — reviewer's closure | §5.3 (TC rows), ARQ §8.1 | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| B-07 | architect | major | new | accepted; the map rows are the architect's, referenced by name | §5.5; ARQ §8 and `docs/architecture.md` rows B100-I13..I22 (architect) | LED-2026-10-26-batch-100.23 | fixed (round 3, bounded verification pending) |
| B-08 | architect | minor | new | accepted — reviewer's closure | P-34 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| B-09 | architect | minor | new | accepted — reviewer's closure | HLR-163 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| B-10 | architect | minor | new | accepted — reviewer's closure | LLR-176.2 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| B-11 | architect | minor | new | accepted — reviewer's closure | HLR-176, LLR-176.1, LLR-178.2 | LED-2026-10-26-batch-100.19 | fixed (round 3, bounded verification pending) |
| B-12 | architect | minor | new | accepted — reviewer's closure | LLR-164.1, BACKLOG-CODE | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| B-13 | architect | minor | new | accepted — reviewer's closure | LLR-169.4 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |
| B-14 | architect | minor | new | accepted — reviewer's closure | LLR-163.6 | LED-2026-10-26-batch-100.20 | fixed (round 3, bounded verification pending) |

**Round 3 bounded verification pending:** each reviewer reads only the rows of its own open findings above and marks each closed or open. A new defect noticed there is recorded and goes to PDR as a condition unless it is a HIGH.

## Round 3 — bounded verification (operator decision after the P2 iteration cap)

Each reviewer checked only the closure of its own open findings against the contract at `4e9c8f1`.

| Reviewer | Record | Verdict | Open | Conditions carried to PDR (non-blocking) |
|---|---|---|---|---|
| ux-reviewer | `design/P2-ux-r3.md` | approve | 1 MINOR (UX-22) | UX-22 (LLR-171.2's refusal row is never painted); C-1 (the panel button label names `enter` while focus starts on the list); C-2 (where the per-open image digest runs, and its time budget) |
| architect | `design/P2-architect-r3.md` | approve | 0 | C-1..C-3 (the map rows B100-I15/I16/I22 take the contract's API forms); C-4 (`_handle_load_project`, the real method name); C-5 (Inc 10 is 4 files, so drop the brackets) |
| security-reviewer | `design/P2-security-r3.md` | approve | 0 | PDR-C1 (`write_project_manifest` calls `contained_in_workarea`, an 8th writer arm at Inc 8b); PDR-C2 (cap `assignments` in total and by key count); PDR-C3 (`%APPDATA%` roams — see the orchestrator ruling below) |
| qa-reviewer | `design/P2-qa-r3.md` | approve | 0 | PDR-QA-1 (`SaveProjectScreen.plan` is immutable, read after `alt+s`, compared by landing name and action); PDR-QA-2 (an `image_differs_from_source` pre-check may only lead to the data comparison, never decide "copy" by itself) |

**P2 verdict: approved.** No HIGH is open in any lens. Round 1 recorded 86 findings and round 2 recorded 58, all of them closed or carried as the PDR conditions above.

**Orchestrator ruling on PDR-C3:** the recent-sources store moves to `%LOCALAPPDATA%\s19_app\recent_sources.json`. This is not the roaming `%APPDATA%`. The operator's S-16 choice was "Por usuario … las rutas nunca viajan con el proyecto", and a roaming profile copies the paths to a domain profile server, against that intent. The change goes into the contract at PDR.

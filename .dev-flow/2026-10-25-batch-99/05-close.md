# Batch close — s19_app — Batch 2026-10-25-batch-99

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language — the **prose**,
> and never a label.

> **Owed in.** `core` ✓ · `full` —

> **Field guide:** `templates/guides/close-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Conditional-gate discharge` · `New controls` · `Human perimeter` · `Human review ledger` · `Gated tree` · `Found before the batch` · `⏸ DEFER`
> **And the §6 DEPTH tokens — cell VALUES rather than field names, reserved for the same reason:**
> `light` · `rigorous` · `spot-check` · `none` · `✅` · `❌`. A CLOSED set, declared closed by the first
> revision that ships it — so the vocabulary a later promotion of `V54` to BLOCK will need already exists,
> instead of being introduced over a free-text field that six authors have by then written six ways.
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

> **Notice convention.** `⚠` yellow = declare and continue · `✗` red = block · `✓` green = satisfied
> **with its citation**.

---

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `python "C:/Users/jjgh8/.claude/skills/dev-flow/scripts/devflow-validate.py" .` from the project root · exit 0 · 0 block · 891 notice · 2026-10-26 |
| Gated tree | `79d8810e4187d2cfe0f24aac862eb704d17790d0` · dirty — .dev-flow/BACKLOG-CODE.md, .dev-flow/BACKLOG-PROCESS.md (the close record itself excluded) |
| Requirements canon | `REQUIREMENTS.md` (`artifact_homes.requirements_canon` = `repo:REQUIREMENTS.md`) — `devflow-init.py --fold-canon` run at this close: `canon: REQUIREMENTS.md -- 51 folded, 0 kept, 0 refused` (HLR-152..HLR-162 and their 40 live LLRs); LLR-157.3 then added by hand with status `retired` at the closing validator run (V26 / V22, `PLAN.md` §Gate notices) |

**Close record for a `full` batch.** This project closes `full` batches with `05-close.md`, as batch-97 did. The post-mortem content a `full` close owes is in `05-postmortem.md` (architect + qa-reviewer), and `06-docs/` holds the P6 documents.

---

## 1 · What changed

**BLUF.** Every image, report and run record the tool writes now says what was and was not applied, and a loaded image holds only what its file declares. The S0 header is no longer image data. A flow PATCH that skips entries reports an error, and WRITE-OUT writes nothing after it. Parallel lanes cannot overwrite each other's output. Patch Editor undo reverts the image. A2L values encode and decode in the byte order and RAT_FUNC direction the A2L declares. COMPU_TAB refuses values outside the table. A CRC over an empty region is refused. Truncated S19/HEX images are reported. Exports stay inside their destination. Run records list their refusals. The Bytes field reads hex only. Save-back keeps the work copy, and the project pickers load by name. A generated synthetic corpus, with an independent reader as the oracle, backs the byte comparisons.

**Mechanism.** One S0 predicate feeds every walk. Every write goes through private staging plus atomic placement, which reuses a byte-identical file and suffixes different content. `ChangeService` keeps a journal, so the image equals the source plus the document. `ChainRunOutcome` and both reports carry the dispositions. The loaders return five issue codes. The A2L codec reads `MOD_COMMON BYTE_ORDER` and the ASAM RAT_FUNC rule. One sanitiser builds export names.

| Requirement | Version | Verified by | Verdict |
|---|---|---|---|
| HLR-152 (synthetic corpus + independent reader) | v1 — first canon row, batch-99 | AT-B99-01 · TC-B99-01..03 (with the `-03b` arm) | pass (`04-validation.md` Layer A / B) |
| HLR-153 (S0 is not image data) | v1 | AT-B99-02 · TC-B99-04..07 | pass |
| HLR-154 (truncated / inconsistent images reported) | v1 | AT-B99-03 · TC-B99-08..10 | pass |
| HLR-155 (own staging, atomic placement, D7, D9, CRC staging) | v1 | AT-B99-04, -05 · TC-B99-11..16, -38, -39, -44 | pass |
| HLR-156 (PATCH status + run records name what was not applied) | v1 | AT-B99-06, -07 · TC-B99-17..20 | pass |
| HLR-157 (Patch Editor image = source + document) | v1 | AT-B99-08 · TC-B99-21, -22, -40 | pass |
| HLR-158 (A2L encode/decode as declared) | v1 | AT-B99-09, -14 · TC-B99-23..25, -42, -43 | pass |
| HLR-159 (no CRC over an empty region) | v1 | AT-B99-10 · TC-B99-26, -27 | pass |
| HLR-160 (exports contained, no invented byte) | v1 | AT-B99-11 · TC-B99-28..31, -41 | pass |
| HLR-161 (Bytes field reads hex) | v1 — amends batch-07 LLR-001.2 | AT-B99-12 · TC-B99-32, -33 | pass |
| HLR-162 (pickers load by name) | v1 | AT-B99-13 · TC-B99-34..36 | pass |

The per-LLR rows (40 live; LLR-157.3 retired at LED .2) are in `04-validation.md` Layer A and in `06-docs/traceability-matrix.md`.

**Visible behaviour change.** In the shipped examples, case_06 now decodes 71,513 of 220,040 tags big-endian, because its `MOD_COMMON BYTE_ORDER` is now read. In software_a, 1,640 of 13,990 RAT_FUNC tags now decode in the ASAM direction (`evidence/inc-10/example-impact.txt`).

**What worked, what didn't, root causes:** `05-postmortem.md` (synthesis first, then the architect and qa-reviewer halves).

---

## 2 · New controls discovered — and where they landed (C-45)

| Control | What failure it closes | Measured origin |
|---|---|---|
| *(candidate, not minted)* whole-tree guards (import census, snapshot cells, id registry, address census, freeze guards) run at every increment gate | stale whole-tree pins that only the full suite reaches | batch-99 Increment 013: TC-653 stale after Inc-6, TC-016s cell stale after Inc-11 (`evidence/suite-triage-e7732f6.md`). The same candidate was raised at batch-97 §2, so this is the second batch it would have caught a defect in |
| *(candidate, not minted)* mechanical AT shape check at the increment gate (one node per AT, no private access) | ATs realised in parts or through private calls | DDR DQ-1..DQ-4, Inc-8 F2, Inc-10 F2, P4 G-006 |
| *(candidate, not minted)* a flake verdict cites an on-disk standalone and base-tree re-run | flake verdicts resting on output that was never saved | P4 G-004 |

**The four landings — record which ones actually happened. Command-but-not-template is *half-encoded*, and the missing half is the enforceable one:**

| # | Landing | Done? | SHA / path |
|---|---|---|---|
| 1 | the **command** (`commands/…`) — the rule itself | n/a — no control minted | |
| 2 | its **artifact** (a template section) — a control with no output degrades to "I thought about it" | n/a — no control minted | |
| 3 | the **catalog** entry (`dev-flow-lessons`) with its measured origin | n/a — no control minted | |
| 4 | **committed and pushed**, manifest re-hashed and bumped | n/a — no control minted | |

- **New controls:** `none — no control minted at this close: encoding is the operator's control-encode sitting; three candidates are proposed above with their measured origins and filed in .dev-flow/BACKLOG-PROCESS.md §Registered by batch-99's close`

---

## 3 · Working-file reconciliation (C-44)

Sweep run 2026-10-26: `git status --short` and `git log main --not --remotes` in `C:\Users\jjgh8\Github\s19_app`, the only repository the batch touched. The flow bundle and the Kimi config were read, not edited.

| File | State | Evidence |
|---|---|---|
| `s19_app/**`, `tests/**` | ✅ committed **and landed** — pushed to `main` at each increment close (no PR, the standing authorization's Git answer) | `a52e2be` · `c62c842` · `5021bb6` · `9d7fb18` · `725d474` · `c58b02d` · `f1ba70c` · `7ffad92` · `d62b0c1` · `4ee51a6` · `87dcd3a` · `e7732f6` · `c1d088a` · `1a59d3b` |
| `.dev-flow/2026-10-25-batch-99/**` (contract, ledger, review, PDR, DDR, packets, evidence, validation, post-mortem) and `docs/architecture.md` | ✅ committed **and landed** on `main` | through `bf3917d`, then the deliverable commit of this close |
| `REQUIREMENTS.md` (canon fold), `.dev-flow/state.json`, `04-validation.md` (confirmation line), `06-docs/**` | ✅ committed in the deliverable commit of this close, pushed to `main` | the `Gated tree` row above |
| `.dev-flow/BACKLOG-CODE.md`, `.dev-flow/BACKLOG-PROCESS.md` (carries) | ✅ committed in the close commit with this record, pushed to `main` | §4 |
| worktree `C:\Users\jjgh8\Github\s19_app-b99-suite` | 🗑️ removed after the confirmation run | the full-suite worktree; every increment worktree was removed at its merge |
| `prototypes/` | 📋 left on purpose — untracked, never staged by rule | — |

- **Found before the batch:** `none — no tracked file was modified when the batch began`

### Conditional-gate discharge

- **Conditional-gate discharge:** `all discharged — the PDR conditions were re-read at the DDR, and the DDR conditions DDR-A1..A3, C-DDR-SD-1 = DQ-1, the ledger counts and DQ-2..DQ-7 were each discharged and re-checked by the reviewer who raised them`

| Condition | Discharged? | The artifact line that proves it |
|---|---|---|
| PDR conditions (C1..C7, PQ-1..PQ-6, UX-C1..C7) | ✅ | `design/DDR-2026-10-25-batch-99.md` and the three `design/DDR-*.md` reviewer files |
| DDR-A1..A3, C-DDR-SD-1 = DQ-1, ledger counts, DQ-2..DQ-7 | ✅ all | `design/DDR-2026-10-25-batch-99.md` §Conditions — discharged (commits `bab3bff`, `c1d088a`; `LED-2026-10-25-batch-99.8`; `evidence/ddr/`) |

---

## 4 · Backlog reconciliation — the carry-over contract

| Item | Move | Reference |
|---|---|---|
| H-1..H-10 (read/write investigation) | ✅ marked DONE in place, each with its increment and commit | `.dev-flow/BACKLOG-CODE.md` §*Routed 2026-10-23 — read/write integrity investigation* |
| CW-U-4 = CW-D-4, CW-D-10, CW-D-7, CW-U-1 deeper tests + sibling, CW-U-3 | ✅ marked DONE in place | §*Routed 2026-10-23 — Code-Wire audits* |
| Code-Wire pilot H-7 (`MOD_COMMON BYTE_ORDER`) | ✅ marked DONE in place (Inc-10) | §*Routed 2026-10-19 — Code-Wire pilot findings* |
| R-006, R-013 (oracle half), M-4 | ✅ marked DONE in place | §*Reconciled 2026-10-23* and the close block |
| G-005 tc018 / at031b: dedup suffix against byte-identical reuse | carried as an operator DECISION | §*Routed 2026-10-26 — batch-99 (read/write integrity) close* |
| G-002, G-003, G-006; DDR LOWs (group placement duplicated, not-applied listed twice, project-less save-back); D-3 / F-2 / F-3; D-5 | carried forward | same section |
| Increment review carries (Inc-3a, 3b, 4, 5, 6, 7, 9, 10, 11), P2 out-of-scope items, the flake and test-race items | already routed at their gates | §*Routed 2026-10-25 — batch-99 Phase-2 out-of-scope findings* (grown through P3/P4) |
| Process carries (whole-tree guards, AT shape check, flake transcript, A4 re-record + registry by glob, P2 executes tokens, iteration counter, validator at every gate — the closing run's 99 record BLOCKs, repaired to 0 at this gate, `PLAN.md` §Gate notices) | carried forward | `.dev-flow/BACKLOG-PROCESS.md` §*Registered by batch-99's close* |
| Header | refreshed: last refresh 2026-10-26, batch-99 close | `.dev-flow/BACKLOG-CODE.md` header |

---

## 5 · Batch metrics — the 13 keys of `core`

Extract, do not invent: a key the artifacts did not record goes `null`, and the key is never dropped.

```yaml
type: dev-flow-batch
project: s19_app
batch_id: 2026-10-25-batch-99
mode: full
verdict: pass
increments: 14
source_files_max: 4
notices_raised: 19
rework_returns: 17
triggers_fired: "A2,A3,A4,B1,B3,B4,C6,C8,D1,E1,E2"
tests_base_to_post: "3634 -> 3773"
new_control: none
open_items_next: 34
```

- `verdict: pass` — P4 `PASS-WITH-NOTES` (`04-validation.md`), no HIGH; DDR approved.
- `increments: 14` — 001–011, 003b, 012 (DDR test fixes), 013 (P4 suite fixes); 012 and 013 change tests only.
- `source_files_max: 4` — Inc-3a and Inc-9; no cap trip.
- `notices_raised: 19` — distinct NOTICE ids declared in `PLAN.md` §*Gate notices and runtime absences* (P0 gate); the close run's notices are declared on the `Gate record` row.
- `rework_returns: 17` — 2 P1 amendments after P2, 14 extra P3 review rounds across 11 increments, and 1 P4 return (Increment 013) (`design/P5-qa.md` §8).
- `triggers_fired` — A4 added at P5: the implementation ran in parallel worktrees (`05-postmortem.md` §Record corrections).
- `tests_base_to_post` — collected nodes: base 3634 (`a293213`: 11 F / 3617 P / 3 s / 3 xf) → 3776 at the gate run (`e7732f6`) → 3773 on the final tree (Increment 012 merges).
- `open_items_next: 34` — open `▸` rows of batch-99 origin in `.dev-flow/BACKLOG-CODE.md` (27) plus `.dev-flow/BACKLOG-PROCESS.md` (7).
- Iterations per station, counted from the record (the `iterations_per_station` counter only counts `--iterate-to` moves): P1 2 · P2 2 rounds (+ round 3 scoped) · P3 14 extra review rounds · P4 1. `state.json` shows P1 2 and 0 elsewhere.
- Findings: P2 75 · P3 gate ≈99 (15 HIGH, all fixed before merge) · P4 12 (10 validation gaps, all minor, + 2 stale pins) (`design/P5-qa.md` §2); pct caught at P2 = 40.3 %.
- **Declared NOT done:** evaluation with real users on the operator's own data; a CI run on Python 3.12 (CI runs 3.11 only; backlog); the surface arms of G-002.

---

## 6 · Human review ledger — what a human audited, at what depth

| Artifact | Machine verdict (citation) | Human review | Depth | Deliberately NOT reviewed |
|---|---|---|---|---|
| Decision page `design/plan-b99.html` (D1–D10) | P2 approved (`02-review.md`) | ✅ | `light` | the options not chosen; all ten answers took the recommended option (`design/veredicto-b99.json`) |
| `01-requirements.md` contract | P2 approved, 3 rounds | ❌ | `none — the operator answered the decisions on the page instead` | the contract text |
| Increment packets and code | reviewer verdicts in each packet §4b | ❌ | `none — read the status summaries in chat instead` | not audited line by line |
| `04-validation.md`, `05-postmortem.md`, `05-close.md`, DDR | qa-reviewer PASS-WITH-NOTES; DDR approved | ❌ | `none — written at the close; the operator reviews them at the close packet` | |

- **Human perimeter:** what to build and in what order; whether the visible decode changes in case_06 and software_a match the operator's real tools and data; the G-005 ruling on duplicate-name saves; release communication to users.
- **Human review ledger:** `human:operator — 1 artifact(s) reviewed, 0 rigorous · 3 declared not-reviewed` (depths read off the decision records by the close writer; the operator corrects them if they differ)

# Traceability Matrix — s19_app — Batch 2026-10-11-batch-92

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches **translate the prose, never a label**. This document mints no field a rule keys on — its ids (`US-`/`HLR-`/`LLR-`/`AT-`/`TC-`/`R-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block; what it must not do is order the translation of somebody else's.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row. ⚠ **This template is seeded by a BULLET under that table rather than by a row**, because `06-docs/` exists only in `full` — the same fact `V39`'s `_V39_OWED_IN["P6"]` carries.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| `<one row per LLR, from its story to the file:line that implements it>` | | | | | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| *(example)* US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| *(example)* US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| *(example)* US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |
```

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. A story with a complete functional chain but no behavioral row is INCOMPLETE.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| `<one row per user story>` | | | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* US-001 | AT-001 | `<handler/screen/CLI>` | `<outcome / file:path>` | pass |
```

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `<N>` |
| Covered user stories | `<N>` (`<%>`) |
| Total HLR | `<N>` |
| Implemented HLR | `<N>` (`<%>`) |
| Total LLR | `<N>` |
| Implemented LLR | `<N>` (`<%>`) |
| Test cases | `<N>` |
| TC pass | `<N>` |
| TC fail | `<N>` |
| TC pending | `<N>` |

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or TCs without code mapping.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| `<one row per gap, or none — no gap>` | | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| *(example)* G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |
```

---

## 4. Changes from previous batch

*(If applicable — what was added, modified, or closed since the previous batch.)*

| Type | Item | Detail |
|------|------|--------|
| `<one row per item added, modified or closed>` | | |

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a trace nobody made. Write your own rows in the table above.

```text
| *(example)* new | HLR-007 | Added in this batch |
| *(example)* modified | LLR-002.1 | Statement adjusted per review finding |
| *(example)* closed | G-003 (previous batch) | Resolved in TC-008 |
```

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- `<one line per user story: US → HLR → LLR → TC>`

### 5.2 By code file
- `<one line per touched file: file → LLR → TC>`

**Worked examples of both maps — text to read, never lines of your record:**

```text
- *(example)* **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003
- *(example)* `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- *(example)* `src/bar.ts` → LLR-002.1 → TC-003
```

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-10-11-batch-92` |
| Closing date | `2026-10-11` |
| Total iterations (sum of phases) | `<N>` |
| Validation passed | yes / no |
| Synced to Obsidian | yes / no |

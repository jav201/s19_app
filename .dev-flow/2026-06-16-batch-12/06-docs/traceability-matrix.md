# Traceability Matrix — s19_app — Batch 2026-06-16-batch-12

> **Artifact language:** canonical English scaffold. Generate the artifact in the batch's development language (`state.json` `language`); for Spanish batches translate headers and labels.

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Every row must be complete when closing the batch (phase 6). Incomplete rows = coverage gaps and must be listed in the gaps section.

---

## 1. Master table

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-001 | HLR-001 | LLR-001.1 | TC-001 | `src/foo.ts:42` | pass | |
| US-001 | HLR-001 | LLR-001.2 | TC-002 | `src/foo.ts:78` | pass | |
| US-001 | HLR-002 | LLR-002.1 | TC-003 | `src/bar.ts:15` | pass | |
| US-002 | HLR-003 | LLR-003.1 | TC-004 | `src/baz.ts:90` | fail | See gap G-001 |

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
| G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
| G-002 | no coverage | LLR-005.2 has no associated TC | Move to next batch |

---

## 4. Changes from previous batch

*(If applicable — what was added, modified, or closed since the previous batch.)*

| Type | Item | Detail |
|------|------|--------|
| new | HLR-007 | Added in this batch |
| modified | LLR-002.1 | Statement adjusted per review finding |
| closed | G-003 (previous batch) | Resolved in TC-008 |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-001** → HLR-001, HLR-002 → LLR-001.1, LLR-001.2, LLR-002.1 → TC-001, TC-002, TC-003

### 5.2 By code file
- `src/foo.ts` → LLR-001.1, LLR-001.2 → TC-001, TC-002
- `src/bar.ts` → LLR-002.1 → TC-003

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-16-batch-12` |
| Closing date | `<YYYY-MM-DD>` |
| Total iterations (sum of phases) | `<N>` |
| Validation passed | yes / no |
| Synced to Obsidian | yes / no |

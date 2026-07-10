# PLAN — batch-32 · CRC multi-region single-CRC groups (B-21, P1)

> Living compendium. Updated at every gate + significant checkpoint.

## Where we are
- **Phase 2 (Cross-review) — in progress.** Phase-1 approved under standing auth 2026-07-09: 01-requirements.md locked with the QA fold applied — 20 ATs (AT-045f duplicate-span S-2 owner; AT-047e Layer-B handler AT; AT-047f S-6 pristine-compute owner; AT-047c split own/cross → AT-047g; AT-044b value round-trip; AT-044d/046b parametrized; AT-045d counterfactual corrected to RED-first; AT-044a gapped-legacy fixture condition). Validation strategy §11 (methods, C-12 binding spec, N1-N6/B1-B14 inventory, ledger base 49 CRC / 1191 total, output-bytes naming guard). Architect + qa + security reviewers dispatched in parallel on the locked artifact.

## Objective
Operator-declared **groups** of disjoint memory regions → concatenated in **declared order** → **one** CRC → **one** `output_address` with configurable `output_bytes` {1,2,4,8} LE (default 4). Legacy per-region configs parse + behave byte-identically. 0 engine-frozen modules.

## RC-1 (base currency)
- Branch `feat/batch-32-crc-groups` cut from `origin/main` tip **`551fc77`** (2026-07-09, post #58/#59), clean tree. Verified via `git fetch` + checkout this session.
- Already-shipped check: `crc_config.py` `CrcConfig` = flat per-region list, per-region `output_address`; `LE32_WIDTH = 4` fixed codec (crc.py:48); no `R-CRC-GROUP/WIDTH` rows in REQUIREMENTS.md → all stories net-new.

## Stories (Phase-0: all READY)
| US | What | Status |
|----|------|--------|
| US-044 | `groups` schema + backward compat (legacy `regions` untouched) | READY |
| US-045 | Single-CRC group semantics (declared-order concat, one non-resetting state) | READY |
| US-046 | Configurable output width {1,2,4,8} LE, default 4 | READY |
| US-047 | Check/inject/report surface for groups (verdicts, notes, JSON, C-12 re-read) | READY |

## Key decisions
- **Schema Option A**: new top-level `groups` key beside legacy `regions` (structural backward compat; one-error-string contract preserved; best raw-JSON-TextArea ergonomics; reversible). Option B (unified shape-sniffed list) rejected; A′ (`crc_groups` name) folded into A.
- **Operator-question defaults adopted under standing auth** (overridable → §6.5 amendment): (Q1) gaps = present-bytes-only CRC + mandatory group coverage warning; (Q2) widths {1,2,4,8}, <4 truncate-low + warning; (Q3) mixed results = legacy regions first (file order), then groups; (Q4) legacy regions stay silent on gaps.
- Normalization: legacy regions become single-span groups (width 4) internally → one evaluation loop; legacy results keep first positions.
- Computes-before-writes pipeline preserved (S-6); overlap = warn-never-block (S-7 — the committed dummy config is self-referential today).

## Roadmap / increment sketch (firm at Phase-3 entry)
1. Inc-1: `crc_config.py` schema (`CrcGroup`, `groups` parse, at-least-one rule) + parser tests.
2. Inc-2: `crc.py` group compute + width codec (`encode_le`/`decode_le`; `encode_le32/decode_le32` stay as wrappers) + oracle tests (AT-045a/b/e RED-first).
3. Inc-3: check/inject/result-model (`CrcRegionResult.output_bytes=4` defaulted) + AT-046/047 chains incl. the C-12 write→re-read node.
4. Inc-4: `DUMMY_CONFIG_TEXT` + example file + TUI notes surface + AT-044e; snapshot-drift check.

## Risks / watch-items
- RK-1 gap divergence vs device tools (mitigated: mandatory coverage warning; residual RK-7).
- RK-4 snapshot drift from `DUMMY_CONFIG_TEXT` pre-fill → canonical-CI regen only.
- RK-5 result-model ripple → defaulted field + AT-044a suite-unmodified pin.
- C-18: every §3/§5 AT-NNN must land as exactly ONE on-disk node (checked per increment + Phase 4).

## Conventions honored
Engine-frozen 0-diff; docstring sections (Summary→…→Example); type hints; ≤5 files/inc; RED-first counterfactuals; test ledger `post = base − D + A`; inline-paste at gates (worktree-not-editor-root).

## Test ledger
- Base (main 551fc77): 1196 collected (1183 + batch-31's 13). CRC-file base: pending qa count.

## Decision log (mirror)
- 2026-07-09 P0 approved (standing auth): 4 stories READY; RC-1 PASS @ 551fc77; Q1–Q4 defaulted, overridable.

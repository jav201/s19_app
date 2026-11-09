# CLOSE-REPAIR notes — batch-101 close-stage validator blocks

Run: `devflow-validate.py --brief .` from the worktree root. Starting state: **218 `[x]`**
(65 × V22, 153 × V59). Ending state: **57 `[x]`** (all V22, declared below as not
clearable within the brief's constraints). V59 → 0, V20 → 0 (atlas regenerated).

## V22 — 65 entries → 9 cleared, 56 + 1 exposed

**Cleared (9 `DUP` blocks, one id declared as a heading more than once).** Turned each
later declaring heading into a non-declaring heading (`### Rows of <id> — …`), keeping the
first user-story block (the one with the statement). No requirement text, id or table row
was changed.

- `inc-16/01-requirements.md` — 4 headings renamed (US-DOC-HYG-1 ×1, US-DOC-HYG-2 ×2,
  US-DOC-HYG-3 ×1).
- `inc-14/01-requirements.md` — 6 headings renamed (US-HELP-1, US-LEGEND-1, US-README-1,
  US-SEC-1, US-REL-1, US-GUIDE-1, one each).

**One id promoted, not changed.** `inc-1/01-requirements.md` — `**US-101.1**` (bold) became
a `### US-101.1 — …` heading, matching the `### US-*` heading convention every other
increment uses, so increment-001's §2 `Traces to` cells resolve. This correctly exposes
US-101.1 as an id the canon does not yet mirror (it joins the MISSING set below).

## V59 — 153 entries → 153 cleared

Every listed file now carries a §2 "Files modified" row in the packet of the increment whose
commit added/changed/deleted it. The rule's packet reader accepts only `increment-<digits>.md`
(`_V60_PACKET = increment-\d+\.md$`), so the two split-increment packets `increment-010b.md`
and `increment-012b.md` are **not read**; their files were listed in the readable siblings
instead, with a note naming the split.

- `increment-001.md` — 108 rows added (replaced the prose §2): 27 Inc 1 canon files
  (`.gitattributes`, `docs/requirements/history/*`, 19 `docs/requirements/review/*`,
  3 `tools/*`, 3 `tests/*`), 64 batch-level/operator files (`.gitignore`, 61 `prototypes/*`
  deleted, 2 redaction files), and 17 files brought in by the rebase (batch-102 hot-fixes
  merged to main after `base_ref`; each row's Change cell says so).
- `increment-016.md` — 33 rows: the single `.fast-dev-flow/` folder row replaced by one row
  per deleted file (the rule's `_v59_norm` matches exact paths, so a folder row clears
  nothing).
- `increment-002.md` — 1 row: `tests/test_flow_report_service.py` (Inc 2 CI redaction fix).
- `increment-010.md` — 1 row: `tests/test_b101_inplace_views.py` (Inc 10b file).
- `increment-012.md` — 10 rows: the Inc 12b test files.

## V20 — 4 entries → 4 cleared

`--atlas --write .` regenerated `.dev-flow/_derived/ATLAS-{BATCHES,IFC,ORPHANS,TRACE}.md`
after the record edits; V20 back to green.

## Not clearable within the brief (57 blocks, all V22)

- **55 `MISSING`** (54 increment user-story ids + US-101.1, exposed by the promotion): the
  rule's fix is the requirements-canon fold-back (`devflow-init.py --fold-canon` writes the
  id into `REQUIREMENTS.md`). The batch's own `05-close.md` DEFERs that fold to the
  requirements re-write session (`close/FORWARD-requirements-session.md`, 273 rows); the
  brief's "records only — no product, test or doc file" keeps `REQUIREMENTS.md` out of scope.
  `--fold-canon` was already run and folded 0 (it reads only the batch-level template, whose
  two headings are the phantoms below).
- **2 `TPLTEXT`** (`HLR-001`, `LLR-001.1`): the shipped template example headings of the
  batch-level `01-requirements.md`. Their rule-sanctioned fixes — write a Statement, or
  delete the example block — are both out of bounds here: a Statement would change
  requirement text the brief forbids, and deleting `LLR-001.1` breaks `V10` (it is the owner
  every IFC FLOW node names in that skeleton).

## Superseded — the canon fold (orchestrator ruling, 2026-11-07) clears the last 57 V22 blocks

The "Not clearable within the brief" section above is SUPERSEDED. The operator ruled the
canon fold in-scope for this close, and it is now done:

1. **The batch-level `01-requirements.md` body was rewritten as the batch's requirement
   index** (header/notice lines and reserved field names kept). `HLR-001` now carries the
   batch objective from `PLAN.md` §Objective as a one-`shall` EARS Statement; `LLR-001.1`
   now carries a Statement that is true and verifiable on the final tree
   (`tests/test_b101_help_legend_docs.py::_FIXED`); and one block per user story the
   increments declare (the 55 `### US-…` headings across `inc-*/01-requirements.md`, plus
   `US-101.1`) names its Statement verbatim and its increment file.
2. **`devflow-init.py --fold-canon --root .`** appended the 55 US ids the canon lacked to
   `REQUIREMENTS.md` (a new `| Id | Statement | Owning batch | Status |` table at the file
   end) and KEPT `HLR-001`/`LLR-001.1` (already canon rows). Fold line:
   `canon: REQUIREMENTS.md -- 55 folded, 2 kept, 0 refused`.
3. **No id is declared twice.** V22's rule source shows the batch-level index heading PLUS
   the increment's own `### US-…` heading counts as TWO declarations (both readers use the
   `^#{2,5}\s+<id>` grammar). The fold reader reads ONLY the batch-level file and the SAME
   grammar, so there is no heading form the fold reads that V22 reads as a reference — the
   fold must run while the index blocks declare the id, and the index blocks are then
   converted to non-declaring references. Applied: each index heading `### US-… — title`
   became `### Rows of US-… — title` (the same non-declaring form used to clear the 9 DUPs
   above), keeping its `**Statement:**` and `**Increment:**` lines; the increments keep
   their own declarations.
4. **`devflow-validate.py --atlas --write .`** regenerated the four ATLAS files once at the
   end.

Final gate: `devflow-validate.py --brief .` reports **0 block** (V22 0, V26 0, V59 0,
V20 0).

# Requirements ledger — s19_app — Batch 2026-10-26-batch-100

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._

### LED-2026-10-26-batch-100.1 — Phase-1 derivation: D1–D7, rulings O-1 to O-11, the G-005 answer, the R-TUI-012 amendment and the variant-slot policy
- **Requirement:** HLR-163, HLR-164, HLR-167, HLR-168, HLR-169, HLR-170, HLR-171, HLR-173, HLR-174, HLR-175, HLR-177, HLR-178
- **Requirement:** LLR-163.3, LLR-163.4, LLR-164.2, LLR-167.2, LLR-167.4, LLR-168.2, LLR-168.3, LLR-169.2, LLR-169.6, LLR-169.7, LLR-170.2, LLR-171.1, LLR-171.2, LLR-171.3, LLR-174.1, LLR-175.2, LLR-177.1
- **Date:** 2026-10-26
- **What changed:** the live contract was written from the seeded template. The requirements above say what they say because of an operator decision, an orchestrator ruling or a requirement change that this entry records. Body first: every line the table names already exists in `01-requirements.md`.

| Decision | What it put in the contract | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| Kickoff G-005 = "reuse + re-pin tests" | identical bytes reuse any `<name>` or `<stem>_<N>`; TC-018 and AT-031b re-pinned as two pairs each; the one ripple re-pin (P-22) | HLR-163: the re-pins are its test expectations, no change | HLR-163 Statement; LLR-163.3; LLR-163.4 |
| O-9 | a clash with a project other than the open one is refused with a notice; the open project updates in place | HLR-164 clause (a) carries it | HLR-164 Statement; LLR-164.2 |
| D1 = `imagen`; O-5; O-6 | Save project emits the in-memory image through `save_patched` at 32 bytes per line with the source S0, with no prompt; a blocked re-derive refuses the whole save | HLR-167 carries all three | HLR-167 Statement; LLR-167.2; LLR-167.4 |
| D2 = `ultima`; O-1; O-10 | the save-back becomes `active_variant`; every in-project writer rewrites the manifest through the seam; `current_file.path` keeps the source | HLR-168 carries all three | HLR-168 Statement; LLR-168.2; LLR-168.3 |
| D3 = `abre_y_reporta`; O-2; O-11 | `files` digests over the top-level data and A2L files and the active document only; Load opens what is valid and lists every problem; private manifest staging | HLR-169 carries all three | HLR-169 Statement; LLR-169.2; LLR-169.6; LLR-169.7 |
| D4 = `reabrir` | the active document, pasted or file-backed, is placed in `patches/`, recorded and reopened | HLR-170 | HLR-170 Statement; LLR-170.2 |
| D5 = `copiar` with O-4; D6 = `abrir`; D7 = `solo_workarea` | save-as copies every sub-folder; an A2L-only project opens; the parent must be the app's work area (the handler half), and the dialog has no parent field (the dialog half, HLR-175) | HLR-171 and HLR-175 | HLR-171 Statement; LLR-171.1; LLR-171.2; LLR-171.3; HLR-175 Statement; LLR-175.2 |
| O-3 | the unsaved-work question also fires for unsaved Flow Builder edits | HLR-174 | HLR-174 Statement; LLR-174.1 (the 16-cell table) |
| O-7 | Inc 12b moves project load, Save project and the A2L parse to workers; flow runs stay; conditional on the P-D verdict | HLR-177 | HLR-177 Statement; LLR-177.1 |
| O-8 and the D2 note | the Load-result announcement is its own story, US-168, and its own HLR, HLR-178 | HLR-178 | HLR-178 Statement and its Variant slots line |
| Commission: the UI stories stay REFINE until the prototype round | HLR-173, HLR-174, HLR-175, HLR-177 and HLR-178 state the clauses that hold in any variant; each variant-specific clause is a named slot that the verdict on its surface fills by a new entry in this ledger before the increment opens. HLR-176 carries slots VS-PD-1 and VS-PD-2 but no ruling, so it pairs with no entry yet | each REFINE HLR | the `Variant slots` line of each of the six UI HLRs |

- **Requirement change — R-TUI-012 is amended to agree with LLR-015.3.** Before (`REQUIREMENTS.md:1244-1245`): "Saving a project must copy the loaded file into a workarea subfolder named by a sanitized project name." After (written into the canon at the batch's documentation station, not by P1): "Saving a project must place the image the session holds into a workarea subfolder named by a sanitized project name: an image that differs from its source file is emitted through the verified emitter (`ChangeService.save_patched`, 32 bytes per line, source S0 preserved); an unchanged image, its MAC and its A2L are copied byte for byte." The conflict: R-TUI-012 says copy, while LLR-015.3 (`2026-06-23-batch-14/01-requirements.md:222`) routes the project save flow through the emitter, and its TC-220 drives `ChangeService.save_patched` (`tests/test_changes_apply.py:926-929`). The copy is what drops the patch (PH-1). D1 resolved the conflict in LLR-015.3's favour. Deleted tokens: "copy the loaded file". New tokens: "place the image the session holds", "emitted through the verified emitter". Re-derived verification: HLR-167, LLR-167.2, TC-B100-15, AT-B100-05. R-TUI-012's own node, `test_save_project_creates_project_folder_on_disk` (an unpatched session), is expected to stay green. Assumption, listed as Q-7 in the contract's §6.3: LLR-015.3's width-selector clause is met by the service argument TC-220 drives, and O-5 adds no prompt to Save project.
- **Why:** the operator's verdict of 2026-10-26 (`design/veredicto-b100.json`: D1–D7 all on the recommended option, plus the D2 note), the kickoff answers (PLAN header), and the orchestrator rulings O-1 to O-11, taken under the standing authorization (`design/ARQ-batch-100.md` §10.1). Questions that no document settles are listed in the contract's §6.3 (Q-1 to Q-7) and are not decided here.
- **Evidence:** `evidence/p0-premises/` (premises P-1 to P-21, executed on a `git archive` of `1d677ba`); the draft-time probes of P-22 to P-29 (their commands are in §2.7). Security pattern scan: `python -I ~/.claude/skills/dev-flow/scripts/devflow-scan-spec.py <abs>/01-requirements.md` → 5 control rows ok; flags `session`, `permission`, `hash`, `form`, `escape`, `expose`; `security_required: true`; exit 1. Each flag is answered in §6.3.

# Inc 14 — E3 rulings, round 1 (orchestrator, 2026-11-05)

Inputs: E3-architect.md (FAIL: A-1…A-6 MAJOR, A-7…A-19 MINOR), E3-security.md (PASS-WITH-NOTES: S-1 MEDIUM, S-2…S-5 LOW, S-6…S-8 INFO). Round 2 re-checks A-1…A-6 and S-1 only.

| Id | Ruling |
|---|---|
| A-1 | The escaping claim is limited to names: "names carry a backslash before Markdown marks; paths stay as written inside their code spans". R-DOC-RELNOTE.5 → "… of a name"; guide /11 and CHANGELOG (c) follow. |
| A-2 | README block (5) is reworded to what the code does (Write .chk.json writes to the common `workarea/patches/`; the Open checks/ chip opens the project's `checks/`). The product split goes to BACKLOG as an Inc 5 / Inc 6 interface. |
| A-3 | `test_tc707_numbering_generated_sequential` re-body asserts each paragraph equals `f"{n}. {step}"`, that no stored step starts with a number, and the step count of all 12 sections; its negative control is a stored step starting with a number → RED. |
| A-4 | K(w) is the set of keys active with window w shown (honouring `check_action` and window-local bindings); negative control: "`,` in a Checks step → RED". |
| A-5 | AT-285's inherited keys come from `S19TuiApp._merged_bindings`; `ctrl+p` counts only while the command palette is enabled; a monkeypatch negative control (palette disabled → a README `Ctrl+P` row is RED). |
| A-6 + S-1 | Private vulnerability reporting enabled (`gh api … {"enabled":true}`) is a **merge precondition for SECURITY.md**, checked at E5 with the transcript as evidence. If the setting is still off at merge, SECURITY.md is held out of the merge (the rest of Inc 14 merges) and re-checked at the batch end; no public-issue fallback text. Enabling the setting is the operator's action; the orchestrator has asked. |
| A-7, A-8, A-9 | Reports step 4 reworded (the box shows the lines of the last Generate) with a case for that state; Workspace step 5 names `.s19tool\templates\` for CRC templates; CRC step 3 says "end excluded". |
| A-10, A-18 | README row 1 lists `^p palette`; the Workarea table lists `filters/`. |
| A-11, A-12 | README sentences that open increments will change (F-45 chain-set report, Inc 9; "recomputes after each edit", Inc 13) are written to the shipped behaviour of this branch's base and listed as interfaces I-x that the owning increment updates when it merges. |
| A-13, A-14 + S-2, S-3 | CHANGELOG: drop the HTML-pane overclaim; add the merged changes an rc1 user meets — Inc 3 (a deleted project folder is not re-created), Inc 8 R-FLOW-EXT.14 (climbing relative log/output paths are refused; remedy: use an absolute path), EXT.2, EXT.10, the CRC-config cause texts, Inc 7 (no partial/orphan report on a failed write; control and direction-override characters in names written as visible replacements; an interrupted write may leave a `<name>.<hex>.part` file that is safe to delete). No exploit detail. |
| A-15 | R-DOC-GUIDE.2/2: a pinned set extended by named supersession, plus "no limitation row is marked". |
| A-16, A-17 | Slice says 6 Flow Builder steps; `_HELP_SECTIONS_MD` constants are removed from the re-bodied files. |
| A-19 + S-4, S-5 | SECURITY.md scope lists `project.json` manifests, flow sets, report filters, CRC Designer templates and pasted text; one sentence names the processes the app starts on purpose (the OS file manager, the clipboard command) and that an external step's command is text from the flow file the app never runs; the README adds: read an external step's command before running it, and import flows only from sources you trust. |
| S-6 | SECURITY.md ships with the 1.0.0 release; the supported-versions table stays `1.0.x`. |

Interfaces (architect §3) are recorded in the graph's interface list; the batch-end doc pass reconciles them.
Runs: tests on the LAN Linux host only (operator rule).

## Round 2 (2026-11-05)

Round 2 (architect + security items, one reviewer): PASS-WITH-NOTES; A-1…A-6 and S-1 closed. E4 addenda (binding, no further round):
- **N-1:** K(w) excludes `/`, `g`, `pgdn`, `pgup` on windows where they do not act (`app.py:9351`, `:10474`); the census test models that.
- **N-2:** the SECURITY.md hold-out names everything it takes with it: the file, its two tests, and the README link to it plus the README link-check arm (all held out together, re-checked at the batch end).
- **N-3:** R-DOC-RELNOTE.7 cites `app.py:14980-14992`.
- INFO notes (R-WHELP.12/1 count, CHANGELOG (f) wording) are fixed in the records at E4 integration.

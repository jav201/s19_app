# Executive summary — s19_app — Batch 2026-10-25-batch-99

> **Roles:** `presentation-builder` (this artifact). Batch `2026-10-25-batch-99`, repo `s19_app`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 Bottom line (read first)

- **What we delivered:** the read/write integrity batch. Every memory image, report and run record the tool writes now says what was applied and what was not, and a loaded image holds only the data its file declares. All ten serious findings of the 2026-10-22 read/write investigation, the project save-back defect and three data defects from the Code-Wire audits are fixed on `main`.
- **Business outcome:** the tool no longer reports success when part of a change was not applied. Independent validation passed with notes: all 51 requirements (11 high-level, 40 low-level) and all 14 end-to-end acceptance tests pass, and no product defect reached final validation. Independent reviewers caught 15 serious defects before any of them was merged.
- **What users will notice:** some A2L values in two shipped example projects now decode differently (71,513 tags in case_06, 1,640 in software_a). The Bytes field in the Patch Editor accepts hex only. A run that did not fully apply its changes now ends in an error or a notice, not in "ok".
- **Next step:** the operator decides the one open question on duplicate-name saves (G-005), and closes the batch. The Load+projects batch is next.

---

## Context (reference)

### Context
s19_app is the terminal tool (TUI, terminal user interface) a calibration engineer uses to prepare and review software changes for ECUs (engine control units). The tool reads and writes memory images: S19 and Intel HEX files that are later flashed to a controller. On 2026-10-22 an investigation of how the tool reads and writes these files found ten serious ("HIGH") defects and judged the tool not ready for producing flash images. This batch fixed those defects. It started on 2026-10-25 and reached final validation on 2026-10-26 (`PLAN.md` §Header, §Where we are).

### Problem
The tool could write a file, or report a clean run, that did not match what the engineer asked for. The engineer had no way to tell:

- **"ok" that was not true.** A patch step reported "ok" even when entries were skipped or the change file could not be read. Run reports said "CLEAN", and run records dropped what was not applied (H-2, H-10).
- **Data the file never held.** The S19 header record was read as data at address 0, so saved images and the Memory Map carried bytes that were not in the source. Cut-off (truncated) files loaded without any warning (H-1, H-8).
- **Wrong or mixed-up output.** Runs that wrote at the same time could swap each other's output. After an undo in the Patch Editor, the saved image could still hold the undone bytes. A checksum (CRC) could be written for a region that held no data (H-3, H-4, H-7).
- **Wrong values.** The A2L codec, which turns raw bytes into engineering values, ignored the byte order the file declares and ran one conversion type (RAT_FUNC) in the wrong direction. Table lookups snapped to the nearest entry without saying so (H-5, H-6, CW-D-10).
- **Small traps.** The Bytes field read some values as decimal. Exports could place files outside the chosen folder, and an export with only a MAC record wrote a byte that was not there. Saving a project after a save-back deleted the work copy or crashed (H-9, CW-D-4, CW-D-7, PH-3).

### Solution
What shipped, in plain terms (12 stories, US-141..US-152):

- **An independent check.** A set of generated test files and a separate file reader, written apart from the tool's own code, are the reference for every byte the tests check. This matters because the tool's own verify step shared the header defect.
- **Honest results.** A patch step that skips an entry ends in "notices" or "error" and names each address that was not applied. A failed step writes no file. Reports and run records list what was not applied and never say "CLEAN" for a run that was not clean.
- **Images hold only what the file declares.** The S19 header is never read as data. A cut-off S19 or HEX file loads with a named warning, and a flow that uses it stops before it writes anything.
- **Safe placement of output.** Each write is prepared in its own private folder and then put in place. Two lanes with the same output name are refused before the run starts. After a flow writes a file, it reads the file back and compares it with what it meant to write.
- **Correct values.** A2L values follow the byte order the file declares, and RAT_FUNC conversions run in the right direction. A table value that cannot be matched exactly is refused or flagged. A value that cannot be decoded shows `n/a` with its reason.
- **Fixed traps.** The Bytes field reads every value as hex and names any value it refuses. Memory-region extraction (Split/Join/Export) cleans file names so files stay in the chosen folder, and a second export takes a `_1` suffix instead of overwriting the first. Save project keeps the work copy. The Load project dialog lists only real projects and loads the one the engineer picks.

### Outcomes / results
The status of each claim is in brackets. These are the flow's evidence states.

- **Requirements verified [executed, approved]:** 51 of 51 requirements pass (11 high-level, 40 low-level). The independent validation verdict is PASS-WITH-NOTES, with no high-severity finding and 10 minor gaps (`04-validation.md` §Verdict, §Gaps detected).
- **Acceptance behaviours [executed]:** all 14 acceptance tests drive the shipped screens and check the result in the written files, the painted screen or the reports. Each of the 12 stories has one. Three minor gaps remain: some refusal and boundary cases are checked below the screen level, for example the Bytes-field refusal message and HEX files with defects (G-002, G-003).
- **No product defect escaped [executed]:** the full test run on the final product code had 14 failures. 9 also failed before the batch, 3 were intermittent and passed when re-run, and 2 were out-of-date test expectations that were fixed in test files only (Increment 013). None was a product defect.
- **Defects caught before merge [executed]:** independent reviewers found 15 serious defects in 10 of the 12 code increments. The implementer's own tests (the implementer was an AI coding agent, Kimi K2.8) caught none of them. Five of the 15 were breakages in nearby features. All 15 were fixed before merge (`05-postmortem.md` §Synthesis).
- **Delivery [executed]:** 14 increments on `main`: 12 implementation increments and 2 test-fix increments. 88 files changed (17 product, 71 test). The test count went from 3,634 to 3,773.
- **Visible changes in shipped examples [executed]:** in case_06, 71,513 of 220,040 tags now decode with the byte order the file declares. In case_00_public's `software_a.a2l`, 1,640 of 13,990 tags with RAT_FUNC conversions now decode in the other direction (`evidence/inc-10/example-impact.txt`).
- **Test evidence [executed]:** the confirmation run of the full suite on the final tree finished with 3,755 passed and 12 failed. 8 failures predate the batch, and 4 are intermittent tests that also fail on the pre-batch tree or pass when run alone (G-001, `evidence/suite-triage-75f947a.md`).
- **Not done [not-run]:** there was no evaluation with real users: automated tests show that the messages are on the screen, not that an engineer reads them correctly. Time saved, error rate and other business metrics: **not recorded**.

### Next steps
The order below follows the operator's plan of 2026-10-25 (`.dev-flow/BACKLOG-CODE.md` §*Decided 2026-10-25*). The sources do not record target dates.

1. **Close this batch (now, operator).** Approve the `06-docs/` documents, then commit, push and run `/dev-flow-sync`.
2. **One decision (operator, at the close).** Two tests older than this batch expect a second save under the same name to create a new, suffixed file. This batch keeps one file when the bytes are identical. Choose: keep the reuse and update the two tests, or restore the suffix (G-005). Both tests failed before the batch, so the batch did not cause the conflict.
3. **Route the open items.** The backlog holds 18 items from this batch. Three more go in at the close (G-002, G-003, G-005), which makes 21. The most useful ones are screen-level tests for the Bytes-field refusal and for a cut-off HEX file, and a shared, public way to place written files instead of four private copies of the same steps.
4. **Load+projects batch.** It takes the project-loading items this batch left out of scope.
5. **Waiting-lane scroll prototype**, then the **batch-98 flow report**.

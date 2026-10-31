# E4 — implementer A notes (`s19_app/tui/app.py`)

Deviations from `codewire/proto-8a-app.md` and open seams found while building. Each names the node, the example, what differs and why.

## Deviations

**D-1 — `_handle_save_dialog`, the unsaved-edits line (E3 R1; examples TC-B100-29 "second Save project", TC-B100-70 "natural path").**
The app reads `PatchEditorPanel._dirty` (private) to decide whether a file-backed document recorded as on disk "holds unsaved edits". The panel has no public dirty reader before Inc 10 (P-43), and `screens_directionb.py` is outside the 4-file budget. No other signal is correct: comparing the document's serialized bytes with the file flags a hand-formatted file as edited. Replace with the public reader when Inc 10 adds it.

**D-2 — `_handle_save_dialog`, the E3 R5 kept note (example TC-B100-05 S3R2-7, "a non-string value is named by its JSON type").**
The dropped value is named through the reader's clipped mark (`issue.details["entry"]`, at most 120 characters, then `safe_text`). For a non-string value the reader's mark is `json.dumps(raw)` clipped, so the line shows the value's JSON text (for example `5` or `{"a": …`), not a type name such as "a number". Naming the type would need a second read of `project.json` or a new mark in the reader (group C's file). The 120-character bound and the no-control-character rule hold either way.

**D-3 — `_handle_save_dialog`, what the gather gets for a file-backed document with no plan row.**
The proto says the gather gets the source for a file-backed document at any entry count. The app passes the source only when the plan holds a document row; with no row (class `inside_elsewhere` or `missing`, or an `OSError` on the document's digest) it passes `None` and paints the one status line itself. Reason: after a digest `OSError` the class can still be `outside`, and the gather would then copy a file the plan did not name (plan ≠ written tree, LLR-167.6). For `inside_elsewhere` / `missing` the visible result is the same; only the gather's log finding is not emitted.

## Seam gap (not in app.py)

**G-1 — next-step tokens of the two new `not readable` rows (§3 rows 361 and 362, E3 R16).**
`_reopen_active_document` returns `ProjectFileProblem("not readable", text, reason)` with reason `too large to reopen` or `could not be read`. The Load panel composes `reason + " - " + PROBLEM_NEXT_STEP[kind]` in `compose_load_announcement` (`variant_execution_service.py`, group C), so both rows paint the generic next step "replace the file, or Save project to drop it" instead of "open it from the Patch Editor (it can take a while)" / "check that the file can be opened, then Load again". With R8 refined Save project keeps those two records, so the painted next step is wrong for them. No node in the design owns a reason-specific next step; it needs a ruling (for example a next-step mark on `ProjectFileProblem`, or a lookup by reason in the composer).

## Notes (no deviation)

- `_handle_save_dialog` calls `classify_active_document` once itself (after the plan) to know the class for the unsaved-edits line and for the wording of the "not recorded" line; it is the same one gather classifier (E3 R11), not a second rule.
- The `io_error` line uses the R16 wording ("could not be read … check that the file can be opened, then Load again") plus "it stays recorded"; the proto's "could not be checked" is superseded by R16.
- The unsaved-edits line is painted for class `in_home` only, as the proto states; an `outside` copy with panel edits keeps the flag set and paints no line (example "file-backed arm, outside the project" asks only for the flag).

# E4 — reader notes (group C, `variant_execution_service.py`)

Implementer notes for Inc 8a step E4, the manifest reader. Spec: `codewire/proto-8a-reader.md`, `codewire/interfaces-8a.md`, `E3-rulings.md`. Only `s19_app/tui/services/variant_execution_service.py` was edited (CRLF kept).

## Implementation choices (no behaviour change against the graph)

- **C-E4-1. How `manifest_keep_reason` finds a refused `active_document`.** The node says "any issue whose context is `active_document`". `ValidationIssue` has no context field, and the file's rule is "recognised by a mark, never by its message text". So `_parse_manifest_active_document` adds the mark `details["key"] = "active_document"` (`_ISSUE_KEY`, `_KEY_ACTIVE_DOCUMENT`) to the one finding of a refusal, whatever step refused it (text rule, form or walk). `manifest_problems` ignores the new mark, so the panel row is unchanged.
- **C-E4-2. `is_active_document_form(text: str)`.** The annotation follows the interface (`str`); the function is total as P3 requires (any other type → `False`, no raise). The docstring says so.

## Deviations (the graph cannot hold as written)

- **D-E4-1. `manifest_rewrite_refusal` example for a refused document.** The node (NO CODE CHANGE) has the example "active_document `patches/x.txt` → reason `holds entries that were skipped`". That example was written in E2, before E3 R5. With R5, `manifest_keep_reason` returns "holds an active_document this version refused" for the same manifest, and `manifest_rewrite_refusal` returns the keep reason first. Both examples cannot hold without a code change in `manifest_rewrite_refusal`, which the node forbids. Implemented: no code change; the reason is `holds an active_document this version refused`. The behaviour that matters holds: the rewrite is still refused (non-`None`), never carried verbatim (SEC6-2). The tester should assert the R5 phrase, or assert non-`None` only.
- **D-E4-2. "1 001 escaping batch entries" (SEC6-5 + parse order example of `read_project_manifest`).** 1 001 `batch` entries is over `MANIFEST_ENTRY_CAP` (1 000): the read returns the empty manifest with the over-cap finding, and `active_document` is never parsed. The closest example that tests the rule: 1 000 escaping batch entries plus the refused `active_document` = 1 001 skipped entries. Probe result: the `active_document` finding is first and kept one by one, the fold finding says "901 more manifest entries were skipped", read in 0.014 s. Same for the R2-2 ceiling example: 1 000 batch entries in distinct folders plus the document (1 001 folder checks needed) → `active_document` accepted, the last batch entry unchecked and counted in the fold.

## For other groups / the reviewer (not deviations)

- **N-E4-1 (R6, group A).** The keep-reason phrase given by the node, "holds an active_document this version refused", is painted by `app.py` in the Save project status (`project.json {keep_reason}: its previous content is kept as ...`) and by `_rewrite_project_manifest` (`project.json in project ... {refusal} and was not rewritten`). It names the key `active_document`, which is not a user term. Implemented verbatim per the node; if R6 applies to it, the phrase is one string in `manifest_keep_reason`.
- **N-E4-2.** The Edit tool rewrote the file with LF line endings during the work; the file was converted back to CRLF before the tests ran (`file`: "with CRLF line terminators"; git diff counts only the changed lines).

# HANDOFF-fix — batch-99 Increment 11, review round 1 (code-reviewer F1–F3)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc11` (branch b99-inc11). Nothing committed; all changes are in the working tree for the orchestrator.

## What was done

- **F1 [MEDIUM]** — `s19_app/tui/services/change_service.py` (`parse_new_bytes`): a token is now accepted only when `re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]{1,2}", token)` matches (ASCII only); anything else raises the `ValueError` naming the token. The old `int(body, 16)` path admitted signs (`+F` → 15, `0x+F` → 15), non-ASCII digits (`１２` → 0x12, `٣٣` → 51) and let `-1` slip to a `ChangeEntry` value-range refusal naming the value. Docstring claims corrected (Returns / Raises / Data Flow); `import re` added. CRLF preserved (2384 `\r\n` lines after, hash `c830459e…3ddef`).
- **F1 tests** — TC-B99-32's refused set in `tests/test_b99_bytes_field.py` gained `+F`, `-1`, `0x+F`, `１２`, `٣٣` (each asserted to be named in the message).
- **F2 [MEDIUM]** — AT-B99-12 rewritten black-box: the image loads through the app's own load path (`app.load_from_path`, the `b97_fixtures.open_patch_editor` idiom) instead of injecting `app.current_file`; the saved file is found on disk under `<base>/.s19tool/workarea/` (via `WORKAREA_DIRNAME`/`WORKAREA_SUBDIR`, the `staging_block` idiom) by the name the shipped `#patch_saveback_name_input` pre-fills; only the independent reader reads the bytes. No internal attribute or service is touched.
- **F3 [LOW]** — packet corrected: three existing test nodes changed, not two — `test_parse_new_bytes_rejects_a_garbage_token` (test_tui_memory_patch.py) gained the `100`-refusal arm. Fixed in the §2 file table, the §4 re-pin list (third entry added), the signed-balance ledger and gate checklist item 5; new "Review round 1 fixes" subsection added to the packet with the fix-round evidence table.

## Verification (all transcripts in `.dev-flow/2026-10-25-batch-99/evidence/inc-11/`)

- GREEN after fixes: `tests/test_b99_bytes_field.py` 3 passed (`green-fix-b99_bytes_field.txt`); `tests/test_change_service.py` + `tests/test_tui_memory_patch.py` 30 passed (`green-fix-repinned.txt`); `tests/test_address_census.py` 23 passed (`green-fix-address-census.txt`).
- AT-B99-12 stability: 8/8 passed (`stability-at12.txt`).
- C-40 mutation (F1's declared negative control): the `int(token, 16)` path without the fullmatch → TC-B99-32 KILLED (`+F` did not raise) — `mut-LLR-161.1-fix.txt`; restore proven byte-identical by SHA-256 (`baseline-hashes-fix.txt`).
- RED kept on the new black-box shape: under the HEAD base-0-first grammar both TC-B99-32 and AT-B99-12 fail, the AT with `got [15, 10, 31, 20]` = `0F 0A 1F 14` — `mut-LLR-161.1-fix-headgrammar.txt`; both mutants reverted, no mutant left in place.
- This-worktree import proof: `python -c "import s19_app; print(s19_app.__file__)"` → `C:\Users\jjgh8\Github\s19_app-b99-inc11\s19_app\__init__.py`.

## Open items

- `s19_app/tui/changes/io.py:13-19` docstring still describes the old permissive TUI grammar (carried over from the first round; doc-only, outside the SOURCE cap — flagged in the packet's Correction population).
- §4b independent review stays `pending — orchestrator`.

__KIMI_UNIT_DONE__
Files changed: 1 SOURCE (change_service.py — ASCII fullmatch grammar) + 1 test file (test_b99_bytes_field.py — TC-B99-32 refused set +5 tokens, AT-B99-12 rewritten black-box) + packet increment-011.md (F3 corrections + Review round 1 fixes subsection).
Tests added: 0 new nodes; TC-B99-32 extended by 5 refused tokens, AT-B99-12 restructured (load via app's own path, saved file found on disk by the prompt's name).
RED/GREEN: 3 GREEN (b99_bytes_field) + 30 GREEN (change_service + memory_patch) + 23 GREEN (address_census); AT-B99-12 8/8 stable; mutation REDs: TC-32 KILLED (no-fullmatch mutant) and AT-12 RED 0F 0A 1F 14 (HEAD-grammar mutant).
Mutations: 2 run (int-without-fullmatch, HEAD base-0-first), both reverted byte-identical by SHA-256 (c830459e…3ddef).
Open questions: stale doc-only mention in changes/io.py:13-19 (outside the SOURCE cap); §4b review pending the orchestrator.

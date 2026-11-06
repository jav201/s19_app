# Inc 6 — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-mutants.md` (DeepSeek, M1–M42: **39/41 killed**, 1 not applicable, 3 survivors), `E5-code-review.md` (code-reviewer **PASS-WITH-NOTES**: F1–F3 MINOR, F4–F6 NIT), `E5-security.md` (security-reviewer **PASS-WITH-NOTES**: every E3 mitigation executed, S-1/S-3/S-4/S-5 approved by mutant; E5-1, E5-2 LOW; 4 INFO), `E5-coverage-audit.md` (qa-reviewer: 81 cases, 17 marks changed = 21 %; 66 covered, 15 partial; 12 key/dialog route cases; Windows not run). No BLOCKER/HIGH/MAJOR open. Rulings:

| Id | Ruling | Why |
|---|---|---|
| C-1 | Move every case's marks in `02-test-cases.md` to the audited values; cite the mutant transcripts. | The record shows the audited state. |
| C-2 (survivors M10, M27, M35) | Equivalent under every buildable route: the variant install (`_apply_prepared_load`) and the reopen tail also hide and repaint on a project load. The redundant calls in `_reset_project_session` stay (a project load that installs no variant would rely on them); the three mutants are recorded as equivalent, M27 as the expected E3A-16 survivor. | Honest score; removing the calls would leave a future route uncovered. |
| C-3 (audit: 12 route cases) | Drive the 6 project loads through `p` and its dialog (incl. the replace question with unsaved bytes) and the 3 Save projects through `ctrl+s` and its dialog; press Add/Remove/Write on the shown tab for CHK-PE-008/3, 009/4, 014/1. Where a route cannot be built, the case stays `partial` with the reason. | The increment owes black-box ATs through keys and dialogs. |
| C-4 (audit: weak checks) | 001.3/3 ribbon asserted exactly; `test_at030a` reads the source; `test_tc_b94_15` asserts the painted label order. | Expected results must be exact. |
| C-5 (CR F3, design-gap case) | The "no img-patched*.s19" assertion gets an arm that presses Write file, or leaves cases R-TUI-049.3.2/1 and /8. | An assert that cannot fail does not verify a case. |
| C-6 (CR F1, F2) | Fix guide §8.9 (`ch08-patch-editor.md:102`) and add capture notes to ch08-09 and ch08-20 ("capture taken before 1.0.0"); fix the stale docstrings (`app.py` pick handlers and save-back; `set_change_files` / `set_check_files` Args). | Docs and comments must match behaviour. |
| C-7 (CR F4) | `_resolve_listed_file` refuses `.` and `..`. | A name that resolves to the folder is not a file. |
| C-8 (CR F5, F6 NIT) | No change; recorded. | Cosmetic / cost noted. |
| C-9 (SEC E5-2, design-gap) | The Check Editor Write status names the home: `wrote checks/<name>` in a project (exact text fixed in the Write row, which is amended), unchanged without a project. | After a `library/` pick the operator must see that the project copy was written, not the library. |
| C-10 (SEC E5-1, pre-existing) | Backlog: a dangling `workarea/patches` link crashes Check Editor Write (`changes/io.py:1648`, outside the slice); nothing is written. | Outside the four files; fails closed. |
| C-11 (SEC E5-3 … E5-6 INFO) | No action; E5-6 already in the backlog. | Informational. |
| C-12 (Windows) | The 10 cases with junction or file-link arms run once on this PC under the Windows-only-arm rule (isolated app-state folders, never the clipboard); otherwise they stay `not_run` on Windows. | CI and the LAN hosts are Linux. |

Corrective: one Opus pass (tests, records, docs, comment fixes, C-7 and C-9 code within the slice). Then a re-audit of the cases C-1 … C-5, C-9 touched, and a security re-check of C-9.

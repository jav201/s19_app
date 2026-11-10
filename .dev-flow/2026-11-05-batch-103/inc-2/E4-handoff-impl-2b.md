# E4 handoff — Inc 2b implementer

Role: implement the approved 2b write side of interface I-2. Do not write tests and do not communicate with the tester.

Worktree: `C:\Users\<user>\Github\s19_app-b103-inc2b-code`, branch `b103-inc2b-code` (created by the orchestrator after E3 closes). Own only `s19_app/tui/a2l_definition.py`. Do not edit `a2l.py`, tests, records or another source file. Do not commit or push.

Read the corrected `inc-2/codewire/graph-inc2.md`, `01-requirements.md`, `E3-rulings.md` final section, `E1-slice.md`, and current module. The final E3 ruling wins over older graph text. Implement every 2b node: `Encoded`, `encode_definition`, number/enum/ASCII encode, limits, mask merge, precision, overlap index, `shared_with`, selected bits and parse-error refusal. Insert `shared_with` after `compu_tab_ref` before `refusal`, with no default, at all five current `Definition(...)` sites. Keep all Inc 2a/3a behaviour and signatures intact.

Key rulings: use `a2l_data["declared_spans"]` for BLOB/INSTANCE; an address-bearing object with unreadable length covers that address; AXIS_PTS is Inc 3b. CLEAN means a mask counts only from a definition with no refusal, computed on demand and cached by name, never by describing the whole file. Remove obsolete text-of-object mask guards; keep only the record-word checks, duplicate BIT_MASK and duplicate BYTE_ORDER source residuals. Any payload parse error refuses encode after the definition's own refusal. Echo file and operator words through the existing 256-character `_echo`. Never mutate image or A2L data.

Reuse `encode_physical_to_raw_bytes` as the graph specifies. Pure stdlib plus `s19_app.tui.a2l`; no I/O, Textual, clipboard or global mutable state. Follow `PROJECT_RULES.md` docstrings and update the module's read-side-only docstring.

On Windows run only `python -m py_compile s19_app/tui/a2l_definition.py`. Do not import the package, run pytest, run probes or use the clipboard on Windows. The orchestrator runs everything else on Linux. Report nodes implemented, commands and exit codes, deviations and open questions in at most 300 words.

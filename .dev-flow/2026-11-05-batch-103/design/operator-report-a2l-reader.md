# Operator report — A2L reader (2026-11-07)

Verbatim (Spanish, the operator's words): «Esa descripción es precisamente un comportamiento visto y reportado que nunca se replicó. Me da gusto que se siga viendo... al parecer las direcciones de memoria a veces se reportan incluso con caracteres contiguos como salto de línea... si debemos ser minuciosos y rigurosos, es un riesgo muy alto tener problemas con lectura de a2l.»

English summary for the records: the operator has seen, in real use, memory addresses reported wrongly — apparently with an adjacent character such as a line break attached — and it was never reproduced. They ask for a meticulous, rigorous reader: problems reading A2L are a very high risk.

Context: Inc 2's E3 security rounds 1–5 found the frozen reader (`a2l.py`) mis-reading comments, quoted strings, one-line IF_DATA, INSTANCE/BLOB and commented ECU_ADDRESS lines (`inc-2/E3-security.md`, `inc-2/E3-rulings.md`). Amendment A2 created Inc 11 to fix the reader. This report is Inc 11's first user story and its first reproduction target.

**Follow-up (2026-11-06T21:32:27-06:00):** «No lo tengo, fue un evento en campo... puedo intentar replicarlo pero no es muy factible volverlo a ver.» No sample file exists; the reproduction is searched systematically (line-ending and adjacency corpus, differential oracle) and any candidate is shown to the operator to confirm it matches what was seen.

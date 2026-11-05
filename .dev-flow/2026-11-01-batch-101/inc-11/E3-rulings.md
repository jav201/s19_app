# Inc 11 — E3 rulings, round 1 (orchestrator, 2026-11-05)

Inputs: E3-architect.md (FAIL: A-1 HIGH, A-2…A-4 MAJOR, A-5…A-12 MINOR), E3-security.md (PASS-WITH-NOTES: S-1, S-2 MEDIUM, S-3…S-6 LOW, S-7…S-11 INFO). Round 2 re-checks A-1…A-4, S-1, S-2 only.

| Id | Ruling |
|---|---|
| A-1 (HIGH) + S-1, S-2, A-7 | MEMORY_SEGMENT reader, anchored rule: the base is the first unquoted word after the name that starts with a digit or a sign; it is a Number and ≥ 0, and the next word is a Number > 0; otherwise the segment has no base and no size (no further scan). A quoted word is never a Number. **Number** is redefined by an ASCII pattern (decimal `[0-9]+`, hex `0[xX][0-9A-Fa-f]+`, no underscores, no `0o`/`0b`, no non-ASCII digits, at most 8 hex digits / 10 decimal digits); a new If-row: base + size > 2^32 → no base and no size. Add the broken-record cases (`0x1000 BAD -1 …`, `0xZZ 0x1000 0x400 …`, `0400`, quoted `"1"`, base −1, size 0) as robustness cases with exact expected "no base". The residual unterminated-quote case (S-6) is closed by resetting quote state per line in the record-word helper. Fold E2-2(b) accordingly. |
| A-2 (MAJOR) | `tests/test_segment_split_window.py` fixtures `DEMO_A2L_SECTIONS` / `PrgCode` are rewritten to the real `memorysegment.a2l` record shape (names and assertions unchanged); listed in E1-slice §4 Nodes touched. |
| A-3 (MAJOR) | The six `a2l-*` snapshot baselines in `tests/test_tui_snapshot.py` change (Region `unknown` → `flash`, OR-4). They are re-recorded at integration in the CI-matching environment on the LAN Linux host (the snapshot-regen-env rule), never on Windows; the before/after diff goes on the batch-end review page for the operator. `conftest.make_large_a2l` / `large_project` are added to D-8. |
| A-4 (MAJOR) | `AR_COMPONENT` is added: 62 names, threshold 62/62, cited to the public grammar reference used in E3. The D-9 pin test covers the 37-file corpus (A-9 adds `tests/fixtures/synth/synth_a2l.a2l`). |
| A-5 + S-5 | The sort rank map gives any severity outside `SEVERITY_ORDER` a default rank after INFO; it gets a distinct name (not `_A2L_ISSUE_SEVERITY_RANK`); one case with an OK/NEUTRAL issue. |
| A-6 | Definition says "inside IF_DATA as the section tree nests it"; a test pins the V171 one-line IF_DATA shape. Parser `/end` name checking (S-4, O-5) → BACKLOG. |
| A-8 | `docs/architecture.md:396-416` and the module docstring of `tests/test_tui_issues_triage_b94.py` are updated (text only) and listed in the slice; the doc counts toward no source cap. |
| A-10 | R-A2L-121/122 add "holds at least one point". |
| A-11 | The size > 0 rule of A-1 closes O-2 (size-0 a2l rows) inside the reader; record it. |
| A-12 | D-8 lists the Workspace stat pane warning count (release demo 364 → 262) and the A2L Explorer find/sort over `memory_region` as admitted value changes. |
| S-3 | Recursion on deep nesting: pre-existing, contained by the attach worker → BACKLOG (iterative parser); the new skip passes the flag down, never recomputes from ancestors (graph note). |
| S-9 | Modal title markup parse of tag names and unscrubbed body (pre-existing) → BACKLOG. |
| S-11 | Optional laziness of the record-word helper: not required. |

Runs: every test, probe and snapshot regeneration on the LAN Linux host (operator rule).

## Round 1 addendum (orchestrator, 2026-11-05)

- `0400` is read as decimal 400 under the ASCII Number pattern (leading zeros allowed for decimal); case R-A2L-036.2/5 expecting base 400 is accepted. The A-1 ruling listed it among the "no base" inputs by mistake; the reading that matters is that the pair can no longer slide onto the size and offset words.

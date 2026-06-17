# Increment I3b — CRC TUI surface (config editor + worker + per-region rows)

**LLRs:** LLR-004.2 (editable text config, dummy pre-fill, config-error→no compute), LLR-002.3 (R-6 worker-thread), LLR-002.4 (per-region result rows). **TCs:** TC-115 (through-handler), TC-116 (worker inspection), F-L1 case, parse_crc_config tests, + a stale-worker race regression. **Carries F-L1** from I3a.

## 1. What changed
The CRC check now runs from the TUI. `crc_config.py` gained `parse_crc_config(text)` (text-level parse, same collect-don't-abort contract; `read_crc_config` delegates to it) + a `DUMMY_CONFIG_TEXT` constant. `OperationsScreen` shows an editable `TextArea` pre-filled with the dummy template only while the `crc` row is selected; on Execute it parses that text and — on a config/parse error — surfaces the error and runs NO computation (F-L1), else dispatches the real `CrcOperation.execute(..., config=config)` to a `@work(thread=True, exclusive=True, group="crc_operation")` worker (R-6) that marshals the result back via `call_from_thread`. The presenter renders one row per `crc_regions` entry (output address, computed, stored, MATCH/MISMATCH/no-stored-value — LLR-002.4). Non-CRC placeholder ops keep their synchronous, config-less path.

## 2. Files modified (5, then +0: the F1 fix touched 2 already-in-scope files)
- `s19_app/tui/operations/crc_config.py` (+`parse_crc_config`, +`DUMMY_CONFIG_TEXT`, delegation)
- `s19_app/tui/screens.py` (`OperationsScreen`: config TextArea + worker + presenter + per-region rows + F-L1 + the F1 token-guard fix)
- `tests/test_crc_config.py` (+5 parse tests)
- `tests/test_tui_crc_surface.py` (NEW pilot: TC-115/TC-116/F-L1 + the stale-worker race regression)
- `tests/test_tui_operations_view.py` (5th-file reconciliation — see §5)

## 3. How to test
```
python -m pytest -q tests/test_tui_crc_surface.py tests/test_crc_config.py tests/test_tui_operations_view.py
python -m pytest -q -m "not slow"
ruff check s19_app/tui/screens.py s19_app/tui/operations/crc_config.py <test files>
```
Manual: `s19tui --load <fixture.s19>` → `x` → select crc → dummy-prefilled config editor → edit/replace → Execute → per-region verdict rows.

## 4. Test results
- `pytest -q -m "not slow"`: **818 passed**, 29 skipped, 3 xfailed (exit 0) — orchestrator re-ran (241s).
- ruff clean. **Ledger: 809→817 (I3b +8: 5 parse + 3 pilot) → 818 (F1 race regression +1) = net +9; collection 862→871.** Frozen guards green.

## 5. Independent review (code-reviewer) — APPROVE-WITH-NITS, 0 HIGH; 1 MEDIUM FIXED
All 3 rule-ons passed: (a) worker marshalling correct, no off-thread UI mutation, parse on UI thread / compute off-thread; (b) F-L1 distinction real + tested (error path clears hex, no MATCH, no "status: ok"); (c) TC-011/012/013 re-pointing preserved intent (seam/hex-baseline/KeyError-scope against the `extract` placeholder), and the crc-no-config-through-TUI path is unreachable by construction (editor always pre-filled, LLR-004.2) so its `config=None` note stays covered headlessly in `test_crc_operation.py` — not a coverage hole.
- **F1 (MEDIUM, FIXED):** a stale in-flight CRC worker could overwrite a later config-error surface with a stale `status: ok` + MATCH (defeating F-L1 via a race). Fixed with a **dispatch-token guard** (`_crc_dispatch_token` bumped on every Execute incl. the error branch; `_present_result` drops any result whose token is stale) + `cancel_group` for prompt slot release. The token guard is load-bearing (cancelling a thread worker can't interrupt the running thread); verified against Textual 8.2.5. Regression test `test_stale_crc_worker_result_does_not_overwrite_error` — fail-before/pass-after confirmed.
- LOW: F2 (typed `config: Optional[CrcConfig]`, `operation: Operation` via TYPE_CHECKING) FIXED; F4 (unused test param) FIXED; F3 (TC-116 source-level inspection) left as-is per the spec's stated inspection threshold.

## 6. Risks
- TC-116 is source-level (`"@work(thread=True" in getsource`) per the LLR-002.3 inspection threshold; can't catch a mis-targeted decorator. TC-115 covers the behavioral guarantee (result reaches the surface through the handler).
- `OperationsScreen` not snapshot-tested (`test_tui_snapshot.py` covers only the main density layout), so the new widgets introduce no SVG baseline drift. No `styles.tcss` polish added (default TextArea/Label styling) — not required by any LLR.

## 7. Pending / next
- **I4** — persistent project report CRC section (LLR-002.5/003.5): `_crc_section_lines(...)` consuming `crc_regions` into `report_service.py::generate_project_report` + `tests/test_report_crc.py` (TC-117/126). Then **I5** (inject + emit + verify + two-stage confirm, HLR-003 — the side-effectful write; security-reviewer sign-off mandatory).
- TC-115/116/F-L1/parse-test/race-test ids reconcile into §5.2 at Phase 4 (V-5).

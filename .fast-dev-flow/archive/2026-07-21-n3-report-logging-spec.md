# Quick Spec — s19_app · N3 Report-generation observability

> Minimal spec for `/fast-dev-flow`. Goal: capture what's needed in 5-10 minutes without IEEE 830 overhead.
> **Hard rule:** acceptance criteria must be **observable** (input → verifiable output).

- **Date:** 2026-07-21
- **Batch:** n3-report-logging
- **Flow:** /fast-dev-flow
- **Language:** English
- **Run mode / merge:** autonomous end-to-end + self-merge (operator-granted this batch, per-batch only).
- **Status:** Phase C — validating.
- **Branch:** `fix/n3-report-logging` off `main` `9bb50f2` (post-#117, RC-1 verified HEAD == origin/main tip).

---

## 1. Objective (1 line)

Make report generation observable: emit a structured log line (report kind · source artifact(s) · output path · success/failure) to `.s19tool/logs/s19tui.log` every time the app generates a project report, a before/after report, or a diff report — closing a confirmed fail-loud gap where these actions currently write **nothing** to the log.

---

## 2. User stories (Connextra)

- As an engineer operating the TUI, I want every report I generate to leave a log entry (what kind, from what source, to what path, and whether it succeeded), so that I can audit and troubleshoot report activity from `s19tui.log` instead of guessing.
- As a support/maintainer, I want a **failed** report generation to log its failure, so that a silent no-output is never indistinguishable from a success.

---

## 3. Acceptance criteria (observable)

> The app's file log is the rotating logger wired by `workspace.py::setup_logging` → `logging.getLogger("s19tui")` → `.s19tool/logs/s19tui.log`. "The log gains an entry" means that file's content, read back after the action.

- [ ] **AC-1 (project report success):** When a project report is generated successfully (`generate_project_report` call site in `app.py`), the system shall append one log line to `s19tui.log` naming the report **kind** (project), the **source** (project name/dir), the **output path**, and a success marker.
- [ ] **AC-2 (before/after report success):** When a before/after report is generated (`compose_before_after_report` call site), the system shall append a log line naming kind (before/after), source (before + after paths/names), output path, and success.
- [ ] **AC-3 (diff report success):** When a diff report is generated (`generate_diff_report` / `generate_diff_report_html` call site), the system shall append a log line naming kind (diff), source, output path(s), and success.
- [ ] **AC-4 (failure is logged, not silent):** When a report generation raises (e.g. `generate_project_report` throws `FileExistsError` on the 100-report same-second cap, or any emitter raises), the system shall append a log line at WARNING/ERROR level naming the kind, the source, and the failure — never leaving zero trace.
- [ ] **AC-5 (metadata only — privacy constraint):** The logged lines shall contain only **metadata** (kind, source name/path, output path, outcome); they shall **not** contain report body content or memory/byte values. (Honors the emitters' original "no body in logs" design intent.)
- [ ] **AC-6 (lands in the file):** The emitted lines shall reach the `s19tui.log` **file** (logged on the `"s19tui"` logger or a child such as `"s19tui.report"`), verifiable by reading the file — not merely a `getLogger(__name__)` call that never propagates to the file handler.

---

## 4. Validation strategy

Unit/integration tests, headless, in `tests/`. The clean seam: a small formatting helper (e.g. `_report_log_fields(kind, sources, output_path, outcome) -> str`, or the log call routed through a `"s19tui.report"` child logger) that the three `app.py` call sites use. Tests wire a real logger via `setup_logging(tmp_path)` (or attach a `FileHandler` to `getLogger("s19tui")` against a temp `.s19tool/logs/s19tui.log`), invoke the logging path for each report kind + the failure path, then **read the log file back** and assert the expected metadata substrings are present (AC-1..4, AC-6) and that body/byte content is absent (AC-5). This is a black-box, output-then-consume assertion over the produced log file (C-12/C-31/C-32) — not a mock-was-called check. Manual smoke: launch `s19tui`, generate one report, `tail` `s19tui.log`, confirm the line.

---

## 5. Non-goals (OUT)

- **No logging inside the pure emitter modules** (`report_service.py` / `diff_report_service.py` / `before_after_service.py`) — they are deliberately Textual-free, headless, and documented as "performs NO logging"; logging goes at the `app.py` orchestration call sites where the `"s19tui"` logger already lives. Keeps the pure/orchestration split intact.
- No new log rotation / retention / format framework — reuse the existing `setup_logging` handler and the app's current `self.logger.info/…` convention.
- No log-viewer UI, no surfacing these lines in the in-app task panel (that is N2/N5 territory).
- No change to report content, filenames, or destinations.
- Not touching the engine-frozen set (none of these targets are frozen).

---

## 6. Detected security flags

> Scanned sections 1-4.

- [ ] Auth / identity
- [ ] Secrets / config
- [ ] External integrations
- [ ] Sensitive data (PII, payments, health, encryption)
- [ ] Destructive DB
- [ ] Input / attack surface
- [ ] Network / exposure

**`security_required`:** `false`

**Note (not a flag, but a design constraint):** logging is an information-disclosure surface. AC-5 explicitly bounds the log to **metadata only** (no report body, no memory/byte values), preserving the emitters' original privacy intent. No auth/secret/PII/external/DB/network/input pattern fires → `security_required: false`, but the metadata-only bound is a hard acceptance criterion, not optional.

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | C |
| Started | 2026-07-21 |
| Closed | - (pending full-suite green + merge) |
| Promoted to /dev-flow | no |
| Notes | 1 increment; app.py + tests/test_report_logging.py (2 files). Base `9bb50f2` post-#117. |

---

## 8. Close (filled in phase C)

### What changed
Report generation now leaves a structured, metadata-only trace in `.s19tool/logs/s19tui.log`. Added a pure module-level formatter `format_report_log_line(kind, source, output, outcome)` and an app method `S19TuiApp._log_report_event(...)` (INFO on success / WARNING on failure), wired at the three `app.py` orchestration call sites — the project-report worker (`_start_generate_report_worker`: success + `ValueError` reject + crash), `action_before_after_report` (success + refusal, previously fully silent), and the diff handler (`on_ab_diff_panel_report_requested`: md + html success + both refusals, previously fully silent). The thin path-only line in `_finish_generate_report` was replaced by the structured success line emitted in the worker (which has the project source in scope). No logging was added inside the pure emitter services — they stay Textual-free/headless by design (non-goal honored).

### Finding (honest scoping correction)
The backlog framed this as "`report_service.py` has ZERO logger calls" — true for the pure service module, but the **project-report app call site already logged** (thinly: path-only success + a crash `logger.exception`). The genuinely silent surfaces were **before/after** and **diff** (zero logging, incl. their refusal branches) and the project **reject** (`ValueError`) branch. N3 enriches the project line and closes the silent surfaces.

### How it was tested
`tests/test_report_logging.py` (6 tests, all green; full suite re-run in Phase C):
- `test_format_report_log_line_names_all_four_fields` / `_is_metadata_only` — AC-1/2/3 format + AC-5.
- `test_log_report_event_success_is_info` / `_failure_is_warning` — AC-1..4 level routing on the real method.
- `test_report_line_reaches_s19tui_log_file` — AC-6, line lands in `s19tui.log` via `setup_logging`.
- `test_before_after_report_generation_logs_to_file` — **driven gold-standard AT**: boots the real app (`base_dir=tmp_path`), drives the `b` before/after action, reads the produced `s19tui.log`, asserts the `report kind=before-after … outcome=ok` line and NO entry-byte leak (AC-2+AC-5+AC-6). **RED verified**: with the before/after log call disabled the driven AT fails (no `report kind=` line) — the test has teeth.
- Regression: `test_before_after_report.py` + `test_report_service.py` (60 green), `test_tui_diff_screen.py` + `test_diff_report_service.py` + `test_tui_diff_compare_realpath.py` + `test_tui_app.py` (113 passed / 1 xfailed).

### Open risks / pending
- **AC-1 (project) and AC-3 (diff) are not driven end-to-end through the app** — covered by the pure formatter + level-routing + file-landing tests, and the call sites are straight-line. A follow-up could add driven ATs for the project + diff report kinds (mirror the before/after driven AT). Low risk (mechanism proven; call sites trivial).
- Diff `source` is the project/destination name (the diff has no single file source); acceptable metadata.

### Security flags — handling
`security_required: false`. The metadata-only bound (AC-5) is enforced structurally (the formatter interpolates only its four given fields; callers pass names/paths, never bodies) and asserted by `_is_metadata_only` + the driven AT's `"AA BB"`-absence check.

### Suggested commit message
```
fix(tui): log report generation to s19tui.log (N3 observability)

Report generation left no trace in the log: before/after and diff reports
logged nothing (incl. their refusal branches) and the project report logged
only a thin path-only success line + crash. Add format_report_log_line() +
S19TuiApp._log_report_event() (INFO ok / WARNING fail), wired at the three
app.py call sites, emitting a metadata-only line (kind, source, output,
outcome). Pure emitter services stay no-logging by design.
```

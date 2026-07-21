# Security Review — batch-59 (CRC Designer VIEW-FIDELITY rebuild)

> Phase-2 cross-review, SECURITY dimension (attack surface).
> Reviewer: security-reviewer. Date: 2026-07-21.
> Subject: `.dev-flow/2026-07-21-batch-59/01-requirements.md` + the shipped
> `s19_app/tui/crc_designer_view.py` (batch-58 baseline being re-composed).

## Scope reviewed
- The batch-59 requirements (5 US / 5 HLR / 10 LLR / 8 AT), specifically the ONE
  net-new attack surface: the live-rendered coverage window `#crc_coverage_window`
  (HLR-L1, LLR-L1.1/L1.2/L1.3).
- The batch-58 render sinks being re-nested verbatim (`crc_designer_view.py`:
  help/verdict/vector/preview/warnings/status/coverage Statics).
- The reused Load/Save path (`_save_template` / `_load_template`) for outbound /
  destructive-write regression.
- Frozen-set containment (`§2.4`).

BLUF: **One layout-only batch, one new render sink, no new outbound/destructive
surface.** The new sink is markup-safe *by construction* (markup=False is
mandated), but the requirements do NOT mandate a hostile-input acceptance test
for it — and the project's own markup-sink lineage says a "no-crash" boundary
check is insufficient. Verdict: **CHANGES-REQUESTED** (add the AT; no HIGH).

## Findings

### F1 — New live window has a mandated markup=False LLR but NO hostile-input AT  [Severity: MAJOR]
- **What:** The one net-new sink (`#crc_coverage_window`) is required to render
  `markup=False` (good), but no acceptance test drives a hostile string through
  it and asserts a LITERAL render. The requirements only assert "no crash" on
  malformed ranges (HLR-L1 boundary catalog: "invalid (malformed ranges →
  markup-safe note, no crash)"). That is a crash-only payload check.
- **Where:** `01-requirements.md` HLR-L1 / AT-B59-01 / AT-B59-02 / LLR-L1.1;
  the AT set proves glyphs + span-count + a range-edit delta, none of them a
  markup-injection payload.
- **Why it matters:** The project's own control lineage requires more here.
  MEMORY "Markup-sink SWEEP rule": *"Crash-only payloads insufficient — assert
  `plain` verbatim AND `spans == []`."* C-31 = assert-the-painted-result. The
  markup grammar for a `Static` is Textual `Content.from_markup`, where a payload
  like `[link=x]`, `[/]`, or a bare `[` raises `MarkupError` on the parse path if
  markup ever gets re-enabled — i.e. a future edit that drops `markup=False`, or
  a colored-span implementation that interpolates a style string, would inject or
  crash and NO test would catch it. Since batch-59's own US-L5 remit is "a
  fidelity gate with teeth (C-31)," omitting the markup-safety tooth for the
  single new sink is the exact gap this batch exists to close.
- **Recommendation:** Add one LLR + one AT (proposed **AT-B59-09**): with an
  image loaded, set `#crc_coverage_ranges` to a hostile string containing markup
  and ANSI metacharacters (e.g. `[link=evil]0x8000-0x8008[/]` and a token with a
  raw `[`), then read the mounted `#crc_coverage_window` rendered `Text` and
  assert (a) it does not crash, (b) the raw operator substring appears in
  `.plain` **verbatim**, and (c) the only style spans present are the window's
  own present/erased/pad-fill styles — no span whose payload derives from the
  input string (no injected `link`/style span). This mirrors the batch-58
  `load_save_and_markup` discipline for the preview sink and gives the new sink a
  regression guard rather than a construction-only guarantee.

### F2 — "int-only source, no untrusted string" claim is inaccurate on the fault branch  [Severity: MINOR]
- **What:** `§2.4` (C-17), `A3`, and LLR-L1.1 justify the window's safety as
  drawing "only from `mem_map` bytes + typed range ints (no untrusted string)."
  That is true on the happy path but NOT on the invalid-range branch the window
  is required to render.
- **Where:** `crc_designer_view.py:764` — `_parse_ranges` raises
  `ValueError(f"range {token!r} must be 'start-end'")`, echoing the raw operator
  token; HLR-L1 requires the window to render that fault as a "markup-safe note."
  So an operator-controlled string DOES reach the sink on the error branch.
- **Why it matters:** The safety therefore rests on `markup=False`, NOT on the
  source being int-only. This is not a vulnerability (markup=False is mandated),
  but the stated rationale would let a reviewer wave the sink through as
  "data-typed, can't inject" — which is the wrong mental model and directly
  reinforces why F1's hostile-string AT is needed rather than optional.
- **Recommendation:** Correct the LLR-L1.1 / C-17 rationale to "the sink renders
  `markup=False`; operator range text may appear verbatim on the fault branch and
  is rendered literally" and let F1's AT be the proof. No code change; a
  one-line accuracy fix to the requirement plus the F1 AT.

### F3 — No new outbound / destructive / external-write surface  [Severity: NONE — PASS]
- **What:** A view rebuild should add zero side-effecting surface; confirmed it
  does.
- **Where / evidence:**
  - Out of scope is explicit: "New functional behavior (no new field, no new
    compute, no new Load/Save path)" (`§1.2`); LLR-L4.1 requires the Load/Save
    handler bodies **byte-unchanged**.
  - The only file write remains the batch-58 template Save
    (`_save_template`, `crc_designer_view.py:952-1010`), untouched. Its basename
    is `sanitize_project_name`-normalized (`workspace.py:362-365` strips to
    `alnum | - | _` — no `/`, `\`, `.`, or `..` survives → path-traversal-proof)
    and the directory is fixed via `ensure_template_lib`. Confirmed the sanitizer
    is not in the batch-59 edit set.
  - The window is read-only over `mem_map` (US-V8 preview-only; R-4 mitigation;
    `_coverage_preview_text`/`_build_coverage_target` only READ `self.app`
    `current_file.mem_map`). No firmware write, no network, no process, no delete.
- **Recommendation:** None. Preserve the LLR-L4.1 byte-unchanged constraint and
  the US-V8 read-only assertion (R-4 / batch-58 AT-058-09) in the Phase-3 suite.

### F4 — Engine-frozen set respected  [Severity: NONE — PASS]
- **What:** Batch-59 must not touch the git-frozen engine modules.
- **Where / evidence:** `§2.4` lists the frozen set OFF-LIMITS
  (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
  `tui/mac.py`, `tui/color_policy.py` + the frozen test files) and constrains all
  edits to `crc_designer_view.py` (a VIEW — non-frozen), `styles.tcss`, and one
  non-frozen test file (`§5.3`, 3 files total). The window reuses
  `_build_target` / `compute_target_crc` / `evaluate_target` from
  `operations/crc_designer_model` **verbatim** (imports already present,
  `crc_designer_view.py:78-88`) — no engine edit, and that module is not in the
  frozen set regardless.
- **Recommendation:** None. Phase-3 runs `test_engine_unchanged.py` as the guard.

## Verdict
- [ ] OK to ship
- [x] **OK to ship with the listed mitigations applied first** — add the F1
      hostile-input AT (AT-B59-09) and the F2 rationale correction to the
      requirements before Phase-3 implementation closes.
- [ ] Block

No HIGH finding. The new attack surface is markup-safe by construction
(markup=False mandated at LLR-L1.2 and §2.4), reads `mem_map` read-only, and adds
no outbound/destructive/external-write path. The single actionable gap is a
missing regression test for the preserved C-17 control on the one new sink —
squarely inside this batch's own "fidelity gate with teeth / C-31" remit and
cheap to add.

## Evidence checklist
- [x] Each finding has what · where · why · recommendation — F1, F2 (F3/F4 are PASS records with evidence).
- [x] Each finding has a severity rating — MAJOR / MINOR / NONE-PASS.
- [x] No secret values in output — none present; nothing to redact.
- [x] Verdict explicit — OK-with-mitigations (add AT-B59-09 + fix F2 rationale).
- [x] New surface scope + blast radius addressed — the live window: markup=False
      by construction (scope), read-only over `mem_map`, no outbound/destructive
      (blast radius contained); reused Save path traversal-proof and untouched.
- [x] C-17 markup-safety of the new sink assessed — mandated (pass) but its
      hostile-input AT is missing (F1) and its "int-only" rationale is inaccurate
      on the fault branch (F2).

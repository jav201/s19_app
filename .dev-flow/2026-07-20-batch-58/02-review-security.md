# Security Review — batch-58 CRC Algorithm Designer view + engine prerequisites (Phase-2 cross-review, security lens)

## Verdict (BLUF)
**OK to ship with mitigations applied first.** No BLOCKER. The two NEW attack surfaces —
(a) the E5 template-file loader facade and (b) the view rendering template/file-derived text —
are correctly reasoned: the E5 facade REUSES the merged keel's collect-don't-abort posture
verbatim (object identity required, 0 parsing logic — cannot weaken it), and the preview-only
guard (R-010 / LLR-V8.1 / AT-058-09) is a real negative test over the write symbols. Two
non-blocking gaps to fix in the spec before Phase-3: the C-17 markup-safety enumeration is
non-exhaustive at the highest-risk sink (the JSON preview), and the Save path does not specify the
`sanitize_project_name` empty/None branch.

Counts: **0 blocker · 1 major · 2 minor.**

---

## Scope reviewed
- `.dev-flow/2026-07-20-batch-58/01-requirements.md` (artifact under review).
- `docs/crc-algorithm-designer/01-requirements.md` §10 (Security & risks).
- Reused posture, verified against merged keel `84180b4`:
  - `s19_app/tui/operations/crc_designer_model.py` — `read_template` (`:672`), `parse_template`
    (`:504`), `parse_job` (`:554`), `_build_target` (`:452`).
  - `s19_app/tui/operations/crc_config.py` — read-path contract mirror (`:1-80`).
  - `s19_app/tui/workspace.py` — `sanitize_project_name` (`:329`), `resolve_input_path` (`:483`).
  - `s19_app/tui/changes/io.py` — `READ_SIZE_CAP_BYTES`.

---

## Findings

### F1 — C-17 markup-safety enumeration is non-exhaustive; the JSON preview is the unguarded high-risk sink  [Severity: MAJOR]
- **What:** LLR-V5.3 mandates markup-safe rendering but scopes it with a closed-looking
  parenthetical — "(name, aliases, loader error, diagnostics)". The **live JSON preview**
  (HLR-V4 / LLR-V4.1) renders `emit_template(current_template)`, whose text embeds the file-derived
  `name` and `aliases`. A template named `[bold]x[/]` or carrying an ANSI escape flows into the
  preview verbatim. If the preview widget interprets markup (a `Static`/`Content.from_markup` sink,
  the exact class the project has been repeatedly bitten by — MEMORY markup-sink SWEEP rule), the
  payload injects there even though the name-label render site is markup-safe.
- **Where:** `01-requirements.md` LLR-V5.3 (`:428-434`), HLR-V4/LLR-V4.1 (`:221-234`, `:404-410`),
  and the hostile-input AT-058-06 (`:242-248`). AT-058-06 as worded ("a template named `[bold]x[/]`
  renders literally") does not name the preview site.
- **Why it matters:** the implementer can satisfy every named AT while leaving the preview an
  injection/rendering hole — the classic false-confidence surface (C-31). Same-firmware markup is
  low blast radius (no exfil, local TUI), but it is a shipped-defect regression against C-17 and
  the project's own SWEEP rule.
- **Recommendation:** (1) make LLR-V5.3 genuinely exhaustive — drop the closed parenthetical or
  extend it to "including the JSON preview text and any echoed custom-vector / coverage / preset
  label"; (2) extend AT-058-06 to assert the hostile name renders literally **at the JSON preview
  site** (assert `plain` verbatim AND `spans == []`), not only at the verdict/name label. Aligns
  with the design-doc §10 "any template-derived text shown renders `markup=False`".

### F2 — Save path does not specify the `sanitize_project_name` empty/None branch  [Severity: MINOR]
- **What:** `sanitize_project_name` strips to alnum + `-`/`_` and returns **`None`** when nothing
  survives (verified `workspace.py:329-332`). A hostile/pathological name made only of markup or
  punctuation (e.g. `[bold]`, `../`) sanitizes to empty → `None`. LLR-V5.2 says the filename is
  "normalized via the existing `sanitize_project_name` idiom" but does not define the `None` branch.
- **Where:** `01-requirements.md` LLR-V5.2 (`:420-426`); `workspace.py:329`.
- **Why it matters:** an unhandled `None` becomes a `None.crc.json` write or an `AttributeError`
  crash on the Save path — a self-inflicted DoS / bad-write from attacker-controlled input.
- **Recommendation:** LLR-V5.2 shall specify: when `sanitize_project_name` returns `None`, the Save
  handler surfaces a markup-safe "invalid template name" warning and writes **nothing** (no file).
  Add a boundary case to the save-KAT AT.

### F3 — Confirm the Save write target is app-controlled, not file/name-derived (hardening, no defect found)  [Severity: MINOR]
- **What:** the only write the view performs is `<lib>/<normalized name>.crc.json`. Traversal is
  already prevented — `sanitize_project_name` removes `/`, `\`, `.` so `..` and separators cannot
  survive into the basename. The **directory** (`<lib>`) must be an app-resolved template-library
  path, never derived from the loaded file or the template body.
- **Where:** LLR-V5.2 (`:420-426`), LLR-V8.1 (`:460-466`).
- **Why it matters:** the preview-only guarantee (R-010) depends on the single permitted write
  being bounded to the template lib; a file-derived directory would reopen a traversal path.
- **Recommendation:** state explicitly in LLR-V5.2 that the library directory is the app template-lib
  constant and only the basename comes from the (sanitized) name. No code change implied — this is a
  spec-explicitness item.

---

## What passed (evidence)

- **E5 facade reuses the posture verbatim — cannot weaken it.** `read_template` (`crc_designer_model.py:672-724`)
  already does: `resolve_input_path` → injectable `size_probe`/`st_size` size cap vs
  `READ_SIZE_CAP_BYTES` **before** `read_text` → `parse_template`; `parse_template` (`:504-551`) has
  the top-level-object guard (`:540`) and returns `(None, [one error])` on every fault, `Raises: None`.
  LLR-E5.1 requires the facade to be **object-identity** re-exports with **0 parsing logic**
  (`:324-330`) — it structurally cannot re-invent or loosen the posture. The spec does NOT invent a
  new posture (D-1, LLR-E5.2 "reuses `READ_SIZE_CAP_BYTES` … no new cap constant"). PASS.
- **DoS/size/traversal bounded.** Pre-read size cap enforced before bytes are read; `parse_job`
  enforces `RANGE_COUNT_CEILING = 4096` (`:611-613`); ranges bounded to the 32-bit space
  (`_build_target:465-490`); `resolve_input_path` is the same read-only, uncontained-by-design path
  used by the shipped `crc_config` loader (consistent, not a regression). PASS.
- **Preview-only guard is real.** LLR-V8.1 + AT-058-09 grep the view handlers for
  `emit_s19_from_mem_map|copy_into_workarea|write_crc_image|inject_crcs` (0 hits required) AND assert
  `current_file.mem_map` object-identity after exercising every control. The negative AT actually
  guards R-010. The sole write is the bounded `.crc.json` template. PASS (subject to F2/F3 explicitness).
- **No secret/PII surface.** CRC math + operator-supplied firmware addresses only; no credentials,
  tokens, or client PII flow through the loader or the view. No LFPDPPP client-data egress. PASS.

---

## Evidence checklist
- [x] Each finding has what · where · why · recommendation — F1/F2/F3 above.
- [x] Each finding has a severity rating — MAJOR / MINOR / MINOR.
- [x] No secret values in output — none present; CRC math only.
- [x] Verdict explicit — OK-with-mitigations (0 blocker).
- [x] New tool/integration scope + blast radius addressed — E5 loader is a local read-only file
      surface reusing the shipped posture verbatim (facade, object-identity, size-capped,
      collect-don't-abort); blast radius = one collected error / literal-rendered text; no outbound
      or destructive action, no new external connector.

---

## Verdict
- [ ] OK to ship
- [x] OK to ship with the listed mitigations applied first (F1 major + F2 minor folded into the spec before Phase-3)
- [ ] Block — must fix HIGH findings before ship

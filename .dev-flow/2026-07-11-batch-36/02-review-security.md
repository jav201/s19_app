# 02 — Security Review — batch-36 (US-058 / US-059 / US-060)

> Phase-2 independent cross-review. Reviewer: security-reviewer. Tree: worktree
> `heuristic-wu-1c7c49` @ base `7df60dd`. Scope: security / safety / destructive-action surface
> of the three stories as specified in `01-requirements.md` + `01b-qa-strategy-and-verification.md`.
> No code is modified by this review.

## Verdict

**PASS.** No HIGH or MEDIUM findings. The one destructive story (US-060) is confirmed
**safe** (nothing sensitive or needed is removed) and **working-tree-only** (no history rewrite).
Two LOW hygiene notes + one scope-change watch recorded below; none block.

## Scope reviewed
- Requirements + QA strategy for US-058 (compose/CSS patch-editor regroup), US-059 (static hex
  legend rows into modal + report), US-060 (delete 54 MB A2L duplicate + relocate 3 tracked files).
- Seams read: `s19_app/tui/legend.py` (full), `s19_app/tui/services/report_service.py:1290-1324`
  (`_legend_lines`), `s19_app/tui/screens.py:493-554` (`LegendScreen`), `.gitignore`, and the
  on-disk deletion/move targets under `tmp/stress_smoke/` and `examples/professional_validation/`.

## Findings

### S-01 — LegendScreen Labels render with console markup enabled  [Severity: LOW · US-059]
- **What:** `LegendScreen.compose` renders each row as `Label(f"{classification} — {meaning}", …)`
  with no `markup=False` (`screens.py:538`). Textual `Label` parses console markup by default, so a
  `[...]` token in a legend string would be interpreted as markup rather than shown literally.
- **Why it matters (low):** the new US-059 Hex rows — and every existing row — are **static
  in-repo literals** (`LEGEND_TABLE`, `legend.py:33-97`), never file-derived. There is no untrusted
  input path into this text, so this is not an injection vector; it is only a rendering-correctness
  concern if an author writes markup metacharacters into a meaning string. The proposed Hex meanings
  ("focused/highlighted byte range (goto/search target row)", "byte covered by a MAC record
  address") contain no `[`/`]`. This is the pre-existing pattern (all A2L/MAC/Issues rows render the
  same way today), not a regression introduced by batch-36.
- **Recommendation:** keep the two new Hex meaning strings free of Textual markup metacharacters
  (`[`/`]`); no code change required. (Contrast the batch-33 `markup=False` scrub — that hardening
  was needed for *file-derived* check/related-artifact text; static legend literals do not need it.)

### S-02 — US-060 deletions/moves must go through git, not raw FS  [Severity: LOW · US-060]
- **What:** the change deletes `examples/professional_validation/case_06_large_nested_a2l/` (4 files,
  56 MB A2L) and relocates the three tracked `tmp/stress_smoke/stress.{a2l,mac,s19}` into
  `examples/case_07_stress_smoke/`.
- **Why it matters (low):** a raw filesystem `rm`/move on git-tracked files can leave stale index
  entries or orphaned paths; `git rm` / `git mv` keeps the index consistent and — because history is
  NOT rewritten (see S-03) — makes the deletion fully reversible via `git revert`/checkout. Positive
  posture: recovery path exists (detection > prevention > recovery).
- **Recommendation:** implement with `git rm -r` / `git mv` (QA §3.3 M2 already requires
  `git ls-files tmp/stress_smoke` to be empty afterward). Verify `git status` shows the moves as
  rename/delete, not untracked orphans.

### S-03 — History rewrite explicitly out of scope; confirmed no sneak  [Severity: INFO · US-060]
- **What:** grep of the batch-36 spec dir for `filter-repo|filter-branch|force.?push|BFG|rewrite
  hist` returns matches only in the two **out-of-scope** disclaimers (`01-requirements.md:73`,
  `:488`). No implementation step performs or implies a history rewrite or force-push.
- **Why it matters:** confirms the destructive action is bounded to the working tree; the existing
  clone/history weight is intentionally not reclaimed, and no irreversible force-push is introduced.
  Any later attempt to reclaim history size would be a **separate, separately-approved** change
  requiring its own review.
- **Recommendation:** none; recorded as evidence that the working-tree-only bound holds.

## US-060 deletion-safety attestation (the load-bearing check)
Direct inspection of every deletion/move target — nothing sensitive or needed is removed:

| Target | Nature | Secret/PII? | License/attribution? | Verdict |
|---|---|---|---|---|
| `tmp/stress_smoke/stress.a2l` (2.5 KB) | synthetic `StressProject`/`MEAS_0000NN` fixture | none | none | safe to move |
| `tmp/stress_smoke/stress.mac` (545 B) | synthetic `# Stress-generated MAC fixture` | none | none | safe to move |
| `tmp/stress_smoke/stress.s19` (3.1 KB) | synthetic S-record image | none | none | safe to move |
| `…/pv/case_06_large_nested_a2l/firmware.a2l` (56 MB) | header: `"Synthetic professional dataset for S19Tool"`, `"Synthetic ECU module"` | none (sampled header; synthetic by construction) | none | safe to delete |
| `…/pv/case_06_large_nested_a2l/firmware.{mac,s19}` (240 KB / 19 KB) | synthetic | none | none | safe to delete |
| `…/pv/case_06_large_nested_a2l/README.txt` (110 B) | Spanish size description only | none | none | safe to delete |

- **Secret/PII scan** across the move targets + the pv README/.mac/.s19
  (`password|secret|api[_-]?key|token|BEGIN (RSA|OPENSSH|PRIVATE)|aws_|bearer|email`): **0 matches.**
- **License / NOTICE / copyright / attribution files** in either tree:
  `find … -iname *license* -o -iname *notice* -o -iname *copyright* -o -iname *attribution*` → **none.**
- **Vendor data:** the fixtures are self-labelled synthetic (`EPK "S19TOOL_PRO_SUITE"`); DF-2 in the
  spec already reconciles the "real-vendor" wording against the `MANIFEST.md:25` "synthetic, not tied
  to any OEM/ECU/vendor" statement. No genuine vendor firmware is exposed or lost.
- **Blast radius of the delete:** only `case_06_large_nested_a2l` under `professional_validation/` is
  targeted; the other seven cases (`case_01…case_08` minus `case_06`) are retained (verified
  present). The retained 36 MB `examples/case_06_large_nested_a2l/firmware.a2l` is present. Deleting
  a fixture can only *reduce* any theoretical data-exposure surface, never increase it.

## Relocation / path-confusion check (US-060)
- `.gitignore` ignores neither `examples/` nor `tmp/`. `git check-ignore` on
  `examples/case_07_stress_smoke/stress.{s19,a2l}` returns exit 1 (**not** ignored) → the relocated
  case will be tracked normally, no accidental drop into an ignored path.
- `tmp/stress_smoke/stress.s19` is currently tracked (check-ignore exit 1), so the move is a real
  `git mv`, not a copy of an ignored artifact.
- The runtime work-area (`.s19tool/workarea/temp/`, gitignored) is a **separate** namespace from the
  repo's `tmp/` directory — no path/name confusion between the relocation and the TUI's transient
  load area (`workspace.py`).

## US-058 (compose + CSS) attack-surface check
- LLR-058.3 constrains the change to **compose-tree + CSS only**: no `on_button_pressed` branch,
  no handler, no key binding altered, all 15 widget ids preserved (AT-058b census). CSS/layout
  geometry changes carry **no input/output surface, no external-state action, no command execution**.
  Nothing to review beyond confirming the no-behaviour-change contract, which the QA plan enforces
  via the id/wiring regression (AT-058b) + the frozen-module guards. **No new attack surface.**

## US-059 markup-safety / C-17 discharge (report + modal)
- **(a) No file-derived text interpolated.** Both surfaces iterate the static `LEGEND_TABLE`
  (`legend.py:33-97`); the two new Hex rows are hard-coded literals whose colour names are *read*
  (never written) from the engine-frozen `color_policy` constants. No S19/A2L/MAC file content, no
  user input, reaches the legend rows. The spec's blanket **C-17 = N/A** for all three stories (§3)
  is **correct** — C-17 governs render-mode flips over *file-derived* text, which none of these
  stories introduce.
- **(b) Report Markdown emission is consistent + static.** `_legend_lines`
  (`report_service.py:1317-1323`) f-string-interpolates `classification`/`colour`/`meaning` straight
  into `- **{classification}**{suffix} — {meaning}` with no escaping. Because every value is a
  reviewed static literal, there is no injection risk; the new Hex rows travel the identical path as
  the existing rows, so emission stays consistent. No change to the escaping posture is warranted for
  static content.

## Scope-change re-routing note (for Phase-3 / requirement amendments)
- US-059's report leg writes to `reports/*.md` through the **existing** `generate_project_report`
  path; US-059 adds only static rows to already-generated output — **no new external-write surface.**
- **Watch:** if a Phase-3 requirement amendment makes any legend row derive from *run data*
  (e.g. interpolating a loaded artifact's name/colour into the Hex meanings), that would (i) create a
  file-derived-text render path and **re-trigger C-17**, and (ii) require re-routing back through
  this security gate. As specified today, no such surface exists.

## Evidence checklist
- ✓ Each finding has what · where · why · recommendation — S-01/S-02/S-03 above.
- ✓ Each finding has a severity — LOW / LOW / INFO.
- ✓ No secret values in this output — scans referenced by location + result, never value; scan
  returned 0 matches regardless.
- ✓ Verdict explicit — **PASS** (no HIGH/MEDIUM).
- ✓ New tool/integration scope + blast radius — **none added** (no MCP/Composio/n8n/3rd-party
  connector, no new dependency, no auth flow); the only destructive surface is the US-060 in-repo
  fixture delete, whose blast radius is bounded (working-tree only, one pv case, reversible via
  retained history) and attested above.
- ✓ US-060 deletions confirmed safe (synthetic fixtures, no secrets/PII/license) and working-tree
  only (history rewrite grep-confirmed out of scope).

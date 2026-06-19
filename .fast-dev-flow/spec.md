# Quick Spec — s19_app

> Minimal spec for `/fast-dev-flow`. Goal: capture what's needed in 5-10 minutes without IEEE 830 overhead.
> **Hard rule:** acceptance criteria must be **observable** (input → verifiable output).

---

## 1. Objective (1 line)

Make the Operations view (which hosts the CRC operation) discoverable by surfacing its `x` keybinding in the TUI footer instead of leaving it hidden.

---

## 2. User stories (1-3, Connextra format)

- As a **TUI user who doesn't know the keymap**, I want **the Operations (CRC) action to be visibly listed in the footer**, so that **I can discover the operation exists without having to already know to press `x`**.

---

## 3. Acceptance criteria (3-7 bullets, observable)

- [ ] **AC-1 — `x` is footer-shown.** When the app is running on any rail screen, the footer's visible binding set (`app.active_bindings` filtered to `binding.show and enabled`) shall include the `x` key. (Today it does not, because the binding is `show=False`.)
- [ ] **AC-2 — the chip is labelled "Operations".** When `x` is shown in the footer, its rendered description shall be `Operations` (the existing binding description, unchanged).
- [ ] **AC-3 — the action still works.** When the user presses `x`, the system shall still open the Operations view (`action_operations_view` reachability is unchanged — only `show` flips).
- [ ] **AC-4 — no regression to the existing footer contract.** When the footer is rendered, the keymap §2 global set (`ctrl+k · ctrl+d · ctrl+l · ctrl+s · / · g · q`) and the per-screen paging keys shall still be present (TC-030 family stays green).
- [ ] **AC-5 — engine-frozen set untouched.** The change shall live only in `s19_app/tui/app.py`; no file in the engine-frozen set is modified (TC-031 family stays green).

---

## 4. Validation strategy (1 paragraph)

One new unit/integration test in `tests/test_tui_directionb.py` (the home of the existing TC-030 footer tests), reusing the established `_shown_footer_keys(app)` helper to assert `"x"` is in the shown footer set on every rail screen and that its `active_bindings` description is `"Operations"` (AC-1, AC-2). AC-3 is covered by the existing `_PRE_BATCH_BINDINGS` keyboard-reachability test (`x`/`operations_view` already asserted reachable) plus a focused press-`x` smoke if needed. AC-4/AC-5 are covered by the existing TC-030 (subset-based footer assertions) and TC-031 (engine-frozen diff) families — run the full suite to confirm zero regressions. Evidence to close: new test passes by name on disk + full suite green + `git diff` shows only `app.py` (one line) + the new test.

---

## 5. Non-goals (what is OUT)

- **No tier-policy redesign.** We are NOT deciding the footer/rail policy for the *other* hidden bindings (`1`–`8` screen switches, `l`, `s`, `p`, `t`, `r`, `o`, `v`, `j`). Only `x`/Operations flips to shown, per the operator's explicit scope choice. (The keymap-proposal.md §2 "uncrowded footer" rationale predates the Operations view; this is a deliberate, scoped exception for Operations discoverability, not a reversal of that rationale.)
- **No command-palette / help-screen / on-screen-hint work** (the other discoverability options the operator did not pick).
- **No change to the CRC operation itself or the Operations screen contents.**
- **No batch-13 sync work** — its `state.json` still reads `awaiting-sync` / `obsidian_synced:false` after the PR #18 merge; closing that is a separate `/dev-flow-sync` task.

---

## 6. Detected security flags

- [ ] Auth / identity (login, sessions, tokens, permissions)
- [ ] Secrets / config (.env, API keys, credentials)
- [ ] External integrations (webhooks, MCP, Composio, n8n, third-party)
- [ ] Sensitive data (PII, payments, health, encryption)
- [ ] Destructive DB (drop, delete, truncate, migrations)
- [ ] Input / attack surface (uploads, forms, sanitization, CORS)
- [ ] Network / exposure (new public endpoints, webhook receivers)

**`security_required`:** `false`

**Risk summary (if security_required = true):**
N/A — this is a single-attribute UI visibility flip (`show=False` → `show=True`) on an existing, already-wired keybinding. No new action, input surface, data path, or external interaction.

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-06-19 |
| Closed | 2026-06-19 |
| Promoted to /dev-flow | no |
| Notes | Routed here from `/dev-flow` (operator picked fast-dev-flow); design = footer-show `x`. Closed PASS, 0 defects. |

---

## 8. Close (filled in phase C)

### What changed
The Operations view — which hosts the CRC operation — was reachable only by the undocumented `x` key, with no on-screen affordance telling users it existed. Flipped the `x` binding from `show=False` to `show=True` in `s19_app/tui/app.py`, so it now renders as an `x Operations` chip in the TUI footer on every rail screen. Key, action (`operations_view`), and description are unchanged; only visibility flipped. Added one regression test pinning the new footer behavior.

### How it was tested
- New test `tests/test_tui_directionb.py::test_tc030_operations_binding_shown_in_footer` — asserts `"x"` is in the footer's shown set on every rail screen (AC-1) and that its description reads `"Operations"` (AC-2). Passes by node id.
- Existing TC-030 footer family + TC-031 engine-frozen guards — green (AC-3 reachability via `_PRE_BATCH_BINDINGS`; AC-4 footer contract; AC-5 frozen set untouched).
- Full suite: **862 passed, 29 skipped, 3 xfailed, 0 failed** (674s) — +1 vs the batch-13 baseline of 861 (the new test), no regressions.
- ruff: changed test file clean; `app.py` has 6 pre-existing F401/F402 errors (identical at HEAD — not introduced here).
- `git diff --stat`: only `app.py` (1 line) + `test_tui_directionb.py` (+35) changed.

### Open risks / pending
- Cosmetic only: one extra footer chip per screen.
- Out of scope (flag only): the 6 pre-existing ruff F401/F402 in `app.py`; tier-policy for the other hidden bindings (`1`–`8`, `l`, `s`, `p`, `t`…) was deliberately not addressed.
- Unrelated: batch-13 `state.json` still reads `awaiting-sync` / `obsidian_synced:false` after PR #18 merge — needs `/dev-flow-sync`.

### Security flags — handling
N/A — security_required was false (single-attribute visibility flip on an already-wired binding).

### Suggested commit message
```
feat(tui): surface Operations (CRC) binding in the footer

Flip the `x`/operations_view binding to show=True so the Operations
view (host of the CRC operation) is discoverable in the footer instead
of requiring users to already know the keybinding. Add a TC-030 footer
test pinning the visibility and the "Operations" chip label.
```

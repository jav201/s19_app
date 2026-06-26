# Quick Spec — s19_app · AT-gap closure (compare hex-window + CRC width)

> `/fast-dev-flow` batch. Two latent **black-box AT gaps** from prior batches, both **test-only** on already-shipped code. Cut fresh off `origin/main` `16ab9aab` (RC-1 PASS). English. Branch `claude/fdf-at-gaps`.

---

## 1. Objective (1 line)

Close two latent acceptance-test gaps with black-box ATs that observe *content* a blanked/regressed surface would otherwise pass silently: the A↔B compare **hex-window** panes (#6 / C-9), and the CRC save path's **S19 record width** (#7, reframed to a fixed-32 lock-AT).

---

## 2. User stories (Connextra)

- As an operator comparing two firmware images, I want the compare view's hex windows to actually show the selected run's bytes, so that I can trust the on-screen A/B hex is real and not a blank/stale pane.
- As an operator saving a CRC-injected image, I want the written `.s19` to keep its documented record width, so that a downstream tool reading the file gets the byte layout it expects.

---

## 3. Acceptance criteria (observable)

- [ ] **AT-COMPARE-HEX (#6 / C-9):** When the operator compares two on-disk S19 images that differ at known bytes and selects the changed run, the system shall render those exact differing bytes in `#diff_hex_a` AND `#diff_hex_b` — the AT asserts the specific hex byte values appear (not merely that the panes are non-empty / not the placeholder), and FAILS if either pane is blank. (C-10: non-default differing pair; assert content.)
- [ ] **AT-COMPARE-HEX-EQUAL (#6 boundary):** When the two compared images are byte-identical over the shared range and a run is selected, `#diff_hex_a` / `#diff_hex_b` shall render the same real bytes on both sides — a content assertion that still FAILS on a blanked pane (the boundary control distinguishing "real equal content" from "blank").
- [ ] **AT-CRC-WIDTH-32 (#7 lock):** When `write_crc_image` saves a CRC-injected image into the work area, the written `.s19`'s data records shall each carry ≤ 32 data bytes with at least one full 32-byte record (the current fixed contract) — read back off disk and asserted on actual per-record data-byte counts; a regression that changed the emitted width (e.g. to 16) FAILS this lock.

---

## 4. Validation strategy (1 paragraph)

Three black-box ATs, all driving the **shipped surface** and observing real artifacts; **no engine/source edits expected**. #6 extends `tests/test_tui_diff_compare_realpath.py`'s Pilot harness (`_drive_compare`): after `#diff_compare_button`, drive the run-selection that populates the hex windows, then read `#diff_hex_a` / `#diff_hex_b` `.render()` and assert the known differing bytes (fixtures via `emit_s19_from_mem_map`, existing pattern). The one Phase-B unknown to confirm: the run-selection mechanism is Pilot-drivable (the panes populate on run pick per screens_directionb.py:965). #7 adds a test near `tests/test_crc_operation.py` calling `write_crc_image` with a `tmp_path` workarea, reads the written `.s19` back (line inspection / `S19File`), and asserts per-record data-byte width — locking the default-32 contract. **Close evidence:** all 3 ATs GREEN; each shown to FAIL under its counterfactual per C-10 (blank-pane / placeholder for #6; width-flipped emit for #7); full `pytest -q -m "not slow"` stays green; 0 engine-frozen edits; `code-reviewer` pass.

---

## 5. Non-goals (what is OUT)

- **Making the CRC save honor an operator-selected width** — `write_crc_image` (crc.py:790) has no width parameter; threading a selection through it + the I5b confirm handler is a production **feature**, deferred to its own batch (logging to BACKLOG). This batch only LOCKS the current fixed-32 contract.
- No changes to diff/compare classification, the CRC algorithm, or any engine-frozen module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).
- No new UI, no new save/export surface.

---

## 6. Detected security flags

- [ ] Auth / identity
- [ ] Secrets / config
- [ ] External integrations
- [ ] Sensitive data
- [ ] Destructive DB
- [ ] Input / attack surface
- [ ] Network / exposure

**`security_required`:** `false`

Rationale: both items are read-only **observation** ATs on existing behavior. #6 reads rendered widgets; #7 reads a `.s19` the existing CRC path already writes into its contained work area. No new write/external surface, no auth/secrets/PII/network. (The CRC path's existing containment seam is unchanged and out of scope.)

---

## 7. Batch status

| Field | Value |
|-------|-------|
| Current phase | **closed** |
| Started | 2026-06-25 |
| Closed | 2026-06-25 |
| Promoted to /dev-flow | no |
| Notes | RC-1 PASS off origin/main 16ab9aab; branch claude/fdf-at-gaps. #7 reframed to fixed-32 lock-AT per operator (CRC save has no width param — feature deferred to BACKLOG). PASS: 3 ATs, 0 source/engine edits, suite 883/0. |

---

## 8. Close (phase C)

### What changed
Added 3 black-box acceptance tests closing two latent AT gaps, **test-only, 0 source/engine edits**. (#6/C-9) two ATs in `tests/test_tui_diff_compare_realpath.py` observe the compare hex-pane CONTENT (`#diff_hex_a`/`#diff_hex_b`) through the shipped Compare surface — one asserts the exact differing bytes per pane, one covers the no-run branch (C-10 (b)). (#7) one AT in `tests/test_crc_operation.py` reads the `write_crc_image`-written `.s19` back as text and locks the fixed 32-byte record width (the `S19File` map oracle is width-agnostic). BACKLOG updated: C-9 + CRC-lock marked done; the "CRC honours operator-selected width" feature logged as deferred.

### How it was tested
- `tests/test_tui_diff_compare_realpath.py` — 6 passed (4 existing + 2 new).
- `tests/test_crc_operation.py` — 13 passed (12 existing + 1 new).
- Full `pytest -q -m "not slow"` — **883 passed, 29 skipped, 3 xfailed, 0 failed**.
- **Counterfactuals (non-vacuity, C-10/QC-2):** blank-pane → compare-hex AT RED (`pane='Image A'`); 16-byte CRC emit → width lock RED (`widths=[16,16,16,16,4]`, value-discriminating). Independently re-verified by `code-reviewer` (blank + swapped + 16-byte, all RED).
- `code-reviewer`: APPROVE (1 LOW docstring nit, fixed). 3 new functions confirmed on disk.

### Open risks / pending
- None for this batch. Deferred (tracked in BACKLOG): making the CRC save honour an operator-**selected** width is net-new feature work (`write_crc_image` has no width param).

### Security flags — handling
`security_required: false` — no flags fired (read-only observation ATs; no new write/external/auth/secret surface). No security pass needed.

### Suggested commit message
```
test(tui): black-box ATs for compare hex-window content + CRC record width

Close two latent AT gaps (test-only, 0 source edits): observe the A↔B compare
hex panes (#diff_hex_a/b) through the shipped Compare surface (C-9), and lock the
CRC save path's fixed 32-byte S19 record width (the S19File map oracle is
width-agnostic). Both counterfactually shown RED. CRC selectable-width logged as
a deferred feature in BACKLOG.
```

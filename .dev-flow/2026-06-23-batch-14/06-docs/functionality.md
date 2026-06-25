# S19 Record Width + S0 Header — Operator Walkthrough (US-015)

> Phase 6 artifact. Owner: `docs-writer`. **Audience:** firmware engineers and
> technical stakeholders using the TUI. **Purpose:** understand how to choose the
> S19 output format on save and what each choice produces. Feature shipped in
> batch-14 (`2026-06-23-batch-14`).

## What this gives you

When you save a patched image from the **Patch Editor**, you can now choose how
wide each S19 data record is — **16 or 32 data bytes per record** — and, in
32-byte mode, the file is written with a **populated S0 header** instead of the
old empty one. The default is **32**. This is for downstream flashing and diff
tools (e.g. HxD-style hex viewers, some flashers) that require the wider record
and/or a header to accept the file.

Nothing about the firmware *data* changes — only the framing (how the bytes are
grouped into records) and the cosmetic header line. The bytes that get flashed
are identical regardless of which width you pick.

## How to pick 16 vs 32 at save-back

1. Open the **Patch Editor** and load / paste your change document as usual.
2. Apply the changes and proceed to **save-back**.
3. On the save-back surface there is a **cycling Width selector** (button id
   `#patch_saveback_width_button`). Click it to toggle between **32** and **16**.
   It starts on **32**.
4. Confirm the save. The chosen width is carried through to the S19 writer.

The selector is the only place you set this; the choice flows automatically into
the existing save path — no extra steps and no new save dialog.

## What each mode produces

| Mode | Data record width | S0 header |
|------|-------------------|-----------|
| **32** (default) | each S3/S2/S1 data record carries up to 32 data bytes | **populated** — see the preserve/synthesize rule below |
| **16** (legacy) | each data record carries up to 16 data bytes (byte-identical to the previous behavior) | **empty** (the legacy data-free S0) |

### The S0 header rule in 32-byte mode (preserve vs synthesize)

In 32-byte mode the S0 header is filled in by one of two rules:

- **Preserve** — if the image you loaded already had a content-bearing S0 header,
  that exact header is carried through to the output. (Example: a source S0 of
  `SRCHDR_PRESERVE_ME` is written back unchanged.)
- **Synthesize** — if the loaded image had no S0, or an empty one, a minimal
  ASCII header is generated from the **output filename**, bounded to at most 252
  bytes. An over-long header is rejected before anything is written (it raises an
  error rather than producing a malformed file).

In **16-byte mode** the S0 stays empty, preserving exact backward compatibility
with files produced before this feature.

## The data-integrity guarantee

Every emitted file is validated by **re-reading it through the same frozen
`S19File` reader** the rest of the tool uses, and comparing the result against the
image you intended to save. For both widths:

- the re-parsed **data-record map** (the S1/S2/S3 firmware bytes) is **byte-equal**
  to your in-app patched image — **0 byte difference**, and
- the reader reports **0 errors** on the output.

A negative control test confirms this check is real: deliberately corrupting one
data byte makes the comparison fail. So the guarantee is not vacuous — if the
emitter ever wrote the wrong bytes, the oracle would catch it.

Cross-format conversions were also checked at the new 32 default (S19 → re-parse,
HEX → S19, S19 → HEX): **0 byte delta, 0 errors** in every direction.

## A note on the S0 header: cosmetic, not payload

The S0 header is **cosmetic for data integrity**. It contributes **0 bytes to the
firmware payload**: it sits at low addresses that never overlap the real image
(which lives at high addresses), so populating it cannot change what gets flashed.
Its only purpose is that some downstream tools *display or key on* the header
label. Picking 32-byte mode with a header is therefore safe by construction — the
flashed data is the same as 16-byte mode with no header.

> Technical footnote: the frozen reader folds every record's data into its full
> memory map by address, including the S0 at address 0. So the S0 bytes do appear
> in the *full* `get_memory_map()` at low addresses — but they never collide with
> the high-address payload, which is why inertness is asserted against the
> **data-record map** (S1/S2/S3 only). See Amendment B in
> `01-requirements.md` §6.5b.

## Scope notes

- The record **type** (S1/S2/S3) is still chosen automatically by the maximum
  address — this feature does not change that.
- Only **16** and **32** are valid widths; any other value is rejected.
- This is wired through the **Patch Editor save-back** surface (the project-save
  path threads the 32 default). There are no CLI flags for it in this batch.
- The Intel-HEX writer is unchanged (it stays at 16 bytes/record); the S19-only
  width setting does not affect HEX saves.

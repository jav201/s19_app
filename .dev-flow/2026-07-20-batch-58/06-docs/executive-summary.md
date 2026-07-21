# Executive Summary — batch-58: CRC Algorithm Designer (Variant B view)

## Context
Firmware for these ECUs is protected by a CRC checksum. Until now the tool could only compute the one hard-wired 32-bit CRC. Operators working with different ECUs need to *tailor* a CRC variant (different width, polynomial, seed, reflection, memory coverage) and be sure it's correct before trusting it.

## Problem
There was no way inside the tool to define a custom CRC, prove it matches a device's reference value, or see how different memory-coverage choices change the result — all of that lived in external notes and guesswork, which is error-prone on a safety-relevant checksum.

## Solution
A new **CRC Algorithm Designer** screen (rail key `0`). The operator picks a starting preset or types the parameters, and the tool **immediately shows whether the CRC matches the standard known-answer value** as they edit. They can check it against a device-supplied test vector, preview the CRC over the actually-loaded firmware under different "fill the gaps or not" policies, and save the design as a reusable file. A built-in safety check warns when a "fill" policy would pad over a region that actually still holds data — the exact case where a previewed CRC would silently disagree with the device. The screen is **preview-only**: it never modifies firmware.

## Outcomes
- **Any-width CRC (8–64 bit)** with full parametric control, replacing the 32-bit-only limit.
- **Live correctness proof** against the standard known-answer test — a wrong design is visible instantly, not after a failed flash.
- **Coverage preview over real firmware** with side-by-side gap policies + a gap-safety guard.
- **Reusable, shareable templates** (JSON), loaded/saved safely (hardened against malformed or hostile files).
- Shipped **additively** — the existing CRC operation is untouched; **zero changes to the frozen safety-critical parsing engine**.

## Quality
11 user stories, fully traced (every story has an automated black-box acceptance test through the real screen, plus white-box unit tests). Every code increment passed an independent review (the file-handling increment also a security review — confirmed traversal-proof and injection-safe). 1757+ tests green; ~90 new for this feature.

## Next steps
- A cosmetic follow-up regenerates the terminal-layout baseline images (the new rail icon shifts them) — mechanical, done in the standardized CI environment.
- Wiring the new any-width engine into the existing write path, and a few minor polish items, are queued as follow-ups. None blocks this delivery.

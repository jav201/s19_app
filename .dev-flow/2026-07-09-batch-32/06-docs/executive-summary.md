# Executive summary — batch-32: multi-region CRC groups

**Audience:** non-technical stakeholders. **Purpose:** what shipped, why it matters, how quality was
assured, and what remains before full trust.

## Context

Firmware images are often checked for corruption using a CRC — a compact fingerprint stored inside
the image itself. Until now the tool could compute one fingerprint per memory region. Many real
firmware build processes instead take **several separate regions**, stitch them together **in a
specific order**, and compute **one single fingerprint** for the whole set. Operators could not
reproduce that workflow, which is exactly the check they need when verifying or repairing production
images. This was the top-priority item (B-21) from the operator's baseline review.

## What shipped

- Operators can now declare **groups** of memory regions in the existing configuration editor. Each
  group produces one CRC, stored at one chosen address.
- The **size of the stored fingerprint field is configurable** (1, 2, 4, or 8 bytes) to match how
  different targets lay out their memory; risky choices (undersized fields) work but raise a warning.
- The tool **warns instead of failing** on suspicious situations — missing bytes inside a declared
  region, or a fingerprint written on top of data that feeds another fingerprint — so the operator
  always gets a complete result plus clear notices.
- **Nothing changes for existing users:** every configuration written before this release parses and
  behaves exactly as before, byte for byte.

## Quality evidence

- **23 acceptance tests**, each tied to exactly one automated test in the codebase — a full
  requirements-to-test audit trail with zero gaps (see the accompanying traceability matrix).
- **Backward compatibility double-proven:** the "old configs behave identically" guarantee is pinned
  by a golden test whose expected value was independently reproduced by a second reviewer against the
  previous engine — not just re-computed by the new code.
- **Independent reviews** (architecture, QA, and security) ran in parallel before implementation:
  no blockers; all findings were folded into the requirements and verified in tests, including new
  safety limits on configuration size and address ranges.
- The protected core parsing engine was **not touched** (0 changes, guard tests confirm it), and the
  full test suite grew from 49 to 110 CRC-related tests, all passing.

## Next steps

- **Before trusting automatic fingerprint injection on real firmware**, the operator should validate
  one real production configuration against their own build tool: confirm the tool and this feature
  produce the same CRC for the same regions. Our tests prove the mathematics are wired correctly,
  but only that comparison proves it matches a specific vendor's process.
- Candidate follow-ups (on file, not committed): a guided form for building group configurations, and
  an optional "fill missing bytes" mode for tools that fingerprint padded memory.

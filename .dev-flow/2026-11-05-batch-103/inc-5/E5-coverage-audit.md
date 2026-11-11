# Inc 5 — independent coverage audit

**Verdict: PASS-WITH-NOTES.** Final static audit by Kimi (`agent-37`), after two corrective rounds. No HIGH/MAJOR coverage gap remains.

The final audit confirmed real operator routes and visible read-backs; success outcomes through the real seam; Split/Join model verification before any read-back repaint; exact row counts, names, addresses, lengths and values; Memory Map ordered ranges and content; complete STATE snapshots including visible cells, Split text and recursive project hashes; real API spies for worker/UI delivery; and `.028` rejection through a real worker with deliberate generation-stamp mismatch injection. Picker cells that the terminal elides assert their visible `u8`/`u16` prefix while the complete format (including `%.3`) is asserted in the picker model.

Non-blocking notes:

1. `.028` injects each mismatch into the prepared snapshot before releasing the real worker; it proves both preflight refusals and atomic preservation, not a naturally timed concurrent product transition. The ledger names this injection explicitly.
2. Generic SNAP read-back may cycle Split/Join to its A2L tab, which can repaint. The dedicated `.016` cases keep that tab visible throughout the transition and read it without reactivation, so the required visible behavior is covered directly.
3. The static verdict does not replace a complete runtime GREEN on the final test tree. That run is recorded separately in `04-validation.md` and the canonical evidence path.

Earlier FAIL findings — internal-only oracles, missing order/outcome assertions, incomplete STATE and project hashes, weak UI-thread spies and direct internal `.028` setup — were corrected before this verdict.

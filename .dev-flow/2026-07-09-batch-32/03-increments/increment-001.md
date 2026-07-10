# Increment 001 — groups schema + parser (LLR-GRP-001.1/.2/.3/.14/.15)

1. **What changed** — `CrcGroup` dataclass; `CrcConfig.groups` (defaulted); `_build_config` presence rule widened (section 6.5 amendment #1 LANDED: "regions must contain at least one region" -> "at least one of regions/groups present and non-empty"); new `_build_group` with N5 REJECT (inverted/zero-length span), N6 REJECT (stray output_address in a span, targeted tripwire), ALLOWED_OUTPUT_BYTES {1,2,4,8}, CRC_SPAN_COUNT_CEILING=4096 (deliberately tighter than MF_ENTRY_COUNT_CEILING=100k because each span costs a full mem_map scan — rationale in the constant docstring), 32-bit bounds incl. output window (groups-only; legacy tolerant for AT-044a).
2. **Files** — s19_app/tui/operations/crc_config.py, tests/test_crc_config.py (2 of <=5).
3. **How to test** — `pytest tests/test_crc_config.py -q`.
4. **Results** — 33 passed (15 base intact + 18 new: AT-044b value round-trip TC-201.1, default-4 TC-201.2, legacy-empty-groups sanity, AT-044d 14 parametrized rejection cases TC-201.3, allowed-widths TC-201.4). **RED counterfactual captured**: `git stash` of crc_config.py -> new module fails collection (group symbols absent = trigger-absent, specced reason) -> pop -> 33 green. Ledger: base 49 -> 67 CRC-file tests (+18, -0).
5. **Risks** — ceiling value 4096 is a judgment call (operator may override); the section 6.5 amendment changes the missing-regions error string (no existing test pinned it — verified by the 15-green base).
6. **Pending** — Inc-2 group compute + width codec; independent code-review dispatched.
7. **Next** — Inc-2.

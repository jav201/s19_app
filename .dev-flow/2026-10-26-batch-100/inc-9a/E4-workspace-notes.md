# E4 notes — G1 (`workspace.py`) implementation

Spec followed: `proto-9a-workspace.md`, `interfaces-9a.md` ("Applied after E3 r1"),
`E3-rulings.md` R1–R17, `01-requirements.md` HLR-172 / HLR-172b / LLR-172.*.

Only `s19_app/tui/workspace.py` was edited. CRLF line endings preserved
(verified: 0 bare-LF lines; `python -m py_compile` passes with the s19env
interpreter). No test suite was run; the pure functions were verified with
standalone scratch scripts (byte counts, kind table, entry checks, read/record
round-trip, 65 536/65 537 size arms, hostile shapes).

## Functions / classes added or changed (line numbers in the final file)

- `import json` (line 3) — added.
- `from pathlib import Path, PureWindowsPath` (line 15) — changed (added `PureWindowsPath`).
- `RECENT_STORE_DIRNAME` / `RECENT_STORE_FILENAME` (2046–2047) — new module constants.
- `RECENT_STORE_MAX_BYTES: int = 65_536` (2049) — new (LLR-172.2a / LLR-172.1m).
- `RECENT_LIMIT: int = 20` (2051) — new (LLR-172.1c / LLR-172.2).
- `RECENT_PROBLEM_TOO_LARGE = "too large"` (2053), `RECENT_PROBLEM_UNREADABLE = "could not be read"` (2054) — new (seam S5).
- `_DRIVE_ROOTED_RE` (2057) — new private compiled regex `^[A-Za-z]:[\\/]`, shared by `recent_store_path` and `_recent_entry_ok` (D-1 / R5).
- `RecentEntry` (2061) — new frozen dataclass (`path: str`, `kind: str`).
- `RecentSources` (2083) — new frozen dataclass (`entries: tuple[RecentEntry, ...]`, `problem: Optional[str]`).
- `recent_store_path` (2101) — new.
- `recent_kind` (2138) — new.
- `_recent_entry_ok` (2180) — new.
- `read_recent_sources` (2237) — new.
- `_encode_recent_store` (2338) — new.
- `record_recent_source` (2389) — new.
- `list_workarea_files` (2525) — new.

## Graph node -> code location

- `recent_store_path` -> `workspace.py:2101`
- `recent_kind` -> `workspace.py:2138`
- `RecentEntry` -> `workspace.py:2061`
- `RecentSources` -> `workspace.py:2083`
- `_recent_entry_ok` -> `workspace.py:2180`
- `read_recent_sources` -> `workspace.py:2237`
- `_encode_recent_store` -> `workspace.py:2338`
- `record_recent_source` -> `workspace.py:2389`
- `list_workarea_files` -> `workspace.py:2525`
- `_is_reparse_point` -> unchanged (`workspace.py:207`), reused by `read_recent_sources` (link check), `record_recent_source` (store-folder check), `list_workarea_files` (temp + each entry).
- `is_windows_device_name` -> unchanged (`workspace.py:1833`), reused by `_recent_entry_ok` per path component.
- Entity `[I/O: recent-sources store]` -> read arm in `read_recent_sources`, replace arm in `record_recent_source`; the `_RECENT_LOCK` entity removed by E3 R8 never existed at base, so nothing was removed.
- The four extension sets (`workspace.py:107-110`) and `RESERVED_WORKAREA_HOMES` (`:43`) are unchanged and read by `recent_kind` / G2.

## Deviations

1. `read_recent_sources` success-path debug line logs `problem=%s` with the
   literal word `"none"` (the problem is `None` on that arm). The graph only
   requires "at most 1 debug line with the counts (accepted, refused) and the
   problem word"; there is no problem word when the read succeeds, so the
   word `none` is emitted in its place. No path text is ever logged.
2. `_encode_recent_store` with an empty input returns the valid empty store
   document (32 bytes, `{"schema_version":1,"sources":[]}`) rather than
   `b""`. This arm is unreachable from `record_recent_source` (step 7 always
   yields at least the new entry after step 4 accepts it), so it is a
   harmless fallback, kept for correctness.

No other deviations: every step, token, size arm and order of checks follows
the graph character-for-character (verified against the example byte counts
65 / 65 492 / 62 314, the 65 536/65 537 size arms, the six path forms, the
device-name and control-character arms, and the 1 000 -> 20 + mixed-order
read arms).

## Open questions

- Whether the read debug line should omit the `problem=` field entirely on
  the success arm (no test asserts it; the only hard constraints are DEBUG
  level and no path text).
- `_encode_recent_store([])` is unspecified; noted as a fallback above, not
  exercised by any 9a example.

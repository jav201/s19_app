# Inc 11 E5 lane B — DeepSeek coverage closure (two residual findings)

Lane: batch-103 Inc 11 E5 lane B (DeepSeek tester).
Owned file: `tests/test_b103_a2l_reader.py` only.
Source of the two residuals: `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-completion-report.md`.

## Changes made (exact)

### (1) R-A2L-READ.48/1 — add the ≤120 s elapsed-time assertion

File `tests/test_b103_a2l_reader.py`.

- Added `import time` to the top import block (after `import subprocess`).
- `test_r_a2l_read_48_tracked_files_equal_ref` now times the real tracked-file
  differential loop and asserts the bound:

```python
def test_r_a2l_read_48_tracked_files_equal_ref(ref: Callable[[str], dict]) -> None:
    """R-A2L-READ.48/1: the 35 tracked files equal the reference reading."""
    started = time.monotonic()
    for path in _tracked_a2l():
        text = path.read_text(encoding="utf-8", errors="replace")
        data = parse_a2l_file(path)
        reading = ref(text)
        _assert_sections_equal(data["sections"], reading["sections"])
        _assert_tags_equal(data["tags"], reading["tags"])
        _assert_spans_equal(_spans(data), reading["spans"])
        _assert_errors_equal(data["errors"], reading["errors"])
        del data, reading
    elapsed = time.monotonic() - started
    assert elapsed <= 120, f"tracked-file differential took {elapsed:.1f}s, exceeding 120s"
```

The bound is the existing requirement bound (`≤ 120 s`, `02-test-cases.md:287`);
it is enforced exactly (`<= 120`), not weakened. Timing covers the parse + REF
comparison loop for all tracked `.a2l` files.

### (2) R-A2L-READ.49/2 — D5 uses the exact required layout name

File `tests/test_b103_a2l_reader.py`, inside
`test_r_a2l_read_49_2_defect_classes_hand_written`, the D5 second reduction
(`d5b`).

Before:

```python
"/begin RECORD_LAYOUT RL_SWORD\nFNC_VALUES 1 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
'/begin CHARACTERISTIC CK6B ""\n VAL_BLK 0x3000 RL_SWORD 0 CM_ID 0 65535\n MATRIX_DIM 3 4 1\n/end CHARACTERISTIC'
```

After:

```python
"/begin RECORD_LAYOUT RL.FNC.SWORD.ROW_DIR\nFNC_VALUES 1 SWORD ROW_DIR DIRECT\n/end RECORD_LAYOUT\n"
'/begin CHARACTERISTIC CK6B ""\n VAL_BLK 0x3000 RL.FNC.SWORD.ROW_DIR 0 CM_ID 0 65535\n MATRIX_DIM 3 4 1\n/end CHARACTERISTIC'
```

Both the `RECORD_LAYOUT` declaration and the `VAL_BLK` reference now use the
exact requirement name `RL.FNC.SWORD.ROW_DIR` (the `RL_<type>`-shaped suffix no
longer encodes a datatype keyword). Expected values are preserved:

- D5 first arm (`RL_U16`, `MATRIX_DIM 4`) → length `8` (unchanged).
- D5b (`RL.FNC.SWORD.ROW_DIR`, `FNC_VALUES 1 SWORD ROW_DIR DIRECT`,
  `MATRIX_DIM 3 4 1` = 12 elements × SWORD 2 bytes) → length `24` (unchanged).

No other case was changed.

## Verification status

- Local syntax check: `python -m py_compile tests/test_b103_a2l_reader.py`
  → `PY_COMPILE_OK` (Windows, local repo checkout).
- Linux pytest: **NOT RUN — SSH unavailable.** The runner
  `javiergr@192.168.1.67` (cachyos-rtx) is unreachable from this machine:
  `ssh: connect to host 192.168.1.67 port 22: Connection timed out` and
  `ping` reports `Destination host unreachable` from 192.168.1.66.
  Per the lane instructions, the change is implemented and py_compiled, and the
  Linux run is left as **pending evidence**.

Intended Linux command (pending runner availability):

```
/home/javiergr/miniconda3/envs/s19ci/bin/python
```

with an isolated `/tmp/b103-e5-11-deep-b/zq_iso_user` user, closed stdin,
`PYTHONDONTWRITEBYTECODE=1`, and the package path printed first.

## Scope guard

- Only `tests/test_b103_a2l_reader.py` was edited.
- No product, other tests, perf, records, or commits were touched.
- No git mutation, no child agents, no clipboard use.

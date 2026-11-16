from __future__ import annotations

import csv
import json
import re
import sys
from pathlib import Path

EXPECTED_HEAD = {
    "base": "e4485817d7ac3706c77f14a4c2a8cf784fe35038",
    "tip": "31f28f5e9209eb6eaa7957a0362656fa30973df9",
}


def main() -> int:
    out = Path(sys.argv[1])
    rows = list(csv.DictReader((out / "fx9c-correction-status.tsv").open(), delimiter="\t"))
    if len(rows) != 2:
        raise ValueError(f"expected two corrected probes, found {len(rows)}")
    result = {}
    for row in rows:
        path = out / Path(row["transcript"]).name
        text = path.read_text(encoding="utf-8")
        side = row["side"]
        if row["test_rc"] != "0" or row["validation"] != "PASS" or "Q9B_VALID=PASS" not in text:
            raise ValueError(f"corrected probe did not pass: {path.name}")
        if f"Q9B_HEAD={EXPECTED_HEAD[side]}" not in text:
            raise ValueError(f"wrong HEAD: {path.name}")
        load = float(row["load1"])
        if load >= 1.0:
            raise ValueError(f"loaded run: {path.name}")
        payload = json.loads(re.findall(r"FX9CPARTS (\{.*\})", text)[0])
        block = payload.get("refresh_block")
        if not isinstance(block, (int, float)) or block < 0:
            raise ValueError(f"missing whole block: {path.name}")
        result[side] = {
            "load": load,
            "refresh_block": block,
            "parts": payload["parts"],
            "after_stage": payload["after_stage"],
        }
    (out / "fx9c-correction.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("| Side | Part | Start s | Duration s |")
    print("|---|---|---:|---:|")
    for side in ("base", "tip"):
        parts = result[side]["parts"]
        stage_start = next(part[1] for part in parts if part[0] == "_stage_bench_record")
        print(f"| {side} | **whole write+refresh, stage entry→record_done** | {stage_start:.3f} | **{result[side]['refresh_block']:.3f}** |")
        for name, start, duration in parts:
            if name != "_paint":
                print(f"| {side} | {name} | {start:.3f} | {duration:.3f} |")
        paints = [duration for name, start, duration in parts if name == "_paint"]
        print(f"| {side} | `_paint` callbacks over 0.05 s: n={len(paints)}, total={sum(paints):.3f} s, max={max(paints):.3f} s | — | — |")
    print(f"\nCorrected probes: 2/2 PASS; loads {result['base']['load']:.2f} / {result['tip']['load']:.2f}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

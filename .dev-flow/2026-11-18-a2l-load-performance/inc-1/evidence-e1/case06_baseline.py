from __future__ import annotations

import argparse
import gc
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from s19_app.tui import a2l_definition  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limits", default="1000,4000")
    parser.add_argument("--repetitions", type=int, default=1)
    args = parser.parse_args()
    limits = [int(value) for value in args.limits.split(",")]
    if not limits or any(value < 1 for value in limits) or args.repetitions < 1:
        raise SystemExit("limits and repetitions must be positive")

    case_path = ROOT / "examples/case_06_large_nested_a2l/firmware.a2l"
    started = time.perf_counter()
    a2l = parse_a2l_file(case_path)
    parse_seconds = time.perf_counter() - started
    names = list(dict.fromkeys(tag["name"] for tag in a2l["tags"]))
    if len(a2l["tags"]) != 220040 or len(names) != 220040:
        raise AssertionError((len(a2l["tags"]), len(names)))
    if max(limits) > len(names):
        raise SystemExit("a limit exceeds the case_06 population")

    real_overlap = a2l_definition._entry_overlaps
    checks = 0

    def counted_overlap(definition, entry):
        nonlocal checks
        checks += 1
        return real_overlap(definition, entry)

    a2l_definition._entry_overlaps = counted_overlap
    runs = []
    try:
        for repetition in range(1, args.repetitions + 1):
            for limit in limits:
                gc.collect()
                gc.disable()
                checks = 0
                started = time.perf_counter()
                result = a2l_definition.describe_definitions(names[:limit], a2l)
                elapsed = time.perf_counter() - started
                gc.enable()
                if list(result) != names[:limit]:
                    raise AssertionError("the describe result does not match the requested names")
                runs.append(
                    {
                        "repetition": repetition,
                        "requested": limit,
                        "available": len(names),
                        "results": len(result),
                        "overlap_checks": checks,
                        "shared_with_not_none": sum(
                            definition.shared_with is not None for definition in result.values()
                        ),
                        "describe_seconds": elapsed,
                    }
                )
                del result
    finally:
        gc.enable()
        a2l_definition._entry_overlaps = real_overlap

    report = {
        "schema": "a2l-load-performance/inc-1/case06-baseline/v1",
        "status": "observation-only; no new requirement threshold was evaluated",
        "command": f"python {Path(__file__).name} --limits {args.limits} --repetitions {args.repetitions}",
        "root": "<repo>",
        "head": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip(),
        "base": subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "f44e8bc4"], text=True).strip(),
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "ci": os.environ.get("CI", ""),
        "case": {
            "path": case_path.relative_to(ROOT).as_posix(),
            "bytes": case_path.stat().st_size,
            "sha256": hashlib.sha256(case_path.read_bytes()).hexdigest(),
            "tags": len(a2l["tags"]),
            "unique_names": len(names),
            "addressed_tags": sum(tag.get("address") is not None for tag in a2l["tags"]),
            "tags_without_length": sum(tag.get("length") is None for tag in a2l["tags"]),
            "declared_spans": len(a2l.get("declared_spans") or []),
            "parse_errors": len(a2l.get("errors") or []),
        },
        "parse_seconds_not_in_describe_measurements": parse_seconds,
        "runs": runs,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

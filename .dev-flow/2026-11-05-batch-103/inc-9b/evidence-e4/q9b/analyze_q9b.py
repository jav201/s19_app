from __future__ import annotations

import csv
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

GAP_SEGMENTS = {
    "key_to_action": ("key", "action_move"),
    "action_to_selection": ("action_move", "selection_changed"),
    "selection_to_enqueue": ("selection_changed", "enqueue_decode"),
    "enqueue_to_active_K2": ("enqueue_decode", "active_job"),
    "active_to_run": ("active_job", "run_job"),
    "run_to_busy_paint": ("run_job", "paint_busy"),
}
EXPECTED = {
    ("gap", "a"): 10,
    ("gap", "b"): 10,
    ("gap", "c-press"): 10,
    ("gap", "c-post"): 10,
    ("gap", "d"): 10,
    ("oe", "29_1"): 10,
    ("oe", "29_2"): 10,
    ("oe", "82_1"): 10,
    ("oe", "20_1"): 10,
    ("fx9c", "parts"): 2,
    ("timing", "94_1"): 5,
    ("timing", "94_2"): 5,
    ("timing", "94_3"): 5,
    ("timing", "97_1"): 5,
    ("timing", "97_3"): 5,
    ("timing", "98_1"): 5,
    ("timing", "99_1"): 5,
}
MARGIN_RE = re.compile(
    r"(?m)^(?:LOW )?(-?[0-9.]+)%  ([0-9.]+) s / ([0-9.]+) s  ([^ ]+(?: [^ ]+)*)  ([^ ]+)$"
)


def dist(values: list[float]) -> dict[str, float | int | list[float] | None]:
    return {
        "n": len(values),
        "p50": statistics.median(values) if values else None,
        "max": max(values) if values else None,
        "values": values,
    }


def event_map(payload: dict) -> dict[str, float]:
    result = {}
    for event in payload["events"]:
        result.setdefault(event["m"], event["t"])
    return result


def gc_values(payload: dict, key: float, end: float) -> tuple[float, int, float]:
    starts: list[float] = []
    overlap = 0.0
    before = 0.0
    count = 0
    for event in payload["events"]:
        if event["m"] == "gc_start":
            starts.append(event["t"])
        elif event["m"] == "gc_stop" and starts:
            start = starts.pop(0)
            stop = event["t"]
            covered = max(0.0, min(stop, end) - max(start, key))
            if covered:
                overlap += covered
                count += 1
            if stop <= key:
                before += stop - start
    return overlap, count, before


def parse_margin(text: str, requirement: str) -> dict[str, float | str]:
    for match in MARGIN_RE.finditer(text):
        margin, measured, bound, label, node = match.groups()
        if label.startswith("R-PE-BENCH." + requirement):
            return {
                "margin_pct": float(margin),
                "measured": float(measured),
                "bound": float(bound),
                "label": label,
                "node": node,
            }
    raise ValueError(f"no margin for {requirement}")


def main() -> int:
    out = Path(sys.argv[1])
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    rows = list(csv.DictReader((out / "status.tsv").open(), delimiter="\t"))
    if mode == "gap-only":
        rows = [row for row in rows if row["family"] == "gap"]
    errors: list[str] = []
    valid_rows = []
    measurement_rows = []
    counts = defaultdict(int)
    for row in rows:
        counts[(row["family"], row["label"])] += 1
        path = out / Path(row["transcript"]).name
        if not path.is_file():
            errors.append(f"missing transcript: {path.name}")
            continue
        text = path.read_text(encoding="utf-8")
        expected_head = {
            "base": "e4485817d7ac3706c77f14a4c2a8cf784fe35038",
            "tip": "31f28f5e9209eb6eaa7957a0362656fa30973df9",
        }[row["side"]]
        heads = re.findall(r"(?m)^Q9B_HEAD=([0-9a-f]{40})$", text)
        if heads != [expected_head]:
            errors.append(f"wrong or missing source HEAD: {path.name}")
            continue
        loads = re.findall(r"(?m)^Q9B_LOAD1=([0-9.]+)$", text)
        if len(loads) != 1 or float(loads[0]) >= 1.0:
            errors.append(f"invalid quiet-host load: {path.name}")
            continue
        row["text"] = text
        row["load"] = float(loads[0])
        if row["test_rc"] == "0" and row["validation"] == "PASS" and "Q9B_VALID=PASS" in text:
            valid_rows.append(row)
            measurement_rows.append(row)
            continue
        requirement = row["label"].replace("_", "/", 1)
        has_margin = any(
            match.group(4).startswith("R-PE-BENCH." + requirement)
            for match in MARGIN_RE.finditer(text)
        )
        measured_failure = (
            row["test_rc"] == "1"
            and row["family"] in {"oe", "timing"}
            and re.search(r"(?m)=+ 1 failed in [0-9.]+s.*=+$", text)
            and (row["label"] == "97_1" or has_margin)
        )
        if measured_failure:
            measurement_rows.append(row)
        else:
            errors.append(f"invalid or marker-empty run excluded: {path.name}")
    expected_counts = EXPECTED if mode == "full" else {
        key: value for key, value in EXPECTED.items() if key[0] == "gap"
    }
    for key, expected in expected_counts.items():
        if counts[key] != expected:
            errors.append(f"run count {key}: {counts[key]} != {expected}")

    gap: dict[str, dict] = {}
    for scenario in ("a", "b", "c-press", "c-post", "d"):
        selected = [r for r in valid_rows if r["family"] == "gap" and r["label"] == scenario]
        segment_values: dict[str, list[float]] = defaultdict(list)
        totals = []
        paint_totals = []
        loads = []
        gc_overlap = []
        gc_counts = []
        gc_before = []
        gate_hold = []
        post_gate = []
        for row in selected:
            payload_text = re.findall(r"Q9BGAP (\{.*\})", row["text"])[0]
            payload = json.loads(payload_text)
            events = event_map(payload)
            loads.append(row["load"])
            for name, (start, end) in GAP_SEGMENTS.items():
                segment_values[name].append(events[end] - events[start])
            total = events["run_job"] - events["key"]
            totals.append(total)
            paint_totals.append(events["paint_busy"] - events["key"])
            if scenario == "b":
                gate_hold.append(events["gate_release"] - events["enqueue_decode"])
                post_gate.append(events["active_job"] - events["gate_release"])
            if scenario == "d":
                covered, count, before = gc_values(payload, events["key"], events["run_job"])
                gc_overlap.append(covered)
                gc_counts.append(count)
                gc_before.append(before)
        result = {
            "n": len(selected),
            "loads": loads,
            "key_to_run": dist(totals),
            "key_to_busy_paint": dist(paint_totals),
            "segments": {name: dist(values) for name, values in segment_values.items()},
            "median_shares_of_key_to_run": {
                name: statistics.median(values) / statistics.median(totals) if totals else None
                for name, values in segment_values.items()
            },
        }
        if scenario == "b":
            result["gate_hold_inside_K2"] = dist(gate_hold)
            result["post_gate_to_active"] = dist(post_gate)
            result["median_gate_share_of_key_to_run"] = (
                statistics.median(gate_hold) / statistics.median(totals) if totals else None
            )
            result["median_post_gate_share_of_key_to_run"] = (
                statistics.median(post_gate) / statistics.median(totals) if totals else None
            )
        if scenario == "d":
            result["gc_overlap_with_key_to_run"] = dist(gc_overlap)
            result["gc_passes_overlapping"] = gc_counts
            result["gc_before_key"] = dist(gc_before)
            result["median_gc_share_of_key_to_run"] = (
                statistics.median(gc_overlap) / statistics.median(totals) if totals else None
            )
        gap[scenario] = result

    oe: dict[str, dict] = defaultdict(dict)
    for side in ("base", "tip"):
        for label in ("29_1", "29_2", "82_1", "20_1"):
            selected = [
                r for r in measurement_rows
                if r["family"] == "oe" and r["side"] == side and r["label"] == label
            ]
            values = [parse_margin(r["text"], label.replace("_", "/", 1)) for r in selected]
            measured = [float(v["measured"]) for v in values]
            passed = sum(r["validation"] == "PASS" for r in selected)
            oe[side][label] = {
                "n": len(selected),
                "n_pass": passed,
                "measured": dist(measured),
                "loads": [r["load"] for r in selected],
                "bounds": sorted({float(v["bound"]) for v in values}),
                "margins_pct": [float(v["margin_pct"]) for v in values],
                "under_0.4": sum(value < 0.4 for value in measured),
                "pass_5_of_5": passed == 5,
            }

    fx9c = {}
    for side in ("base", "tip"):
        selected = [r for r in valid_rows if r["family"] == "fx9c" and r["side"] == side]
        if not selected:
            continue
        payload = json.loads(re.findall(r"FX9CPARTS (\{.*\})", selected[0]["text"])[0])
        stages = [part for part in payload["parts"] if part[0] == "_stage_bench_record"]
        fx9c[side] = {
            "load": selected[0]["load"],
            "block": stages[-1][2],
            "parts": payload["parts"],
            "n_keys": payload["n_keys"],
            "max_key_end": payload["max"],
            "keys_over_0.3": payload["keys_over_0.3"],
            "after_stage": payload["after_stage"],
        }

    timing: dict[str, dict] = {}
    for label in ("94_1", "94_2", "94_3", "97_1", "97_3", "98_1", "99_1"):
        selected = [r for r in measurement_rows if r["family"] == "timing" and r["label"] == label]
        metrics: dict[str, list[dict]] = defaultdict(list)
        if label != "97_1":
            for row in selected:
                for match in MARGIN_RE.finditer(row["text"]):
                    margin, measured, bound, metric_label, node = match.groups()
                    if metric_label.startswith("R-PE-BENCH." + label.replace("_", "/", 1)):
                        metrics[metric_label].append({
                            "measured": float(measured),
                            "bound": float(bound),
                            "margin_pct": float(margin),
                        })
        timing[label] = {
            "n": len(selected),
            "n_pass": sum(r["validation"] == "PASS" for r in selected),
            "loads": [r["load"] for r in selected],
            "metrics": {
                name: {
                    "measured": dist([float(v["measured"]) for v in values]),
                    "bound": sorted({float(v["bound"]) for v in values}),
                    "worst_margin_pct": min(float(v["margin_pct"]) for v in values),
                    "within_bound": sum(float(v["measured"]) <= float(v["bound"]) for v in values),
                }
                for name, values in metrics.items()
            },
            "margin_note": "committed node emits no QC-TM margin" if label == "97_1" else None,
        }

    summary = {
        "errors": errors,
        "status_rows": len(rows),
        "valid_rows": len(valid_rows),
        "measurement_rows": len(measurement_rows),
        "gap": gap,
        "oe": oe,
        "fx9c": fx9c,
        "timing": timing,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "errors": errors,
        "status_rows": len(rows),
        "valid_rows": len(valid_rows),
        "measurement_rows": len(measurement_rows),
    }, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())

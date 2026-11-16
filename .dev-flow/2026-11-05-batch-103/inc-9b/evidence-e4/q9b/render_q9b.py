from __future__ import annotations

import json
import sys
from pathlib import Path

SEGMENTS = (
    "key_to_action",
    "action_to_selection",
    "selection_to_enqueue",
    "enqueue_to_active_K2",
    "active_to_run",
    "run_to_busy_paint",
)


def f6(value: float | None) -> str:
    return "—" if value is None else f"{value:.6f}"


def f3(value: float | None) -> str:
    return "—" if value is None else f"{value:.3f}"


def render_gap(gap: dict) -> None:
    if not gap:
        return
    print("## Gap totals")
    print("| Scenario | Valid | key→run p50 s | max s | key→busy paint p50 s | max s | Pre-run loads |")
    print("|---|---:|---:|---:|---:|---:|---|")
    for name in ("a", "b", "c-press", "c-post", "d"):
        result = gap[name]
        total = result["key_to_run"]
        paint = result["key_to_busy_paint"]
        loads = result["loads"]
        print(
            f"| {name} | {result['n']} | {f6(total['p50'])} | {f6(total['max'])} | "
            f"{f6(paint['p50'])} | {f6(paint['max'])} | {min(loads):.2f}–{max(loads):.2f} |"
        )
    print("\n## Gap segments")
    print("| Scenario | Segment | p50 s | max s | p50 share of key→run |")
    print("|---|---|---:|---:|---:|")
    for name in ("a", "b", "c-press", "c-post", "d"):
        result = gap[name]
        for segment in SEGMENTS:
            values = result["segments"][segment]
            share = result["median_shares_of_key_to_run"][segment]
            share_text = "—" if segment == "run_to_busy_paint" else f"{share * 100:.2f}%"
            print(
                f"| {name} | {segment} | {f6(values['p50'])} | {f6(values['max'])} | "
                f"{share_text} |"
            )
    gated = gap["b"]
    print("\n## Scenario b gate split")
    print("| Interval | p50 s | max s | p50 share of key→run |")
    print("|---|---:|---:|---:|")
    for key, share_key in (
        ("gate_hold_inside_K2", "median_gate_share_of_key_to_run"),
        ("post_gate_to_active", "median_post_gate_share_of_key_to_run"),
    ):
        values = gated[key]
        print(
            f"| {key} | {f6(values['p50'])} | {f6(values['max'])} | "
            f"{gated[share_key] * 100:.2f}% |"
        )
    gc = gap["d"]
    print("\n## Scenario d GC")
    print("| Runs with overlap | GC overlap p50 s | max s | p50 share of key→run | GC before key p50 s | max s |")
    print("|---|---:|---:|---:|---:|---:|")
    overlap = gc["gc_overlap_with_key_to_run"]
    before = gc["gc_before_key"]
    print(
        f"| {sum(count > 0 for count in gc['gc_passes_overlapping'])}/10 | "
        f"{f6(overlap['p50'])} | {f6(overlap['max'])} | "
        f"{gc['median_gc_share_of_key_to_run'] * 100:.2f}% | {f6(before['p50'])} | {f6(before['max'])} |"
    )


def render_oe(oe: dict) -> None:
    if not oe:
        return
    print("## O-E nodes")
    print("| Node | Side | n / PASS | p50 s | max s | <0.4 s | Pre-run loads |")
    print("|---|---|---:|---:|---:|---:|---|")
    for label in ("29_1", "29_2", "82_1", "20_1"):
        for side in ("base", "tip"):
            result = oe[side][label]
            print(
                f"| {label} | {side} | {result['n']} / {result['n_pass']} | "
                f"{f3(result['measured']['p50'])} | {f3(result['measured']['max'])} | "
                f"{result['under_0.4']}/5 | {', '.join(f'{load:.2f}' for load in result['loads'])} |"
            )


def render_fx9c(fx9c: dict) -> None:
    if not fx9c:
        return
    print("## FX9c parts")
    print("| Side | Part | Start s | Duration s |")
    print("|---|---|---:|---:|")
    for side in ("base", "tip"):
        parts = fx9c[side]["parts"]
        for name, start, duration in parts:
            if name != "_paint":
                print(f"| {side} | {name} | {start:.3f} | {duration:.3f} |")
        paints = [duration for name, start, duration in parts if name == "_paint"]
        print(
            f"| {side} | `_paint` callbacks over 0.05 s: n={len(paints)}, "
            f"total={sum(paints):.3f} s, max={max(paints):.3f} s | — | — |"
        )


def render_timing(timing: dict) -> None:
    if not timing:
        return
    print("## Inc 9b timing cases")
    print("| Case | Metric | Executed / PASS | p50 s | max s | Bound s | Worst margin | Within bound | Pre-run loads |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---|")
    for label, result in timing.items():
        loads = ", ".join(f"{load:.2f}" for load in result["loads"])
        if not result["metrics"]:
            print(f"| {label} | executed assertions | {result['n']} / {result['n_pass']} | — | — | — | — | — | {loads} |")
        for metric, values in result["metrics"].items():
            print(
                f"| {label} | {metric} | {result['n']} / {result['n_pass']} | "
                f"{f3(values['measured']['p50'])} | {f3(values['measured']['max'])} | "
                f"{values['bound'][0]:.3f} | {values['worst_margin_pct']:.1f}% | "
                f"{values['within_bound']}/{result['n']} | {loads} |"
            )


def main() -> int:
    summary = json.loads(Path(sys.argv[1]).read_text())
    mode = sys.argv[2] if len(sys.argv) > 2 else "full"
    if mode in {"gap-only", "full"}:
        render_gap(summary["gap"])
    if mode == "full":
        render_oe(summary["oe"])
        render_fx9c(summary["fx9c"])
        render_timing(summary["timing"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

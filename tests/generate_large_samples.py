"""
Summary:
    CLI entry-point for writing large, deterministic S19 + A2L + MAC fixtures to a
    user-chosen folder so the TUI can be stress-tested manually against production-
    scale inputs (the scenario that originally surfaced the MAC-load freeze).

Example:
    python -m tests.generate_large_samples --out ./tmp/stress \\
        --s19-ranges 2000 --bytes-per-range 4096 \\
        --a2l-measurements 6000 --a2l-characteristics 1000 \\
        --mac-records 32000 --mac-diagnostics 13000

Dependencies:
    Uses:
        - ``tests.conftest.make_large_s19`` / ``make_large_a2l`` / ``make_large_mac``
    Used by:
        - Developers reproducing the original "stuck loading" symptom against the TUI.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from tests.conftest import make_large_a2l, make_large_mac, make_large_s19


def _build_arg_parser() -> argparse.ArgumentParser:
    """
    Summary:
        Assemble the argparse parser used by both ``main`` and tests.

    Returns:
        argparse.ArgumentParser: Fully configured parser with per-artifact knobs.

    Data Flow:
        - Declare the required ``--out`` target directory.
        - Declare sizing knobs for each generator (S19, A2L, MAC).
        - Declare a shared ``--seed`` for deterministic reruns.
    """
    parser = argparse.ArgumentParser(
        prog="python -m tests.generate_large_samples",
        description=(
            "Generate large, deterministic S19 + A2L + MAC sample files for manual "
            "TUI stress testing."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Destination folder (created if missing).",
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="stress",
        help="Basename for the generated files (default: 'stress').",
    )
    parser.add_argument("--seed", type=int, default=0, help="PRNG seed for all generators.")

    # S19 knobs
    parser.add_argument("--s19-ranges", type=int, default=2000)
    parser.add_argument("--bytes-per-range", type=int, default=4096)
    parser.add_argument("--s19-base", type=lambda v: int(v, 0), default=0x0800_0000)
    parser.add_argument("--s19-gap", type=lambda v: int(v, 0), default=0x100)

    # A2L knobs
    parser.add_argument("--a2l-measurements", type=int, default=6000)
    parser.add_argument("--a2l-characteristics", type=int, default=1000)
    parser.add_argument("--a2l-in-memory-fraction", type=float, default=0.7)

    # MAC knobs
    parser.add_argument("--mac-records", type=int, default=32000)
    parser.add_argument("--mac-diagnostics", type=int, default=13000)
    parser.add_argument("--mac-a2l-hit-ratio", type=float, default=0.5)

    parser.add_argument(
        "--skip",
        action="append",
        choices=["s19", "a2l", "mac"],
        default=[],
        help="Skip generation for one or more artifacts (repeatable).",
    )
    return parser


def generate_samples(args: argparse.Namespace) -> dict[str, Path]:
    """
    Summary:
        Write S19/A2L/MAC fixtures under ``args.out`` using the shared generators.

    Args:
        args (argparse.Namespace): Parsed CLI arguments (see ``_build_arg_parser``).

    Returns:
        dict[str, Path]: Map of artifact label (``"s19" | "a2l" | "mac"``) to the
        written file path. Skipped artifacts are absent.

    Data Flow:
        - Ensure the output directory exists.
        - Compute a consistent ``memory_span_bytes`` from S19 sizing so A2L / MAC
          addresses overlap the S19 image for realistic coexistence validation.
        - Invoke each generator unless explicitly skipped via ``--skip``.
        - Return the resulting path map for the caller to log or chain.

    Dependencies:
        Uses:
            - ``make_large_s19`` / ``make_large_a2l`` / ``make_large_mac``
    """
    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    memory_span_bytes = args.s19_ranges * args.bytes_per_range
    results: dict[str, Path] = {}

    if "s19" not in args.skip:
        s19_path = out_dir / f"{args.prefix}.s19"
        make_large_s19(
            s19_path,
            num_ranges=args.s19_ranges,
            bytes_per_range=args.bytes_per_range,
            base_address=args.s19_base,
            gap_bytes=args.s19_gap,
            seed=args.seed,
        )
        results["s19"] = s19_path

    if "a2l" not in args.skip:
        a2l_path = out_dir / f"{args.prefix}.a2l"
        make_large_a2l(
            a2l_path,
            num_measurements=args.a2l_measurements,
            num_characteristics=args.a2l_characteristics,
            base_address=args.s19_base,
            in_memory_fraction=args.a2l_in_memory_fraction,
            memory_span_bytes=memory_span_bytes,
            seed=args.seed,
        )
        results["a2l"] = a2l_path

    if "mac" not in args.skip:
        mac_path = out_dir / f"{args.prefix}.mac"
        make_large_mac(
            mac_path,
            num_records=args.mac_records,
            num_diagnostics=args.mac_diagnostics,
            base_address=args.s19_base,
            memory_span_bytes=memory_span_bytes,
            a2l_hit_ratio=args.mac_a2l_hit_ratio,
            num_a2l_tags=args.a2l_measurements,
            seed=args.seed,
        )
        results["mac"] = mac_path

    return results


def main(argv: Sequence[str] | None = None) -> int:
    """
    Summary:
        Parse CLI arguments, generate the requested fixtures, and print a summary.

    Args:
        argv (Sequence[str] | None): Optional override for ``sys.argv[1:]``.

    Returns:
        int: Process exit code (``0`` on success, non-zero on generator failure).

    Data Flow:
        - Delegate parsing to ``_build_arg_parser``.
        - Delegate file creation to ``generate_samples``.
        - Print one line per written artifact including its size in bytes.
    """
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        produced = generate_samples(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    for label, path in produced.items():
        size_bytes = path.stat().st_size
        print(f"{label}: {path} ({size_bytes:,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

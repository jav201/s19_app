"""Inc 2 E2 probe 2 (batch-103): the RAT_FUNC zero-denominator input of R-A2L-DEF.28/3.

The first probe showed that the E1 case input ``CM(RAT_FUNC 0 1 0 0 1 0)``, stored 1, gives
``RAT_FUNC has no solution for this value`` on the base decode, not the zero-denominator error. This
probe runs the unchanged ``a2l._apply_compu_method`` on the E1 input and on a corrected input whose one
root has a zero denominator. Pure function calls only; imports ``s19_app`` from the read-only clone.

Usage: python i2e2-probe2.py <clone root> <out dir>
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    clone = Path(argv[1])
    sys.path.insert(0, str(clone))
    import s19_app
    print("s19_app.__file__ =", s19_app.__file__)
    from s19_app.tui import a2l

    def rat(*coeffs):
        return {"conversion_type": "RAT_FUNC", "coeffs": [float(c) for c in coeffs]}

    for label, stored, coeffs in (
        ("E1 case 28/3 input: COEFFS 0 1 0 0 1 0, stored 1", 1, (0, 1, 0, 0, 1, 0)),
        ("corrected 28/3 input: COEFFS 0 1 1 0 1 1, stored 2 (raw = (P+1)/(P+1); root P = -1)", 2, (0, 1, 1, 0, 1, 1)),
        ("same method, stored 1 (every P but -1 solves it; the smaller-magnitude root rule)", 1, (0, 1, 1, 0, 1, 1)),
    ):
        print(f"[P9 {label}] {a2l._apply_compu_method(stored, rat(*coeffs), {})}")
    print("# exit 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

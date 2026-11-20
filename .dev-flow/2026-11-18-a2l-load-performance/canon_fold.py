"""Canon fold for batch 2026-11-18-a2l-load-performance: append the 30 new
requirement rows (already E1/E4-amended in the increment files) to
REQUIREMENTS.md at their existing blocks. Idempotent: skips rows already
present."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / ".dev-flow/2026-11-18-a2l-load-performance"
CANON = ROOT / "REQUIREMENTS.md"

NEW_IDS = [
    *(f"R-A2L-DEF.{n}" for n in range(156, 166)),
    *(f"R-A2L-REFRESH.{n:03d}" for n in range(29, 49)),
]
ANCHORS = {
    "R-A2L-DEF.155": "R-A2L-DEF.155",
    "R-A2L-REFRESH.028": "R-A2L-REFRESH.028",
}


def extract_rows() -> dict[str, tuple[str, str]]:
    rows: dict[str, tuple[str, str]] = {}
    for inc in ("inc-1", "inc-2", "inc-3"):
        req = BATCH / inc / "01-requirements.md"
        for line in req.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\| (R-A2L-DEF\.\d+|R-A2L-REFRESH\.\d+) \|", line)
            if not m:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            rid = cells[0]
            if rid in NEW_IDS:
                rows[rid] = (cells[1], cells[2])
    return rows


def main() -> int:
    canon = CANON.read_text(encoding="utf-8")
    rows = extract_rows()
    missing = [rid for rid in NEW_IDS if rid not in rows]
    if missing:
        print("MISSING ROWS:", missing)
        return 2
    lines = canon.splitlines()
    out: list[str] = []
    inserted = 0
    group: str | None = None
    for line in lines:
        m = re.match(r"^\| (R-A2L-DEF\.\d+|R-A2L-REFRESH\.\d+) \|", line)
        if m and m.group(1) in ANCHORS:
            out.append(line)
            group = m.group(1)
            continue
        out.append(line)
        if group is not None and line.strip() == "":
            family = "R-A2L-DEF" if group.startswith("R-A2L-DEF") else "R-A2L-REFRESH"
            for rid in NEW_IDS:
                if rid in rows and rid.startswith(family) and rid not in canon:
                    form, sentence = rows[rid]
                    out.append(f"| {rid} | {form} | {sentence} |")
                    inserted += 1
            group = None
    if inserted:
        CANON.write_text("\n".join(out) + "\n", encoding="utf-8")
    already = sum(1 for rid in NEW_IDS if rid in canon)
    print(f"inserted={inserted} already_present={already}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

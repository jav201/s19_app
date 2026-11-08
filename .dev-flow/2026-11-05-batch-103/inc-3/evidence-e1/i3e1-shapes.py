"""Inc 3 E1 shape census (batch-103): the array and axis shapes of every
tracked A2L file, read as text (comments left out).

Imports ``s19_app`` from the read-only clone only for its section tree
(``build_section_tree``) and its comment stripper (``_strip_a2l_comments``);
everything else is counted from the section text, so the census reports what
the files declare, not what the parser makes of it. Pure: no app, no screen,
no clipboard, no writes outside stdout.

Usage: python i3e1-shapes.py <repo clone>
"""
from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

KINDS_C = {"VALUE", "VAL_BLK", "ASCII", "CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5", "MAP_BLOCK"}


def main(argv: list[str]) -> int:
    repo = Path(argv[1]).resolve()
    sys.path.insert(0, str(repo))
    import s19_app  # noqa: E402
    from s19_app.tui import a2l  # noqa: E402

    print(f"s19_app.__file__ = {s19_app.__file__}")
    files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"],
                           capture_output=True, text=True, check=True).stdout.split()
    print(f"tracked .a2l files: {len(files)}")

    def body_lines(section: dict) -> list[str]:
        text = a2l._A2L_LINE_SENTINEL.join(section.get("lines") or [])
        return [ln.strip() for ln in a2l._strip_a2l_comments(text).split(a2l._A2L_LINE_SENTINEL)]

    def tokens(section: dict) -> list[str]:
        head = a2l._split_line_respecting_quotes(a2l._strip_a2l_comments(section.get("meta") or ""))
        return head + a2l._flatten_body_tokens(section.get("lines") or [])

    def walk(sections, out):
        for s in sections:
            out.append(s)
            walk(s.get("children") or [], out)

    def is_num(w: str) -> bool:
        try:
            int(w, 0)
            return True
        except ValueError:
            try:
                float(w)
                return True
            except ValueError:
                return False

    c_kind = Counter()
    md_shape = Counter()          # (owner kind, number count, trailing-ones form)
    md_nonnum = []
    valblk_size_src = Counter()
    ascii_md = 0
    meas_layout = Counter()
    axes_per = Counter()          # (kind, n axes)
    axis_kind = Counter()
    axis_kw = Counter()
    monotony = Counter()
    fixpar = []
    comref = Counter()            # resolves to AXIS_PTS / to CHARACTERISTIC / dangling
    conv_differs = Counter()
    rl_comp = Counter()
    fnc_mode = Counter()
    fnc_addr = Counter()
    axpts_order = Counter()
    axpts_addr = Counter()
    pos_order = Counter()
    fix_no = Counter()
    layout_vs_axes = Counter()
    layout_vs_axes_samples = []
    axis_pts_kw = Counter()
    tabverb_on = Counter()
    bitmask_on = Counter()
    per_file = []

    for rel in files:
        sections, _errors = a2l.build_section_tree(repo / rel)
        flat: list[dict] = []
        walk(sections, flat)
        layouts = {}
        methods = {}
        axis_pts = {}
        chars = {}
        for s in flat:
            name = s.get("name")
            if name == "RECORD_LAYOUT":
                layouts[(s.get("meta") or "").split()[0] if (s.get("meta") or "").split() else ""] = s
            elif name == "COMPU_METHOD":
                t = tokens(s)
                if t:
                    methods[t[0]] = t
            elif name == "AXIS_PTS":
                t = tokens(s)
                if t:
                    axis_pts[t[0]] = (s, t)
            elif name == "CHARACTERISTIC":
                t = tokens(s)
                if t:
                    chars[t[0]] = (s, t)

        def method_type(mname: str):
            t = methods.get(mname)
            if not t:
                return None
            for w in t[2:]:
                if w in {"IDENTICAL", "LINEAR", "RAT_FUNC", "TAB_INTP", "TAB_NOINTP", "TAB_VERB", "FORM"}:
                    return w
            return "?"

        n_curve = n_map = n_vb = n_marr = 0
        for s in flat:
            name = s.get("name")
            if name not in ("CHARACTERISTIC", "MEASUREMENT"):
                continue
            t = tokens(s)
            lines = body_lines(s)
            if name == "CHARACTERISTIC":
                kind = t[2] if len(t) > 2 else "?"
                kind = kind if kind in KINDS_C else "other"
                conv = t[6] if len(t) > 6 else None
            else:
                kind = "MEASUREMENT"
                conv = t[3] if len(t) > 3 else None
            c_kind[kind] += 1
            md = [ln.split()[1:] for ln in lines if ln.split()[:1] == ["MATRIX_DIM"]]
            if md:
                words = md[0]
                if not all(is_num(w) for w in words) or not words:
                    md_nonnum.append(f"{rel}: {t[0] if t else '?'} MATRIX_DIM {' '.join(words)}")
                else:
                    nums = [int(w, 0) for w in words]
                    prod = 1
                    for n in nums:
                        prod *= n
                    real = len([n for n in nums if n != 1]) or 1
                    md_shape[(kind, len(nums), f"{real}-D", "prod>1" if prod > 1 else "prod=1")] += 1
                    if kind == "MEASUREMENT" and prod > 1:
                        n_marr += 1
            if kind == "VAL_BLK":
                n_vb += 1
                has = [k for k in ("MATRIX_DIM", "NUMBER", "LENGTH", "DATA_SIZE")
                       if any(ln.split()[:1] == [k] for ln in lines)]
                valblk_size_src["+".join(has) or "none"] += 1
            if kind == "ASCII" and md:
                ascii_md += 1
            if kind == "MEASUREMENT":
                lay = [ln.split()[1] for ln in lines if ln.split()[:1] == ["LAYOUT"] and len(ln.split()) > 1]
                if lay:
                    meas_layout[lay[0]] += 1
            if kind in ("VAL_BLK", "CURVE", "MAP") and method_type(conv or "") == "TAB_VERB":
                tabverb_on[kind] += 1
            if kind in ("VAL_BLK", "CURVE", "MAP", "MEASUREMENT") and any(ln.split()[:1] == ["BIT_MASK"] for ln in lines):
                if kind != "MEASUREMENT" or md:
                    bitmask_on[kind] += 1
            if kind not in ("CURVE", "MAP", "CUBOID", "CUBE_4", "CUBE_5"):
                continue
            n_curve += kind == "CURVE"
            n_map += kind == "MAP"
            axes = [c for c in (s.get("children") or []) if c.get("name") == "AXIS_DESCR"]
            axes_per[(kind, len(axes))] += 1
            layout_name = t[4] if len(t) > 4 else ""
            lay_s = layouts.get(layout_name)
            comps = []
            if lay_s:
                comps = [ln.split()[0] for ln in body_lines(lay_s) if ln.split()]
            for i, ax in enumerate(axes):
                at = a2l._flatten_body_tokens(ax.get("lines") or [])
                ak = at[0] if at else "?"
                axis_kind[ak] += 1
                for kw in ("FIX_AXIS_PAR", "FIX_AXIS_PAR_DIST", "AXIS_PTS_REF", "CURVE_AXIS_REF",
                           "MONOTONY", "FORMAT", "EXTENDED_LIMITS", "DEPOSIT", "BYTE_ORDER", "PHYS_UNIT",
                           "READ_ONLY", "STEP_SIZE", "MAX_GRAD"):
                    if kw in at:
                        axis_kw[kw] += 1
                if any(c.get("name") == "FIX_AXIS_PAR_LIST" for c in (ax.get("children") or [])):
                    axis_kw["FIX_AXIS_PAR_LIST (block)"] += 1
                if "MONOTONY" in at:
                    monotony[at[at.index("MONOTONY") + 1]] += 1
                for kw in ("FIX_AXIS_PAR", "FIX_AXIS_PAR_DIST"):
                    if kw in at:
                        j = at.index(kw)
                        fixpar.append(f"{rel}: {t[0]} axis {i + 1} {kw} {' '.join(at[j + 1:j + 4])} max={at[3] if len(at) > 3 else '?'}")
                for blk in (ax.get("children") or []):
                    if blk.get("name") == "FIX_AXIS_PAR_LIST":
                        vals = a2l._flatten_body_tokens(blk.get("lines") or [])
                        fixpar.append(f"{rel}: {t[0]} axis {i + 1} FIX_AXIS_PAR_LIST {' '.join(vals)} max={at[3] if len(at) > 3 else '?'}")
                if "AXIS_PTS_REF" in at:
                    ref = at[at.index("AXIS_PTS_REF") + 1] if at.index("AXIS_PTS_REF") + 1 < len(at) else ""
                    if ref in axis_pts:
                        comref["AXIS_PTS section"] += 1
                        apt = axis_pts[ref][1]
                        if len(apt) > 6 and len(at) > 2:
                            conv_differs["same" if apt[6] == at[2] else "differs"] += 1
                    elif ref in chars:
                        comref["CHARACTERISTIC of that name"] += 1
                    else:
                        comref["dangling"] += 1
                letter = "XYZ"[i] if i < 3 else str(i + 1)
                has_pts = f"AXIS_PTS_{letter}" in comps
                key = (ak, f"AXIS_PTS_{letter} in layout" if has_pts else f"no AXIS_PTS_{letter} in layout")
                layout_vs_axes[key] += 1
                if (ak == "STD_AXIS") != has_pts and len(layout_vs_axes_samples) < 12:
                    layout_vs_axes_samples.append(f"{rel}: {t[0]} axis {i + 1} {ak} layout {layout_name}: {comps}")
        per_file.append(f"{rel:62s} CURVE={n_curve:<4d} MAP={n_map:<4d} VAL_BLK={n_vb:<4d} MEAS-array={n_marr:<4d} AXIS_PTS={len(axis_pts):<4d}")

        for lname, lay_s in layouts.items():
            positions = []
            for ln in body_lines(lay_s):
                w = ln.split()
                if not w:
                    continue
                rl_comp[w[0]] += 1
                if w[0] == "FNC_VALUES":
                    fnc_mode[w[3] if len(w) > 3 else "(none)"] += 1
                    fnc_addr[w[4] if len(w) > 4 else "(none)"] += 1
                if w[0].startswith("AXIS_PTS_"):
                    axpts_order[w[3] if len(w) > 3 else "(none)"] += 1
                    axpts_addr[w[4] if len(w) > 4 else "(none)"] += 1
                if w[0].startswith("FIX_NO_AXIS_PTS_"):
                    fix_no[w[0]] += 1
                if len(w) > 1 and w[0] not in a2l._ALIGNMENT_DIRECTIVES and not w[0].startswith("FIX_NO_AXIS_PTS_") and w[0] not in ("STATIC_RECORD_LAYOUT", "STATIC_ADDRESS_OFFSETS"):
                    try:
                        positions.append(int(w[1]))
                    except ValueError:
                        positions.append(None)
            if positions:
                if None in positions:
                    pos_order["a position word is not a number"] += 1
                elif positions == sorted(positions) and len(set(positions)) == len(positions):
                    pos_order["lines in position order"] += 1
                else:
                    pos_order["lines NOT in position order"] += 1
        for ap_name, (ap_s, apt) in axis_pts.items():
            for ln in body_lines(ap_s):
                w = ln.split()
                if w and w[0] in ("DEPOSIT", "MONOTONY", "FORMAT", "BYTE_ORDER", "EXTENDED_LIMITS", "PHYS_UNIT", "READ_ONLY", "STEP_SIZE"):
                    axis_pts_kw[" ".join(w[:2]) if w[0] in ("DEPOSIT", "MONOTONY") else w[0]] += 1

    def show(title, counter):
        print(f"\n## {title}")
        for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0]))):
            print(f"  {v:6d}  {k}")

    print("\n## per file")
    for line in per_file:
        if "CURVE=0 " in line and "MAP=0 " in line and "VAL_BLK=0 " in line and "MEAS-array=0 " in line and "AXIS_PTS=0 " in line:
            continue
        print("  " + line)
    show("CHARACTERISTIC kinds and MEASUREMENT (all files)", c_kind)
    show("MATRIX_DIM: (owner, number count, real dimensions, product)", md_shape)
    print(f"\n## MATRIX_DIM lines whose words are not all numbers: {len(md_nonnum)}")
    for x in md_nonnum[:8]:
        print("  " + x)
    show("VAL_BLK size source lines present", valblk_size_src)
    print(f"\n## ASCII CHARACTERISTICs with MATRIX_DIM: {ascii_md}")
    show("MEASUREMENT LAYOUT word", meas_layout)
    show("AXIS_DESCR count per object (kind, axes)", axes_per)
    show("AXIS_DESCR kinds", axis_kind)
    show("AXIS_DESCR optional keywords", axis_kw)
    show("AXIS_DESCR MONOTONY values", monotony)
    print("\n## FIX_AXIS parameters (all)")
    for x in fixpar:
        print("  " + x)
    show("AXIS_PTS_REF resolves to", comref)
    show("COM_AXIS: AXIS_DESCR conversion vs the AXIS_PTS conversion", conv_differs)
    show("AXIS_PTS optional keywords", axis_pts_kw)
    show("RECORD_LAYOUT first words", rl_comp)
    show("FNC_VALUES index mode", fnc_mode)
    show("FNC_VALUES address type", fnc_addr)
    show("AXIS_PTS_<x> index order", axpts_order)
    show("AXIS_PTS_<x> address type", axpts_addr)
    show("FIX_NO_AXIS_PTS_<x>", fix_no)
    show("RECORD_LAYOUT line order vs position numbers", pos_order)
    show("axis kind vs the object's record layout", layout_vs_axes)
    print("\n## samples: STD_AXIS without its AXIS_PTS component, or another kind with one")
    for x in layout_vs_axes_samples:
        print("  " + x)
    show("TAB_VERB conversion on array values", tabverb_on)
    show("BIT_MASK on arrays", bitmask_on)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

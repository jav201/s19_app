"""X8b E5 mutant driver: one fresh hard-link copy per mutant (HT-09), the mutated file replaced by a new inode,
then only the named nodes. Usage: python mut.py PRISTINE OUTDIR [ids...]"""
import os
import shutil
import subprocess
import sys

DS = "s19_app/tui/definition_sheet.py"
SH = "s19_app/tui/screens_directionb/patch_editor/sheet.py"
BV = "s19_app/tui/definition_bench_view.py"
S1, S2 = "tests/test_b103_inc8b_s1.py", "tests/test_b103_inc8b_s2.py"
AT, BW = "tests/test_b103_inc8b_at.py", "tests/test_b103_inc8b_bw.py"

MUTANTS = {
    "N-91": (SH, "lines = [header_line(widths), header_rule(widths)]", "lines = [header_line(widths)]",
             [BW, "-k", "91_1"]),
    "N-101": (DS, 'glyph = "●" if staged else "◆" if pending else " "',
              'glyph = " " if staged else "◆" if pending else " "', [S1, "-k", "101_"]),
    "N-103": (DS, 'mark.append(glyph, style=_GLYPH_STYLES.get(glyph, ""))',
              'mark.append(" " if glyph == "◆" else glyph, style=f"on {_PENDING}" if glyph == "◆" else _GLYPH_STYLES.get(glyph, ""))',
              [S1, "-k", "103_"]),
    "C-103a": (DS, '_bit(msk, "■" if masked else "·", f"bold {_RULE}" if masked else _DIM)',
               '_bit(msk, " " if masked else "·", f"on {_RULE}" if masked else _DIM)', [S1, "-k", "103_"]),
    "C-103b": (DS, '_CHANGED_STYLE = f"{_PENDING_STYLE} underline"', "_CHANGED_STYLE = _PENDING_STYLE",
               [S1, "-k", "103_"]),
    "N-94c": (SH, "self._grid.scroll_to(x=x, animate=False, immediate=True)",
              "self._grid.scroll_to(x=x, animate=True, immediate=True)", [AT, "-k", "94_6"]),
    "N-115b": (DS, "    row.plain = plain(row.plain)\n", "    row.plain = row.plain\n", [S2, "-k", "115_"]),
    "P-B5_5": (BV, 'the sheet width."""\n    if room < 1:\n        return []\n', 'the sheet width."""\n',
               [S2, "-k", "bench_5_5"]),
    "P-81_6": (SH, '    def on_resize(self, event: events.Resize) -> None:\n        """A width-only resize leaves the body at 143 x h and sends it no event: repaint here."""\n        self._paint()\n\n',
               "", [BW, "-k", "81_6"]),
}


def main() -> None:
    pristine, out = sys.argv[1], sys.argv[2]
    ids = sys.argv[3:] or list(MUTANTS)
    os.makedirs(out, exist_ok=True)
    for mid in ids:
        path, old, new, args = MUTANTS[mid]
        copy = os.path.join(out, "copy-" + mid)
        shutil.rmtree(copy, ignore_errors=True)
        subprocess.run(["cp", "-al", pristine, copy], check=True)
        target = os.path.join(copy, path)
        text = open(target, encoding="utf-8").read()
        assert text.count(old) == 1, (mid, "the mutation's old text must occur once")
        os.unlink(target)  # break the hard link: the pristine tree is never written
        with open(target, "w", encoding="utf-8", newline="") as handle:
            handle.write(text.replace(old, new))
        log = os.path.join(out, mid + ".txt")
        with open(log, "w", encoding="utf-8") as handle:
            handle.write(f"## mutant {mid}: {path}\n## - {old!r}\n## + {new!r}\n")
        subprocess.run(["bash", os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh"), copy,
                        log + ".run", "-n", "0", *args], check=False)
        with open(log, "a", encoding="utf-8") as handle:
            handle.write(open(log + ".run", encoding="utf-8").read())
        os.unlink(log + ".run")
        shutil.rmtree(copy)
    open(os.path.join(out, "MUT_DONE"), "w").write("done\n")


if __name__ == "__main__":
    main()

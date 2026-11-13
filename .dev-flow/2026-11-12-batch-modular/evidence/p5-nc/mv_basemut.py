"""Scratch-base mutations (line count preserved, so the map spans stay valid).  Usage: mv_basemut.py <work-tree> <6|38>
6  : an `except Exception:` inside a method names an unknown identifier  -> a mixin loads an unresolvable name (E12)
38 : a method binds the D1 name `os` locally                              -> E6"""
import os
import sys
from pathlib import Path

work, case = Path(sys.argv[1]), sys.argv[2]
p = work / "s19_app/tui/app.py"
t = p.read_text(encoding="utf-8")
a = "                handler.flush()\n            except Exception:\n"
assert t.count(a) == 1, t.count(a)
if case == "6":
    b = "                handler.flush()\n            except NC_MV6_MISSING:\n"
else:
    b = "                handler.flush(); os = None\n            except Exception:\n"
os.unlink(p)  # new inode: the work copy is hard-linked to the base checkout
p.write_text(t.replace(a, b), encoding="utf-8", newline="\n")
print("mutated", case)

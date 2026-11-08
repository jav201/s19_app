#!/usr/bin/env python3
"""batch-103 Inc 4 E3 architect probe 3 (THROWAWAY): two-structure memory
mutants for R-A2L-MATCH.37, and oracle values for proposed cases."""
from __future__ import annotations

import gc
import os
import runpy
import sys
import tracemalloc
from pathlib import Path

HERE = Path(os.environ["PILOT_DIR"])
P4 = runpy.run_path(str(HERE / "i4e2-pilot4.py"), run_name="i4e2_pilot_v4")
IndexC, naive_rank_b, tokens, names_of, REPO, s19_app = (
    P4["IndexC"], P4["naive_rank_b"], P4["tokens"], P4["names_of"], P4["REPO"], P4["s19_app"])


def peak(fn):
    gc.collect()
    tracemalloc.start()
    obj = fn()
    cur, pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return obj, cur, pk


class DictTrieTok(IndexC):
    """M2 + M3: a nested-dict trie of the tokens and a per-name tuple of token strings."""

    def __init__(self, names):
        super().__init__(names)
        root = {}
        for tid, t in enumerate(self.utok):
            node = root
            for c in t:
                node = node.setdefault(c, {})
            node[""] = tid
        self.dtrie = root
        self.ntoks = tuple(tuple(f[s:e] for s, e in tokens(n)) for n, f in zip(self.names, self.folded))


class ListsTok(IndexC):
    """M1 + M3: every array as a list, and a per-name tuple of token strings."""

    def __init__(self, names):
        super().__init__(names)
        self.nmask, self.ntid, self.noff = list(self.nmask), list(self.ntid), list(self.noff)
        self.post, self.poff = list(self.post), list(self.poff)
        ch, de, fi, en = self.nodes
        self.nodes = (ch, list(de), list(fi), list(en))
        self.ntoks = tuple(tuple(f[s:e] for s, e in tokens(n)) for n, f in zip(self.names, self.folded))


def main() -> int:
    print(f"s19_app.__file__ = {s19_app.__file__}")
    print(f"python = {sys.version.split()[0]}  host = {os.uname().nodename}")
    sw_a = names_of(REPO / "examples/case_00_public/software_a.a2l")
    ref = (sw_a + [n + "_1" for n in sw_a] + [n + "_2" for n in sw_a] + [n + "_3" for n in sw_a])[:50000]
    print("=== R-A2L-MATCH.37 two-structure mutants on REF (bound 67,108,864; 32 MiB = 33,554,432)")
    for label, cls in (("M2+M3 dict trie + token tuples", DictTrieTok), ("M1+M3 lists + token tuples", ListsTok)):
        obj, cur, pk = peak(lambda: cls(ref))
        print(f"  {label:34s} peak {pk:>12,} = {pk / 1048576:5.1f} MiB -> {'RED' if pk > 67_108_864 else 'GREEN'} at 64 MiB")
        del obj
        gc.collect()
    print("=== oracle (naive_rank_b, E1 v3) values for proposed cases")
    c08 = names_of(Path(os.environ["OUT"]) / "firmware.a2l")
    for label, names, q in (("C08", c08, "crxuve"), ("C08", c08, "\x1cVALUE_0001"), ("C08", c08, "\xa0VALUE_0001"),
                            ("[٣٣٣_X]", ["٣٣٣_X"], "٣٣٤"),
                            ("TW", ["RPM", "rpm", "Rpm"], "rpm"), ("NA", ["Drück_Max", "DRÜCK_MAX", "druck_max"], "drück")):
        print(f"  [{label}] query={q!r}: {naive_rank_b(q, names, 20)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

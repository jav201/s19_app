"""Compare two junit files node for node. Usage: junit_cmp.py <a.xml> <b.xml>"""
import sys
import xml.etree.ElementTree as ET
from collections import Counter


def load(p):
    out = {}
    for tc in ET.parse(p).getroot().iter("testcase"):
        o = "passed"
        for tag in ("failure", "error", "skipped"):
            if tc.find(tag) is not None:
                o = tag
        out[f"{tc.get('classname')}::{tc.get('name')}"] = o
    return out


a, b = load(sys.argv[1]), load(sys.argv[2])
print("A", dict(Counter(a.values())), "B", dict(Counter(b.values())))
diff = sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))
print(f"nodes A={len(a)} B={len(b)} differing={len(diff)}")
for k in diff:
    print(f"  {k}: {a.get(k)} -> {b.get(k)}")
for k in sorted(a):
    if a[k] == "skipped":
        print(f"  skipped(A): {k}")

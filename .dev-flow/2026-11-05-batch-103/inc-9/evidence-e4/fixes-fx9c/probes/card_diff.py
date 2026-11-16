"""FX9c O-C equality probe (scratch only): the digest of before_after_card_text over seeded random cases and one
1 MiB LARGE-sized case. Run once per tree (cwd = the tree); two trees paint the same cards iff the outputs match."""
import hashlib
import random
import sys

import s19_app
from s19_app.tui.screens_directionb.shared import STRIP_ROW_BYTES, before_after_card_text

print(s19_app.__file__)


def digest(text):
    h = hashlib.sha256(text.plain.encode("utf-8"))
    h.update(repr([(s.start, s.end, str(s.style)) for s in text.spans]).encode("utf-8"))
    return h.hexdigest()[:16]


def byte(rng, p_none):
    return None if rng.random() < p_none else rng.randrange(256)


rng = random.Random(9031)
for case in range(int(sys.argv[1]) if len(sys.argv) > 1 else 3000):
    per_row = rng.choice(STRIP_ROW_BYTES)
    span = rng.choice((0, 1, 2, rng.randrange(1, 40), rng.randrange(40, 400)))
    after = [rng.randrange(256) for _ in range(span)]
    shape = rng.random()
    if shape < 0.05:
        before = None
    else:
        n = span if shape < 0.7 else max(0, span + rng.randrange(-span - 1, 6))
        before = [after[i] if i < span and rng.random() < 0.5 else byte(rng, 0.2) for i in range(n)]
    address = rng.randrange(0, 1 << 33) if rng.random() < 0.1 else rng.randrange(0, 1 << 20)
    lead = [byte(rng, 0.2) for _ in range(rng.randrange(0, per_row))]
    trail = [byte(rng, 0.2) for _ in range(rng.randrange(0, per_row))]
    kw = {"lead": lead, "trail": trail}
    if rng.random() < 0.5:
        kw["row_cap"] = rng.randrange(0, 12)
    addr = None if rng.random() < 0.02 else address
    print(case, digest(before_after_card_text(addr, before, after, per_row, **kw)))

big = 1 << 20
after = [rng.randrange(256) for _ in range(big)]
before = [a if rng.random() < 0.7 else byte(rng, 0.1) for a in after]
text = before_after_card_text(0x80000, before, after, 32, lead=[], trail=[])
print("LARGE", digest(text), text.plain.splitlines()[-1])

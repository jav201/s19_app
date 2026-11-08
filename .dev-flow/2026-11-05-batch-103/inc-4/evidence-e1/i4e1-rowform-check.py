#!/usr/bin/env python3
"""batch-103 Inc 4 E1: check the rows of 01-requirements.md with the canon's own form rules.

The regexes are copied from tests/test_requirements_canon.py at e07fb00 (FORM_PREFIX
:59-63, the one-`shall` rule R-DOC-CANON.4 :237-248, the one-sentence rule
R-DOC-CANON.11 :460-475). Form letters of the increment record map E -> When. Reads
one file; imports nothing from s19_app.
"""
import re
import sys

FORM = {"U": r"The system shall ", "E": r"When .+?, the system shall ", "When": r"When .+?, the system shall ",
        "While": r"While .+?, the system shall ", "If": r"If .+?, then the system shall ",
        "Where": r"Where .+?, the system shall "}
CODE_SPAN_RE = re.compile(r"`[^`]*`")
rows = bad = 0
for line in open(sys.argv[1], encoding="utf-8"):
    if not line.startswith("| R-A2L-MATCH."):
        continue
    cells = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip())[1:-1]]
    rid, form, sentence = cells[0], cells[1], cells[2]
    rows += 1
    errs = []
    if not re.match(FORM[form], sentence):
        errs.append(f"does not open as form {form}")
    n = len(re.findall(r"\bshall\b", sentence))
    if n != 1:
        errs.append(f"'shall' {n} times")
    plain = CODE_SPAN_RE.sub("", sentence)
    if re.search(r"\. [A-Z]", plain):
        errs.append("a second sentence")
    if not sentence.endswith("."):
        errs.append("no final full stop")
    if errs:
        bad += 1
        print(f"{rid}: {'; '.join(errs)}")
print(f"rows checked {rows}; rows with a finding {bad}")

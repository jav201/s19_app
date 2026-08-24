#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""coherence_probe -- measures the IFC <-> requirements MIRROR, by execution.

Summary:
    D-VII ruled the canon plane AUTHORED and owed a COHERENCE rule against the IFC
    (DECISION-D-VII-2026-08-23.md). Before that rule can be written, its obligations
    must be discovered the way the Atlas field set was: by running them over the
    corpus as it stands and publishing what holds, what fails, and what cannot be
    checked. This probe measures four obligations:

      C1  owner closure (IFC -> REQ): every `owner` on a FLOW node or OUTPUT names
          a requirement id declared in the batch corpus AND reflected in the living
          REQUIREMENTS.md. (V10 checks flow nodes vs batch corpus only; OUTPUT
          owners are checked by NOTHING today.)
      C2  transform closure (REQ -> IFC): within a batch that declares IFC, which
          of its own LLRs are never used as an owner -- the "LLR claiming a
          transform with no node" half of Part A, unchecked by any rule.
      C3  canon reflection: batch-declared requirement ids vs the living
          REQUIREMENTS.md -- the consolidation debt a seeding pass would close.
      C4  test reflection: AT/TC ids the living REQUIREMENTS.md cites, joined to
          registry status -- a canon citing RETIRED/BURNED ids is stale.

    NOT the shipped coherence rule. Same contract as atlas_probe: imports the canon
    validator (never a second parser), deterministic, deletable when the rule ships.

Data Flow:
    ~/.claude/docs/tools/devflow-validate.py --(importlib)--> dv module
    _ifc_corpus + REQUIREMENTS.md + AT-TC-REGISTRY.jsonl --> C1..C4 measurements
    --> stdout report

Dependencies:
    Uses: devflow-validate.py (canon), json, os, re, sys.
    Used by: nobody at runtime -- evidence generator for the coherence-rule design.

Example:
    python tools/coherence_probe.py        # from the worktree root
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

CANON = os.path.expanduser(os.path.join("~", ".claude", "docs", "tools", "devflow-validate.py"))
AT_TC = re.compile(r"\b(?:AT|TC)-(?:B\d+-)?\d+(?:\.\d+)?(?:[a-z]+)?\b")


def _load_canon():
    spec = importlib.util.spec_from_file_location("devflow_validate", CANON)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read(path):
    try:
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


def _first_line(raw):
    """Scalar view of a possibly prose-absorbed field (see ATLAS-FIELD-SET par.4 P1)."""
    return raw.splitlines()[0].strip() if raw else raw


def _owners(corpus):
    """-> sorted set of (owner, kind, where) over FLOW nodes AND outputs."""
    out = set()
    for flow in corpus["flows"]:
        for node in flow["nodes"]:
            o = _first_line(node.get("owner"))
            if o:
                out.add((o, "flow-node", "%s:%d" % (node["src"], node["line"])))
    for comp in corpus["components"]:
        for output in comp["outputs"]:
            o = _first_line(output.get("owner"))
            if o:
                out.add((o, "output", "%s:%d" % (output["src"], output["line"])))
    return sorted(out)


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    dv = _load_canon()
    corpus = dv._ifc_corpus(root)
    req_text = _read(os.path.join(root, "REQUIREMENTS.md")) or ""

    print("coherence_probe over %s" % root)
    print("=" * 74)
    print("C1 -- owner closure: IFC owner -> declared id -> living REQUIREMENTS.md")
    print("=" * 74)
    owners = _owners(corpus)
    n_flow = sum(1 for _, k, _ in owners if k == "flow-node")
    n_out = sum(1 for _, k, _ in owners if k == "output")
    print("distinct (owner, site) pairs : %d  (%d flow-node, %d output)"
          % (len(owners), n_flow, n_out))
    bad_decl, bad_canon = [], []
    for owner, kind, where in owners:
        if owner not in corpus["declared"]:
            bad_decl.append((owner, kind, where))
        if owner not in req_text:
            bad_canon.append((owner, kind, where))
    print("owners NOT declared in batch corpus  : %d  %s"
          % (len(bad_decl), [o for o, _, _ in bad_decl]))
    print("owners NOT reflected in REQUIREMENTS.md (living canon): %d" % len(bad_canon))
    for owner, kind, where in bad_canon:
        print("  MISSING %-12s (%s) %s" % (owner, kind, where))
    print("NOTE: OUTPUT owners are enforced by NO rule today -- V10 covers flow nodes "
          "only, V11 never reads `owner`. %d output-owner sites run unguarded." % n_out)

    print()
    print("=" * 74)
    print("C2 -- transform closure: LLRs of an IFC-bearing batch never used as owner")
    print("=" * 74)
    ifc_srcs = sorted({b["src"] for b in corpus["flows"] + corpus["components"]})
    owner_ids = {o for o, _, _ in owners}
    for src in ifc_srcs:
        text = _read(os.path.join(root, src.replace("/", os.sep))) or ""
        batch_llrs = set(re.findall(r"^#{2,5}\s+(LLR-[\w.]+(?:-[\w.]+)*)", text, re.M))
        unowned = sorted(batch_llrs - owner_ids)
        print("%s" % src)
        print("  LLR headings: %d   used as owner: %d   NEVER an owner: %s"
              % (len(batch_llrs), len(batch_llrs & owner_ids), unowned or "none"))
    print("NOTE: 'never an owner' is a QUESTION per LLR, not automatically a defect -- "
          "an LLR may constrain without transforming. The shipped rule needs a "
          "declared exemption convention, or this stays a NOTICE census.")

    print()
    print("=" * 74)
    print("C3 -- canon reflection: batch-declared ids vs living REQUIREMENTS.md")
    print("=" * 74)
    canon_missing = sorted(i for i in corpus["declared"] if i not in req_text)
    fam = {}
    for i in canon_missing:
        fam[i.split("-")[0]] = fam.get(i.split("-")[0], 0) + 1
    print("batch-declared heading ids           : %d" % len(corpus["declared"]))
    print("absent from REQUIREMENTS.md (debt)   : %d   by family: %s"
          % (len(canon_missing), json.dumps(fam, sort_keys=True)))
    print("  sample: %s" % ", ".join(canon_missing[:10]))
    print("This absence set IS the seeding backlog for the living requirements doc.")

    print()
    print("=" * 74)
    print("C4 -- test reflection: AT/TC cited by REQUIREMENTS.md vs registry status")
    print("=" * 74)
    status = {}
    for i, line in enumerate((_read(os.path.join(root, "AT-TC-REGISTRY.jsonl")) or "").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if "id" in row and "status" in row:
            status[row["id"]] = row["status"]
    cited = sorted(set(AT_TC.findall(req_text)))
    by_status, unknown = {}, []
    for cid in cited:
        st = status.get(cid)
        if st is None:
            unknown.append(cid)
        else:
            by_status[st] = by_status.get(st, 0) + 1
    print("AT/TC ids cited by REQUIREMENTS.md   : %d" % len(cited))
    print("  registry status of the cited       : %s" % json.dumps(by_status, sort_keys=True))
    print("  cited but NOT in registry          : %d  (batch-scoped by grammar: %d)"
          % (len(unknown), sum(1 for i in unknown if re.match(r"(?:AT|TC)-B\d+-", i))))
    stale = [c for c in cited if status.get(c) in ("RETIRED", "BURNED")]
    # REQUIREMENTS.md carries a `## Retired ids` ledger BY DESIGN (CLAUDE.md) -- a retired
    # id cited there is bookkeeping, not staleness. The debt is citations in the BODY.
    # Scoping measured 2026-08-23: without this split the figure read 21; the true body
    # debt is the list below. An unscoped threshold here would be handoff defect #7 again.
    split = req_text.split("\n## Retired ids", 1)
    body, retired_sec = split[0], (split[1] if len(split) > 1 else "")
    body_stale = sorted(c for c in stale if c in body)
    # Second scope, measured 2026-08-23: every one of the 6 first-pass body hits was
    # itself retirement PROSE ("are retired ->", "is deleted", "not reused") -- a record
    # OF the retirement, not a live citation. Split by line-level markers; the bare
    # remainder is the only claim of staleness, and it stays a NOTICE census (operator
    # ruling, same convention as C2), never an unscoped BLOCK.
    markers = re.compile(r"retired|deleted|not reused|superseded|withdrawn", re.I)
    bare = []
    for cid in body_stale:
        lines = [ln for ln in body.splitlines() if cid in ln]
        if not all(markers.search(ln) for ln in lines):
            bare.append(cid)
    print("  cited ids with registry status RETIRED/BURNED: %d total" % len(stale))
    print("    in the `## Retired ids` ledger only (correct bookkeeping): %d"
          % len([c for c in stale if c not in body]))
    print("    body mentions that are themselves retirement records     : %d  %s"
          % (len(body_stale) - len(bare), [c for c in body_stale if c not in bare]))
    print("    BARE body citations (the real staleness census)          : %d  %s"
          % (len(bare), bare))
    if not retired_sec:
        print("    WARNING: no `## Retired ids` section found -- split is vacuous")
    return 0


if __name__ == "__main__":
    sys.exit(main())

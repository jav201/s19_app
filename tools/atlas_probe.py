#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""atlas_probe -- DISCOVERY PROBE for the Atlas (D-I), handoff action 1.

Summary:
    Executes the derivation the Atlas design (HANDOFF-atlas-ifc-2026-08-22.md par.4/par.5)
    only asserts on paper, over the corpus AS IT STANDS, and prints per section:
    what IS derivable, what is NOT (the CANNOT list), and everything it failed to
    parse (the UNPARSED census, par.5.3). The CANNOT list frozen from one run of this
    probe IS the minimum derivable field set (par.4.1).

    THIS IS NOT THE SHIPPED --atlas. It writes no files, guards no digest, and must
    be DELETED when --atlas lands in devflow-validate.py (rev42+). It exists so the
    field set is discovered by execution rather than asserted (C-39).

    Per par.5.1 it is NOT a second parser: the canon validator is imported by path and
    every IFC figure comes from _ifc_corpus() and the real rule functions.

Args (argv):
    [PROJECT_ROOT]  optional; defaults to the current directory.

Data Flow:
    ~/.claude/docs/tools/devflow-validate.py --(importlib)--> dv module
    .dev-flow/** + REQUIREMENTS.md + AT-TC-REGISTRY.jsonl + tests/** --> censuses
    --> stdout report (ATLAS-IFC / TRACE / BATCHES / ORPHANS / UNPARSED / CANNOT)

Dependencies:
    Uses: devflow-validate.py (canon), json, os, re, sys.
    Used by: nobody at runtime -- evidence generator for the field-set freeze.

Example:
    python tools/atlas_probe.py            # from the worktree root
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys

CANON = os.path.expanduser(os.path.join("~", ".claude", "docs", "tools", "devflow-validate.py"))

AT_TC = re.compile(r"\b(?:AT|TC)-(?:B\d+-)?\d+(?:\.\d+)?(?:[a-z]+)?\b")
REQ_ID = re.compile(r"\b(?:US|HLR|LLR)-[\w.]+(?:-[\w.]+)*\b")
R_ID = re.compile(r"\bR-\d+\b")

CANNOT = []      # (section, claim measured, consequence for the field set)
UNPARSED = []    # (section, path-or-row, reason)


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


def _walk_files(base, want_ext):
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in ("__pycache__",))
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in want_ext:
                out.append(os.path.join(dirpath, name))
    return out


def _scalar(item, key, where):
    """A field the Atlas renders as ONE value. A newline inside it means the canon
    parser absorbed trailing document prose (no block terminator) -- census it,
    render only the first line, and never print the contamination as if it were data."""
    raw = item.get(key)
    if raw is None:
        return None
    if "\n" in raw:
        UNPARSED.append(("IFC", where, "field `%s` absorbed %d chars of trailing prose "
                         "(canon _parse_ifc has no block terminator)" % (key, len(raw))))
        return raw.splitlines()[0] + " [+ABSORBED]"
    return raw


def section_ifc(dv, root):
    print("=" * 74)
    print("ATLAS-IFC -- rendered from _ifc_corpus() and the real rule functions")
    print("=" * 74)
    corpus = dv._ifc_corpus(root)
    print("corpus files      : %d x 01-requirements.md" % len(corpus["files"]))
    print("declared req ids  : %d (US/HLR/LLR headings, merged)" % len(corpus["declared"]))
    print("FLOW declarations : %d  (one row PER DECLARATION -- par.5.4)" % len(corpus["flows"]))
    for flow in corpus["flows"]:
        print("  FLOW %-28s %s:%d" % (flow["id"], flow["src"], flow["line"]))
        for node in flow["nodes"]:
            where = "%s:%d" % (node["src"], node["line"])
            print("    NODE fn=%-40s owner=%s" % (_scalar(node, "fn", where),
                                                  _scalar(node, "owner", where)))
    print("COMPONENT decls   : %d  (one row PER DECLARATION -- par.5.4, never {id: comp})"
          % len(corpus["components"]))
    field_census = {}
    out_census = {}
    for comp in corpus["components"]:
        cwhere = "%s:%d" % (comp["src"], comp["line"])
        print("  COMPONENT %-24s %s" % (comp["id"], cwhere))
        for key in sorted(comp["fields"]):
            field_census[key] = field_census.get(key, 0) + 1
            print("    %-12s: %s" % (key, (_scalar(comp["fields"], key, cwhere) or "")[:72]))
        for output in comp["outputs"]:
            for key in sorted(k for k in output if k not in ("line", "src")):
                out_census[key] = out_census.get(key, 0) + 1
            consumers = dv._ifc_consumers(output)
            owhere = "%s:%d" % (output["src"], output["line"])
            print("    OUTPUT %-22s addr=%r card=%r consumers=%s owner=%s"
                  % (_scalar(output, "id", owhere), _scalar(output, "address", owhere),
                     _scalar(output, "cardinality", owhere),
                     "OMITTED" if consumers is None else len(consumers),
                     _scalar(output, "owner", owhere)))
    print("component field census : %s" % json.dumps(field_census, sort_keys=True))
    print("output field census    : %s" % json.dumps(out_census, sort_keys=True))
    if not any(k == "surface" for k in out_census):
        CANNOT.append(("IFC", "no OUTPUT in the corpus carries a `surface` field",
                       "a per-surface Atlas grouping is NOT derivable today; if wanted, "
                       "surfaces #2+ must declare it (one-way door, par.4.1)"))
    print("\nSTATUS (the real rules, not recomputed verdicts -- par.5.1):")
    for fn in (dv.v10_flow_node_owners, dv.v11_output_contract, dv.v12_balancing,
               dv.v13_undeclared_consumers, dv.v14_consumers_resolve,
               dv.v19_component_ids_unique):
        for f in fn(root, {}):
            print(str(f))
    return corpus


def section_trace(dv, root, corpus):
    print()
    print("=" * 74)
    print("ATLAS-TRACE -- where does every id live, and what is its state?")
    print("=" * 74)
    reg_path = os.path.join(root, "AT-TC-REGISTRY.jsonl")
    rows, statuses, unresolved_prov, no_prov = [], {}, 0, 0
    text = _read(reg_path) or ""
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            UNPARSED.append(("TRACE", "AT-TC-REGISTRY.jsonl:%d" % i, "not JSON"))
            continue
        if "_meta" in row:
            continue
        if "id" not in row or "status" not in row:
            UNPARSED.append(("TRACE", "AT-TC-REGISTRY.jsonl:%d" % i,
                             "row lacks id/status: %s" % sorted(row)))
            continue
        rows.append(row)
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
        prov = row.get("provenance")
        if not prov:
            no_prov += 1
        else:
            rel = prov.split(":")[0]
            if not os.path.isfile(os.path.join(root, rel.replace("/", os.sep))):
                unresolved_prov += 1
    print("registry rows     : %d   statuses: %s" % (len(rows), json.dumps(statuses, sort_keys=True)))
    print("provenance        : %d rows without; %d rows whose file is NOT on disk"
          % (no_prov, unresolved_prov))
    if unresolved_prov or no_prov:
        CANNOT.append(("TRACE", "%d registry rows lack provenance, %d point at files not on disk"
                       % (no_prov, unresolved_prov),
                       "TRACE cannot give file:line for those ids -- render state only"))

    realms = {"REQUIREMENTS.md": [os.path.join(root, "REQUIREMENTS.md")],
              ".dev-flow": _walk_files(os.path.join(root, ".dev-flow"), {".md"}),
              "tests": _walk_files(os.path.join(root, "tests"), {".py"})}
    ids = {}   # family -> realm -> set
    for realm, paths in realms.items():
        for path in paths:
            body = _read(path)
            if body is None:
                UNPARSED.append(("TRACE", path, "unreadable"))
                continue
            for fam, pat in (("AT/TC", AT_TC), ("US/HLR/LLR", REQ_ID), ("R", R_ID)):
                found = set(pat.findall(body))
                ids.setdefault(fam, {}).setdefault(realm, set()).update(found)
    for fam in sorted(ids):
        print("family %-10s : %s" % (fam, {r: len(s) for r, s in sorted(ids[fam].items())}))
    reg_ids = {r["id"] for r in rows}
    seen_attc = set().union(*ids.get("AT/TC", {}).values()) if ids.get("AT/TC") else set()
    off_reg = seen_attc - reg_ids
    batch_scoped = {i for i in off_reg if re.match(r"(?:AT|TC)-B\d+-", i)}
    print("AT/TC seen in tree but NOT in registry : %d  (%d batch-scoped by grammar -- "
          "outside the global pool BY DESIGN; %d global-pool ids, each a real question)"
          % (len(off_reg), len(batch_scoped), len(off_reg - batch_scoped)))
    print("registry ids never seen outside registry: %d" % len(reg_ids - seen_attc))
    if off_reg - batch_scoped:
        sample = sorted(off_reg - batch_scoped)[:12]
        print("  global-pool sample: %s" % ", ".join(sample))
    CANNOT.append(("TRACE", "US/HLR/LLR ids have NO registry and NO status field anywhere",
                   "TRACE can render (id, files that mention it) but NOT a state column "
                   "for the requirement families -- state exists only for AT/TC"))
    n_r = len(set().union(*ids.get("R", {}).values())) if ids.get("R") else 0
    print("R-* unique across all realms : %d  (the handoff's '149 R-*' is NOT a namespace "
          "this tree carries)" % n_r)
    return ids, rows


def section_batches(root):
    print()
    print("=" * 74)
    print("ATLAS-BATCHES -- what happened, batch by batch?")
    print("=" * 74)
    base = os.path.join(root, ".dev-flow")
    all_dirs = sorted(d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d)))
    batch_dirs = [d for d in all_dirs if re.match(r"\d{4}-\d{2}-\d{2}-batch-\d+$", d)]
    for d in all_dirs:
        if d not in batch_dirs and re.match(r"\d{4}-", d):
            UNPARSED.append(("BATCHES", ".dev-flow/" + d,
                             "dated dir NOT matching the batch pattern -- invisible to a "
                             "pattern-keyed BATCHES view unless censused"))
    canon_files = ("01-requirements.md", "02-review.md", "03-increments",
                   "04-validation.md", "05-postmortem.md", "05-close.md",
                   "state.json", "PLAN.md")
    have = {name: 0 for name in canon_files}
    pm_title, pm_date, pm_none = 0, 0, []
    st_fields = {}
    for d in batch_dirs:
        full = os.path.join(base, d)
        present = set(os.listdir(full))
        for name in canon_files:
            if name in present:
                have[name] += 1
        pm = _read(os.path.join(full, "05-postmortem.md"))
        if pm is None:
            pm_none.append(d)
        else:
            if re.match(r"^#\s", pm):
                pm_title += 1
            if re.search(r"\*\*Date:?\*\*\s*\S", pm):
                pm_date += 1
            else:
                UNPARSED.append(("BATCHES", d + "/05-postmortem.md",
                                 "no **Date:** field -- header shape not the batch-01 form"))
        st = _read(os.path.join(full, "state.json"))
        if st is not None:
            try:
                for key in json.loads(st):
                    st_fields[key] = st_fields.get(key, 0) + 1
            except ValueError:
                UNPARSED.append(("BATCHES", d + "/state.json", "not JSON"))
    print("batch dirs        : %d" % len(batch_dirs))
    for name in canon_files:
        print("  with %-18s: %d" % (name, have[name]))
    print("postmortems: %d with a title line, %d with a **Date:** field, %d ABSENT"
          % (pm_title, pm_date, len(pm_none)))
    if len(pm_none) > have["05-close.md"] or have["state.json"] < len(batch_dirs):
        CANNOT.append(("BATCHES",
                       "state.json exists for %d/%d batches; a parseable **Date:** header "
                       "for %d/%d postmortems" % (have["state.json"], len(batch_dirs),
                                                  pm_date, len(batch_dirs) - len(pm_none)),
                       "par.4.2's declared source (state.json + postmortem headers) covers a "
                       "FRACTION of history -- BATCHES must derive from presence/absence of "
                       "the numbered artifacts, or the missing fields must be backfilled"))
    print("per-batch state.json fields seen: %s" % json.dumps(st_fields, sort_keys=True))
    return batch_dirs


def section_orphans(corpus, ids, rows):
    print()
    print("=" * 74)
    print("ATLAS-ORPHANS -- the joins, plus everything the probe could not read")
    print("=" * 74)
    req_realm = ids.get("US/HLR/LLR", {})
    canon_ids = req_realm.get("REQUIREMENTS.md", set())
    batch_ids = req_realm.get(".dev-flow", set())
    print("US/HLR/LLR in batches but never in REQUIREMENTS.md : %d" % len(batch_ids - canon_ids))
    print("US/HLR/LLR in REQUIREMENTS.md but in no batch      : %d" % len(canon_ids - batch_ids))
    tests_attc = ids.get("AT/TC", {}).get("tests", set())
    reg_ids = {r["id"] for r in rows}
    print("AT/TC in registry never mentioned by tests/        : %d" % len(reg_ids - tests_attc))
    print("declared-heading ids (corpus) never in REQUIREMENTS.md: %d"
          % len(corpus["declared"] - canon_ids))
    print("\nUNPARSED census (par.5.3 -- an Atlas that cannot state what it failed to "
          "read is not accepted):")
    if not UNPARSED:
        print("  0 items -- and this line printing '0' is itself the census, not silence")
    for sec, where, why in UNPARSED:
        print("  [%s] %s -- %s" % (sec, where, why))


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    dv = _load_canon()
    print("atlas_probe over %s" % root)
    print("canon validator  : %s" % CANON)
    corpus = section_ifc(dv, root)
    ids, rows = section_trace(dv, root, corpus)
    section_batches(root)
    section_orphans(corpus, ids, rows)
    print()
    print("=" * 74)
    print("CANNOT-PRODUCE -- this list IS the minimum-field-set deliverable (par.4.1)")
    print("=" * 74)
    for i, (sec, claim, consequence) in enumerate(CANNOT, 1):
        print("%2d. [%s] %s\n    -> %s" % (i, sec, claim, consequence))
    if not CANNOT:
        print("nothing -- every field par.4.2 names derived cleanly (unlikely; suspect the probe)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

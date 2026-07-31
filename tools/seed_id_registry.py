"""
One-time seeder for ``AT-TC-REGISTRY.jsonl`` — spec §6 legacy-corpus disposition.

Run once, at the seed commit, to turn the repository's existing AT/TC id
population into the allocation authority::

    python tools/seed_id_registry.py --write
    python tools/seed_id_registry.py --outliers      # §6.4 report only

After the registry exists this script is **history, not machinery**: allocation
happens by appending reservations per spec §4.2, never by re-running the seed.
Re-running it would rebuild the file from current occupancy and silently drop
every ``RESERVED`` / ``RETIRED`` / ``BURNED`` row — the exact failure spec §10
rejects under *"generate the registry from tests/ on every run"*. The
``--write`` flag refuses to clobber an existing registry for that reason.

The per-id dispositions in :data:`DISPOSITIONS` are **hand-authored evidence**,
not derivation: spec §6.1 forbids a bulk relabel because the phantoms are not
one class. Each entry records what was verified on disk and in git history.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.id_registry import (  # noqa: E402
    CONFORMING_BODY_RE,
    derive_citation_nodes,
    derive_named_nodes,
    dump_entry,
    iter_tokens,
    normalize,
    read_text,
    registry_path,
    repo_root,
    requirements_path,
    scanned_test_files,
    sort_key,
)

SEED_COMMIT = "232eb0a"

# ---------------------------------------------------------------------------
# Reservations the registry must be BORN knowing (spec §4.2 / §4.3).
#
# batch-75 is chartered and may be executing concurrently with this seed. A
# registry that did not record its block would set next_free below work already
# in flight, and its own guard would then redden against legitimate ids — a
# guard that fires on correct work is worse than no guard, because it teaches
# everyone to wave it through.
# ---------------------------------------------------------------------------
RESERVED_BLOCKS: List[Tuple[str, int, int, str, str]] = [
    ("AT", 250, 279, "batch-75", "Chartered F4 + D2 carry from batch-74; block reserved ahead of its Phase 1."),
    ("TC", 552, 599, "batch-75", "Chartered F4 + D2 carry from batch-74; block reserved ahead of its Phase 1."),
]

# ---------------------------------------------------------------------------
# Ids this batch mints for its own work, from ABOVE the batch-75 reservation.
# ---------------------------------------------------------------------------
MINTED: List[Tuple[str, str, List[str]]] = [
    (
        "AT-280",
        "The repository and the id registry agree in both directions: no test node "
        "carries an unregistered id, and no registered LIVE id names a node that "
        "does not exist.",
        ["tests/test_id_registry.py::test_at280_registry_and_repository_agree_in_both_directions"],
    ),
    (
        "AT-281",
        "Each of the seven guard rules G1-G7 can be made to fail by a single "
        "targeted mutation of the registry or the tree, so none of them is vacuous.",
        ["tests/test_id_registry.py::test_at281_every_guard_rule_can_fail"],
    ),
    (
        "TC-600",
        "G1 - every id derivable from a test node name is registered.",
        ["tests/test_id_registry.py::test_tc600_g1_every_named_node_id_is_registered"],
    ),
    (
        "TC-601",
        "G2 - every LIVE entry's declared nodes exist; non-LIVE statuses are exempt "
        "by status, not by absence.",
        ["tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes"],
    ),
    (
        "TC-602",
        "G3 - every governed id cited in tests/ or REQUIREMENTS.md is registered in "
        "some status.",
        ["tests/test_id_registry.py::test_tc602_g3_every_citation_is_registered"],
    ),
    (
        "TC-603",
        "G4 - an id cited in REQUIREMENTS.md is LIVE unless the citation falls under "
        "a declared exempt anchor.",
        ["tests/test_id_registry.py::test_tc603_g4_requirements_citations_are_live"],
    ),
    (
        "TC-604",
        "G5 - every governed token in the scanned corpus either parses per the "
        "grammar or is a registered conforming:false entry.",
        ["tests/test_id_registry.py::test_tc604_g5_grammar_holds_or_is_registered_legacy"],
    ),
    (
        "TC-605",
        "G6 - no two registry entries share a normalized key, so zero-padding "
        "aliases cannot both be allocated.",
        ["tests/test_id_registry.py::test_tc605_g6_normalized_keys_are_unique"],
    ),
    (
        "TC-606",
        "G7 - no entry's stem exceeds the recorded high-water mark for its space.",
        ["tests/test_id_registry.py::test_tc606_g7_no_stem_exceeds_the_high_water_mark"],
    ),
    (
        "TC-607",
        "The guard's scanned-file count matches its declared constant, bounding CI "
        "cost as an executable threshold rather than a wall-clock assertion.",
        ["tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound"],
    ),
    (
        "TC-608",
        "Normalization collapses zero-padding and dotted stems to one key, and the "
        "tokenizer's attested edge cases resolve as specified.",
        ["tests/test_id_registry.py::test_tc608_tokenizer_and_normalizer_edge_cases"],
    ),
    (
        "TC-610",
        "The batch-75 reservation block is recorded in the registry and nothing was "
        "minted inside it.",
        ["tests/test_id_registry.py::test_tc610_reservations_are_recorded_and_respected"],
    ),
    (
        "TC-609",
        "The registry file is well-formed: a _meta header, one JSON object per "
        "line, required keys present, and status-conditional fields supplied.",
        ["tests/test_id_registry.py::test_tc609_registry_file_is_well_formed"],
    ),
]

# ---------------------------------------------------------------------------
# Phantom dispositions (spec §6.1). One line per id, each with what was
# verified. A bulk relabel is FORBIDDEN and every rationale here names the
# evidence that produced it.
# ---------------------------------------------------------------------------
_CDFX = (
    "Verifier lived in the cdfx/ test suite (tests/test_cdfx_*.py), which was removed "
    "when the cdfx package retired at batch-07 E3b; no such file exists at the seed "
    "commit. Recorded in tests/test_engine_unchanged.py's module docstring."
)
_ENTROPY = (
    "Verifier lived in tests/test_tui_entropy_viewer.py, which does not exist at the "
    "seed commit. REQUIREMENTS.md:3839 and :3879 already stated the file 'is deleted' "
    "in prose while the Validation lines kept citing it as a live verifier."
)
_GRID_2X2 = (
    "Retired by REQUIREMENTS.md:3525 itself (batch-46 §36, R-TUI-063/064): the 2x2 "
    "four-pane grid was superseded by the responsive three-window layout and "
    "'AT-033a/b/c + TC-033 are retired -> AT-063a/b/c + AT-064a/b/c'. The cited "
    "nodes test_at_033a/b/c_* were removed in 19bf1eb and exist nowhere at the seed "
    "commit; the Validation line at :3523 was never updated."
)

DISPOSITIONS: Dict[str, Dict[str, object]] = {
    # -- already declared retired in prose; zero judgement required (§6.1 row 3)
    "AT-195": {"status": "RETIRED", "retired_reason":
               "Transcribed from REQUIREMENTS.md:5106, which already declares AT-195 and "
               "TC-496 'retired ids and are not reused': AT-195 was mechanism-only under a "
               "black-box id and was withdrawn."},
    "TC-496": {"status": "RETIRED", "retired_reason":
               "Transcribed from REQUIREMENTS.md:5106-5107: TC-496 was file-observed under a "
               "white-box id and was promoted, and the id is not reused."},

    # -- the 2x2 patch-layout supersession
    "AT-33a": {"status": "RETIRED", "retired_reason": _GRID_2X2},
    "AT-33b": {"status": "RETIRED", "retired_reason": _GRID_2X2},
    "AT-33c": {"status": "RETIRED", "retired_reason": _GRID_2X2},

    # -- the deleted entropy viewer (§6.1 row 1, extended: the AT side is the
    #    same deletion and the spec counted only the TC half)
    "AT-62a": {"status": "RETIRED", "retired_reason": _ENTROPY},
    "AT-62b": {"status": "RETIRED", "retired_reason": _ENTROPY},
    "TC-324": {"status": "RETIRED", "retired_reason": _ENTROPY},
    "TC-325": {"status": "RETIRED", "retired_reason": _ENTROPY},
    "TC-326": {"status": "RETIRED", "retired_reason": _ENTROPY},
    "TC-327": {"status": "RETIRED", "retired_reason": _ENTROPY},

    # -- the retired cdfx suite
    "TC-19a": {"status": "RETIRED", "retired_reason": _CDFX},
    "TC-19d": {"status": "RETIRED", "retired_reason": _CDFX},
    "TC-19h": {"status": "RETIRED", "retired_reason": _CDFX},
    "TC-27a": {"status": "RETIRED", "retired_reason": _CDFX},
    "TC-27b": {"status": "RETIRED", "retired_reason": _CDFX},

    # -- §6.1 row 2: TC-319/TC-320, "renamed or removed - must be determined,
    #    not assumed". Determined from git history, not assumed.
    "TC-319": {"status": "RETIRED", "retired_reason":
               "REMOVED, not renamed - determined from git history. "
               "test_tc319_regroup_section_structure_census was added at 2a647d1 (batch-35) "
               "and removed at 19bf1eb (batch-46) when tests/test_tui_patch_layout.py was "
               "rewritten for the three-window layout. Its census assertion SURVIVES, "
               "re-homed as the module-level _MUST_PRESERVE_IDS tuple "
               "(tests/test_tui_patch_layout.py:67) consumed at :353 by _drive_reparent_safety, "
               "which feeds test_at063c_reparent_safety_at_80/_at_120. "
               "CONSEQUENCE FOR C-26: its evidentiary basis is intact but now carried by "
               "AT-063c, not TC-319. The id is dead; the evidence is not. Anyone tracing "
               "C-26 through TC-319 finds nothing and must follow AT-063c instead."},
    "TC-320": {"status": "RETIRED", "retired_reason":
               "Cited once, at REQUIREMENTS.md:3658, as a parenthetical '(TC-320 drift-set "
               "assertion: patch cells only)' with no node reference anywhere in the repo and "
               "no node of that id in git history. The drift-set assertion it names is carried "
               "by tests/test_tui_snapshot.py::test_tc321_batch36_patch_xfail_set (TC-321, "
               "LIVE), which pins the patch xfail set to exactly the two patch cells. TC-320 "
               "is a stale second id for TC-321's observable."},

    # -- AT-58a: removed and superseded in one commit
    "AT-58a": {"status": "RETIRED", "retired_reason":
               "Node test_at058a_paste_editor_in_viewport_and_separated was removed at 19bf1eb "
               "(batch-46) and replaced in the same commit by "
               "tests/test_tui_patch_layout.py::test_tc46_2_paste_in_viewport_at_body_scroll0, "
               "whose docstring names itself 'the single authoritative verifier of the "
               "paste-in-viewport outcome'. The observable is covered under TC-46.2; the id "
               "AT-058a is spent."},

    # -- non-conforming legacy whose node DOES exist: LIVE, not phantom.
    "AT-030a-r2": {"status": "LIVE",
                  "nodes": ["tests/test_tui_patch_editor_v2.py::"
                            "test_at030a_r2_save_while_open_appears_without_reactivation"],
                  "statement": "A change file saved while the Patch Editor is open appears in the "
                               "dropdown without reactivating the screen.",
                  "note": "Not a phantom: the node exists. The id is non-conforming "
                          "(AT-030a-R2 carries a '-R2' tail the grammar does not produce), so "
                          "no name-derivation rule reaches it and it must be declared."},

    # -- bound to a PARAMETRIZED node; §2.4 forbids brackets in a node ref, so
    #    the binding is to the bare name.
    "AT-34a": {"status": "LIVE",
               "nodes": ["tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot"],
               "statement": "The patch screen renders at the comfortable density at 80x24 "
                            "without layout drift (snapshot case patch-comfortable-80x24)."},
    "AT-34b": {"status": "LIVE",
               "nodes": ["tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot"],
               "statement": "The patch screen renders at the comfortable density at 120x30 "
                            "without layout drift (snapshot case patch-comfortable-120x30)."},

    # -- a whole FILE is cited, no node ref. The pilot node exists under a
    #    conforming sibling id; verified by name, not assumed.
    "AT-050a-pilot": {"status": "LIVE",
                     "nodes": ["tests/test_tui_patch_editor_v2.py::"
                               "test_at050a_pilot_mixed_results_via_real_button"],
                     "statement": "The batch-33 pilot drives US-050 through the real Patch "
                                  "Editor button over a check doc with a collision."},

    # -- §6.2 residue: cited in a MODULE DOCSTRING only. Each resolved
    #    individually; none is bound by invention.
    "AT-58": {"status": "LIVE",
              "nodes": ["tests/test_crc_designer_view.py::"
                        "test_routing_key_0_shows_crc_designer_hides_others"],
              "statement": "Navigation into the CRC Designer is driven through the routing "
                           "gate rather than direct mounting (LLR-V1.1)."},
    "TC-141": {"status": "RETIRED", "retired_reason":
               "Cited only in the module docstring of tests/test_a2l_inline_axis_length.py:19 as "
               "a PLACEMENT constraint ('batch-55's new tests must NOT land there', LLR-P1b.7), "
               "not as an assertion that file makes. No node carries it and none should: the "
               "constraint is about where tests live, so the file it names is the subject, not "
               "the verifier."},
    "TC-152": {"status": "RETIRED", "retired_reason":
               "Same shape as TC-141: cited only in the module docstring of "
               "tests/test_a2l_alignment_sizing.py:20 as a placement constraint "
               "('batch-56's new tests must NOT land there', LLR-A56.6). No node asserts it."},

    # -- the CONSOLIDATED BATTERY case: one id, N nodes, the mapping held in
    #    prose until now. This is exactly the C-3 / batch-62 '16 of 23' shape,
    #    and expressing it is what closes them (spec §8.1).
    "TC-24.3": {"status": "LIVE",
                "nodes": ["tests/test_report_addendum.py::test_membership_is_inclusive_at_both_bounds",
                          "tests/test_report_addendum.py::test_rejects_bad_bounds",
                          "tests/test_report_addendum.py::test_rejects_empty_or_control_only_name",
                          "tests/test_report_addendum.py::test_name_is_scrubbed_of_control_and_ansi",
                          "tests/test_report_addendum.py::test_name_is_length_capped"],
                "statement": "The DeclaredRegion model enforces inclusive bounds, rejects bad "
                             "bounds and empty/control-only names, scrubs control and ANSI "
                             "sequences from the name, and caps its length (US-020c, LLR-024.1)."},

    # -- §6.4 OUTLIER. The gap report flags three stems at the seed commit;
    #    only this one is pathological, and each was inspected individually
    #    rather than the whole flagged set being relabelled:
    #      TC-201 (gap 153->201) -- a deliberate block start, in sequence. KEEP conforming.
    #      TC-301 (gap 231->301) -- a deliberate block start, in sequence. KEEP conforming.
    #      TC-1728                -- pathological, disposed here.
    #    Forcing conforming:false is what keeps next_free(TC) at 610 instead of
    #    1729. A blind bulk import would have broken the allocation rule on day one.
    "TC-1728": {"status": "BURNED", "conforming": False, "provenance":
                ".dev-flow/2026-07-08-batch-29/_qa-acceptance-validation.md:252 — a stray "
                "reference, 1119 above its nearest neighbour, already identified as stray by "
                "batch-65 (.dev-flow/2026-07-28-batch-65/PLAN.md:90). Marked conforming:false so "
                "it is permanently spent WITHOUT dragging the TC high-water mark to 1729."},

    # -- a COVERAGE GAP, surfaced rather than papered over.
    "TC-355": {"status": "BURNED", "provenance":
               "tests/test_flow_crc_block.py:10 — the module docstring advertises "
               "'TC-355 no-raise' as one of the file's arms, but no node in that file asserts a "
               "no-raise path, and `git log -S tc355` over all refs returns nothing: the id "
               "NEVER had a verifier. BURNED, not RETIRED, precisely so this reads as 'no "
               "coverage claim ever existed' rather than 'coverage was lost'. The gap itself is "
               "registered in .dev-flow/BACKLOG-CODE.md."},
}

# Ids whose disposition above names a node that must be verified to exist before
# the seed is written; a disposition citing a non-existent node would be a
# phantom created by the fix.
_VERIFY_NODES = (
    "AT-030a-r2", "AT-34a", "AT-34b", "AT-050a-pilot", "AT-58", "TC-24.3",
)


def collect(root: Path) -> dict:
    """Gather every corpus fact the seed needs, in one pass per corpus."""
    tests = scanned_test_files(root)

    def cited(paths: List[Tuple[str, str]]) -> Dict[str, Dict[str, object]]:
        out: Dict[str, Dict[str, object]] = {}
        for rel, text in paths:
            if "AT-" not in text and "TC-" not in text:
                continue
            for token, line in iter_tokens(text):
                if not token.governed or token.key is None:
                    continue
                slot = out.setdefault(
                    token.key, {"raw": set(), "locs": [], "conforming": token.conforming}
                )
                slot["raw"].add(token.raw)
                if len(slot["locs"]) < 4:
                    slot["locs"].append(f"{rel}:{line}")
        return out

    tests_pairs = [(p.relative_to(root).as_posix(), read_text(p)) for p in tests]
    req_pairs = [("REQUIREMENTS.md", read_text(requirements_path(root)))]

    devflow_pairs = []
    for folder in (".dev-flow", ".fast-dev-flow"):
        base = root / folder
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                devflow_pairs.append((path.relative_to(root).as_posix(), read_text(path)))

    c_tests, c_req, c_dev = cited(tests_pairs), cited(req_pairs), cited(devflow_pairs)
    attested = set(c_tests) | set(c_req) | set(c_dev)

    named = derive_named_nodes(tests, root, attested=attested)
    banner = derive_citation_nodes(tests, root)

    return {
        "tests": c_tests,
        "req": c_req,
        "dev": c_dev,
        "attested": attested,
        "named": named,
        "banner": banner,
        "n_test_files": len(tests),
    }


def canonical_raw(raws: Set[str]) -> str:
    """Pick the canonical spelling: the longest, then lexicographically first."""
    return sorted(raws, key=lambda r: (-len(r), r))[0]


def build(root: Path) -> Tuple[List[dict], dict, dict]:
    """Build every registry record. Returns (records, meta, stats)."""
    facts = collect(root)
    c_tests, c_req, c_dev = facts["tests"], facts["req"], facts["dev"]
    named, banner = facts["named"], facts["banner"]

    records: List[dict] = []
    stats = {"LIVE": 0, "RESERVED": 0, "RETIRED": 0, "BURNED": 0,
             "named_bound": 0, "banner_bound": 0, "declared_bound": 0}

    # An id may exist ONLY as a node name, never cited as text anywhere — e.g.
    # AT-125b, carried by test_at125b_crc_after_patch_does_not_warn and written
    # down in no document. Seeding from citations alone would leave every such
    # id unregistered and G1 red on the day the registry landed.
    all_keys = set(c_tests) | set(c_req) | set(c_dev) | set(named) | set(banner)

    minted_keys = {normalize(*i.split('-', 1)) for i, _, _ in MINTED}

    for key in sorted(all_keys):
        # MINTED ids are declared explicitly below; the derived pass would
        # otherwise seed them a second time from this batch's own guard node
        # names and G6 would (correctly) report every one as a duplicate.
        if key in minted_keys:
            continue
        space = key.split("-", 1)[0]
        raws = set()
        conforming = True
        for source in (c_tests, c_req, c_dev):
            if key in source:
                raws |= source[key]["raw"]
                conforming = conforming and bool(source[key]["conforming"])
        if not raws:
            # Node-only id: reconstruct the canonical spelling from the key.
            raws = {key}
            conforming = bool(CONFORMING_BODY_RE.fullmatch(key.split("-", 1)[1]))
        identifier = canonical_raw(raws)

        nodes = sorted(named.get(key, set()) | banner.get(key, set()))
        disposition = DISPOSITIONS.get(key)

        if disposition is not None:
            record = {
                "id": identifier,
                "space": space,
                "status": disposition["status"],
                # A disposition may FORCE conforming:false for a §6.4 outlier
                # that parses fine but must not participate in allocation.
                "conforming": bool(disposition.get("conforming", conforming)),
                "origin": "seed",
            }
            if disposition["status"] == "LIVE":
                record["statement"] = disposition["statement"]
                record["nodes"] = list(disposition.get("nodes") or nodes)
                stats["declared_bound"] += 1
            elif disposition["status"] == "BURNED":
                record["provenance"] = disposition["provenance"]
            else:
                record["retired_reason"] = disposition["retired_reason"]
            records.append(record)
            stats[disposition["status"]] += 1
            continue

        if nodes:
            record = {
                "id": identifier,
                "space": space,
                "status": "LIVE",
                "conforming": conforming,
                "origin": "seed",
                "statement": _statement_for(key, nodes),
                "nodes": nodes,
            }
            stats["LIVE"] += 1
            if key in named:
                stats["named_bound"] += 1
            else:
                stats["banner_bound"] += 1
            records.append(record)
            continue

        # No node, no hand disposition -> it exists only in the batch archive.
        records.append({
            "id": identifier,
            "space": space,
            "status": "BURNED",
            "conforming": conforming,
            "origin": "seed",
            "provenance": sorted(c_dev.get(key, {}).get("locs", ["unknown"]))[0],
        })
        stats["BURNED"] += 1

    # Reservations, then this batch's own mints, both above every seeded stem.
    for space, low, high, owner, why in RESERVED_BLOCKS:
        for stem in range(low, high + 1):
            records.append({
                "id": f"{space}-{stem}",
                "space": space,
                "status": "RESERVED",
                "conforming": True,
                "origin": owner,
                "statement": why,
                "reserved_by": owner,
            })
            stats["RESERVED"] += 1

    for identifier, statement, nodes in MINTED:
        records.append({
            "id": identifier,
            "space": identifier.split("-", 1)[0],
            "status": "LIVE",
            "conforming": True,
            "origin": "at-tc-registry-lane-a",
            "statement": statement,
            "nodes": list(nodes),
        })
        stats["LIVE"] += 1

    high_water = {
        space: max(
            (int(re.match(r"\d+", r["id"].split("-", 1)[1]).group(0))
             for r in records
             if r["space"] == space and r["conforming"]
             and re.match(r"\d+", r["id"].split("-", 1)[1])),
            default=0,
        )
        for space in ("AT", "TC")
    }

    meta = {
        "_meta": {
            "schema": 1,
            "purpose": "Single authority for AT/TC id allocation. "
                       "See .dev-flow/AT-TC-REGISTRY-SPEC.md; allocation rule in its section 4.",
            "seed_commit": SEED_COMMIT,
            "grammar": "id ::= (AT|TC) '-' stem [suffix]; stem ::= digit+ ['.' digit+]; "
                       "suffix ::= [a-z]+",
            "token_pattern": r"\b(AT|TC)-([A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)",
            "governed": "A token whose body starts with a digit. Letter-initial bodies "
                        "(AT-B64-04, AT-CRC-DSN-010, the AT-NNN placeholder) are "
                        "batch-scoped / named-subspace ids, outside this authority by spec 2.3.",
            "high_water": high_water,
            "next_free": {space: value + 1 for space, value in high_water.items()},
            "g4_exempt_anchors": [
                "## History / superseded",
                "## Retired ids",
            ],
            "scanned": ["tests/**/*.py (excluding goldens, __snapshots__, _artifacts)",
                        "REQUIREMENTS.md"],
            "not_scanned": [".dev-flow/", ".fast-dev-flow/", "s19_app/", "docs/", "prototypes/"],
        }
    }
    return records, meta, stats


def _statement_for(key: str, nodes: List[str]) -> str:
    """Derive a minimal statement for a mechanically-bound id."""
    names = sorted({node.split("::", 1)[1] for node in nodes})
    shown = ", ".join(names[:3]) + (f" (+{len(names) - 3} more)" if len(names) > 3 else "")
    return f"Seeded from the existing verifier(s): {shown}."


def outlier_report(records: List[dict]) -> List[str]:
    """Spec §6.4 — flag every stem gap greater than 25, per space."""
    lines: List[str] = []
    for space in ("AT", "TC"):
        stems = sorted({
            int(re.match(r"\d+", r["id"].split("-", 1)[1]).group(0))
            for r in records
            if r["space"] == space and re.match(r"\d+", r["id"].split("-", 1)[1])
        })
        previous: Optional[int] = None
        for stem in stems:
            if previous is not None and stem - previous > 25:
                lines.append(f"{space}: gap {previous} -> {stem} (delta {stem - previous})")
            previous = stem
        lines.append(f"{space}: {len(stems)} distinct stems, max {stems[-1] if stems else 0}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write AT-TC-REGISTRY.jsonl")
    parser.add_argument("--outliers", action="store_true", help="print the §6.4 outlier report")
    parser.add_argument("--force", action="store_true", help="allow overwriting an existing registry")
    args = parser.parse_args()

    root = repo_root(Path(__file__))
    records, meta, stats = build(root)

    if args.outliers:
        for line in outlier_report(records):
            print(line)
        return 0

    records.sort(key=sort_key)
    body = "\n".join([_dump_meta(meta)] + [dump_entry(r) for r in records]) + "\n"

    print(f"records: {len(records)}")
    for name, count in sorted(stats.items()):
        print(f"  {name}: {count}")
    print(f"  high_water: {meta['_meta']['high_water']}  next_free: {meta['_meta']['next_free']}")

    target = registry_path(root)
    if args.write:
        if target.exists() and not args.force:
            print(f"refusing to overwrite {target} — the seed is a one-time operation "
                  f"(pass --force only if you mean to discard every reservation)")
            return 1
        target.write_text(body, encoding="utf-8", newline="\n")
        print(f"wrote {target}")
    return 0


def _dump_meta(meta: dict) -> str:
    import json
    return json.dumps(meta, ensure_ascii=False)


if __name__ == "__main__":
    raise SystemExit(main())

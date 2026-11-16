from collections import Counter
from pathlib import Path
import re

BATCH = Path(".dev-flow/2026-11-05-batch-103")
FORMS = {"U": "U", "E": "When", "I": "If", "S": "While", "When": "When", "While": "While", "If": "If", "Where": "Where"}
GONE = re.compile(r"(?:—|–|\s-)\s*\**\s*withdrawn\b", re.I)
CANON_TEXT = {
    "R-COPY.23": "When the operator presses `q` while no session action runs, the system shall show one instance of the quit dialog, whether a selection is present or absent.",
    "R-PE-BENCH.29": "When the operator moves the cursor on the bench of an object of more than 4,096 elements that holds a previewed bench edit, the system shall handle the key within 0.5 s, or within 1.0 s while a preview or a record-stage encode of that object is running.",
}


INCREMENT_ORDER = (
    "inc-1a", "inc-1b", "inc-2", "inc-3", "inc-4", "inc-5", "inc-6", "inc-7",
    "inc-8", "inc-9", "inc-8b", "inc-9b", "inc-10", "inc-11", "inc-12",
)


def increment_key(path):
    return INCREMENT_ORDER.index(path.parent.name)


def cells(line):
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def requirement_rows(path):
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("| R-"):
            continue
        row = cells(line)
        if len(row) < 3 or row[1] not in FORMS:
            continue
        yield {
            "id": row[0],
            "form": FORMS[row[1]],
            "text": CANON_TEXT.get(row[0], row[2]),
            "status": row[6] if len(row) > 6 else "unlabelled",
            "withdrawn": bool(GONE.search(line)),
            "source": f"{path.parent.name}:{number}",
        }


def status_class(row):
    if row["withdrawn"]:
        return "withdrawn"
    status = row["status"].strip("* ").lower()
    if status.startswith("new"):
        return "new"
    if status.startswith("changed") or status == "Δ":
        return "changed"
    if status.startswith("cited"):
        return "cited"
    return "other-active"


def id_key(requirement_id):
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in re.split(r"[.-]", requirement_id))


def canon_row(row):
    return f"| {row['id']} | {row['form']} | {row['text']} |"


def table(rows):
    return "\n".join(["| Id | Form | Requirement |", "|---|---|---|", *(canon_row(row) for row in rows)])


def insert_after_id(text, requirement_id, row):
    marker = f"| {requirement_id} |"
    position = text.index(marker)
    end = text.index("\n", position)
    return text[: end + 1] + canon_row(row) + "\n" + text[end + 1 :]


def main():
    repo = Path.cwd()
    canon_path = repo / "REQUIREMENTS.md"
    paths = sorted((repo / BATCH).glob("inc-*/01-requirements.md"), key=increment_key)
    assert len(paths) == 15, [str(path) for path in paths]
    rows_by_increment = {path.parent.name: list(requirement_rows(path)) for path in paths}

    inventory = []
    latest = {}
    for path in paths:
        increment = path.parent.name
        rows = rows_by_increment[increment]
        classes = Counter(status_class(row) for row in rows)
        cases = ", ".join(case.name for case in sorted(path.parent.glob("02-test-cases*.md")))
        withdrawn = [row["id"] for row in rows if row["withdrawn"]]
        inventory.append(f"{increment}: {len(rows)} definitions; " + ", ".join(f"{key}={value}" for key, value in sorted(classes.items())))
        inventory.append(f"  cases: {cases}")
        inventory.append(f"  withdrawn here: {', '.join(withdrawn) if withdrawn else 'none'}")
        inventory.append("  active definitions: " + ", ".join(row["id"] for row in rows if not row["withdrawn"]))
        for row in rows:
            latest[row["id"]] = row
    (repo / BATCH / "evidence/canon/inventory.txt").write_text("\n".join(inventory) + "\n", encoding="utf-8")

    text = canon_path.read_text(encoding="utf-8")
    canon = {}
    for line in text.splitlines():
        if line.startswith("| R-"):
            row = cells(line)
            if len(row) == 3 and row[1] in set(FORMS.values()):
                assert row[0] not in canon, f"duplicate canon id: {row[0]}"
                canon[row[0]] = (row[1], row[2])

    report = []
    for requirement_id, row in sorted(latest.items(), key=lambda item: id_key(item[0])):
        current = canon.get(requirement_id)
        if row["withdrawn"]:
            if current is not None:
                text = "\n".join(line for line in text.split("\n") if not line.startswith(f"| {requirement_id} |"))
                report.append(f"REMOVE {requirement_id} ({row['source']})")
                del canon[requirement_id]
            continue
        wanted = (row["form"], row["text"])
        if current is not None and current != wanted:
            old_line = f"| {requirement_id} | {current[0]} | {current[1]} |"
            assert text.count(old_line) == 1, requirement_id
            text = text.replace(old_line, canon_row(row))
            report.append(f"REPLACE {requirement_id} ({row['source']})")
            canon[requirement_id] = wanted

    missing = {requirement_id: row for requirement_id, row in latest.items() if not row["withdrawn"] and requirement_id not in canon}
    for requirement_id in ("R-TUI-042a.3", "R-HEX-EMIT-001.11"):
        row = missing.pop(requirement_id, None)
        if row is not None:
            previous = "R-TUI-042a.2" if requirement_id == "R-TUI-042a.3" else "R-HEX-EMIT-001.10"
            text = insert_after_id(text, previous, row)
            report.append(f"INSERT {requirement_id} after {previous} ({row['source']})")

    groups = [
        ("R-A2L-LIST", "##### List of labels (CTX-A2L-LIST; batch-103 Inc 7)", "\n<a id=\"s3\"></a>"),
        ("R-COPY", "##### Copy out of a view (CTX-COPY; batch-103 Inc 1b)", "\n#### S7.4 · Window help"),
        ("R-PE-DEF", "#### S10.10 · Edit by definition (CTX-PE-DEF; batch-103 Inc 8/8b)", "\n<a id=\"s11\"></a>"),
        ("R-PE-BENCH", "#### S10.11 · CURVE / MAP / VAL_BLK benches (CTX-PE-BENCH; batch-103 Inc 8b/9/9b)", "\n<a id=\"s11\"></a>"),
        ("R-PE-EXPORT", "#### S10.12 · Apply visibly and export (CTX-SAVEBACK; batch-103 Inc 10)", "\n<a id=\"s11\"></a>"),
    ]
    for prefix, heading, marker in groups:
        rows = sorted((row for requirement_id, row in missing.items() if requirement_id.startswith(prefix + ".") or requirement_id.startswith(prefix + "-")), key=lambda row: id_key(row["id"]))
        if not rows:
            continue
        assert text.count(marker) == 1, marker
        block = f"\n{heading}\n\n{table(rows)}\n"
        text = text.replace(marker, block + marker)
        report.append(f"GROUP {prefix}: {len(rows)} rows; {', '.join(row['id'] + ' (' + row['source'] + ')' for row in rows)}")

    leftovers = [requirement_id for requirement_id in missing if not any(requirement_id.startswith(prefix + ".") or requirement_id.startswith(prefix + "-") for prefix, _, _ in groups)]
    assert not leftovers, f"unmapped missing ids: {leftovers}"
    canon_path.write_text(text, encoding="utf-8")
    report.append(f"SUMMARY latest={len(latest)} active={sum(not row['withdrawn'] for row in latest.values())} withdrawn={sum(row['withdrawn'] for row in latest.values())}")
    (repo / BATCH / "evidence/canon/fold-report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    print("\n".join(report))


if __name__ == "__main__":
    main()

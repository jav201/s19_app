from __future__ import annotations

from typing import Any, Optional


def build_a2l_name_index(a2l_data: Optional[dict]) -> dict[str, list[dict]]:
    """
    Summary:
        Case-insensitive index from measurement/characteristic name to tag dicts.

    Args:
        a2l_data (Optional[dict]): Parsed A2L payload with ``tags`` list.

    Returns:
        dict[str, list[dict]]: Lowercased name to list of matching tag rows.

    Data Flow:
        - Scan ``tags``; skip blank names; append under lowercased key.

    Dependencies:
        Used by:
            - MAC table rendering in the web viewer
    """
    index: dict[str, list[dict]] = {}
    if not a2l_data:
        return index
    for tag in a2l_data.get("tags", []):
        name = str(tag.get("name") or "").strip()
        if not name:
            continue
        index.setdefault(name.lower(), []).append(tag)
    return index


def enrich_tags_with_validation(
    a2l_data: dict, mem_map: Optional[dict[int, int]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Summary:
        Merge ``validate_a2l_tags`` results onto raw tags and build full summary lines.

    Args:
        a2l_data (dict): Parsed A2L payload.
        mem_map (Optional[dict[int, int]]): Loaded image bytes for memory checks, or None.

    Returns:
        tuple[list[dict[str, Any]], list[str]]: Enriched tag rows and summary text lines.

    Data Flow:
        - Run validation with optional memory map.
        - Merge check rows by ``(section, name)``.
        - Build full summary line list for scrollable HTML.

    Dependencies:
        Uses:
            - ``validate_a2l_tags`` / ``build_a2l_summary_lines`` from ``s19_app.tui.a2l``
    """
    from s19_app.tui.a2l import build_a2l_summary_lines, validate_a2l_tags

    source_tags = a2l_data.get("tags", [])
    tag_checks = validate_a2l_tags(source_tags, mem_map)
    check_map = {(t.get("section"), t.get("name")): t for t in tag_checks}
    enriched: list[dict[str, Any]] = []
    for tag in source_tags:
        lookup = (tag.get("section"), tag.get("name"))
        enriched.append({**tag, **check_map.get(lookup, {})})
    lines = build_a2l_summary_lines(a2l_data, tag_checks)
    return enriched, lines

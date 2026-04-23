from __future__ import annotations

from typing import Any, Optional

from ..a2l_extract import enrich_a2l_tags_with_values
from ..a2l_render import render_a2l_view
from ..a2l_validate import validate_a2l_tags


def enrich_tags_and_render(
    a2l_data: Optional[dict],
    mem_map: Optional[dict[int, int]],
    max_tag_lines: int = 500,
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Build enriched A2L tag rows and human-readable summary lines.
    """
    if not a2l_data:
        return [], []
    source_tags = enrich_a2l_tags_with_values(a2l_data, mem_map)
    checked_tags = validate_a2l_tags(source_tags, mem_map)
    check_map = {(tag.get("section"), tag.get("name")): tag for tag in checked_tags}
    merged: list[dict[str, Any]] = []
    for tag in source_tags:
        merged.append({**tag, **check_map.get((tag.get("section"), tag.get("name")), {})})
    summary_lines = render_a2l_view(a2l_data, checked_tags, max_tag_lines=max_tag_lines).splitlines()
    return merged, summary_lines

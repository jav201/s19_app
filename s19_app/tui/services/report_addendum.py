"""Operator-declared memory regions for the report addendum (batch-19, LLR-024.1).

A :class:`DeclaredRegion` is an operator-supplied ``(name, start, end)`` memory
range declared for a generated report. The report addendum lists each region
and, per region, the modifications and validation issues whose address falls
inside it — **inclusive** ``[start, end]`` (DoR pick A, Expected-zone).

Security (Phase-2 F1): the region ``name`` is operator free text that reaches
the Markdown report and ``project.json``, so it is scrubbed + length-capped at
construction through the SAME ``validation.model._scrub_issue_message`` primitive
the codebase applies to issue messages — stripping control chars / ANSI and
bounding length before the value ever leaves this module.

Structurally modelled on ``tui.operations.crc_config.CrcRegion``, but the
membership convention differs: ``DeclaredRegion`` is INCLUSIVE ``[start, end]``
whereas ``CrcRegion`` is half-open ``[start, end)`` (architect-M1).
"""

from __future__ import annotations

from dataclasses import dataclass

from ...validation.model import _scrub_issue_message

#: Max rendered length of a declared-region name (Phase-2 F1 length cap).
DECLARED_REGION_NAME_MAX = 80


@dataclass(frozen=True, slots=True)
class DeclaredRegion:
    """
    Summary:
        One operator-declared memory region (LLR-024.1): a ``name`` plus an
        inclusive ``[start, end]`` address range. Validated at construction —
        one explicit ``ValueError`` per invalid field, never a silent clamp —
        and ``name`` is scrubbed + length-capped via
        ``validation.model._scrub_issue_message`` (security-F1) before storage.

    Args:
        name (str): Operator label. Scrubbed (control/ANSI stripped) + capped to
            :data:`DECLARED_REGION_NAME_MAX`; must be non-empty after scrubbing.
        start (int): Inclusive start address. Must be ``>= 0``.
        end (int): Inclusive end address. Must be ``>= start``.

    Returns:
        None: Frozen dataclass container.

    Raises:
        ValueError: empty ``name`` (after scrub), ``start < 0``, or
            ``start > end``.

    Data Flow:
        - Constructed from the report dialog (Inc3) or a headless caller.
        - Consumed by :func:`report_service._addendum_lines` for per-region
          membership via :meth:`contains`.

    Dependencies:
        Uses:
            - validation.model._scrub_issue_message
        Used by:
            - report_service._addendum_lines / ReportOptions.declared_regions

    Example:
        >>> DeclaredRegion("cal", 0x1000, 0x10FF).contains(0x1000)
        True
    """

    name: str
    start: int
    end: int

    def __post_init__(self) -> None:
        scrubbed = _scrub_issue_message(
            self.name, max_length=DECLARED_REGION_NAME_MAX
        )
        if not scrubbed:
            raise ValueError(
                f"declared region name must be non-empty after scrubbing, "
                f"got {self.name!r}"
            )
        if not isinstance(self.start, int) or isinstance(self.start, bool) or self.start < 0:
            raise ValueError(
                f"declared region start must be an int >= 0, got {self.start!r}"
            )
        if not isinstance(self.end, int) or isinstance(self.end, bool) or self.end < self.start:
            raise ValueError(
                f"declared region end must be an int >= start ({self.start}), "
                f"got {self.end!r}"
            )
        object.__setattr__(self, "name", scrubbed)

    def contains(self, address: int) -> bool:
        """True when ``address`` is within the inclusive ``[start, end]`` range."""
        return self.start <= address <= self.end

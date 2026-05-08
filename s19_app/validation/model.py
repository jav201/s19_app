from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ValidationSeverity(str, Enum):
    """Shared severity levels for all validation domains."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"
    NEUTRAL = "neutral"


_ANSI_CSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_TRUNCATION_MARKER = "…[truncated]"
_DEFAULT_MESSAGE_MAX_LENGTH = 500


def _scrub_issue_message(message: str, max_length: int = _DEFAULT_MESSAGE_MAX_LENGTH) -> str:
    """
    Summary:
        Strip control characters and ANSI escapes from ``message`` and truncate
        the result to ``max_length`` characters (default 500). Removes ASCII
        control chars (``\\x00``-``\\x1f`` and ``\\x7f``, including ``\\n``,
        ``\\r``, ``\\t``, BEL) and ANSI CSI sequences (``\\x1b[...]``) to prevent
        log-injection or panel-formatting disruption from attacker-supplied
        symbol/tag names. Truncated output is suffixed with ``"…[truncated]"``
        so downstream readers can tell. The marker counts toward ``max_length``;
        the returned string is always ``<= max_length`` characters.

        Rules that need detail beyond ``max_length`` characters shall emit
        multiple ``ValidationIssue`` records rather than rely on truncation
        (per LLR-002.3 / S-N03).

        The function is idempotent: scrubbing an already-scrubbed message
        returns an equivalent string with no doubled markers.

    Args:
        message (str): Raw human-readable message, possibly attacker-supplied.
        max_length (int): Maximum permitted length of the returned string,
            including any truncation marker. Defaults to 500.

    Returns:
        str: Sanitised message no longer than ``max_length`` characters.

    Raises:
        TypeError: If ``message`` is not a string.

    Data Flow:
        - Called from ``ValidationIssue.__post_init__`` for every issue created.
        - Output is what tests, the Issues panel, and the rotating log observe.

    Dependencies:
        Uses:
        - ``_ANSI_CSI_RE``, ``_CONTROL_CHAR_RE``, ``_TRUNCATION_MARKER``.
        Used by:
        - ``ValidationIssue.__post_init__``.

    Example:
        >>> _scrub_issue_message("foo\\n[CRITICAL] cleared\\n")
        'foo[CRITICAL] cleared'
    """
    if not isinstance(message, str):  # defensive: rules may pass non-str by mistake
        raise TypeError(f"message must be str, got {type(message).__name__}")
    cleaned = _ANSI_CSI_RE.sub("", message)
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    if len(cleaned) <= max_length:
        return cleaned
    if cleaned.endswith(_TRUNCATION_MARKER):
        # Already a truncated form long enough to exceed the cap on its own;
        # re-truncate without doubling the marker.
        body = cleaned[: -len(_TRUNCATION_MARKER)]
    else:
        body = cleaned
    keep = max_length - len(_TRUNCATION_MARKER)
    if keep <= 0:
        return _TRUNCATION_MARKER[:max_length]
    return body[:keep] + _TRUNCATION_MARKER


@dataclass(slots=True)
class ValidationIssue:
    """
    Summary:
        Represent one validation finding tied to an artifact and optional symbol/address context.

    Args:
        code (str): Stable machine-readable issue code (for tests, filters, and summaries).
        severity (ValidationSeverity): Severity bucket used by CLI/TUI presentation.
        message (str): Human-readable explanation of the finding.
        artifact (str): Primary artifact identifier (for example ``s19``, ``mac``, ``a2l``, ``cross``).
        symbol (Optional[str]): Related symbol/tag name when applicable.
        address (Optional[int]): Related address when applicable.
        line_number (Optional[int]): Source line when available from parser diagnostics.
        related_artifacts (list[str]): Secondary artifacts participating in cross checks.
        details (dict[str, str]): Extra structured attributes for debug and reporting.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Validation stages create ``ValidationIssue`` entries instead of ad-hoc strings.
        - UI and CLI consume the same structure for status text and severity color.
        - Tests assert ``code`` and ``severity`` to keep behavior stable.

    Dependencies:
        Uses:
        - ``ValidationSeverity``
        Used by:
        - MAC/A2L/internal validation rules
        - Cross-artifact validation engine
        - TUI and CLI reporting
    """

    code: str
    severity: ValidationSeverity
    message: str
    artifact: str
    symbol: Optional[str] = None
    address: Optional[int] = None
    line_number: Optional[int] = None
    related_artifacts: list[str] = field(default_factory=list)
    details: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Scrub control chars and ANSI escapes from ``message`` and cap length.

        Centralised here (per LLR-002.3) so every rule construction site in
        ``rules.py`` and ``engine.py`` benefits without per-call routing.
        """
        self.message = _scrub_issue_message(self.message)


@dataclass(slots=True)
class CoverageMetrics:
    """
    Summary:
        Hold aggregate consistency coverage metrics across MAC, A2L, and S19.

    Args:
        mac_total (int): Number of parse-valid MAC records considered.
        mac_in_s19 (int): MAC records whose addresses are present in S19 ranges.
        a2l_total (int): Number of A2L tags with parsed integer addresses.
        a2l_in_s19 (int): A2L tags whose required ranges are present in S19.
        a2l_mac_intersection (int): Count of symbols present in both A2L and MAC by name.
        a2l_mac_address_matches (int): Count of intersecting symbols with matching addresses.

    Returns:
        None: Dataclass container with derived percentage helpers.

    Data Flow:
        - Cross-validator counts totals and covered subsets.
        - Percentage helpers normalize the counts for dashboard/status display.
        - Result is rendered in summary lines and test assertions.

    Dependencies:
        Used by:
        - ``validate_artifact_consistency``
        - TUI summary rendering
    """

    mac_total: int = 0
    mac_in_s19: int = 0
    a2l_total: int = 0
    a2l_in_s19: int = 0
    a2l_mac_intersection: int = 0
    a2l_mac_address_matches: int = 0

    def mac_in_s19_pct(self) -> float:
        return 0.0 if self.mac_total == 0 else (self.mac_in_s19 / self.mac_total) * 100.0

    def a2l_in_s19_pct(self) -> float:
        return 0.0 if self.a2l_total == 0 else (self.a2l_in_s19 / self.a2l_total) * 100.0

    def a2l_mac_match_pct(self) -> float:
        if self.a2l_mac_intersection == 0:
            return 0.0
        return (self.a2l_mac_address_matches / self.a2l_mac_intersection) * 100.0

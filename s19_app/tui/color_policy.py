from __future__ import annotations

from ..validation import ValidationSeverity

SEVERITY_CLASS_MAP: dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "sev-error",
    ValidationSeverity.WARNING: "sev-warning",
    ValidationSeverity.INFO: "sev-info",
    ValidationSeverity.OK: "sev-ok",
    ValidationSeverity.NEUTRAL: "sev-neutral",
}

FOCUS_HIGHLIGHT_STYLE = "bold yellow"
MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"


def css_class_for_severity(severity: ValidationSeverity) -> str:
    """Return the canonical TUI CSS class for a validation severity."""
    return SEVERITY_CLASS_MAP.get(severity, "sev-neutral")

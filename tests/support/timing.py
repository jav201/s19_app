"""Timing bounds for wall-clock assertions (batch-100 Inc 8b E5 corrective
pass 1, LED .80).

The requirements state their time bounds for the local machine (1 s). Shared
CI runners are slower and noisier: Inc 7 and Inc 8a "< 1 s" nodes failed on
Linux CI only. ``timing_bound`` keeps the requirement's number locally and
doubles it when the ``CI`` environment variable is truthy, so a CI run checks
the same order of magnitude without flaking on runner load.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Callable, Union

import pytest

#: The factor a CI run applies to a requirement's local time bound.
CI_TIMING_FACTOR = 2

#: Wall-clock ceiling of a yielding shared wait, in seconds.
WAIT_TIMEOUT_S = 60.0

#: Poll period of a yielding shared wait, in seconds.
POLL_S = 0.05

#: A margin below this percentage is a gate finding (QC-TM `LOW ` prefix).
MARGIN_FINDING_PCT = 20.0

#: Margin reports accumulated during a test's call phase; per process (each
#: xdist worker has its own), emptied by the report hook on every phase.
_QC_TM_PENDING: list = []


def timing_bound(seconds: float) -> float:
    """``seconds`` locally; ``seconds * CI_TIMING_FACTOR`` when env ``CI`` is
    truthy (set, and not "", "0", "false" or "no", any case)."""
    value = os.environ.get("CI", "").strip().lower()
    if value in ("", "0", "false", "no"):
        return seconds
    return seconds * CI_TIMING_FACTOR


async def wait_until(
    pilot,
    predicate: Callable[[], bool],
    failure: Union[str, Callable[[], str]],
    *,
    timeout: float = WAIT_TIMEOUT_S,
    pause_first: bool = False,
) -> None:
    """Poll ``predicate`` until it is truthy, yielding to the app between
    checks; raise ``AssertionError`` with ``failure`` at the deadline.

    A callable ``failure`` is called only when this raises, so its text can
    show state accumulated up to the timeout.
    """
    deadline = time.monotonic() + timeout
    if pause_first:
        await pilot.pause()
    while True:
        if predicate():
            return
        if time.monotonic() > deadline:
            raise AssertionError(failure() if callable(failure) else failure)
        await asyncio.sleep(POLL_S)
        await pilot.pause()


def report_margin(label: str, measured: float, bound: float) -> float:
    """Record a QC-TM margin report and return ``bound`` unchanged.

    Never asserts and never raises on a large ``measured``; the caller's own
    comparison against the returned bound is what fails.
    """
    if "|" in label or any(ord(ch) < 0x20 for ch in label):
        raise ValueError(f"invalid QC-TM label: {label!r}")
    margin = (bound - measured) / bound * 100
    _QC_TM_PENDING.append((label, measured, bound, margin))
    return bound


def qc_tm_drain(user_properties: list) -> int:
    """Move every pending QC-TM record into ``user_properties`` as a
    ``("qc_tm", "<label>|<measured:.3f>|<bound:.3f>|<margin:.1f>")`` pair;
    clear the pending list; return how many records moved."""
    drained = 0
    while _QC_TM_PENDING:
        label, measured, bound, margin = _QC_TM_PENDING.pop(0)
        user_properties.append(
            ("qc_tm", f"{label}|{measured:.3f}|{bound:.3f}|{margin:.1f}")
        )
        drained += 1
    return drained


def qc_tm_summary_lines(reports: list) -> list:
    """Render the QC-TM section lines for ``(nodeid, qc_tm value)`` pairs of
    call-phase reports; ``[]`` when there are none."""
    if not reports:
        return []
    rows = []
    for nodeid, value in reports:
        label, measured, bound, margin = value.rsplit("|", 3)
        rows.append((float(margin), measured, bound, label, nodeid))
    rows.sort(key=lambda row: row[0])
    lines = ["QC-TM timing margins"]
    low = 0
    for margin, measured, bound, label, nodeid in rows:
        if margin < MARGIN_FINDING_PCT:
            low += 1
            lines.append(
                f"LOW {margin:.1f}%  {measured} s / {bound} s  {label}  {nodeid}"
            )
        else:
            lines.append(
                f"{margin:.1f}%  {measured} s / {bound} s  {label}  {nodeid}"
            )
    lines.append(f"QC-TM: {len(rows)} bounds, {low} under 20 % margin")
    return lines


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Drain pending QC-TM records into the item's user properties before the
    report of EVERY phase is built, so a record made in a fixture or a
    teardown never lands on the next test."""
    qc_tm_drain(item.user_properties)
    yield


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print the QC-TM timing-margin section from call-phase reports."""
    reports = []
    for key in ("passed", "failed"):
        for report in terminalreporter.stats.get(key, []):
            if getattr(report, "when", None) != "call":
                continue
            for name, value in report.user_properties:
                if name == "qc_tm":
                    reports.append((report.nodeid, value))
    lines = qc_tm_summary_lines(reports)
    if not lines:
        return
    terminalreporter.section("QC-TM timing margins")
    for line in lines[1:]:
        terminalreporter.line(line)

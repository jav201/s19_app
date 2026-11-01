"""Batch-100 Inc 12b — the one wait helper of ruling Q6.

Inc 12b moves project load, Save project and the A2L attach onto thread
workers (HLR-177). A test that called one of those handlers and then read the
session after a fixed number of ``pilot.pause()`` calls no longer waits for
the install, which now lands from a worker through ``call_from_thread`` (and,
for the project load and the A2L attach, one ``call_after_refresh`` later).

Ruling Q6 (E1 rulings; E3 A12b-01): every success path waits through ONE
helper — ``app.workers.wait_for_complete()`` and then 2 pauses (the second
pause lets the deferred install of ``_on_project_loaded`` /
``_on_a2l_attached`` run). There is no synchronous test-only entry point in
the product. On a tree without workers ``wait_for_complete()`` returns at
once, so a test re-pinned to this helper keeps passing where only its wait
changed.

Never call it while a forced slow step is still held: the held worker never
completes and the wait never returns. Release the step first.
"""
from __future__ import annotations


async def settle_workers(pilot) -> None:
    """Ruling Q6's one wait: every running worker finishes, then 2 pauses
    so the deferred main-thread install (``call_after_refresh``) has run."""
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()
    await pilot.pause()

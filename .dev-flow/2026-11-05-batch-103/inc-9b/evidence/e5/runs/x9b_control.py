"""Apply one named E5 review control to an isolated tree, by exact anchor."""
from __future__ import annotations

import sys
from pathlib import Path

B = "s19_app/tui/screens_directionb/patch_editor/bench_sheet.py"
P = "s19_app/tui/app/patch.py"

CONTROLS = {
    "hold-mount": [
        (
            B,
            "    def on_mount(self) -> None:\n        self._busy_timer = self.set_interval(BUSY_TICK_S, self._busy_tick, pause=True)\n",
            "    def on_mount(self) -> None:\n        super().on_mount()\n        self._busy_timer = self.set_interval(BUSY_TICK_S, self._busy_tick, pause=True)\n",
        )
    ],
    "hold-load": [
        (
            P,
            "        service = self._change_service\n        loaded = self.current_file\n        loaded_ranges = loaded.ranges if loaded is not None else None\n        # batch-48 (LLR-080.2) — the load path's memory-map push.\n",
            "        return\n        service = self._change_service\n        loaded = self.current_file\n        loaded_ranges = loaded.ranges if loaded is not None else None\n        # batch-48 (LLR-080.2) — the load path's memory-map push.\n",
        )
    ],
    "hold-apply": [
        (
            P,
            "        if event.action == \"apply_doc\":\n            self._note_image_bytes_written()\n",
            "        if event.action == \"apply_doc\":\n            self._note_image_bytes_written()\n            return\n",
        )
    ],
    "hold-apply-no-hook": [
        (
            P,
            "        if event.action == \"apply_doc\":\n            self._note_image_bytes_written()\n",
            "        if event.action == \"apply_doc\":\n            return\n",
        )
    ],
    "chain": [
        (
            P,
            "                self.set_timer(STEP_GAP_S, lambda: run(index))\n",
            "                self.call_after_refresh(run, index)\n",
        )
    ],
    "stall-sheet": [
        (
            P,
            "        def sheet() -> None:\n            self.query_one(\"#patch_editor_panel\", PatchEditorPanel).refresh_sheet_document()\n",
            "        def sheet() -> None:\n            __import__(\"time\").sleep(1.3)\n            self.query_one(\"#patch_editor_panel\", PatchEditorPanel).refresh_sheet_document()\n",
        )
    ],
    "stall-serialize": [
        (
            P,
            "        def serialize() -> None:\n            held[\"view\"] = self._patch_document_view()\n",
            "        def serialize() -> None:\n            __import__(\"time\").sleep(1.3)\n            held[\"view\"] = self._patch_document_view()\n",
        )
    ],
    "later-raise-valid": [
        (
            P,
            "            except BaseException:\n                on_done()\n                raise\n",
            "            except BaseException:\n                raise\n",
        )
    ],
    "active-job": [
        (
            B,
            "        job = busy_job(name, self.states.get(name), self._busy_stage_name())\n",
            "        job = None if self._active_job is None else self._active_job[:2]\n",
        )
    ],
    "title-once": [
        (
            B,
            "        win.border_title = busy_title(\n            str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n        )\n",
            "        if self._busy_frame == 0:\n            win.border_title = busy_title(\n                str(self._busy_idle_title), job[0], job[1], pending, self._busy_frame, win.size.width - 4\n            )\n",
        )
    ],
    "sync-worker-valid": [
        (
            B,
            "    @work(thread=True, group=\"bench\", exit_on_error=False)\n",
            "",
        ),
        (
            B,
            "        self.app.call_from_thread(self._job_done, kind, name, generation, result, derived)\n",
            "        self._job_done(kind, name, generation, result, derived)\n",
        ),
    ],
}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in CONTROLS:
        print("usage: x9b_control.py TREE CONTROL", file=sys.stderr)
        print("controls: " + " ".join(sorted(CONTROLS)), file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    control = sys.argv[2]
    for relative, old, new in CONTROLS[control]:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        count = text.count(old)
        if count != 1:
            raise RuntimeError(f"{control}: anchor count {count}, expected 1: {relative}")
        path.write_text(text.replace(old, new), encoding="utf-8", newline="\n")
        print(f"APPLIED {control} {relative} anchors=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

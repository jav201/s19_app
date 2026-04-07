from logging.handlers import RotatingFileHandler
from pathlib import Path

from s19_app.tui.workspace import (
    LOGS_SUBDIR,
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WORKAREA_TEMP,
    ensure_workarea,
    setup_logging,
)


def test_ensure_workarea_creates_expected_directories(tmp_path: Path):
    workarea = ensure_workarea(tmp_path)

    assert workarea == tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert workarea.exists()
    assert (workarea / WORKAREA_TEMP).exists()
    assert (tmp_path / WORKAREA_DIRNAME / LOGS_SUBDIR).exists()


def test_setup_logging_reuses_handler_for_same_path(tmp_path: Path):
    logger = setup_logging(tmp_path)
    logger = setup_logging(tmp_path)
    log_path = tmp_path / WORKAREA_DIRNAME / LOGS_SUBDIR / "s19tui.log"
    matching_handlers = [
        handler
        for handler in logger.handlers
        if isinstance(handler, RotatingFileHandler)
        and Path(handler.baseFilename) == log_path
    ]

    assert len(matching_handlers) == 1
    assert matching_handlers[0].maxBytes == 5 * 1024 * 1024

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from s19_app.tui.models import LoadedFile


@dataclass
class ViewerSession:
    """
    Summary:
        Server-side viewer state for one browser session (not stored in the Flask cookie).

    Args:
        (field definitions below)

    Returns:
        ViewerSession: Mutable holder for loaded image and A2L presentation data.

    Data Flow:
        - Created after successful upload parse.
        - Read by view and JSON API routes; replaced on new upload.

    Dependencies:
        Used by:
            - Flask routes in ``routes``
    """

    session_id: str
    loaded: Optional[LoadedFile] = None
    errors: list[str] = field(default_factory=list)
    a2l_summary_lines: list[str] = field(default_factory=list)
    enriched_tags: list[dict[str, Any]] = field(default_factory=list)
    last_search_address: Optional[int] = None
    last_search_query: Optional[str] = None


class SessionStore:
    """Thread-safe in-memory map from opaque session id to ``ViewerSession``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, ViewerSession] = {}

    def new_session(self) -> ViewerSession:
        sid = uuid.uuid4().hex
        session = ViewerSession(session_id=sid)
        with self._lock:
            self._sessions[sid] = session
        return session

    def get(self, session_id: str) -> Optional[ViewerSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

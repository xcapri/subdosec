"""
Crash-safe scan progress tracker.

Uses two files for durability:
- scan_session.json: Written once at scan start, stores all targets and config.
- scan_done.txt: Append-only, one completed target per line. Safe against crashes.
"""

import os
import json
import threading
from datetime import datetime
from typing import List, Optional, Set


class ProgressTracker:
    """Track scan progress using crash-safe append-only file writes."""

    SESSION_FILE = "scan_session.json"
    DONE_FILE = "scan_done.txt"

    def __init__(self, progress_dir: str):
        self._progress_dir = progress_dir
        self._session_path = os.path.join(progress_dir, self.SESSION_FILE)
        self._done_path = os.path.join(progress_dir, self.DONE_FILE)
        self._lock = threading.Lock()
        self._done_file = None
        self._flush_counter = 0
        self._flush_interval = 10

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    def start_session(self, targets: List[str], config_snapshot: dict) -> None:
        """Create a new scan session. Writes session file and resets done file."""
        os.makedirs(self._progress_dir, exist_ok=True)

        session = {
            "started_at": datetime.now().isoformat(),
            "config": config_snapshot,
            "total_targets": len(targets),
            "all_targets": targets,
        }

        # Atomic-ish write: write to tmp then rename
        tmp_path = self._session_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self._session_path)

        # Reset done file for new session
        with open(self._done_path, "w", encoding="utf-8") as f:
            pass

        # Open done file in append mode for the session
        self._done_file = open(self._done_path, "a", encoding="utf-8")
        self._flush_counter = 0

    def mark_done(self, target: str) -> None:
        """Append a completed target to the done file (thread-safe)."""
        with self._lock:
            if self._done_file is None:
                return
            self._done_file.write(target + "\n")
            self._flush_counter += 1
            if self._flush_counter % self._flush_interval == 0:
                self._done_file.flush()
                os.fsync(self._done_file.fileno())

    def finish_session(self) -> None:
        """Finalize the current session and clean up progress files."""
        self._close_done_file()
        self._remove_file(self._session_path)
        self._remove_file(self._done_path)

    # ------------------------------------------------------------------
    # Resume support
    # ------------------------------------------------------------------

    def has_pending_session(self) -> bool:
        """Check if there is an unfinished session to resume."""
        return os.path.isfile(self._session_path)

    def load_remaining_targets(self) -> Optional[List[str]]:
        """Load the remaining (not yet completed) targets from a previous session.

        Returns None if there is no pending session.
        """
        if not self.has_pending_session():
            return None

        try:
            with open(self._session_path, "r", encoding="utf-8") as f:
                session = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

        all_targets: List[str] = session.get("all_targets", [])
        done: Set[str] = self._read_done_set()

        remaining = [t for t in all_targets if t not in done]
        return remaining

    def load_session_config(self) -> Optional[dict]:
        """Load the config snapshot from a pending session."""
        if not self.has_pending_session():
            return None
        try:
            with open(self._session_path, "r", encoding="utf-8") as f:
                session = json.load(f)
            return session.get("config")
        except (json.JSONDecodeError, OSError):
            return None

    def resume_session(self) -> None:
        """Re-open the done file in append mode for a resumed session."""
        self._done_file = open(self._done_path, "a", encoding="utf-8")
        self._flush_counter = 0

    def discard_session(self) -> None:
        """Discard a pending session without resuming."""
        self._close_done_file()
        self._remove_file(self._session_path)
        self._remove_file(self._done_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_done_set(self) -> Set[str]:
        """Read the done file into a set of completed targets."""
        done = set()
        if not os.path.isfile(self._done_path):
            return done
        try:
            with open(self._done_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        done.add(stripped)
        except OSError:
            pass
        return done

    def _close_done_file(self) -> None:
        if self._done_file is not None:
            try:
                self._done_file.flush()
                os.fsync(self._done_file.fileno())
                self._done_file.close()
            except OSError:
                pass
            self._done_file = None

    @staticmethod
    def _remove_file(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass

"""RemoteSync — Serial operation queue.

When you save 5 files quickly, each upload is queued and processed
in order without losing any.
"""

import sublime
import threading
import traceback
from collections import deque


class OperationQueue:
    """Thread-safe serial queue for remote operations."""

    def __init__(self):
        self._queue = deque()
        self._lock = threading.Lock()
        self._running = False
        self._cancelled = False

    def enqueue(self, fn, window=None, label=""):
        """Add an operation.  Starts processing if idle."""
        with self._lock:
            if self._cancelled:
                self._cancelled = False
            self._queue.append((fn, window, label))
            if self._running:
                self._update_status(window)
                return
            self._running = True

        threading.Thread(target=self._process, daemon=True).start()

    def cancel_all(self, window=None):
        """Cancel all pending operations."""
        with self._lock:
            self._cancelled = True
            dropped = len(self._queue)
            self._queue.clear()
        if window:
            from . import panel
            if dropped > 0:
                panel.log(window, f"Cancelled {dropped} pending operation(s)")
            else:
                panel.log(window, "No pending operations to cancel")
        sublime.set_timeout(
            lambda: sublime.status_message(
                f"RemoteSync: Cancelled {dropped} operation(s)"
            ), 0
        )
        return dropped

    def _process(self):
        while True:
            with self._lock:
                if not self._queue or self._cancelled:
                    self._running = False
                    self._cancelled = False
                    return
                fn, window, label = self._queue.popleft()
                pending = len(self._queue)

            try:
                if window and pending > 0:
                    from . import panel
                    panel.log(window, f"Queue: processing '{label}' ({pending} pending)")
                fn()
            except Exception as exc:
                from . import panel as _panel
                from .errors import RemoteSyncError
                if not isinstance(exc, RemoteSyncError):
                    # Unexpected error (bug, not a remote failure) — make it visible.
                    tb = traceback.format_exc()
                    print(f"[RemoteSync] Unexpected error in '{label}':\n{tb}")
                    if window:
                        _panel.log(window,
                            f"Unexpected error in '{label}': {exc}\n{tb}",
                            error=True)
                    sublime.set_timeout(lambda m=str(exc): sublime.error_message(
                        f"RemoteSync — Unexpected error:\n{m}\n\nSee the output panel for details."
                    ), 0)
                # RemoteSyncError: already logged by panel.tracked() — just continue.

            with self._lock:
                remaining = len(self._queue)
            if remaining > 0:
                sublime.set_timeout(
                    lambda r=remaining: sublime.status_message(
                        f"RemoteSync: {r} operation(s) queued"
                    ), 0
                )

    def _update_status(self, window):
        count = len(self._queue)
        if window and count > 0:
            sublime.set_timeout(
                lambda c=count: sublime.status_message(
                    f"RemoteSync: {c} operation(s) queued"
                ), 0
            )

    @property
    def pending_count(self):
        with self._lock:
            return len(self._queue)

    @property
    def is_busy(self):
        with self._lock:
            return self._running

"""RemoteSync — Output panel (logging).

Extracted from RemoteSync.py for modularity.  Improvements:
  - Auto-truncates after max_panel_lines to prevent infinite growth
  - Respects show_panel_on_error, auto_hide_panel, log_operations settings
  - Two-phase progress logging with file size display
  - Animated spinner with elapsed time for long operations
"""

import sublime
import sublime_plugin
import threading
import time
from datetime import datetime


PANEL_NAME = "remotesync"

# Braille spinner frames — smooth circular animation
_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# ---------------------------------------------------------------------------
# Active-operation counter — prevents premature auto-hide during batch ops
# ---------------------------------------------------------------------------
_active_ops = 0
_active_ops_lock = threading.Lock()


def _op_started():
    global _active_ops
    with _active_ops_lock:
        _active_ops += 1


def _maybe_hide(window, success):
    """Decrement op counter; schedule panel hide when the last op finishes."""
    global _active_ops
    with _active_ops_lock:
        _active_ops = max(0, _active_ops - 1)

    if not success:
        return

    hide_delay = _get_settings().get("auto_hide_panel", 4)
    if not hide_delay or hide_delay <= 0:
        return

    def _check_and_hide():
        with _active_ops_lock:
            if _active_ops > 0:
                return  # another op is still running — let it handle hide
        window.run_command("hide_panel", {"panel": f"output.{PANEL_NAME}"})

    sublime.set_timeout(_check_and_hide, int(hide_delay * 1000))


def _get_settings():
    """Load plugin settings from RemoteSync.sublime-settings."""
    return sublime.load_settings("RemoteSync.sublime-settings")


def _get_panel(window):
    """Get or create the RemoteSync output panel."""
    panel = window.find_output_panel(PANEL_NAME)
    if not panel:
        panel = window.create_output_panel(PANEL_NAME)
        panel.settings().set("word_wrap", True)
        panel.settings().set("gutter", False)
        panel.settings().set("scroll_past_end", False)
        panel.set_read_only(True)
        panel.assign_syntax("Packages/RemoteSync/RemoteSyncOutput.sublime-syntax")
    return panel


def _panel_append(panel, characters, scroll_to_end=True):
    """Append text to the read-only panel (temporarily unlocks it)."""
    panel.set_read_only(False)
    panel.run_command("append", {"characters": characters, "scroll_to_end": scroll_to_end})
    panel.set_read_only(True)


class RemoteSyncPanelReplaceCommand(sublime_plugin.TextCommand):
    """Internal command to replace text from a given position to end of view.

    Used by animate_progress() to update the spinner + elapsed time in-place
    without accumulating text on the line.
    """
    def run(self, edit, start, text):
        size = self.view.size()
        if start > size:
            start = size
        region = sublime.Region(start, size)
        self.view.set_read_only(False)
        self.view.replace(edit, region, text)
        self.view.set_read_only(True)
        # Scroll to end
        self.view.show(self.view.size())


def _auto_truncate(panel, config=None):
    """Trim the panel to max_panel_lines if configured.

    Removes oldest lines from the top so the most recent output stays visible.
    """
    max_lines = 5000  # default
    if config:
        max_lines = int(config.get("max_panel_lines", 5000))
    if max_lines <= 0:
        return  # 0 = unlimited

    line_count = panel.rowcol(panel.size())[0] + 1
    if line_count > max_lines:
        # Remove the oldest (line_count - max_lines) lines
        excess = line_count - max_lines
        end_point = panel.text_point(excess, 0)
        panel.set_read_only(False)
        panel.run_command("select_all")
        # We can't easily delete a range with built-in commands, so we
        # use a simple approach: replace the whole content keeping only tail.
        content = panel.substr(sublime.Region(end_point, panel.size()))
        panel.run_command("select_all")
        panel.run_command("insert", {"characters": content})
        panel.set_read_only(True)


def log(window, message, error=False):
    """Write a timestamped line to the RemoteSync output panel.

    Respects settings:
      - log_operations: if False, skip non-error messages
      - show_panel_on_error: auto-show panel on errors
    """
    if not window:
        return

    settings = _get_settings()
    if not error and not settings.get("log_operations", True):
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = "ERR" if error else ">>>"
    line = f"[{timestamp}] {prefix} {message}\n"
    show_panel = error and settings.get("show_panel_on_error", True)

    def _write():
        panel = _get_panel(window)
        _panel_append(panel, line)
        if show_panel:
            window.run_command("show_panel", {"panel": f"output.{PANEL_NAME}"})
        _auto_truncate(panel)

    sublime.set_timeout(_write, 0)


def log_separator(window):
    """Write a blank separator line between operation batches."""
    if not window:
        return

    def _write():
        panel = _get_panel(window)
        if panel.size() > 0:
            _panel_append(panel, "\n")

    sublime.set_timeout(_write, 0)


def log_progress(window, message):
    """Write a 'starting' line — shown BEFORE the operation runs.

    Output: Uploading "file.txt" (1.2 MB) to "/path" .........
    Then log_complete appends: ... success (0.3s)
    """
    if not window:
        return
    line = f"{message} ......... "

    def _write():
        panel = _get_panel(window)
        _panel_append(panel, line)
        window.run_command("show_panel", {"panel": f"output.{PANEL_NAME}"})

    sublime.set_timeout(_write, 0)


def log_complete(window, success=True, detail="", elapsed=None):
    """Complete a progress line with the result.

    Respects auto_hide_panel: hides panel N seconds after success.
    """
    if not window:
        return

    if success:
        result = f"success ({elapsed:.1f}s)" if elapsed is not None else "success"
    else:
        if detail:
            # Show first error line inline, rest on separate lines
            detail_lines = str(detail).strip().splitlines()
            result = f"failure ({detail_lines[0]})"
            if len(detail_lines) > 1:
                result += "\n" + "\n".join(f"  {l}" for l in detail_lines[1:])
        else:
            result = "failure"
    line = f"{result}\n"

    def _write():
        panel = _get_panel(window)
        _panel_append(panel, line)
        window.run_command("show_panel", {"panel": f"output.{PANEL_NAME}"})

        _auto_truncate(panel)

    sublime.set_timeout(_write, 0)


def tracked(fn, window, message):
    """Two-phase logging with animated dots.

    User sees dots appearing one by one while the operation runs,
    then the result (success/failure) at the end.
    """
    _op_started()
    done_event = threading.Event()
    op_error = [None]
    op_result = [None]

    def _run():
        try:
            op_result[0] = fn()
        except Exception as e:
            op_error[0] = e
        finally:
            done_event.set()

    t0 = time.monotonic()
    op_thread = threading.Thread(target=_run, daemon=True)
    op_thread.start()

    animate_progress(window, message, done_event)

    elapsed = time.monotonic() - t0
    success = op_error[0] is None
    if success:
        log_complete(window, success=True, elapsed=elapsed)
    else:
        log_complete(window, success=False, detail=str(op_error[0]))

    op_thread.join()
    _maybe_hide(window, success)

    if op_error[0] is not None:
        raise op_error[0]
    return op_result[0]


def animate_progress(window, message, done_event, max_dots=9, dot_interval=0.3,
                     progress=None):
    """Write message with animated dots, then spinner + elapsed time.

    Call from a worker thread.  Uses sublime.set_timeout (FIFO) to write
    to the panel on the UI thread.  Blocks until done_event fires.

    Phase 1 (first ~3s): Animated dots appear one by one.
    Phase 2 (3s+): Braille spinner rotates with elapsed time, updated
                    in-place so the line stays clean.

    Args:
        progress: Optional dict with live counters, e.g.
                  {"files": 0, "dirs": 0}. Updated by another thread.
                  Displayed alongside the spinner for real-time feedback.

    Output example:
      Downloading "file.zip" ......... ⠹ 15s                  (while running)
      Scanning remote files  ......... ⠹ 45s | 234 files, 18 dirs  (with progress)
      Downloading "file.zip" .........                          (then log_complete adds result)

    After returning, the caller should use log_complete() to append the result.
    """
    if not window:
        done_event.wait()
        return

    def _append(text):
        sublime.set_timeout(lambda: (
            _panel_append(_get_panel(window), text),
            window.run_command("show_panel", {"panel": f"output.{PANEL_NAME}"})
        ), 0)

    # Write the message prefix
    _append(f"{message} ")

    # Phase 1: Animate dots while the operation runs
    dots = 0
    t_start = time.monotonic()
    while not done_event.wait(timeout=dot_interval):
        if dots < max_dots:
            _append(".")
            dots += 1
        else:
            break  # dots full — switch to spinner

    # Phase 2: Spinner + elapsed time (updated in-place)
    if not done_event.is_set():
        # Record position right after the dots — spinner text goes here
        spinner_start = [None]

        def _mark_position():
            panel = _get_panel(window)
            spinner_start[0] = panel.size()

        sublime.set_timeout(_mark_position, 0)
        # Small wait to ensure the UI thread processes _mark_position
        time.sleep(0.05)

        frame_idx = 0
        while not done_event.wait(timeout=0.15):
            elapsed = int(time.monotonic() - t_start)
            spinner = _SPINNER_FRAMES[frame_idx % len(_SPINNER_FRAMES)]
            frame_idx += 1

            if progress:
                status = progress.get("status", "")
                files = progress.get("files", 0)
                dirs = progress.get("dirs", 0)
                if status:
                    # Single-command methods (find, rsync) show status text
                    spinner_text = f" {spinner} {elapsed}s | {status}"
                    if files > 0:
                        spinner_text += f" ({files} files)"
                elif files > 0 or dirs > 0:
                    # Multi-step methods (parallel, sequential) show counters
                    spinner_text = f" {spinner} {elapsed}s | {files} files, {dirs} dirs"
                else:
                    spinner_text = f" {spinner} {elapsed}s"
            else:
                spinner_text = f" {spinner} {elapsed}s"

            if spinner_start[0] is not None:
                start = spinner_start[0]
                sublime.set_timeout(
                    lambda s=start, t=spinner_text: (
                        _get_panel(window).run_command(
                            "remote_sync_panel_replace",
                            {"start": s, "text": t}
                        ),
                        window.run_command("show_panel", {"panel": f"output.{PANEL_NAME}"})
                    ), 0
                )

        # Clean up: remove spinner text, leave just the dots + space for log_complete
        if spinner_start[0] is not None:
            start = spinner_start[0]
            sublime.set_timeout(
                lambda s=start: _get_panel(window).run_command(
                    "remote_sync_panel_replace",
                    {"start": s, "text": " "}
                ), 0
            )
            # Small wait to ensure cleanup is processed before log_complete writes
            time.sleep(0.05)
    else:
        # Operation finished during dot phase — fill remaining dots
        remaining = max_dots - dots
        if remaining > 0:
            _append("." * remaining)
        _append(" ")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def format_size(size):
    """Human-readable file size."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

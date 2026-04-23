"""RemoteSync — Free SFTP/FTP/FTPS/SCP plugin for Sublime Text 4.

v2: Modular architecture.  Infrastructure lives in separate modules:
  - config.py     — load, validate, cache configs
  - sftp_client.py — SSH/FTP transfer clients
  - errors.py     — granular exception hierarchy
  - panel.py      — output panel with auto-truncate
  - pool.py       — connection pool, parallel ops, retry
  - queue.py      — serial operation queue
"""

import sublime
import sublime_plugin
import os
import re
import threading
from functools import wraps

from .config import (
    find_config, load_config, get_remote_path, create_default_config,
    invalidate_cache, CONFIG_FILENAME, should_ignore, get_timeout,
)
from .sftp_client import create_client, _shell_quote
from .errors import (
    RemoteConnectionError, ConnectionTimeoutError, ScanTimeoutError,
    ConfigError, is_critical, user_friendly_message,
)
from . import panel
from . import pool
from .queue import OperationQueue
from .scanner import fast_scan


# Global operation queue
_op_queue = OperationQueue()


# =============================================================================
# Proper async decorator (Mejora #2)
# =============================================================================

def run_async(on_success=None, on_error=None, config=None, window=None,
              project_root=None):
    """Decorator that runs the function in a background thread.

    Usage:
        @run_async(on_success=cb, on_error=err_cb, config=cfg)
        def do_upload():
            ...
        # do_upload() is called automatically — no extra () needed.

    The decorated function is invoked immediately in a daemon thread.
    on_success receives the return value; on_error receives the error string.
    If config is provided, the call is wrapped in pool.with_retry().
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            def _task():
                try:
                    if config:
                        result = pool.with_retry(
                            fn, config, window, project_root=project_root
                        )
                    else:
                        result = fn()
                    if on_success:
                        sublime.set_timeout(lambda: on_success(result), 0)
                except Exception as e:
                    err_str = str(e)
                    if on_error:
                        sublime.set_timeout(lambda: on_error(err_str), 0)
                    else:
                        sublime.set_timeout(
                            lambda: sublime.status_message(f"RemoteSync: {err_str}"), 0
                        )
                    # Show popup dialog for critical errors
                    if is_critical(e):
                        msg = user_friendly_message(e)
                        sublime.set_timeout(
                            lambda: sublime.error_message(f"RemoteSync\n\n{msg}"), 0
                        )
            threading.Thread(target=_task, daemon=True).start()
        # Auto-invoke: the decorator calls the function immediately
        wrapper()
        return wrapper
    return decorator


# =============================================================================
# Shared helpers
# =============================================================================

def _get_config_for_file(file_path, window=None):
    """Load config for a given file path."""
    folders = window.folders() if window else []
    config_path, project_root = find_config(file_path, folders)
    if not config_path:
        return None, None
    try:
        config = load_config(config_path)
    except ConfigError as e:
        if window:
            panel.log(window, str(e), error=True)
        return None, None
    return config, project_root


def _should_ignore(file_path, rel_path, config, remote_size=None):
    """Check if a file should be skipped (delegates to config.should_ignore)."""
    return should_ignore(file_path, rel_path, config, remote_size=remote_size)


def _no_config_msg(window):
    msg = "RemoteSync: No remote-sync-config.json found."
    sublime.status_message(msg)
    panel.log(window, msg, error=True)


def _has_config_for_paths(paths, window=None):
    """Check if any of the given paths have a remote config."""
    if not paths:
        return False
    for path in paths:
        check = path if os.path.isfile(path) else os.path.join(path, "dummy")
        folders = window.folders() if window else []
        config_path, _ = find_config(check, folders)
        if config_path:
            return True
    return False


# =============================================================================
# Upload helpers
# =============================================================================

def _run_pre_upload(config, window):
    """Run local pre_upload_command if configured."""
    cmd = config.get("pre_upload_command")
    if not cmd:
        return True
    try:
        import subprocess as sp
        run_kwargs = dict(shell=True, capture_output=True, text=True)
        if os.name == 'nt':
            run_kwargs["creationflags"] = sp.CREATE_NO_WINDOW
        result = sp.run(cmd, **run_kwargs)
        if result.returncode != 0:
            panel.log(window, f"pre_upload_command failed: {result.stderr.strip()}", error=True)
            return False
        panel.log(window, f"pre_upload_command OK: {cmd}")
    except Exception as e:
        panel.log(window, f"pre_upload_command error: {e}", error=True)
        return False
    return True


def _run_post_upload(config, client, window):
    """Run remote post_upload_command if configured."""
    cmd = config.get("post_upload_command")
    if not cmd:
        return
    conn_type = config.get("type", "sftp").lower()
    if conn_type in ("ftp", "ftps"):
        panel.log(window, "post_upload_command skipped (not supported over FTP)")
        return
    try:
        output = client.exec_command(cmd)
        panel.log(window, f"post_upload_command OK: {cmd}")
        if output:
            panel.log(window, f"  → {output}")
    except Exception as e:
        panel.log(window, f"post_upload_command failed: {e}", error=True)


# =============================================================================
# Event listener — upload on save
# =============================================================================

class RemoteSyncEventListener(sublime_plugin.EventListener):
    def on_activated(self, view):
        """Update status bar when switching views."""
        if view.window():
            pool.update_status_bar(view.window())

    def on_post_save_async(self, view):
        file_path = view.file_name()
        if not file_path:
            return

        window = view.window()

        # Invalidate cache and drop stale connection when user edits config
        if os.path.basename(file_path) == CONFIG_FILENAME:
            invalidate_cache(file_path)
            # Find project root for this config and disconnect old connection
            config_dir = os.path.dirname(file_path)
            pool.drop_connection(config_dir, window)
            if window:
                panel.log(window, "Config changed — reconnecting on next operation")
            return
        config, project_root = _get_config_for_file(file_path, window)
        if not config or not project_root:
            return
        if not config.get("upload_on_save", False):
            return

        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        if _should_ignore(file_path, rel_path, config):
            return

        remote_path = get_remote_path(config, file_path, project_root)
        conn_type = config.get("type", "sftp").upper()

        def _do_upload():
            try:
                panel.log_separator(window)
                panel.log(window, f"[{conn_type}] Saving and uploading {rel_path}...")
                if not _run_pre_upload(config, window):
                    raise Exception("pre_upload_command failed")
                client = pool.get_connection(config, project_root, window)
                file_size = panel.format_size(os.path.getsize(file_path)) if os.path.isfile(file_path) else ""
                size_info = f" ({file_size})" if file_size else ""
                panel.tracked(
                    lambda: client.upload(file_path, remote_path),
                    window,
                    f'Uploading "{rel_path}"{size_info} to "{remote_path}"'
                )
                _run_post_upload(config, client, window)
                panel.log(window, f"[{conn_type}] Uploaded {rel_path}")
                sublime.set_timeout(lambda: view.set_status("remotesync", f"Uploaded {rel_path}"), 0)
            except Exception as e:
                sublime.set_timeout(lambda: view.set_status("remotesync", "Upload failed"), 0)
                panel.log(window, f"[{conn_type}] Upload failed: {rel_path} — {e}", error=True)
                if is_critical(e):
                    msg = user_friendly_message(e)
                    sublime.set_timeout(
                        lambda: sublime.error_message(f"RemoteSync\n\n{msg}"), 0
                    )

        def _show_panel():
            panel._get_panel(window)
            window.run_command("show_panel", {"panel": f"output.{panel.PANEL_NAME}"})

        sublime.set_timeout(_show_panel, 0)
        view.set_status("remotesync", f"Uploading {rel_path}...")
        _op_queue.enqueue(_do_upload, window, rel_path)


# =============================================================================
# Commands
# =============================================================================

class RemoteSyncUploadFileCommand(sublime_plugin.TextCommand):
    """Upload the current file."""
    def run(self, edit):
        view = self.view
        file_path = view.file_name()
        if not file_path:
            sublime.status_message("RemoteSync: Save the file first.")
            return

        window = view.window()
        config, project_root = _get_config_for_file(file_path, window)
        if not config:
            _no_config_msg(window)
            return

        if config.get("save_before_upload", False) and view.is_dirty():
            view.run_command("save")

        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, file_path, project_root)
        conn_type = config.get("type", "sftp").upper()

        def on_success(_):
            sublime.status_message(f"RemoteSync: Uploaded {rel_path}")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Upload failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_upload():
            panel.log_separator(window)
            panel.log(window, f"[{conn_type}] Uploading {rel_path}...")
            if not _run_pre_upload(config, window):
                raise Exception("pre_upload_command failed")
            client = pool.get_connection(config, project_root, window)
            file_size = panel.format_size(os.path.getsize(file_path)) if os.path.isfile(file_path) else ""
            size_info = f" ({file_size})" if file_size else ""
            panel.tracked(
                lambda: client.upload(file_path, remote_path),
                window,
                f'Uploading "{rel_path}"{size_info} to "{remote_path}"'
            )
            _run_post_upload(config, client, window)
            panel.log(window, f"[{conn_type}] Uploaded {rel_path}")

        sublime.status_message(f"RemoteSync: Uploading {rel_path}...")


class RemoteSyncDownloadFileCommand(sublime_plugin.TextCommand):
    """Download the current file from server."""
    def run(self, edit):
        view = self.view
        file_path = view.file_name()
        if not file_path:
            sublime.status_message("RemoteSync: No file open.")
            return

        window = view.window()
        config, project_root = _get_config_for_file(file_path, window)
        if not config:
            _no_config_msg(window)
            return

        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, file_path, project_root)
        conn_type = config.get("type", "sftp").upper()

        if config.get("confirm_downloads", True):
            if not sublime.ok_cancel_dialog(
                f"Download from server?\n\n{rel_path}\n\nThis will overwrite the local file.",
                "Download"
            ):
                return

        def on_success(_):
            sublime.set_timeout(lambda: view.run_command("revert"), 100)
            sublime.status_message(f"RemoteSync: Downloaded {rel_path}")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Download failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_download():
            panel.log_separator(window)
            panel.log(window, f"[{conn_type}] Downloading {rel_path}...")
            client = pool.get_connection(config, project_root, window)
            panel.tracked(
                lambda: client.download(remote_path, file_path),
                window, f'Downloading "{remote_path}" to "{rel_path}"'
            )
            panel.log(window, f"[{conn_type}] Downloaded {rel_path}")

        sublime.status_message(f"RemoteSync: Downloading {rel_path}...")


class RemoteSyncUploadFolderCommand(sublime_plugin.WindowCommand):
    """Upload a folder — uses parallel connections."""
    def run(self, dirs=None):
        if not dirs:
            return
        folder = dirs[0]
        window = self.window
        config, project_root = _get_config_for_file(os.path.join(folder, "dummy"), window)
        if not config:
            _no_config_msg(window)
            return

        conn_type = config.get("type", "sftp").upper()
        folder_name = os.path.basename(folder)

        def on_success(result):
            completed, errors, elapsed = result
            msg = f"[{conn_type}] Finished — Uploaded {completed} files to {folder_name}/"
            if errors:
                msg += f" ({errors} failed)"
            msg += f" ({elapsed:.1f}s)"
            panel.log(window, msg, error=(errors > 0))
            sublime.status_message(f"RemoteSync: Uploaded {completed} files" + (f" ({errors} failed)" if errors else ""))

        def on_error(err):
            sublime.status_message(f"RemoteSync: Upload failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_upload():
            file_list = []
            for root, _dirs, files in os.walk(folder):
                for fname in files:
                    local_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(local_path, project_root).replace("\\", "/")
                    if _should_ignore(local_path, rel_path, config):
                        continue
                    rp = get_remote_path(config, local_path, project_root)
                    file_list.append((local_path, rp, rel_path))
            if not file_list:
                return (0, 0, 0.0)

            return pool.parallel_operation(
                file_list, lambda c, lp, rp: c.upload(lp, rp),
                config, project_root, window, op_label="Uploading"
            )

        sublime.status_message(f"RemoteSync: Uploading {folder_name}/...")

    def is_visible(self, dirs=None):
        return bool(dirs) and _has_config_for_paths(dirs, self.window)


class RemoteSyncUploadPathsCommand(sublime_plugin.WindowCommand):
    """Upload files from sidebar selection."""
    def run(self, paths=None):
        if not paths:
            return
        for path in paths:
            if os.path.isdir(path):
                self.window.run_command("remote_sync_upload_folder", {"dirs": [path]})
            elif os.path.isfile(path):
                view = self.window.find_open_file(path)
                if view:
                    view.run_command("remote_sync_upload_file")
                else:
                    self._upload_path(path)

    def _upload_path(self, file_path):
        window = self.window
        config, project_root = _get_config_for_file(file_path, window)
        if not config:
            return
        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, file_path, project_root)

        def on_success(_):
            sublime.status_message(f"RemoteSync: Uploaded {rel_path}")

        @run_async(on_success, config=config, window=window)
        def do_upload():
            client = pool.get_connection(config, project_root, window)
            file_size = panel.format_size(os.path.getsize(file_path)) if os.path.isfile(file_path) else ""
            size_info = f" ({file_size})" if file_size else ""
            panel.tracked(
                lambda: client.upload(file_path, remote_path),
                window, f'Uploading "{rel_path}"{size_info} to "{remote_path}"'
            )

    def is_visible(self, paths=None):
        return bool(paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncDownloadFolderCommand(sublime_plugin.WindowCommand):
    """Download a folder from server — uses parallel connections."""
    def run(self, dirs=None):
        if not dirs:
            return
        folder = dirs[0]
        window = self.window
        config, project_root = _get_config_for_file(os.path.join(folder, "dummy"), window)
        if not config:
            _no_config_msg(window)
            return

        conn_type = config.get("type", "sftp").upper()
        folder_name = os.path.basename(folder)
        remote_base = config.get("remote_path", "/").rstrip("/")
        rel_folder = os.path.relpath(folder, project_root).replace("\\", "/")
        remote_folder = remote_base + "/" + rel_folder

        def on_success(result):
            completed, errors, elapsed = result
            msg = f"[{conn_type}] Finished — Downloaded {completed} files to {folder_name}/"
            if errors:
                msg += f" ({errors} failed)"
            msg += f" ({elapsed:.1f}s)"
            panel.log(window, msg, error=(errors > 0))
            sublime.status_message(f"RemoteSync: Downloaded {completed} files" + (f" ({errors} failed)" if errors else ""))

        def on_error(err):
            sublime.status_message(f"RemoteSync: Download failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_download():
            import threading as _th
            client = pool.get_connection(config, project_root, window)

            # Scan with cascading methods + timeout + error handling
            scan_timeout = get_timeout(config, "scan")
            scan_done = _th.Event()
            scan_error = [None]
            file_list = []
            scan_progress = {"files": 0, "dirs": 0}

            def _scan():
                try:
                    file_list.extend(
                        fast_scan(client, config, remote_folder,
                                  project_root, window,
                                  progress=scan_progress)
                    )
                except Exception as e:
                    scan_error[0] = e
                finally:
                    scan_done.set()

            # Timeout safety net — forces scan_done.set() so the
            # spinner stops. Only active if scan_timeout > 0 (0 = unlimited).
            timeout_timer = None
            if scan_timeout > 0:
                def _timeout_handler():
                    if not scan_done.is_set():
                        scan_error[0] = ScanTimeoutError(
                            f"Scan timed out after {scan_timeout}s")
                        scan_done.set()

                timeout_timer = _th.Timer(scan_timeout, _timeout_handler)
                timeout_timer.daemon = True
                timeout_timer.start()

            scan_thread = _th.Thread(target=_scan, daemon=True)
            scan_thread.start()
            panel.animate_progress(window, "Scanning remote files",
                                   scan_done, progress=scan_progress)
            scan_thread.join(timeout=5)
            if timeout_timer:
                timeout_timer.cancel()

            # Handle scan error (includes timeout)
            if scan_error[0]:
                panel.log_complete(window, success=False,
                                   detail=str(scan_error[0]))
                raise scan_error[0]

            if not file_list:
                panel.log_complete(window, success=True, detail="empty")
                return (0, 0, 0.0)

            panel.log_complete(window, success=True,
                               detail=f"{len(file_list)} files found")

            return pool.parallel_operation(
                file_list, lambda c, lp, rp: c.download(rp, lp),
                config, project_root, window, op_label="Downloading"
            )

        sublime.status_message(f"RemoteSync: Downloading {folder_name}/...")

    def is_visible(self, dirs=None):
        return bool(dirs) and _has_config_for_paths(dirs, self.window)


class RemoteSyncDownloadPathsCommand(sublime_plugin.WindowCommand):
    """Download files/folders from sidebar selection."""
    def run(self, paths=None):
        if not paths:
            return
        for path in paths:
            if os.path.isdir(path):
                self.window.run_command("remote_sync_download_folder", {"dirs": [path]})
            elif os.path.isfile(path):
                view = self.window.find_open_file(path)
                if view:
                    view.run_command("remote_sync_download_file")
                else:
                    self._download_path(path)

    def _download_path(self, file_path):
        window = self.window
        config, project_root = _get_config_for_file(file_path, window)
        if not config:
            return
        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, file_path, project_root)

        def on_success(_):
            sublime.status_message(f"RemoteSync: Downloaded {rel_path}")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Download failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_download():
            client = pool.get_connection(config, project_root, window)
            panel.tracked(
                lambda: client.download(remote_path, file_path),
                window, f'Downloading "{remote_path}" to "{rel_path}"'
            )

    def is_visible(self, paths=None):
        return bool(paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncUploadFileSidebarCommand(sublime_plugin.WindowCommand):
    """Upload file — only visible when right-clicking files."""
    def run(self, paths=None):
        self.window.run_command("remote_sync_upload_paths", {"paths": paths})

    def is_visible(self, paths=None):
        return bool(paths) and all(os.path.isfile(p) for p in paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncDownloadFileSidebarCommand(sublime_plugin.WindowCommand):
    """Download file — only visible when right-clicking files."""
    def run(self, paths=None):
        self.window.run_command("remote_sync_download_paths", {"paths": paths})

    def is_visible(self, paths=None):
        return bool(paths) and all(os.path.isfile(p) for p in paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncDeleteRemoteFileSidebarCommand(sublime_plugin.WindowCommand):
    """Delete remote file — only visible when right-clicking files."""
    def run(self, paths=None):
        self.window.run_command("remote_sync_delete_remote_paths", {"paths": paths})

    def is_visible(self, paths=None):
        return bool(paths) and all(os.path.isfile(p) for p in paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncDeleteRemotePathsCommand(sublime_plugin.WindowCommand):
    """Delete remote files/folders."""
    def run(self, paths=None):
        if not paths:
            return
        window = self.window
        names = [os.path.basename(p) for p in paths]
        msg = ", ".join(names) if len(names) <= 3 else f"{len(names)} items"

        if not sublime.ok_cancel_dialog(
            f"Delete remote files?\n\n{msg}\n\nThis cannot be undone.", "Delete"
        ):
            return

        for path in paths:
            self._delete_remote(path)

    def _delete_remote(self, local_path):
        window = self.window
        config, project_root = _get_config_for_file(local_path, window)
        if not config:
            return
        rel_path = os.path.relpath(local_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, local_path, project_root)

        def on_success(_):
            sublime.status_message(f"RemoteSync: Deleted {rel_path}")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Delete failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_delete():
            client = pool.get_connection(config, project_root, window)
            panel.tracked(lambda: client.remove(remote_path), window, f'Deleting remote "{remote_path}"')

    def is_visible(self, paths=None):
        return bool(paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncRenameLocalAndRemoteCommand(sublime_plugin.WindowCommand):
    """Rename a folder/file both locally and on the remote server."""
    def run(self, paths=None):
        if not paths:
            return
        local_path = paths[0]
        window = self.window
        config, project_root = _get_config_for_file(local_path, window)
        if not config:
            _no_config_msg(window)
            return

        old_name = os.path.basename(local_path)

        def on_done(new_name):
            if not new_name or new_name == old_name:
                return
            parent = os.path.dirname(local_path)
            new_local = os.path.join(parent, new_name)
            old_remote = get_remote_path(config, local_path, project_root)
            new_remote = os.path.dirname(old_remote).rstrip("/") + "/" + new_name

            def on_success(_):
                sublime.status_message(f"RemoteSync: Renamed {old_name} → {new_name}")

            def on_error(err):
                sublime.status_message(f"RemoteSync: Rename failed - {err}")

            @run_async(on_success, on_error, config=config, window=window)
            def do_rename():
                # Rename remote first
                client = pool.get_connection(config, project_root, window)
                panel.log_separator(window)
                panel.tracked(
                    lambda: client.rename(old_remote, new_remote),
                    window, f'Renaming remote "{old_remote}" → "{new_remote}"'
                )
                # Rename local
                os.rename(local_path, new_local)
                panel.log(window, f"Renamed local {old_name} → {new_name}")

        window.show_input_panel("New name:", old_name, on_done, None, None)

    def is_visible(self, paths=None):
        return bool(paths) and len(paths) == 1 and _has_config_for_paths(paths, self.window)


class RemoteSyncDeleteLocalAndRemoteCommand(sublime_plugin.WindowCommand):
    """Delete folders/files both locally and on the remote server."""
    def run(self, paths=None):
        if not paths:
            return
        window = self.window
        names = [os.path.basename(p) for p in paths]
        msg = ", ".join(names) if len(names) <= 3 else f"{len(names)} items"

        if not sublime.ok_cancel_dialog(
            f"Delete LOCAL and REMOTE?\n\n{msg}\n\nThis will delete both the local and remote copies.\nThis cannot be undone.",
            "Delete Both"
        ):
            return

        for path in paths:
            self._delete_both(path)

    def _delete_both(self, local_path):
        window = self.window
        config, project_root = _get_config_for_file(local_path, window)
        if not config:
            return
        rel_path = os.path.relpath(local_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, local_path, project_root)
        is_dir = os.path.isdir(local_path)

        def on_success(_):
            sublime.status_message(f"RemoteSync: Deleted {rel_path} (local + remote)")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Delete failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_delete():
            client = pool.get_connection(config, project_root, window)
            panel.log_separator(window)
            # Delete remote
            if is_dir:
                panel.tracked(
                    lambda: client.remove_dir(remote_path),
                    window, f'Deleting remote folder "{remote_path}"'
                )
            else:
                panel.tracked(
                    lambda: client.remove(remote_path),
                    window, f'Deleting remote "{remote_path}"'
                )
            # Delete local
            import shutil
            if is_dir:
                shutil.rmtree(local_path)
            else:
                os.remove(local_path)
            panel.log(window, f"Deleted local {rel_path}")

    def is_visible(self, paths=None):
        return bool(paths) and _has_config_for_paths(paths, self.window)


class RemoteSyncDeleteRemoteFolderCommand(sublime_plugin.WindowCommand):
    """Delete only the remote folder (keep local)."""
    def run(self, dirs=None):
        if not dirs:
            return
        window = self.window
        names = [os.path.basename(d) for d in dirs]
        msg = ", ".join(names) if len(names) <= 3 else f"{len(names)} folders"

        if not sublime.ok_cancel_dialog(
            f"Delete REMOTE folders only?\n\n{msg}\n\nLocal folders will NOT be deleted.\nThis cannot be undone.",
            "Delete Remote"
        ):
            return

        for d in dirs:
            self._delete_remote_dir(d)

    def _delete_remote_dir(self, local_path):
        window = self.window
        config, project_root = _get_config_for_file(
            os.path.join(local_path, "dummy"), window
        )
        if not config:
            return
        rel_path = os.path.relpath(local_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, local_path, project_root)

        def on_success(_):
            sublime.status_message(f"RemoteSync: Deleted remote folder {rel_path}")

        def on_error(err):
            sublime.status_message(f"RemoteSync: Delete failed - {err}")

        @run_async(on_success, on_error, config=config, window=window)
        def do_delete():
            client = pool.get_connection(config, project_root, window)
            panel.log_separator(window)
            panel.tracked(
                lambda: client.remove_dir(remote_path),
                window, f'Deleting remote folder "{remote_path}"'
            )

    def is_visible(self, dirs=None):
        return bool(dirs) and _has_config_for_paths(dirs, self.window)


class RemoteSyncBrowseCommand(sublime_plugin.WindowCommand):
    """Browse remote server files."""
    def is_visible(self, dirs=None):
        if dirs is not None:
            return bool(dirs) and _has_config_for_paths(dirs, self.window)
        return True

    def run(self, dirs=None):
        window = self.window
        config, project_root = None, None
        if dirs:
            config, project_root = _get_config_for_file(os.path.join(dirs[0], "dummy"), window)
        if not config:
            view = window.active_view()
            file_path = view.file_name() if view else None
            config, project_root = _get_config_for_file(file_path, window)
        if not config:
            _no_config_msg(window)
            return

        remote_base = config.get("remote_path", "/").rstrip("/") or "/"
        if dirs and project_root:
            rel_folder = os.path.relpath(dirs[0], project_root).replace("\\", "/")
            start_path = remote_base if rel_folder == "." else remote_base.rstrip("/") + "/" + rel_folder
        else:
            start_path = remote_base

        self._browse_dir(config, project_root, start_path, window)

    def _browse_dir(self, config, project_root, remote_dir, window):
        remote_base = config.get("remote_path", "/").rstrip("/") or "/"
        host = config.get("host", "?")
        display_path = remote_dir + "/"

        KIND_PATH = (sublime.KIND_ID_COLOR_CYANISH, "›", "")
        KIND_ACTIONS = (sublime.KIND_ID_COLOR_LIGHT, "…", "")
        KIND_PARENT = (sublime.KIND_ID_COLOR_LIGHT, "‹", "")
        KIND_FOLDER = (sublime.KIND_ID_COLOR_YELLOWISH, "▪", "")
        KIND_FILE = (sublime.KIND_ID_AMBIGUOUS, " ", "")

        def on_success(entries):
            items = [
                sublime.QuickPanelItem(f"{host}:{display_path}", annotation="Path", kind=KIND_PATH),
                sublime.QuickPanelItem("Folder Actions", details="Create file, create folder, download, upload, refresh",
                                       annotation="Submenu", kind=KIND_ACTIONS),
            ]
            if remote_dir != remote_base:
                parent_path = remote_dir.rsplit("/", 1)[0] + "/"
                items.append(sublime.QuickPanelItem("Up a Folder", details=parent_path, annotation="Parent", kind=KIND_PARENT))

            for entry in entries:
                name = entry["name"]
                if entry["is_dir"]:
                    items.append(sublime.QuickPanelItem(name + "/", annotation="Folder", kind=KIND_FOLDER))
                else:
                    items.append(sublime.QuickPanelItem(name, annotation=panel.format_size(entry["size"]), kind=KIND_FILE))

            def on_select(idx):
                if idx <= 0:
                    return
                if idx == 1:
                    self._folder_actions(config, project_root, remote_dir, window)
                    return
                has_parent = remote_dir != remote_base
                if has_parent and idx == 2:
                    parent = remote_dir.rsplit("/", 1)[0] or "/"
                    if len(parent) < len(remote_base):
                        parent = remote_base
                    self._browse_dir(config, project_root, parent, window)
                    return
                entry_offset = 3 if has_parent else 2
                entry = entries[idx - entry_offset]
                full_path = remote_dir + "/" + entry["name"]
                if entry["is_dir"]:
                    self._browse_dir(config, project_root, full_path, window)
                else:
                    self._file_actions(config, project_root, remote_dir, full_path, entry, window)

            if window.num_groups() > 1:
                window.focus_group(0)
            window.show_quick_panel(items, on_select)

        def on_error(err):
            sublime.status_message(f"RemoteSync: Browse failed - {err}")
            panel.log(window, f"Browse failed: {remote_dir} — {err}", error=True)

        @run_async(on_success, on_error, config=config, window=window)
        def do_list():
            client = pool.get_connection(config, project_root, window)
            return client.listdir(remote_dir)

        sublime.status_message(f"RemoteSync: Listing {remote_dir}...")

    def _folder_actions(self, config, project_root, remote_dir, window):
        remote_base = config.get("remote_path", "/").rstrip("/") or "/"
        rel = remote_dir[len(remote_base):].lstrip("/") or "."
        local_dir = os.path.join(project_root, rel.replace("/", os.sep)) if rel != "." else project_root

        KIND_BACK = (sublime.KIND_ID_COLOR_LIGHT, "‹", "")
        KIND_ACTION = (sublime.KIND_ID_COLOR_GREENISH, "▸", "")

        items = [
            sublime.QuickPanelItem("Back", details="Return to file listing", kind=KIND_BACK),
            sublime.QuickPanelItem("New Folder", details=f"Create folder in {remote_dir}/", kind=KIND_ACTION),
            sublime.QuickPanelItem("New File", details=f"Create file in {remote_dir}/", kind=KIND_ACTION),
            sublime.QuickPanelItem("Download Folder", details=f"Download all files to {rel}/", kind=KIND_ACTION),
            sublime.QuickPanelItem("Upload to Here", details=f"Upload local {rel}/ to server", kind=KIND_ACTION),
            sublime.QuickPanelItem("Refresh", details="Reload directory listing", kind=KIND_ACTION),
        ]

        def on_select(idx):
            if idx <= 0:
                self._browse_dir(config, project_root, remote_dir, window)
                return
            actions = {
                1: lambda: self._create_remote_folder(config, project_root, remote_dir, window),
                2: lambda: self._create_remote_file(config, project_root, remote_dir, window),
                3: lambda: self._download_browse_folder(config, project_root, remote_dir, local_dir, window),
                4: lambda: self._upload_browse_folder(config, project_root, remote_dir, local_dir, window),
                5: lambda: self._browse_dir(config, project_root, remote_dir, window),
            }
            actions.get(idx, lambda: None)()

        if window.num_groups() > 1:
            window.focus_group(0)
        window.show_quick_panel(items, on_select)

    def _create_remote_folder(self, config, project_root, remote_dir, window):
        def on_done(name):
            if not name:
                self._browse_dir(config, project_root, remote_dir, window)
                return
            new_path = remote_dir + "/" + name

            @run_async(lambda _: (sublime.status_message(f"RemoteSync: Created {name}/"),
                                   self._browse_dir(config, project_root, remote_dir, window)),
                       lambda e: self._browse_dir(config, project_root, remote_dir, window),
                       config=config, window=window)
            def do_mkdir():
                client = pool.get_connection(config, project_root, window)
                panel.tracked(lambda: client.exec_command(f"mkdir -p {_shell_quote(new_path)}"),
                              window, f'Creating folder "{new_path}"')

        window.show_input_panel("Folder name:", "", on_done, None,
                                lambda: self._browse_dir(config, project_root, remote_dir, window))

    def _create_remote_file(self, config, project_root, remote_dir, window):
        def on_done(name):
            if not name:
                self._browse_dir(config, project_root, remote_dir, window)
                return
            new_path = remote_dir + "/" + name

            @run_async(lambda _: (sublime.status_message(f"RemoteSync: Created {name}"),
                                   self._browse_dir(config, project_root, remote_dir, window)),
                       lambda e: self._browse_dir(config, project_root, remote_dir, window),
                       config=config, window=window)
            def do_touch():
                client = pool.get_connection(config, project_root, window)
                panel.tracked(lambda: client.exec_command(f"touch {_shell_quote(new_path)}"),
                              window, f'Creating file "{new_path}"')

        window.show_input_panel("File name:", "", on_done, None,
                                lambda: self._browse_dir(config, project_root, remote_dir, window))

    def _download_browse_folder(self, config, project_root, remote_dir, local_dir, window):
        @run_async(lambda r: (panel.log(window, f"Downloaded {r[0]} files" + (f" ({r[1]} failed)" if r[1] else "")),
                              sublime.status_message(f"RemoteSync: Downloaded {r[0]} files")),
                   lambda e: sublime.status_message(f"RemoteSync: Download failed - {e}"),
                   config=config, window=window)
        def do_download():
            import threading as _th
            client = pool.get_connection(config, project_root, window)

            # Scan with cascading methods + timeout + error handling
            scan_timeout = get_timeout(config, "scan")
            scan_done = _th.Event()
            scan_error = [None]
            file_list = []
            scan_progress = {"files": 0, "dirs": 0}

            def _scan():
                try:
                    file_list.extend(
                        fast_scan(client, config, remote_dir,
                                  project_root, window,
                                  progress=scan_progress)
                    )
                except Exception as e:
                    scan_error[0] = e
                finally:
                    scan_done.set()

            # Timeout safety net — forces scan_done.set() so the
            # spinner stops. Only active if scan_timeout > 0 (0 = unlimited).
            timeout_timer = None
            if scan_timeout > 0:
                def _timeout_handler():
                    if not scan_done.is_set():
                        scan_error[0] = ScanTimeoutError(
                            f"Scan timed out after {scan_timeout}s")
                        scan_done.set()

                timeout_timer = _th.Timer(scan_timeout, _timeout_handler)
                timeout_timer.daemon = True
                timeout_timer.start()

            scan_thread = _th.Thread(target=_scan, daemon=True)
            scan_thread.start()
            panel.animate_progress(window, "Scanning remote files",
                                   scan_done, progress=scan_progress)
            scan_thread.join(timeout=5)
            if timeout_timer:
                timeout_timer.cancel()

            # Handle scan error (includes timeout)
            if scan_error[0]:
                panel.log_complete(window, success=False,
                                   detail=str(scan_error[0]))
                raise scan_error[0]

            if not file_list:
                panel.log_complete(window, success=True, detail="empty")
                return (0, 0, 0.0)

            panel.log_complete(window, success=True,
                               detail=f"{len(file_list)} files found")
            return pool.parallel_operation(file_list, lambda c, lp, rp: c.download(rp, lp),
                                           config, project_root, window, "Downloading")

    def _upload_browse_folder(self, config, project_root, remote_dir, local_dir, window):
        if not os.path.isdir(local_dir):
            sublime.status_message(f"RemoteSync: Local folder not found: {local_dir}")
            return

        @run_async(lambda r: sublime.status_message(f"RemoteSync: Uploaded {r[0]} files"),
                   lambda e: sublime.status_message(f"RemoteSync: Upload failed - {e}"),
                   config=config, window=window)
        def do_upload():
            file_list = []
            for root, _dirs, files in os.walk(local_dir):
                for fname in files:
                    local_path = os.path.join(root, fname)
                    rel_path = os.path.relpath(local_path, project_root).replace("\\", "/")
                    if _should_ignore(local_path, rel_path, config):
                        continue
                    rpath = remote_dir + "/" + os.path.relpath(local_path, local_dir).replace("\\", "/")
                    file_list.append((local_path, rpath, rel_path))
            return pool.parallel_operation(file_list, lambda c, lp, rp: c.upload(lp, rp),
                                           config, project_root, window, "Uploading") if file_list else (0, 0, 0.0)

    def _file_actions(self, config, project_root, remote_dir, remote_path, entry, window):
        remote_base = config.get("remote_path", "/").rstrip("/") or "/"
        rel = remote_path[len(remote_base):].lstrip("/")
        local_path = os.path.join(project_root, rel.replace("/", os.sep))
        name = entry["name"]
        size = panel.format_size(entry["size"])

        KIND_FILE_HDR = (sublime.KIND_ID_COLOR_CYANISH, "›", "")
        KIND_BACK = (sublime.KIND_ID_COLOR_LIGHT, "‹", "")
        KIND_ACTION = (sublime.KIND_ID_COLOR_GREENISH, "▸", "")
        KIND_DANGER = (sublime.KIND_ID_COLOR_REDISH, "▸", "")

        items = [
            sublime.QuickPanelItem(name, details=remote_path, annotation=size, kind=KIND_FILE_HDR),
            sublime.QuickPanelItem("Back", details="Return to file listing", kind=KIND_BACK),
            sublime.QuickPanelItem("Download", details=f"Save to {rel}", kind=KIND_ACTION),
            sublime.QuickPanelItem("Open", details="Download and open in editor", kind=KIND_ACTION),
            sublime.QuickPanelItem("Rename", details=f"Rename {name} on server", kind=KIND_ACTION),
            sublime.QuickPanelItem("Delete", details=f"Delete {name} from server", kind=KIND_DANGER),
            sublime.QuickPanelItem("Permissions", details=f"Change permissions of {name}", kind=KIND_ACTION),
        ]

        def on_select(idx):
            if idx <= 0:
                return
            actions = {
                1: lambda: self._browse_dir(config, project_root, remote_dir, window),
                2: lambda: self._dl_file(config, project_root, remote_path, rel, local_path, window, False),
                3: lambda: self._dl_file(config, project_root, remote_path, rel, local_path, window, True),
                4: lambda: self._rename_remote(config, project_root, remote_dir, remote_path, name, window),
                5: lambda: self._delete_remote_browse(config, project_root, remote_dir, remote_path, name, window),
                6: lambda: self._chmod_remote(config, project_root, remote_dir, remote_path, name, window),
            }
            actions.get(idx, lambda: None)()

        if window.num_groups() > 1:
            window.focus_group(0)
        window.show_quick_panel(items, on_select)

    def _dl_file(self, config, project_root, remote_path, rel, local_path, window, open_after):
        def on_success(_):
            sublime.status_message(f"RemoteSync: Downloaded {rel}")
            if open_after:
                sublime.set_timeout(lambda: window.open_file(local_path), 100)

        @run_async(on_success, lambda e: sublime.status_message(f"RemoteSync: Download failed - {e}"),
                   config=config, window=window)
        def do_dl():
            client = pool.get_connection(config, project_root, window)
            panel.tracked(lambda: client.download(remote_path, local_path), window, f'Downloading "{remote_path}"')

    def _rename_remote(self, config, project_root, remote_dir, remote_path, old_name, window):
        def on_done(new_name):
            if not new_name or new_name == old_name:
                self._browse_dir(config, project_root, remote_dir, window)
                return
            new_path = remote_dir + "/" + new_name

            @run_async(lambda _: (sublime.status_message(f"RemoteSync: Renamed to {new_name}"),
                                   self._browse_dir(config, project_root, remote_dir, window)),
                       lambda e: sublime.status_message(f"RemoteSync: Rename failed - {e}"),
                       config=config, window=window)
            def do_rename():
                client = pool.get_connection(config, project_root, window)
                panel.tracked(lambda: client.rename(remote_path, new_path), window, f'Renaming "{old_name}" to "{new_name}"')

        window.show_input_panel("New name:", old_name, on_done, None,
                                lambda: self._browse_dir(config, project_root, remote_dir, window))

    def _delete_remote_browse(self, config, project_root, remote_dir, remote_path, name, window):
        if not sublime.ok_cancel_dialog(f"Delete remote file?\n\n{name}\n\nThis cannot be undone.", "Delete"):
            return

        @run_async(lambda _: (sublime.status_message(f"RemoteSync: Deleted {name}"),
                               self._browse_dir(config, project_root, remote_dir, window)),
                   lambda e: sublime.status_message(f"RemoteSync: Delete failed - {e}"),
                   config=config, window=window)
        def do_delete():
            client = pool.get_connection(config, project_root, window)
            panel.tracked(lambda: client.remove(remote_path), window, f'Deleting remote "{remote_path}"')

    def _chmod_remote(self, config, project_root, remote_dir, remote_path, name, window):
        def on_done(perms):
            if not perms:
                return
            import re as _re
            if not _re.match(r'^[0-7]{3,4}$', perms.strip()):
                sublime.status_message("RemoteSync: Invalid permissions — use octal like 644 or 0755")
                return
            perms = perms.strip()

            @run_async(lambda _: sublime.status_message(f"RemoteSync: Permissions set to {perms}"),
                       lambda e: sublime.status_message(f"RemoteSync: chmod failed - {e}"),
                       config=config, window=window)
            def do_chmod():
                client = pool.get_connection(config, project_root, window)
                panel.tracked(lambda: client.exec_command(f"chmod {perms} {_shell_quote(remote_path)}"),
                              window, f'Setting permissions {perms} on "{name}"')

        window.show_input_panel("Permissions (e.g. 644, 755):", "644", on_done, None, None)


# =============================================================================
# Config, settings, and utility commands
# =============================================================================

class RemoteSyncCreateConfigCommand(sublime_plugin.WindowCommand):
    """Create a new remote-sync-config.json in the project root."""
    def run(self):
        folders = self.window.folders()
        if not folders:
            sublime.status_message("RemoteSync: No project folder open.")
            return
        project_root = folders[0]
        config_path = os.path.join(project_root, CONFIG_FILENAME)
        if os.path.exists(config_path):
            self.window.open_file(config_path)
            return
        path = create_default_config(project_root)
        self.window.open_file(path)
        sublime.status_message("RemoteSync: Created remote-sync-config.json — edit it with your server details.")
        panel.log(self.window, f"Created config: {path}")


class RemoteSyncEditServerConfigCommand(sublime_plugin.WindowCommand):
    """Open the remote-sync-config.json for the selected path."""
    def run(self, paths=None, dirs=None):
        target = (dirs or paths or [None])[0]
        if not target:
            return
        lookup = os.path.join(target, "dummy") if os.path.isdir(target) else target
        config_file, _ = find_config(lookup)
        if config_file:
            self.window.open_file(config_file)
        else:
            sublime.status_message("RemoteSync: No config found for this path.")

    def is_visible(self, paths=None, dirs=None):
        items = dirs or paths
        return bool(items) and _has_config_for_paths(items, self.window)


class RemoteSyncCreateConfigSidebarCommand(sublime_plugin.WindowCommand):
    """Sidebar version — only visible when the selected folder has no direct config."""
    def run(self, dirs=None):
        if not dirs:
            return
        folder = dirs[0]
        config_path = os.path.join(folder, CONFIG_FILENAME)
        if os.path.exists(config_path):
            self.window.open_file(config_path)
            return
        path = create_default_config(folder)
        self.window.open_file(path)
        sublime.status_message("RemoteSync: Created remote-sync-config.json — edit it with your server details.")

    def is_visible(self, dirs=None):
        if not dirs:
            return False
        # Show when the selected folder does NOT have its own config directly inside it.
        # Walking up to parent configs is intentionally ignored here so subfolders can
        # each get their own config independently of a parent config.
        return not os.path.isfile(os.path.join(dirs[0], CONFIG_FILENAME))


class RemoteSyncDisconnectCommand(sublime_plugin.WindowCommand):
    """Disconnect all connections."""
    def run(self):
        count = pool.disconnect_all(self.window)
        msg = f"Closed {count} connection(s)." if count else "No active connections."
        sublime.status_message(f"RemoteSync: {msg}")
        panel.log(self.window, msg)


class RemoteSyncCancelCommand(sublime_plugin.WindowCommand):
    """Cancel all pending operations."""
    def run(self):
        _op_queue.cancel_all(self.window)

    def is_enabled(self):
        return _op_queue.is_busy or _op_queue.pending_count > 0


class RemoteSyncShowPanelCommand(sublime_plugin.WindowCommand):
    """Show the RemoteSync output panel."""
    def run(self):
        self.window.run_command("show_panel", {"panel": f"output.{panel.PANEL_NAME}"})


class RemoteSyncClearPanelCommand(sublime_plugin.WindowCommand):
    """Clear the RemoteSync output panel."""
    def run(self):
        p = self.window.find_output_panel(panel.PANEL_NAME)
        if p:
            p.run_command("select_all")
            p.run_command("right_delete")
        sublime.status_message("RemoteSync: Panel cleared")


class RemoteSyncOpenSettingsCommand(sublime_plugin.WindowCommand):
    """Open plugin settings (side-by-side defaults + user overrides)."""
    def run(self):
        self.window.run_command("edit_settings", {
            "base_file": "${packages}/RemoteSync/RemoteSync.sublime-settings",
            "default": "// RemoteSync User Settings\n// Place your overrides here\n{\n\t$0\n}\n"
        })


class RemoteSyncOpenKeybindingsCommand(sublime_plugin.WindowCommand):
    """Open keybindings for the current platform."""
    def run(self):
        pkg_dir = os.path.dirname(__file__)
        platform_map = {"windows": "Windows", "osx": "OSX", "linux": "Linux"}
        platform_name = platform_map.get(sublime.platform(), "Windows")
        keymap_file = os.path.join(pkg_dir, f"Default ({platform_name}).sublime-keymap")
        self.window.open_file(keymap_file)


class RemoteSyncDiffRemotePathsCommand(sublime_plugin.WindowCommand):
    """Sidebar wrapper — diff selected file with remote."""
    def run(self, paths=None):
        if not paths:
            return
        path = paths[0]
        if os.path.isdir(path):
            return
        view = self.window.find_open_file(path)
        if view:
            view.run_command("remote_sync_diff_remote")
        else:
            view = self.window.open_file(path)

            def _check():
                if view.is_loading():
                    sublime.set_timeout(_check, 100)
                else:
                    view.run_command("remote_sync_diff_remote")
            sublime.set_timeout(_check, 100)

    def is_visible(self, paths=None):
        if not paths or os.path.isdir(paths[0]):
            return False
        return _has_config_for_paths(paths, self.window)


class RemoteSyncDiffRemoteCommand(sublime_plugin.TextCommand):
    """Download remote version and diff with local."""
    def run(self, edit):
        view = self.view
        file_path = view.file_name()
        if not file_path:
            return

        window = view.window()
        config, project_root = _get_config_for_file(file_path, window)
        if not config:
            _no_config_msg(window)
            return

        rel_path = os.path.relpath(file_path, project_root).replace("\\", "/")
        remote_path = get_remote_path(config, file_path, project_root)
        tmp_path = file_path + ".remote-sync-tmp"

        def on_success(_):
            def show_diff():
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        local_content = f.read()
                except Exception:
                    local_content = ""
                try:
                    with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                        remote_content = f.read()
                except Exception:
                    remote_content = ""

                import difflib
                diff = difflib.unified_diff(
                    remote_content.splitlines(keepends=True),
                    local_content.splitlines(keepends=True),
                    fromfile=f"REMOTE: {rel_path}",
                    tofile=f"LOCAL: {rel_path}",
                    lineterm=""
                )
                diff_text = "\n".join(diff)

                if not diff_text:
                    sublime.status_message(f"RemoteSync: No differences found in {rel_path}")
                else:
                    diff_view = window.new_file()
                    diff_view.set_name(f"Diff: {os.path.basename(file_path)}")
                    diff_view.set_scratch(True)
                    diff_view.assign_syntax("Packages/Diff/Diff.sublime-syntax")
                    diff_view.run_command("append", {"characters": diff_text})
                    diff_view.set_read_only(True)

                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            sublime.set_timeout(show_diff, 100)

        @run_async(on_success, lambda e: sublime.status_message(f"RemoteSync: Diff failed - {e}"),
                   config=config, window=window)
        def do_download():
            client = pool.get_connection(config, project_root, window)
            panel.tracked(lambda: client.download(remote_path, tmp_path),
                          window, f'Downloading remote for diff "{rel_path}"')

        sublime.status_message("RemoteSync: Downloading remote for diff...")

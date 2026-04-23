"""RemoteSync — Connection pool and parallel operations.

Thread-safe connection management with:
  - Global lock protecting all connection state
  - Keepalive ping timers
  - Parallel operations using a semaphore-based connection pool
  - Smart retry that only retries on retryable errors
"""

import sublime
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from .sftp_client import create_client
from .errors import is_retryable, RemoteConnectionError
from . import panel


# ---------------------------------------------------------------------------
# Connection pool (one persistent connection per project root)
# ---------------------------------------------------------------------------

_connections = {}       # project_root → client
_connection_info = {}   # project_root → {"host": ..., "type": ...}
_keepalive_timers = {}  # project_root → threading.Timer
_pool_lock = threading.Lock()


def _stop_keepalive(project_root):
    """Stop the keepalive timer.  Caller must hold _pool_lock."""
    timer = _keepalive_timers.pop(project_root, None)
    if timer:
        timer.cancel()


def update_status_bar(window=None):
    """Update status bar with connection info (⚡ SFTP: host)."""
    with _pool_lock:
        if not _connections:
            for w in sublime.windows():
                for v in w.views():
                    v.erase_status("remotesync_conn")
            return

        parts = []
        for root, info in list(_connection_info.items()):
            if root in _connections and _connections[root].is_connected():
                parts.append(f"{info['type']}: {info['host']}")

    status = ("⚡ " + ", ".join(parts)) if parts else ""
    windows = [window] if window else sublime.windows()
    for w in windows:
        for v in w.views():
            if status:
                v.set_status("remotesync_conn", status)
            else:
                v.erase_status("remotesync_conn")


def start_keepalive(config, project_root):
    """Start periodic keepalive pings for a connection."""
    interval = int(config.get("keepalive", 0))
    if interval <= 0:
        return

    def _ping():
        with _pool_lock:
            if project_root not in _connections:
                return
            client = _connections[project_root]

        try:
            if client.is_connected():
                conn_type = config.get("type", "sftp").lower()
                if conn_type in ("sftp", "scp") and hasattr(client, '_ssh_bin') and client._ssh_bin:
                    client._run_ssh("echo keepalive", timeout=10)
            else:
                with _pool_lock:
                    _stop_keepalive(project_root)
                    _connections.pop(project_root, None)
                    _connection_info.pop(project_root, None)
                sublime.set_timeout(lambda: update_status_bar(), 0)
                return
        except Exception:
            with _pool_lock:
                _stop_keepalive(project_root)
                old = _connections.pop(project_root, None)
                _connection_info.pop(project_root, None)
            if old:
                try:
                    old.disconnect()
                except Exception:
                    pass
            sublime.set_timeout(lambda: update_status_bar(), 0)
            return

        with _pool_lock:
            timer = threading.Timer(interval, _ping)
            timer.daemon = True
            _keepalive_timers[project_root] = timer
            timer.start()

    with _pool_lock:
        _stop_keepalive(project_root)
        timer = threading.Timer(interval, _ping)
        timer.daemon = True
        _keepalive_timers[project_root] = timer
        timer.start()


_connecting = {}  # project_root → threading.Event (prevents duplicate connections)


def get_connection(config, project_root, window=None):
    """Get or create a connection for a project (thread-safe).

    Prevents duplicate simultaneous connection attempts to the same server.
    """
    # Fast path: already connected
    with _pool_lock:
        if project_root in _connections:
            client = _connections[project_root]
            if client.is_connected():
                return client
            client.disconnect()
            _stop_keepalive(project_root)

    # Prevent duplicate connection attempts — wait if another thread is connecting
    with _pool_lock:
        if project_root in _connecting:
            wait_event = _connecting[project_root]
        else:
            wait_event = None
            _connecting[project_root] = threading.Event()

    if wait_event:
        # Another thread is already connecting — wait for it
        if window:
            panel.log(window, "Waiting for existing connection attempt...")
        wait_event.wait(timeout=60)
        # Check if the other thread succeeded
        with _pool_lock:
            if project_root in _connections:
                client = _connections[project_root]
                if client.is_connected():
                    return client
        raise RemoteConnectionError("Connection failed (another attempt already tried)")

    conn_type = config.get("type", "sftp").upper()
    host = config.get("host", "?")
    user = config.get("user", "?")
    msg = f'Connecting to {conn_type} server "{host}" as "{user}"'

    t0 = time.monotonic()
    try:
        connect_done = threading.Event()
        connect_error = [None]
        client_holder = [None]

        def _do_connect():
            try:
                client = create_client(config)
                client.connect()
                client_holder[0] = client
            except Exception as e:
                connect_error[0] = e
            finally:
                connect_done.set()

        if window:
            conn_thread = threading.Thread(target=_do_connect, daemon=True)
            conn_thread.start()
            panel.animate_progress(window, msg, connect_done)
            conn_thread.join()
        else:
            _do_connect()

        if connect_error[0]:
            raise connect_error[0]

        client = client_holder[0]

        with _pool_lock:
            _connections[project_root] = client
            _connection_info[project_root] = {"host": host, "type": conn_type}

        if window:
            panel.log_complete(window, success=True, elapsed=time.monotonic() - t0)

        sublime.set_timeout(lambda: update_status_bar(window), 0)
        start_keepalive(config, project_root)

        # Validate remote folder
        remote_base = config.get("remote_path", "/").rstrip("/") or "/"
        validate_done = threading.Event()
        validate_error = [None]

        def _do_validate():
            try:
                client.listdir(remote_base)
            except Exception as e:
                validate_error[0] = e
            finally:
                validate_done.set()

        t1 = time.monotonic()
        if window:
            val_thread = threading.Thread(target=_do_validate, daemon=True)
            val_thread.start()
            panel.animate_progress(window, f'Validating remote folder "{remote_base}"', validate_done)
            val_thread.join()
            if validate_error[0]:
                panel.log_complete(window, success=False,
                                   detail=str(validate_error[0]) or "folder not found")
            else:
                panel.log_complete(window, success=True, elapsed=time.monotonic() - t1)
        else:
            _do_validate()

        return client
    except Exception as e:
        if window:
            panel.log_complete(window, success=False, detail=str(e))
        raise
    finally:
        # Signal waiting threads and clean up
        with _pool_lock:
            evt = _connecting.pop(project_root, None)
        if evt:
            evt.set()


def drop_connection(project_root, window=None):
    """Drop a single connection by project root (e.g. after config change)."""
    with _pool_lock:
        _stop_keepalive(project_root)
        client = _connections.pop(project_root, None)
        _connection_info.pop(project_root, None)
        # Also clear any in-progress connection attempt
        evt = _connecting.pop(project_root, None)
        if evt:
            evt.set()

    if client:
        try:
            client.disconnect()
        except Exception:
            pass

    sublime.set_timeout(lambda: update_status_bar(window), 0)


def disconnect_all(window=None):
    """Disconnect all connections (thread-safe)."""
    with _pool_lock:
        # Signal any threads waiting to connect
        for evt in _connecting.values():
            evt.set()
        _connecting.clear()
        count = len(_connections)
        clients = list(_connections.values())
        for key in list(_connections.keys()):
            _stop_keepalive(key)
        _connections.clear()
        _connection_info.clear()

    for c in clients:
        try:
            c.disconnect()
        except Exception:
            pass

    update_status_bar()
    return count


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

def with_retry(fn, config, window=None, project_root=None):
    """Run fn with automatic retries based on config retry_count.

    Uses is_retryable() — only retries on timeout/connection-lost errors,
    not on auth failures or permission errors.
    """
    retries = int(config.get("retry_count", 0))
    last_error = None

    for attempt in range(1 + retries):
        try:
            return fn()
        except Exception as e:
            last_error = e
            if attempt < retries and is_retryable(e):
                delay = 2 * (attempt + 1)
                if window:
                    panel.log(window, f"Retry {attempt + 1}/{retries} in {delay}s — {e}")
                time.sleep(delay)
                # Force reconnect
                with _pool_lock:
                    if project_root and project_root in _connections:
                        _stop_keepalive(project_root)
                        old = _connections.pop(project_root, None)
                        _connection_info.pop(project_root, None)
                    elif not project_root:
                        old = None
                        for key in list(_connections.keys()):
                            _stop_keepalive(key)
                            try:
                                _connections[key].disconnect()
                            except Exception:
                                pass
                        _connections.clear()
                        _connection_info.clear()
                    else:
                        old = None

                if old:
                    try:
                        old.disconnect()
                    except Exception:
                        pass
                sublime.set_timeout(lambda: update_status_bar(), 0)
            elif attempt < retries:
                # Non-retryable error — fail immediately
                break
    raise last_error


# ---------------------------------------------------------------------------
# Parallel operations (with connection pool via semaphore)
# ---------------------------------------------------------------------------

def parallel_operation(files, operation_fn, config, project_root, window,
                       op_label="Processing"):
    """Run operations in parallel using a thread pool.

    Improvement over v1: uses a semaphore-limited pool of reusable
    connections instead of creating+destroying one per file.
    """
    max_workers = int(config.get("parallel_connections", 4))
    max_workers = min(max_workers, len(files), 8)
    if max_workers <= 1 or len(files) <= 2:
        return serial_operation(files, operation_fn, config, project_root, window, op_label)

    conn_type = config.get("type", "sftp").upper()
    panel.log(window, f"[{conn_type}] Starting {op_label.lower()} — {len(files)} files, {max_workers} connections")

    _t_start = time.monotonic()
    completed = [0]
    errors = [0]
    total = len(files)
    lock = threading.Lock()
    display_lock = threading.Lock()

    # Create a pool of reusable connections
    conn_pool = []
    conn_semaphore = threading.Semaphore(max_workers)
    conn_pool_lock = threading.Lock()

    def _get_worker_conn():
        """Get a connection from pool or create a new one."""
        conn_semaphore.acquire()
        with conn_pool_lock:
            if conn_pool:
                return conn_pool.pop()
        # Create new
        c = create_client(config)
        c.connect()
        return c

    def _return_worker_conn(client):
        """Return a connection to the pool."""
        with conn_pool_lock:
            conn_pool.append(client)
        conn_semaphore.release()

    def _worker(item):
        local_path, remote_path, rel_path = item
        t0 = time.monotonic()
        client = None
        op_done = threading.Event()
        op_error = [None]

        # Get connection
        try:
            client = _get_worker_conn()
        except Exception as e:
            panel.log(window, f'{op_label} "{rel_path}" ......... failure ({e})', error=True)
            with lock:
                errors[0] += 1
            return

        # Run the operation in a sub-thread so we can animate dots
        def _run_op():
            try:
                operation_fn(client, local_path, remote_path)
            except Exception as e:
                op_error[0] = str(e)
            finally:
                op_done.set()

        op_thread = threading.Thread(target=_run_op, daemon=True)
        op_thread.start()

        # Display with animated dots (one worker at a time)
        with display_lock:
            panel.animate_progress(window, f'{op_label} "{rel_path}"', op_done)
            elapsed = time.monotonic() - t0
            if op_error[0] is None:
                panel.log_complete(window, success=True, elapsed=elapsed)
            else:
                panel.log_complete(window, success=False, detail=op_error[0])

        op_thread.join()

        # Bookkeeping
        if op_error[0] is None:
            _return_worker_conn(client)
            client = None
            with lock:
                completed[0] += 1
                n = completed[0]
            sublime.set_timeout(
                lambda: sublime.status_message(f"RemoteSync: {op_label} ({n}/{total}) ..."), 0
            )
        else:
            with lock:
                errors[0] += 1
            if client:
                try:
                    client.disconnect()
                except Exception:
                    pass
                conn_semaphore.release()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            pool.map(_worker, files)
    finally:
        # Clean up pooled connections
        with conn_pool_lock:
            for c in conn_pool:
                try:
                    c.disconnect()
                except Exception:
                    pass
            conn_pool.clear()

    return completed[0], errors[0], time.monotonic() - _t_start


def serial_operation(files, operation_fn, config, project_root, window,
                     op_label="Processing"):
    """Serial fallback — one connection, files one by one."""
    conn_type = config.get("type", "sftp").upper()
    panel.log(window, f"[{conn_type}] Starting {op_label.lower()} — {len(files)} files")

    client = get_connection(config, project_root, window)
    completed = 0
    errors = 0
    total = len(files)
    _t_start = time.monotonic()
    for local_path, remote_path, rel_path in files:
        try:
            panel.tracked(
                lambda lp=local_path, rp=remote_path: operation_fn(client, lp, rp),
                window,
                f'{op_label} "{rel_path}"'
            )
            completed += 1
            sublime.set_timeout(
                lambda c=completed: sublime.status_message(
                    f"RemoteSync: {op_label} ({c}/{total}) ..."
                ), 0
            )
        except Exception:
            errors += 1

    return completed, errors, time.monotonic() - _t_start

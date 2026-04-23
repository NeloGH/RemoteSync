"""RemoteSync — Fast remote directory scanning with cascading methods.

Tries the fastest scan method first and falls back to slower ones:
  0. find   — single SSH command, fastest (SFTP/SCP only)
  1. rsync  — single SSH command (SFTP/SCP only)
  2. parallel — N connections doing listdir in parallel (all protocols)
  3. sequential — recursive listdir, one dir at a time (always works)

Remembers which method worked per host so subsequent scans skip
methods that already failed.
"""

import os
import threading
import queue as _queue
from concurrent.futures import ThreadPoolExecutor

from .config import should_ignore, get_timeout, get_remote_path
from .sftp_client import create_client, _shell_quote
from .errors import RemoteConnectionError, ConnectionTimeoutError
from . import panel


# ---------------------------------------------------------------------------
# Method memory — remembers which scan method worked per host
# ---------------------------------------------------------------------------

_scan_method_cache = {}    # host → method index (0-3)
_scan_cache_lock = threading.Lock()

_METHOD_NAMES = ["find", "rsync --list-only", "parallel scan", "sequential scan"]


def _get_start_method(host, is_ftp):
    """Get the method index to start from for this host."""
    with _scan_cache_lock:
        cached = _scan_method_cache.get(host)
    if cached is not None:
        return cached
    # FTP can't run shell commands and most shared hosting limits
    # concurrent connections — go straight to sequential (index 3)
    return 3 if is_ftp else 0


def _remember_method(host, method_index):
    """Store the method that worked for this host."""
    with _scan_cache_lock:
        _scan_method_cache[host] = method_index


# ---------------------------------------------------------------------------
# Path mapping helper
# ---------------------------------------------------------------------------

def _map_remote_to_local(remote_path, remote_base, project_root):
    """Convert a remote file path to (local_path, rel_path)."""
    # Strip the remote base to get the relative portion
    if remote_path.startswith(remote_base):
        rel = remote_path[len(remote_base):].lstrip("/")
    else:
        rel = remote_path.lstrip("/")
    local = os.path.join(project_root, rel.replace("/", os.sep))
    return local, rel


# ---------------------------------------------------------------------------
# Method 0: find (fastest — single SSH command)
# ---------------------------------------------------------------------------

def _scan_find(client, remote_dir, remote_base, project_root, config, timeout,
               progress=None):
    """Scan using `find -type f -printf '%s\\t%p\\n'`.

    Returns list of (local_path, remote_path, rel_path).
    Raises on failure (command not found, permission denied, etc).
    """
    if progress is not None:
        progress["status"] = "running find..."

    cmd = f"find {_shell_quote(remote_dir)} -type f -printf '%s\\t%p\\n'"
    output = client.exec_command(cmd, timeout=timeout)

    if not output:
        return []

    if progress is not None:
        progress["status"] = "parsing"

    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        rpath = parts[1]
        local_path, rel_path = _map_remote_to_local(rpath, remote_base, project_root)
        if not should_ignore(local_path, rel_path, config, remote_size=size):
            results.append((local_path, rpath, rel_path))
            if progress is not None:
                progress["files"] = len(results)

    return results


# ---------------------------------------------------------------------------
# Method 1: rsync --list-only (single SSH command)
# ---------------------------------------------------------------------------

def _scan_rsync(client, remote_dir, remote_base, project_root, config, timeout,
                progress=None):
    """Scan using `rsync --list-only -r`.

    rsync output format: <perms> <size> <date> <time> <path>
    Returns list of (local_path, remote_path, rel_path).
    """
    if progress is not None:
        progress["status"] = "running rsync..."

    cmd = f"rsync --list-only -r {_shell_quote(remote_dir)}/"
    output = client.exec_command(cmd, timeout=timeout)

    if not output:
        return []

    if progress is not None:
        progress["status"] = "parsing"

    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Skip directories (permissions start with 'd')
        if line.startswith("d"):
            continue
        # Parse: -rw-r--r--    1234 2024/01/15 10:30:00 path/to/file
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        try:
            size = int(parts[1].replace(",", ""))
        except ValueError:
            continue
        # rsync gives paths relative to the source directory
        rel_from_source = parts[4]
        rpath = remote_dir.rstrip("/") + "/" + rel_from_source
        local_path, rel_path = _map_remote_to_local(rpath, remote_base, project_root)
        if not should_ignore(local_path, rel_path, config, remote_size=size):
            results.append((local_path, rpath, rel_path))
            if progress is not None:
                progress["files"] = len(results)

    return results


# ---------------------------------------------------------------------------
# Method 2: parallel scan (N connections, BFS)
# ---------------------------------------------------------------------------

def _scan_parallel(client, config, remote_dir, remote_base, project_root):
    """Scan using N parallel connections doing listdir in BFS order.

    Works with all protocols (SFTP, FTP, FTPS).
    Uses the same semaphore-based connection pool pattern as pool.py.

    Probes with a single test connection first — if the server rejects
    extra connections (common on shared FTP hosting), falls through
    immediately instead of spamming N failed attempts.
    """
    max_workers = min(int(config.get("parallel_connections", 4)), 8)
    if max_workers <= 1:
        # Fall through to sequential if only 1 connection allowed
        raise RemoteConnectionError("parallel_connections=1, using sequential")

    # Probe: test ONE extra connection before spinning up workers.
    # Many FTP servers reject concurrent logins — fail fast here.
    probe = create_client(config)
    try:
        probe.connect()
        probe.disconnect()
    except Exception as e:
        raise RemoteConnectionError(
            f"Server rejected extra connection — using sequential ({e})")

    dir_queue = _queue.Queue()
    dir_queue.put(remote_dir)

    results = []
    results_lock = threading.Lock()
    active_count = [1]    # dirs queued but not yet processed
    active_lock = threading.Lock()
    done = threading.Event()
    error_holder = [None]

    # Connection pool (separate from the main persistent connection)
    conn_pool = []
    conn_sem = threading.Semaphore(max_workers)
    conn_lock = threading.Lock()

    def _get_conn():
        conn_sem.acquire()
        with conn_lock:
            if conn_pool:
                return conn_pool.pop()
        c = create_client(config)
        c.connect()
        return c

    def _put_conn(c):
        with conn_lock:
            conn_pool.append(c)
        conn_sem.release()

    def _worker():
        while not done.is_set():
            try:
                rdir = dir_queue.get(timeout=1.0)
            except _queue.Empty:
                # Check if all work is done
                with active_lock:
                    if active_count[0] <= 0:
                        return
                continue

            conn = None
            try:
                conn = _get_conn()
                entries = conn.listdir(rdir)
                _put_conn(conn)
                conn = None

                for entry in entries:
                    rpath = rdir.rstrip("/") + "/" + entry["name"]
                    if entry["is_dir"]:
                        with active_lock:
                            active_count[0] += 1
                        dir_queue.put(rpath)
                    else:
                        local_path, rel_path = _map_remote_to_local(
                            rpath, remote_base, project_root
                        )
                        size = entry.get("size", 0)
                        if not should_ignore(local_path, rel_path, config, remote_size=size):
                            with results_lock:
                                results.append((local_path, rpath, rel_path))
            except Exception as e:
                error_holder[0] = e
                if conn:
                    try:
                        conn.disconnect()
                    except Exception:
                        pass
                    conn_sem.release()
                done.set()
                return
            finally:
                with active_lock:
                    active_count[0] -= 1
                    if active_count[0] <= 0:
                        done.set()

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_worker) for _ in range(max_workers)]
            done.wait()
            # Let workers finish their current iteration
            done.set()
    finally:
        # Cleanup pooled connections
        with conn_lock:
            for c in conn_pool:
                try:
                    c.disconnect()
                except Exception:
                    pass
            conn_pool.clear()

    if error_holder[0]:
        raise error_holder[0]

    return results


# ---------------------------------------------------------------------------
# Method 3: sequential scan (always works — current behavior)
# ---------------------------------------------------------------------------

def _scan_sequential(client, remote_dir, remote_base, project_root, config,
                     progress=None):
    """Scan using recursive listdir — one directory at a time.

    This is the slowest method but always works with any protocol.
    Updates progress dict in real-time so the UI can show live counters.
    """
    results = []

    def _collect(rdir):
        if progress is not None:
            progress["dirs"] += 1
        entries = client.listdir(rdir)
        for entry in entries:
            rpath = rdir.rstrip("/") + "/" + entry["name"]
            if entry["is_dir"]:
                _collect(rpath)
            else:
                local_path, rel_path = _map_remote_to_local(
                    rpath, remote_base, project_root
                )
                size = entry.get("size", 0)
                if not should_ignore(local_path, rel_path, config, remote_size=size):
                    results.append((local_path, rpath, rel_path))
                    if progress is not None:
                        progress["files"] += 1

    _collect(remote_dir)
    return results


# ---------------------------------------------------------------------------
# Main entry point — cascading scan
# ---------------------------------------------------------------------------

def fast_scan(client, config, remote_dir, project_root, window=None,
              progress=None):
    """Scan a remote directory recursively using the fastest available method.

    Tries methods in order of speed: find → rsync → parallel → sequential.
    Remembers which method worked per host for future scans.
    For FTP/FTPS, skips SSH-only methods (find, rsync).

    Args:
        client: Connected SFTPClient or FTPClient.
        config: Config dict from remote-sync-config.json.
        remote_dir: Remote directory to scan.
        project_root: Local project root for path mapping.
        window: Sublime Text window for panel logging.
        progress: Optional dict {"files": 0, "dirs": 0} updated in real-time
                  by scan methods. The UI reads this to show live counters.

    Returns:
        List of (local_path, remote_path, rel_path) tuples.
    """
    host = config.get("host", "unknown")
    conn_type = config.get("type", "sftp").lower()
    is_ftp = conn_type in ("ftp", "ftps")
    remote_base = config.get("remote_path", "/").rstrip("/") or "/"
    scan_timeout = get_timeout(config, "scan")
    # 0 = unlimited → pass None so subprocess.run has no timeout
    cmd_timeout = scan_timeout if scan_timeout > 0 else None

    start_method = _get_start_method(host, is_ftp)

    # Methods ordered fastest → slowest
    methods = [
        ("find", lambda: _scan_find(
            client, remote_dir, remote_base, project_root, config, cmd_timeout,
            progress=progress
        )),
        ("rsync --list-only", lambda: _scan_rsync(
            client, remote_dir, remote_base, project_root, config, cmd_timeout,
            progress=progress
        )),
        ("parallel scan", lambda: _scan_parallel(
            client, config, remote_dir, remote_base, project_root
        )),
        ("sequential scan", lambda: _scan_sequential(
            client, remote_dir, remote_base, project_root, config,
            progress=progress
        )),
    ]

    last_error = None

    for idx in range(start_method, len(methods)):
        name, method_fn = methods[idx]

        # Skip SSH-only methods for FTP
        if is_ftp and idx < 2:
            continue

        try:
            if window:
                panel.log(window, f"Scanning via {name}...")
            results = method_fn()
            # Success — remember this method for next time
            _remember_method(host, idx)
            if window:
                panel.log(window, f"Scan via {name}: found {len(results)} files")
            return results
        except Exception as e:
            last_error = e
            if window:
                # Show which method failed and why, then try next
                next_idx = idx + 1
                if next_idx < len(methods):
                    next_name = methods[next_idx][0]
                    if is_ftp and next_idx < 2:
                        next_name = methods[2][0]
                    panel.log(window,
                              f"Scan via {name} failed: {e} — trying {next_name}...")
                else:
                    panel.log(window,
                              f"Scan via {name} failed: {e}", error=True)

    raise RemoteConnectionError(
        f"All scan methods failed for {host}:{remote_dir}. "
        f"Last error: {last_error}"
    )

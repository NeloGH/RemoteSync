"""Read, validate, and cache remote-sync-config.json files.

Improvements over v1:
  - String-aware comment stripper that preserves URLs inside JSON strings
  - Config validation with clear error messages for missing/invalid fields
  - mtime-based cache to avoid re-reading JSON on every save
"""

import os
import json
import re
import threading

from .errors import ConfigError


CONFIG_FILENAME = "remote-sync-config.json"

# ---------------------------------------------------------------------------
# Config cache — avoids re-reading JSON on every on_post_save_async
# ---------------------------------------------------------------------------

_cache = {}        # config_path → {"mtime": float, "config": dict}
_cache_lock = threading.Lock()


def invalidate_cache(config_path=None):
    """Clear cache for one path or all.  Called when user edits config."""
    with _cache_lock:
        if config_path:
            _cache.pop(config_path, None)
        else:
            _cache.clear()


# ---------------------------------------------------------------------------
# Locate config
# ---------------------------------------------------------------------------

def find_config(file_path, folders=None):
    """Find config by walking up from file_path or checking project folders."""
    if file_path:
        d = os.path.dirname(file_path)
        while d:
            cfg = os.path.join(d, CONFIG_FILENAME)
            if os.path.isfile(cfg):
                return cfg, d
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent

    if folders:
        for folder in folders:
            cfg = os.path.join(folder, CONFIG_FILENAME)
            if os.path.isfile(cfg):
                return cfg, folder

    return None, None


# ---------------------------------------------------------------------------
# JSONC parser (JSON with comments)
# ---------------------------------------------------------------------------

def _strip_json_comments(text):
    """Remove // comments while preserving URLs in strings.

    Walks char-by-char, tracking whether we're inside a double-quoted
    string.  Only strips // that appear outside of strings.
    """
    result = []
    i = 0
    in_string = False
    length = len(text)

    while i < length:
        ch = text[i]
        if in_string:
            result.append(ch)
            if ch == '\\' and i + 1 < length:
                i += 1
                result.append(text[i])
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
                result.append(ch)
            elif ch == '/' and i + 1 < length and text[i + 1] == '/':
                while i < length and text[i] != '\n':
                    i += 1
                continue
            else:
                result.append(ch)
        i += 1
    return ''.join(result)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = ("host", "user", "remote_path")
_VALID_TYPES = ("sftp", "scp", "ftp", "ftps")
_PLACEHOLDER_VALUES = {"example.com", "username", "/path/to/remote/"}


def validate_config(config, config_path=""):
    """Raise ConfigError with a clear message if config is invalid."""
    errors = []

    conn_type = config.get("type", "sftp").lower()
    if conn_type not in _VALID_TYPES:
        errors.append(f'"type" must be one of {_VALID_TYPES}, got "{conn_type}"')

    for field in _REQUIRED_FIELDS:
        val = config.get(field, "")
        if not val or val in _PLACEHOLDER_VALUES:
            errors.append(f'"{field}" is missing or still has the placeholder value')

    port = config.get("port")
    if port is not None:
        try:
            p = int(port)
            if not (1 <= p <= 65535):
                raise ValueError()
        except (ValueError, TypeError):
            errors.append(f'"port" must be 1-65535, got "{port}"')

    # Validate host format
    host = config.get("host", "")
    if host:
        if " " in host:
            errors.append('"host" must not contain spaces')
        if host.startswith(("http://", "https://", "ftp://", "sftp://")):
            errors.append('"host" must be a hostname or IP, not a URL (remove the protocol prefix)')

    # Validate credentials: must have password or ssh_key_file
    password = config.get("password", "")
    ssh_key = config.get("ssh_key_file", "")
    if not password and not ssh_key:
        errors.append('No credentials: set "password" or "ssh_key_file"')

    # Validate ssh_key_file exists
    if ssh_key:
        key_path = os.path.expanduser(ssh_key)
        if not os.path.isfile(key_path):
            errors.append(f'"ssh_key_file" not found: {key_path}')

    for timeout_key in ("connect_timeout", "upload_timeout",
                        "download_timeout", "command_timeout",
                        "scan_timeout"):
        val = config.get(timeout_key)
        if val is not None:
            try:
                t = int(val)
                if t <= 0:
                    raise ValueError()
            except (ValueError, TypeError):
                errors.append(f'"{timeout_key}" must be a positive integer')

    if errors:
        name = os.path.basename(config_path) if config_path else "config"
        raise ConfigError(f"{name}: {'; '.join(errors)}")


# ---------------------------------------------------------------------------
# Load (with cache + validation)
# ---------------------------------------------------------------------------

def load_config(config_path, validate=True):
    """Load and parse config JSON (supports // comments and trailing commas).

    Uses mtime-based cache so repeated calls (e.g. on_post_save) skip
    disk I/O when the file hasn't changed.
    """
    try:
        current_mtime = os.path.getmtime(config_path)
    except OSError:
        raise ConfigError(f"Config file not found: {config_path}")

    with _cache_lock:
        cached = _cache.get(config_path)
        if cached and cached["mtime"] == current_mtime:
            return cached["config"]

    with open(config_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = _strip_json_comments(content)
    content = re.sub(r',\s*([}\]])', r'\1', content)

    try:
        config = json.loads(content)
    except json.JSONDecodeError as e:
        raise ConfigError(f"Invalid JSON in {config_path}: {e}")

    if validate:
        validate_config(config, config_path)

    with _cache_lock:
        _cache[config_path] = {"mtime": current_mtime, "config": config}

    return config


# ---------------------------------------------------------------------------
# Path mapping
# ---------------------------------------------------------------------------

def get_remote_path(config, local_path, project_root):
    """Convert local path to remote path using config."""
    remote_base = config.get("remote_path", "/").rstrip("/")
    rel = os.path.relpath(local_path, project_root).replace("\\", "/")
    return remote_base + "/" + rel


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

def should_ignore(file_path, rel_path, config, remote_size=None):
    """Check if a file should be skipped based on config filters.

    Args:
        file_path: Local file path (may not exist yet during download scans).
        rel_path: Relative path for pattern matching.
        config: Config dict with ignore_regexes, exclude_extensions, max_file_size_mb.
        remote_size: File size in bytes from remote listing. Used when the local
                     file doesn't exist yet (e.g. during download scanning).
    """
    for pattern in config.get("ignore_regexes", []):
        if re.search(pattern, rel_path):
            return True
    for ext in config.get("exclude_extensions", []):
        if rel_path.endswith(ext):
            return True
    max_mb = config.get("max_file_size_mb")
    if max_mb:
        # Use remote_size if provided, otherwise check local file
        if remote_size is not None:
            if remote_size / (1024 * 1024) > max_mb:
                return True
        elif os.path.isfile(file_path):
            if os.path.getsize(file_path) / (1024 * 1024) > max_mb:
                return True
    return False


# ---------------------------------------------------------------------------
# Timeout helpers
# ---------------------------------------------------------------------------

def get_timeout(config, operation="command"):
    """Return the timeout for an operation type.

    Checks operation-specific keys first, falls back to a sensible default.
    operation: "upload" | "download" | "command" | "connect" | "scan"
    """
    key = f"{operation}_timeout"
    val = config.get(key)
    if val is not None:
        return int(val)

    # Defaults per operation type
    # scan=0 means unlimited — only limited if user sets scan_timeout
    defaults = {
        "upload": 120,
        "download": 120,
        "command": 30,
        "scan": 0,
        "connect": int(config.get("connect_timeout", 30)),
    }
    return defaults.get(operation, 60)


# ---------------------------------------------------------------------------
# Default template
# ---------------------------------------------------------------------------

DEFAULT_CONFIG_TEMPLATE = """\
{
    // RemoteSync configuration
    // Tab through the fields to fill in your server details

    // sftp, ftp, ftps or scp
    "type": "sftp",

    "host": "example.com",
    "user": "username",
    //"password": "password",
    //"port": 22,

    "remote_path": "/path/to/remote/",
    "upload_on_save": true,
    //"save_before_upload": true,
    //"confirm_downloads": false,

    //"ssh_key_file": "~/.ssh/id_rsa",
    "connect_timeout": 30,
    //"keepalive": 120,

    //"file_permissions": "664",
    //"dir_permissions": "775",

    //"ftp_passive_mode": true,

    // --- Timeouts (seconds, per operation) ---
    // Large files need more time; quick commands need less
    //"upload_timeout": 120,
    //"download_timeout": 120,
    //"command_timeout": 30,
    //"scan_timeout": 300,  // 0 or commented = unlimited

    // --- RemoteSync exclusive features ---

    // Run a remote command after each upload (e.g. restart services)
    //"post_upload_command": "sudo systemctl reload nginx",

    // Run a local command before each upload (e.g. lint, compile)
    //"pre_upload_command": "npm run build",

    // Skip files larger than this (MB) to avoid accidental uploads
    //"max_file_size_mb": 10,

    // Automatically create remote directories if they don't exist
    "auto_create_dirs": true,

    // Quick way to exclude files by extension (no regex needed)
    //"exclude_extensions": [".log", ".tmp", ".zip", ".gz", ".bak"],

    // Auto-retry failed uploads/downloads
    //"retry_count": 2,

    // Parallel connections for folder uploads/downloads (1-8, default 4)
    //"parallel_connections": 4,

    // Max lines in the output panel before auto-truncation (0 = unlimited)
    //"max_panel_lines": 5000,

    "ignore_regexes": [
        "\\\\.git/", "\\\\.svn/", "\\\\.DS_Store",
        "__pycache__/", "node_modules/",
        "remote-sync-config\\\\.json"
    ]
}
"""


def create_default_config(project_root):
    """Create a default remote-sync-config.json template."""
    path = os.path.join(project_root, CONFIG_FILENAME)
    with open(path, "w", encoding="utf-8") as f:
        f.write(DEFAULT_CONFIG_TEMPLATE)
    return path

"""RemoteSync — Granular exception hierarchy.

Specific error types so the UI can show targeted messages and the retry
logic can decide whether a retry makes sense.
"""


class RemoteSyncError(Exception):
    """Base class for all RemoteSync errors."""
    pass


class RemoteConnectionError(RemoteSyncError):
    """Generic connection error (kept for backwards compat)."""
    pass


class AuthenticationError(RemoteConnectionError):
    """Wrong credentials, key rejected, or SSH agent failure."""
    pass


class ConnectionTimeoutError(RemoteConnectionError):
    """Connection or operation timed out."""
    pass


class ConnectionLostError(RemoteConnectionError):
    """Connection was alive but dropped mid-operation."""
    pass


class PermissionDeniedError(RemoteSyncError):
    """Remote server refused the operation."""
    pass


class HostKeyError(RemoteConnectionError):
    """Remote host key verification failed."""
    pass


class ScanTimeoutError(RemoteSyncError):
    """Remote directory scan took too long."""
    pass


class ConfigError(RemoteSyncError):
    """Invalid or missing configuration."""
    pass


class SFTPOnlyError(RemoteConnectionError):
    """The account allows SFTP file transfer only — no shell commands."""
    pass


# Messages servers print when an account is jailed to SFTP (ForceCommand
# internal-sftp, rssh, scponly, ...). Matched case-insensitively.
_SFTP_ONLY_SIGNATURES = (
    "allows sftp connections only",
    "only sftp",
    "sftp connections only",
    "only allows sftp",
    "this service allows sftp",
)


def is_sftp_only_message(text):
    """Return True if text is a server's 'SFTP only, no shell' rejection."""
    low = (text or "").lower()
    return any(sig in low for sig in _SFTP_ONLY_SIGNATURES)


def classify_ssh_error(stderr_text):
    """Inspect SSH/SCP stderr and return the most specific exception."""
    text = (stderr_text or "").lower()

    if is_sftp_only_message(text):
        return SFTPOnlyError(stderr_text)
    if "permission denied" in text or "authentication" in text:
        return AuthenticationError(stderr_text)
    if "host key verification failed" in text:
        return HostKeyError(stderr_text)
    if "connection timed out" in text or "operation timed out" in text:
        return ConnectionTimeoutError(stderr_text)
    if "connection refused" in text or "no route to host" in text:
        return ConnectionLostError(stderr_text)
    # SSH server rate-limiting (MaxStartups) and dropped handshakes — these are
    # transient: the server momentarily refused a new connection. Worth retrying.
    if ("kex_exchange_identification" in text
            or "connection closed" in text
            or "connection reset" in text
            or "broken pipe" in text):
        return ConnectionLostError(stderr_text)
    if "no such file" in text or "not a regular file" in text:
        return PermissionDeniedError(stderr_text)

    return RemoteConnectionError(stderr_text)


def is_retryable(error):
    """Return True if the error is worth retrying (transient/connection-level)."""
    if isinstance(error, (ConnectionTimeoutError, ConnectionLostError)):
        return True
    # Some errors arrive as plain strings/other exceptions from batch workers;
    # match the transient SSH signatures defensively.
    text = str(error).lower()
    return any(s in text for s in (
        "kex_exchange_identification", "connection closed",
        "connection reset", "broken pipe", "timed out",
    ))


def is_rate_limit(error):
    """Return True if the error looks like server-side connection rate-limiting.

    sshd's MaxStartups drops NEW connections during handshake — the telltale
    signatures are kex/handshake failures and abrupt closes/resets. Used by the
    adaptive limiter to know when to reduce parallel connections (as opposed
    to plain timeouts, which don't necessarily mean "too many connections").
    """
    text = str(error).lower()
    return any(s in text for s in (
        "kex_exchange_identification", "connection closed",
        "connection reset",
    ))


def user_friendly_message(error):
    """Return a clear, user-friendly error message for popup dialogs."""
    if isinstance(error, AuthenticationError):
        return "Invalid login/password specified.\n\nCheck your 'user' and 'password' (or 'ssh_key_file') in remote-sync-config.json."
    if isinstance(error, HostKeyError):
        return "Host key verification failed.\n\nThe server's identity has changed or is not trusted. Remove the old key from known_hosts and try again."
    if isinstance(error, ScanTimeoutError):
        return ("Scan timed out.\n\n"
                "The remote directory has too many files/folders to scan in time.\n\n"
                "Try:\n"
                "• Download a smaller subfolder instead\n"
                "• Increase \"scan_timeout\" in your config\n"
                "• Remove \"scan_timeout\" to scan without time limit")
    if isinstance(error, ConnectionTimeoutError):
        return "Connection timed out.\n\nThe server did not respond. Check that the host and port are correct and that the server is reachable."
    if isinstance(error, ConnectionLostError):
        return "Connection lost.\n\nThe connection was dropped. Check your network or if the server is running."
    if isinstance(error, PermissionDeniedError):
        return "Permission denied.\n\nThe server refused the operation. Check file/directory permissions on the remote server."
    if isinstance(error, ConfigError):
        return f"Configuration error.\n\n{error}"
    if isinstance(error, SFTPOnlyError):
        return ("This account only allows SFTP file transfer (no shell).\n\n"
                "Uploads, downloads and browsing work, but this action needs "
                "a remote shell command, which the server does not allow.")
    if isinstance(error, RemoteConnectionError):
        return f"Connection error.\n\n{error}"
    return str(error)


def is_critical(error):
    """Return True if the error should show a popup dialog to the user."""
    return isinstance(error, (
        AuthenticationError, HostKeyError, ConnectionTimeoutError,
        ConnectionLostError, RemoteConnectionError, ConfigError,
        ScanTimeoutError,
    ))


def is_user_actionable(error):
    """Return True for errors the user MUST fix before anything will work.

    These always warrant an interrupting modal dialog (wrong credentials,
    untrusted host key, broken config). Everything else — dropped/reset
    connections, timeouts, rate-limiting — is transient or environmental:
    it's logged to the output panel and shown in the status bar, but a modal
    per failed file would be overwhelming during a multi-file batch.
    """
    return isinstance(error, (
        AuthenticationError, HostKeyError, ConfigError, ScanTimeoutError,
    ))

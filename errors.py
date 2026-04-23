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


def classify_ssh_error(stderr_text):
    """Inspect SSH/SCP stderr and return the most specific exception."""
    text = (stderr_text or "").lower()

    if "permission denied" in text or "authentication" in text:
        return AuthenticationError(stderr_text)
    if "host key verification failed" in text:
        return HostKeyError(stderr_text)
    if "connection timed out" in text or "operation timed out" in text:
        return ConnectionTimeoutError(stderr_text)
    if "connection refused" in text or "no route to host" in text:
        return ConnectionLostError(stderr_text)
    if "broken pipe" in text or "connection reset" in text:
        return ConnectionLostError(stderr_text)
    if "no such file" in text or "not a regular file" in text:
        return PermissionDeniedError(stderr_text)

    return RemoteConnectionError(stderr_text)


def is_retryable(error):
    """Return True if the error is worth retrying."""
    return isinstance(error, (ConnectionTimeoutError, ConnectionLostError))


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

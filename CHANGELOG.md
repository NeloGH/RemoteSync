# Changelog

## 1.7.0

- **SFTP-only accounts:** accounts jailed to SFTP (`ForceCommand internal-sftp`, chroot) now work. RemoteSync detects that no shell is available and runs every operation over SFTP: browse, upload (creating folders when needed), download, rename, delete, recursive folder delete, new folder, new file and chmod. Folder downloads scan by listing instead of `find`/`rsync`. You can force this mode with `"sftp_only": true`.
- **FTPS:** data connections reuse the control connection's TLS session, which fixes `522 SSL connection failed: session reuse required` on vsftpd (`require_ssl_reuse=YES`) and FileZilla Server.
- **Clearer errors:** when a server reports the failure on stdout, the panel now shows that real reason instead of "Unknown error".
- **FTP:** new folder, new file and chmod from Browse Server now work over FTP/FTPS too (they used to need a shell).
- **Fix:** the in-place progress spinner in the output panel works again (its command was no longer registered after the move to `core/`).
- SSH commands never inherit stdin, so a restricted account can't make them hang.
- New file from Browse Server never truncates an existing file.
- Deleting the remote root `/` is refused.

## 1.6.2

- Concurrent connection failures are retried instead of failing.

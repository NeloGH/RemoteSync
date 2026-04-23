"""Remote file transfer clients using system SSH tools and ftplib.

SFTP/SCP: Uses system OpenSSH commands (ssh, sftp, scp) via subprocess.
FTP/FTPS: Uses Python's built-in ftplib module.

No compiled extensions needed — works inside Sublime Text's embedded Python.

v2 changes:
  - Configurable per-operation timeouts (upload_timeout, download_timeout, etc.)
  - Granular error classification (auth, timeout, permission, host-key)
  - Improved askpass security (atexit + icacls on Windows)
"""

import os
import subprocess
import ftplib
import threading
import tempfile

from .errors import (
    RemoteConnectionError, ConnectionTimeoutError, ConnectionLostError,
    AuthenticationError, classify_ssh_error,
)


def _shell_quote(path):
    """Safely quote a path for remote shell commands."""
    return "'" + path.replace("'", "'\\''") + "'"


def _clean_sftp_error(stderr_text):
    """Extract the meaningful error from SFTP/SSH stderr output.

    Removes noise like connection banners ('Connected to ...') and
    keeps only the actual error lines so users see useful messages.
    """
    if not stderr_text:
        return "Unknown error"
    lines = stderr_text.strip().splitlines()
    # Filter out noise: connection banners, empty lines, warnings
    noise_prefixes = ("connected to ", "warning:", "banner ")
    error_lines = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith(noise_prefixes):
            continue
        error_lines.append(stripped)
    return "\n".join(error_lines) if error_lines else stderr_text.strip()


def _find_ssh_binary(name):
    """Find an SSH binary (ssh, sftp, scp) on the system."""
    win_path = os.path.join(
        os.environ.get("SYSTEMROOT", r"C:\Windows"),
        "System32", "OpenSSH", f"{name}.exe"
    )
    if os.path.isfile(win_path):
        return win_path

    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        for ext in ("", ".exe"):
            full = os.path.join(path_dir, name + ext)
            if os.path.isfile(full):
                return full
    return None


def _convert_ppk_to_openssh(ppk_path):
    """Convert a PuTTY .ppk key file to OpenSSH PEM format.

    Supports PPK v2 and v3 (unencrypted).  Returns the path to the
    converted OpenSSH key file (cached next to the .ppk so conversion
    only happens once).  Returns None if conversion fails.
    """
    openssh_path = ppk_path.rsplit(".", 1)[0] + "_openssh"

    # If already converted and newer than the ppk, reuse it
    if os.path.isfile(openssh_path):
        if os.path.getmtime(openssh_path) >= os.path.getmtime(ppk_path):
            return openssh_path

    try:
        import struct
        import base64

        with open(ppk_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

        # Check it's actually a PPK file
        if not lines or not lines[0].startswith("PuTTY-User-Key-File-"):
            return None

        # Check encryption (only unencrypted keys supported)
        encryption = ""
        for line in lines:
            if line.startswith("Encryption:"):
                encryption = line.split(":", 1)[1].strip()
                break
        if encryption != "none":
            return None  # Encrypted PPK — user must convert manually

        # Extract public key
        pub_count = 0
        pub_start = 0
        for i, line in enumerate(lines):
            if line.startswith("Public-Lines:"):
                pub_count = int(line.split(":")[1].strip())
                pub_start = i + 1
                break
        pub_b64 = "".join(lines[pub_start:pub_start + pub_count])
        pub_bytes = base64.b64decode(pub_b64)

        # Extract private key
        priv_count = 0
        priv_start = 0
        for i, line in enumerate(lines):
            if line.startswith("Private-Lines:"):
                priv_count = int(line.split(":")[1].strip())
                priv_start = i + 1
                break
        priv_b64 = "".join(lines[priv_start:priv_start + priv_count])
        priv_bytes = base64.b64decode(priv_b64)

        # Parse public key — read SSH mpints
        def read_mpint(data, offset):
            length = struct.unpack(">I", data[offset:offset + 4])[0]
            offset += 4
            value = int.from_bytes(data[offset:offset + length], "big")
            return value, offset + length

        offset = 0
        # Skip key type string
        slen = struct.unpack(">I", pub_bytes[offset:offset + 4])[0]
        offset += 4 + slen
        e, offset = read_mpint(pub_bytes, offset)
        n, offset = read_mpint(pub_bytes, offset)

        # Parse private key — d, p, q, iqmp
        offset = 0
        d, offset = read_mpint(priv_bytes, offset)
        p, offset = read_mpint(priv_bytes, offset)
        q, offset = read_mpint(priv_bytes, offset)
        # iqmp is present but we let the library recompute it

        # Build PEM using DER encoding (no external dependencies)
        def int_to_der_integer(n):
            """Encode an integer as DER INTEGER."""
            b = n.to_bytes((n.bit_length() + 8) // 8, "big")
            # Ensure positive (add leading zero if high bit set)
            if b[0] & 0x80:
                b = b"\x00" + b
            return _der_tag(0x02, b)

        def _der_tag(tag, data):
            length = len(data)
            if length < 0x80:
                return bytes([tag, length]) + data
            elif length < 0x100:
                return bytes([tag, 0x81, length]) + data
            else:
                return bytes([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]) + data

        # RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, iqmp }
        dp = d % (p - 1)
        dq = d % (q - 1)
        iqmp = pow(q, -1, p)

        seq_contents = b"".join([
            int_to_der_integer(0),      # version
            int_to_der_integer(n),
            int_to_der_integer(e),
            int_to_der_integer(d),
            int_to_der_integer(p),
            int_to_der_integer(q),
            int_to_der_integer(dp),
            int_to_der_integer(dq),
            int_to_der_integer(iqmp),
        ])
        der = _der_tag(0x30, seq_contents)

        pem_b64 = base64.b64encode(der).decode("ascii")
        pem_lines = [pem_b64[i:i + 64] for i in range(0, len(pem_b64), 64)]
        pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        pem += "\n".join(pem_lines) + "\n"
        pem += "-----END RSA PRIVATE KEY-----\n"

        with open(openssh_path, "w", newline="\n") as f:
            f.write(pem)

        # Restrict permissions (important for OpenSSH)
        if os.name == "nt":
            import subprocess as _sp
            username = os.environ.get("USERNAME", "")
            if username:
                try:
                    _sp.run(
                        ["icacls", openssh_path, "/inheritance:r",
                         "/grant:r", f"{username}:(R)"],
                        capture_output=True, timeout=5,
                        creationflags=_sp.CREATE_NO_WINDOW,
                    )
                except Exception:
                    pass
        else:
            os.chmod(openssh_path, 0o600)

        return openssh_path

    except Exception:
        return None


class SFTPClient:
    """SFTP/SCP client using system OpenSSH commands."""

    def __init__(self, host, port, user, password=None, ssh_key_file=None,
                 connect_timeout=30, file_permissions=None,
                 dir_permissions=None, upload_timeout=120,
                 download_timeout=120, command_timeout=30):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.ssh_key_file = ssh_key_file
        self.connect_timeout = connect_timeout
        self.upload_timeout = upload_timeout
        self.download_timeout = download_timeout
        self.command_timeout = command_timeout
        self.file_permissions = file_permissions
        self.dir_permissions = dir_permissions
        self._sftp_bin = _find_ssh_binary("sftp")
        self._scp_bin = _find_ssh_binary("scp")
        self._ssh_bin = _find_ssh_binary("ssh")
        self._connected = False
        self._lock = threading.Lock()

        if not self._sftp_bin:
            raise RemoteConnectionError(
                "No sftp binary found. Install OpenSSH or Git for Windows."
            )

        # Auto-convert PuTTY .ppk keys to OpenSSH format
        if self.ssh_key_file:
            key_path = os.path.expanduser(self.ssh_key_file)
            if key_path.lower().endswith(".ppk"):
                converted = _convert_ppk_to_openssh(key_path)
                if converted:
                    self.ssh_key_file = converted

    def _ssh_opts(self):
        opts = [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={self.connect_timeout}",
        ]
        if self.ssh_key_file:
            key_path = os.path.expanduser(self.ssh_key_file)
            opts.extend(["-i", key_path])
        if not self.password:
            opts.extend(["-o", "BatchMode=yes"])
        return opts

    def _run_scp(self, args, timeout=None):
        """Run scp with common options."""
        if timeout is None:
            timeout = self.upload_timeout
        cmd = [self._scp_bin] + self._ssh_opts() + ["-P", str(self.port)] + args
        return self._run_cmd(cmd, timeout)

    def _run_sftp_batch(self, commands, timeout=None):
        """Run sftp commands via stdin (avoids -b flag which suppresses password auth)."""
        if timeout is None:
            timeout = self.command_timeout

        cmd = [self._sftp_bin] + self._ssh_opts() + [
            "-P", str(self.port),
            f"{self.user}@{self.host}"
        ]
        input_data = "\n".join(commands) + "\nbye\n"
        result = self._run_cmd(cmd, timeout, input_data=input_data)

        # Without -b flag, sftp may return 0 even on command errors.
        # Check stderr for transfer failures.
        stderr = (result.stderr or "").lower()
        if any(err in stderr for err in [
            "no such file", "not found", "permission denied",
            "failure", "couldn't stat", "cannot access",
        ]):
            error_text = _clean_sftp_error(result.stderr.strip())
            raise classify_ssh_error(error_text)

        return result

    def _run_ssh(self, remote_cmd, timeout=None):
        """Run a command on the remote server via ssh."""
        if timeout is None:
            timeout = self.command_timeout
        cmd = [self._ssh_bin] + self._ssh_opts() + [
            "-p", str(self.port),
            f"{self.user}@{self.host}",
            remote_cmd
        ]
        return self._run_cmd(cmd, timeout)

    def _run_cmd(self, cmd, timeout=60, input_data=None):
        """Execute a subprocess command with granular error handling."""
        askpass_file = None
        try:
            env = os.environ.copy()
            use_askpass = False
            if self.password and not self.ssh_key_file:
                askpass_file = self._create_askpass_script()
                if askpass_file:
                    env["SSH_ASKPASS"] = askpass_file
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = ":0"
                    use_askpass = True

            run_kwargs = dict(
                capture_output=True, text=True, timeout=timeout, env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )

            if input_data is not None:
                run_kwargs["input"] = input_data
            elif use_askpass:
                run_kwargs["stdin"] = subprocess.DEVNULL

            result = subprocess.run(cmd, **run_kwargs)

            if result.returncode != 0:
                error_text = _clean_sftp_error(result.stderr) or result.stdout.strip() or "Unknown error"
                raise classify_ssh_error(error_text)

            return result
        except subprocess.TimeoutExpired:
            raise ConnectionTimeoutError(f"Operation timed out after {timeout}s")
        except FileNotFoundError as e:
            raise RemoteConnectionError(f"SSH tool not found: {e}")
        finally:
            if askpass_file:
                try:
                    os.remove(askpass_file)
                except OSError:
                    pass

    def _create_askpass_script(self):
        """Create a temporary script that outputs the password for SSH_ASKPASS.

        Security: restrictive perms + atexit cleanup as crash safety net.
        """
        if not self.password:
            return None
        try:
            if os.name == 'nt':
                fd, path = tempfile.mkstemp(suffix=".bat", prefix="rs_askpass_")
                safe_pw = self.password
                for ch in ('^', '&', '<', '>', '|', '%', '"'):
                    safe_pw = safe_pw.replace(ch, f'^{ch}')
                with os.fdopen(fd, "w") as f:
                    f.write(f"@echo off\necho {safe_pw}\n")
                try:
                    username = os.environ.get("USERNAME", "")
                    if username:
                        subprocess.run(
                            ["icacls", path, "/inheritance:r",
                             "/grant:r", f"{username}:(R,X)"],
                            capture_output=True, timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                        )
                except Exception:
                    pass
            else:
                fd, path = tempfile.mkstemp(suffix=".sh", prefix="rs_askpass_")
                safe_pw = self.password.replace("'", "'\\''")
                with os.fdopen(fd, "w") as f:
                    f.write(f"#!/bin/sh\necho '{safe_pw}'\n")
                os.chmod(path, 0o700)

            import atexit
            def _cleanup(p=path):
                try:
                    os.remove(p)
                except OSError:
                    pass
            atexit.register(_cleanup)

            return path
        except Exception:
            return None

    def connect(self):
        """Test the connection."""
        with self._lock:
            if self._connected:
                return
            if self._ssh_bin:
                self._run_ssh("echo ok", timeout=self.connect_timeout)
                self._connected = True
            else:
                self._connected = True

    def disconnect(self):
        with self._lock:
            self._connected = False

    def is_connected(self):
        return self._connected

    def upload(self, local_path, remote_path):
        """Upload a file using sftp batch mode."""
        remote_dir = os.path.dirname(remote_path).replace("\\", "/")

        # Create remote directory tree via SSH (mkdir -p needs a shell)
        if self._ssh_bin:
            mkdir_cmd = f"mkdir -p {_shell_quote(remote_dir)}"
            if self.dir_permissions:
                mkdir_cmd += f" && chmod {self.dir_permissions} {_shell_quote(remote_dir)}"
            try:
                self._run_ssh(mkdir_cmd)
            except Exception:
                pass

        # Transfer via sftp batch (avoids SCP quoting issues on Windows)
        local_sftp = local_path.replace("\\", "/")
        batch_cmds = [f'put "{local_sftp}" "{remote_path}"']

        if self.file_permissions:
            batch_cmds.append(f'chmod {self.file_permissions} "{remote_path}"')

        self._run_sftp_batch(batch_cmds, timeout=self.upload_timeout)
        self._connected = True

    def download(self, remote_path, local_path):
        """Download a file using sftp batch mode."""
        local_dir = os.path.dirname(local_path)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)

        local_sftp = local_path.replace("\\", "/")
        self._run_sftp_batch([
            f'get "{remote_path}" "{local_sftp}"'
        ], timeout=self.download_timeout)
        self._connected = True

    def listdir(self, remote_path):
        """List remote directory using ssh ls or sftp."""
        entries = []
        if self._ssh_bin:
            result = self._run_ssh(
                f"LC_ALL=C /bin/ls -la {_shell_quote(remote_path)}"
            )
            entries = self._parse_ls_output(result.stdout, remote_path)
        elif self._sftp_bin:
            result = self._run_sftp_batch([f"ls -la {remote_path}"])
            entries = self._parse_ls_output(result.stdout, remote_path)

        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        self._connected = True
        return entries

    def _parse_ls_output(self, output, remote_path):
        """Parse ls -la output into entry dicts."""
        entries = []
        for line in output.strip().splitlines():
            if line.startswith("total ") or not line.strip():
                continue
            if line.startswith("sftp>"):
                line = line[5:].strip()
                if not line or line.startswith("total "):
                    continue
            parts = line.split()
            if len(parts) < 9:
                continue
            name = " ".join(parts[8:])
            if name in (".", ".."):
                continue
            is_dir = line[0] == "d"
            try:
                size = int(parts[4])
            except (ValueError, IndexError):
                size = 0
            entries.append({
                "name": name, "is_dir": is_dir,
                "size": size, "mtime": 0,
            })
        return entries

    def stat(self, remote_path):
        if self._ssh_bin:
            result = self._run_ssh(f"stat -c '%s %Y %F' {_shell_quote(remote_path)}")
            return result.stdout.strip()
        return None

    def remove(self, remote_path):
        if self._ssh_bin:
            self._run_ssh(f"rm {_shell_quote(remote_path)}")
        elif self._sftp_bin:
            self._run_sftp_batch([f'rm "{remote_path}"'])

    def remove_dir(self, remote_path):
        """Recursively remove a remote directory."""
        if self._ssh_bin:
            self._run_ssh(f"rm -rf {_shell_quote(remote_path)}")
        elif self._sftp_bin:
            self._run_sftp_batch([f'rm "{remote_path}"'])

    def exec_command(self, command, timeout=None):
        """Execute a remote command via SSH. Returns stdout.

        Args:
            command: Shell command to run on the remote server.
            timeout: Override timeout in seconds (defaults to command_timeout).
        """
        if self._ssh_bin:
            result = self._run_ssh(command, timeout=timeout)
            return result.stdout.strip()
        raise RemoteConnectionError("exec_command requires SSH")

    def rename(self, old_path, new_path):
        if self._ssh_bin:
            self._run_ssh(f"mv {_shell_quote(old_path)} {_shell_quote(new_path)}")
        elif self._sftp_bin:
            self._run_sftp_batch([f'rename "{old_path}" "{new_path}"'])


class SCPClient(SFTPClient):
    """SCP client — same implementation as SFTP (both use system OpenSSH)."""
    pass


class FTPClient:
    """FTP/FTPS client using Python's built-in ftplib."""

    def __init__(self, host, port, user, password=None, use_tls=False,
                 connect_timeout=30, passive_mode=True, file_permissions=None,
                 dir_permissions=None, upload_timeout=120,
                 download_timeout=120, command_timeout=30):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password or ""
        self.use_tls = use_tls
        self.connect_timeout = connect_timeout
        self.passive_mode = passive_mode
        self.file_permissions = file_permissions
        self.dir_permissions = dir_permissions
        self.upload_timeout = upload_timeout
        self.download_timeout = download_timeout
        self.command_timeout = command_timeout
        self._ftp = None
        self._lock = threading.RLock()

    def connect(self):
        with self._lock:
            if self._ftp:
                return
            try:
                if self.use_tls:
                    self._ftp = ftplib.FTP_TLS()
                else:
                    self._ftp = ftplib.FTP()
                self._ftp.connect(self.host, self.port, timeout=self.connect_timeout)
                self._ftp.login(self.user, self.password)
                if self.use_tls:
                    self._ftp.prot_p()
                self._ftp.set_pasv(self.passive_mode)
            except ftplib.error_perm as e:
                self._cleanup_ftp()
                err_text = str(e).lower()
                if "530" in str(e) or "login" in err_text or "auth" in err_text:
                    raise AuthenticationError(f"FTP login failed: {e}")
                raise RemoteConnectionError(f"FTP error: {e}")
            except (TimeoutError, OSError) as e:
                self._cleanup_ftp()
                err_text = str(e).lower()
                if "timed out" in err_text or isinstance(e, TimeoutError):
                    raise ConnectionTimeoutError(
                        f"FTP connection timed out after {self.connect_timeout}s — "
                        f"check host '{self.host}' and port {self.port}"
                    )
                if "refused" in err_text or "no route" in err_text:
                    raise ConnectionLostError(f"FTP connection refused: {e}")
                raise RemoteConnectionError(f"FTP connection failed: {e}")
            except Exception as e:
                self._cleanup_ftp()
                raise RemoteConnectionError(f"FTP connection failed: {e}")

    def _cleanup_ftp(self):
        """Clean up FTP object after failed connection (no lock needed, called from connect)."""
        if self._ftp:
            try:
                self._ftp.close()
            except Exception:
                pass
            self._ftp = None

    def disconnect(self):
        with self._lock:
            if self._ftp:
                try:
                    self._ftp.quit()
                except Exception:
                    try:
                        self._ftp.close()
                    except Exception:
                        pass
                self._ftp = None

    def is_connected(self):
        if self._ftp is None:
            return False
        try:
            # Set a short timeout for the NOOP check to avoid hanging
            old_timeout = self._ftp.sock.gettimeout() if self._ftp.sock else None
            if self._ftp.sock:
                self._ftp.sock.settimeout(5)
            self._ftp.voidcmd("NOOP")
            if self._ftp.sock and old_timeout is not None:
                self._ftp.sock.settimeout(old_timeout)
            return True
        except Exception:
            self._cleanup_ftp()
            return False

    def upload(self, local_path, remote_path):
        remote_dir = os.path.dirname(remote_path).replace("\\", "/")
        with self._lock:
            self._ensure_connected()
            self._mkdir_p(remote_dir)
            with open(local_path, "rb") as f:
                self._ftp.storbinary(f"STOR {remote_path}", f)
            if self.file_permissions:
                try:
                    self._ftp.sendcmd(f"SITE CHMOD {self.file_permissions} {remote_path}")
                except Exception:
                    pass

    def download(self, remote_path, local_path):
        local_dir = os.path.dirname(local_path)
        if not os.path.exists(local_dir):
            os.makedirs(local_dir, exist_ok=True)
        with self._lock:
            self._ensure_connected()
            with open(local_path, "wb") as f:
                self._ftp.retrbinary(f"RETR {remote_path}", f.write)

    def listdir(self, remote_path):
        entries = []
        items = []
        with self._lock:
            self._ensure_connected()
            saved_cwd = self._ftp.pwd()
            try:
                self._ftp.cwd(remote_path)
                try:
                    self._ftp.retrlines("MLSD", items.append)
                    entries = self._parse_mlsd(items)
                except ftplib.error_perm:
                    items = []
                    self._ftp.retrlines("LIST", items.append)
                    entries = self._parse_list(items)
            finally:
                try:
                    self._ftp.cwd(saved_cwd)
                except Exception:
                    pass
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        return entries

    def remove(self, remote_path):
        with self._lock:
            self._ensure_connected()
            self._ftp.delete(remote_path)

    def remove_dir(self, remote_path):
        """Recursively remove a remote directory via FTP."""
        self._rmd_recursive(remote_path)

    def _rmd_recursive(self, path):
        """Recursively delete a directory tree via FTP."""
        entries = self.listdir(path)
        for entry in entries:
            child = path.rstrip("/") + "/" + entry["name"]
            if entry.get("is_dir"):
                self.remove_dir(child)
            else:
                with self._lock:
                    self._ftp.delete(child)
        with self._lock:
            self._ftp.rmd(path)

    def rename(self, old_path, new_path):
        with self._lock:
            self._ensure_connected()
            self._ftp.rename(old_path, new_path)

    def exec_command(self, command):
        raise RemoteConnectionError("exec_command is not supported over FTP")

    def _ensure_connected(self):
        if not self.is_connected():
            self.disconnect()
            self.connect()

    def _parse_mlsd(self, items):
        entries = []
        for line in items:
            parts = line.split(";")
            name = parts[-1].strip()
            if name in (".", ".."):
                continue
            facts = {}
            for p in parts[:-1]:
                if "=" in p:
                    k, v = p.split("=", 1)
                    facts[k.strip().lower()] = v.strip()
            is_dir = facts.get("type", "").lower() == "dir"
            size = int(facts.get("size", 0))
            entries.append({"name": name, "is_dir": is_dir, "size": size, "mtime": 0})
        return entries

    def _parse_list(self, items):
        entries = []
        for line in items:
            parts = line.split()
            if len(parts) < 9:
                continue
            name = " ".join(parts[8:])
            if name in (".", ".."):
                continue
            is_dir = line.startswith("d")
            try:
                size = int(parts[4])
            except (ValueError, IndexError):
                size = 0
            entries.append({"name": name, "is_dir": is_dir, "size": size, "mtime": 0})
        return entries

    def _mkdir_p(self, remote_dir):
        """Create remote directory tree, similar to mkdir -p.

        Saves and restores CWD so callers (upload, etc.) are not
        affected by the directory traversal done here.
        """
        if not remote_dir or remote_dir == "/":
            return
        remote_dir = remote_dir.replace("\\", "/").rstrip("/")

        # Save current directory so we can restore it after
        try:
            saved_cwd = self._ftp.pwd()
        except Exception:
            saved_cwd = None

        try:
            parts = remote_dir.split("/")
            current = ""
            for part in parts:
                if not part:
                    current = "/"
                    continue
                current = ("/" + part) if current == "/" else (current + "/" + part)
                try:
                    self._ftp.cwd(current)
                except ftplib.error_perm:
                    # Directory doesn't exist (or can't cd) — try to create it
                    try:
                        self._ftp.mkd(current)
                        if self.dir_permissions:
                            try:
                                self._ftp.sendcmd(f"SITE CHMOD {self.dir_permissions} {current}")
                            except Exception:
                                pass
                    except ftplib.error_perm:
                        # mkd failed — directory may already exist (550 File exists)
                        pass
                    # Always cwd into the directory after mkdir attempt
                    # so subsequent parts are created in the right place
                    try:
                        self._ftp.cwd(current)
                    except ftplib.error_perm:
                        # Can't cd even after mkdir — real permission problem, skip
                        pass
        finally:
            # Restore original CWD so STOR uses correct path context
            if saved_cwd:
                try:
                    self._ftp.cwd(saved_cwd)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_client(config):
    """Factory: create the right client based on config type."""
    from .config import get_timeout

    conn_type = config.get("type", "sftp").lower()
    host = config.get("host", "")
    port = config.get("port", 22 if conn_type in ("sftp", "scp") else 21)
    user = config.get("user", "")
    password = config.get("password", "")
    ssh_key = config.get("ssh_key_file", "")
    timeout = get_timeout(config, "connect")
    file_perms = config.get("file_permissions", "") or None
    dir_perms = config.get("dir_permissions", "") or None

    if conn_type in ("sftp", "scp"):
        return SFTPClient(
            host=host, port=int(port), user=user,
            password=password if password else None,
            ssh_key_file=ssh_key if ssh_key else None,
            connect_timeout=timeout,
            file_permissions=file_perms, dir_permissions=dir_perms,
            upload_timeout=get_timeout(config, "upload"),
            download_timeout=get_timeout(config, "download"),
            command_timeout=get_timeout(config, "command"),
        )
    elif conn_type in ("ftp", "ftps"):
        return FTPClient(
            host=host, port=int(port), user=user, password=password,
            use_tls=(conn_type == "ftps"),
            connect_timeout=timeout,
            passive_mode=config.get("ftp_passive_mode", True),
            file_permissions=file_perms, dir_permissions=dir_perms,
            upload_timeout=get_timeout(config, "upload"),
            download_timeout=get_timeout(config, "download"),
            command_timeout=get_timeout(config, "command"),
        )
    else:
        raise ValueError(f"Unknown connection type: {conn_type}")

"""Remote file transfer clients using system SSH tools and ftplib.

SFTP/SCP: Uses system OpenSSH commands (ssh, sftp, scp) via subprocess.
FTP/FTPS: Uses Python's built-in ftplib module.

No compiled extensions needed — works inside Sublime Text's embedded Python.

v2 changes:
  - Configurable per-operation timeouts (upload_timeout, download_timeout, etc.)
  - Granular error classification (auth, timeout, permission, host-key)
  - Improved askpass security (atexit + icacls on Windows)
"""

import io
import os
import posixpath
import subprocess
import ftplib
import threading
import tempfile

from .errors import (
    RemoteSyncError, RemoteConnectionError, ConnectionTimeoutError,
    ConnectionLostError, AuthenticationError, HostKeyError, SFTPOnlyError,
    classify_ssh_error, is_sftp_only_message,
)


# ===========================================================================
# Minimal AES-256-CBC — pure Python, no external dependencies.
# Used exclusively for decrypting PPK v2 encrypted private key blobs.
# ===========================================================================

_AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

# Inverse S-box (INV_SBOX[SBOX[i]] == i)
_AES_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[_v] = _i
_AES_INV_SBOX = bytes(_AES_INV_SBOX)

# GF(2^8) multiplication tables for InvMixColumns
_MUL2 = bytes(((b << 1) ^ 0x1b) & 0xff if b & 0x80 else (b << 1) for b in range(256))
_MUL4 = bytes(_MUL2[_MUL2[b]] for b in range(256))
_MUL8 = bytes(_MUL2[_MUL4[b]] for b in range(256))
_MUL9  = bytes(_MUL8[b] ^ b                         for b in range(256))
_MUL11 = bytes(_MUL8[b] ^ _MUL2[b] ^ b              for b in range(256))
_MUL13 = bytes(_MUL8[b] ^ _MUL4[b] ^ b              for b in range(256))
_MUL14 = bytes(_MUL8[b] ^ _MUL4[b] ^ _MUL2[b]      for b in range(256))

_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]


def _aes256_key_expand(key):
    """Expand a 32-byte AES-256 key into 15 round keys (each 16 bytes)."""
    w = [key[i:i + 4] for i in range(0, 32, 4)]  # 8 initial words
    for i in range(8, 60):
        t = bytearray(w[i - 1])
        if i % 8 == 0:
            t = bytearray([_AES_SBOX[t[1]], _AES_SBOX[t[2]],
                           _AES_SBOX[t[3]], _AES_SBOX[t[0]]])
            t[0] ^= _AES_RCON[i // 8 - 1]
        elif i % 8 == 4:
            t = bytearray(_AES_SBOX[b] for b in t)
        w.append(bytes(a ^ b for a, b in zip(w[i - 8], t)))
    return [w[4*r] + w[4*r+1] + w[4*r+2] + w[4*r+3] for r in range(15)]


def _aes256_decrypt_block(block, rks):
    """Decrypt one 16-byte AES-256 block with precomputed round keys."""
    s = bytearray(block)
    for i in range(16): s[i] ^= rks[14][i]          # AddRoundKey(14)
    for r in range(13, 0, -1):
        s[1],s[5],s[9],s[13]   = s[13],s[1],s[5],s[9]    # InvShiftRows
        s[2],s[6],s[10],s[14]  = s[10],s[14],s[2],s[6]
        s[3],s[7],s[11],s[15]  = s[7],s[11],s[15],s[3]
        for i in range(16): s[i] = _AES_INV_SBOX[s[i]]    # InvSubBytes
        for i in range(16): s[i] ^= rks[r][i]             # AddRoundKey(r)
        for c in range(4):                                 # InvMixColumns
            i = c * 4
            a, b, cc, d = s[i], s[i+1], s[i+2], s[i+3]
            s[i]   = _MUL14[a] ^ _MUL11[b] ^ _MUL13[cc] ^ _MUL9[d]
            s[i+1] = _MUL9[a]  ^ _MUL14[b] ^ _MUL11[cc] ^ _MUL13[d]
            s[i+2] = _MUL13[a] ^ _MUL9[b]  ^ _MUL14[cc] ^ _MUL11[d]
            s[i+3] = _MUL11[a] ^ _MUL13[b] ^ _MUL9[cc]  ^ _MUL14[d]
    s[1],s[5],s[9],s[13]  = s[13],s[1],s[5],s[9]         # Final InvShiftRows
    s[2],s[6],s[10],s[14] = s[10],s[14],s[2],s[6]
    s[3],s[7],s[11],s[15] = s[7],s[11],s[15],s[3]
    for i in range(16): s[i] = _AES_INV_SBOX[s[i]]        # Final InvSubBytes
    for i in range(16): s[i] ^= rks[0][i]                 # AddRoundKey(0)
    return bytes(s)


def _aes256_cbc_decrypt(key, ciphertext, iv=b'\x00' * 16):
    """Decrypt ciphertext using AES-256-CBC (pure Python)."""
    rks = _aes256_key_expand(key)
    result = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        blk = ciphertext[i:i + 16]
        dec = _aes256_decrypt_block(blk, rks)
        result.extend(x ^ y for x, y in zip(dec, prev))
        prev = blk
    return bytes(result)



def _shell_quote(path):
    """Safely quote a path for remote shell commands."""
    return "'" + path.replace("'", "'\\''") + "'"


def _clean_sftp_error(stderr_text):
    """Extract the meaningful error from SFTP/SSH stderr output.

    Removes noise like connection banners ('Connected to ...') and
    keeps only the actual error lines so users see useful messages.
    """
    if not stderr_text or not stderr_text.strip():
        return ""
    if is_sftp_only_message(stderr_text):
        return ("This account only allows SFTP (no shell access): "
                + stderr_text.strip())
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


def _find_psftp():
    """Find PuTTY's psftp binary — supports .ppk keys natively.

    Checks the Wbond SFTP plugin's bundled binary first (most reliable),
    then common PuTTY install paths, then PATH.
    """
    import shutil
    candidates = [
        # Bundled in the commercial SFTP plugin by Wbond
        os.path.join(os.path.expanduser("~"),
                     r"AppData\Roaming\Sublime Text\Packages\SFTP\bin\psftp.exe"),
        r"C:\Program Files\PuTTY\psftp.exe",
        r"C:\Program Files (x86)\PuTTY\psftp.exe",
        os.path.join(os.path.expanduser("~"),
                     r"AppData\Local\Programs\PuTTY\psftp.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return shutil.which("psftp")


def _fix_key_permissions(key_path):
    """Fix SSH private key file permissions so OpenSSH accepts it.

    OpenSSH refuses keys that are readable by other users.
    On Windows: removes inherited ACLs and grants only the current user read access.
    On Unix: sets 0o600.
    Returns True if permissions were fixed successfully.
    """
    try:
        if os.name == "nt":
            username = os.environ.get("USERNAME", "")
            if not username:
                return False
            result = subprocess.run(
                ["icacls", key_path,
                 "/inheritance:r",
                 "/grant:r", f"{username}:(R)"],
                capture_output=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return result.returncode == 0
        else:
            os.chmod(key_path, 0o600)
            return True
    except Exception:
        return False




def _convert_ppk_v3_encrypted(ppk_path, openssh_path, passphrase):
    """Encrypted PPK v3 keys: explain the one-time manual conversion.

    PPK v3 protects the key with Argon2, which is impractical to run in pure
    Python (~10 min) and we ship no compiled crypto. puttygen's CLI is
    unreliable (some builds open blocking GUI popups), so instead of risking
    a hang we guide the user through a quick, 100%-reliable manual conversion.
    """
    raise RemoteConnectionError(
        "This is an encrypted PPK v3 key, which can't be converted on the fly.\n\n"
        "Convert it once with PuTTYgen (takes ~20 seconds):\n"
        "  1. Open PuTTYgen and load the .ppk file\n"
        "  2. Enter the passphrase when prompted\n"
        "  3. Menu: Conversions -> Export OpenSSH key -> save the file\n"
        "  4. In remote-sync-config.json set:\n"
        "       \"ssh_key_file\": \"<path to the exported file>\"\n"
        "       \"ssh_key_passphrase\": \"<your passphrase>\"\n\n"
        "RemoteSync handles the exported OpenSSH key automatically from then on."
    )


def _ppk_parse_fields(lines):
    """Extract named fields and blob sections from a PPK file's lines."""
    import base64
    fields = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip()] = v.strip()

    def get_blob(count_key):
        count = int(fields.get(count_key, 0))
        start = next((i + 1 for i, l in enumerate(lines)
                      if l.startswith(count_key + ":")), None)
        if start is None:
            return b""
        return base64.b64decode("".join(lines[start:start + count]))

    return fields, get_blob


def _ppk_build_rsa_pem(pub_bytes, priv_bytes):
    """Parse RSA key components from PPK blobs and return an OpenSSH PEM string."""
    import struct

    def read_mpint(data, off):
        ln = struct.unpack(">I", data[off:off + 4])[0]
        return int.from_bytes(data[off + 4:off + 4 + ln], "big"), off + 4 + ln

    def der_tag(tag, data):
        n = len(data)
        if n < 0x80:   return bytes([tag, n]) + data
        if n < 0x100:  return bytes([tag, 0x81, n]) + data
        return bytes([tag, 0x82, n >> 8, n & 0xff]) + data

    def der_int(v):
        b = v.to_bytes((v.bit_length() + 8) // 8, "big")
        if b[0] & 0x80: b = b"\x00" + b
        return der_tag(0x02, b)

    # Public blob: key-type string, e, n
    off = struct.unpack(">I", pub_bytes[:4])[0] + 4   # skip key-type
    e, off = read_mpint(pub_bytes, off)
    n, _   = read_mpint(pub_bytes, off)

    # Private blob: d, p, q, iqmp
    off = 0
    d, off = read_mpint(priv_bytes, off)
    p, off = read_mpint(priv_bytes, off)
    q, off = read_mpint(priv_bytes, off)
    dp, dq, iqmp = d % (p - 1), d % (q - 1), pow(q, -1, p)

    der = der_tag(0x30, b"".join(
        der_int(v) for v in [0, n, e, d, p, q, dp, dq, iqmp]
    ))
    import base64
    b64 = base64.b64encode(der).decode()
    lines = ["-----BEGIN RSA PRIVATE KEY-----"]
    lines += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    lines += ["-----END RSA PRIVATE KEY-----", ""]
    return "\n".join(lines)


def _ppk_write_and_secure(openssh_path, pem):
    """Write PEM to file and set restrictive permissions."""
    with open(openssh_path, "w", newline="\n") as f:
        f.write(pem)
    if os.name == "nt":
        username = os.environ.get("USERNAME", "")
        if username:
            try:
                subprocess.run(
                    ["icacls", openssh_path, "/inheritance:r",
                     "/grant:r", f"{username}:(R)"],
                    capture_output=True, timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            except Exception:
                pass
    else:
        os.chmod(openssh_path, 0o600)


def _convert_ppk_to_openssh(ppk_path, passphrase=None):
    """Convert a PuTTY .ppk key to OpenSSH PEM format.

    PPK v2 unencrypted  → pure Python (no tools needed)
    PPK v2 encrypted    → pure Python AES-256-CBC (no tools needed)
    PPK v3 unencrypted  → pure Python (no tools needed)
    PPK v3 encrypted    → puttygen 0.76+ required

    Converted file is cached next to the .ppk; reused if newer.
    Returns the converted path, or None/raises on failure.
    """
    openssh_path = ppk_path.rsplit(".", 1)[0] + "_openssh"

    if os.path.isfile(openssh_path):
        if os.path.getmtime(openssh_path) >= os.path.getmtime(ppk_path):
            return openssh_path

    try:
        with open(ppk_path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()

        if not lines or not lines[0].startswith("PuTTY-User-Key-File-"):
            return None

        fields, get_blob = _ppk_parse_fields(lines)
        version = 2 if lines[0].startswith("PuTTY-User-Key-File-2") else 3
        key_type = lines[0].split(":", 1)[1].strip() if ":" in lines[0] else ""
        encryption = fields.get("Encryption", "none")

        pub_bytes = get_blob("Public-Lines")

        if encryption == "none":
            priv_bytes = get_blob("Private-Lines")

        elif version == 2:
            # PPK v2 encrypted: SHA1-based KDF + AES-256-CBC, pure Python
            import hashlib
            pw = passphrase.encode("utf-8") if passphrase else b""
            aes_key = (hashlib.sha1(b"\x00\x00\x00\x00" + pw).digest() +
                       hashlib.sha1(b"\x00\x00\x00\x01" + pw).digest())[:32]
            priv_bytes = _aes256_cbc_decrypt(aes_key, get_blob("Private-Lines"))

        else:
            # PPK v3 encrypted: Argon2 KDF — impractical in pure Python.
            # Delegate to puttygen 0.76+ (handled with version check, no GUI).
            return _convert_ppk_v3_encrypted(ppk_path, openssh_path, passphrase)

        if key_type != "ssh-rsa":
            # Only RSA is supported by the pure-Python path; other key types
            # (ed25519, ecdsa) need puttygen for non-encrypted PPKs too.
            if encryption != "none":
                return _convert_ppk_v3_encrypted(ppk_path, openssh_path, passphrase)
            return None

        pem = _ppk_build_rsa_pem(pub_bytes, priv_bytes)
        _ppk_write_and_secure(openssh_path, pem)
        return openssh_path

    except RemoteConnectionError:
        # Clear, actionable errors (e.g. PPK v3 instructions) must reach the user.
        raise
    except Exception:
        return None


# Accounts already found to be SFTP-only, keyed by (host, port, user), so
# every new connection (parallel workers, scans) skips the failing shell probe.
_SFTP_ONLY_ACCOUNTS = set()
_SFTP_ONLY_LOCK = threading.Lock()


class SFTPClient:
    """SFTP/SCP client using system OpenSSH commands."""

    def __init__(self, host, port, user, password=None, ssh_key_file=None,
                 ssh_key_passphrase=None,
                 connect_timeout=30, file_permissions=None,
                 dir_permissions=None, upload_timeout=120,
                 download_timeout=120, command_timeout=30, sftp_only=False):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.ssh_key_file = ssh_key_file
        self.ssh_key_passphrase = ssh_key_passphrase
        self.connect_timeout = connect_timeout
        self.upload_timeout = upload_timeout
        self.download_timeout = download_timeout
        self.command_timeout = command_timeout
        self.file_permissions = file_permissions
        self.dir_permissions = dir_permissions
        self._sftp_bin = _find_ssh_binary("sftp")
        self._scp_bin = _find_ssh_binary("scp")
        self._ssh_bin = _find_ssh_binary("ssh")
        self._psftp_bin = _find_psftp()   # PuTTY sftp — reads .ppk natively
        self._use_psftp = False            # activated when key is .ppk and psftp available
        self._connected = False
        self._lock = threading.Lock()
        with _SFTP_ONLY_LOCK:
            known = (self.host, self.port, self.user) in _SFTP_ONLY_ACCOUNTS
        # True when the account has no shell (forced or detected on connect)
        self._sftp_only = bool(sftp_only) or known
        # Login already proven for this account in this session — skip probe
        self._login_verified = known

        if not self._sftp_bin:
            raise RemoteConnectionError(
                "No sftp binary found. Install OpenSSH or Git for Windows."
            )

        self._temp_key = None  # temp unencrypted key, cleaned up on disconnect

        # Handle .ppk key files.
        # Priority: pure-Python conversion (v2) > psftp native PPK support > error.
        if self.ssh_key_file:
            key_path = os.path.expanduser(self.ssh_key_file)
            if key_path.lower().endswith(".ppk"):
                converted = _convert_ppk_to_openssh(key_path, self.ssh_key_passphrase)
                if converted:
                    # PPK converted to OpenSSH — use with standard sftp
                    self.ssh_key_file = converted
                    self.ssh_key_passphrase = None
                    key_path = converted
                elif self._psftp_bin:
                    # Cannot convert (e.g. PPK v3 encrypted) but psftp can
                    # read .ppk natively — switch to psftp transport.
                    self._use_psftp = True
                else:
                    raise RemoteConnectionError(
                        f"Cannot use PPK key '{os.path.basename(key_path)}' directly.\n"
                        "Convert it first: PuTTYgen → Conversions → Export OpenSSH key,\n"
                        "then set 'ssh_key_file' to the exported path and\n"
                        "'ssh_key_passphrase' to the passphrase (if the key is protected)."
                    )

            # For encrypted OpenSSH keys: use ssh-keygen to create a temp
            # unencrypted copy — more reliable than SSH_ASKPASS on Windows.
            if self.ssh_key_passphrase:
                temp = self._strip_key_passphrase(key_path, self.ssh_key_passphrase)
                if temp:
                    self._temp_key = temp
                    self.ssh_key_file = temp
                    self.ssh_key_passphrase = None
                    key_path = temp

            # Pre-emptively fix permissions so OpenSSH doesn't reject the key
            _fix_key_permissions(key_path)

    def _ssh_opts(self):
        opts = [
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={self.connect_timeout}",
        ]
        if self.ssh_key_file:
            key_path = os.path.expanduser(self.ssh_key_file)
            opts.extend(["-i", key_path])
        if not self.password and not self.ssh_key_passphrase:
            opts.extend(["-o", "BatchMode=yes"])
        return opts

    def _psftp_opts(self):
        """Build psftp command-line options (PuTTY SFTP client)."""
        opts = ["-batch"]
        if self.ssh_key_file:
            opts.extend(["-i", os.path.expanduser(self.ssh_key_file)])
        if self.password:
            opts.extend(["-pw", self.password])
        elif self.ssh_key_passphrase:
            # psftp doesn't support SSH_ASKPASS; passphrase via -pw works for
            # key passphrase in some psftp versions, otherwise Pageant is needed.
            opts.extend(["-pw", self.ssh_key_passphrase])
        if self.port != 22:
            opts.extend(["-P", str(self.port)])
        return opts

    def _run_psftp_batch(self, commands, timeout=None, check_errors=True):
        """Run SFTP commands via psftp (PuTTY). Used when key is .ppk."""
        if timeout is None:
            timeout = self.command_timeout
        cmd = [self._psftp_bin] + self._psftp_opts() + [
            f"{self.user}@{self.host}"
        ]
        # psftp has no '-' (ignore-error) prefix; strip it, rely on check_errors
        commands = [c[1:] if c.startswith("-") else c for c in commands]
        input_data = "\n".join(commands) + "\nbye\n"
        result = self._run_cmd(cmd, timeout, input_data=input_data)
        stderr = (result.stderr or "").lower()
        if check_errors and any(err in stderr for err in [
            "no such file", "not found", "permission denied",
            "failure", "couldn't stat", "cannot access",
        ]):
            error_text = _clean_sftp_error(result.stderr.strip())
            raise classify_ssh_error(error_text)
        return result

    def _run_scp(self, args, timeout=None):
        """Run scp with common options."""
        if timeout is None:
            timeout = self.upload_timeout
        cmd = [self._scp_bin] + self._ssh_opts() + ["-P", str(self.port)] + args
        return self._run_cmd(cmd, timeout)

    def _run_sftp_batch(self, commands, timeout=None, check_errors=True):
        """Run sftp commands — uses psftp if key is .ppk, otherwise OpenSSH sftp."""
        if self._use_psftp:
            return self._run_psftp_batch(commands, timeout, check_errors)

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
        if check_errors and any(err in stderr for err in [
            "no such file", "not found", "permission denied",
            "failure", "couldn't stat", "cannot access",
        ]):
            error_text = _clean_sftp_error(result.stderr.strip())
            raise classify_ssh_error(error_text)

        return result

    def _run_ssh(self, remote_cmd, timeout=None):
        """Run a command on the remote server via ssh."""
        if self._sftp_only:
            raise SFTPOnlyError(
                "This account only allows SFTP (no shell access); "
                "this action needs a remote shell command.")
        if timeout is None:
            timeout = self.command_timeout
        cmd = [self._ssh_bin] + self._ssh_opts() + [
            "-p", str(self.port),
            f"{self.user}@{self.host}",
            remote_cmd
        ]
        try:
            return self._run_cmd(cmd, timeout)
        except SFTPOnlyError:
            self._mark_sftp_only()
            raise

    def has_shell(self):
        """True if remote shell commands can be used (ssh present, not jailed)."""
        return bool(self._ssh_bin) and not self._sftp_only

    def _mark_sftp_only(self):
        """Switch this account to SFTP-only mode and remember it per host."""
        self._sftp_only = True
        with _SFTP_ONLY_LOCK:
            _SFTP_ONLY_ACCOUNTS.add((self.host, self.port, self.user))

    def _shell_or_sftp(self, shell_fn, sftp_fn):
        """Run shell_fn when a shell is usable, else (or if rejected) sftp_fn."""
        if self.has_shell():
            try:
                return shell_fn()
            except SFTPOnlyError:
                pass
        return sftp_fn()

    def keepalive(self):
        """Cheap liveness ping; SFTP-only sessions are per-command, so no-op."""
        if self.has_shell():
            self._run_ssh("echo keepalive", timeout=10)

    def _run_cmd(self, cmd, timeout=60, input_data=None):
        """Execute a subprocess command with granular error handling."""
        askpass_file = None
        try:
            env = os.environ.copy()
            if self.ssh_key_passphrase:
                # Passphrase-protected key: provide passphrase via SSH_ASKPASS
                askpass_file = self._create_askpass_script(self.ssh_key_passphrase)
                if askpass_file:
                    env["SSH_ASKPASS"] = askpass_file
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = ":0"
            elif self.password and not self.ssh_key_file:
                # Password auth: provide password via SSH_ASKPASS
                askpass_file = self._create_askpass_script(self.password)
                if askpass_file:
                    env["SSH_ASKPASS"] = askpass_file
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = ":0"

            run_kwargs = dict(
                capture_output=True, text=True, timeout=timeout, env=env,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
            )

            if input_data is not None:
                run_kwargs["input"] = input_data
            else:
                # Never inherit stdin: a jailed account (ForceCommand
                # internal-sftp) would otherwise wait on it forever.
                run_kwargs["stdin"] = subprocess.DEVNULL

            result = subprocess.run(cmd, **run_kwargs)

            if result.returncode != 0:
                stderr = result.stderr or ""
                # Auto-fix key permissions and retry (OpenSSH rejects world-readable keys)
                if self.ssh_key_file and (
                    "bad permissions" in stderr.lower() or
                    "unprotected private key" in stderr.lower()
                ):
                    key_path = os.path.expanduser(self.ssh_key_file)
                    if _fix_key_permissions(key_path):
                        result = subprocess.run(cmd, **run_kwargs)
                        if result.returncode == 0:
                            return result
                        stderr = result.stderr or ""

                # Some servers print the real reason on stdout (e.g. jailed
                # SFTP accounts), so fall back to it before "Unknown error".
                error_text = (_clean_sftp_error(stderr)
                              or _clean_sftp_error(result.stdout)
                              or "Unknown error")
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

    def _create_askpass_script(self, secret):
        """Create a temporary script that outputs secret for SSH_ASKPASS.

        Used for both passwords and key passphrases.
        Security: restrictive perms + atexit cleanup as crash safety net.
        """
        if not secret:
            return None
        try:
            if os.name == 'nt':
                fd, path = tempfile.mkstemp(suffix=".bat", prefix="rs_askpass_")
                safe_pw = secret
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
                safe_pw = secret.replace("'", "'\\''")
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
        """Verify login; detect accounts that allow SFTP but no shell."""
        with self._lock:
            if self._connected:
                return
            if self.has_shell():
                try:
                    out = self._run_ssh("echo ok", timeout=self.connect_timeout)
                    # Any line == "ok" (shells may print extra rc-file output)
                    if "ok" in (ln.strip() for ln in out.stdout.splitlines()):
                        self._connected = True
                        return
                except (AuthenticationError, HostKeyError,
                        ConnectionTimeoutError, ConnectionLostError):
                    raise
                except RemoteConnectionError:
                    pass  # shell refused (jail, nologin) — probe plain SFTP
            # SFTP probe: proves the login works even without a shell. Skipped
            # for accounts already verified this session (parallel workers).
            if not self._login_verified:
                self._run_sftp_batch(["pwd"], timeout=self.connect_timeout)
            if self._ssh_bin and not self._sftp_only:
                self._mark_sftp_only()
            self._connected = True

    def _strip_key_passphrase(self, key_path, passphrase):
        """Create a temp unencrypted copy of an encrypted OpenSSH key.

        Uses ssh-keygen -p to remove the passphrase. The temp file is
        tracked in self._temp_key and deleted on disconnect().
        Returns the temp path on success, or None if ssh-keygen fails.
        """
        import tempfile, shutil
        ssh_keygen = _find_ssh_binary("ssh-keygen")
        if not ssh_keygen:
            return None
        fd, temp_path = tempfile.mkstemp(prefix="rs_key_")
        os.close(fd)
        try:
            shutil.copy2(key_path, temp_path)
            _fix_key_permissions(temp_path)
            result = subprocess.run(
                [ssh_keygen, "-p",
                 "-P", passphrase,
                 "-N", "",
                 "-f", temp_path],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if result.returncode == 0:
                _fix_key_permissions(temp_path)
                return temp_path
        except Exception:
            pass
        try:
            os.remove(temp_path)
        except OSError:
            pass
        return None

    def disconnect(self):
        with self._lock:
            self._connected = False
        # Clean up temp unencrypted key if we created one
        if self._temp_key:
            try:
                os.remove(self._temp_key)
            except OSError:
                pass
            self._temp_key = None

    def is_connected(self):
        return self._connected

    def upload(self, local_path, remote_path):
        """Upload a file using sftp batch mode."""
        remote_dir = os.path.dirname(remote_path).replace("\\", "/")
        local_sftp = local_path.replace("\\", "/")
        batch_cmds = [f'put "{local_sftp}" "{remote_path}"']
        if self.file_permissions:
            batch_cmds.append(f'chmod {self.file_permissions} "{remote_path}"')

        # Create remote directory tree via SSH (mkdir -p needs a shell)
        if self.has_shell():
            mkdir_cmd = f"mkdir -p {_shell_quote(remote_dir)}"
            if self.dir_permissions:
                mkdir_cmd += f" && chmod {self.dir_permissions} {_shell_quote(remote_dir)}"
            try:
                self._run_ssh(mkdir_cmd)
            except Exception:
                pass

        if self.has_shell():
            # Transfer via sftp batch (avoids SCP quoting issues on Windows)
            self._run_sftp_batch(batch_cmds, timeout=self.upload_timeout)
        else:
            # No shell: try the put first (the folder usually exists) and
            # only build the directory tree when the server says it's missing.
            try:
                self._run_sftp_batch(batch_cmds, timeout=self.upload_timeout)
            except RemoteSyncError as e:
                if "no such file" not in str(e).lower():
                    raise
                self._sftp_mkdir_p(remote_dir, self.dir_permissions)
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
        """List a remote directory via ssh ls, or via sftp when there's no shell."""
        def _shell():
            result = self._run_ssh(
                f"LC_ALL=C /bin/ls -la {_shell_quote(remote_path)}"
            )
            return self._parse_ls_output(result.stdout, remote_path)

        def _sftp():
            result = self._run_sftp_batch([self._sftp_ls_cmd(remote_path)])
            return self._parse_ls_output(result.stdout, remote_path)

        entries = self._shell_or_sftp(_shell, _sftp)
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        self._connected = True
        return entries

    def _sftp_ls_cmd(self, remote_path):
        """Long-listing command for the active sftp client (psftp has no flags)."""
        if self._use_psftp:
            return f'ls "{remote_path}"'
        return f'ls -la "{remote_path}"'

    def _parse_ls_output(self, output, remote_path):
        """Parse ls -la / sftp ls -la / psftp ls output into entry dicts."""
        entries = []
        for line in output.strip().splitlines():
            if line.startswith("total ") or not line.strip():
                continue
            if line.startswith("sftp>") or line.startswith("psftp>"):
                line = line.split(">", 1)[1].strip()
                if not line or line.startswith("total "):
                    continue
            parts = line.split()
            if len(parts) < 9 or len(parts[0]) < 10:
                continue  # banners like "Listing directory /x" or the echoed command
            name = " ".join(parts[8:])
            if line[0] == "l" and " -> " in name:
                name = name.split(" -> ", 1)[0]
            if "/" in name:
                # sftp may print entries with the listed path as prefix
                name = name.rstrip("/").rsplit("/", 1)[-1]
            if name in (".", "..", ""):
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

    def _find_entry(self, remote_path):
        """Return the listing entry for remote_path from its parent, or None."""
        parent, name = posixpath.split(remote_path.rstrip("/"))
        for entry in self.listdir(parent or "/"):
            if entry["name"] == name:
                return entry
        return None

    def stat(self, remote_path):
        """Return 'size mtime type' for a remote path (mtime 0 without a shell)."""
        def _shell():
            result = self._run_ssh(f"stat -c '%s %Y %F' {_shell_quote(remote_path)}")
            return result.stdout.strip()

        def _sftp():
            entry = self._find_entry(remote_path)
            if entry is None:
                return None
            kind = "directory" if entry["is_dir"] else "regular file"
            return f"{entry['size']} 0 {kind}"

        return self._shell_or_sftp(_shell, _sftp)

    def remove(self, remote_path):
        """Delete a remote file."""
        self._shell_or_sftp(
            lambda: self._run_ssh(f"rm {_shell_quote(remote_path)}"),
            lambda: self._run_sftp_batch([f'rm "{remote_path}"']),
        )

    def remove_dir(self, remote_path):
        """Recursively remove a remote directory."""
        if not remote_path.strip().rstrip("/"):
            raise RemoteConnectionError("Refusing to delete the remote root '/'")
        self._shell_or_sftp(
            lambda: self._run_ssh(f"rm -rf {_shell_quote(remote_path)}"),
            lambda: self._sftp_rmtree(remote_path),
        )

    def _sftp_rmtree(self, remote_path):
        """Delete a tree over SFTP: list it, remove files, then dirs bottom-up."""
        files, dirs = [], []

        def _walk(rdir):
            dirs.append(rdir)
            for entry in self.listdir(rdir):
                child = rdir.rstrip("/") + "/" + entry["name"]
                if entry["is_dir"]:
                    _walk(child)
                else:
                    files.append(child)

        _walk(remote_path.rstrip("/"))
        cmds = [f'rm "{f}"' for f in files] + [f'rmdir "{d}"' for d in reversed(dirs)]
        self._run_sftp_batch(cmds, timeout=self.command_timeout + len(cmds))

    def _sftp_mkdir_p(self, remote_dir, perms=None):
        """Create remote_dir and its parents over SFTP ('-' ignores 'exists')."""
        remote_dir = remote_dir.replace("\\", "/").rstrip("/")
        if not remote_dir:
            return
        prefix = "/" if remote_dir.startswith("/") else ""
        levels, current = [], ""
        for part in remote_dir.split("/"):
            if not part:
                continue
            current = (current + "/" + part) if current else (prefix + part)
            levels.append(current)
        cmds = [f'-mkdir "{level}"' for level in levels]
        if perms:
            cmds.append(f'-chmod {perms} "{remote_dir}"')
        self._run_sftp_batch(cmds, check_errors=False)

    def mkdir(self, remote_path):
        """Create a remote directory and any missing parents (mkdir -p)."""
        self._shell_or_sftp(
            lambda: self._run_ssh(f"mkdir -p {_shell_quote(remote_path)}"),
            lambda: self._sftp_mkdir_p(remote_path),
        )

    def touch(self, remote_path):
        """Create an empty remote file; never truncates an existing one."""
        def _sftp():
            if self._find_entry(remote_path) is not None:
                return
            fd, tmp = tempfile.mkstemp(prefix="rs_touch_")
            os.close(fd)
            try:
                tmp_sftp = tmp.replace("\\", "/")
                self._run_sftp_batch([f'put "{tmp_sftp}" "{remote_path}"'],
                                     timeout=self.upload_timeout)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

        self._shell_or_sftp(
            lambda: self._run_ssh(f"touch {_shell_quote(remote_path)}"),
            _sftp,
        )

    def chmod(self, remote_path, perms):
        """Change permissions of a remote path (octal string like '644')."""
        self._shell_or_sftp(
            lambda: self._run_ssh(f"chmod {perms} {_shell_quote(remote_path)}"),
            lambda: self._run_sftp_batch([f'chmod {perms} "{remote_path}"']),
        )

    def exec_command(self, command, timeout=None):
        """Run a remote shell command via SSH and return its stdout."""
        if not self._ssh_bin:
            raise RemoteConnectionError("exec_command requires SSH")
        return self._run_ssh(command, timeout=timeout).stdout.strip()

    def rename(self, old_path, new_path):
        """Rename or move a remote path."""
        self._shell_or_sftp(
            lambda: self._run_ssh(f"mv {_shell_quote(old_path)} {_shell_quote(new_path)}"),
            lambda: self._run_sftp_batch([f'rename "{old_path}" "{new_path}"']),
        )


class SCPClient(SFTPClient):
    """SCP client — same implementation as SFTP (both use system OpenSSH)."""
    pass


class _ReusedSessionFTP_TLS(ftplib.FTP_TLS):
    """FTP_TLS that reuses the control channel's TLS session on data channels."""

    def ntransfercmd(self, cmd, rest=None):
        """Open the data connection, resuming the control TLS session.

        Servers with vsftpd require_ssl_reuse=YES (and FileZilla Server)
        reject a fresh TLS handshake on the data channel with
        "522 SSL connection failed: session reuse required".
        """
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        if self._prot_p:
            conn = self.context.wrap_socket(
                conn, server_hostname=self.host, session=self.sock.session)
        return conn, size


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
                    self._ftp = _ReusedSessionFTP_TLS()
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

    def has_shell(self):
        """FTP never offers remote shell commands."""
        return False

    def mkdir(self, remote_path):
        """Create a remote directory and any missing parents."""
        with self._lock:
            self._ensure_connected()
            self._mkdir_p(remote_path)

    def touch(self, remote_path):
        """Create an empty remote file; never truncates an existing one."""
        parent, name = posixpath.split(remote_path.rstrip("/"))
        if any(e["name"] == name for e in self.listdir(parent or "/")):
            return
        with self._lock:
            self._ensure_connected()
            self._ftp.storbinary(f"STOR {remote_path}", io.BytesIO(b""))

    def chmod(self, remote_path, perms):
        """Change permissions via SITE CHMOD (server must support it)."""
        with self._lock:
            self._ensure_connected()
            self._ftp.sendcmd(f"SITE CHMOD {perms} {remote_path}")

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
    ssh_key_passphrase = config.get("ssh_key_passphrase", "")
    timeout = get_timeout(config, "connect")
    file_perms = config.get("file_permissions", "") or None
    dir_perms = config.get("dir_permissions", "") or None

    if conn_type in ("sftp", "scp"):
        return SFTPClient(
            host=host, port=int(port), user=user,
            password=password if password else None,
            ssh_key_file=ssh_key if ssh_key else None,
            ssh_key_passphrase=ssh_key_passphrase if ssh_key_passphrase else None,
            sftp_only=bool(config.get("sftp_only", False)),
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

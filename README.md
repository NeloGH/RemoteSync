# RemoteSync

A Sublime Text 4 plugin for syncing files to remote servers via **SFTP, FTP, FTPS, and SCP**.

## Features

- Upload on save — files sync automatically when you hit Ctrl+S
- Batch upload/download entire folders with parallel connections
- Interactive remote file browser
- Diff local vs remote file before overwriting
- Multiple configs — one per subfolder, each with its own server
- Run commands on the server after each upload (e.g. `sudo systemctl reload nginx`)
- Run local commands before upload (e.g. `npm run build`)
- Connection pooling with keepalive — no reconnect on every save
- Output panel with animated progress, auto-hides after operations finish
- JSON config with comment support (`// comments` allowed)
- Auto-converts PuTTY `.ppk` keys to OpenSSH format

## Installation

### Via Package Control (recommended)
1. Open the Command Palette: `Ctrl+Shift+P`
2. Run **Package Control: Install Package**
3. Search for **RemoteSync** and install

### Manual
Clone or download this repo into your Sublime Text `Packages/` folder:
```
Packages/RemoteSync/
```

## Requirements

- Sublime Text 4
- OpenSSH (`sftp`, `scp`, `ssh`) — included on macOS/Linux; on Windows install [Git for Windows](https://git-scm.com/download/win) or enable the optional OpenSSH feature

## Setup

Right-click any folder in the sidebar and select **RemoteSync → Setup Remote Server...**

A `remote-sync-config.json` file will be created. Fill in your server details:

```json
{
    "type": "sftp",
    "host": "your-server.com",
    "user": "username",
    "password": "password",
    "remote_path": "/var/www/mysite/",
    "upload_on_save": true
}
```

### Multiple servers
Place a separate `remote-sync-config.json` in each subfolder. Files will automatically use the nearest config when saved.

## Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `type` | `sftp` | Protocol: `sftp`, `ftp`, `ftps`, `scp` |
| `host` | — | Server hostname or IP |
| `user` | — | Login username |
| `password` | — | Login password (or use `ssh_key_file`) |
| `ssh_key_file` | — | Path to private key (`~/.ssh/id_rsa`) |
| `port` | `22` | Server port |
| `remote_path` | — | Base remote directory |
| `upload_on_save` | `false` | Auto-upload on every save |
| `auto_create_dirs` | `false` | Create remote dirs if missing |
| `parallel_connections` | `4` | Workers for folder operations (1–8) |
| `retry_count` | `0` | Auto-retry failed transfers |
| `keepalive` | `0` | Seconds between keepalive pings |
| `pre_upload_command` | — | Local command before upload |
| `post_upload_command` | — | Remote command after upload |
| `ignore_regexes` | `[]` | Patterns to skip (e.g. `"\\.git/"`) |
| `exclude_extensions` | `[]` | Extensions to skip (e.g. `".log"`) |
| `max_file_size_mb` | — | Skip files larger than this |

## Plugin Settings

Open via **Preferences → Package Settings → RemoteSync → Settings**:

```json
{
    "show_panel_on_error": true,
    "auto_hide_panel": 4,
    "log_operations": true
}
```

- `auto_hide_panel` — seconds before the output panel closes after success (`0` = never hide)

## Commands

All commands are available via:
- **Right-click** on files/folders in the sidebar
- **Command Palette** (`Ctrl+Shift+P`) — search "RemoteSync"

| Command | Description |
|---------|-------------|
| Upload File | Upload current file |
| Download File | Download current file from server |
| Upload Folder | Batch upload entire folder |
| Download Folder | Batch download entire folder |
| Browse Server | Interactive remote file browser |
| Diff with Remote | Compare local vs remote |
| Rename Local and Remote | Rename on both sides |
| Delete Local and Remote | Delete on both sides |
| Setup Remote Server | Create config for selected folder |
| Edit Server Config | Open config for selected path |

## License

MIT

# ServerDedupe

A self-hosted, web-based duplicate file finder designed for servers and NAS devices.

It runs in Docker alongside your files, scanning them in place without transferring data across the network. You can review, manage, and clean up duplicate files from any web browser.

The application was developed and is used daily on a Synology DS223j with 6 GB of memory, but it's not Synology-dependent. It runs anywhere Docker is supported.

<b>The real advantage is performance:</b> powerful duplicate detection and management tools run directly on the NAS or server, eliminating unnecessary network transfers and latency. More available memory generally means better performance, especially when scanning large file collections.

## Features

- **Scan types:** regular files, photos, videos, audio, empty folders, a video health check, and a large-files finder.
- **Match methods:** exact content (SHA-256), same name / name + size, similar photos (resized, re-saved, converted, optionally mirrored or rotated),
  similar videos (frame matching, ignores resolution, format and bitrate, optionally mirrored), same audio recording (fingerprint), same tags.
- **Health check:** finds videos that are unreadable, cut off, or blank/black for a set time at the end or in the middle.
- **Review tools:** side-by-side compare of photos, videos and PDFs; "why it matched"; resolution, bitrate, megapixels and date details; keyboard-driven viewer;
  auto-select rules (newest, oldest, highest resolution, largest, copy in a chosen folder...); protected folders.
- **Safe by design:** scans are read-only, removal goes to a restorable quarantine, every action re-checks the file first, and the last copy is never removed.
- **Large files:** list the biggest files biggest-first, then remove, move, or compress them to 7z or zip (tested before the original is quarantined).
- **Scheduled jobs**, a permanent **ignore list**, hash cache (re-scans only read new or changed files), hardlink replacement, move, CSV export.

## Quick start

Requires Docker with Compose.

```bash
git clone https://github.com/bcwilly/serverdedupe.git
cd serverdedupe
# 1. edit docker-compose.yml (see below), then:
docker compose up -d --build
```

Open `http://<server-address>:5081`.

Before starting, open `docker-compose.yml` and set:
- **The folder to scan:** the last line under `volumes:`. Replace `/path/to/your/files` with your own folder.
- **Your time zone:** `TZ`, for scheduled jobs (for example `America/New_York`).
- **The port:** see below.

### Changing the port

The default web address uses port **5081**. In `docker-compose.yml`, find:

```yaml
ports:
  - "5081:5070"
```

Change only the **left** number to the port you want, for example `"8080:5070"`, then open `http://<server-address>:8080`. Leave the right number (`5070`) alone: that is the port inside the container. If the app doesn't start, another program is probably already using that port, so pick a different one.

After changing it, apply it with `docker compose up -d` (on Synology, Stop and Start the project in Container Manager).

On Synology: Container Manager → Project → Create, point it at the folder holding `docker-compose.yml`, then Build/Start.

## Configuration

Set these under `environment:` in `docker-compose.yml`.

| Variable | Default | Meaning |
|---|---|---|
| `TZ` | `UTC` | Clock used by scheduled jobs |
| `DATA_ROOT` | `/data` | The in-container folder the app may see (keep in step with the volume mapping) |
| `START_SUBDIR` | empty | Sub-folder (under `DATA_ROOT`) the folder picker opens in |
| `HASH_WORKERS` | `2` | Parallel file readers. Raise on fast hardware, lower on small NAS boxes |
| `ALLOW_PERMANENT_DELETE` | `0` | `1` adds a "Delete permanently" action (needs typed confirmation) |
| `APP_USER`, `APP_PASSWORD` | unset | Optional HTTP login for the web page |
| `SMB_HOST` | browser address | Server name shown in the Windows network paths in the file panel |
| `DSM_PORT` | `5000` | Synology only: port for the "Show in File Station" link |

## Safety and security

- **Mount only what you want scanned.** The app can see and change everything under the folder you map to `/data`. Use a narrow mapping first, and keep a backup of anything irreplaceable.
- **Quarantine, not delete.** "Move to quarantine" moves files into a hidden `.dedupe_trash` folder in the same shared folder (instant, restorable).
- **Don't expose it to the internet.** There is no TLS. Set `APP_USER` / `APP_PASSWORD` and keep it on your LAN or behind a VPN or reverse proxy.
- Symlinks are not followed. `@eaDir`, `#recycle`, `#snapshot` and `@tmp` are skipped by default.
- Hardlinks only work inside one filesystem or share; cross-share replacements are reported as skipped.
- Results live in `appdata/dedupe.db` (SQLite) and thumbnails in `appdata/thumbs`. Deleting scans in the app never touches your files.

## Notes on the media features

- The first video/audio scan reads details (and fingerprints for similar video / same recording) from every file. That is slow on big libraries and low-power hardware, but cached afterwards. Start with one folder.
- "Same length" is a weak match: review those groups before removing anything.
- Mirrored/rotated matching and the health check's full decode are slower, so they are off by default.
- Video and audio features need ffmpeg, which the Docker image installs.

## Updating

```bash
git pull
docker compose up -d --build
```

Your scan data in `appdata/` is kept.

## Project layout

`app.py` web server and API · `scanner.py` scan engine · `media.py` photo/video/audio details, fingerprints, health check · `actions.py` quarantine/link/move ·
`db.py` SQLite schema · `ignores.py` ignore list · `emptyfolders.py` empty-folder tool · `schedule.py` scheduled jobs · `static/index.html` the UI.

## Contributing

Issues and pull requests are welcome. Please describe your platform (OS, Docker version, hardware) and attach the version shown in the page header when reporting a bug.

## License

MIT. See [LICENSE](LICENSE). Use at your own risk: this tool can move and delete files, so test on copies first.

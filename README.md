# dingbap

Self-hosted file archive. One Go binary. No database. No Node build.

Browse, upload, preview, search, trash, bulk ZIP, and passworded share links — for you, friends, or a small crew. English UI.

Live at **[dingbap.xyz](https://dingbap.xyz)**. Self-host anywhere you want.

```bash
ADMIN_USER=admin ADMIN_PASS='pick-something-long' go run .
# → http://localhost:8080/login
# files land in ./storage by default
```

---

## Features

| | |
|---|---|
| **Auth** | Argon2id passwords, HttpOnly `SameSite=Strict` cookies, login lockout, optional **admin TOTP (2FA)** (on-box secrets) |
| **Roles** | `admin` (full control) · `viewer` (browse / download / preview / search / ZIP) · optional anonymous read |
| **Users** | In-app admin: add, delete, reset password, change role · anyone signed in can change their own password |
| **Files** | Chunked resumable upload, mkdir, rename, move, **copy / duplicate**, download |
| **Bulk** | Multi-select → trash, move, or download as ZIP |
| **Preview** | Images, PDF, video, text/code in a modal — unsafe types forced download |
| **Share** | Public `/s/<token>` links for **files or folders** · optional password · expiry 24h / 7d / 30d / never / 1 download · folder browse + ZIP · **drop boxes** (upload-only into a folder) · file links show a landing page before download |
| **Trash** | Soft delete → restore / empty · auto-purge after 30 days |
| **Search** | Instant local filter + deep search over the listing cache (no disk walk) |
| **Security** | Path traversal hardening, symlink escape checks, CSRF origin check, upload size caps |
| **Perf** | Gzip, LRU directory listing cache (~1000 dirs), embedded UI with inline SVG icons |
| **Ops** | Docker, TLS flags, reverse-proxy friendly, sessions survive restarts, graceful SIGTERM drain (15s), admin disk usage, optional local activity log, optional read-only WebDAV |

Storage is one folder on disk (`./storage` by default). App metadata lives under `.dingbap/` inside it.

---

## Quick start

### From source

```bash
git clone https://github.com/YOUR_USER/dingbap.git
cd dingbap

export ADMIN_USER=admin
export ADMIN_PASS='choose-a-long-random-password'   # min 8 characters
# optional first viewer:
# export VIEWER_USER=friends VIEWER_PASS='shared-secret'

go run .
```

First boot creates `./storage` (if needed) and writes `storage/.dingbap/users.json` (`0600`). After that, env bootstrap is optional — manage users in the admin UI.

| URL | |
|-----|---|
| `/login` | Sign in |
| `/` | Archive (viewer / public) |
| `/admin` | Admin UI |
| `/s/<token>` | Public share link |

### Docker

```bash
export ADMIN_PASS='choose-a-long-random-password'
# local HTTP: export COOKIE_SECURE=0
docker compose up -d --build
```

Data persists in the `dingbap-data` volume (mounted at `/data`, which is `-storage-dir`).

### Binary

```bash
go build -trimpath -pgo=auto -ldflags="-s -w" -o dingbap .
./dingbap
# or: ./dingbap -storage-dir /var/lib/dingbap
```

Drop a `default.pgo` next to `main.go` for PGO; `-pgo=auto` picks it up.

---

## Config

### First boot only (empty `.dingbap/users.json`)

| Variable | |
|----------|---|
| `ADMIN_USER` + `ADMIN_PASS` | **Required** — creates the first admin |
| `VIEWER_USER` + `VIEWER_PASS` | Optional first viewer (`PUBLIC_USER` / `PUBLIC_PASS` still work) |

### Runtime

| Variable / flag | Default | |
|-----------------|---------|---|
| `PORT` / `-port` | `8080` | Listen port |
| `DINGBAP_STORAGE_DIR` / `-storage-dir` | `./storage` | File storage root. **Priority:** CLI → env → default. Absolute path, created if missing, must be writable. Startup-only. |
| `PUBLIC_OPEN` | off | `1` = anonymous browse / download / preview / search / ZIP |
| `COOKIE_SECURE` | **on** | `0` = allow non-Secure cookies (plain HTTP testing only). Built-in TLS always forces Secure. |
| `TRUST_PROXY` | off | `1` = trust `X-Real-IP` / `X-Forwarded-For` for login rate limiting (only behind a proxy that overwrites these headers) |
| `PROXY_AUTH` | off | `1` = trust `Remote-User` / `X-Remote-User` / `X-Forwarded-User` from your reverse proxy (**also requires `TRUST_PROXY=1`**). Maps to existing local users only. |
| `PROXY_AUTH_HEADER` | — | Optional single header name instead of the defaults above |
| `WEBDAV` | off | `1` = enable read-only WebDAV at `/dav/` (auth required — never anonymous, even with `PUBLIC_OPEN`) |
| `ACTIVITY_LOG` | off | `1` = append local JSONL audit under `.dingbap/activity.jsonl` (admin UI → Activity). Action + path + user only. |
| `ACTIVITY_LOG_IP` | off | `1` = also store client IP in the activity log (only meaningful with `ACTIVITY_LOG=1`) |
| `MAX_UPLOAD_MB` | `500` | Per-file upload cap |
| `-tls-cert` + `-tls-key` | — | Built-in HTTPS (`TLS_CERT` / `TLS_KEY` env also OK) |

\* Prefer leaving unset (Secure on). Use `COOKIE_SECURE=0` only for plain HTTP testing.

---

## Using dingbap

### Users

- **Admin** header → **Users**: create accounts, reset passwords, change roles, delete users.
- Cannot delete yourself while logged in, and cannot remove or demote the last admin.
- Password resets (and role changes) invalidate that user’s sessions.
- Any signed-in user → **Password** in the header to change their own (min 8 characters).
- **Admins** → **2FA**: optional TOTP with an authenticator app. Secrets stay in `users.json` on disk (no Google/Microsoft login). Recovery codes shown once at enable time.

### Activity log

- Off by default. Set `ACTIVITY_LOG=1` to record mutations (upload, trash, share, users, …) as local JSONL.
- Admin header → **Activity**. Retention ~14 days / 5000 lines.
- Does **not** log IPs unless `ACTIVITY_LOG_IP=1`. Never logs User-Agent.

### WebDAV (read-only)

- Off by default. Set `WEBDAV=1` → **`/dav/`** for Finder, Explorer, rclone.
- **Always requires auth** (HTTP Basic, session cookie, or `PROXY_AUTH`) — never anonymous, even with `PUBLIC_OPEN=1`.
- Methods: `OPTIONS` / `GET` / `HEAD` / `PROPFIND` only (writes → `405`).
- Same path vault as the UI (no `.dingbap` / `.trash` / dotfiles).
- Prefer HTTPS — Basic auth over plain HTTP sends passwords in cleartext.
- Basic auth cannot complete admin TOTP; use a viewer account or `PROXY_AUTH` when 2FA is on.

### Shares

- On a file or folder row → link icon → choose expiry, optional password → copy the public URL.
- **Folders** can also create a **drop box** (upload-only). Guests cannot browse existing files. Drops always expire (24h / 7d / 30d), cap at 50 uploads, and use the normal per-file size limit. Not the default share type.
- **Admin** header → **Shares**: list active links, copy, revoke.
- Folder download shares open a simple public page: browse subfolders, download files, or **Download ZIP**.
- File shares open a landing page first; the visitor chooses **Download**.
- **1 download** works for download shares (files and folders). Drop boxes use an upload quota instead.
- Password-protected shares set a short-lived unlock cookie scoped to `/s/<token>`.

### Bulk actions

- Checkboxes on rows, or **Select** in the toolbar (toggle all in the current folder).
- **ZIP** downloads the selection (viewers and admins).
- Admins also get **Move** and **Trash** on the selection bar.

### Uploads

- Drag-and-drop or **Upload**. Large files are chunked.
- **Upload folder** (or drop a folder) keeps the relative directory tree under the current path.
- If an upload is interrupted, pick the **same file** again in the same folder — finished chunks are skipped (resume keys in `localStorage`; chunk data on the server ~24h).

---

## Production

Put **HTTPS in front**. Don’t expose plain HTTP to the internet.

```caddy
dingbap.xyz {
    reverse_proxy 127.0.0.1:8080
}
```

```caddy
files.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

```nginx
# client_max_body_size ≥ MAX_UPLOAD_MB
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 900s;
}
```

Then: firewall so only your reverse proxy can reach dingbap, `TRUST_PROXY=1`, back up your storage directory (files + `.dingbap/` + `.trash/`). Cookies default to `Secure` (override with `COOKIE_SECURE=0` only for local plain HTTP). For Authelia/Authentik SSO, also set `PROXY_AUTH=1` (see Auth model).

---

## Auth model

| Who | Can do |
|-----|--------|
| **admin** | Everything (upload, mutate, trash, shares, users) |
| **viewer** | Browse, download, preview, search, ZIP |
| **anon** | Same as viewer **only if** `PUBLIC_OPEN=1` |

- Sessions: cookie `dingbap_session`, 7 days, written to `.dingbap/sessions.json` on login/logout (survives restarts). Concurrent session writes are serialized so logins cannot clobber each other.
- Passwords: Argon2id (`t=3`, 64 MiB). New / changed passwords must be at least 8 characters. Login always runs a full hash verify (dummy hash on unknown usernames) to reduce timing oracles.
- Failed logins: lockout after 5 failures per IP per minute (stale entries are reaped).
- Login rate limit uses `RemoteAddr` by default. Set `TRUST_PROXY=1` behind Caddy/Nginx so it uses `X-Real-IP` / `X-Forwarded-For` (proxy must overwrite client-supplied values).
- **Proxy / SSO auth (self-hosted IdP only):** set `TRUST_PROXY=1` and `PROXY_AUTH=1` behind Authelia, Authentik, or Caddy forward-auth. The proxy must set `Remote-User` (or `X-Remote-User`) to a username that already exists in dingbap. Roles stay in local `users.json` — no auto-provision, no Google/Microsoft login in-app. **Do not expose dingbap directly to the internet with these flags** (clients could spoof the header). Bind to localhost / private network and terminate TLS + auth at the proxy. Local password login remains available as break-glass.
- **WebDAV:** `WEBDAV=1` serves read-only `/dav/` (Basic / session / `PROXY_AUTH`). Never anonymous. Prefer TLS.
- JSON API bodies capped at 1 MiB (`http.MaxBytesReader`).
- Share download quotas are reserved **before** the transfer starts (closes parallel “1 download” races).

---

## Layout on disk

```
storage/                 # -storage-dir / DINGBAP_STORAGE_DIR (default ./storage)
├── .dingbap/
│   ├── users.json       # accounts (0600)
│   ├── sessions.json    # login sessions (0600)
│   ├── shares.json      # public share links
│   ├── activity.jsonl   # optional audit (ACTIVITY_LOG=1)
│   └── .uploads/        # chunked upload scratch
├── .trash/              # soft-deleted items (+ trash_info.json)
└── …                    # your files
```

Dot directories are hidden from the UI tree and search.

---

## Internals (short)

| Piece | Behavior |
|-------|----------|
| **Listing cache** | Per-directory listings in RAM, LRU-capped (~1000 dirs), invalidated on mutations |
| **Search** | Walks the listing cache (fills on miss via the same path as `/api/tree`) |
| **ZIP** | Streams `application/zip` from selected paths; skips dotfiles; caps ~5000 files / ~4 GiB |
| **Shares** | Tokens in `shares.json`; folder browse stays under the shared path via `safePath` |
| **Icons** | Inline SVG sprite in HTML templates — no third-party icon JS |
| **Uploads** | Chunked + resumable; relative paths create nested dirs (folder drag-upload); state in memory (chunk bytes on disk for resume) |
| **Shutdown** | SIGTERM/SIGINT → stop accepting connections, drain in-flight handlers up to 15s, then force close |
| **WebDAV** | Opt-in `/dav/` read-only via `golang.org/x/net/webdav` + `safePath`; auth required |

---

## API (sketch)

Mutations return `{"ok":true,"message":"..."}` or `{"ok":false,"error":"..."}`.  
Admin and password/ZIP POSTs require a same-origin request (CSRF check).

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/api/login` · `/api/login/totp` · `/api/logout` | public |
| `GET` | `/api/me` · `/api/totp/status` | public / signed-in |
| `POST` | `/api/password` · `/api/totp/begin` · `confirm` · `disable` | logged-in (admin for TOTP) |
| `GET` | `/api/tree?path=` · `/api/search?q=` | viewer / open |
| `POST` | `/api/zip` | viewer / open |
| `GET` | `/download/…` · `/preview/…` | viewer / open |
| `GET`/`POST` | `/s/{token}` · `/unlock` · `/download` · `/browse/…` · `/f/…` · `/zip` · `/upload` (drop) | public (share; password cookie if set) |
| `POST` | `/admin/upload` · `/admin/upload/*` | admin |
| `POST` | `/admin/mkdir` · `rename` · `move` · `copy` · `duplicate` · `delete` | admin |
| `POST` | `/admin/bulk/delete` · `/admin/bulk/move` · `/admin/bulk/zip` | admin |
| `POST` | `/admin/share` · `/admin/share/revoke` | admin |
| `GET` | `/admin/api/tree` · `search` · `disk` · `activity` · `trash` · `shares` · `users` | admin |
| `POST` | `/admin/users` · `/users/delete` · `/users/password` · `/users/role` | admin |
| `POST` | `/admin/trash/restore` · `purge` · `empty` | admin |

Share create body: `{ "path", "expires": "24h\|7d\|30d\|never\|1download", "password?" }`.  
Bulk body: `{ "paths": [...], ... }` (delete also needs `"confirm": true`).

---

## Security notes

- No default passwords — won’t start without bootstrap env or an existing `users.json`
- Path checks via `safePath` / `withinRoot` (symlinks included); storage real root resolved once at startup
- Any path segment starting with `.` is denied at the API layer (`.dingbap`, `.trash`, `.uploads`, …), including after symlink resolution — metadata is not downloadable even by direct URL or a planted symlink
- Metadata JSON writes use temp + `fsync` + rename
- Main UI sends a strict Content-Security-Policy (inline script/style allowed for the embedded UI)
- HTML / SVG / JS never inline-previewed
- Share URLs never expose internal paths; password hashes stored with Argon2id
- Prefer Caddy/Nginx TLS over exposing the app port raw; cookies are `Secure` by default

---

## License

Add one before you publish (MIT / Apache-2.0 are fine).

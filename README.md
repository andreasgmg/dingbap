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
| **Auth** | Argon2id passwords, HttpOnly `SameSite=Strict` cookies, login lockout |
| **Roles** | `admin` (full control) · `viewer` (browse / download / preview / search / ZIP) · optional anonymous read |
| **Users** | In-app admin: add, delete, reset password, change role · anyone signed in can change their own password |
| **Files** | Chunked resumable upload, mkdir, rename, move, download |
| **Bulk** | Multi-select → trash, move, or download as ZIP |
| **Preview** | Images, PDF, video, text/code in a modal — unsafe types forced download |
| **Share** | Public `/s/<token>` links for **files or folders** · optional password · expiry 24h / 7d / 30d / never / 1 download · folder browse + ZIP · file links show a landing page before download |
| **Trash** | Soft delete → restore / empty · auto-purge after 30 days |
| **Search** | Instant local filter + deep search over the listing cache (no disk walk) |
| **Security** | Path traversal hardening, symlink escape checks, CSRF origin check, upload size caps |
| **Perf** | Gzip, LRU directory listing cache (~1000 dirs), embedded UI with inline SVG icons |
| **Ops** | Docker, TLS flags, reverse-proxy friendly, sessions survive restarts |

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
| `COOKIE_SECURE` | off* | `1` behind an HTTPS reverse proxy |
| `MAX_UPLOAD_MB` | `500` | Per-file upload cap |
| `-tls-cert` + `-tls-key` | — | Built-in HTTPS (`TLS_CERT` / `TLS_KEY` env also OK) |

\* Auto-on when using built-in TLS.

---

## Using dingbap

### Users

- **Admin** header → **Users**: create accounts, reset passwords, change roles, delete users.
- Cannot delete yourself while logged in, and cannot remove or demote the last admin.
- Password resets (and role changes) invalidate that user’s sessions.
- Any signed-in user → **Password** in the header to change their own (min 8 characters).

### Shares

- On a file or folder row → link icon → choose expiry, optional password → copy the public URL.
- **Admin** header → **Shares**: list active links, copy, revoke.
- Folder shares open a simple public page: browse subfolders, download files, or **Download ZIP**.
- File shares open a landing page first; the visitor chooses **Download**.
- **1 download** works for files and folders (first file or ZIP download consumes the link; browsing a folder does not).
- Password-protected shares set a short-lived unlock cookie scoped to `/s/<token>`.

### Bulk actions

- Checkboxes on rows, or **Select** in the toolbar (toggle all in the current folder).
- **ZIP** downloads the selection (viewers and admins).
- Admins also get **Move** and **Trash** on the selection bar.

### Uploads

- Drag-and-drop or **Upload**. Large files are chunked.
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
    proxy_read_timeout 900s;
}
```

Then: `COOKIE_SECURE=1`, firewall to 80/443 only, back up your storage directory (files + `.dingbap/` + `.trash/`).

---

## Auth model

| Who | Can do |
|-----|--------|
| **admin** | Everything (upload, mutate, trash, shares, users) |
| **viewer** | Browse, download, preview, search, ZIP |
| **anon** | Same as viewer **only if** `PUBLIC_OPEN=1` |

Sessions: cookie `dingbap_session`, 7 days, written to `.dingbap/sessions.json` on login/logout (survives restarts).  
Passwords: Argon2id. New / changed passwords must be at least 8 characters.  
Failed logins: lockout after 5 failures per IP per minute (stale entries are reaped).

---

## Layout on disk

```
storage/                 # -storage-dir / DINGBAP_STORAGE_DIR (default ./storage)
├── .dingbap/
│   ├── users.json       # accounts (0600)
│   ├── sessions.json    # login sessions (0600)
│   ├── shares.json      # public share links
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
| **Uploads** | Chunked + resumable; active upload state in memory (chunk bytes on disk for resume) |

---

## API (sketch)

Mutations return `{"ok":true,"message":"..."}` or `{"ok":false,"error":"..."}`.  
Admin and password/ZIP POSTs require a same-origin request (CSRF check).

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/api/login` · `/api/logout` | public |
| `GET` | `/api/me` | public |
| `POST` | `/api/password` | logged-in |
| `GET` | `/api/tree?path=` · `/api/search?q=` | viewer / open |
| `POST` | `/api/zip` | viewer / open |
| `GET` | `/download/…` · `/preview/…` | viewer / open |
| `GET`/`POST` | `/s/{token}` · `/unlock` · `/download` · `/browse/…` · `/f/…` · `/zip` | public (share; password cookie if set) |
| `POST` | `/admin/upload` · `/admin/upload/*` | admin |
| `POST` | `/admin/mkdir` · `rename` · `move` · `delete` | admin |
| `POST` | `/admin/bulk/delete` · `/admin/bulk/move` · `/admin/bulk/zip` | admin |
| `POST` | `/admin/share` · `/admin/share/revoke` | admin |
| `GET` | `/admin/api/tree` · `search` · `trash` · `shares` · `users` | admin |
| `POST` | `/admin/users` · `/users/delete` · `/users/password` · `/users/role` | admin |
| `POST` | `/admin/trash/restore` · `purge` · `empty` | admin |

Share create body: `{ "path", "expires": "24h\|7d\|30d\|never\|1download", "password?" }`.  
Bulk body: `{ "paths": [...], ... }` (delete also needs `"confirm": true`).

---

## Security notes

- No default passwords — won’t start without bootstrap env or an existing `users.json`
- Path checks via `safePath` / `withinRoot` (symlinks included); storage real root resolved once at startup
- HTML / SVG / JS never inline-previewed
- Share URLs never expose internal paths; password hashes stored with Argon2id
- Prefer Caddy/Nginx TLS over exposing the app port raw

---

## License

Add one before you publish (MIT / Apache-2.0 are fine).

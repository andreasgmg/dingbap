package main

import (
	"context"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"

	"golang.org/x/net/webdav"
)

// WEBDAV=1 enables read-only WebDAV at /dav/. Always requires authentication
// (session cookie, PROXY_AUTH, or HTTP Basic). Never available anonymously,
// even when PUBLIC_OPEN=1. Write methods are rejected.
var webdavEnabled bool

func configureWebDAV() {
	webdavEnabled = envTruthy("WEBDAV")
	if webdavEnabled {
		log.Printf("WEBDAV=1 — read-only WebDAV at /dav/ (auth required: Basic, session, or PROXY_AUTH; never anonymous)")
	}
}

func newWebDAVHandler() http.Handler {
	h := &webdav.Handler{
		Prefix:     "/dav",
		FileSystem: dingbapDAVFS{},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("webdav %s %s: %v", r.Method, r.URL.Path, err)
			}
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT", "POST", "DELETE", "MKCOL", "COPY", "MOVE", "PROPPATCH", "LOCK", "UNLOCK", "PATCH":
			w.Header().Set("Allow", "OPTIONS, GET, HEAD, PROPFIND")
			http.Error(w, "WebDAV is read-only", http.StatusMethodNotAllowed)
			return
		case http.MethodOptions:
			w.Header().Set("Allow", "OPTIONS, GET, HEAD, PROPFIND")
			w.Header().Set("DAV", "1")
			w.Header().Set("MS-Author-Via", "DAV")
			w.WriteHeader(http.StatusOK)
			return
		case "PROPFIND":
			// Cap depth to avoid expensive infinity walks.
			if strings.EqualFold(r.Header.Get("Depth"), "infinity") {
				r.Header.Set("Depth", "1")
			}
		}
		w.Header().Set("DAV", "1")
		h.ServeHTTP(w, r)
	})
}

// requireWebDAVAuth requires a logged-in viewer/admin. Unlike the browse UI,
// PUBLIC_OPEN does not grant anonymous WebDAV.
func requireWebDAVAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := sessionFromCtx(r); s != nil {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := parseBasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="dingbap", charset="UTF-8"`)
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		u, err := users.authenticate(user, pass)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="dingbap", charset="UTF-8"`)
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		// WebDAV Basic cannot complete TOTP; password alone is accepted here.
		// Prefer PROXY_AUTH or a non-TOTP viewer account when 2FA is enabled.
		ctx := context.WithValue(r.Context(), sessionCtxKey, &Session{
			Username: u.Username,
			Role:     u.Role,
		})
		ctx = context.WithValue(ctx, authViaCtxKey, "basic")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func parseBasicAuth(r *http.Request) (username, password string, ok bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return "", "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(dec), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// dingbapDAVFS exposes storage via safePath — same traversal/hidden/symlink rules
// as the HTTP API. All mutations return permission errors.
type dingbapDAVFS struct{}

func (dingbapDAVFS) Mkdir(context.Context, string, os.FileMode) error {
	return os.ErrPermission
}

func (dingbapDAVFS) RemoveAll(context.Context, string) error {
	return os.ErrPermission
}

func (dingbapDAVFS) Rename(context.Context, string, string) error {
	return os.ErrPermission
}

func (dingbapDAVFS) Stat(_ context.Context, name string) (os.FileInfo, error) {
	abs, err := resolveDAVPath(name)
	if err != nil {
		return nil, os.ErrNotExist
	}
	return os.Stat(abs)
}

func (dingbapDAVFS) OpenFile(_ context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_TRUNC) != 0 {
		return nil, os.ErrPermission
	}
	abs, err := resolveDAVPath(name)
	if err != nil {
		return nil, os.ErrNotExist
	}
	f, err := os.Open(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return &davFile{File: f}, nil
}

func resolveDAVPath(name string) (string, error) {
	rel := strings.Trim(path.Clean("/"+strings.ReplaceAll(name, `\`, `/`)), "/")
	if rel == "." {
		rel = ""
	}
	// Deny any request that still contains a hidden segment after clean.
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." {
			continue
		}
		if strings.HasPrefix(part, ".") {
			return "", os.ErrNotExist
		}
	}
	return safePath(rel)
}

type davFile struct {
	*os.File
	dirOffset int
	dirCache  []os.FileInfo
}

func (f *davFile) Write([]byte) (int, error) {
	return 0, os.ErrPermission
}

func (f *davFile) Readdir(count int) ([]os.FileInfo, error) {
	if f.dirCache == nil {
		all, err := f.File.Readdir(-1)
		if err != nil {
			return nil, err
		}
		f.dirCache = make([]os.FileInfo, 0, len(all))
		for _, info := range all {
			if strings.HasPrefix(info.Name(), ".") {
				continue
			}
			f.dirCache = append(f.dirCache, info)
		}
		f.dirOffset = 0
	}
	if f.dirOffset >= len(f.dirCache) {
		if count > 0 {
			return nil, io.EOF
		}
		return nil, nil
	}
	if count <= 0 {
		out := f.dirCache[f.dirOffset:]
		f.dirOffset = len(f.dirCache)
		return out, nil
	}
	end := f.dirOffset + count
	if end > len(f.dirCache) {
		end = len(f.dirCache)
	}
	out := f.dirCache[f.dirOffset:end]
	f.dirOffset = end
	if len(out) == 0 {
		return nil, io.EOF
	}
	return out, nil
}

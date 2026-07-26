package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// Proxy auth (forward-auth / Remote-User) for self-hosted IdPs only
// (Authelia, Authentik, Caddy + oauth2-proxy, nginx auth_request).
//
// Requires BOTH:
//   PROXY_AUTH=1  — opt in
//   TRUST_PROXY=1 — same discipline as client IP: never trust identity headers
//                   when the app is exposed directly to the internet
//
// Identity is mapped to an existing local users.json account (role stays local).
// No auto-provisioning, no SaaS IdP integration.

var (
	proxyAuthEnabled bool
	// Optional override; empty = try Remote-User, X-Remote-User, X-Forwarded-User.
	proxyAuthHeader string
)

func configureProxyAuth() {
	want := envTruthy("PROXY_AUTH")
	proxyAuthHeader = strings.TrimSpace(os.Getenv("PROXY_AUTH_HEADER"))
	if want && !trustProxy {
		log.Printf("WARNING: PROXY_AUTH=1 ignored — set TRUST_PROXY=1 as well (identity headers are only safe behind a reverse proxy that overwrites them)")
		proxyAuthEnabled = false
		return
	}
	proxyAuthEnabled = want
	if proxyAuthEnabled {
		hdr := proxyAuthHeader
		if hdr == "" {
			hdr = "Remote-User | X-Remote-User | X-Forwarded-User"
		}
		log.Printf("PROXY_AUTH=1 — trusting %s from reverse proxy (maps to existing local users only)", hdr)
	}
}

func proxyUsername(r *http.Request) string {
	if !proxyAuthEnabled || r == nil {
		return ""
	}
	var raw string
	if proxyAuthHeader != "" {
		raw = r.Header.Get(proxyAuthHeader)
	} else {
		for _, h := range []string{"Remote-User", "X-Remote-User", "X-Forwarded-User"} {
			if v := r.Header.Get(h); v != "" {
				raw = v
				break
			}
		}
	}
	return sanitizeProxyUsername(raw)
}

func sanitizeProxyUsername(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// Some proxies send "user@realm" — take the local part.
	if i := strings.IndexByte(raw, '@'); i > 0 {
		raw = raw[:i]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 64 {
		return ""
	}
	// Reject path / header injection style junk.
	if strings.ContainsAny(raw, "/\\\x00\r\n") {
		return ""
	}
	return raw
}

// sessionFromProxy returns a non-persisted session when PROXY_AUTH maps to a local user.
func sessionFromProxy(r *http.Request) *Session {
	name := proxyUsername(r)
	if name == "" || users == nil {
		return nil
	}
	u, ok := users.byUsername(name)
	if !ok {
		return nil
	}
	return &Session{
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour), // request-scoped; not persisted
	}
}

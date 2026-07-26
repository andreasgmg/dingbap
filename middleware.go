package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

type ctxKey int

const (
	sessionCtxKey ctxKey = 1
	authViaCtxKey ctxKey = 2
)

func sessionFromCtx(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionCtxKey).(*Session)
	return s
}

func authViaFromCtx(r *http.Request) string {
	v, _ := r.Context().Value(authViaCtxKey).(string)
	return v
}

func withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Strict CSP; 'unsafe-inline' required for the embedded layout/login scripts & styles.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "+
				"script-src 'unsafe-inline'; style-src 'unsafe-inline'; "+
				"img-src 'self' blob: data:; media-src 'self' blob:; frame-src 'self'; "+
				"connect-src 'self'; font-src 'self'; object-src 'none'")
		var s *Session
		var via string
		// Prefer reverse-proxy identity when present (SSO source of truth).
		if proxy := sessionFromProxy(r); proxy != nil {
			s = proxy
			via = "proxy"
		} else if cookie := sessions.fromRequest(r); cookie != nil {
			s = cookie
			via = "session"
		}
		if s != nil {
			ctx := context.WithValue(r.Context(), sessionCtxKey, s)
			if via != "" {
				ctx = context.WithValue(ctx, authViaCtxKey, via)
			}
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			jsonErr(w, http.StatusForbidden, "Invalid origin")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := sessionFromCtx(r)
		if s == nil {
			denyAuth(w, r)
			return
		}
		if s.Role != roleAdmin {
			if shouldRedirectToLogin(r) {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
			jsonErr(w, http.StatusForbidden, "Admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireViewerOrOpen allows anyone when PUBLIC_OPEN, else requires a logged-in user.
func requireViewerOrOpen(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicOpen {
			next.ServeHTTP(w, r)
			return
		}
		if sessionFromCtx(r) == nil {
			denyAuth(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func denyAuth(w http.ResponseWriter, r *http.Request) {
	if shouldRedirectToLogin(r) {
		next := url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, "/login?next="+next, http.StatusFound)
		return
	}
	jsonErr(w, http.StatusUnauthorized, "Authentication required")
}

func shouldRedirectToLogin(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/download/") || strings.HasPrefix(path, "/preview/") {
		return false
	}
	if strings.HasPrefix(path, "/admin/") {
		return false
	}
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if s := sessionFromCtx(r); s != nil {
		dest := safeNextPath(r.URL.Query().Get("next"), s.Role)
		http.Redirect(w, r, dest, http.StatusFound)
		return
	}
	execTemplate(w, loginTpl, map[string]any{
		"Next":       r.URL.Query().Get("next"),
		"PublicOpen": publicOpen,
		"ProxyAuth":  proxyAuthEnabled,
		"Error":      r.URL.Query().Get("error"),
	})
}

func safeNextPath(next, role string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		if role == roleAdmin {
			return "/admin"
		}
		return "/"
	}
	if strings.HasPrefix(next, "/admin") && role != roleAdmin {
		return "/"
	}
	return next
}

func handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if !sameOrigin(r) {
		jsonErr(w, http.StatusForbidden, "Invalid origin")
		return
	}

	ip := clientIP(r)
	if !sessions.allowLogin(ip) {
		jsonErr(w, http.StatusTooManyRequests, "Too many failed attempts — try again in a minute")
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}

	user, err := users.authenticate(body.Username, body.Password)
	if err != nil {
		sessions.recordFailure(ip)
		jsonErr(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	finishLoginAfterPassword(w, r, ip, user)
}

func handleLogoutAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		sessions.destroy(c.Value)
	}
	sessions.clearCookie(w)
	jsonOK(w, "Logged out")
}

func handleMeAPI(w http.ResponseWriter, r *http.Request) {
	s := sessionFromCtx(r)
	if s == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"authenticated": false,
			"publicOpen":    publicOpen,
			"proxyAuth":     proxyAuthEnabled,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"authenticated": true,
		"username":      s.Username,
		"role":          s.Role,
		"publicOpen":    publicOpen,
		"totpEnabled":   s.Role == roleAdmin && users.totpEnabled(s.Username),
		"authVia":       authViaFromCtx(r),
		"proxyAuth":     proxyAuthEnabled,
	})
}

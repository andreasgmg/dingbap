package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "dingbap_session"
	sessionTTL        = 7 * 24 * time.Hour
	loginMaxFailures  = 5
	loginLockDuration = time.Minute
)

type Session struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

type sessionManager struct {
	mu           sync.RWMutex
	sessions     map[string]*Session
	path         string // sessions.json path; empty = memory-only (tests)
	secureCookie bool
	failures     map[string]loginAttempt
}

type loginAttempt struct {
	count       int
	lockedUntil time.Time
	lastFail    time.Time
}

type sessionsFile struct {
	Sessions map[string]Session `json:"sessions"`
}

func newSessionManager(path string, secureCookie bool) *sessionManager {
	sm := &sessionManager{
		sessions:     make(map[string]*Session),
		path:         path,
		secureCookie: secureCookie,
		failures:     make(map[string]loginAttempt),
	}
	if err := sm.load(); err != nil {
		log.Printf("Warning: could not load sessions from %s: %v", path, err)
	}
	go sm.reapLoop()
	return sm
}

func (sm *sessionManager) load() error {
	if sm.path == "" {
		return nil
	}
	data, err := os.ReadFile(sm.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var f sessionsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	now := time.Now()
	loaded := 0
	sm.mu.Lock()
	for id, s := range f.Sessions {
		if id == "" || s.Username == "" || s.Role == "" {
			continue
		}
		if now.After(s.ExpiresAt) {
			continue
		}
		cp := s
		sm.sessions[id] = &cp
		loaded++
	}
	sm.mu.Unlock()
	if loaded > 0 {
		log.Printf("Restored %d session(s) from %s", loaded, sm.path)
	}
	return nil
}

// persist writes sessions.json atomically. Call without holding sm.mu.
func (sm *sessionManager) persist() {
	if sm.path == "" {
		return
	}
	sm.mu.RLock()
	f := sessionsFile{Sessions: make(map[string]Session, len(sm.sessions))}
	now := time.Now()
	for id, s := range sm.sessions {
		if now.After(s.ExpiresAt) {
			continue
		}
		f.Sessions[id] = *s
	}
	sm.mu.RUnlock()

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		log.Printf("Warning: marshal sessions: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(sm.path), 0700); err != nil {
		log.Printf("Warning: sessions dir: %v", err)
		return
	}
	tmp := sm.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("Warning: write sessions: %v", err)
		return
	}
	if err := os.Rename(tmp, sm.path); err != nil {
		log.Printf("Warning: rename sessions: %v", err)
		_ = os.Remove(tmp)
	}
}

func (sm *sessionManager) reapLoop() {
	t := time.NewTicker(time.Hour)
	for range t.C {
		sm.reap()
	}
}

func (sm *sessionManager) reap() {
	now := time.Now()
	changed := false
	sm.mu.Lock()
	for id, s := range sm.sessions {
		if now.After(s.ExpiresAt) {
			delete(sm.sessions, id)
			changed = true
		}
	}
	for ip, a := range sm.failures {
		// Expire lockouts and partial failure counters after their window,
		// even when count > 0 (previously those entries leaked forever).
		expiry := a.lastFail.Add(loginLockDuration)
		if a.lockedUntil.After(expiry) {
			expiry = a.lockedUntil
		}
		if a.lastFail.IsZero() && a.lockedUntil.IsZero() {
			delete(sm.failures, ip)
			continue
		}
		if now.After(expiry) {
			delete(sm.failures, ip)
		}
	}
	sm.mu.Unlock()
	if changed {
		sm.persist()
	}
}

func (sm *sessionManager) create(username, role string) (string, error) {
	id, err := randomToken(32)
	if err != nil {
		return "", err
	}
	sm.mu.Lock()
	sm.sessions[id] = &Session{
		Username:  username,
		Role:      role,
		ExpiresAt: time.Now().Add(sessionTTL),
	}
	sm.mu.Unlock()
	sm.persist()
	return id, nil
}

func (sm *sessionManager) get(id string) (Session, bool) {
	if id == "" {
		return Session{}, false
	}
	sm.mu.RLock()
	s, ok := sm.sessions[id]
	if !ok {
		sm.mu.RUnlock()
		return Session{}, false
	}
	cp := *s
	sm.mu.RUnlock()
	if time.Now().After(cp.ExpiresAt) {
		sm.destroy(id)
		return Session{}, false
	}
	return cp, true
}

func (sm *sessionManager) destroy(id string) {
	sm.mu.Lock()
	_, ok := sm.sessions[id]
	if ok {
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()
	if ok {
		sm.persist()
	}
}

// destroyByUsername drops all sessions for a user (password change / delete).
func (sm *sessionManager) destroyByUsername(username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	changed := false
	sm.mu.Lock()
	for id, s := range sm.sessions {
		if strings.EqualFold(s.Username, username) {
			delete(sm.sessions, id)
			changed = true
		}
	}
	sm.mu.Unlock()
	if changed {
		sm.persist()
	}
}

func (sm *sessionManager) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   sm.secureCookie,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (sm *sessionManager) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   sm.secureCookie,
		MaxAge:   -1,
	})
}

func (sm *sessionManager) fromRequest(r *http.Request) *Session {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	s, ok := sm.get(c.Value)
	if !ok {
		return nil
	}
	// Heap-allocate a per-request copy so context holders never share map memory.
	cp := s
	return &cp
}

func (sm *sessionManager) allowLogin(ip string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	a := sm.failures[ip]
	if time.Now().Before(a.lockedUntil) {
		return false
	}
	if !a.lockedUntil.IsZero() && time.Now().After(a.lockedUntil) {
		sm.failures[ip] = loginAttempt{}
	}
	return true
}

func (sm *sessionManager) recordFailure(ip string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	a := sm.failures[ip]
	a.count++
	a.lastFail = time.Now()
	if a.count >= loginMaxFailures {
		a.lockedUntil = time.Now().Add(loginLockDuration)
		a.count = 0
	}
	sm.failures[ip] = a
}

func (sm *sessionManager) clearFailures(ip string) {
	sm.mu.Lock()
	delete(sm.failures, ip)
	sm.mu.Unlock()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sameOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			return true
		}
		exp := expectedOrigin(r)
		return strings.HasPrefix(ref, exp+"/") || ref == exp+"/" || ref == exp
	}
	return origin == expectedOrigin(r)
}

func expectedOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

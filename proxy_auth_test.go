package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeProxyUsername(t *testing.T) {
	cases := map[string]string{
		"alice":                "alice",
		"  bob@realm  ":        "bob",
		"":                     "",
		"a/b":                  "",
		"ok-user_1":            "ok-user_1",
		strings.Repeat("x", 65): "",
	}
	for in, want := range cases {
		if got := sanitizeProxyUsername(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestProxyAuthRequiresTrustProxy(t *testing.T) {
	prevTrust, prevAuth := trustProxy, proxyAuthEnabled
	t.Cleanup(func() {
		trustProxy, proxyAuthEnabled = prevTrust, prevAuth
	})

	t.Setenv("PROXY_AUTH", "1")
	t.Setenv("PROXY_AUTH_HEADER", "")
	trustProxy = false
	configureProxyAuth()
	if proxyAuthEnabled {
		t.Fatal("PROXY_AUTH must stay off without TRUST_PROXY")
	}

	trustProxy = true
	configureProxyAuth()
	if !proxyAuthEnabled {
		t.Fatal("expected enabled with TRUST_PROXY")
	}
}

func TestSessionFromProxyMapsLocalUser(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("alice", "password12", roleViewer); err != nil {
		t.Fatal(err)
	}
	prevUsers, prevTrust, prevAuth := users, trustProxy, proxyAuthEnabled
	users = store
	trustProxy = true
	proxyAuthEnabled = true
	proxyAuthHeader = ""
	t.Cleanup(func() {
		users, trustProxy, proxyAuthEnabled = prevUsers, prevTrust, prevAuth
		proxyAuthHeader = ""
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Remote-User", "alice")
	s := sessionFromProxy(r)
	if s == nil || s.Username != "alice" || s.Role != roleViewer {
		t.Fatalf("got %+v", s)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Remote-User", "nobody")
	if sessionFromProxy(r2) != nil {
		t.Fatal("unknown user must not get a session")
	}
}

func TestProxyAuthIgnoredWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.addUser("alice", "password12", roleAdmin)
	prevUsers, prevAuth := users, proxyAuthEnabled
	users = store
	proxyAuthEnabled = false
	t.Cleanup(func() {
		users, proxyAuthEnabled = prevUsers, prevAuth
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Remote-User", "alice")
	if sessionFromProxy(r) != nil {
		t.Fatal("must ignore Remote-User when PROXY_AUTH is off")
	}
}

func TestWithSessionPrefersProxyOverCookie(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.addUser("alice", "password12", roleAdmin)
	_ = store.addUser("bob", "password12", roleViewer)

	prevUsers, prevSess, prevAuth := users, sessions, proxyAuthEnabled
	users = store
	sessions = newSessionManager("", false)
	proxyAuthEnabled = true
	t.Cleanup(func() {
		users, sessions, proxyAuthEnabled = prevUsers, prevSess, prevAuth
	})

	id, err := sessions.create("bob", roleViewer)
	if err != nil {
		t.Fatal(err)
	}

	var gotUser, gotVia string
	h := withSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := sessionFromCtx(r); s != nil {
			gotUser = s.Username
		}
		gotVia = authViaFromCtx(r)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	req.Header.Set("Remote-User", "alice")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotUser != "alice" || gotVia != "proxy" {
		t.Fatalf("user=%q via=%q want alice/proxy", gotUser, gotVia)
	}
}

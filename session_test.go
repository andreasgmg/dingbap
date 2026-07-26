package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSessionPersistAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")

	sm := newSessionManager(path, false)
	id, err := sm.create("alice", roleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sm.get(id); !ok {
		t.Fatal("session missing after create")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("sessions.json not written:", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o want 0600", info.Mode().Perm())
	}

	sm2 := newSessionManager(path, false)
	s, ok := sm2.get(id)
	if !ok || s.Username != "alice" || s.Role != roleAdmin {
		t.Fatalf("restored %+v ok=%v", s, ok)
	}
}

func TestSessionDestroyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	sm := newSessionManager(path, false)
	id, err := sm.create("bob", roleViewer)
	if err != nil {
		t.Fatal(err)
	}
	sm.destroy(id)

	sm2 := newSessionManager(path, false)
	if _, ok := sm2.get(id); ok {
		t.Fatal("logout should not survive restart")
	}

	var f sessionsFile
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Sessions) != 0 {
		t.Fatalf("file still has sessions: %+v", f.Sessions)
	}
}

func TestSessionLoadSkipsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	f := sessionsFile{Sessions: map[string]Session{
		"deadbeef": {
			Username:  "old",
			Role:      roleViewer,
			ExpiresAt: time.Now().Add(-time.Hour),
		},
		"cafebabe": {
			Username:  "live",
			Role:      roleAdmin,
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}}
	data, _ := json.Marshal(f)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	sm := newSessionManager(path, false)
	if _, ok := sm.get("deadbeef"); ok {
		t.Fatal("expired session restored")
	}
	if s, ok := sm.get("cafebabe"); !ok || s.Username != "live" {
		t.Fatalf("live session: %+v ok=%v", s, ok)
	}
}

func TestSessionMemoryOnlyWhenNoPath(t *testing.T) {
	sm := newSessionManager("", false)
	id, err := sm.create("x", roleViewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sm.get(id); !ok {
		t.Fatal("expected in-memory session")
	}
}

func TestSessionGetReturnsCopy(t *testing.T) {
	sm := newSessionManager("", false)
	id, err := sm.create("carol", roleViewer)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := sm.get(id)
	if !ok {
		t.Fatal("missing")
	}
	a.Username = "mutated"
	b, _ := sm.get(id)
	if b.Username != "carol" {
		t.Fatal("get returned shared mutable session")
	}
}

func TestLoginFailuresReapPartial(t *testing.T) {
	sm := newSessionManager("", false)
	sm.recordFailure("1.2.3.4")
	sm.mu.Lock()
	a := sm.failures["1.2.3.4"]
	a.lastFail = time.Now().Add(-2 * loginLockDuration)
	sm.failures["1.2.3.4"] = a
	sm.mu.Unlock()
	sm.reap()
	sm.mu.Lock()
	_, ok := sm.failures["1.2.3.4"]
	sm.mu.Unlock()
	if ok {
		t.Fatal("partial failure should be reaped after window")
	}
}

func TestClientIPHonorsProxyHeaders(t *testing.T) {
	prev := trustProxy
	trustProxy = true
	t.Cleanup(func() { trustProxy = prev })

	mk := func(remote string, hdr http.Header) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: make(http.Header)}
		for k, vals := range hdr {
			for _, v := range vals {
				r.Header.Add(k, v)
			}
		}
		return r
	}
	if got := clientIP(mk("10.0.0.1:1234", nil)); got != "10.0.0.1" {
		t.Fatalf("remote: %q", got)
	}
	h := http.Header{}
	h.Set("X-Real-IP", "203.0.113.9")
	h.Set("X-Forwarded-For", "198.51.100.2, 10.0.0.1")
	if got := clientIP(mk("10.0.0.1:1234", h)); got != "203.0.113.9" {
		t.Fatalf("X-Real-IP preferred: %q", got)
	}
	h2 := http.Header{}
	h2.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")
	if got := clientIP(mk("10.0.0.1:1234", h2)); got != "198.51.100.7" {
		t.Fatalf("XFF leftmost: %q", got)
	}
	h3 := http.Header{}
	h3.Set("X-Forwarded-For", "not-an-ip")
	if got := clientIP(mk("10.0.0.1:99", h3)); got != "10.0.0.1" {
		t.Fatalf("fallback remote: %q", got)
	}
}

func TestClientIPIgnoresProxyHeadersUnlessTrusted(t *testing.T) {
	prev := trustProxy
	trustProxy = false
	t.Cleanup(func() { trustProxy = prev })

	r := &http.Request{
		RemoteAddr: "10.0.0.1:1234",
		Header:     http.Header{"X-Real-IP": []string{"203.0.113.9"}},
	}
	if got := clientIP(r); got != "10.0.0.1" {
		t.Fatalf("untrusted proxy headers must be ignored, got %q", got)
	}
}

func TestSessionPersistConcurrentNoLostWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	sm := newSessionManager(path, false)

	const n = 40
	var wg sync.WaitGroup
	wg.Add(n)
	ids := make([]string, n)
	var mu sync.Mutex
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			id, err := sm.create(fmt.Sprintf("u%d", i), roleViewer)
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			mu.Lock()
			ids[i] = id
			mu.Unlock()
		}()
	}
	wg.Wait()

	sm2 := newSessionManager(path, false)
	missing := 0
	for _, id := range ids {
		if id == "" {
			missing++
			continue
		}
		if _, ok := sm2.get(id); !ok {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("lost %d/%d sessions after concurrent create", missing, n)
	}
}

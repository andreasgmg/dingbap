package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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

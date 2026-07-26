package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomicRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "meta.json")
	body := []byte(`{"ok":true}`)
	if err := writeFileAtomic(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %s", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("tmp file should be gone")
	}
}

func TestHashPasswordUsesRaisedTimeCost(t *testing.T) {
	h, err := hashPassword("password12")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h, ",t=3,") {
		t.Fatalf("expected t=3 in hash, got %s", h)
	}
	ok, err := verifyPassword(h, "password12")
	if err != nil || !ok {
		t.Fatal("verify failed")
	}
}

func TestAuthenticateUnknownUserStillRunsDummyHash(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("alice", "password12", roleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.authenticate("nosuch", "password12"); err != errInvalidCredentials {
		t.Fatalf("want invalid credentials, got %v", err)
	}
	// Dummy hash must be initialized after a miss.
	if dummyPasswordHash() == "" {
		t.Fatal("dummy hash empty")
	}
}

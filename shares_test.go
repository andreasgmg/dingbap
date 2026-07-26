package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShareCreateAndResolve(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	mustWrite(t, filepath.Join(root, "doc.txt"), "hello share")

	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	shares = store

	sh, err := store.create("doc.txt", "admin", shareExpiry24h, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !validShareToken(sh.Token) {
		t.Fatalf("bad token %q", sh.Token)
	}
	if sh.ExpiresAt == nil {
		t.Fatal("expected expiry")
	}

	got, err := store.getValid(sh.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "doc.txt" {
		t.Fatalf("path %q", got.Path)
	}

	// Traversal in stored path must fail at serve-time via safePath
	store.mu.Lock()
	store.Shares[0].Path = "../../etc/passwd"
	_ = store.saveLocked()
	store.mu.Unlock()

	abs, err := safePath(store.Shares[0].Path)
	if err == nil && !withinRoot(mustAbs(t, root), abs) {
		t.Fatal("escaped root")
	}
	// After Clean("/"+../../etc/passwd) this becomes etc/passwd under root — still inside.
	if abs == "/etc/passwd" {
		t.Fatal("resolved to host passwd")
	}
}

func TestShareOneDownload(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	mustWrite(t, filepath.Join(root, "once.bin"), "x")

	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := store.create("once.bin", "admin", shareExpiry1Download, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if sh.MaxDownloads != 1 {
		t.Fatal("expected max 1")
	}
	if err := store.beginDownload(sh.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.getValid(sh.Token); err == nil {
		t.Fatal("expected share gone after one download")
	}
	if err := store.beginDownload(sh.Token); err == nil {
		t.Fatal("second beginDownload must fail")
	}
}

func TestShareBeginDownloadSerializesQuota(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "once.bin"), "x")
	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := store.create("once.bin", "admin", shareExpiry1Download, "", "")
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			errs <- store.beginDownload(sh.Token)
		}()
	}
	ok, fail := 0, 0
	for i := 0; i < n; i++ {
		if err := <-errs; err == nil {
			ok++
		} else {
			fail++
		}
	}
	if ok != 1 || fail != n-1 {
		t.Fatalf("ok=%d fail=%d want 1 success and %d failures", ok, fail, n-1)
	}
}

func TestShareExpired(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	mustWrite(t, filepath.Join(root, "old.txt"), "x")
	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	sh, err := store.create("old.txt", "admin", shareExpiry24h, "", "")
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	store.mu.Lock()
	store.Shares[0].ExpiresAt = &past
	_ = store.saveLocked()
	store.mu.Unlock()

	if _, err := store.getValid(sh.Token); err == nil {
		t.Fatal("expected expired")
	}
}

func TestShareRewriteOnRename(t *testing.T) {
	dir := t.TempDir()
	store, err := openShareStore(filepath.Join(dir, "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	store.Shares = []Share{{Token: "aa", Path: "a/b.txt", Name: "b.txt"}}
	store.rewritePathPrefix("a/b.txt", "a/c.txt")
	if store.Shares[0].Path != "a/c.txt" || store.Shares[0].Name != "c.txt" {
		t.Fatalf("%+v", store.Shares[0])
	}
	_ = os.Remove(filepath.Join(dir, "shares.json"))
}

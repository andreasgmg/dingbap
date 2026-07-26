package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChunkedUploadAssemble(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	meta := filepath.Join(storage, ".dingbap")
	um, err := newUploadManager(meta)
	if err != nil {
		t.Fatal(err)
	}
	uploads = um
	maxUploadBytes = 50 << 20

	payload := bytes.Repeat([]byte("abcdefghij"), 300000) // ~3MB
	chunkSize := int64(1 << 20)                          // 1MB
	m, _, err := um.init("", "big.bin", int64(len(payload)), chunkSize, "admin")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < m.TotalChunks; i++ {
		start := int64(i) * chunkSize
		end := start + chunkSize
		if end > int64(len(payload)) {
			end = int64(len(payload))
		}
		if err := um.writeChunk(m.ID, i, bytes.NewReader(payload[start:end]), end-start); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}

	name, err := um.complete(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if name != "big.bin" {
		t.Fatalf("name %q", name)
	}
	got, err := os.ReadFile(filepath.Join(rootDir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("assembled size %d want %d", len(got), len(payload))
	}
	if _, err := os.Stat(um.sessionDir(m.ID)); !os.IsNotExist(err) {
		t.Fatal("session dir should be removed")
	}
}

func TestChunkedUploadRejectsBadDest(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	_ = configureStorageRoot(storage)
	um, err := newUploadManager(filepath.Join(storage, ".dingbap"))
	if err != nil {
		t.Fatal(err)
	}
	// Dot-prefixed destinations are rejected by safePath.
	_, _, err = um.init(".dingbap", "evil.txt", 10, 1024, "admin")
	if err == nil {
		t.Fatal("expected invalid destination path")
	}
}

func TestChunkedUploadNestedRelativePath(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	_ = configureStorageRoot(storage)
	um, err := newUploadManager(filepath.Join(storage, ".dingbap"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("nested folder upload")
	m, _, err := um.init("inbox", "Album/vacation/photo.jpg", int64(len(payload)), 1024, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "photo.jpg" {
		t.Fatalf("name %q", m.Name)
	}
	if m.Path != "inbox/Album/vacation" {
		t.Fatalf("path %q", m.Path)
	}
	dir := filepath.Join(rootDir, "inbox", "Album", "vacation")
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected nested dirs: %v", err)
	}
	if err := um.writeChunk(m.ID, 0, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatal(err)
	}
	if _, err := um.complete(m.ID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "photo.jpg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch")
	}
}

func TestChunkedUploadRejectsDotDotInName(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	_ = configureStorageRoot(storage)
	um, err := newUploadManager(filepath.Join(storage, ".dingbap"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../evil.txt", "a/../b.txt", ".hidden/x.txt", "ok/.secret"} {
		if _, _, err := um.init("", name, 10, 1024, "admin"); err == nil {
			t.Fatalf("expected reject for %q", name)
		}
	}
}

func TestChunkedUploadResumeStatus(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	um, err := newUploadManager(filepath.Join(storage, ".dingbap"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("hello world chunked")
	m, _, err := um.init("", "hello.txt", int64(len(payload)), 8, "admin")
	if err != nil {
		t.Fatal(err)
	}
	// write only first chunk
	end := 8
	if end > len(payload) {
		end = len(payload)
	}
	if err := um.writeChunk(m.ID, 0, bytes.NewReader(payload[:end]), int64(end)); err != nil {
		t.Fatal(err)
	}
	got := um.receivedList(um.active[m.ID])
	if len(got) != 1 || got[0] != 0 {
		t.Fatalf("received=%v", got)
	}
}

func TestUploadAbortNotFound(t *testing.T) {
	storage := t.TempDir()
	rootDir = storage
	_ = configureStorageRoot(storage)
	um, err := newUploadManager(filepath.Join(storage, ".dingbap"))
	if err != nil {
		t.Fatal(err)
	}
	err = um.abort("0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected not found")
	}
}

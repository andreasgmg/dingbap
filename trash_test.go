package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTrashMoveRestorePurge(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	mustWrite(t, filepath.Join(root, "docs", "a.txt"), "hello")

	store, err := openTrashStore(root)
	if err != nil {
		t.Fatal(err)
	}
	trash = store

	item, err := store.moveToTrash("docs/a.txt", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "a.txt")); !os.IsNotExist(err) {
		t.Fatal("source should be gone")
	}
	if _, err := os.Stat(store.itemPath(item.ID)); err != nil {
		t.Fatal(err)
	}

	path, err := store.restore(item.ID)
	if err != nil {
		t.Fatal(err)
	}
	if path != "docs/a.txt" {
		t.Fatalf("path %q", path)
	}
	got, err := os.ReadFile(filepath.Join(root, "docs", "a.txt"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("restore failed: %v %q", err, got)
	}

	item2, err := store.moveToTrash("docs/a.txt", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.purge(item2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.itemPath(item2.ID)); !os.IsNotExist(err) {
		t.Fatal("purged item should be gone")
	}
}

func TestTrashAutoExpire(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	mustWrite(t, filepath.Join(root, "old.txt"), "x")
	store, err := openTrashStore(root)
	if err != nil {
		t.Fatal(err)
	}
	item, err := store.moveToTrash("old.txt", "admin")
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	for i := range store.Items {
		if store.Items[i].ID == item.ID {
			store.Items[i].DeletedAt = time.Now().UTC().Add(-31 * 24 * time.Hour)
		}
	}
	_ = store.saveLocked()
	store.mu.Unlock()

	n := store.purgeExpired(30 * 24 * time.Hour)
	if n != 1 {
		t.Fatalf("purged %d", n)
	}
}

func TestIsTrashPath(t *testing.T) {
	if !isTrashPath(".trash") || !isTrashPath(".trash/items/x") {
		t.Fatal("expected trash paths")
	}
	if isTrashPath("docs") || isTrashPath("trash") {
		t.Fatal("false positive")
	}
}

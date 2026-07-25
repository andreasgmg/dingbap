package main

import (
	"path/filepath"
	"testing"
)

func TestUserCRUD(t *testing.T) {
	dir := t.TempDir()
	store, err := openUserStore(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("admin", "password1", roleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("friend", "password2", roleViewer); err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("friend", "password2", roleViewer); err == nil {
		t.Fatal("expected duplicate error")
	}
	if err := store.addUser("x", "short", roleViewer); err == nil {
		t.Fatal("expected short password error")
	}

	list := store.listPublic()
	if len(list) != 2 || list[0].PasswordHash != "" {
		t.Fatalf("listPublic %#v", list)
	}

	if err := store.setPassword("friend", "password3"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.authenticate("friend", "password3"); err != nil {
		t.Fatal(err)
	}

	// Cannot demote the only admin
	if err := store.setRole("admin", roleViewer); err == nil {
		t.Fatal("expected demote last admin error")
	}

	if err := store.setRole("friend", roleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := store.setRole("admin", roleViewer); err != nil {
		t.Fatal(err)
	}
	if err := store.deleteUser("admin"); err != nil {
		t.Fatal(err)
	}
	if err := store.deleteUser("friend"); err == nil {
		t.Fatal("cannot delete last admin")
	}
}

func TestShareFolderAndPassword(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "docs", "a.txt"), "hello")
	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	shares = store

	sh, err := store.create("docs", "admin", shareExpiry7d, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if !sh.IsDir {
		t.Fatal("expected dir share")
	}
	got, err := store.getValid(sh.Token)
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash == "" {
		t.Fatal("expected password hash stored")
	}
	ok, err := verifyPassword(got.PasswordHash, "secret")
	if err != nil || !ok {
		t.Fatal("password verify failed")
	}

	if _, err := store.create("docs", "admin", shareExpiry1Download, ""); err != nil {
		t.Fatalf("1download should allow folders: %v", err)
	}
}

func TestBulkZipPaths(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "a.txt"), "aaa")
	mustWrite(t, filepath.Join(root, "b", "c.txt"), "ccc")

	paths := uniqueNonEmptyPaths([]string{"a.txt", "a.txt", "/b/", "", "b"})
	if len(paths) != 2 {
		t.Fatalf("unique %v", paths)
	}
}

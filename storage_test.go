package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveStorageDirDefault(t *testing.T) {
	t.Setenv("DINGBAP_STORAGE_DIR", "")
	cwd := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	got, err := resolveStorageDir("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cwd, "storage")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if st, err := os.Stat(got); err != nil || !st.IsDir() {
		t.Fatalf("expected created dir: %v", err)
	}
}

func TestResolveStorageDirEnv(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "from-env")
	t.Setenv("DINGBAP_STORAGE_DIR", target)

	got, err := resolveStorageDir("")
	if err != nil {
		t.Fatal(err)
	}
	if got != target {
		t.Fatalf("got %q want %q", got, target)
	}
}

func TestResolveStorageDirFlagBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	fromEnv := filepath.Join(dir, "env")
	fromFlag := filepath.Join(dir, "flag")
	t.Setenv("DINGBAP_STORAGE_DIR", fromEnv)

	got, err := resolveStorageDir(fromFlag)
	if err != nil {
		t.Fatal(err)
	}
	if got != fromFlag {
		t.Fatalf("got %q want %q", got, fromFlag)
	}
}

func TestResolveStorageDirRejectsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notadir")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DINGBAP_STORAGE_DIR", "")
	if _, err := resolveStorageDir(file); err == nil {
		t.Fatal("expected error for non-directory")
	}
}

func TestResolveStorageDirAbsolute(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join(dir, "rel-store")
	t.Setenv("DINGBAP_STORAGE_DIR", "")
	got, err := resolveStorageDir(rel)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("expected absolute path, got %q", got)
	}
}

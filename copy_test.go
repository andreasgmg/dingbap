package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMeasureDiskUsage(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello") // 5 bytes
	mustMkdir(t, filepath.Join(root, ".dingbap"))
	mustWrite(t, filepath.Join(root, ".dingbap", "users.json"), "12345") // 5 bytes
	mustMkdir(t, filepath.Join(root, "sub"))
	mustWrite(t, filepath.Join(root, "sub", "b.bin"), "abcdefghij") // 10 bytes

	u, err := measureDiskUsage(root)
	if err != nil {
		t.Fatal(err)
	}
	if u.UsedBytes < 20 {
		t.Fatalf("used %d, want at least 20", u.UsedBytes)
	}
	if u.TotalBytes <= 0 || u.FreeBytes < 0 {
		t.Fatalf("bad fs stats: %+v", u)
	}
	if u.FreeBytes > u.TotalBytes {
		t.Fatalf("free > total: %+v", u)
	}
}

func TestCopyNameCandidate(t *testing.T) {
	cases := []struct {
		name string
		n    int
		want string
	}{
		{"photo.jpg", 0, "photo.jpg"},
		{"photo.jpg", 1, "photo copy.jpg"},
		{"photo.jpg", 2, "photo copy 2.jpg"},
		{"readme", 1, "readme copy"},
		{"archive.tar.gz", 1, "archive.tar copy.gz"}, // Ext = last suffix only
	}
	for _, c := range cases {
		if got := copyNameCandidate(c.name, c.n); got != c.want {
			t.Fatalf("%q n=%d: got %q want %q", c.name, c.n, got, c.want)
		}
	}
}

func TestUniqueCopyName(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "a.txt"), "1")
	mustWrite(t, filepath.Join(dir, "a copy.txt"), "2")
	got := uniqueCopyName(dir, "a.txt")
	if got != "a copy 2.txt" {
		t.Fatalf("got %q", got)
	}
}

func TestCopyPathFileAndDir(t *testing.T) {
	root := t.TempDir()
	srcFile := filepath.Join(root, "src.txt")
	mustWrite(t, srcFile, "payload")
	dstFile := filepath.Join(root, "dst.txt")
	info, err := os.Stat(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyPath(srcFile, dstFile, info); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dstFile)
	if err != nil || string(b) != "payload" {
		t.Fatalf("dst content %q err=%v", b, err)
	}

	srcDir := filepath.Join(root, "folder")
	mustMkdir(t, srcDir)
	mustWrite(t, filepath.Join(srcDir, "inner.txt"), "in")
	mustMkdir(t, filepath.Join(srcDir, "nested"))
	mustWrite(t, filepath.Join(srcDir, "nested", "x.txt"), "x")
	mustWrite(t, filepath.Join(srcDir, ".hidden"), "skip")

	dstDir := filepath.Join(root, "folder-out")
	dinfo, err := os.Stat(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyPath(srcDir, dstDir, dinfo); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "inner.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "nested", "x.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, ".hidden")); !os.IsNotExist(err) {
		t.Fatal("expected hidden file to be skipped")
	}
}

func TestCopyPathRefusesOversize(t *testing.T) {
	prev := copyMaxBytes
	copyMaxBytes = 4
	t.Cleanup(func() { copyMaxBytes = prev })

	root := t.TempDir()
	src := filepath.Join(root, "big.txt")
	mustWrite(t, src, "12345")
	info, _ := os.Stat(src)
	if err := copyPath(src, filepath.Join(root, "out.txt"), info); err == nil {
		t.Fatal("expected size limit error")
	}
}

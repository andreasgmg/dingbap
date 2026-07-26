package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUnderRoot_StaysInside(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "ok.txt"), "safe")
	mustMkdir(t, filepath.Join(root, "etc", "evil"))
	mustWrite(t, filepath.Join(root, "etc", "evil", "ba.txt"), "inside")
	realRoot := mustAbs(t, root)

	cases := []struct {
		name     string
		req      string
		wantBase string
		wantRel  string // relative to root; empty skips
		wantErr  bool
	}{
		{"plain file", "ok.txt", "ok.txt", "ok.txt", false},
		{"nested archive path", "etc/evil/ba.txt", "ba.txt", "etc/evil/ba.txt", false},
		// Clean("/"+req) collapses .. into a path still under root — must NOT touch system /etc.
		{"dotdot collapse", "../../etc/passwd", "passwd", "etc/passwd", false},
		{"dotdot slash", "/../../etc/passwd", "passwd", "etc/passwd", false},
		{"dotdot mid", "etc/../../etc/passwd", "passwd", "etc/passwd", false},
		{"dotdot deep", "etc/evil/../../../etc/passwd", "passwd", "etc/passwd", false},
		{"absolute looks like host path", "/etc/passwd", "passwd", "etc/passwd", false},
		{"null byte", "ok.txt\x00.jpg", "", "", true},
		{"empty is root", "", filepath.Base(realRoot), ".", false},
		{"dot is root", ".", filepath.Base(realRoot), ".", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveUnderRoot(root, tc.req)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if !withinRoot(realRoot, got) {
				t.Fatalf("escaped root: %q", got)
			}
			// Critical: never resolve to the real host /etc/passwd
			if got == "/etc/passwd" {
				t.Fatalf("served host path %q", got)
			}
			if tc.wantBase != "" && filepath.Base(got) != tc.wantBase {
				t.Fatalf("got base %q want %q (full %q)", filepath.Base(got), tc.wantBase, got)
			}
			if tc.wantRel != "" {
				rel, err := filepath.Rel(realRoot, got)
				if err != nil {
					t.Fatal(err)
				}
				if filepath.ToSlash(rel) != tc.wantRel {
					t.Fatalf("rel=%q want %q", rel, tc.wantRel)
				}
			}
		})
	}
}

func TestResolveUnderRoot_SymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "nope")

	link := filepath.Join(root, "evil")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}

	_, err := resolveUnderRoot(root, "evil/secret.txt")
	if err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestResolveUnderRoot_SymlinkInside(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "real"))
	mustWrite(t, filepath.Join(root, "real", "a.txt"), "ok")
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}

	got, err := resolveUnderRoot(root, "link/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "a.txt" {
		t.Fatalf("got %q", got)
	}
	if !withinRoot(mustAbs(t, root), got) {
		t.Fatalf("escaped: %q", got)
	}
}

func TestWithinRoot_PrefixFootgun(t *testing.T) {
	root := "/tmp/data"
	if withinRoot(root, "/tmp/data-evil/x") {
		t.Fatal("data-evil must not count as inside data")
	}
	if !withinRoot(root, "/tmp/data/x") {
		t.Fatal("expected inside")
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return abs
	}
	return resolved
}

func TestResolveUnderRoot_DeniesHiddenSegments(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, ".dingbap"))
	mustWrite(t, filepath.Join(root, ".dingbap", "users.json"), `{"users":[]}`)
	mustMkdir(t, filepath.Join(root, ".trash", "items", "abc"))
	mustWrite(t, filepath.Join(root, ".trash", "items", "abc", "secret.txt"), "deleted")
	mustMkdir(t, filepath.Join(root, "docs", ".hidden"))
	mustWrite(t, filepath.Join(root, "docs", ".hidden", "x.txt"), "nope")
	mustWrite(t, filepath.Join(root, "docs", "ok.txt"), "yes")

	denied := []string{
		".dingbap",
		".dingbap/users.json",
		".dingbap/sessions.json",
		".trash",
		".trash/trash_info.json",
		".trash/items/abc/secret.txt",
		"docs/.hidden",
		"docs/.hidden/x.txt",
		"/.dingbap/users.json",
		"docs/../.dingbap/users.json",
	}
	for _, req := range denied {
		t.Run("deny_"+req, func(t *testing.T) {
			got, err := resolveUnderRoot(root, req)
			if err == nil {
				t.Fatalf("expected deny, got %q", got)
			}
		})
	}

	got, err := resolveUnderRoot(root, "docs/ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "ok.txt" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveUnderRoot_DeniesSymlinkIntoHidden(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, ".dingbap"))
	mustWrite(t, filepath.Join(root, ".dingbap", "users.json"), `{}`)
	mustMkdir(t, filepath.Join(root, ".trash", "items"))
	if err := os.Symlink(filepath.Join(root, ".dingbap"), filepath.Join(root, "evil")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, ".trash"), filepath.Join(root, "bin")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}

	for _, req := range []string{"evil", "evil/users.json", "bin", "bin/items"} {
		if _, err := resolveUnderRoot(root, req); err == nil {
			t.Fatalf("expected deny for symlink into hidden via %q", req)
		}
	}

	// Symlink to a normal folder still works.
	mustMkdir(t, filepath.Join(root, "real"))
	mustWrite(t, filepath.Join(root, "real", "a.txt"), "ok")
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	got, err := resolveUnderRoot(root, "link/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "a.txt" {
		t.Fatalf("got %q", got)
	}
}

func TestSafePathDeniesMetaEvenWhenRootConfigured(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, ".dingbap", "users.json"), "{}")
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	if _, err := safePath(".dingbap/users.json"); err == nil {
		t.Fatal("safePath must deny .dingbap")
	}
	if _, err := assertUserContentPath(".trash/items/x"); err == nil {
		t.Fatal("assertUserContentPath must deny .trash")
	}
}

func TestConfigureStorageRootCachesEval(t *testing.T) {
	root := t.TempDir()
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	got, err := resolveUnderRoot(root, "")
	if err != nil {
		t.Fatal(err)
	}
	want, ok := cachedRealRoot(root)
	if !ok || got != want {
		t.Fatalf("got %q cached %q ok=%v", got, want, ok)
	}
}


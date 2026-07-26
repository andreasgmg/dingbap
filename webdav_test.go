package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDAVPathDeniesHidden(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, ".dingbap"))
	mustWrite(t, filepath.Join(root, "ok.txt"), "x")
	prev := rootDir
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rootDir = prev })

	if _, err := resolveDAVPath(".dingbap/users.json"); err == nil {
		t.Fatal("expected deny")
	}
	if _, err := resolveDAVPath("ok.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestDAVFSReadOnly(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	mustMkdir(t, filepath.Join(root, "sub"))
	mustWrite(t, filepath.Join(root, "sub", "b.txt"), "b")
	mustWrite(t, filepath.Join(root, ".secret"), "nope")
	prev := rootDir
	rootDir = root
	_ = configureStorageRoot(root)
	t.Cleanup(func() { rootDir = prev })

	fs := dingbapDAVFS{}
	ctx := context.Background()
	if err := fs.Mkdir(ctx, "/new", 0755); err != os.ErrPermission {
		t.Fatalf("Mkdir: %v", err)
	}
	if _, err := fs.OpenFile(ctx, "/a.txt", os.O_WRONLY, 0644); err != os.ErrPermission {
		t.Fatalf("OpenFile write: %v", err)
	}
	f, err := fs.OpenFile(ctx, "/a.txt", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("x")); err != os.ErrPermission {
		t.Fatalf("Write: %v", err)
	}

	dir, err := fs.OpenFile(ctx, "/", os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	infos, err := dir.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range infos {
		if stringsHasPrefixDot(info.Name()) {
			t.Fatalf("hidden entry leaked: %s", info.Name())
		}
	}
}

func stringsHasPrefixDot(name string) bool {
	return len(name) > 0 && name[0] == '.'
}

func TestWebDAVRequiresAuthAndBlocksWrites(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "readme.txt"), "hi")
	store, err := openUserStore(filepath.Join(root, "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.addUser("viewer", "password12", roleViewer); err != nil {
		t.Fatal(err)
	}

	prevRoot, prevUsers, prevSess := rootDir, users, sessions
	rootDir = root
	_ = configureStorageRoot(root)
	users = store
	sessions = newSessionManager("", false)
	t.Cleanup(func() {
		rootDir, users, sessions = prevRoot, prevUsers, prevSess
	})

	h := withSession(requireWebDAVAuth(newWebDAVHandler()))

	// No auth → 401
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("PROPFIND", "/dav/", nil)
	req.Header.Set("Depth", "0")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status %d", rr.Code)
	}

	// Basic auth → PROPFIND OK-ish (207 Multi-Status typical)
	rr = httptest.NewRecorder()
	req = httptest.NewRequest("PROPFIND", "/dav/", nil)
	req.Header.Set("Depth", "1")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("viewer:password12")))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMultiStatus && rr.Code != http.StatusOK {
		t.Fatalf("propfind status %d body %s", rr.Code, rr.Body.String())
	}

	// PUT rejected
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPut, "/dav/evil.txt", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("viewer:password12")))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("put status %d", rr.Code)
	}

	// GET file
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/dav/readme.txt", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("viewer:password12")))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "hi" {
		t.Fatalf("get status %d body %q", rr.Code, rr.Body.String())
	}
}

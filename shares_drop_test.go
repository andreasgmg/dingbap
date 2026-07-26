package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDropShareCreateAndUpload(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	if err := configureStorageRoot(root); err != nil {
		t.Fatal(err)
	}
	mustMkdir(t, filepath.Join(root, "inbox"))
	mustWrite(t, filepath.Join(root, "inbox", "secret.txt"), "hidden")

	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	shares = store
	prevMax := maxUploadBytes
	maxUploadBytes = 1024
	t.Cleanup(func() { maxUploadBytes = prevMax })

	if _, err := store.create("inbox", "admin", shareExpiryNever, "", shareKindDrop); err == nil {
		t.Fatal("drop must require real expiry")
	}
	if _, err := store.create("secret.txt", "admin", shareExpiry24h, "", shareKindDrop); err == nil {
		t.Fatal("drop requires folder")
	}

	sh, err := store.create("inbox", "admin", shareExpiry24h, "", shareKindDrop)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Kind != shareKindDrop || sh.MaxUploads != dropDefaultMaxUploads {
		t.Fatalf("got kind=%q max=%d", sh.Kind, sh.MaxUploads)
	}

	// Upload via public handler
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("payload"))
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/s/"+sh.Token+"/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rr := httptest.NewRecorder()
	handlePublicShare(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload status %d body %s", rr.Code, rr.Body.String())
	}
	got, err := os.ReadFile(filepath.Join(root, "inbox", "hello.txt"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("file content %q err=%v", got, err)
	}

	// Drop page must not list existing files (no secret.txt in HTML).
	req = httptest.NewRequest(http.MethodGet, "/s/"+sh.Token, nil)
	rr = httptest.NewRecorder()
	handlePublicShare(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("drop page %d", rr.Code)
	}
	body := rr.Body.String()
	if bytes.Contains([]byte(body), []byte("secret.txt")) {
		t.Fatal("drop page must not reveal existing folder contents")
	}
	if !bytes.Contains([]byte(body), []byte("drop")) && !bytes.Contains([]byte(body), []byte("Drop")) {
		t.Fatal("expected drop upload UI")
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !bytes.Contains([]byte(csp), []byte("script-src")) || !bytes.Contains([]byte(csp), []byte("connect-src")) {
		t.Fatalf("drop page CSP must allow scripts + XHR, got %q", csp)
	}

	// JSON upload (progress UI)
	buf.Reset()
	w = multipart.NewWriter(&buf)
	part, err = w.CreateFormFile("file", "via-json.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("json-ok"))
	_ = w.Close()
	req = httptest.NewRequest(http.MethodPost, "/s/"+sh.Token+"/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	rr = httptest.NewRecorder()
	handlePublicShare(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("json upload %d %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"ok":true`)) {
		t.Fatalf("expected json ok: %s", rr.Body.String())
	}
	got, err = os.ReadFile(filepath.Join(root, "inbox", "via-json.txt"))
	if err != nil || string(got) != "json-ok" {
		t.Fatalf("json file %q err=%v", got, err)
	}
}

func TestDropShareUploadQuota(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	_ = configureStorageRoot(root)
	mustMkdir(t, filepath.Join(root, "inbox"))
	store, err := openShareStore(filepath.Join(t.TempDir(), "shares.json"))
	if err != nil {
		t.Fatal(err)
	}
	shares = store
	sh, err := store.create("inbox", "admin", shareExpiry7d, "", shareKindDrop)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.Shares[0].MaxUploads = 1
	_ = store.saveLocked()
	store.mu.Unlock()

	if err := store.beginUpload(sh.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := store.getValid(sh.Token); err == nil {
		t.Fatal("share should be expired after upload quota")
	}
}

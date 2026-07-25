package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleSearch(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	invalidateListingCache()
	mustWrite(t, filepath.Join(root, "docs", "report.pdf"), "pdf")
	mustWrite(t, filepath.Join(root, "docs", "notes.txt"), "txt")
	mustWrite(t, filepath.Join(root, ".trash", "items", "x", "secret.txt"), "nope")
	mustMkdir(t, filepath.Join(root, "photos"))
	mustWrite(t, filepath.Join(root, "photos", "cat.png"), "img")

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=note", nil)
	rr := httptest.NewRecorder()
	handleSearch(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	var body struct {
		OK      bool        `json:"ok"`
		Results []searchHit `json:"results"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || len(body.Results) != 1 || body.Results[0].Name != "notes.txt" {
		t.Fatalf("%+v", body)
	}

	// Second query must hit the warm listing cache (no need to re-walk disk).
	if _, ok := dirCache.get(""); !ok {
		t.Fatal("expected root listing to be cached after search")
	}
	if _, ok := dirCache.get("docs"); !ok {
		t.Fatal("expected docs listing to be cached after search")
	}

	// trash must not appear
	req = httptest.NewRequest(http.MethodGet, "/api/search?q=secret", nil)
	rr = httptest.NewRecorder()
	handleSearch(rr, req)
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if len(body.Results) != 0 {
		t.Fatalf("leaked trash: %+v", body.Results)
	}

	// symlink escape must not be followed into results outside root
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "passwd.txt"), "x")
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Skip(err)
	}
	invalidateListingCache() // force re-list so evil is considered
	req = httptest.NewRequest(http.MethodGet, "/api/search?q=passwd", nil)
	rr = httptest.NewRecorder()
	handleSearch(rr, req)
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if len(body.Results) != 0 {
		t.Fatalf("leaked symlink target: %+v", body.Results)
	}
	for _, hit := range body.Results {
		if !withinRoot(mustAbs(t, root), filepath.Join(root, filepath.FromSlash(hit.Path))) {
			t.Fatalf("suspicious hit %+v", hit)
		}
	}
}

func TestSearchUsesTreeCache(t *testing.T) {
	root := t.TempDir()
	rootDir = root
	invalidateListingCache()
	mustWrite(t, filepath.Join(root, "alpha", "beta.txt"), "x")

	// Warm cache via tree API (as the UI does while browsing).
	rr := httptest.NewRecorder()
	handleTree(rr, httptest.NewRequest(http.MethodGet, "/api/tree?path=", nil))
	if rr.Code != 200 {
		t.Fatalf("tree status %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	handleTree(rr, httptest.NewRequest(http.MethodGet, "/api/tree?path=alpha", nil))
	if rr.Code != 200 {
		t.Fatalf("tree status %d", rr.Code)
	}

	hits, limited := searchInTree("beta", 100)
	if limited || len(hits) != 1 || hits[0].Path != "alpha/beta.txt" {
		t.Fatalf("hits=%+v limited=%v", hits, limited)
	}
}

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGzipMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.Repeat("<p>hello dingbap</p>", 200))
	})
	h := withGzip(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("expected gzip, got %q", rr.Header().Get("Content-Encoding"))
	}
	if !strings.Contains(rr.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatal("expected Vary")
	}
	if rr.Body.Len() == 0 {
		t.Fatal("empty body")
	}
}

func TestGzipSkipsImages(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47})
	})
	h := withGzip(inner)
	req := httptest.NewRequest(http.MethodGet, "/x.png", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Header().Get("Content-Encoding") == "gzip" {
		t.Fatal("should not gzip images")
	}
}

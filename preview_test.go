package main

import "testing"

func TestPreviewContentType(t *testing.T) {
	cases := []struct {
		name     string
		wantType string
		wantKind string
	}{
		{"photo.PNG", "image/png", "image"},
		{"a.jpg", "image/jpeg", "image"},
		{"a.jpeg", "image/jpeg", "image"},
		{"a.webp", "image/webp", "image"},
		{"doc.pdf", "application/pdf", "pdf"},
		{"clip.mp4", "video/mp4", "video"},
		{"clip.webm", "video/webm", "video"},
		{"readme.txt", "text/plain; charset=utf-8", "text"},
		{"data.json", "application/json", "text"},
		{"README.md", "text/plain; charset=utf-8", "text"},
		{"main.go", "text/plain; charset=utf-8", "text"},
		{"evil.html", "", ""},
		{"script.js", "", ""},
		{"archive.zip", "", ""},
	}
	for _, tc := range cases {
		ctype, kind := previewContentType(tc.name)
		if ctype != tc.wantType || kind != tc.wantKind {
			t.Fatalf("%s: got (%q,%q) want (%q,%q)", tc.name, ctype, kind, tc.wantType, tc.wantKind)
		}
	}
}

func TestContentDispositionInline(t *testing.T) {
	got := contentDispositionInline("report.pdf")
	if got[:6] != "inline" {
		t.Fatalf("expected inline, got %q", got)
	}
	att := contentDisposition("report.pdf")
	if att[:10] != "attachment" {
		t.Fatalf("expected attachment, got %q", att)
	}
}

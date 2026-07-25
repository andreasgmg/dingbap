package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

var gzipWriterPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz            *gzip.Writer
	wroteHeader   bool
	shouldCompress bool
	checked       bool
}

func (w *gzipResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.decide()
	if w.shouldCompress {
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.shouldCompress {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipResponseWriter) Flush() {
	if w.shouldCompress && w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipResponseWriter) decide() {
	if w.checked {
		return
	}
	w.checked = true
	if w.Header().Get("Content-Encoding") != "" {
		w.shouldCompress = false
		return
	}
	ct := w.Header().Get("Content-Type")
	w.shouldCompress = compressibleContentType(ct)
}

func compressibleContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if ct == "" {
		// Handlers often set Content-Type on first Write via ServeContent; allow gzip and let
		// sniffing happen — but if empty at header time, still compress HTML/JSON/JS paths.
		return true
	}
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case strings.HasPrefix(ct, "application/json"):
		return true
	case strings.HasPrefix(ct, "application/javascript"):
		return true
	case strings.Contains(ct, "javascript"):
		return true
	case strings.HasPrefix(ct, "application/xml"):
		return true
	case strings.HasPrefix(ct, "image/svg+xml"):
		return true
	default:
		return false
	}
}

func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// Don't wrap upload/chunk bodies oddly — responses are small JSON; compression is fine.
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		grw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
		defer func() {
			if grw.wroteHeader && grw.shouldCompress {
				_ = gz.Close()
			}
			gz.Reset(io.Discard)
			gzipWriterPool.Put(gz)
		}()
		next.ServeHTTP(grw, r)
	})
}

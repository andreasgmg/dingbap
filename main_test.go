package main

import (
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeUntilStopDrainsInFlight(t *testing.T) {
	var started, finished atomic.Bool
	release := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		started.Store(true)
		<-release
		_, _ = io.WriteString(w, "done")
		finished.Store(true)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}

	stop := make(chan struct{})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveUntilStop(srv, func() error { return srv.Serve(ln) }, stop, 2*time.Second)
	}()

	// Wait until the server accepts connections.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			t.Errorf("in-flight GET: %v", err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "done" {
			t.Errorf("body %q", body)
		}
	}()

	deadline = time.Now().Add(2 * time.Second)
	for !started.Load() {
		if time.Now().After(deadline) {
			t.Fatal("handler never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	close(stop) // simulate SIGTERM
	time.Sleep(50 * time.Millisecond)

	// New connections must be rejected after Shutdown begins.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Error("expected new connections to fail after shutdown started")
	}

	close(release) // let the in-flight handler finish
	wg.Wait()

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveUntilStop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serveUntilStop did not return")
	}

	if !finished.Load() {
		t.Fatal("in-flight handler did not finish during drain")
	}
}

func TestServeUntilStopForceCloseWhenDrainExceedsGrace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stuck", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = io.WriteString(w, "late")
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux}

	stop := make(chan struct{})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveUntilStop(srv, func() error { return srv.Serve(ln) }, stop, 100*time.Millisecond)
	}()

	go func() {
		_, _ = http.Get("http://" + ln.Addr().String() + "/stuck")
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serveUntilStop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected force-close to return promptly after grace")
	}
}

package main

import (
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed layout.html login.html share.html
var templateFS embed.FS

var (
	layoutTpl *template.Template
	loginTpl  *template.Template
	rootDir   string
	users     *userStore
	sessions  *sessionManager
	publicOpen bool
)

func init() {
	var err error
	layoutTpl, err = template.ParseFS(templateFS, "layout.html")
	if err != nil {
		log.Fatalf("Failed to parse layout template: %v", err)
	}
	loginTpl, err = template.ParseFS(templateFS, "login.html")
	if err != nil {
		log.Fatalf("Failed to parse login template: %v", err)
	}
	shareTpl, err = template.ParseFS(templateFS, "share.html")
	if err != nil {
		log.Fatalf("Failed to parse share template: %v", err)
	}
}

type pageData struct {
	Admin    bool
	Username string
	Role     string
}

func main() {
	port := flag.Int("port", 8080, "Server port")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate (PEM)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key (PEM)")
	storageDirFlag := flag.String("storage-dir", "", "File storage directory (default ./storage; env DINGBAP_STORAGE_DIR)")
	flag.Parse()

	if envPort := os.Getenv("PORT"); envPort != "" {
		fmt.Sscanf(envPort, "%d", port)
	}
	if v := os.Getenv("TLS_CERT"); v != "" && *tlsCert == "" {
		*tlsCert = v
	}
	if v := os.Getenv("TLS_KEY"); v != "" && *tlsKey == "" {
		*tlsKey = v
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("Config error: -tls-cert and -tls-key must both be set, or both omitted")
	}

	useTLS := *tlsCert != "" && *tlsKey != ""
	secureCookie := useTLS || envTruthy("COOKIE_SECURE")

	publicOpen = envTruthy("PUBLIC_OPEN")
	maxUploadBytes = loadMaxUploadBytes()

	storageDir, err := resolveStorageDir(*storageDirFlag)
	if err != nil {
		log.Fatalf("Storage: %v", err)
	}
	rootDir = storageDir
	if err := configureStorageRoot(storageDir); err != nil {
		log.Fatalf("Storage root: %v", err)
	}

	metaDir := filepath.Join(storageDir, ".dingbap")
	if err := os.MkdirAll(metaDir, 0700); err != nil {
		log.Fatalf("Failed to create metadata dir: %v", err)
	}

	users, err = openUserStore(filepath.Join(metaDir, "users.json"))
	if err != nil {
		log.Fatalf("Failed to load users: %v", err)
	}
	if err := bootstrapUsers(users); err != nil {
		log.Fatalf("Config error: %v", err)
	}

	shares, err = openShareStore(filepath.Join(metaDir, "shares.json"))
	if err != nil {
		log.Fatalf("Failed to load shares: %v", err)
	}

	trash, err = openTrashStore(rootDir)
	if err != nil {
		log.Fatalf("Failed to init trash: %v", err)
	}
	startTrashJanitor(trash)

	uploads, err = newUploadManager(metaDir)
	if err != nil {
		log.Fatalf("Failed to init upload manager: %v", err)
	}

	sessions = newSessionManager(filepath.Join(metaDir, "sessions.json"), secureCookie)

	// Public archive routes
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("/", handlePagePublic)
	publicMux.HandleFunc("/download/", handleDownload)
	publicMux.HandleFunc("/preview/", handlePreview)
	publicMux.HandleFunc("/api/tree", handleTree)
	publicMux.HandleFunc("/api/search", handleSearch)
	publicMux.Handle("/api/zip", requireCSRF(http.HandlerFunc(handleZip)))

	// Admin routes
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin", handlePageAdmin)
	adminMux.HandleFunc("/admin/upload", handleUpload)
	adminMux.HandleFunc("/admin/upload/init", handleUploadInit)
	adminMux.HandleFunc("/admin/upload/chunk", handleUploadChunk)
	adminMux.HandleFunc("/admin/upload/status", handleUploadStatus)
	adminMux.HandleFunc("/admin/upload/complete", handleUploadComplete)
	adminMux.HandleFunc("/admin/upload/abort", handleUploadAbort)
	adminMux.HandleFunc("/admin/mkdir", handleMkdir)
	adminMux.HandleFunc("/admin/rename", handleRename)
	adminMux.HandleFunc("/admin/delete", handleDelete)
	adminMux.HandleFunc("/admin/move", handleMove)
	adminMux.HandleFunc("/admin/bulk/delete", handleBulkDelete)
	adminMux.HandleFunc("/admin/bulk/move", handleBulkMove)
	adminMux.HandleFunc("/admin/bulk/zip", handleZip)
	adminMux.HandleFunc("/admin/share", handleCreateShare)
	adminMux.HandleFunc("/admin/share/revoke", handleRevokeShare)
	adminMux.HandleFunc("/admin/api/tree", handleTree)
	adminMux.HandleFunc("/admin/api/search", handleSearch)
	adminMux.HandleFunc("/admin/api/trash", handleTrashList)
	adminMux.HandleFunc("/admin/api/shares", handleListShares)
	adminMux.HandleFunc("/admin/api/users", handleUsersList)
	adminMux.HandleFunc("/admin/users", handleUsersCreate)
	adminMux.HandleFunc("/admin/users/delete", handleUsersDelete)
	adminMux.HandleFunc("/admin/users/password", handleUsersSetPassword)
	adminMux.HandleFunc("/admin/users/role", handleUsersSetRole)
	adminMux.HandleFunc("/admin/trash/restore", handleTrashRestore)
	adminMux.HandleFunc("/admin/trash/purge", handleTrashPurge)
	adminMux.HandleFunc("/admin/trash/empty", handleTrashEmpty)

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/login", handleLoginAPI)
	mux.HandleFunc("/api/logout", handleLogoutAPI)
	mux.HandleFunc("/api/me", handleMeAPI)
	mux.Handle("/api/password", requireCSRF(http.HandlerFunc(handleChangeOwnPassword)))
	// Public share links — no login required
	mux.HandleFunc("/s/", handlePublicShare)
	mux.Handle("/", requireViewerOrOpen(publicMux))
	mux.Handle("/admin", requireAdmin(requireCSRF(adminMux)))
	mux.Handle("/admin/", requireAdmin(requireCSRF(adminMux)))

	handler := withGzip(withSession(mux))

	addr := fmt.Sprintf(":%d", *port)
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	log.Printf("Server starting on %s (%s)", addr, scheme)
	log.Printf("App:     %s://localhost%s/", scheme, addr)
	log.Printf("Login:   %s://localhost%s/login", scheme, addr)
	log.Printf("Admin:   %s://localhost%s/admin", scheme, addr)
	log.Printf("Storage: %s", storageDir)
	log.Printf("Upload limit: %d MB", maxUploadBytes>>20)
	if publicOpen {
		log.Printf("Public browsing is OPEN (PUBLIC_OPEN=1) — unauthenticated users can read files")
	} else {
		log.Printf("Public browsing requires login (set PUBLIC_OPEN=1 to allow anonymous read)")
	}
	if !useTLS {
		log.Printf("WARNING: running without TLS — use -tls-cert/-tls-key for remote access")
	}
	if !secureCookie {
		log.Printf("Session cookies are not Secure (set COOKIE_SECURE=1 behind HTTPS reverse proxy)")
	}

	// Timeouts: bare ListenAndServe has none (slowloris / stuck clients).
	// Read/Write are generous so large uploads/downloads still work; header timeout is strict.
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Minute,
		WriteTimeout:      15 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	if useTLS {
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	}
	log.Fatal(srv.ListenAndServe())
}

func bootstrapUsers(store *userStore) error {
	if !store.empty() {
		return nil
	}

	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASS")
	if adminUser == "" || adminPass == "" {
		return fmt.Errorf("no users.json yet — set ADMIN_USER and ADMIN_PASS to create the first admin\n\nExample:\n  ADMIN_USER=admin ADMIN_PASS='your-secret' go run .")
	}
	if err := store.addUser(adminUser, adminPass, roleAdmin); err != nil {
		return err
	}
	log.Printf("Created initial admin user %q in users.json", adminUser)

	// Optional first viewer (supports old PUBLIC_* names)
	viewerUser := os.Getenv("VIEWER_USER")
	viewerPass := os.Getenv("VIEWER_PASS")
	if viewerUser == "" && viewerPass == "" {
		viewerUser = os.Getenv("PUBLIC_USER")
		viewerPass = os.Getenv("PUBLIC_PASS")
	}
	if viewerUser != "" || viewerPass != "" {
		if viewerUser == "" || viewerPass == "" {
			return fmt.Errorf("VIEWER_USER and VIEWER_PASS must both be set, or both omitted")
		}
		if err := store.addUser(viewerUser, viewerPass, roleViewer); err != nil {
			return err
		}
		log.Printf("Created initial viewer user %q in users.json", viewerUser)
	}
	return nil
}

func envTruthy(key string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func loadMaxUploadBytes() int64 {
	v := strings.TrimSpace(os.Getenv("MAX_UPLOAD_MB"))
	if v == "" {
		return defaultMaxUploadBytes
	}
	var mb int64
	if _, err := fmt.Sscanf(v, "%d", &mb); err != nil || mb < 1 {
		log.Printf("WARNING: invalid MAX_UPLOAD_MB=%q — using default %d MB", v, defaultMaxUploadBytes>>20)
		return defaultMaxUploadBytes
	}
	return mb << 20
}

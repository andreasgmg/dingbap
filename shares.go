package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	shareExpiry24h       = "24h"
	shareExpiry7d        = "7d"
	shareExpiry30d       = "30d"
	shareExpiryNever     = "never"
	shareExpiry1Download = "1download"
	shareTokenBytes      = 32
	shareUnlockTTL       = 12 * time.Hour
	shareCookiePrefix    = "dingbap_su_"
	shareKindLink        = "link"
	shareKindDrop        = "drop"
	dropDefaultMaxUploads = 50
)

type Share struct {
	Token         string     `json:"token"`
	Path          string     `json:"path"` // relative to storage root
	Name          string     `json:"name"`
	IsDir         bool       `json:"is_dir"`
	Kind          string     `json:"kind,omitempty"` // ""/"link" = download share; "drop" = inbound upload
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	MaxDownloads  int        `json:"max_downloads,omitempty"` // 0 = unlimited (until expiry)
	DownloadCount int        `json:"download_count"`
	MaxUploads    int        `json:"max_uploads,omitempty"` // drop shares; 0 = unlimited until expiry
	UploadCount   int        `json:"upload_count,omitempty"`
	CreatedBy     string     `json:"created_by,omitempty"`
	PasswordHash  string     `json:"password_hash,omitempty"`
}

type shareStore struct {
	mu     sync.Mutex
	path   string
	Shares []Share `json:"shares"`
}

var shares *shareStore

type sharePageData struct {
	Token       string
	Name        string
	IsDir       bool
	IsDrop      bool
	NeedPass    bool
	NotFound    bool
	Error       string
	Parent      string
	ParentURL   string
	ZipURL      string
	Entries     []shareEntry
	DownloadURL string
	Size        string
	MaxSizeMB   int64
	Message     string
}

type shareEntry struct {
	Name  string
	IsDir bool
	Size  string
	URL   string
}

func openShareStore(path string) (*shareStore, error) {
	s := &shareStore{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("parse shares file: %w", err)
	}
	return s, nil
}

func (s *shareStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Shares []Share `json:"shares"`
	}{Shares: s.Shares}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0600)
}

func (s *shareStore) create(relPath, createdBy, mode, password, kind string) (*Share, error) {
	relPath = strings.Trim(relPath, "/")
	if relPath == "" {
		return nil, fmt.Errorf("cannot share the storage root")
	}

	kind = strings.TrimSpace(strings.ToLower(kind))
	if kind == "" {
		kind = shareKindLink
	}
	if kind != shareKindLink && kind != shareKindDrop {
		return nil, fmt.Errorf("invalid share kind")
	}

	abs, err := safePath(relPath)
	if err != nil {
		return nil, fmt.Errorf("invalid path")
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("path not found")
	}
	if kind == shareKindDrop && !info.IsDir() {
		return nil, fmt.Errorf("drop shares require a folder")
	}

	token, err := randomToken(shareTokenBytes)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	sh := Share{
		Token:     token,
		Path:      relPath,
		Name:      filepath.Base(relPath),
		IsDir:     info.IsDir(),
		Kind:      kind,
		CreatedAt: now,
		CreatedBy: createdBy,
	}

	password = strings.TrimSpace(password)
	if password != "" {
		if len(password) < 4 {
			return nil, fmt.Errorf("share password must be at least 4 characters")
		}
		hash, err := hashPassword(password)
		if err != nil {
			return nil, err
		}
		sh.PasswordHash = hash
	}

	if kind == shareKindDrop {
		// Drops always expire (no "never") and use an upload quota — keeps the door small.
		switch mode {
		case shareExpiry24h:
			exp := now.Add(24 * time.Hour)
			sh.ExpiresAt = &exp
		case shareExpiry7d:
			exp := now.Add(7 * 24 * time.Hour)
			sh.ExpiresAt = &exp
		case shareExpiry30d:
			exp := now.Add(30 * 24 * time.Hour)
			sh.ExpiresAt = &exp
		default:
			return nil, fmt.Errorf("drop shares require expiry (24h, 7d, or 30d)")
		}
		sh.MaxUploads = dropDefaultMaxUploads
	} else {
		switch mode {
		case shareExpiry24h:
			exp := now.Add(24 * time.Hour)
			sh.ExpiresAt = &exp
		case shareExpiry7d:
			exp := now.Add(7 * 24 * time.Hour)
			sh.ExpiresAt = &exp
		case shareExpiry30d:
			exp := now.Add(30 * 24 * time.Hour)
			sh.ExpiresAt = &exp
		case shareExpiryNever:
			// no expiry
		case shareExpiry1Download:
			sh.MaxDownloads = 1
		default:
			return nil, fmt.Errorf("invalid expiry option")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	s.Shares = append(s.Shares, sh)
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	cp := sh
	cp.PasswordHash = "" // never return hash to callers
	return &cp, nil
}

func (s *shareStore) listPublic() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().UTC())
	out := make([]map[string]any, 0, len(s.Shares))
	for _, sh := range s.Shares {
		out = append(out, map[string]any{
			"token":          sh.Token,
			"path":           sh.Path,
			"name":           sh.Name,
			"is_dir":         sh.IsDir,
			"kind":           shareKindOrLink(&sh),
			"created_at":     sh.CreatedAt,
			"expires_at":     sh.ExpiresAt,
			"max_downloads":  sh.MaxDownloads,
			"download_count": sh.DownloadCount,
			"max_uploads":    sh.MaxUploads,
			"upload_count":   sh.UploadCount,
			"created_by":     sh.CreatedBy,
			"has_password":   sh.PasswordHash != "",
		})
	}
	return out
}

func (s *shareStore) getValid(token string) (*Share, error) {
	if !validShareToken(token) {
		return nil, fmt.Errorf("not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().UTC())
	for i := range s.Shares {
		sh := &s.Shares[i]
		if sh.Token != token {
			continue
		}
		if shareExpired(sh, time.Now().UTC()) {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return nil, fmt.Errorf("expired")
		}
		cp := *sh
		return &cp, nil
	}
	return nil, fmt.Errorf("not found")
}

// beginDownload reserves one download against MaxDownloads (if set) before
// the file/zip transfer starts. This closes the parallel-click race where
// many GETs could all pass getValid before any counter increment.
// Unlimited shares (MaxDownloads == 0) still bump DownloadCount for stats.
func (s *shareStore) beginDownload(token string) error {
	if !validShareToken(token) {
		return fmt.Errorf("not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().UTC())
	for i := range s.Shares {
		if s.Shares[i].Token != token {
			continue
		}
		sh := &s.Shares[i]
		if shareIsDrop(sh) {
			return fmt.Errorf("not a download share")
		}
		if shareExpired(sh, time.Now().UTC()) {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return fmt.Errorf("expired")
		}
		if sh.MaxDownloads > 0 && sh.DownloadCount >= sh.MaxDownloads {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return fmt.Errorf("expired")
		}
		sh.DownloadCount++
		hitLimit := sh.MaxDownloads > 0 && sh.DownloadCount >= sh.MaxDownloads
		if err := s.saveLocked(); err != nil {
			sh.DownloadCount-- // best-effort rollback on disk failure
			return err
		}
		if hitLimit {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
		}
		return nil
	}
	return fmt.Errorf("not found")
}

func (s *shareStore) revoke(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Shares {
		if s.Shares[i].Token == token {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return true
		}
	}
	return false
}

func (s *shareStore) removeByPathPrefix(rel string) {
	rel = strings.Trim(rel, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.Shares[:0]
	for _, sh := range s.Shares {
		if sh.Path == rel || strings.HasPrefix(sh.Path, rel+"/") {
			continue
		}
		filtered = append(filtered, sh)
	}
	if len(filtered) != len(s.Shares) {
		s.Shares = filtered
		_ = s.saveLocked()
	}
}

func (s *shareStore) rewritePathPrefix(oldRel, newRel string) {
	oldRel = strings.Trim(oldRel, "/")
	newRel = strings.Trim(newRel, "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for i := range s.Shares {
		sh := &s.Shares[i]
		if sh.Path == oldRel {
			sh.Path = newRel
			sh.Name = filepath.Base(newRel)
			changed = true
		} else if strings.HasPrefix(sh.Path, oldRel+"/") {
			sh.Path = newRel + sh.Path[len(oldRel):]
			sh.Name = filepath.Base(sh.Path)
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}

func (s *shareStore) removeIndexLocked(i int) {
	s.Shares = append(s.Shares[:i], s.Shares[i+1:]...)
}

func (s *shareStore) pruneLocked(now time.Time) {
	filtered := s.Shares[:0]
	for _, sh := range s.Shares {
		if shareExpired(&sh, now) {
			continue
		}
		filtered = append(filtered, sh)
	}
	s.Shares = filtered
}

func shareKindOrLink(sh *Share) string {
	if sh != nil && sh.Kind == shareKindDrop {
		return shareKindDrop
	}
	return shareKindLink
}

func shareIsDrop(sh *Share) bool {
	return shareKindOrLink(sh) == shareKindDrop
}

// beginUpload reserves one upload slot for a drop share before writing bytes.
func (s *shareStore) beginUpload(token string) error {
	if !validShareToken(token) {
		return fmt.Errorf("not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(time.Now().UTC())
	for i := range s.Shares {
		if s.Shares[i].Token != token {
			continue
		}
		sh := &s.Shares[i]
		if !shareIsDrop(sh) {
			return fmt.Errorf("not a drop share")
		}
		if shareExpired(sh, time.Now().UTC()) {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return fmt.Errorf("expired")
		}
		if sh.MaxUploads > 0 && sh.UploadCount >= sh.MaxUploads {
			s.removeIndexLocked(i)
			_ = s.saveLocked()
			return fmt.Errorf("expired")
		}
		sh.UploadCount++
		return s.saveLocked()
	}
	return fmt.Errorf("not found")
}

func (s *shareStore) undoUpload(token string) {
	if !validShareToken(token) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.Shares {
		if s.Shares[i].Token != token {
			continue
		}
		if s.Shares[i].UploadCount > 0 {
			s.Shares[i].UploadCount--
			_ = s.saveLocked()
		}
		return
	}
}

func shareExpired(sh *Share, now time.Time) bool {
	if sh.ExpiresAt != nil && !sh.ExpiresAt.IsZero() && now.After(*sh.ExpiresAt) {
		return true
	}
	if sh.MaxDownloads > 0 && sh.DownloadCount >= sh.MaxDownloads {
		return true
	}
	if shareIsDrop(sh) && sh.MaxUploads > 0 && sh.UploadCount >= sh.MaxUploads {
		return true
	}
	return false
}

func validShareToken(token string) bool {
	if len(token) != shareTokenBytes*2 {
		return false
	}
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func shareNeedsPassword(sh *Share) bool {
	return sh.PasswordHash != ""
}

func shareUnlockCookieName(token string) string {
	if len(token) > 16 {
		token = token[:16]
	}
	return shareCookiePrefix + token
}

func shareUnlockValue(sh *Share) string {
	sum := sha256.Sum256([]byte(sh.PasswordHash + "|" + sh.Token + "|ok"))
	return hex.EncodeToString(sum[:])
}

func shareUnlocked(r *http.Request, sh *Share) bool {
	if !shareNeedsPassword(sh) {
		return true
	}
	c, err := r.Cookie(shareUnlockCookieName(sh.Token))
	if err != nil {
		return false
	}
	want := shareUnlockValue(sh)
	return subtleConstantTimeEq(c.Value, want)
}

func subtleConstantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func setShareUnlockCookie(w http.ResponseWriter, r *http.Request, sh *Share) {
	secure := false
	if sessions != nil {
		secure = sessions.secureCookie
	}
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		secure = true
	}
	http.SetCookie(w, &http.Cookie{
		Name:     shareUnlockCookieName(sh.Token),
		Value:    shareUnlockValue(sh),
		Path:     "/s/" + sh.Token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   secure,
		MaxAge:   int(shareUnlockTTL.Seconds()),
	})
}

func handleCreateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Path     string `json:"path"`
		Expires  string `json:"expires"` // 24h | 7d | 30d | never | 1download
		Password string `json:"password"`
		Kind     string `json:"kind"` // link (default) | drop
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	createdBy := ""
	if s := sessionFromCtx(r); s != nil {
		createdBy = s.Username
	}
	sh, err := shares.create(body.Path, createdBy, body.Expires, body.Password, body.Kind)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	urlPath := "/s/" + sh.Token
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"token":         sh.Token,
		"path":          urlPath,
		"url":           urlPath,
		"name":          sh.Name,
		"is_dir":        sh.IsDir,
		"kind":          shareKindOrLink(sh),
		"expires":       body.Expires,
		"expires_at":    sh.ExpiresAt,
		"max_downloads": sh.MaxDownloads,
		"max_uploads":   sh.MaxUploads,
		"has_password":  body.Password != "",
		"message":       "Share link created",
	})
	auditLog(actorName(r), "share_create", sh.Path, r)
}

func handleListShares(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"shares": shares.listPublic(),
	})
}

func handleRevokeShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if !shares.revoke(body.Token) {
		jsonErr(w, http.StatusNotFound, "Share not found")
		return
	}
	jsonOK(w, "Share revoked")
	auditLog(actorName(r), "share_revoke", body.Token, r)
}

func handlePublicShare(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/s/")
	rest = strings.Trim(rest, "/")
	if rest == "" {
		renderShareGone(w)
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	token := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	sh, err := shares.getValid(token)
	if err != nil {
		renderShareGone(w)
		return
	}

	switch {
	case sub == "unlock" && r.Method == http.MethodPost:
		handleShareUnlock(w, r, sh)
	case !shareUnlocked(r, sh):
		renderSharePage(w, http.StatusOK, sharePageData{
			Token:    sh.Token,
			Name:     sh.Name,
			IsDir:    sh.IsDir,
			IsDrop:   shareIsDrop(sh),
			NeedPass: true,
		})
	case shareIsDrop(sh):
		if sub == "upload" && r.Method == http.MethodPost {
			handleDropUpload(w, r, sh)
			return
		}
		if sub != "" {
			renderShareGone(w)
			return
		}
		renderSharePage(w, http.StatusOK, sharePageData{
			Token:     sh.Token,
			Name:      sh.Name,
			IsDir:     true,
			IsDrop:    true,
			MaxSizeMB: maxUploadBytes >> 20,
		})
	case sub == "download":
		serveShareDownload(w, r, sh)
	case sub == "" || sub == "browse" || strings.HasPrefix(sub, "browse/"):
		relInside := ""
		if strings.HasPrefix(sub, "browse/") {
			relInside = strings.TrimPrefix(sub, "browse/")
		}
		serveShareContent(w, r, sh, relInside)
	case sub == "zip":
		serveShareZip(w, r, sh)
	case strings.HasPrefix(sub, "f/"):
		serveShareFile(w, r, sh, strings.TrimPrefix(sub, "f/"))
	default:
		renderShareGone(w)
	}
}

func handleShareUnlock(w http.ResponseWriter, r *http.Request, sh *Share) {
	if err := r.ParseForm(); err != nil {
		renderSharePage(w, http.StatusBadRequest, sharePageData{
			NotFound: true,
			Error:    "Bad request",
		})
		return
	}
	pass := r.FormValue("password")
	ok, err := verifyPassword(sh.PasswordHash, pass)
	if err != nil || !ok {
		renderSharePage(w, http.StatusUnauthorized, sharePageData{
			Token:    sh.Token,
			Name:     sh.Name,
			IsDir:    sh.IsDir,
			IsDrop:   shareIsDrop(sh),
			NeedPass: true,
			Error:    "Incorrect password",
		})
		return
	}
	setShareUnlockCookie(w, r, sh)
	http.Redirect(w, r, "/s/"+sh.Token, http.StatusSeeOther)
}

func handleDropUpload(w http.ResponseWriter, r *http.Request, sh *Share) {
	if !shareIsDrop(sh) {
		renderShareGone(w)
		return
	}
	wantJSON := strings.Contains(r.Header.Get("Accept"), "application/json")
	respond := func(status int, msg, errMsg string) {
		if wantJSON {
			if errMsg != "" {
				writeJSON(w, status, map[string]any{"ok": false, "error": errMsg})
				return
			}
			writeJSON(w, status, map[string]any{"ok": true, "message": msg})
			return
		}
		if status == http.StatusGone || status == http.StatusNotFound {
			renderSharePage(w, status, sharePageData{NotFound: true, Error: errMsg})
			return
		}
		data := sharePageData{
			Token:     sh.Token,
			Name:      sh.Name,
			IsDir:     true,
			IsDrop:    true,
			MaxSizeMB: maxUploadBytes >> 20,
			Message:   msg,
			Error:     errMsg,
		}
		renderSharePage(w, status, data)
	}

	if err := r.ParseMultipartForm(maxUploadBytes + (1 << 20)); err != nil {
		respond(http.StatusBadRequest, "", "Could not read upload")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		respond(http.StatusBadRequest, "", "No file provided")
		return
	}
	defer file.Close()

	name := sanitizeName(header.Filename)
	if name == "" {
		respond(http.StatusBadRequest, "", "Invalid filename")
		return
	}

	dirAbs, err := safePath(sh.Path)
	if err != nil {
		if wantJSON {
			writeJSON(w, http.StatusGone, map[string]any{"ok": false, "error": "Drop folder is no longer available."})
			return
		}
		renderShareGone(w)
		return
	}
	info, err := os.Stat(dirAbs)
	if err != nil || !info.IsDir() {
		respond(http.StatusNotFound, "", "Drop folder is no longer available.")
		return
	}

	if err := shares.beginUpload(sh.Token); err != nil {
		respond(http.StatusGone, "", "This drop link has expired or reached its upload limit.")
		return
	}

	name = uniqueCopyName(dirAbs, name)
	dest := filepath.Join(dirAbs, name)
	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		shares.undoUpload(sh.Token)
		respond(http.StatusInternalServerError, "", "Failed to create file")
		return
	}

	written, copyErr := io.Copy(dst, io.LimitReader(file, maxUploadBytes+1))
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dest)
		shares.undoUpload(sh.Token)
		respond(http.StatusInternalServerError, "", "Failed to write file")
		return
	}
	if written > maxUploadBytes {
		_ = os.Remove(dest)
		shares.undoUpload(sh.Token)
		respond(http.StatusRequestEntityTooLarge, "", fmt.Sprintf("File too large (max %d MB)", maxUploadBytes>>20))
		return
	}

	invalidateListingCache()
	auditLog("drop:"+sh.Token[:8], "drop_upload", pathJoin(sh.Path, name), r)
	respond(http.StatusOK, fmt.Sprintf("Uploaded %s", name), "")
}

func serveShareContent(w http.ResponseWriter, r *http.Request, sh *Share, relInside string) {
	relInside = strings.Trim(strings.ReplaceAll(relInside, `\`, `/`), "/")
	targetRel := sh.Path
	if relInside != "" {
		if !sh.IsDir {
			renderShareGone(w)
			return
		}
		targetRel = pathJoin(sh.Path, relInside)
	}

	target, err := safePath(targetRel)
	if err != nil {
		renderShareGone(w)
		return
	}
	// Ensure target stays under the shared path.
	if sh.IsDir {
		sharedAbs, err := safePath(sh.Path)
		if err != nil {
			renderShareGone(w)
			return
		}
		rel, err := filepath.Rel(sharedAbs, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			renderShareGone(w)
			return
		}
	} else if targetRel != sh.Path {
		renderShareGone(w)
		return
	}

	info, err := os.Stat(target)
	if err != nil {
		renderSharePage(w, http.StatusNotFound, sharePageData{
			NotFound: true,
			Error:    "This file is no longer available.",
		})
		return
	}

	if !info.IsDir() {
		// File share landing: show a page with an explicit Download button.
		// Nested files under a folder share still download immediately via /f/.
		if !sh.IsDir && relInside == "" {
			renderSharePage(w, http.StatusOK, sharePageData{
				Token:       sh.Token,
				Name:        sh.Name,
				IsDir:       false,
				DownloadURL: "/s/" + sh.Token + "/download",
				Size:        humanBytes(info.Size()),
			})
			return
		}
		reserveAndServeShareFile(w, r, sh, target)
		return
	}

	// Directory listing for folder shares.
	entries, err := os.ReadDir(target)
	if err != nil {
		renderSharePage(w, http.StatusInternalServerError, sharePageData{
			NotFound: true,
			Error:    "Could not read this folder.",
		})
		return
	}
	data := sharePageData{
		Token:  sh.Token,
		Name:   sh.Name,
		IsDir:  true,
		ZipURL: "/s/" + sh.Token + "/zip",
	}
	if relInside != "" {
		data.Name = filepath.Base(targetRel)
		parent := pathDir(relInside)
		data.Parent = parent
		if parent == "" {
			data.ParentURL = "/s/" + sh.Token
		} else {
			data.ParentURL = "/s/" + sh.Token + "/browse/" + parent
		}
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		childRel := pathJoin(relInside, name)
		ent := shareEntry{Name: name, IsDir: e.IsDir()}
		if e.IsDir() {
			ent.URL = "/s/" + sh.Token + "/browse/" + childRel
		} else {
			ent.URL = "/s/" + sh.Token + "/f/" + childRel
			if fi, err := e.Info(); err == nil {
				ent.Size = humanBytes(fi.Size())
			}
		}
		data.Entries = append(data.Entries, ent)
	}
	renderSharePage(w, http.StatusOK, data)
}

func serveShareDownload(w http.ResponseWriter, r *http.Request, sh *Share) {
	if sh.IsDir {
		http.Redirect(w, r, "/s/"+sh.Token+"/zip", http.StatusSeeOther)
		return
	}
	target, err := safePath(sh.Path)
	if err != nil {
		renderShareGone(w)
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		renderShareGone(w)
		return
	}
	reserveAndServeShareFile(w, r, sh, target)
}

func serveShareFile(w http.ResponseWriter, r *http.Request, sh *Share, relInside string) {
	if !sh.IsDir {
		renderShareGone(w)
		return
	}
	relInside = strings.Trim(strings.ReplaceAll(relInside, `\`, `/`), "/")
	if relInside == "" {
		renderShareGone(w)
		return
	}
	targetRel := pathJoin(sh.Path, relInside)
	target, err := safePath(targetRel)
	if err != nil {
		renderShareGone(w)
		return
	}
	sharedAbs, err := safePath(sh.Path)
	if err != nil {
		renderShareGone(w)
		return
	}
	rel, err := filepath.Rel(sharedAbs, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		renderShareGone(w)
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		renderShareGone(w)
		return
	}
	reserveAndServeShareFile(w, r, sh, target)
}

func serveShareZip(w http.ResponseWriter, r *http.Request, sh *Share) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		renderSharePage(w, http.StatusMethodNotAllowed, sharePageData{NotFound: true})
		return
	}
	if err := shares.beginDownload(sh.Token); err != nil {
		renderShareGone(w)
		return
	}
	name := sh.Name + ".zip"
	if err := streamZip(w, name, []string{sh.Path}); err != nil {
		log.Printf("share zip: %v", err)
		return
	}
}

// reserveAndServeShareFile deducts download quota before transferring bytes.
func reserveAndServeShareFile(w http.ResponseWriter, r *http.Request, sh *Share, target string) {
	if err := shares.beginDownload(sh.Token); err != nil {
		renderShareGone(w)
		return
	}
	serveStoredFile(w, r, target, true)
}

func renderShareGone(w http.ResponseWriter) {
	renderSharePage(w, http.StatusNotFound, sharePageData{NotFound: true})
}

func renderSharePage(w http.ResponseWriter, status int, data sharePageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Drop uploads need inline JS + XHR; keep everything else locked down.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "+
			"script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if err := shareTpl.Execute(w, data); err != nil {
		log.Printf("share template: %v", err)
	}
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, u := range units {
		f /= 1024
		if f < 1024 {
			return fmt.Sprintf("%.1f %s", f, u)
		}
	}
	return fmt.Sprintf("%.1f PB", f/1024)
}

// shareTpl is set in main via ParseFS.
var shareTpl *template.Template

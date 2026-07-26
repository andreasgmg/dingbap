package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Default max upload size (override with MAX_UPLOAD_MB).
const defaultMaxUploadBytes int64 = 500 << 20 // 500 MB

var maxUploadBytes = defaultMaxUploadBytes

type jsonResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func jsonOK(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusOK, jsonResponse{OK: true, Message: msg})
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, jsonResponse{OK: false, Error: msg})
}

// Max size for JSON API bodies (login, admin mutations, zip path lists, …).
const maxJSONBodyBytes int64 = 1 << 20 // 1 MiB

// decodeJSONBody decodes r.Body into dst with a hard size limit.
// On error it writes a JSON error response and returns false.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			jsonErr(w, http.StatusRequestEntityTooLarge, "Request body too large")
			return false
		}
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	if code != http.StatusOK {
		w.WriteHeader(code)
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode: %v", err)
	}
}

func execTemplate(w http.ResponseWriter, tpl *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.Execute(w, data); err != nil {
		log.Printf("template execute: %v", err)
	}
}

func handlePagePublic(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		rel := strings.TrimPrefix(r.URL.Path, "/")
		if strings.HasPrefix(rel, "static/") || strings.HasPrefix(rel, "admin") || strings.HasPrefix(rel, "api/") || strings.HasPrefix(rel, "download/") || strings.HasPrefix(rel, "preview/") || strings.HasPrefix(rel, "s/") {
			http.NotFound(w, r)
			return
		}
		target, err := safePath(rel)
		if err != nil {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		info, err := os.Stat(target)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if !info.IsDir() {
			serveStoredFile(w, r, target, false)
			return
		}
	}
	execTemplate(w, layoutTpl, pageDataFrom(r, false))
}

func handlePageAdmin(w http.ResponseWriter, r *http.Request) {
	execTemplate(w, layoutTpl, pageDataFrom(r, true))
}

func pageDataFrom(r *http.Request, adminPage bool) pageData {
	d := pageData{Admin: adminPage}
	if s := sessionFromCtx(r); s != nil {
		d.Username = s.Username
		d.Role = s.Role
	}
	return d
}

type treeNode struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"isDir"`
	Size       int64  `json:"size,omitempty"`
	ChildCount int    `json:"childCount,omitempty"`
}

// listDirNodes returns the children of rel, served from dirCache when possible.
// On miss it reads the directory once, stores the listing, and returns it.
// Dot entries (.trash, .uploads, …) are omitted — same rules as the tree API.
// hit is true when the listing came from cache.
func listDirNodes(rel string) (nodes []treeNode, hit bool, err error) {
	if cached, ok := dirCache.get(rel); ok {
		return cached, true, nil
	}

	target, err := safePath(rel)
	if err != nil {
		return nil, false, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("not a directory")
	}

	entries, err := os.ReadDir(target)
	if err != nil {
		return nil, false, err
	}

	nodes = make([]treeNode, 0, len(entries))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		childRel := pathJoin(rel, e.Name())
		// Reject symlink escapes before caching or exposing the node.
		if _, err := safePath(childRel); err != nil {
			continue
		}
		n := treeNode{
			Name:  e.Name(),
			Path:  childRel,
			IsDir: e.IsDir(),
		}
		if !e.IsDir() {
			if fi, err := e.Info(); err == nil {
				n.Size = fi.Size()
			}
		}
		nodes = append(nodes, n)
	}

	dirCache.set(rel, nodes)
	return nodes, false, nil
}

func handleTree(w http.ResponseWriter, r *http.Request) {
	rel := r.URL.Query().Get("path")
	if _, err := safePath(rel); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}

	nodes, cacheHit, err := listDirNodes(rel)
	if err != nil {
		if os.IsNotExist(err) {
			jsonErr(w, http.StatusNotFound, "Not found")
			return
		}
		if strings.Contains(err.Error(), "not a directory") {
			jsonErr(w, http.StatusBadRequest, "Path is not a directory")
			return
		}
		jsonErr(w, http.StatusInternalServerError, "Failed to read directory")
		return
	}

	if cacheHit {
		w.Header().Set("X-Cache", "HIT")
	} else {
		w.Header().Set("X-Cache", "MISS")
	}
	writeJSON(w, http.StatusOK, nodes)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/download/")
	if rel == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	target, err := safePath(rel)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	serveStoredFile(w, r, target, true)
}

func handlePreview(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/preview/")
	if rel == "" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	target, err := safePath(rel)
	if err != nil {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	name := filepath.Base(target)
	ctype, kind := previewContentType(name)
	if ctype == "" {
		http.Error(w, "Preview not available for this file type", http.StatusUnsupportedMediaType)
		return
	}

	// Cap text previews so huge logs don't blow up browser memory.
	const maxTextPreview = 2 << 20 // 2 MB
	if kind == "text" && info.Size() > maxTextPreview {
		http.Error(w, "File too large to preview", http.StatusRequestEntityTooLarge)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", contentDispositionInline(name))
	w.Header().Set("Cache-Control", "private, max-age=120")
	http.ServeFile(w, r, target)
}

func contentDisposition(name string) string {
	return formatContentDisposition("attachment", name)
}

func contentDispositionInline(name string) string {
	return formatContentDisposition("inline", name)
}

func formatContentDisposition(disposition, name string) string {
	escaped := strings.ReplaceAll(name, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return fmt.Sprintf(`%s; filename="%s"; filename*=UTF-8''%s`, disposition, escaped, url.PathEscape(name))
}

// previewContentType returns MIME type and kind (image|pdf|video|text) for previewable files.
func previewContentType(name string) (ctype, kind string) {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image/png", "image"
	case ".jpg", ".jpeg":
		return "image/jpeg", "image"
	case ".webp":
		return "image/webp", "image"
	case ".gif":
		return "image/gif", "image"
	case ".pdf":
		return "application/pdf", "pdf"
	case ".mp4":
		return "video/mp4", "video"
	case ".webm":
		return "video/webm", "video"
	case ".txt", ".md", ".go":
		return "text/plain; charset=utf-8", "text"
	case ".json":
		return "application/json", "text"
	default:
		return "", ""
	}
}

// serveStoredFile serves a file from the archive with XSS-hardening headers.
// forceDownload always sends Content-Disposition: attachment.
// Dangerous types (HTML/SVG/JS/…) are always forced as downloads even when browsing inline.
func serveStoredFile(w http.ResponseWriter, r *http.Request, target string, forceDownload bool) {
	name := filepath.Base(target)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if forceDownload || isDangerousInlineExt(name) {
		w.Header().Set("Content-Disposition", contentDisposition(name))
		if isDangerousInlineExt(name) {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
	}
	http.ServeFile(w, r, target)
}

func isDangerousInlineExt(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html", ".htm", ".shtml", ".svg", ".svgz", ".xml", ".xhtml", ".js", ".mjs", ".css":
		return true
	default:
		return false
	}
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	// Hard cap request body — ParseMultipartForm alone does NOT limit total size.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			jsonErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("File too large (max %d MB)", maxUploadBytes>>20))
			return
		}
		jsonErr(w, http.StatusBadRequest, "Failed to parse form")
		return
	}

	destDir := r.FormValue("path")
	if isTrashPath(destDir) {
		jsonErr(w, http.StatusBadRequest, "Cannot upload into trash")
		return
	}
	targetDir, err := safePath(destDir)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}

	info, err := os.Stat(targetDir)
	if err != nil || !info.IsDir() {
		jsonErr(w, http.StatusBadRequest, "Destination must be an existing directory")
		return
	}

	file, handler, err := r.FormFile("file")
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "No file provided")
		return
	}
	defer file.Close()

	name := sanitizeName(handler.Filename)
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "Invalid filename")
		return
	}
	dest := filepath.Join(targetDir, name)

	if _, err := os.Stat(dest); err == nil {
		jsonErr(w, http.StatusConflict, fmt.Sprintf("%s already exists", name))
		return
	} else if !os.IsNotExist(err) {
		jsonErr(w, http.StatusInternalServerError, "Failed to check destination")
		return
	}

	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if os.IsExist(err) {
			jsonErr(w, http.StatusConflict, fmt.Sprintf("%s already exists", name))
			return
		}
		jsonErr(w, http.StatusInternalServerError, "Failed to save file")
		return
	}
	defer dst.Close()

	written, err := io.Copy(dst, io.LimitReader(file, maxUploadBytes+1))
	if err != nil {
		os.Remove(dest)
		jsonErr(w, http.StatusInternalServerError, "Failed to write file")
		return
	}
	if written > maxUploadBytes {
		os.Remove(dest)
		jsonErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("File too large (max %d MB)", maxUploadBytes>>20))
		return
	}

	jsonOK(w, fmt.Sprintf("Uploaded %s", name))
	auditLog(actorName(r), "upload", name, r)
	invalidateListingCache()
}

func handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var body struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if isTrashPath(body.Path) || isTrashPath(pathJoin(body.Path, body.Name)) {
		jsonErr(w, http.StatusBadRequest, "Cannot create folders in trash")
		return
	}

	parent, err := safePath(body.Path)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}

	name := sanitizeName(body.Name)
	if name == "" {
		jsonErr(w, http.StatusBadRequest, "Invalid name")
		return
	}

	target := filepath.Join(parent, name)
	if _, err := os.Stat(target); err == nil {
		jsonErr(w, http.StatusConflict, fmt.Sprintf("%s already exists", name))
		return
	} else if !os.IsNotExist(err) {
		jsonErr(w, http.StatusInternalServerError, "Failed to check destination")
		return
	}

	if err := os.Mkdir(target, 0755); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to create directory")
		return
	}

	jsonOK(w, fmt.Sprintf("Created directory %s", name))
	auditLog(actorName(r), "mkdir", pathJoin(body.Path, name), r)
	invalidateListingCache()
}

func handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var body struct {
		OldPath string `json:"oldPath"`
		NewName string `json:"newName"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}

	oldAbs, err := safePath(body.OldPath)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}

	newName := sanitizeName(body.NewName)
	if newName == "" {
		jsonErr(w, http.StatusBadRequest, "Invalid name")
		return
	}

	newAbs := filepath.Join(filepath.Dir(oldAbs), newName)
	if _, err := safePath(pathJoin(pathDir(body.OldPath), newName)); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid destination")
		return
	}

	if _, err := os.Stat(oldAbs); err != nil {
		if os.IsNotExist(err) {
			jsonErr(w, http.StatusNotFound, "Source not found")
			return
		}
		jsonErr(w, http.StatusInternalServerError, "Failed to check source")
		return
	}

	if _, err := os.Stat(newAbs); err == nil {
		jsonErr(w, http.StatusConflict, fmt.Sprintf("%s already exists", newName))
		return
	} else if !os.IsNotExist(err) {
		jsonErr(w, http.StatusInternalServerError, "Failed to check destination")
		return
	}

	if err := os.Rename(oldAbs, newAbs); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to rename")
		return
	}

	newRel := pathJoin(pathDir(body.OldPath), newName)
	if shares != nil {
		shares.rewritePathPrefix(strings.Trim(body.OldPath, "/"), newRel)
	}

	jsonOK(w, fmt.Sprintf("Renamed to %s", newName))
	auditLog(actorName(r), "rename", newRel, r)
	invalidateListingCache()
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var body struct {
		Path         string `json:"path"`
		Confirm      bool   `json:"confirm"`
		ConfirmName  string `json:"confirmName"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}

	if !body.Confirm {
		jsonErr(w, http.StatusBadRequest, "Deletion requires confirmation")
		return
	}

	rel := strings.Trim(body.Path, "/")
	if rel == "" {
		jsonErr(w, http.StatusBadRequest, "Cannot delete root")
		return
	}
	if isTrashPath(rel) {
		jsonErr(w, http.StatusBadRequest, "Cannot delete trash internals this way")
		return
	}

	target, err := safePath(body.Path)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}

	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		jsonErr(w, http.StatusNotFound, "Not found")
		return
	}
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to stat path")
		return
	}

	base := filepath.Base(target)
	if info.IsDir() {
		if body.ConfirmName != base {
			jsonErr(w, http.StatusBadRequest, "Type the folder name to confirm deletion")
			return
		}
	}

	deletedBy := ""
	if s := sessionFromCtx(r); s != nil {
		deletedBy = s.Username
	}
	item, err := trash.moveToTrash(rel, deletedBy)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if shares != nil {
		shares.removeByPathPrefix(rel)
	}

	jsonOK(w, fmt.Sprintf("Moved %s to trash", item.Name))
	auditLog(actorName(r), "trash", rel, r)
	invalidateListingCache()
}

func handleMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var body struct {
		Path    string `json:"path"`
		DestDir string `json:"destDir"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if isTrashPath(body.Path) || isTrashPath(body.DestDir) {
		jsonErr(w, http.StatusBadRequest, "Cannot move to/from trash this way")
		return
	}

	srcAbs, err := safePath(body.Path)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid source path")
		return
	}

	destAbs, err := safePath(body.DestDir)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid destination path")
		return
	}

	destInfo, err := os.Stat(destAbs)
	if err != nil || !destInfo.IsDir() {
		jsonErr(w, http.StatusBadRequest, "Destination must be a directory")
		return
	}

	// Refuse moving a directory into itself or a descendant.
	srcInfo, err := os.Stat(srcAbs)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Source not found")
		return
	}
	if srcInfo.IsDir() {
		rel, err := filepath.Rel(srcAbs, destAbs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			jsonErr(w, http.StatusBadRequest, "Cannot move a folder into itself")
			return
		}
	}

	name := filepath.Base(srcAbs)
	newAbs := filepath.Join(destAbs, name)

	if filepath.Clean(srcAbs) == filepath.Clean(newAbs) {
		jsonErr(w, http.StatusBadRequest, "Source and destination are the same")
		return
	}

	if _, err := os.Stat(newAbs); err == nil {
		jsonErr(w, http.StatusConflict, fmt.Sprintf("%s already exists in destination", name))
		return
	} else if !os.IsNotExist(err) {
		jsonErr(w, http.StatusInternalServerError, "Failed to check destination")
		return
	}

	if err := os.Rename(srcAbs, newAbs); err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to move")
		return
	}

	newRel := pathJoin(strings.Trim(body.DestDir, "/"), name)
	if shares != nil {
		shares.rewritePathPrefix(strings.Trim(body.Path, "/"), newRel)
	}

	jsonOK(w, fmt.Sprintf("Moved to %s", body.DestDir))
	auditLog(actorName(r), "move", newRel, r)
	invalidateListingCache()
}

func pathJoin(parts ...string) string {
	var cleaned []string
	for _, p := range parts {
		p = strings.Trim(p, "/")
		if p != "" && p != "." {
			cleaned = append(cleaned, p)
		}
	}
	return strings.Join(cleaned, "/")
}

func pathDir(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

func sanitizeName(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "/", "")
	name = strings.TrimLeft(name, ".")
	if name == "" || name == "." || name == ".." {
		return ""
	}
	return name
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultChunkSize = 2 << 20 // 2 MB
	maxChunkSize     = 8 << 20 // 8 MB
	uploadSessionTTL = 24 * time.Hour
	uploadsDirName   = ".uploads"
)

type uploadMeta struct {
	ID          string    `json:"id"`
	Path        string    `json:"path"` // destination directory (relative)
	Name        string    `json:"name"`
	Size        int64     `json:"size"`
	ChunkSize   int64     `json:"chunk_size"`
	TotalChunks int       `json:"total_chunks"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

// activeUpload holds in-memory state for an open chunked upload so chunk writes
// do not re-read meta.json or Stat every chunk_* file on each request.
// sessMu serializes complete/abort/chunk ops for the same upload id.
type activeUpload struct {
	sessMu   sync.Mutex
	meta     uploadMeta
	received map[int]struct{}
	aborted  bool
}

type uploadManager struct {
	mu     sync.Mutex
	root   string // <meta>/.uploads
	reaped time.Time
	active map[string]*activeUpload
}

var uploads *uploadManager

func newUploadManager(dataDir string) (*uploadManager, error) {
	root := filepath.Join(dataDir, uploadsDirName)
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	um := &uploadManager{
		root:   root,
		active: make(map[string]*activeUpload),
	}
	um.reapExpired()
	return um, nil
}

func (um *uploadManager) sessionDir(id string) string {
	return filepath.Join(um.root, id)
}

func (um *uploadManager) metaPath(id string) string {
	return filepath.Join(um.sessionDir(id), "meta.json")
}

func (um *uploadManager) chunkPath(id string, index int) string {
	return filepath.Join(um.sessionDir(id), fmt.Sprintf("chunk_%06d", index))
}

func (um *uploadManager) saveMeta(m *uploadMeta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(um.metaPath(m.ID), data, 0600)
}

func (um *uploadManager) readMetaDisk(id string) (*uploadMeta, error) {
	if !validShareToken(id) {
		return nil, fmt.Errorf("invalid upload id")
	}
	data, err := os.ReadFile(um.metaPath(id))
	if err != nil {
		return nil, err
	}
	var m uploadMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, fmt.Errorf("invalid upload id")
	}
	if time.Since(m.CreatedAt) > uploadSessionTTL {
		return nil, fmt.Errorf("upload session expired")
	}
	return &m, nil
}

// scanReceivedDisk is used once when hydrating a resumed upload after restart.
func (um *uploadManager) scanReceivedDisk(id string, total int) map[int]struct{} {
	got := make(map[int]struct{})
	for i := 0; i < total; i++ {
		if _, err := os.Stat(um.chunkPath(id, i)); err == nil {
			got[i] = struct{}{}
		}
	}
	return got
}

// acquire returns the in-memory active upload, loading from disk once if needed
// (e.g. after a process restart mid-upload).
func (um *uploadManager) acquire(id string) (*activeUpload, error) {
	if !validShareToken(id) {
		return nil, fmt.Errorf("invalid upload id")
	}

	um.mu.Lock()
	if a, ok := um.active[id]; ok {
		if time.Since(a.meta.CreatedAt) > uploadSessionTTL {
			delete(um.active, id)
			um.mu.Unlock()
			_ = os.RemoveAll(um.sessionDir(id))
			return nil, fmt.Errorf("upload session expired")
		}
		um.mu.Unlock()
		return a, nil
	}
	um.mu.Unlock()

	m, err := um.readMetaDisk(id)
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			_ = os.RemoveAll(um.sessionDir(id))
		}
		return nil, err
	}
	received := um.scanReceivedDisk(id, m.TotalChunks)

	um.mu.Lock()
	defer um.mu.Unlock()
	if a, ok := um.active[id]; ok {
		return a, nil
	}
	a := &activeUpload{meta: *m, received: received}
	um.active[id] = a
	return a, nil
}

func (um *uploadManager) receivedList(a *activeUpload) []int {
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	got := make([]int, 0, len(a.received))
	for i := 0; i < a.meta.TotalChunks; i++ {
		if _, ok := a.received[i]; ok {
			got = append(got, i)
		}
	}
	return got
}

func (um *uploadManager) init(destPath, name string, size, chunkSize int64, createdBy string) (*uploadMeta, []int, error) {
	// Folder uploads may pass a relative path (e.g. "Album/vacation/img.jpg").
	// Validate segments before Clean so ".." cannot collapse into a benign name.
	rel := strings.ReplaceAll(strings.Trim(name, "/"), `\`, `/`)
	if rel == "" {
		return nil, nil, fmt.Errorf("invalid filename")
	}
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return nil, nil, fmt.Errorf("invalid filename")
		}
		if sanitizeName(part) != part {
			return nil, nil, fmt.Errorf("invalid filename")
		}
	}
	base := parts[len(parts)-1]
	subDir := ""
	if len(parts) > 1 {
		subDir = strings.Join(parts[:len(parts)-1], "/")
	}

	if size < 0 || size > maxUploadBytes {
		return nil, nil, fmt.Errorf("file too large (max %d MB)", maxUploadBytes>>20)
	}
	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}
	if chunkSize > maxChunkSize {
		chunkSize = maxChunkSize
	}

	destRel := strings.Trim(destPath, "/")
	if subDir != "" {
		destRel = pathJoin(destRel, subDir)
	}
	if isTrashPath(destRel) || isTrashPath(pathJoin(destRel, base)) {
		return nil, nil, fmt.Errorf("cannot upload into trash")
	}

	// Ensure destination directory exists (create nested folders for folder upload).
	destDir, err := safePath(destRel)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid path")
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create destination folders")
	}
	info, err := os.Stat(destDir)
	if err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("destination must be a directory")
	}

	finalRel := pathJoin(destRel, base)
	finalAbs, err := safePath(finalRel)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid destination")
	}
	if _, err := os.Stat(finalAbs); err == nil {
		return nil, nil, fmt.Errorf("%s already exists", base)
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("failed to check destination")
	}

	totalChunks := int((size + chunkSize - 1) / chunkSize)
	if size == 0 {
		totalChunks = 1
	}

	id, err := randomToken(shareTokenBytes)
	if err != nil {
		return nil, nil, err
	}
	dir := um.sessionDir(id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}

	m := &uploadMeta{
		ID:          id,
		Path:        destRel,
		Name:        base,
		Size:        size,
		ChunkSize:   chunkSize,
		TotalChunks: totalChunks,
		CreatedAt:   time.Now().UTC(),
		CreatedBy:   createdBy,
	}
	if err := um.saveMeta(m); err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}

	um.mu.Lock()
	um.active[id] = &activeUpload{
		meta:     *m,
		received: make(map[int]struct{}),
	}
	um.mu.Unlock()

	um.reapExpired()
	return m, []int{}, nil
}

func (um *uploadManager) writeChunk(id string, index int, r io.Reader, declaredSize int64) error {
	a, err := um.acquire(id)
	if err != nil {
		return err
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	if a.aborted {
		return fmt.Errorf("upload session not found")
	}

	m := a.meta
	if index < 0 || index >= m.TotalChunks {
		return fmt.Errorf("invalid chunk index")
	}

	expected := m.ChunkSize
	if index == m.TotalChunks-1 {
		expected = m.Size - int64(index)*m.ChunkSize
		if expected < 0 {
			return fmt.Errorf("invalid chunk size")
		}
	}
	if declaredSize >= 0 && declaredSize != expected {
		return fmt.Errorf("unexpected chunk size")
	}

	dstPath := um.chunkPath(id, index)
	tmp := dstPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	written, err := io.Copy(f, io.LimitReader(r, expected+1))
	closeErr := f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}
	if written != expected {
		os.Remove(tmp)
		return fmt.Errorf("incomplete chunk (got %d, want %d)", written, expected)
	}
	if err := os.Rename(tmp, dstPath); err != nil {
		return err
	}
	a.received[index] = struct{}{}
	return nil
}

func (um *uploadManager) complete(id string) (string, error) {
	a, err := um.acquire(id)
	if err != nil {
		return "", err
	}
	a.sessMu.Lock()
	defer a.sessMu.Unlock()
	if a.aborted {
		return "", fmt.Errorf("upload session not found")
	}

	m := a.meta
	if len(a.received) != m.TotalChunks {
		return "", fmt.Errorf("missing chunks (%d/%d)", len(a.received), m.TotalChunks)
	}

	destDir, err := safePath(m.Path)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}
	info, err := os.Stat(destDir)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("destination must be an existing directory")
	}

	finalRel := pathJoin(m.Path, m.Name)
	finalAbs, err := safePath(finalRel)
	if err != nil {
		return "", fmt.Errorf("invalid destination")
	}
	if _, err := os.Stat(finalAbs); err == nil {
		return "", fmt.Errorf("%s already exists", m.Name)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check destination")
	}

	tmpFinal := finalAbs + ".uploading"
	out, err := os.OpenFile(tmpFinal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to create file")
	}

	var total int64
	assembleErr := func() error {
		for i := 0; i < m.TotalChunks; i++ {
			cf, err := os.Open(um.chunkPath(id, i))
			if err != nil {
				return err
			}
			n, err := io.Copy(out, cf)
			cf.Close()
			if err != nil {
				return err
			}
			total += n
		}
		return nil
	}()
	closeErr := out.Close()
	if assembleErr != nil || closeErr != nil || total != m.Size {
		os.Remove(tmpFinal)
		if assembleErr != nil {
			return "", assembleErr
		}
		if closeErr != nil {
			return "", closeErr
		}
		return "", fmt.Errorf("size mismatch after assembly")
	}

	if err := os.Rename(tmpFinal, finalAbs); err != nil {
		os.Remove(tmpFinal)
		return "", err
	}

	a.aborted = true
	um.mu.Lock()
	delete(um.active, id)
	um.mu.Unlock()
	_ = os.RemoveAll(um.sessionDir(id))
	return m.Name, nil
}

func (um *uploadManager) abort(id string) error {
	if !validShareToken(id) {
		return fmt.Errorf("invalid upload id")
	}

	um.mu.Lock()
	a := um.active[id]
	delete(um.active, id)
	um.mu.Unlock()

	dir := um.sessionDir(id)
	if a != nil {
		a.sessMu.Lock()
		a.aborted = true
		a.sessMu.Unlock()
	} else if _, err := os.Stat(dir); os.IsNotExist(err) {
		return fmt.Errorf("upload session not found")
	}

	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return nil
}

func (um *uploadManager) status(id string) (*uploadMeta, []int, error) {
	a, err := um.acquire(id)
	if err != nil {
		return nil, nil, err
	}
	a.sessMu.Lock()
	m := a.meta
	a.sessMu.Unlock()
	return &m, um.receivedList(a), nil
}

func (um *uploadManager) reapExpired() {
	um.mu.Lock()
	if time.Since(um.reaped) < time.Hour {
		um.mu.Unlock()
		return
	}
	um.reaped = time.Now()
	um.mu.Unlock()

	entries, err := os.ReadDir(um.root)
	if err != nil {
		return
	}
	now := time.Now()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		metaFile := filepath.Join(um.root, id, "meta.json")
		data, err := os.ReadFile(metaFile)
		if err != nil {
			info, err := e.Info()
			if err == nil && now.Sub(info.ModTime()) > uploadSessionTTL {
				um.mu.Lock()
				delete(um.active, id)
				um.mu.Unlock()
				os.RemoveAll(filepath.Join(um.root, id))
			}
			continue
		}
		var m uploadMeta
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		if now.Sub(m.CreatedAt) > uploadSessionTTL {
			um.mu.Lock()
			delete(um.active, id)
			um.mu.Unlock()
			os.RemoveAll(filepath.Join(um.root, id))
		}
	}
}

func handleUploadInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Path      string `json:"path"`
		Name      string `json:"name"`
		Size      int64  `json:"size"`
		ChunkSize int64  `json:"chunkSize"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	createdBy := ""
	if s := sessionFromCtx(r); s != nil {
		createdBy = s.Username
	}
	m, received, err := uploads.init(body.Path, body.Name, body.Size, body.ChunkSize, createdBy)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "too large") {
			status = http.StatusRequestEntityTooLarge
		}
		jsonErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"uploadId":    m.ID,
		"chunkSize":   m.ChunkSize,
		"totalChunks": m.TotalChunks,
		"received":    received,
	})
}

func handleUploadStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	m, received, err := uploads.status(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Upload session not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"uploadId":    m.ID,
		"chunkSize":   m.ChunkSize,
		"totalChunks": m.TotalChunks,
		"size":        m.Size,
		"name":        m.Name,
		"path":        m.Path,
		"received":    received,
	})
}

func handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "PUT or POST required")
		return
	}

	id := r.URL.Query().Get("uploadId")
	if id == "" {
		id = r.Header.Get("X-Upload-Id")
	}
	indexStr := r.URL.Query().Get("index")
	if indexStr == "" {
		indexStr = r.Header.Get("X-Chunk-Index")
	}
	index, err := strconv.Atoi(indexStr)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid chunk index")
		return
	}

	a, err := uploads.acquire(id)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Upload session not found")
		return
	}
	a.sessMu.Lock()
	m := a.meta
	a.sessMu.Unlock()

	// Limit body to one chunk (+ tiny slack).
	limit := m.ChunkSize + 1024
	r.Body = http.MaxBytesReader(w, r.Body, limit)

	ct := r.Header.Get("Content-Type")
	var reader io.Reader = r.Body
	var declared int64 = -1
	if strings.HasPrefix(ct, "multipart/") {
		if err := r.ParseMultipartForm(maxChunkSize + (1 << 20)); err != nil {
			jsonErr(w, http.StatusBadRequest, "Failed to parse chunk")
			return
		}
		file, _, err := r.FormFile("chunk")
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "No chunk provided")
			return
		}
		defer file.Close()
		reader = file
	} else if cl := r.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			declared = n
		}
	}

	if err := uploads.writeChunk(id, index, reader, declared); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}

	received := uploads.receivedList(a)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"index":    index,
		"received": len(received),
		"total":    m.TotalChunks,
	})
}

func handleUploadComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		UploadID string `json:"uploadId"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	name, err := uploads.complete(body.UploadID)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		}
		jsonErr(w, status, err.Error())
		return
	}
	jsonOK(w, fmt.Sprintf("Uploaded %s", name))
	auditLog(actorName(r), "upload", name, r)
	invalidateListingCache()
}

func handleUploadAbort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		UploadID string `json:"uploadId"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := uploads.abort(body.UploadID); err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	jsonOK(w, "Upload aborted")
}

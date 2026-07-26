package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	trashDirName     = ".trash"
	trashItemsDir    = "items"
	trashMetaFile    = "trash_info.json"
	trashRetention   = 30 * 24 * time.Hour
	trashPurgeEvery  = time.Hour
)

type TrashItem struct {
	ID           string    `json:"id"`
	OriginalPath string    `json:"original_path"`
	Name         string    `json:"name"`
	IsDir        bool      `json:"is_dir"`
	DeletedAt    time.Time `json:"deleted_at"`
	DeletedBy    string    `json:"deleted_by,omitempty"`
	Size         int64     `json:"size,omitempty"`
}

type trashStore struct {
	mu    sync.Mutex
	root  string // <storage>/.trash
	Items []TrashItem `json:"items"`
}

var trash *trashStore

func openTrashStore(storageRoot string) (*trashStore, error) {
	root := filepath.Join(storageRoot, trashDirName)
	if err := os.MkdirAll(filepath.Join(root, trashItemsDir), 0700); err != nil {
		return nil, err
	}
	s := &trashStore{root: root}
	meta := filepath.Join(root, trashMetaFile)
	data, err := os.ReadFile(meta)
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
		return nil, fmt.Errorf("parse trash metadata: %w", err)
	}
	return s, nil
}

func (s *trashStore) metaPath() string {
	return filepath.Join(s.root, trashMetaFile)
}

func (s *trashStore) itemPath(id string) string {
	return filepath.Join(s.root, trashItemsDir, id)
}

func (s *trashStore) saveLocked() error {
	data, err := json.MarshalIndent(struct {
		Items []TrashItem `json:"items"`
	}{Items: s.Items}, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.metaPath(), data, 0600)
}

func isTrashPath(rel string) bool {
	rel = strings.Trim(rel, "/")
	return rel == trashDirName || strings.HasPrefix(rel, trashDirName+"/")
}

func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		total += info.Size()
		return nil
	})
	return total
}

// moveToTrash relocates a file/folder into .trash and records metadata.
func (s *trashStore) moveToTrash(rel, deletedBy string) (*TrashItem, error) {
	rel = strings.Trim(rel, "/")
	if rel == "" || isTrashPath(rel) {
		return nil, fmt.Errorf("cannot trash this path")
	}

	src, err := safePath(rel)
	if err != nil {
		return nil, fmt.Errorf("invalid path")
	}
	info, err := os.Stat(src)
	if err != nil {
		return nil, err
	}

	id, err := randomToken(shareTokenBytes)
	if err != nil {
		return nil, err
	}
	dest := s.itemPath(id)
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return nil, err
	}

	// Size before rename (avoids holding the lock during a full tree walk).
	size := info.Size()
	if info.IsDir() {
		size = dirSize(src)
	}

	item := TrashItem{
		ID:           id,
		OriginalPath: rel,
		Name:         filepath.Base(rel),
		IsDir:        info.IsDir(),
		DeletedAt:    time.Now().UTC(),
		DeletedBy:    deletedBy,
		Size:         size,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(src, dest); err != nil {
		return nil, fmt.Errorf("failed to move to trash: %w", err)
	}
	s.Items = append(s.Items, item)
	if err := s.saveLocked(); err != nil {
		// Best-effort rollback while still holding the lock.
		_ = os.Rename(dest, src)
		s.Items = s.Items[:len(s.Items)-1]
		return nil, err
	}
	cp := item
	return &cp, nil
}

func (s *trashStore) list() []TrashItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TrashItem, len(s.Items))
	copy(out, s.Items)
	return out
}

func (s *trashStore) restore(id string) (string, error) {
	if !validShareToken(id) {
		return "", fmt.Errorf("invalid id")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	idx := -1
	var item TrashItem
	for i := range s.Items {
		if s.Items[i].ID == id {
			idx = i
			item = s.Items[i]
			break
		}
	}
	if idx < 0 {
		return "", fmt.Errorf("not found")
	}

	src := s.itemPath(id)
	if _, err := os.Stat(src); err != nil {
		// Missing on disk — drop metadata
		s.Items = append(s.Items[:idx], s.Items[idx+1:]...)
		_ = s.saveLocked()
		return "", fmt.Errorf("trash item missing on disk")
	}

	dest, err := safePath(item.OriginalPath)
	if err != nil {
		return "", fmt.Errorf("invalid original path")
	}
	if isTrashPath(item.OriginalPath) {
		return "", fmt.Errorf("invalid original path")
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return "", fmt.Errorf("failed to recreate parent folders")
	}
	if _, err := os.Stat(dest); err == nil {
		return "", fmt.Errorf("original location is occupied: %s", item.OriginalPath)
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if err := os.Rename(src, dest); err != nil {
		return "", fmt.Errorf("failed to restore: %w", err)
	}

	s.Items = append(s.Items[:idx], s.Items[idx+1:]...)
	if err := s.saveLocked(); err != nil {
		return "", err
	}
	return item.OriginalPath, nil
}

func (s *trashStore) purge(id string) error {
	if !validShareToken(id) {
		return fmt.Errorf("invalid id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.purgeLocked(id)
}

func (s *trashStore) purgeLocked(id string) error {
	idx := -1
	for i := range s.Items {
		if s.Items[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		// Still try to remove orphan on disk
		_ = os.RemoveAll(s.itemPath(id))
		return fmt.Errorf("not found")
	}
	_ = os.RemoveAll(s.itemPath(id))
	s.Items = append(s.Items[:idx], s.Items[idx+1:]...)
	return s.saveLocked()
}

func (s *trashStore) empty() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.Items)
	for _, it := range s.Items {
		_ = os.RemoveAll(s.itemPath(it.ID))
	}
	s.Items = nil
	if err := s.saveLocked(); err != nil {
		return 0, err
	}
	// Clean orphans under items/
	entries, _ := os.ReadDir(filepath.Join(s.root, trashItemsDir))
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(s.root, trashItemsDir, e.Name()))
	}
	return n, nil
}

func (s *trashStore) purgeExpired(olderThan time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().UTC().Add(-olderThan)
	kept := s.Items[:0]
	removed := 0
	for _, it := range s.Items {
		if it.DeletedAt.Before(cutoff) {
			_ = os.RemoveAll(s.itemPath(it.ID))
			removed++
			continue
		}
		kept = append(kept, it)
	}
	if removed > 0 {
		s.Items = kept
		_ = s.saveLocked()
	}
	return removed
}

func startTrashJanitor(s *trashStore) {
	go func() {
		// Run once at startup, then hourly.
		if n := s.purgeExpired(trashRetention); n > 0 {
			log.Printf("Trash: purged %d item(s) older than 30 days", n)
		}
		t := time.NewTicker(trashPurgeEvery)
		for range t.C {
			if n := s.purgeExpired(trashRetention); n > 0 {
				log.Printf("Trash: purged %d item(s) older than 30 days", n)
			}
		}
	}()
}

func handleTrashList(w http.ResponseWriter, r *http.Request) {
	items := trash.list()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"items": items,
	})
}

func handleTrashRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	path, err := trash.restore(body.ID)
	if err != nil {
		status := http.StatusBadRequest
		if err.Error() == "not found" || strings.Contains(err.Error(), "missing") {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "occupied") {
			status = http.StatusConflict
		}
		jsonErr(w, status, err.Error())
		return
	}
	jsonOK(w, fmt.Sprintf("Restored to %s", path))
	auditLog(actorName(r), "trash_restore", path, r)
	invalidateListingCache()
}

func handleTrashPurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if err := trash.purge(body.ID); err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	jsonOK(w, "Permanently deleted")
	auditLog(actorName(r), "trash_purge", body.ID, r)
	invalidateListingCache()
}

func handleTrashEmpty(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if !body.Confirm {
		jsonErr(w, http.StatusBadRequest, "Empty trash requires confirmation")
		return
	}
	n, err := trash.empty()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to empty trash")
		return
	}
	jsonOK(w, fmt.Sprintf("Emptied trash (%d item(s))", n))
	auditLog(actorName(r), "trash_empty", "", r)
	invalidateListingCache()
}

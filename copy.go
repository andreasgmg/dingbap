package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	copyMaxFiles = 5000
	copyMaxBytes int64 = 4 << 30 // 4 GiB
)

func handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	u, err := getDiskUsage()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to measure disk usage")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func handleCopy(w http.ResponseWriter, r *http.Request) {
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
		jsonErr(w, http.StatusBadRequest, "Cannot copy to/from trash this way")
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

	srcInfo, err := os.Lstat(srcAbs)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Source not found")
		return
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		jsonErr(w, http.StatusBadRequest, "Cannot copy symlinks")
		return
	}
	if srcInfo.IsDir() {
		rel, err := filepath.Rel(srcAbs, destAbs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			jsonErr(w, http.StatusBadRequest, "Cannot copy a folder into itself")
			return
		}
	}

	name := filepath.Base(srcAbs)
	newAbs := filepath.Join(destAbs, name)
	if filepath.Clean(srcAbs) == filepath.Clean(newAbs) {
		jsonErr(w, http.StatusBadRequest, "Source and destination are the same — use Duplicate")
		return
	}
	if _, err := os.Stat(newAbs); err == nil {
		name = uniqueCopyName(destAbs, name)
		newAbs = filepath.Join(destAbs, name)
	} else if !os.IsNotExist(err) {
		jsonErr(w, http.StatusInternalServerError, "Failed to check destination")
		return
	}

	if err := copyPath(srcAbs, newAbs, srcInfo); err != nil {
		_ = os.RemoveAll(newAbs)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonOK(w, fmt.Sprintf("Copied as %s", name))
	auditLog(actorName(r), "copy", pathJoin(strings.Trim(body.DestDir, "/"), name), r)
	invalidateListingCache()
}

func handleDuplicate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Path string `json:"path"`
	}
	if !decodeJSONBody(w, r, &body) {
		return
	}
	if isTrashPath(body.Path) {
		jsonErr(w, http.StatusBadRequest, "Cannot duplicate trash items this way")
		return
	}
	rel := strings.Trim(body.Path, "/")
	if rel == "" {
		jsonErr(w, http.StatusBadRequest, "Cannot duplicate root")
		return
	}

	srcAbs, err := safePath(body.Path)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid path")
		return
	}
	srcInfo, err := os.Lstat(srcAbs)
	if err != nil {
		jsonErr(w, http.StatusNotFound, "Source not found")
		return
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		jsonErr(w, http.StatusBadRequest, "Cannot duplicate symlinks")
		return
	}

	parent := filepath.Dir(srcAbs)
	name := uniqueCopyName(parent, filepath.Base(srcAbs))
	newAbs := filepath.Join(parent, name)

	if err := copyPath(srcAbs, newAbs, srcInfo); err != nil {
		_ = os.RemoveAll(newAbs)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonOK(w, fmt.Sprintf("Duplicated as %s", name))
	auditLog(actorName(r), "duplicate", pathJoin(pathDir(body.Path), name), r)
	invalidateListingCache()
}

// uniqueCopyName picks name, then "name copy", "name copy 2", … that does not exist in dir.
func uniqueCopyName(dir, name string) string {
	for n := 0; n < 10000; n++ {
		cand := copyNameCandidate(name, n)
		if _, err := os.Stat(filepath.Join(dir, cand)); os.IsNotExist(err) {
			return cand
		}
	}
	return fmt.Sprintf("%s copy %d", name, time.Now().UnixNano())
}

func copyNameCandidate(name string, n int) string {
	if n == 0 {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if n == 1 {
		return base + " copy" + ext
	}
	return fmt.Sprintf("%s copy %d%s", base, n, ext)
}

func copyPath(src, dst string, srcInfo os.FileInfo) error {
	var files int
	var bytes int64
	if srcInfo.IsDir() {
		return copyDir(src, dst, &files, &bytes)
	}
	return copyFile(src, dst, srcInfo.Mode(), &files, &bytes)
}

func copyDir(src, dst string, files *int, bytes *int64) error {
	if err := os.Mkdir(dst, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		srcChild := filepath.Join(src, name)
		dstChild := filepath.Join(dst, name)
		info, err := os.Lstat(srcChild)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if info.IsDir() {
			if err := copyDir(srcChild, dstChild, files, bytes); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(srcChild, dstChild, info.Mode(), files, bytes); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode, files *int, bytes *int64) error {
	if *files >= copyMaxFiles {
		return fmt.Errorf("copy exceeds %d files", copyMaxFiles)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	st, err := in.Stat()
	if err != nil {
		return err
	}
	if *bytes+st.Size() > copyMaxBytes {
		return fmt.Errorf("copy exceeds size limit")
	}

	perm := mode.Perm()
	if perm == 0 {
		perm = 0644
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	n, err := io.Copy(out, in)
	if err != nil {
		return err
	}
	*files++
	*bytes += n
	return nil
}

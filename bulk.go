package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	zipMaxFiles = 5000
	zipMaxBytes = 4 << 30 // 4 GiB uncompressed budget
)

func handleBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Paths   []string `json:"paths"`
		Confirm bool     `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	if !body.Confirm {
		jsonErr(w, http.StatusBadRequest, "Confirmation required")
		return
	}
	paths := uniqueNonEmptyPaths(body.Paths)
	if len(paths) == 0 {
		jsonErr(w, http.StatusBadRequest, "No paths provided")
		return
	}
	if len(paths) > 500 {
		jsonErr(w, http.StatusBadRequest, "Too many paths (max 500)")
		return
	}

	deletedBy := ""
	if s := sessionFromCtx(r); s != nil {
		deletedBy = s.Username
	}

	moved := 0
	var failed []string
	for _, rel := range paths {
		rel = strings.Trim(rel, "/")
		if rel == "" || isTrashPath(rel) {
			failed = append(failed, rel)
			continue
		}
		if _, err := trash.moveToTrash(rel, deletedBy); err != nil {
			failed = append(failed, rel)
			continue
		}
		if shares != nil {
			shares.removeByPathPrefix(rel)
		}
		moved++
	}
	invalidateListingCache()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"moved":   moved,
		"failed":  failed,
		"message": fmt.Sprintf("Moved %d item(s) to trash", moved),
	})
}

func handleBulkMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Paths   []string `json:"paths"`
		DestDir string   `json:"destDir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	paths := uniqueNonEmptyPaths(body.Paths)
	if len(paths) == 0 {
		jsonErr(w, http.StatusBadRequest, "No paths provided")
		return
	}
	if len(paths) > 500 {
		jsonErr(w, http.StatusBadRequest, "Too many paths (max 500)")
		return
	}
	if isTrashPath(body.DestDir) {
		jsonErr(w, http.StatusBadRequest, "Cannot move to trash this way")
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

	moved := 0
	var failed []string
	for _, rel := range paths {
		rel = strings.Trim(rel, "/")
		if rel == "" || isTrashPath(rel) {
			failed = append(failed, rel)
			continue
		}
		srcAbs, err := safePath(rel)
		if err != nil {
			failed = append(failed, rel)
			continue
		}
		srcInfo, err := os.Stat(srcAbs)
		if err != nil {
			failed = append(failed, rel)
			continue
		}
		if srcInfo.IsDir() {
			relCheck, err := filepath.Rel(srcAbs, destAbs)
			if err == nil && relCheck != ".." && !strings.HasPrefix(relCheck, ".."+string(os.PathSeparator)) {
				failed = append(failed, rel)
				continue
			}
		}
		name := filepath.Base(srcAbs)
		newAbs := filepath.Join(destAbs, name)
		if filepath.Clean(srcAbs) == filepath.Clean(newAbs) {
			failed = append(failed, rel)
			continue
		}
		if _, err := os.Stat(newAbs); err == nil {
			failed = append(failed, rel)
			continue
		} else if !os.IsNotExist(err) {
			failed = append(failed, rel)
			continue
		}
		if err := os.Rename(srcAbs, newAbs); err != nil {
			failed = append(failed, rel)
			continue
		}
		newRel := pathJoin(strings.Trim(body.DestDir, "/"), name)
		if shares != nil {
			shares.rewritePathPrefix(rel, newRel)
		}
		moved++
	}
	invalidateListingCache()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"moved":   moved,
		"failed":  failed,
		"message": fmt.Sprintf("Moved %d item(s)", moved),
	})
}

func handleZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonErr(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var body struct {
		Paths []string `json:"paths"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, http.StatusBadRequest, "Invalid JSON")
		return
	}
	paths := uniqueNonEmptyPaths(body.Paths)
	if len(paths) == 0 {
		jsonErr(w, http.StatusBadRequest, "No paths provided")
		return
	}
	if len(paths) > 500 {
		jsonErr(w, http.StatusBadRequest, "Too many paths (max 500)")
		return
	}

	name := "dingbap.zip"
	if len(paths) == 1 {
		base := filepath.Base(strings.Trim(paths[0], "/"))
		if base != "" && base != "." {
			name = base + ".zip"
		}
	}

	if err := streamZip(w, name, paths); err != nil {
		log.Printf("zip: %v", err)
	}
}

func streamZip(w http.ResponseWriter, downloadName string, relPaths []string) error {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", formatContentDisposition("attachment", downloadName))
	w.Header().Set("X-Content-Type-Options", "nosniff")

	zw := zip.NewWriter(w)
	defer zw.Close()

	var fileCount int
	var byteCount int64
	realRoot, err := storageRealRoot()
	if err != nil {
		return err
	}

	for _, rel := range relPaths {
		rel = strings.Trim(rel, "/")
		if rel == "" || isTrashPath(rel) {
			continue
		}
		abs, err := safePath(rel)
		if err != nil {
			return fmt.Errorf("invalid path %q", rel)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if err := addFileToZip(zw, realRoot, abs, filepath.Base(rel), &fileCount, &byteCount); err != nil {
				return err
			}
			continue
		}
		err = filepath.WalkDir(abs, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			relInside, err := filepath.Rel(abs, path)
			if err != nil {
				return err
			}
			zipName := filepath.ToSlash(filepath.Join(filepath.Base(rel), relInside))
			return addFileToZip(zw, realRoot, path, zipName, &fileCount, &byteCount)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func addFileToZip(zw *zip.Writer, realRoot, absPath, zipName string, fileCount *int, byteCount *int64) error {
	if *fileCount >= zipMaxFiles {
		return fmt.Errorf("zip exceeds %d files", zipMaxFiles)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return err
	}
	if *byteCount+info.Size() > zipMaxBytes {
		return fmt.Errorf("zip exceeds size limit")
	}
	real, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return err
	}
	if !withinRoot(realRoot, real) {
		return fmt.Errorf("path escapes storage")
	}

	f, err := os.Open(absPath)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	hdr.Name = zipName
	hdr.Method = zip.Deflate
	hdr.Modified = info.ModTime()

	out, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, f)
	if err != nil {
		return err
	}
	*fileCount++
	*byteCount += n
	return nil
}

func storageRealRoot() (string, error) {
	if real, ok := cachedRealRoot(rootDir); ok {
		return real, nil
	}
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

func uniqueNonEmptyPaths(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.Trim(strings.ReplaceAll(p, `\`, `/`), "/")
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

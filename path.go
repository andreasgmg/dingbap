package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Cached resolved storage root (absolute + EvalSymlinks). Set once at startup via
// configureStorageRoot; tests that only change rootDir fall back to live resolve.
var (
	pathRootMu   sync.RWMutex
	pathRootAbs  string
	pathRootReal string
)

// configureStorageRoot caches Abs+EvalSymlinks(dir) for safePath hot paths.
func configureStorageRoot(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve storage root: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("resolve storage root: %w", err)
	}
	pathRootMu.Lock()
	pathRootAbs = abs
	pathRootReal = real
	pathRootMu.Unlock()
	return nil
}

func cachedRealRoot(storageDir string) (string, bool) {
	abs, err := filepath.Abs(storageDir)
	if err != nil {
		return "", false
	}
	pathRootMu.RLock()
	defer pathRootMu.RUnlock()
	if pathRootReal != "" && abs == pathRootAbs {
		return pathRootReal, true
	}
	return "", false
}

// safePath resolves requestedPath under rootDir and rejects traversal / symlink escapes.
// It is used for every file and directory operation that touches storage.
func safePath(rel string) (string, error) {
	return resolveUnderRoot(rootDir, rel)
}

func resolveUnderRoot(storageDir, requestedPath string) (string, error) {
	if strings.Contains(requestedPath, "\x00") {
		return "", fmt.Errorf("invalid path")
	}

	absRoot, err := filepath.Abs(storageDir)
	if err != nil {
		return "", fmt.Errorf("invalid path")
	}

	realRoot, ok := cachedRealRoot(storageDir)
	if !ok {
		realRoot, err = filepath.EvalSymlinks(absRoot)
		if err != nil {
			return "", fmt.Errorf("invalid path")
		}
	}

	// Clean as if absolute so leading ".." segments collapse instead of escaping Join.
	cleaned := filepath.Clean("/" + strings.ReplaceAll(requestedPath, `\`, `/`))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "." {
		cleaned = ""
	}

	if cleaned == "" {
		return realRoot, nil
	}

	for _, part := range strings.Split(cleaned, "/") {
		if part == ".." {
			return "", fmt.Errorf("path traversal detected")
		}
	}

	current := realRoot
	parts := strings.Split(cleaned, "/")
	for i, part := range parts {
		if part == "" || part == "." {
			continue
		}

		next := filepath.Join(current, part)
		absNext, err := filepath.Abs(next)
		if err != nil || !withinRoot(realRoot, absNext) {
			return "", fmt.Errorf("path traversal detected")
		}

		fi, err := os.Lstat(absNext)
		if err != nil {
			if !os.IsNotExist(err) {
				return "", fmt.Errorf("invalid path")
			}
			// Path does not exist yet (mkdir/upload) — keep the rest lexical, still under root.
			candidate := filepath.Join(append([]string{current}, parts[i:]...)...)
			absCandidate, err := filepath.Abs(candidate)
			if err != nil || !withinRoot(realRoot, absCandidate) {
				return "", fmt.Errorf("path traversal detected")
			}
			return absCandidate, nil
		}

		if fi.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(absNext)
			if err != nil {
				return "", fmt.Errorf("invalid path")
			}
			if !withinRoot(realRoot, resolved) {
				return "", fmt.Errorf("path traversal detected")
			}
			current = resolved
			continue
		}

		current = absNext
	}

	return current, nil
}

// withinRoot reports whether target is root or a path inside it.
// Prefer Rel over strings.HasPrefix(target, root): HasPrefix("/data", "/data-evil") is a classic footgun.
func withinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return true
}

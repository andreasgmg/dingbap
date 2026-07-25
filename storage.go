package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const defaultStorageDir = "storage"

// resolveStorageDir picks the file storage directory from (highest priority first):
//  1. CLI flag value (non-empty)
//  2. DINGBAP_STORAGE_DIR
//  3. ./storage
//
// It resolves to an absolute path, creates the directory if missing, and verifies
// it is a writable directory before the server starts.
func resolveStorageDir(flagVal string) (string, error) {
	dir := strings.TrimSpace(flagVal)
	if dir == "" {
		dir = strings.TrimSpace(os.Getenv("DINGBAP_STORAGE_DIR"))
	}
	if dir == "" {
		dir = defaultStorageDir
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve storage dir %q: %w", dir, err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("stat storage dir %s: %w", abs, err)
		}
		if err := os.MkdirAll(abs, 0755); err != nil {
			return "", fmt.Errorf("create storage dir %s: %w", abs, err)
		}
	} else if !info.IsDir() {
		return "", fmt.Errorf("storage path %s exists but is not a directory", abs)
	}

	probe := filepath.Join(abs, ".dingbap-write-test")
	if err := os.WriteFile(probe, []byte{}, 0600); err != nil {
		return "", fmt.Errorf("storage dir %s is not writable: %w", abs, err)
	}
	_ = os.Remove(probe)

	return abs, nil
}

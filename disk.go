package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const diskUsageCacheTTL = 30 * time.Second

type diskUsage struct {
	UsedBytes  int64 `json:"usedBytes"`  // bytes under storage root (files + meta + trash)
	FreeBytes  int64 `json:"freeBytes"`  // filesystem free (available to non-root)
	TotalBytes int64 `json:"totalBytes"` // filesystem capacity
}

var (
	diskUsageMu    sync.Mutex
	diskUsageCache diskUsage
	diskUsageAt    time.Time
	diskUsageValid bool
)

func invalidateDiskUsageCache() {
	diskUsageMu.Lock()
	diskUsageValid = false
	diskUsageMu.Unlock()
}

// getDiskUsage returns cached storage + filesystem usage for the admin panel.
func getDiskUsage() (diskUsage, error) {
	diskUsageMu.Lock()
	defer diskUsageMu.Unlock()
	if diskUsageValid && time.Since(diskUsageAt) < diskUsageCacheTTL {
		return diskUsageCache, nil
	}
	u, err := measureDiskUsage(rootDir)
	if err != nil {
		return diskUsage{}, err
	}
	diskUsageCache = u
	diskUsageAt = time.Now()
	diskUsageValid = true
	return u, nil
}

func measureDiskUsage(storageRoot string) (diskUsage, error) {
	var u diskUsage
	err := filepath.WalkDir(storageRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries should not fail the whole report.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		u.UsedBytes += info.Size()
		return nil
	})
	if err != nil {
		return diskUsage{}, fmt.Errorf("walk storage: %w", err)
	}

	var st unix.Statfs_t
	if err := unix.Statfs(storageRoot, &st); err != nil {
		return diskUsage{}, fmt.Errorf("statfs: %w", err)
	}
	bsize := int64(st.Bsize)
	if bsize <= 0 {
		bsize = 4096
	}
	u.FreeBytes = int64(st.Bavail) * bsize
	u.TotalBytes = int64(st.Blocks) * bsize
	return u, nil
}

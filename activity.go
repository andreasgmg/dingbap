package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	activityDefaultRetention = 14 * 24 * time.Hour
	activityMaxLines         = 5000
	activityListLimit        = 200
)

var (
	activityEnabled bool
	activityLogIP   bool
	activityPath    string
	activityMu      sync.Mutex
)

type activityEntry struct {
	TS     string `json:"ts"`
	User   string `json:"user,omitempty"`
	Action string `json:"action"`
	Path   string `json:"path,omitempty"`
	IP     string `json:"ip,omitempty"` // only when ACTIVITY_LOG_IP=1
}

func configureActivityLog(metaDir string) {
	activityEnabled = envTruthy("ACTIVITY_LOG")
	activityLogIP = envTruthy("ACTIVITY_LOG_IP")
	activityPath = filepath.Join(metaDir, "activity.jsonl")
	if activityEnabled {
		log.Printf("Activity log ON → %s (retention ~14d, IPs=%v)", activityPath, activityLogIP)
	} else {
		log.Printf("Activity log off (set ACTIVITY_LOG=1 to enable; ACTIVITY_LOG_IP=1 to include IPs)")
	}
}

func actorName(r *http.Request) string {
	if s := sessionFromCtx(r); s != nil {
		return s.Username
	}
	return ""
}

// auditLog appends one line when ACTIVITY_LOG=1. Never logs unless enabled.
// IP/UA are omitted unless ACTIVITY_LOG_IP=1 (UA is never logged).
func auditLog(user, action, path string, r *http.Request) {
	if !activityEnabled || activityPath == "" {
		return
	}
	e := activityEntry{
		TS:     time.Now().UTC().Format(time.RFC3339),
		User:   user,
		Action: action,
		Path:   strings.Trim(path, "/"),
	}
	if activityLogIP && r != nil {
		e.IP = clientIP(r)
	}
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	activityMu.Lock()
	defer activityMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(activityPath), 0700); err != nil {
		return
	}
	f, err := os.OpenFile(activityPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(data, '\n'))
	_ = f.Close()
	pruneActivityLocked()
}

func pruneActivityLocked() {
	data, err := os.ReadFile(activityPath)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return
	}
	cutoff := time.Now().UTC().Add(-activityDefaultRetention)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e activityEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339, e.TS)
		if err != nil || ts.Before(cutoff) {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) > activityMaxLines {
		kept = kept[len(kept)-activityMaxLines:]
	}
	if len(kept) == len(lines) {
		return
	}
	_ = writeFileAtomic(activityPath, []byte(strings.Join(kept, "\n")+"\n"), 0600)
}

func readActivityRecent(limit int) ([]activityEntry, error) {
	if !activityEnabled {
		return nil, nil
	}
	if limit <= 0 || limit > activityListLimit {
		limit = activityListLimit
	}
	activityMu.Lock()
	defer activityMu.Unlock()
	f, err := os.Open(activityPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []activityEntry{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []activityEntry
	sc := bufio.NewScanner(f)
	// Allow slightly long JSON lines.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e activityEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		all = append(all, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	// Newest first for the UI.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all, nil
}

func handleActivityList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonErr(w, http.StatusMethodNotAllowed, "GET required")
		return
	}
	if !activityEnabled {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"enabled": false,
			"entries": []activityEntry{},
			"message": "Activity log is off. Set ACTIVITY_LOG=1 to enable (local JSONL; IPs only with ACTIVITY_LOG_IP=1).",
		})
		return
	}
	entries, err := readActivityRecent(activityListLimit)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "Failed to read activity log")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"enabled": true,
		"logIP":   activityLogIP,
		"entries": entries,
	})
}
